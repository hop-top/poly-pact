package azurerm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/adapters/graph"
	"hop.top/pact-go/core/clock"
)

const (
	// ARMOrigin is the origin of Azure Resource Manager [S3].
	ARMOrigin = "https://management.azure.com"
	// APIVersion is the API version of the restart operation [S3].
	APIVersion = "2025-04-01"
	// ScopeARMDefault is the scope of the on-behalf-of token request.
	ScopeARMDefault = ARMOrigin + "/.default"
	// DefaultTimeout bounds each request when the configuration gives none.
	DefaultTimeout = 30 * time.Second
	// ClassDelegatedUser is the executor identity class of the restart row
	// (example I14, draft Section 17.5).
	ClassDelegatedUser = "delegated-user"

	// maxAnswer bounds the answers the executor reads.
	maxAnswer = 1 << 20
)

// DefaultRoute is the restart row as the task ledger sees it: a
// ledger-deduplicated write with no definitive status (profile section 6.1,
// MO-25, MO-37).
var DefaultRoute = task.Route{ID: "vm-restart", Version: "1", Class: task.ClassLedgerWrite}

// guid is the lower-case form of a subscription ID.
var guid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// segment is a path segment the executor accepts in a resource ID: no
// character that a path would have to percent-encode, and not a dot
// segment.
var segment = regexp.MustCompile(`^[A-Za-z0-9._()-]+$`)

// plain reports whether s is a segment and not a dot segment.
func plain(s string) bool { return segment.MatchString(s) && s != "." && s != ".." }

// ActivationGate is the activation check of the restart: the approval-class
// check of draft Section 17.3.1 that establishes the activation of the
// principal's role for the virtual machine (example I14). The check is the
// deployment's; the executor sends nothing unless it is PASS.
type ActivationGate interface {
	CheckActivation(ctx context.Context, in RestartInput) adapter.CheckOutcome
}

// Config configures an [Executor]. Every value comes from trusted gateway
// configuration, never from a request.
type Config struct {
	// Acquirer obtains the user's delegated token for Azure Resource Manager
	// by the on-behalf-of grant, with the scope [ScopeARMDefault]. Required.
	Acquirer graph.TokenAcquirer
	// Ledger is the task ledger. Required.
	Ledger task.TaskLedger
	// Activation is the activation gate. Required.
	Activation ActivationGate
	// Subscription is the subscription ID the executor acts in. Required.
	Subscription string
	// HandlePrefixes are the prefixes a handle must start with to be
	// followed (MO-43). Nil is the compute operations path of the
	// subscription [S2].
	HandlePrefixes []string
	// Route is the restart row. The zero Route is [DefaultRoute]; its class
	// must be a ledger-deduplicated write.
	Route task.Route
	// Reconcile is the native status source of an ambiguous restart (MO-38,
	// MO-40). Nil means none: an Unknown restart stays Unknown (MO-39).
	Reconcile task.StatusSource
	// MaxStatusReads is max_status_reads per operation (MO-45). Required.
	MaxStatusReads int
	// MinInterval is the wait before a status read when Azure gave no
	// Retry-After (MO-45). Required.
	MinInterval time.Duration
	// Sleep waits d or until ctx ends; nil waits on a timer.
	Sleep func(ctx context.Context, d time.Duration) error
	// HTTPClient sends the requests. Nil is a client with TLS verification
	// and no proxy. Redirects are never followed.
	HTTPClient *http.Client
	// Timeout bounds each request. Zero is [DefaultTimeout].
	Timeout time.Duration
	// Clock is the source of the current time. Required.
	Clock clock.Clock
}

// Executor restarts virtual machines under the task ledger.
type Executor struct {
	cfg    Config
	client *http.Client
}

// New returns the executor of cfg. It validates the configuration.
func New(cfg Config) (*Executor, error) {
	if cfg.Route.ID == "" {
		cfg.Route = DefaultRoute
	}
	switch {
	case cfg.Acquirer == nil || cfg.Acquirer.Grant() != graph.GrantOnBehalfOf:
		return nil, errors.New("azurerm: an on-behalf-of token acquirer is required")
	case cfg.Ledger == nil:
		return nil, errors.New("azurerm: no task ledger")
	case cfg.Activation == nil:
		return nil, errors.New("azurerm: no activation gate")
	case !guid.MatchString(cfg.Subscription):
		return nil, errors.New("azurerm: the subscription must be a lower-case GUID")
	case cfg.Route.Class != task.ClassLedgerWrite:
		return nil, errors.New("azurerm: the restart row is a ledger-deduplicated write")
	case cfg.MaxStatusReads <= 0 || cfg.MinInterval <= 0:
		return nil, errors.New("azurerm: max_status_reads and the minimum interval are required (MO-45)")
	case cfg.Clock == nil:
		return nil, errors.New("azurerm: no clock")
	case cfg.Timeout < 0:
		return nil, errors.New("azurerm: negative timeout")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.HandlePrefixes == nil {
		cfg.HandlePrefixes = []string{ARMOrigin + "/subscriptions/" + cfg.Subscription + "/providers/Microsoft.Compute/locations/"}
	}
	for _, p := range cfg.HandlePrefixes {
		if !strings.HasPrefix(p, "https://") || strings.Count(p, "/") < 3 || !strings.HasSuffix(p, "/") {
			return nil, fmt.Errorf("azurerm: handle prefix %q is not an https origin and a path ending in /", p)
		}
	}
	out := http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	if cfg.HTTPClient != nil {
		out = *cfg.HTTPClient
	}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Executor{cfg: cfg, client: &out}, nil
}

// RestartInput is one admitted restart as the gateway hands it to the
// executor.
type RestartInput struct {
	// Request is the admitted operation for the task ledger: the principal,
	// the agent, the client task_id and the operation context. Its Route is
	// set by the executor.
	Request task.Request
	// Assertion is the user's access token for the on-behalf-of request
	// (token A). It is never sent to Azure Resource Manager.
	Assertion string
	// VM is the resource ID of the virtual machine under the installed
	// operation mapping: /subscriptions/{id}/resourceGroups/{group}/
	// providers/Microsoft.Compute/virtualMachines/{name}.
	VM string
}

// ExecutorRecord is the executor's record of a downstream request, which
// outcome reports cite (draft Section 14.2).
type ExecutorRecord struct {
	Class     string
	AppID     string
	Principal string
	VM        string
	At        time.Time
}

// Ref is the reference of the record.
func (r ExecutorRecord) Ref() string {
	return fmt.Sprintf("azurerm-executor:%s:%s:%s:%d", r.Class, r.AppID, strings.ToLower(r.VM), r.At.Unix())
}

// Outcome is what a restart or a tracking returned: the ledger key, the
// record, and the report of the event with the executor record among its
// evidence.
type Outcome struct {
	Key      task.Key
	Settled  task.Settled
	Executor ExecutorRecord
}

// ActivationError is the error of a restart whose activation gate is not
// PASS: nothing is reserved and nothing is sent (MO-10).
type ActivationError struct {
	Outcome adapter.CheckOutcome
}

func (e *ActivationError) Error() string {
	return fmt.Sprintf("azurerm: the activation check is %s %s", e.Outcome.Result, e.Outcome.ReasonCode)
}

// Is matches [adapter.ErrDependencyUnavailable] for an UNKNOWN result.
func (e *ActivationError) Is(target error) bool {
	return target == adapter.ErrDependencyUnavailable && e.Outcome.Result == adapter.VerdictUnknown
}

// vmPath validates a resource ID of a virtual machine of the subscription.
func (x *Executor) vmPath(id string) (string, error) {
	parts := strings.Split(id, "/")
	if len(parts) != 9 || parts[0] != "" || parts[1] != "subscriptions" || parts[2] != x.cfg.Subscription ||
		parts[3] != "resourceGroups" || len(parts[4]) > 90 || !plain(parts[4]) ||
		parts[5] != "providers" || parts[6] != "Microsoft.Compute" || parts[7] != "virtualMachines" || !plain(parts[8]) {
		return "", fmt.Errorf("azurerm: %q is not a virtual machine of the subscription: %w", id, adapter.ErrInvalidMessage)
	}
	return id, nil
}

// Restart runs one admitted restart (package documentation, steps 1 to 4).
// A ledger refusal is returned as the ledger gave it. A repeat answered from
// a terminal record returns that record and sends nothing.
func (x *Executor) Restart(ctx context.Context, in RestartInput) (Outcome, error) {
	out := Outcome{Executor: ExecutorRecord{Class: ClassDelegatedUser, AppID: x.cfg.Acquirer.ClientID(), Principal: in.Request.Principal.ID, VM: in.VM, At: x.cfg.Clock.Now()}}
	path, err := x.vmPath(in.VM)
	if err != nil {
		return out, err
	}
	if o := x.cfg.Activation.CheckActivation(ctx, in); o.Result != adapter.VerdictPass {
		return out, &ActivationError{Outcome: o}
	}
	req := in.Request
	req.Route = x.cfg.Route
	req.BodyLength = 0
	res, err := x.cfg.Ledger.Reserve(ctx, req)
	if err != nil {
		return out, err
	}
	out.Key = res.Key
	if !res.Send {
		out.Settled = task.Settled{Operation: res.Operation}
		return out, nil
	}
	tok, err := x.cfg.Acquirer.Acquire(ctx, in.Assertion)
	if err != nil {
		_, _ = x.cfg.Ledger.Record(ctx, res, task.Result{})
		return out, err
	}
	result := x.post(ctx, ARMOrigin+path+"/restart?api-version="+APIVersion, tok)
	out.Executor.At = x.cfg.Clock.Now()
	st, err := x.cfg.Ledger.Record(ctx, res, result)
	out.Settled = x.cite(st, out.Executor)
	return out, err
}

// post sends the restart and reads how it ended. The request has no body.
// Only a request that provably did not leave is not sent.
func (x *Executor) post(ctx context.Context, target string, tok graph.Token) task.Result {
	if ctx.Err() != nil {
		return task.Result{}
	}
	ctx, cancel := context.WithTimeout(ctx, x.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, http.NoBody)
	if err != nil {
		return task.Result{}
	}
	tok.Authorize(req)
	req.Header.Set("User-Agent", "")
	resp, err := x.client.Do(req)
	if err != nil {
		// A timeout or a connection closed after the request may have been
		// written: ambiguous (MO-35).
		return task.Result{Sent: true}
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer)); err != nil {
		return task.Result{Sent: true}
	}
	r := task.Result{Sent: true, Status: resp.StatusCode}
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusCreated {
		r.Handle = resp.Header.Get("Azure-AsyncOperation")
		if r.Handle == "" {
			r.Handle = resp.Header.Get("Location")
		}
		r.RetryAfter = retryAfter(resp.Header.Get("Retry-After"), x.cfg.Clock.Now())
	}
	return r
}

// retryAfter reads a Retry-After value: delay-seconds or an HTTP-date (RFC
// 9110 Section 10.2.3); zero when it is absent or malformed.
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 && n < 1<<31 && v[0] != '+' {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}

// cite adds the executor record to the evidence of the report (draft
// Section 14.2).
func (x *Executor) cite(st task.Settled, r ExecutorRecord) task.Settled {
	if st.Report != nil {
		rep := *st.Report
		rep.EvidenceRefs = append([]string{r.Ref()}, rep.EvidenceRefs...)
		st.Report = &rep
	}
	return st
}
