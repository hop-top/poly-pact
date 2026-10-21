package azurerm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/adapters/graph"
)

// ErrNoStatusSource is the error of tracking an ambiguous restart when the
// configuration names no native status source: the record stays Unknown
// (MO-39).
var ErrNoStatusSource = errors.New("azurerm: no native status source for an ambiguous restart (MO-39)")

// Track reads the status of the restart opID of the task k until its record
// is terminal or max_status_reads is reached (package documentation). An
// accepted restart is read through its handle under the user's delegated
// token, obtained from assertion (MO-48); an ambiguous one is reconciled
// through [Config].Reconcile. Tracking never sends a restart.
func (x *Executor) Track(ctx context.Context, assertion string, k task.Key, opID string) (Outcome, error) {
	out := Outcome{Key: k, Executor: ExecutorRecord{Class: ClassDelegatedUser, AppID: x.cfg.Acquirer.ClientID(), At: x.cfg.Clock.Now()}}
	e, err := x.cfg.Ledger.Entry(ctx, k)
	if err != nil {
		return out, err
	}
	out.Executor.Principal = e.Binding.PrincipalID
	var op task.Operation
	for _, o := range e.Operations {
		if o.ID == opID {
			op = o
		}
	}
	if op.ID == "" {
		return out, fmt.Errorf("azurerm: no operation %q in %s", opID, k.Task)
	}
	if op.State == task.OpUnknown && x.cfg.Reconcile == nil {
		out.Settled = task.Settled{Operation: op}
		return out, ErrNoStatusSource
	}
	src := &statusSource{x: x, assertion: assertion}
	tr := task.AsyncTracker{
		Ledger: x.cfg.Ledger, Source: src, MaxReads: x.cfg.MaxStatusReads, MinInterval: x.cfg.MinInterval,
		CheckHandle: x.checkHandle, Sleep: x.cfg.Sleep,
	}
	st, err := tr.Track(ctx, k, opID)
	out.Executor.At = x.cfg.Clock.Now()
	out.Settled = x.cite(st, out.Executor)
	return out, err
}

// checkHandle accepts a handle only under a configured prefix (MO-43).
func (x *Executor) checkHandle(h string) error {
	if strings.ContainsAny(h, "#\\ ") || strings.Contains(h, "/../") || strings.Contains(h, "/./") {
		return errors.New("azurerm: the handle is not a plain URL")
	}
	for _, p := range x.cfg.HandlePrefixes {
		if strings.HasPrefix(h, p) {
			return nil
		}
	}
	return errors.New("azurerm: the handle has another origin or path (MO-43)")
}

// statusSource reads the status of an accepted restart at its handle, and
// reconciles an ambiguous one through the configured source.
type statusSource struct {
	x         *Executor
	assertion string
	tok       *graph.Token
}

// ReadStatus implements [task.StatusSource].
func (s *statusSource) ReadStatus(ctx context.Context, k task.Key, op task.Operation) (task.Status, error) {
	if op.State != task.OpAccepted {
		if s.x.cfg.Reconcile == nil {
			return task.Status{Effect: task.EffectIndeterminate}, nil
		}
		return s.x.cfg.Reconcile.ReadStatus(ctx, k, op)
	}
	if s.tok == nil {
		t, err := s.x.cfg.Acquirer.Acquire(ctx, s.assertion)
		if err != nil {
			return task.Status{}, fmt.Errorf("azurerm: no delegated token for the status read: %w: %w", adapter.ErrDependencyUnavailable, err)
		}
		s.tok = &t
	}
	return s.x.read(ctx, op.Handle, *s.tok)
}

// read sends one GET of the handle: 202 is running; 200 with a status
// member is the operation status object of [S2] (Succeeded applied, Failed
// none, Canceled cancelled, another value running); 200 without one
// establishes nothing (probe P3); 401 and 403 and every other answer are
// DEPENDENCY_UNAVAILABLE (MO-46).
func (x *Executor) read(ctx context.Context, handle string, tok graph.Token) (task.Status, error) {
	ctx, cancel := context.WithTimeout(ctx, x.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, handle, http.NoBody)
	if err != nil {
		return task.Status{}, fmt.Errorf("azurerm: status read: %w", adapter.ErrDependencyUnavailable)
	}
	tok.Authorize(req)
	req.Header.Set("User-Agent", "")
	resp, err := x.client.Do(req)
	if err != nil {
		return task.Status{}, fmt.Errorf("azurerm: the status cannot be read: %w", adapter.ErrDependencyUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil || len(raw) > maxAnswer {
		return task.Status{}, fmt.Errorf("azurerm: the status answer cannot be read: %w", adapter.ErrDependencyUnavailable)
	}
	wait := retryAfter(resp.Header.Get("Retry-After"), x.cfg.Clock.Now())
	switch resp.StatusCode {
	case http.StatusAccepted:
		return task.Status{Effect: task.EffectRunning, RetryAfter: wait}, nil
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return task.Status{}, fmt.Errorf("azurerm: the principal cannot read the status (%d, MO-46): %w", resp.StatusCode, adapter.ErrDependencyUnavailable)
	default:
		return task.Status{}, fmt.Errorf("azurerm: the status read answered %d: %w", resp.StatusCode, adapter.ErrDependencyUnavailable)
	}
	var body struct {
		Status *string `json:"status"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Status == nil {
		return task.Status{Effect: task.EffectIndeterminate, RetryAfter: wait}, nil
	}
	switch *body.Status {
	case "Succeeded":
		return task.Status{Effect: task.EffectApplied}, nil
	case "Failed":
		return task.Status{Effect: task.EffectNone}, nil
	case "Canceled":
		return task.Status{Effect: task.EffectCancelled}, nil
	}
	return task.Status{Effect: task.EffectRunning, RetryAfter: wait}, nil
}
