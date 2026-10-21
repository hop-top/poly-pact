package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/core"
	"hop.top/pact-go/internal/ascii"
)

// ErrExecutorMismatch is the error of an operation whose executor is not the
// declared binding: execution-identity-v1 is FAIL with EXECUTOR_MISMATCH and
// nothing is executed (GR-21, GR-26).
var ErrExecutorMismatch = errors.New("graph: the executor is not the declared binding (EXECUTOR_MISMATCH)")

// Throttled is Graph's HTTP 429 (GR-25): the operation ends with no data
// after one attempt, and the gateway answers 503 with RetryAfter [M10].
type Throttled struct {
	// RetryAfter is Graph's Retry-After value.
	RetryAfter string
}

func (e *Throttled) Error() string { return "graph: Microsoft Graph throttled the request" }

// Is matches [adapter.ErrDependencyUnavailable].
func (e *Throttled) Is(target error) bool { return target == adapter.ErrDependencyUnavailable }

// ExecuteInput is one admitted operation as the gateway hands it to the
// executor.
type ExecuteInput struct {
	// Request is the gateway request that carried the operation, marked as
	// it arrived; in form D its Authorization field holds token A.
	Request *http.Request
	// Principal is the principal authenticate_native established.
	Principal adapter.Principal
	// Operation is the admitted operation context.
	Operation core.OperationContext
	// TaskID and AgentID are the task and the agent of the admission; a
	// continuation is followed only for the same ones (RB-58).
	TaskID, AgentID string
}

// ExecutorRecord is the executor's immutable record of one downstream
// request (GR-29): the executor identity, Graph's request-id when Graph
// answered, and the time.
type ExecutorRecord struct {
	Row       Row
	Class     string
	AppID     string
	Executor  string
	Principal string
	RequestID string
	At        time.Time
}

// Ref is the reference of the record that outcome reports cite.
func (r ExecutorRecord) Ref() string {
	id := "no-request"
	if r.RequestID != "" {
		id = "request-id:" + r.RequestID
	}
	return fmt.Sprintf("graph-executor:%s:%s:%s:%d", strings.ToLower(string(r.Row)), r.AppID, id, r.At.Unix())
}

// Result is what one executed operation returned.
type Result struct {
	// Messages is the value array of the page.
	Messages json.RawMessage
	// Count is the number of messages.
	Count int
	// PageToken is the gateway token of the recorded next link, empty when
	// Graph returned none (RB-57).
	PageToken string
	// Executor is the record of the downstream request.
	Executor ExecutorRecord
}

// Execute runs an admitted operation under the translation row of its
// mapping row (section 2): it maps the request again under the installed
// revision and requires the admitted operation; requires execution-identity-
// v1; in form D authenticates the request again, so that token A is the
// operation's own (GR-5, GR-7), and exchanges it by OBO; in form A uses the
// app-only token of the executor application (GR-15); then sends the one
// downstream request with only the executor's Authorization (GR-2, GR-25).
// Every failure ends the operation: none is retried and none is followed by
// another credential (GR-11).
func (a *Adapter) Execute(ctx context.Context, in ExecuteInput) (Result, error) {
	res := Result{Executor: ExecutorRecord{Class: a.class(), AppID: a.cfg.Acquirer.ClientID(), Executor: a.ExecutorID(a.cfg.Acquirer.ClientID()), Principal: in.Principal.ID, At: a.now()}}
	if err := ctx.Err(); err != nil {
		return res, fmt.Errorf("graph: execute: %w: %w", adapter.ErrDependencyUnavailable, err)
	}
	if in.Request == nil || in.Principal.ID == "" || in.Principal.ID != in.Operation.PrincipalID {
		return res, fmt.Errorf("graph: execute: the operation is not the principal's: %w", adapter.ErrContextMismatch)
	}
	var tokenA string
	if a.cfg.Form == FormDelegated {
		p, err := a.cfg.Authenticator.AuthenticateNative(ctx, in.Request)
		if err != nil || p.ID != in.Principal.ID {
			return res, fmt.Errorf("graph: execute: the request does not authenticate as the operation's principal (GR-5): %w", adapter.ErrContextMismatch)
		}
		var ok bool
		if tokenA, ok = bearer(in.Request); !ok {
			return res, fmt.Errorf("graph: execute: no single bearer token A: %w", adapter.ErrContextMismatch)
		}
	}
	op, cont, err := a.mapRequest(ctx, in.Request, in.Principal, MappingRevision)
	if err != nil {
		return res, err
	}
	if op.OperationID != in.Operation.OperationID || op.TargetURI != in.Operation.TargetURI {
		return res, fmt.Errorf("graph: execute: the request is not the admitted operation: %w", adapter.ErrContextMismatch)
	}
	b, v, err := a.identity(ctx, op)
	switch {
	case err != nil:
		return res, err
	case v.result == adapter.VerdictFail && v.code == CodeExecutorMismatch:
		return res, ErrExecutorMismatch
	case v != vPass:
		return res, fmt.Errorf("graph: execute: execution-identity-v1 is %s %s: %w", v.result, v.code, adapter.ErrDependencyUnavailable)
	}
	row, _ := a.rowOf(op.TargetURI)
	res.Executor.Row = row
	target := GraphOrigin + downstreamPath(row, b.MailboxID) + "?" + FixedQuery
	if row == a.nextRow() {
		// With a task ledger the task of a continuation is the native task
		// reference, which the ledger compares (MO-56); the client task_id
		// is advisory (MO-3).
		if (a.cfg.Tasks == nil && cont.TaskID != in.TaskID) || cont.AgentID != in.AgentID {
			return res, fmt.Errorf("graph: execute: the continuation was recorded for another task or agent (RB-58): %w", adapter.ErrContextMismatch)
		}
		if a.cfg.Tasks != nil && cont.TaskToken == "" {
			return res, fmt.Errorf("graph: execute: the continuation has no task ledger record (RB-57, MO-56): %w", adapter.ErrContextMismatch)
		}
		target = cont.Link
	}
	limit := int64(maxAnswer)
	var resv *task.Reservation
	if a.cfg.Tasks != nil {
		r, err := a.cfg.Tasks.Reserve(ctx, task.Request{
			Principal: in.Principal, AgentID: adapter.AgentID(in.AgentID), TaskID: in.TaskID, Operation: in.Operation,
			Route: ListingRoute(a.cfg.Form), Continuation: cont.TaskToken,
		})
		if err != nil {
			return res, err
		}
		resv = &r
		if r.BytesLeft >= 0 && r.BytesLeft < limit {
			limit = r.BytesLeft
		}
	}
	var tok Token
	if a.cfg.Form == FormDelegated {
		tok, err = a.cfg.Acquirer.Acquire(ctx, tokenA)
	} else {
		tok, err = a.applicationToken(ctx)
	}
	if err != nil {
		// No octet of the downstream request has left: the reservation is
		// released (MO-22).
		return res, a.settle(ctx, resv, task.Result{}, err)
	}
	page, requestID, att, err := a.downstream(ctx, target, tok, limit)
	res.Executor.RequestID, res.Executor.At = requestID, a.now()
	st, err2 := a.settleTask(ctx, resv, att, page.NextLink)
	if err != nil {
		return res, a.settle(ctx, resv, att, err)
	}
	if err2 != nil {
		// A page past max_bytes is not released and its continuation is
		// not recorded (MO-21, MO-59).
		return res, err2
	}
	res.Messages, res.Count = page.Value, page.count
	if page.NextLink != "" {
		t, err := a.cfg.Continuations.Record(ctx, Continuation{
			Row: row, Principal: in.Principal.ID, TaskID: in.TaskID, AgentID: in.AgentID, MappingVersion: MappingRevision, Link: page.NextLink,
			TaskToken: st.PageToken,
		})
		if err != nil {
			return res, err
		}
		res.PageToken = t
	}
	return res, nil
}

// ListingRoute is the route of the listing of a form as the task ledger sees
// it (multi-operation profile section 6.1): a read that returns a page. The
// first-page row and the continuation row are one listing, so that a
// continuation recorded on either is followed on the continuation row
// (GR-24, MO-56). Graph's 4xx answers are final refusals (GR-3).
func ListingRoute(f Form) task.Route {
	id := RowGD1
	if f == FormApplication {
		id = RowGA1
	}
	definitive := make([]int, 0, 100)
	for s := 400; s < 500; s++ {
		definitive = append(definitive, s)
	}
	return task.Route{ID: string(id), Version: MappingRevision, Class: task.ClassRead, Page: true, Definitive: definitive}
}

// settle records an attempt that ended in err with the task ledger, when
// there is one, and returns err.
func (a *Adapter) settle(ctx context.Context, resv *task.Reservation, att task.Result, err error) error {
	if resv != nil {
		_, _ = a.cfg.Tasks.Record(ctx, *resv, att)
	}
	return err
}

// settleTask records a successful page with the task ledger: the bytes of
// the answer are counted when released (MO-21), and the next link is checked
// by the ledger's pager before the ledger binds it to the task (RB-57,
// MO-56).
func (a *Adapter) settleTask(ctx context.Context, resv *task.Reservation, att task.Result, next string) (task.Settled, error) {
	if resv == nil || att.Status != http.StatusOK {
		return task.Settled{}, nil
	}
	att.NextLink = next
	return a.cfg.Tasks.Record(ctx, *resv, att)
}

// bearer is the token of the request's single Authorization field.
func bearer(r *http.Request) (string, bool) {
	vs := r.Header.Values("Authorization")
	if len(vs) != 1 {
		return "", false
	}
	scheme, tok, ok := strings.Cut(vs[0], " ")
	if !ok || !ascii.EqualFold(scheme, "Bearer") || tok == "" || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}

// applicationToken is the cached token B of the executor application, or a
// new one (GR-15). Only a passing preflight leaves a cached token in place.
func (a *Adapter) applicationToken(ctx context.Context) (Token, error) {
	a.mu.Lock()
	if t := a.appToken; t != nil && t.usable(a.now()) {
		a.mu.Unlock()
		return *t, nil
	}
	a.mu.Unlock()
	t, err := a.cfg.Acquirer.Acquire(ctx, "")
	if err != nil {
		return Token{}, err
	}
	a.mu.Lock()
	a.appToken = &t
	a.mu.Unlock()
	return t, nil
}

// page is a decoded List messages answer.
type page struct {
	Value    json.RawMessage `json:"value"`
	NextLink string          `json:"@odata.nextLink"`
	count    int
}

// downstream sends the one Graph request and reads its answer through a
// reader bounded by limit plus one (MO-21): 200 is a page; 429 is
// [*Throttled]; another 4xx is Graph's refusal, a native denial that is final
// (GR-3); anything else is a dependency error. The attempt says whether the
// request may have left, the status and the length of the answer read; a 200
// whose answer passes limit is returned with that length and no page, for
// the task ledger to refuse.
func (a *Adapter) downstream(ctx context.Context, target string, tok Token, limit int64) (page, string, task.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return page{}, "", task.Result{}, fmt.Errorf("graph: downstream: %w", adapter.ErrDependencyUnavailable)
	}
	tok.Authorize(req)
	req.Header.Set("User-Agent", "")
	resp, err := a.client.Do(req)
	if err != nil {
		return page{}, "", task.Result{Sent: true}, fmt.Errorf("graph: Microsoft Graph cannot be reached: %w", adapter.ErrDependencyUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	requestID := resp.Header.Get("request-id")
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	att := task.Result{Sent: true, Status: resp.StatusCode, Bytes: int64(len(raw))}
	switch {
	case err != nil:
		return page{}, requestID, task.Result{Sent: true}, fmt.Errorf("graph: the answer cannot be read: %w", adapter.ErrDependencyUnavailable)
	case resp.StatusCode == http.StatusOK && int64(len(raw)) > limit && limit < maxAnswer:
		return page{}, requestID, att, nil
	case int64(len(raw)) > limit:
		return page{}, requestID, task.Result{Sent: true}, fmt.Errorf("graph: the answer cannot be read: %w", adapter.ErrDependencyUnavailable)
	case resp.StatusCode == http.StatusTooManyRequests:
		return page{}, requestID, att, &Throttled{RetryAfter: resp.Header.Get("Retry-After")}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return page{}, requestID, att, fmt.Errorf("graph: Microsoft Graph refused the request with %d: %w", resp.StatusCode, ErrNativeDenial)
	case resp.StatusCode != http.StatusOK:
		return page{}, requestID, att, fmt.Errorf("graph: Microsoft Graph answered %d: %w", resp.StatusCode, adapter.ErrDependencyUnavailable)
	}
	var p page
	var items []json.RawMessage
	if json.Unmarshal(raw, &p) != nil || json.Unmarshal(p.Value, &items) != nil || items == nil {
		return page{}, requestID, task.Result{Sent: true}, fmt.Errorf("graph: the answer is not a page of messages: %w", adapter.ErrDependencyUnavailable)
	}
	p.count = len(items)
	return p, requestID, att, nil
}

// StatusOf is the gateway's answer to the agent for an execution error, with
// the fields it carries (GR-34): 200 for none, 401 with WWW-Authenticate
// for an interaction requirement (GR-10), 503 with Retry-After for
// throttling (GR-25), 403 for a native denial, an executor mismatch or a
// context mismatch, 400 for a malformed request, 422 for a request no row
// selects, and 503 for a dependency that cannot answer. A refusal of the
// task ledger is 403: TASK_LIMIT for its limit labels (draft 13.4), the
// gateway's own native refusal for the others (MO-11).
func StatusOf(err error) (int, http.Header) {
	h := http.Header{}
	var ir *InteractionRequired
	var th *Throttled
	var refusal *task.Refusal
	switch {
	case err == nil:
		return http.StatusOK, h
	case errors.As(err, &ir):
		h.Set("WWW-Authenticate", ir.Challenge)
		return http.StatusUnauthorized, h
	case errors.As(err, &th):
		if _, perr := strconv.Atoi(th.RetryAfter); perr == nil {
			h.Set("Retry-After", th.RetryAfter)
		}
		return http.StatusServiceUnavailable, h
	case errors.Is(err, ErrNativeDenial), errors.Is(err, ErrExecutorMismatch), errors.As(err, &refusal):
		return http.StatusForbidden, h
	}
	switch code, _ := adapter.CodeOf(err); code {
	case adapter.CodeContextMismatch:
		return http.StatusForbidden, h
	case adapter.CodeInvalidMessage:
		return http.StatusBadRequest, h
	case adapter.CodeUnsupportedRequirement:
		return http.StatusUnprocessableEntity, h
	}
	return http.StatusServiceUnavailable, h
}

// Outcome is the determined part of the outcome report of an execution
// (GR-29, GR-30).
type Outcome struct {
	EventKind    core.EventKind
	Result       core.OutcomeResult
	Dimension    core.Dimension
	Details      string
	EvidenceRefs []string
}

// OutcomeOf maps an execution to its report, or false when it produces none
// (GR-30): a completed page is EXECUTION SUCCESS reliability, with details
// "empty" for an empty page (draft 14.5) and otherwise both actors; a native
// denial (a refused or unusable token exchange, Graph's refusal) is
// AUTHORIZATION FAILURE none naming both actors. A token endpoint or Graph
// that cannot answer, throttling, and a refusal before execution produce no
// report (open item OI-3). The evidence is the executor record.
func OutcomeOf(res Result, err error) (Outcome, bool) {
	actors := fmt.Sprintf("original_actor %s; downstream_actor %s %s", res.Executor.Principal, res.Executor.Class, res.Executor.Executor)
	refs := []string{res.Executor.Ref()}
	switch {
	case err == nil:
		o := Outcome{EventKind: core.EventExecution, Result: core.OutcomeSuccess, Dimension: core.DimensionReliability, Details: actors, EvidenceRefs: refs}
		if res.Count == 0 {
			o.Details = "empty"
		}
		return o, true
	case errors.Is(err, ErrNativeDenial):
		return Outcome{EventKind: core.EventAuthorization, Result: core.OutcomeFailure, Dimension: core.DimensionNone, Details: actors, EvidenceRefs: refs}, true
	}
	return Outcome{}, false
}
