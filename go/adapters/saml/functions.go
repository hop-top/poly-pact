package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// Reason codes of the outcomes of [CheckNativeDelegation]. Draft 17.5 fixes
// TASK_MISMATCH for a changed task and STALE_EVIDENCE or REVOKED_EVIDENCE for
// a stale or revoked delegation; they are check codes, not transport codes.
const (
	CodeTaskMismatch    = "TASK_MISMATCH"
	CodeStaleEvidence   = "STALE_EVIDENCE"
	CodeRevokedEvidence = "REVOKED_EVIDENCE"
	// CodeMissingField is the reason of an operation under a task that has
	// no grant: the required native delegation is absent.
	CodeMissingField = "MISSING_FIELD"
	// CodeRequirementSatisfied is the reason of a usable grant (draft
	// 17.3.1).
	CodeRequirementSatisfied = "REQUIREMENT_SATISFIED"
)

// sourceTimes refuses source times later than now plus the skew.
var sourceTimes = installed.SourceTimes

// MapOperation derives the operation context of draft 10.2 from the request,
// the authenticated principal and the installed mapping revision: the
// baseline HTTP mapping of package binding, with the action and the resource
// from the route of the installed table, never from the client. A request the
// baseline mapping refuses is an error that wraps [adapter.ErrInvalidMessage];
// an uninstalled revision and a request no route matches are
// [adapter.ErrUnsupportedRequirement]; a principal of another realm is
// [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("saml: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("saml: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("saml: the principal does not belong to the broker's realm: %w", adapter.ErrContextMismatch)
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), routes, a.cfg.Realm.EnvironmentID, r, p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("saml: %w", err)
	}
	return op, nil
}

// ReadNativeClaim reads the value at nativePath in the claim context.
//
// [PathPrincipalID] and [PathIDPRealm] are facts of the session that the grant
// of the intent's task records (profile annex F): ClaimContext.Intent.TaskID
// names the grant, and the session is read live, so the observation time and
// the status time are both the time of the read and the source reference is
// empty (SB-23). The session must be live and its principal must be the
// grant's user and the context's principal; a principal of another realm, or
// another principal, is [adapter.ErrContextMismatch], and a task with no
// usable grant and session has no value, an error that carries no code. A
// path of [Config.DirectoryPaths] is read from the directory adapter, whose
// value and times are returned as it gives them and never replaced by the
// login time or the time of a session read (SB-22); a value that names no
// source or carries a time later than now plus the skew is
// [adapter.ErrDependencyUnavailable]. Any other path is
// [adapter.ErrUnsupportedRequirement].
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	switch {
	case nativePath == PathPrincipalID || nativePath == PathIDPRealm:
		return a.sessionClaim(ctx, nativePath, cc)
	case slices.Contains(a.cfg.DirectoryPaths, nativePath):
		c, err := a.cfg.Directory.ReadNativeClaim(ctx, nativePath, cc)
		if err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("saml: read claim: directory: %w", err)
		}
		if c.SourceID == "" {
			return adapter.NativeClaim{}, fmt.Errorf("saml: read claim: the directory value names no source: %w", adapter.ErrDependencyUnavailable)
		}
		if err := sourceTimes(a.now(), c.ObservedAt, c.StatusCheckedAt); err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("saml: read claim: directory: %w", err)
		}
		return c, nil
	}
	return adapter.NativeClaim{}, fmt.Errorf("saml: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
}

// sessionClaim reads an approved path of the session store.
func (a *Adapter) sessionClaim(ctx context.Context, path string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if cc.Principal.Realm != a.cfg.Realm {
		return adapter.NativeClaim{}, fmt.Errorf("saml: read claim: the principal does not belong to the broker's realm: %w", adapter.ErrContextMismatch)
	}
	if cc.Intent.TaskID == "" {
		return adapter.NativeClaim{}, errors.New("saml: read claim: the intent names no task, so no session")
	}
	_, s, err := a.grantSession(ctx, cc.Intent.TaskID)
	switch {
	case errors.Is(err, errNotUsable):
		return adapter.NativeClaim{}, errors.New("saml: read claim: the task has no live session")
	case err != nil:
		return adapter.NativeClaim{}, dependency("read claim", err)
	case cc.Principal.ID != s.Principal:
		return adapter.NativeClaim{}, fmt.Errorf("saml: read claim: the principal is not the principal of the task's session: %w", adapter.ErrContextMismatch)
	}
	now := a.now()
	claim := adapter.NativeClaim{ObservedAt: now, StatusCheckedAt: now, SourceID: a.cfg.Sessions.SourceID()}
	if path == PathPrincipalID {
		claim.Value = s.Principal
	} else {
		claim.Value = s.IDPRealm
	}
	return claim, nil
}

// CheckContext runs the installed check whose id equals checkID exactly:
// [CheckNativeDelegation], evaluated by the adapter or, when
// [Config.DelegationCheck] is set, by that check, or a check of
// [Config.Checks], with the rules of package installed. A check that is not installed is UNKNOWN with
// UNSUPPORTED_REQUIREMENT.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	if checkID == CheckNativeDelegation {
		if dc := a.cfg.DelegationCheck; dc != nil {
			own := map[string]InstalledCheck{CheckNativeDelegation: *dc}
			return installed.RunCheck(ctx, own, a.cfg.Guard, a.cfg.Clock, checkID, in)
		}
		return a.nativeDelegation(ctx, in)
	}
	return installed.RunCheck(ctx, a.cfg.Checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// nativeDelegation evaluates the grant of the operation (SB-11).
//
// The grant is the one the operation's route names, the grant that
// authentication resolved (SB-16): the {task_id} segment of the installed
// route that the operation's method and the path of its target URI match. An
// operation on no such route is UNKNOWN with UNSUPPORTED_REQUIREMENT. The
// grant and its session are read live; a store that cannot answer is UNKNOWN
// with DEPENDENCY_UNAVAILABLE (SB-18). Then, in the order of SB-11: FAIL with
// MISSING_FIELD when the task has no grant; FAIL with REVOKED_EVIDENCE when
// the grant is revoked or its session is not live (SB-10); FAIL with
// STALE_EVIDENCE when now is not before the grant's expires_at, with no
// grace; FAIL with TASK_MISMATCH when the intent's task is not the grant's;
// FAIL with CONTEXT_MISMATCH when the grant's agent is not the agent of the
// binding the check receives (an empty binding never matches), when the
// operation's principal is not the grant's user or the user is not the
// session's principal, and when the intent's purpose, the operation's action
// or one of its resources is not in the grant's scope. A grant that meets
// every condition is PASS with REQUIREMENT_SATISFIED. Authentication serves a
// grant only to its agent (SB-16); the comparison with the binding repeats
// it from the input the validator established.
func (a *Adapter) nativeDelegation(ctx context.Context, in adapter.CheckInput) adapter.CheckOutcome {
	intent, op := in.Intent, in.Operation
	src := a.cfg.Grants.SourceID()
	// The stores are read live, so the observation time of an outcome that
	// rests on them is the time of the read (profile section 8, F1, F2).
	outcome := func(v adapter.Verdict, code string) adapter.CheckOutcome {
		return adapter.CheckOutcome{Result: v, ReasonCode: code, SourceID: src, ObservedAt: a.now()}
	}
	if ctx.Err() != nil {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable), SourceID: src}
	}
	task, ok := a.operationTask(op)
	if !ok {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeUnsupportedRequirement), SourceID: src}
	}
	g, err := a.cfg.Grants.Grant(ctx, task)
	switch {
	case errors.Is(err, ErrNoGrant):
		return outcome(adapter.VerdictFail, CodeMissingField)
	case err != nil || g.TaskID != task:
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable), SourceID: src}
	}
	s, err := a.cfg.Sessions.Session(ctx, g.SessionID)
	sessionLive := err == nil && s.SessionID == g.SessionID && s.Live(a.now())
	if err != nil && !errors.Is(err, ErrNoSession) {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable), SourceID: src}
	}
	switch {
	case g.Revoked || !sessionLive:
		return outcome(adapter.VerdictFail, CodeRevokedEvidence)
	case !a.now().Before(g.ExpiresAt):
		return outcome(adapter.VerdictFail, CodeStaleEvidence)
	case intent.TaskID != g.TaskID:
		return outcome(adapter.VerdictFail, CodeTaskMismatch)
	case g.AgentID != in.Binding.AgentID:
		return outcome(adapter.VerdictFail, string(adapter.CodeContextMismatch))
	case op.PrincipalID != g.User || g.User != s.Principal:
		return outcome(adapter.VerdictFail, string(adapter.CodeContextMismatch))
	case !g.Scope.permits(intent, op):
		return outcome(adapter.VerdictFail, string(adapter.CodeContextMismatch))
	}
	return outcome(adapter.VerdictPass, CodeRequirementSatisfied)
}

// permits reports whether the intent's purpose, the operation's action and
// each of its resources are in the scope, compared exactly (SB-11, condition
// 6). A nil scope permits the whole mapping.
func (sc *GrantScope) permits(intent core.Intent, op core.OperationContext) bool {
	if sc == nil {
		return true
	}
	if !slices.Contains(sc.Purposes, intent.PurposeID) || !slices.Contains(sc.Actions, op.Action) {
		return false
	}
	for _, r := range op.Resources {
		if !slices.Contains(sc.Resources, r) {
			return false
		}
	}
	return true
}

// operationTask returns the task reference of an operation: the {task_id}
// segment of the installed route that its method and the escaped path of its
// target URI match.
func (a *Adapter) operationTask(op core.OperationContext) (string, bool) {
	u, err := url.Parse(op.TargetURI)
	if err != nil || u.Scheme != "https" {
		return "", false
	}
	return a.taskOf(op.Method, u.EscapedPath())
}

// AuthorizeNative asks the SP's access policy about the session principal
// and the actual operation and returns its decision unchanged, with its
// obligations and its provenance (draft 4.3, 17.1). The grant adds no native
// authority (SB-13), the broker's own identity is never substituted (draft
// 17.5), and the adapter never runs the operation. A decision that names no
// source, has no defined effect, or was made later than now plus the skew is
// not passed on: the error wraps [adapter.ErrDependencyUnavailable].
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	d, err := installed.Authorize(ctx, a.cfg.Permissions, p, op, a.now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("saml: authorize: %w", err)
	}
	return d, nil
}

// RecordOutcome signs the observation as an outcome report (draft 14.1). The
// adapter reports admission decisions and native authorization results; the
// broker performs the read and reports its execution, so an EXECUTION
// observation gives NoVisibility unless [Config.ExecutionVisible] is set.
// Free text and evidence references are cleaned of credential material first
// (draft 19).
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the broker performs the read under the user's session and reports its execution", o, a.now())
	if err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	return rec, nil
}
