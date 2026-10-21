package files

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// ResolveAgentBinding returns the enrolled binding of agent to the user's
// account in realm, through [enroll.Resolver]. The account is shared by every
// agent acting for the user (profile section 7), so the agent ID the request
// names selects the record and a workload alone never names an agent. A
// revoked or compromised binding comes back as that status. A registry that
// cannot answer, a status that is not defined, and a time later than now
// plus the skew are [adapter.ErrDependencyUnavailable].
func (b *Broker) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	bd, err := enroll.Resolver{Registry: b.cfg.Registry}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("files: resolve binding: %w", installed.Dependency(err))
	}
	if !bd.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("files: resolve binding: the registry reports status %q: %w", bd.Status, adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(b.cfg.Clock.Now(), bd.ObservedAt, bd.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("files: resolve binding: %w", err)
	}
	if bd.Status != adapter.BindingUnknown {
		bd.EnrolledElsewhere = false
	}
	return bd, nil
}

// MapOperation derives the operation context of draft 10.2 from the request,
// the authenticated principal and the installed mapping revision. Revision
// pact-files-1 serves route R1 only: a request with a query, another method
// or another path violates that mapping and is [adapter.ErrInvalidMessage]
// (draft 13.4, profile section 2). Another installed revision maps by its
// routes ([installed.MapRequest]). An uninstalled revision is
// [adapter.ErrUnsupportedRequirement]; a principal of another realm is
// [adapter.ErrContextMismatch].
func (b *Broker) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("files: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := b.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("files: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != b.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("files: the principal does not belong to the broker's realm: %w", adapter.ErrContextMismatch)
	}
	strict := mappingVersion == MappingRevision
	if strict && (r.URL.RawQuery != "" || r.URL.ForceQuery) {
		return core.OperationContext{}, fmt.Errorf("files: a query violates mapping %s: %w", MappingRevision, adapter.ErrInvalidMessage)
	}
	op, err := installed.MapRequest(b.bindingConfig(mappingVersion), routes, b.cfg.Realm.EnvironmentID, r, p)
	if strict && errors.Is(err, adapter.ErrUnsupportedRequirement) {
		return core.OperationContext{}, fmt.Errorf("files: %v; the request violates mapping %s: %w", err, MappingRevision, adapter.ErrInvalidMessage)
	}
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("files: %w", err)
	}
	return op, nil
}

// ReadNativeClaim reads the value at nativePath for the claim context.
//
// [PathPrincipalID] and [PathGroupIDs] are read from the access token of the
// principal's completed context: the files identifier of the token's user,
// and those of its groups in token order. Their observation and status time
// is the instant the exchange completed, never the time of the read, and the
// source reference names the token and that instant (profile F2). A
// principal of another realm is [adapter.ErrContextMismatch]; one without a
// current context is [adapter.ErrDependencyUnavailable]. Another path is
// read from its source in Config.Claims; a path with none is
// [adapter.ErrUnsupportedRequirement].
func (b *Broker) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	if nativePath == PathPrincipalID || nativePath == PathGroupIDs {
		return b.tokenClaim(nativePath, cc.Principal)
	}
	src, ok := b.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("files: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, b.cfg.Clock.Now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("files: read claim: %w", err)
	}
	return c, nil
}

func (b *Broker) tokenClaim(path string, p adapter.Principal) (adapter.NativeClaim, error) {
	if p.ID == "" || p.Realm != b.cfg.Realm {
		return adapter.NativeClaim{}, fmt.Errorf("files: read claim: the principal does not belong to the broker's realm: %w", adapter.ErrContextMismatch)
	}
	c, ok := b.context(p.Realm, p.ID)
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("files: read claim: no current Negotiate context for the principal: %w", adapter.ErrDependencyUnavailable)
	}
	var v any
	if path == PathPrincipalID {
		id, err := PrincipalID(c.Token.User())
		if err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("files: read claim: %v: %w", err, adapter.ErrDependencyUnavailable)
		}
		v = id
	} else {
		groups := []any{}
		for _, g := range c.Token.Groups() {
			id, err := PrincipalID(g)
			if err != nil {
				return adapter.NativeClaim{}, fmt.Errorf("files: read claim: %v: %w", err, adapter.ErrDependencyUnavailable)
			}
			groups = append(groups, id)
		}
		v = groups
	}
	if err := installed.SourceTimes(b.cfg.Clock.Now(), c.CompletedAt); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("files: read claim: %w", err)
	}
	return adapter.NativeClaim{
		Value: v, ObservedAt: c.CompletedAt, StatusCheckedAt: c.CompletedAt, SourceID: ContextSourceID,
		SourceRef: c.Token.Ref() + "@" + strconv.FormatInt(c.CompletedAt.UnixNano(), 10),
	}, nil
}

// CheckContext runs execution-identity-v1 itself and every other check the
// deployment installed under checkID exactly ([installed.RunCheck]).
//
// execution-identity-v1 enters the impersonation window of the operation's
// principal and compares the thread's effective identity with it, opening
// nothing (draft 17.5, profile TA-3, TA-4): PASS when they are equal, FAIL
// with EXECUTOR_MISMATCH when the executor would be another identity, such as
// the service account, and UNKNOWN with DEPENDENCY_UNAVAILABLE when the
// principal has no current context, the window cannot be entered, or the
// broker is unhealthy.
func (b *Broker) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	if checkID != CheckExecutionIdentity {
		return installed.RunCheck(ctx, b.cfg.Checks, b.cfg.Guard, b.cfg.Clock, checkID, in)
	}
	out := adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable), SourceID: ImpersonationSourceID, ObservedAt: b.cfg.Clock.Now()}
	if err := live(ctx, "check"); err != nil {
		return out
	}
	c, ok := b.context(b.cfg.Realm, in.Operation.PrincipalID)
	if !ok {
		return out
	}
	err := b.impersonate(c, func() error { return nil })
	switch {
	case err == nil:
		out.Result, out.ReasonCode = adapter.VerdictPass, installed.CodeRequirementSatisfied
	case errors.Is(err, ErrExecutorMismatch):
		out.Result, out.ReasonCode = adapter.VerdictFail, "EXECUTOR_MISMATCH"
	}
	return out
}

// RecordOutcome signs the observation as an outcome report
// ([installed.Record]). The broker observes the reads it serves, so an
// EXECUTION observation is signed when Config.ExecutionVisible says so.
func (b *Broker) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(b.cfg.Reporting, b.cfg.Realm, b.cfg.ExecutionVisible,
		"the broker is not configured to observe the execution of reads", o, b.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("files: %w", err)
	}
	return rec, nil
}
