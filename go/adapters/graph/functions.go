package graph

import (
	"context"
	"fmt"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// AuthenticateNative authenticates the request with the inbound
// authentication of the authenticating profile, [Config.Authenticator], and
// returns its principal unchanged: this profile authenticates no request
// itself (profile section 1). A nil error with a principal without an id is
// a dependency error, never passed on.
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := installed.Live(ctx); err != nil {
		return adapter.Principal{}, fmt.Errorf("graph: authenticate: %w", err)
	}
	p, err := a.cfg.Authenticator.AuthenticateNative(ctx, r)
	if err != nil {
		return adapter.Principal{}, err
	}
	if p.ID == "" {
		return adapter.Principal{}, fmt.Errorf("graph: authenticate: no principal: %w", adapter.ErrDependencyUnavailable)
	}
	return p, nil
}

// ResolveAgentBinding returns the enrolled binding of the agent to the
// authenticated workload, from the enrollment registry through
// [enroll.Resolver] (profile section 3, support row). The profile claims no
// shared workloads.
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := installed.Live(ctx); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("graph: resolve binding: %w", err)
	}
	b, err := enroll.Resolver{Registry: a.cfg.Enrollments}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("graph: resolve binding: %w", installed.Dependency(err))
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("graph: resolve binding: undefined status: %w", adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("graph: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// MapOperation maps the rows of the adapter's form under pact-graph-1
// (section 2): GD1 or GA1 with exactly [FixedQuery], GD2 or GA2 with exactly
// one page_token whose continuation record is of the same principal, a row
// of the form and the version, and holds a link of the row's downstream
// path; the resource is the user's mailbox in form D and the registered
// mailbox of the workload's binding in form A. Other routes are those of
// [Config.Mappings]. It requests no token and calls no Graph API.
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, version string) (core.OperationContext, error) {
	if err := installed.Live(ctx); err != nil {
		return core.OperationContext{}, fmt.Errorf("graph: map: %w", err)
	}
	op, _, err := a.mapRequest(ctx, r, p, version)
	return op, err
}

// ReadNativeClaim answers [PathExecutionAppID] from the executor registry
// (GR-32) and other paths from their configured sources.
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := installed.Live(ctx); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("graph: read claim: %w", err)
	}
	if nativePath == PathExecutionAppID {
		if cc.Principal.Realm != a.cfg.Realm {
			return adapter.NativeClaim{}, fmt.Errorf("graph: read claim: another realm: %w", adapter.ErrContextMismatch)
		}
		return a.claim(ctx, cc.Principal.ID)
	}
	src, ok := a.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("graph: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("graph: read claim: %w", err)
	}
	return c, nil
}

// CheckContext runs the installed check whose id equals checkID exactly. The
// adapter's own check is [CheckExecutionIdentity] (GR-26); the others, among
// them native-delegation-v1 over the deployment's task registry (GR-27), are
// the deployment's.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// AuthorizeNative returns the decision of the gateway's policy for the
// original principal and the actual operation, unchanged (draft 17.5). It
// requests no token: Graph decides on token B only when the operation is
// executed (GR-3).
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := installed.Live(ctx); err != nil {
		return adapter.Decision{}, fmt.Errorf("graph: authorize: %w", err)
	}
	d, err := installed.Authorize(ctx, a.cfg.Permissions, p, op, a.now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("graph: authorize: %w", err)
	}
	return d, nil
}

// RecordOutcome signs the gateway's observations as outcome reports. The
// executor sends the downstream request, so the adapter observes the
// execution when [Config.ExecutionVisible] is set; otherwise an EXECUTION
// observation gives NoVisibility. Free text and references are cleaned of credential material
// first; [OutcomeOf] gives the fields of an execution (GR-29, GR-30).
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := installed.Live(ctx); err != nil {
		return nil, fmt.Errorf("graph: record outcome: %w", err)
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the gateway does not run the operations in this deployment", o, a.now())
	if err != nil {
		return nil, fmt.Errorf("graph: %w", err)
	}
	return rec, nil
}
