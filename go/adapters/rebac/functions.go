package rebac

import (
	"context"
	"fmt"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// AuthenticateNative authenticates the request with the deployment's identity
// mechanism, [Config.Authenticator], and returns its principal unchanged: the
// relationship store authenticates nobody, and its subject is a mapped fact,
// never an identifier (profile section 3, section 7). A nil error with a
// principal without an id is reported as a dependency error, never passed
// on.
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	p, err := a.cfg.Authenticator.AuthenticateNative(ctx, r)
	if err != nil {
		return adapter.Principal{}, err
	}
	if p.ID == "" {
		return adapter.Principal{}, fmt.Errorf("rebac: authenticate: the identity mechanism returned no principal: %w", adapter.ErrDependencyUnavailable)
	}
	return p, nil
}

// ResolveAgentBinding returns the enrolled binding of agent to the
// authenticated workload in realm, from the enrollment registry through
// [enroll.Resolver]. The relationship store is not an enrollment source.
//
// The workload alone never names an agent. The profile inherits the
// shared-account choice of the authenticating mechanism (section 7) and this
// adapter claims none, so a workload with more than one enrollment in force
// is the registry's configuration error, an error that wraps
// [adapter.ErrUnsupportedRequirement] (identity mapping IM-19). A registry that
// cannot answer, an undefined status, and a time later than now plus the
// skew are [adapter.ErrDependencyUnavailable].
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Enrollments}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("rebac: resolve binding: %w", installed.Dependency(err))
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("rebac: resolve binding: the registry reports an undefined status: %w", adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("rebac: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// MapOperation derives the operation context of draft 10.2 with the baseline
// HTTP mapping of package binding and the route table of the installed
// revision: the action comes from the method and the path, never from the
// request's text, so an edit is document.write whatever presentation it
// carries (profile RB-5, RB-18). A request the baseline mapping refuses is
// [adapter.ErrInvalidMessage]; an uninstalled revision and a request no route
// matches are [adapter.ErrUnsupportedRequirement]; a principal of another
// realm is [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("rebac: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("rebac: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("rebac: the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), routes, a.cfg.Realm.EnvironmentID, r, p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("rebac: %w", err)
	}
	return op, nil
}

// ReadNativeClaim reads an approved native path from its configured source,
// with the times the source gives (draft 17.1). The relationship store is not
// read through this function (profile RB-14, section 3): its answer is a
// decision, not a field value. A path without a source is
// [adapter.ErrUnsupportedRequirement].
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	src, ok := a.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("rebac: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("rebac: read claim: %w", err)
	}
	return c, nil
}

// CheckContext runs the installed check whose id equals checkID exactly; any
// other id is UNKNOWN with UNSUPPORTED_REQUIREMENT. The profile's checks
// native-principal-binding-v1, native-delegation-v1 and execution-identity-v1
// are the deployment's (section 3).
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.cfg.Checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// RecordOutcome signs admission and authorization observations as outcome
// reports. The gateway does not run the document operation (profile section
// 3), so an EXECUTION observation gives NoVisibility unless
// [Config.ExecutionVisible] is set. Free text and references are cleaned of
// credential material first.
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the gateway does not observe the document operation; the document service reports it", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("rebac: %w", err)
	}
	return rec, nil
}
