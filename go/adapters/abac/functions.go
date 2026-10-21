package abac

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// AuthenticateNative is the native authentication of the mechanism that
// authenticated the request, which the profile inherits (profile section 7):
// [Config.Authenticator], unchanged. The engine authenticates nobody.
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	return a.cfg.Authenticator.AuthenticateNative(ctx, r)
}

// ResolveAgentBinding is the binding resolution of the authenticating
// mechanism's profile, [Config.Bindings]. A status that is not defined and a
// time later than now plus the skew are [adapter.ErrDependencyUnavailable];
// the report of an enrollment for another workload belongs to UNKNOWN only.
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := a.cfg.Bindings.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		if _, ok := adapter.CodeOf(err); ok {
			return adapter.AgentBinding{}, fmt.Errorf("abac: resolve binding: %w", err)
		}
		return adapter.AgentBinding{}, fmt.Errorf("abac: resolve binding: %w: %w", adapter.ErrDependencyUnavailable, err)
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("abac: resolve binding: status %q: %w", b.Status, adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("abac: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// MapOperation derives the operation context of draft 10.2 from the request,
// the authenticated principal and the installed mapping revision, by the
// baseline HTTP mapping of package binding. The action and the one resource
// come from the route, never from the client (profile section 2). A request
// the baseline mapping refuses is [adapter.ErrInvalidMessage]; an
// uninstalled revision and a request no route matches, such as an export, are
// [adapter.ErrUnsupportedRequirement]; a principal of another realm is
// [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("abac: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("abac: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("abac: the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), routes, a.cfg.Realm.EnvironmentID, r, p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("abac: %w", err)
	}
	return op, nil
}

// ReadNativeClaim reads the value at nativePath for the claim context.
//
// A fact path of this profile is read from its source as the source gives it,
// with its own observation and status times (profile ABAC-9): a subject fact
// for the principal, a resource fact for the one resource of the operation,
// the device compliance for the authenticated device identifier, the zone
// for the authenticated peer address, the time from the gateway clock.
// Nothing the intent, a header or another attribute asserts is read
// (ABAC-1). A fact the source does not hold, and a context without the
// device, the address or the one resource, are
// [adapter.ErrUnsupportedRequirement]. Another path is read from its source
// in [Config.Claims]; a path with none is [adapter.ErrUnsupportedRequirement].
// A source that cannot answer, a claim that names no source, and a time later
// than now plus the skew are [adapter.ErrDependencyUnavailable].
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	if !isFactPath(nativePath) {
		src, ok := a.cfg.Claims[nativePath]
		if !ok {
			return adapter.NativeClaim{}, fmt.Errorf("abac: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
		}
		c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
		if err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("abac: read claim: %w", err)
		}
		return c, nil
	}
	c, err := a.readFact(ctx, nativePath, cc.Principal, cc.Operation)
	switch {
	case errors.Is(err, ErrNoFact):
		return adapter.NativeClaim{}, fmt.Errorf("abac: read claim: %w: %w", adapter.ErrUnsupportedRequirement, err)
	case err != nil:
		return adapter.NativeClaim{}, fmt.Errorf("abac: read claim: %w", installed.Dependency(err))
	case c.SourceID == "":
		return adapter.NativeClaim{}, fmt.Errorf("abac: read claim: the value at %q names no source: %w", nativePath, adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), c.ObservedAt, c.StatusCheckedAt); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("abac: read claim: %w", err)
	}
	return c, nil
}

// CheckContext runs the installed check whose id equals checkID exactly. The
// ABAC check of [Config.Entry] runs on the principal and the operation of in
// (profile ABAC-16, draft 17.1); any other id is a check of [Config.Checks],
// by the rules of package installed: a check that is not installed is UNKNOWN
// with UNSUPPORTED_REQUIREMENT (draft 17.2).
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	if e := a.cfg.Entry; e != nil && checkID == e.CheckID {
		return a.check(ctx, in)
	}
	return installed.RunCheck(ctx, a.cfg.Checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// RecordOutcome signs the observation as an outcome report (draft 14.1). The
// gateway observes admission and authorization; execution is reported by the
// executor's native record (profile ABAC-30), so an EXECUTION observation
// gives NoVisibility unless [Config.ExecutionVisible] is set.
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the executor reports the execution of the read in its native record", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("abac: %w", err)
	}
	return rec, nil
}
