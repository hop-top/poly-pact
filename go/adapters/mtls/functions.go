package mtls

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// ResolveAgentBinding returns the enrolled binding of agent to the
// authenticated workload in realm, from the enrollment registry through
// [enroll.Resolver], for every request and without a cache (MTLS-8).
//
// The workload alone never names an agent: the agent ID the request names
// selects among the enrollments of the workload. The profile does not support
// workloads shared by several agents, so a workload with more than one
// enrollment in force is the registry's configuration error, an error that
// wraps [adapter.ErrUnsupportedRequirement], for whichever agent (IM-19). A
// revoked or compromised binding comes back as that status, never as active.
// A registry that cannot answer, a status that is not defined, and a time
// later than now plus the skew are [adapter.ErrDependencyUnavailable]. The
// adapter does not compare the holder key with the TLS key: the validator
// does, with the principal's cnf attribute (MTLS-9).
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Registry}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("mtls: resolve binding: %w", installed.Dependency(err))
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("mtls: resolve binding: the registry reports status %q: %w", b.Status, adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("mtls: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// MapOperation derives the operation context of draft 10.2 from the request,
// the authenticated principal and the installed mapping revision, with the
// baseline HTTP mapping of package binding and the route table of the
// revision ([installed.MapRequest]). An uninstalled revision is
// [adapter.ErrUnsupportedRequirement]; a principal of another realm is
// [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("mtls: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("mtls: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("mtls: the principal does not belong to the listener's realm: %w", adapter.ErrContextMismatch)
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), routes, a.cfg.Realm.EnvironmentID, r, p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("mtls: %w", err)
	}
	return op, nil
}

// ReadNativeClaim reads the value at nativePath for the claim context.
//
// [PathWorkloadID] is the identifier of MTLS-6 of a principal this adapter
// authenticated in the listener's realm, with the observation and status
// times that authentication established for it (MTLS-30): on a direct
// listener the first evaluation of the connection and the status time of its
// record, on a terminated listener no observation time and the status time of
// the snapshot used. A principal without those times is
// [adapter.ErrDependencyUnavailable], and one of another mechanism or realm
// [adapter.ErrContextMismatch]. Another path is read from its source in
// [Config.Claims]; a path with none is [adapter.ErrUnsupportedRequirement].
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	if nativePath == PathWorkloadID {
		return a.workloadClaim(cc.Principal)
	}
	src, ok := a.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("mtls: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("mtls: read claim: %w", err)
	}
	return c, nil
}

// statusSourceID names the source of the workload identifier: the TLS state
// of the request with the status of the pinned CA's list.
const statusSourceID = "mtls-peer-certificate"

func (a *Adapter) workloadClaim(p adapter.Principal) (adapter.NativeClaim, error) {
	if p.Mechanism != Mechanism || p.Realm != a.cfg.Realm || p.ID == "" || string(p.Workload) != p.ID || !strings.HasPrefix(p.ID, "mtls:") {
		return adapter.NativeClaim{}, fmt.Errorf("mtls: read claim: the principal was not authenticated by this listener: %w", adapter.ErrContextMismatch)
	}
	status, _ := p.Attributes[AttrStatus].(map[string]any)
	statusTime, ok := unixOf(status["status_time"])
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("mtls: read claim: the principal carries no status time: %w", adapter.ErrDependencyUnavailable)
	}
	observed, _ := unixOf(status["observed_at"])
	if err := installed.SourceTimes(a.cfg.Clock.Now(), observed, statusTime); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("mtls: read claim: %w", err)
	}
	return adapter.NativeClaim{Value: p.ID, ObservedAt: observed, StatusCheckedAt: statusTime, SourceID: statusSourceID}, nil
}

// unixOf reads a Unix-seconds attribute value.
func unixOf(v any) (time.Time, bool) {
	switch n := v.(type) {
	case int64:
		return time.Unix(n, 0), true
	case float64:
		return time.Unix(int64(n), 0), true
	}
	return time.Time{}, false
}

// CheckContext runs the check the deployment installed under checkID exactly
// ([installed.RunCheck]). The profile installs no check of its own:
// native-principal-binding-v1 is the validator's (MTLS-31), so it is UNKNOWN
// with UNSUPPORTED_REQUIREMENT here unless the deployment installed it.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.cfg.Checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// AuthorizeNative asks the native permission lookup about the original
// principal and the actual operation and returns its decision unchanged
// ([installed.Authorize]); the adapter never runs the operation.
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	d, err := installed.Authorize(ctx, a.cfg.Permissions, p, op, a.cfg.Clock.Now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("mtls: authorize: %w", err)
	}
	return d, nil
}

// RecordOutcome signs the observation as an outcome report ([installed.Record]).
// Execution is reported by the backend, so an EXECUTION observation gives
// NoVisibility unless [Config.ExecutionVisible] is set.
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the gateway does not observe the execution of the read; the backend reports it", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("mtls: %w", err)
	}
	return rec, nil
}
