package ldap

import (
	"context"
	"fmt"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// ResolveAgentBinding returns the enrolled binding of agent to the
// authenticated directory account in realm, from the enrollment registry
// through [enroll.Resolver]. The directory is not an enrollment source and
// never marks a binding (profile LR-29).
//
// The account alone never names an agent: the agent ID the request names
// selects among the account's enrollments. The profile does not support
// accounts shared by several agents, so an account with more than one
// enrollment in force is the registry's configuration error, an error that
// wraps [adapter.ErrUnsupportedRequirement], for whichever agent (identity
// mapping IM-19). A registry that cannot answer, an undefined status, and a
// time later than now plus the skew are [adapter.ErrDependencyUnavailable].
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Registry}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("ldap: resolve binding: %w", installed.Dependency(err))
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, outage("resolve binding", "the registry reports an undefined status")
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("ldap: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// Route maps a method and a path template to an action and a resource
// template.
type Route = installed.Route

// StockRoutes is the route table of mapping revision pact-ldap-1: route R1 of
// the profile, GET /api/v1/warehouses/{warehouse_id}/stock, the action
// stock.read on the resource warehouse:{warehouse_id} (profile section 2).
func StockRoutes() []Route {
	return []Route{{
		Method: http.MethodGet, Path: "/api/v1/warehouses/{warehouse_id}/stock",
		Action: "stock.read", Resource: "warehouse:{warehouse_id}",
	}}
}

// MapOperation derives the operation context of draft 10.2 with the baseline
// HTTP mapping of package binding and the route table of the installed
// revision. A request the baseline mapping refuses is
// [adapter.ErrInvalidMessage]; an uninstalled revision and a request no route
// matches are [adapter.ErrUnsupportedRequirement]; a principal of another
// realm is [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("ldap: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("ldap: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("ldap: the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), routes, a.cfg.Realm.EnvironmentID, r, p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("ldap: %w", err)
	}
	return op, nil
}

// PermissionLookup is the application's native authorization.
type PermissionLookup = installed.PermissionLookup

// AuthorizeNative asks the application's native authorization about the
// original principal and the actual operation and returns its decision
// unchanged (draft 4.3, 17.1). The lookup account is never passed: the
// adapter has no path that substitutes it (profile LR-13). A decision that
// names no source, has no defined effect, or was made later than now plus
// the skew is [adapter.ErrDependencyUnavailable].
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	d, err := installed.Authorize(ctx, a.cfg.Permissions, p, op, a.cfg.Clock.Now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("ldap: authorize: %w", err)
	}
	return d, nil
}

// RecordOutcome signs admission and authorization observations as outcome
// reports. The directory adds no execution visibility (profile section 3), so
// an EXECUTION observation gives NoVisibility unless
// [Config.ExecutionVisible] is set. Free text and references are cleaned of
// credential material first.
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the gateway does not observe the execution of the stock read; the application reports it", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("ldap: %w", err)
	}
	return rec, nil
}

// Reason codes of check outcomes.
const (
	// CodeRequirementSatisfied is the reason of a PASS.
	CodeRequirementSatisfied = installed.CodeRequirementSatisfied
	// CodeExecutorMismatch is the reason code of draft 17.5 for an executor
	// that is not the declared one.
	CodeExecutorMismatch = "EXECUTOR_MISMATCH"
)

// CheckIDExecutionIdentity is the id of the baseline check of draft 17.5.
const CheckIDExecutionIdentity = "execution-identity-v1"

// Check is the native implementation of an installed context check.
type Check = installed.Check

// CheckRecord is what a [Check] found.
type CheckRecord = installed.CheckRecord

// InstalledCheck is a check as the gateway installed it.
type InstalledCheck = installed.InstalledCheck

// Freshness is a pair of age limits in seconds.
type Freshness = installed.Freshness

// CheckContext runs the installed check whose id equals checkID exactly; any
// other id is UNKNOWN with UNSUPPORTED_REQUIREMENT. The profile adds no check
// of its own (section 3).
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.cfg.Checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// ExecutorSource reports the identity under which the application would run
// the operation.
type ExecutorSource interface {
	// RunningIdentity returns that identity as an identifier of the profile.
	// An error means it cannot be established.
	RunningIdentity(ctx context.Context, op core.OperationContext) (string, error)
}

// ExecutionIdentity is execution-identity-v1 (draft 17.5) for route R1, whose
// mapping declares the authenticated account itself as the executor: PASS
// only when the running identity is the operation's principal and not a
// denied principal; any other identity, the lookup account among them, is
// FAIL with EXECUTOR_MISMATCH (profile LR-13); an identity that cannot be
// established is UNKNOWN with DEPENDENCY_UNAVAILABLE. sourceID names the
// executor source; denied lists the denied principals of every realm.
func ExecutionIdentity(src ExecutorSource, sourceID string, denied []string, clk clock.Clock) Check {
	return executionCheck{src: src, sourceID: sourceID, denied: denied, clk: clk}
}

type executionCheck struct {
	src      ExecutorSource
	sourceID string
	denied   []string
	clk      clock.Clock
}

func (c executionCheck) Consult(ctx context.Context, in adapter.CheckInput) (CheckRecord, error) {
	op := in.Operation
	id, err := c.src.RunningIdentity(ctx, op)
	if err != nil {
		return CheckRecord{SourceID: c.sourceID}, installed.Dependency(err)
	}
	if id == "" {
		return CheckRecord{SourceID: c.sourceID}, fmt.Errorf("ldap: the executor cannot be established: %w", adapter.ErrDependencyUnavailable)
	}
	now := c.clk.Now()
	rec := CheckRecord{SourceID: c.sourceID, ObservedAt: now, StatusCheckedAt: now,
		Result: adapter.VerdictFail, ReasonCode: CodeExecutorMismatch}
	isDenied := false
	for _, d := range c.denied {
		isDenied = isDenied || d == id || d == op.PrincipalID
	}
	if id == op.PrincipalID && op.PrincipalID != "" && !isDenied {
		rec.Result, rec.ReasonCode = adapter.VerdictPass, CodeRequirementSatisfied
	}
	return rec, nil
}
