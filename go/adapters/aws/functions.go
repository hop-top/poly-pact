package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// ResolveAgentBinding returns the enrolled binding of agent to the
// authenticated workload in realm, from the enrollment registry through
// [enroll.Resolver], for every evaluation and without a cache (AR-12,
// section 8, F2).
//
// The workload alone never names an agent: the agent ID the presentation
// names selects among the enrollments of the workload. The profile does not
// support roles shared by several agents, so a workload with more than one
// enrollment in force is the registry's configuration error, an error that
// wraps [adapter.ErrUnsupportedRequirement], for whichever agent (IM-19). A
// revoked or compromised binding comes back as that status, never as active.
// A registry that cannot answer, a status that is not defined, and a time
// later than now plus the skew are [adapter.ErrDependencyUnavailable]. No
// AWS credential is a holder key (AR-12): the key is the enrolled one.
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Registry}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("aws: resolve binding: %w", installed.Dependency(err))
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("aws: resolve binding: the registry reports status %q: %w", b.Status, adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("aws: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// ReadNativeClaim reads the value at nativePath for the claim context.
//
// The paths of AR-25 are answered from a principal this adapter
// authenticated in the gateway's realm: [PathPrincipalID] is its identifier,
// [PathWorkloadRole] the role ARN of its role entry and [PathAccountID] its
// account. The claim has no observation time, because the event carries no
// issue time of the session, and its status time is
// requestContext.timeEpoch minus the propagation bound L (freshness section
// 4.2, convention 1). A principal of another mechanism or realm is
// [adapter.ErrContextMismatch], one without the status time
// [adapter.ErrDependencyUnavailable]. Another path is read from its source in
// [Config.Claims]; a path with none is [adapter.ErrUnsupportedRequirement].
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	switch nativePath {
	case PathPrincipalID, PathWorkloadRole, PathAccountID:
		return a.iamClaim(nativePath, cc.Principal)
	}
	src, ok := a.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("aws: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("aws: read claim: %w", err)
	}
	return c, nil
}

func (a *Adapter) iamClaim(nativePath string, p adapter.Principal) (adapter.NativeClaim, error) {
	if p.Mechanism != Mechanism || p.Realm != a.cfg.Realm || p.ID == "" || string(p.Workload) != p.ID || !strings.HasPrefix(p.ID, "aws:") {
		return adapter.NativeClaim{}, fmt.Errorf("aws: read claim: the principal was not authenticated by this adapter: %w", adapter.ErrContextMismatch)
	}
	attr, _ := p.Attributes[AttrIAM].(map[string]any)
	account, _ := attr["account_id"].(string)
	role, _ := attr["role_arn"].(string)
	status, ok := unixOf(attr["status_time"])
	if !ok || account == "" || role == "" {
		return adapter.NativeClaim{}, fmt.Errorf("aws: read claim: the principal carries no IAM context: %w", adapter.ErrDependencyUnavailable)
	}
	if WorkloadID(account, role) != p.ID {
		return adapter.NativeClaim{}, fmt.Errorf("aws: read claim: the principal's IAM context names another role: %w", adapter.ErrContextMismatch)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), status); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("aws: read claim: %w", err)
	}
	c := adapter.NativeClaim{StatusCheckedAt: status, SourceID: sourceIAMContext}
	switch nativePath {
	case PathPrincipalID:
		c.Value = p.ID
	case PathWorkloadRole:
		c.Value = role
	case PathAccountID:
		c.Value = account
	}
	return c, nil
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

// CheckContext runs the check installed under checkID exactly
// ([installed.RunCheck]): the adapter's own [CheckExecutionIdentity] or one
// the deployment installed. native-principal-binding-v1 is the validator's
// (AR-26), so it is UNKNOWN with UNSUPPORTED_REQUIREMENT here unless the
// deployment installed it.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// executionCheck is execution-identity-v1 (draft 17.5, AR-22): PASS only
// when the identity the function would run the operation under is the
// declared execution role; FAIL with EXECUTOR_MISMATCH for any other
// identity, a role of the role table, a broader role, or a credential of the
// caller; UNKNOWN with DEPENDENCY_UNAVAILABLE when the executor cannot be
// established. The outcome's source reference names the identity, the record
// of the actual executor (draft 14.2).
type executionCheck struct{ a *Adapter }

func (c executionCheck) Consult(ctx context.Context, _ adapter.CheckInput) (installed.CheckRecord, error) {
	id, err := c.a.cfg.Executor.RunningIdentity(ctx)
	if err != nil {
		return installed.CheckRecord{SourceID: sourceExecutor}, installed.Dependency(err)
	}
	if id == "" {
		return installed.CheckRecord{SourceID: sourceExecutor}, fmt.Errorf("aws: the executor cannot be established: %w", adapter.ErrDependencyUnavailable)
	}
	rec := installed.CheckRecord{SourceID: sourceExecutor, SourceRef: id, ObservedAt: c.a.cfg.Clock.Now()}
	if id == c.a.cfg.ExecutionRoleARN {
		rec.Result, rec.ReasonCode = adapter.VerdictPass, installed.CodeRequirementSatisfied
	} else {
		rec.Result, rec.ReasonCode = adapter.VerdictFail, CodeExecutorMismatch
	}
	return rec, nil
}

// AuthorizeNative asks the business handler's permission check about the
// original principal and the actual operation and returns its decision
// unchanged ([installed.Authorize]); a denial is final (AR-21). The adapter
// never runs the operation.
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	d, err := installed.Authorize(ctx, a.cfg.Permissions, p, op, a.cfg.Clock.Now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("aws: authorize: %w", err)
	}
	return d, nil
}

// RecordOutcome signs the observation as an outcome report
// ([installed.Record]). Execution is reported by the handler, so an
// EXECUTION observation gives NoVisibility unless [Config.ExecutionVisible]
// is set.
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the adapter does not observe the execution of the operation; the business handler reports it", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("aws: %w", err)
	}
	return rec, nil
}
