package db

import (
	"context"
	"fmt"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// AuthenticateNative authenticates the request with the front-door
// authentication the deployment names, [Config.Authenticator], and returns
// its principal unchanged: this profile does not define that mechanism
// (profile section 1), and the login role is the executor, never the
// principal (RB-26). A nil error with a principal without an id is reported
// as a dependency error, never passed on.
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	p, err := a.cfg.Authenticator.AuthenticateNative(ctx, r)
	if err != nil {
		return adapter.Principal{}, err
	}
	if p.ID == "" {
		return adapter.Principal{}, fmt.Errorf("db: authenticate: the front door returned no principal: %w", adapter.ErrDependencyUnavailable)
	}
	return p, nil
}

// ResolveAgentBinding returns the enrolled binding of agent to the
// authenticated workload in realm, from the enrollment registry through
// [enroll.Resolver] (profile section 3, support row). The role registry is
// not an enrollment source. The adapter claims no shared workloads, so a
// workload with more than one enrollment in force is the registry's
// configuration error, [adapter.ErrUnsupportedRequirement].
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Enrollments}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("db: resolve binding: %w", installed.Dependency(err))
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("db: resolve binding: the registry reports an undefined status: %w", adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("db: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// ReadNativeClaim reads an approved native path. The role and tenant
// registry answers [PathDatabaseRole] with the executor identifier
// db:{cluster-id}:{login-role} and [PathTenantID] with the principal's
// tenant, for the principal of the claim context (F1): observed at the
// record's last change and status-checked at the read, a lookup of the
// current record, with the registry revision as the source reference. Other
// paths come from their configured sources; a path without one is
// [adapter.ErrUnsupportedRequirement]. No connection is opened.
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	switch nativePath {
	case PathDatabaseRole, PathTenantID:
		now := a.cfg.Clock.Now()
		rec, err := a.lookup(ctx, cc.Principal.Realm, cc.Principal.ID)
		if err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("db: read claim: %w", err)
		}
		c := adapter.NativeClaim{Value: Identifier(rec.ClusterID, rec.LoginRole), ObservedAt: rec.ChangedAt, StatusCheckedAt: now, SourceID: SourceRegistry, SourceRef: rec.Revision}
		if nativePath == PathTenantID {
			c.Value = rec.TenantID
		}
		return c, nil
	}
	src, ok := a.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("db: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("db: read claim: %w", err)
	}
	return c, nil
}

// CheckContext runs the installed check whose id equals checkID exactly;
// any other id is UNKNOWN with UNSUPPORTED_REQUIREMENT. The adapter's own
// check is [CheckExecutionIdentity] at evaluation (RA-5); the others are the
// deployment's.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// identityCheck is execution-identity-v1 at evaluation (profile RA-5): PASS
// only when the registry maps the operation's principal to a login role of
// the cluster, the operation's action has a query registry entry, whose
// executor class is dedicated-role, and the broker holds a pool for the
// role. It opens no connection: one is acquired only after admission (CR-2),
// and CV-1 to CV-7 apply the check again to that connection.
type identityCheck struct{ a *Adapter }

func (c identityCheck) Consult(ctx context.Context, in adapter.CheckInput) (CheckRecord, error) {
	op := in.Operation
	a := c.a
	if op.EnvironmentID != a.cfg.Realm.EnvironmentID {
		return CheckRecord{Result: adapter.VerdictFail, ReasonCode: string(adapter.CodeContextMismatch), SourceID: SourceRegistry}, nil
	}
	if _, ok := a.queries[queryKey{op.Action, a.cfg.Revision}]; !ok {
		return CheckRecord{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeUnsupportedRequirement), SourceID: SourceRegistry}, nil
	}
	rec, err := a.lookup(ctx, a.cfg.Realm, op.PrincipalID)
	if err != nil {
		return CheckRecord{SourceID: SourceRegistry}, err
	}
	if _, err := a.pool(ctx, rec); err != nil {
		return CheckRecord{SourceID: SourceRegistry}, err
	}
	return CheckRecord{
		Result: adapter.VerdictPass, ReasonCode: installed.CodeRequirementSatisfied,
		SourceID: SourceRegistry, SourceRef: rec.Revision, ObservedAt: rec.ChangedAt,
	}, nil
}

// AuthorizeNative returns the decision of the broker's native task policy,
// [Config.Permissions], for the original principal and the actual
// operation, unchanged, with its obligations and provenance (profile
// section 3, row 4). It opens no connection: PostgreSQL's privilege and
// row-policy checks apply when Execute runs the statement under the mapped
// role, never as an authorization of another identity (draft 17.5).
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	d, err := installed.Authorize(ctx, a.cfg.Permissions, p, op, a.cfg.Clock.Now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("db: authorize: %w", err)
	}
	return d, nil
}

// RecordOutcome signs the broker's observations as outcome reports. The
// broker runs the statement, so it observes the execution when
// [Config.ExecutionVisible] is set; otherwise an EXECUTION observation gives
// NoVisibility. Free text and references are cleaned of credential material
// first. The observation carries what [OutcomeOf] gives and the reference of
// the [ExecutorRecord], never row content (RS-5, RS-6).
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the broker does not observe the execution in this deployment", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	return rec, nil
}
