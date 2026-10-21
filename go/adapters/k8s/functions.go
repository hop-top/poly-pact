package k8s

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core"
)

// ResolveAgentBinding returns the enrolled binding of agent to the
// authenticated workload in realm, from the enrollment registry through
// [enroll.Resolver], for every evaluation (KR-10).
//
// The workload alone never names an agent. One registered account serves one
// agent, so a workload with more than one enrollment in force is the
// registry's configuration error, an error that wraps
// [adapter.ErrUnsupportedRequirement], for whichever agent (IM-19). A revoked
// or compromised binding comes back as that status, never as active. A
// registry that cannot answer, a status that is not defined, and a time later
// than now plus the skew are [adapter.ErrDependencyUnavailable]. No token,
// Secret or certificate is a holder key (KR-10).
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Registry}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("k8s: resolve binding: %w", installed.Dependency(err))
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("k8s: resolve binding: the registry reports status %q: %w", b.Status, adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("k8s: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// deploymentName is the grammar of the name parameter of row R2: 1 to 253
// lowercase letters, digits, "-" and ".", beginning and ending with a letter
// or digit (profile section 2).
var deploymentName = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// MapOperation derives the operation context of draft 10.2 with the baseline
// HTTP mapping of package binding and the route table of the installed
// revision ([installed.MapRequest]); the query binds into target_uri as sent
// and is never translated (KR-13, KR-24). Under the reference table, a name
// outside the grammar of R2 matches no row. An uninstalled revision, and a
// request no row matches, are [adapter.ErrUnsupportedRequirement]; a
// principal of another realm is [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("k8s: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("k8s: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("k8s: the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), routes, a.cfg.Realm.EnvironmentID, StripUserHeaders(r), p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("k8s: %w", err)
	}
	if a.cfg.Mappings == nil && op.Action == ActionGet {
		if _, ok := rowName(a.cfg.ClusterID, op.Resources); !ok {
			return core.OperationContext{}, fmt.Errorf("k8s: name outside the grammar of R2: %w", adapter.ErrUnsupportedRequirement)
		}
	}
	return op, nil
}

// rowName returns the deployment name of an R2 resource.
func rowName(clusterID string, resources []string) (string, bool) {
	if len(resources) != 1 {
		return "", false
	}
	name, ok := strings.CutPrefix(resources[0], ResourceBase(clusterID)+"/")
	return name, ok && deploymentName.MatchString(name)
}

// facts are the review facts a principal of this adapter carries.
type facts struct {
	account  Account
	groups   []string
	issuedAt time.Time
	reviewed time.Time
}

// factsOf reads the [AttrK8s] attribute of a principal this adapter
// authenticated in the gateway's realm for a registered account.
func (a *Adapter) factsOf(p adapter.Principal) (facts, bool) {
	if p.Mechanism != Mechanism || p.Realm != a.cfg.Realm || p.ID == "" || string(p.Workload) != p.ID {
		return facts{}, false
	}
	attr, ok := p.Attributes[AttrK8s].(map[string]any)
	if !ok {
		return facts{}, false
	}
	ns, _ := attr["namespace"].(string)
	name, _ := attr["name"].(string)
	uid, _ := attr["uid"].(string)
	cluster, _ := attr["cluster_id"].(string)
	acct, ok := a.accounts[ns+"/"+name]
	if !ok || acct.UID != uid || cluster != a.cfg.ClusterID || Identifier(cluster, ns, name) != p.ID {
		return facts{}, false
	}
	f := facts{account: acct}
	switch g := attr["groups"].(type) {
	case []string:
		f.groups = slices.Clone(g)
	case []any:
		for _, v := range g {
			s, ok := v.(string)
			if !ok {
				return facts{}, false
			}
			f.groups = append(f.groups, s)
		}
	default:
		return facts{}, false
	}
	var ok1, ok2 bool
	f.issuedAt, ok1 = unixOf(attr["issued_at"])
	f.reviewed, ok2 = unixOf(attr["reviewed_at"])
	if !ok1 || !ok2 {
		return facts{}, false
	}
	return f, true
}

// unixOf reads a Unix-seconds attribute value.
func unixOf(v any) (time.Time, bool) {
	switch n := v.(type) {
	case int64:
		return time.Unix(n, 0), true
	case int:
		return time.Unix(int64(n), 0), true
	case float64:
		return time.Unix(int64(n), 0), true
	}
	return time.Time{}, false
}

// ReadNativeClaim reads the value at nativePath for the claim context.
//
// The paths of KR-20 are answered from a principal this adapter
// authenticated: [PathPrincipalID] and [PathNamespace] observed at the
// token's iat and status-checked at the review time minus B, with the source
// [SourceTokenReview]; [PathClusterID] with both times the time of the
// evaluation and the source [SourceClusterEntry]. Any other principal is
// [adapter.ErrContextMismatch]. Another path is read from its source in
// [Config.Claims]; a path with none is [adapter.ErrUnsupportedRequirement].
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	switch nativePath {
	case PathPrincipalID, PathNamespace, PathClusterID:
		f, ok := a.factsOf(cc.Principal)
		if !ok {
			return adapter.NativeClaim{}, fmt.Errorf("k8s: read claim: the principal was not authenticated by this adapter: %w", adapter.ErrContextMismatch)
		}
		now := a.cfg.Clock.Now()
		c := adapter.NativeClaim{ObservedAt: f.issuedAt, StatusCheckedAt: f.reviewed.Add(-a.cfg.ReviewBound), SourceID: SourceTokenReview}
		switch nativePath {
		case PathPrincipalID:
			c.Value = cc.Principal.ID
		case PathNamespace:
			c.Value = f.account.Namespace
		case PathClusterID:
			c = adapter.NativeClaim{Value: a.cfg.ClusterID, ObservedAt: now, StatusCheckedAt: now, SourceID: SourceClusterEntry}
		}
		if err := installed.SourceTimes(now, c.ObservedAt, c.StatusCheckedAt); err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("k8s: read claim: %w", err)
		}
		return c, nil
	}
	src, ok := a.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("k8s: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("k8s: read claim: %w", err)
	}
	return c, nil
}

// CheckContext runs the check installed under checkID exactly
// ([installed.RunCheck]): the adapter's own [CheckExecutionIdentity] or one
// the deployment installed. native-principal-binding-v1 is the validator's
// (KR-21), so it is UNKNOWN with UNSUPPORTED_REQUIREMENT here unless the
// deployment installed it.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// executionCheck is execution-identity-v1 (draft 17.5, KR-11): PASS only when
// the executor of the operation's registered account holds a projected token
// and nothing else and its self-review names that account with its recorded
// uid; FAIL with EXECUTOR_MISMATCH for another credential or another
// identity; UNKNOWN with DEPENDENCY_UNAVAILABLE when the executor, its token
// or its self-review cannot be established.
type executionCheck struct{ a *Adapter }

func (c executionCheck) Consult(ctx context.Context, in adapter.CheckInput) (installed.CheckRecord, error) {
	op := in.Operation
	rec := installed.CheckRecord{SourceID: SourceExecutor}
	acct, ok := c.a.accountOf(op.PrincipalID)
	if !ok {
		return rec, fmt.Errorf("k8s: the operation names no registered account: %w", adapter.ErrDependencyUnavailable)
	}
	ex, ok := c.a.cfg.Executors[acct.Namespace+"/"+acct.Name]
	if !ok || ex == nil {
		return rec, fmt.Errorf("k8s: no executor for %s/%s: %w", acct.Namespace, acct.Name, adapter.ErrDependencyUnavailable)
	}
	kinds, err := ex.Credentials(ctx)
	if err != nil {
		return rec, installed.Dependency(err)
	}
	rec.ObservedAt = c.a.cfg.Clock.Now()
	if !slices.Equal(kinds, []CredentialKind{CredentialProjectedToken}) {
		rec.Result, rec.ReasonCode = adapter.VerdictFail, CodeExecutorMismatch
		return rec, nil
	}
	info, err := ex.SelfReview(ctx)
	if err != nil {
		return installed.CheckRecord{SourceID: SourceExecutor}, installed.Dependency(err)
	}
	rec.SourceRef = info.Username
	if info.Username == acct.Username() && info.UID == acct.UID {
		rec.Result, rec.ReasonCode = adapter.VerdictPass, installed.CodeRequirementSatisfied
	} else {
		rec.Result, rec.ReasonCode = adapter.VerdictFail, CodeExecutorMismatch
	}
	return rec, nil
}

// AuthorizeNative asks the API server whether the registered account, which
// is the original principal, may make the translated request of the
// operation's row (KR-12, KR-13), with a SubjectAccessReview whose user, uid
// and groups are those of the principal's review (KR-15), and returns the
// answer unchanged ([installed.Authorize]): ALLOW for allowed true without an
// evaluationError, UNKNOWN with an evaluationError, DENY otherwise, since a
// request on which no authorizer has an opinion is denied [K8]. The decision
// names [SourceAPIServer] and carries the API server's reason; the API
// server's answer has no obligation, decision record, decision time or policy
// revision, so the decision has none. A principal this adapter did not
// authenticate, and an operation of no row, are a DENY of the adapter's own
// mapping source: the API server decides only for its own users. A denial is
// final; the adapter never runs the operation.
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	d, err := installed.Authorize(ctx, apiServerAuthorization{a: a}, p, op, a.cfg.Clock.Now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("k8s: authorize: %w", err)
	}
	return d, nil
}

// apiServerAuthorization is the PermissionLookup of KR-12.
type apiServerAuthorization struct{ a *Adapter }

func (l apiServerAuthorization) Decide(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	a := l.a
	f, ok := a.factsOf(p)
	if !ok {
		return adapter.Decision{Effect: adapter.EffectDeny, Reason: "the principal is not a reviewed service account of the cluster", SourceID: sourceMapping}, nil
	}
	ra, ok := a.translation(op)
	if !ok {
		return adapter.Decision{Effect: adapter.EffectDeny, Reason: "the operation has no translation row", SourceID: sourceMapping}, nil
	}
	gw, err := a.cfg.GatewayToken(ctx)
	if err != nil || gw == "" {
		return adapter.Decision{}, dependency("the gateway account's token cannot be read")
	}
	st, err := a.api.accessReview(ctx, gw, SubjectAccessReviewSpec{User: f.account.Username(), UID: f.account.UID, Groups: f.groups, ResourceAttributes: &ra})
	if err != nil {
		return adapter.Decision{}, dependency("the API server's authorization cannot answer")
	}
	d := adapter.Decision{Effect: adapter.EffectDeny, Reason: st.Reason, SourceID: SourceAPIServer}
	switch {
	case st.EvaluationError != "":
		d.Effect = adapter.EffectUnknown
	case st.Allowed:
		d.Effect = adapter.EffectAllow
	}
	return d, nil
}

// translation returns the resource attributes of the downstream request of
// the operation's row (KR-13): list or get of deployments in the row's
// namespace. Only the reference rows translate.
func (a *Adapter) translation(op core.OperationContext) (ResourceAttributes, bool) {
	ra := ResourceAttributes{Namespace: RowNamespace, Group: "apps", Resource: "deployments"}
	switch op.Action {
	case ActionList:
		if len(op.Resources) != 1 || op.Resources[0] != ResourceBase(a.cfg.ClusterID) {
			return ResourceAttributes{}, false
		}
		ra.Verb = "list"
	case ActionGet:
		name, ok := rowName(a.cfg.ClusterID, op.Resources)
		if !ok {
			return ResourceAttributes{}, false
		}
		ra.Verb, ra.Name = "get", name
	default:
		return ResourceAttributes{}, false
	}
	return ra, true
}

// RecordOutcome signs the observation as an outcome report
// ([installed.Record]). The executor's request is observed by the API
// server's audit log, so an EXECUTION observation gives NoVisibility unless
// [Config.ExecutionVisible] is set.
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the gateway does not observe the executor's request; the API server's audit log records it", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("k8s: %w", err)
	}
	return rec, nil
}
