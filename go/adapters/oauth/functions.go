package oauth

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
// authenticated client workload in realm, from the enrollment registry
// through [enroll.Resolver], for every request (OAUTH-38).
//
// The workload alone never names an agent. The profile does not support
// clients shared by several agents, so a workload with more than one
// enrollment in force is the registry's configuration error, an error that
// wraps [adapter.ErrUnsupportedRequirement], for whichever agent (IM-19). A
// revoked or compromised binding comes back as that status, never as active.
// A registry that cannot answer, a status that is not defined, and a time
// later than now plus the skew are [adapter.ErrDependencyUnavailable]. The
// holder key is not compared with a token's cnf here: the validator does,
// with the principal's [AttrConfirmation] attribute (OAUTH-34).
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Registry}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("oauth: resolve binding: %w", installed.Dependency(err))
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("oauth: resolve binding: the registry reports status %q: %w", b.Status, adapter.ErrDependencyUnavailable)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("oauth: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}

// customerID is the grammar of the customer_id parameter of row R1.
var customerID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// MapOperation derives the operation context of draft 10.2 with the baseline
// HTTP mapping of package binding and the route table of the installed
// revision ([installed.MapRequest]). Under the reference table, the resource
// of R2 is the authenticated principal's mailbox, and a customer_id outside
// the grammar of R1 matches no route. An uninstalled revision, and a request
// no route matches, are [adapter.ErrUnsupportedRequirement]; a principal of
// another realm is [adapter.ErrContextMismatch].
func (a *Adapter) MapOperation(ctx context.Context, r *http.Request, p adapter.Principal, mappingVersion string) (core.OperationContext, error) {
	if err := live(ctx, "map operation"); err != nil {
		return core.OperationContext{}, err
	}
	if r == nil || r.URL == nil {
		return core.OperationContext{}, fmt.Errorf("oauth: no request: %w", adapter.ErrInvalidMessage)
	}
	routes, ok := a.mappings[mappingVersion]
	if !ok {
		return core.OperationContext{}, fmt.Errorf("oauth: mapping revision %q is not installed: %w", mappingVersion, adapter.ErrUnsupportedRequirement)
	}
	if p.ID == "" || p.Realm != a.cfg.Realm {
		return core.OperationContext{}, fmt.Errorf("oauth: the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	}
	op, err := installed.MapRequest(a.bindingConfig(mappingVersion), routes, a.cfg.Realm.EnvironmentID, r, p)
	if err != nil {
		return core.OperationContext{}, fmt.Errorf("oauth: %w", err)
	}
	if a.cfg.Mappings == nil {
		for i, res := range op.Resources {
			if id, ok := strings.CutPrefix(res, "crm-customer:"); ok && op.Action == "crm.customer.read" && !customerID.MatchString(id) {
				return core.OperationContext{}, fmt.Errorf("oauth: customer_id outside the grammar of R1: %w", adapter.ErrUnsupportedRequirement)
			}
			op.Resources[i] = strings.ReplaceAll(res, "{principal_id}", p.ID)
		}
	}
	return op, nil
}

// tokenFacts are the facts of a token that a principal of this adapter
// carries in [AttrToken].
type tokenFacts struct {
	entry         *entry
	tenant        string
	scopes        []string
	issuedAt      time.Time
	statusChecked time.Time
	tokenID       string
}

// factsOf reads the token facts of a principal this adapter authenticated in
// the gateway's realm under a configured entry.
func (a *Adapter) factsOf(p adapter.Principal) (tokenFacts, bool) {
	if p.Mechanism != Mechanism || p.Realm != a.cfg.Realm || p.ID == "" || p.Workload == "" {
		return tokenFacts{}, false
	}
	tok, ok := p.Attributes[AttrToken].(map[string]any)
	if !ok {
		return tokenFacts{}, false
	}
	id, _ := tok["entry"].(string)
	e, ok := a.entries[id]
	if !ok || tok["form"] != string(e.Form) {
		return tokenFacts{}, false
	}
	t := tokenFacts{entry: e}
	t.tenant, _ = tok["tenant"].(string)
	if t.tenant != e.Tenant || !strings.HasPrefix(p.ID, "oauth:"+component(e.Issuer)+":"+component(e.Tenant)+":") {
		return tokenFacts{}, false
	}
	switch list := tok["scopes"].(type) {
	case []string:
		t.scopes = slices.Clone(list)
	case []any:
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return tokenFacts{}, false
			}
			t.scopes = append(t.scopes, s)
		}
	default:
		return tokenFacts{}, false
	}
	t.issuedAt, _ = unixAttr(tok["issued_at"])
	t.statusChecked, _ = unixAttr(tok["status_checked_at"])
	t.tokenID, _ = tok["token_id"].(string)
	return t, true
}

// unixAttr reads a Unix-seconds attribute value.
func unixAttr(v any) (time.Time, bool) {
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
// The four paths of profile section F are read from the token facts of
// cc.Principal: /oauth/principal_id, /oauth/tenant_id, /oauth/client_id (the
// namespaced client) and /oauth/scopes. ObservedAt is the token's iat;
// StatusCheckedAt is the instant introspection was sent in form I and zero in
// form E, which has no status mechanism; SourceID is the issuer entry and
// SourceRef the jti or uti. A principal this adapter did not authenticate is
// [adapter.ErrContextMismatch]. Another path is read from its source in
// [Config.Claims]; a path with none is [adapter.ErrUnsupportedRequirement].
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	switch nativePath {
	case PathPrincipalID, PathTenantID, PathClientID, PathScopes:
		return a.tokenClaim(nativePath, cc.Principal)
	}
	src, ok := a.cfg.Claims[nativePath]
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("oauth: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	c, err := installed.ReadClaim(ctx, src, nativePath, cc, a.cfg.Clock.Now())
	if err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("oauth: read claim: %w", err)
	}
	return c, nil
}

func (a *Adapter) tokenClaim(path string, p adapter.Principal) (adapter.NativeClaim, error) {
	t, ok := a.factsOf(p)
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("oauth: read claim: the principal was not authenticated by this adapter: %w", adapter.ErrContextMismatch)
	}
	if err := installed.SourceTimes(a.cfg.Clock.Now(), t.issuedAt, t.statusChecked); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("oauth: read claim: %w", err)
	}
	c := adapter.NativeClaim{ObservedAt: t.issuedAt, SourceID: t.entry.ID, SourceRef: t.tokenID}
	if t.entry.Form == FormIntrospection {
		c.StatusCheckedAt = t.statusChecked
	}
	if path == PathScopes && t.entry.Form == FormGoogleID {
		return adapter.NativeClaim{}, fmt.Errorf("oauth: read claim: an ID token carries no scope (OAUTH-49): %w", adapter.ErrUnsupportedRequirement)
	}
	switch path {
	case PathPrincipalID:
		c.Value = p.ID
	case PathTenantID:
		c.Value = t.tenant
	case PathClientID:
		c.Value = string(p.Workload)
	case PathScopes:
		c.Value = t.scopes
	}
	return c, nil
}

// CheckContext runs the check the deployment installed under checkID exactly
// ([installed.RunCheck]): native-delegation-v1 and execution-identity-v1 come
// from the deployment, and native-principal-binding-v1 is the validator's
// (OAUTH-39), so it is UNKNOWN with UNSUPPORTED_REQUIREMENT here unless the
// deployment installed it.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	return installed.RunCheck(ctx, a.cfg.Checks, a.cfg.Guard, a.cfg.Clock, checkID, in)
}

// scopeSource names the adapter as the source of a denial for a missing
// scope.
const scopeSource = "oauth-delegated-scope"

// AuthorizeNative applies the required delegated scope of the operation's
// route, then asks the API's native permission lookup about the original
// principal and returns its decision unchanged ([installed.Authorize]).
//
// A route with a scope allows only a principal this adapter authenticated
// whose token's scope list contains it; any other principal gets a DENY with
// the reason insufficient_scope, the RFC 6750 section 3.1 error the gateway
// answers with HTTP 403 (OAUTH-31). The adapter never adds a scope and never
// runs the operation.
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	if rt, ok := a.routeOf(op.Method, targetPath(op.TargetURI, a.cfg.Origin)); ok && rt.Scope != "" {
		t, ok := a.factsOf(p)
		if !ok || !slices.Contains(t.scopes, rt.Scope) {
			return adapter.Decision{Effect: adapter.EffectDeny, Reason: "insufficient_scope", SourceID: scopeSource}, nil
		}
	}
	d, err := installed.Authorize(ctx, a.cfg.Permissions, p, op, a.cfg.Clock.Now())
	if err != nil {
		return adapter.Decision{}, fmt.Errorf("oauth: authorize: %w", err)
	}
	return d, nil
}

// targetPath returns the path of a target URI: what follows the scheme and
// authority, up to the query.
func targetPath(target, _ string) string {
	rest, ok := strings.CutPrefix(target, "https://")
	if !ok {
		return ""
	}
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "/"
	}
	path, _, _ := strings.Cut(rest[i:], "?")
	return path
}

// RecordOutcome signs the observation as an outcome report
// ([installed.Record]). Execution is reported by the API, so an EXECUTION
// observation gives NoVisibility unless [Config.ExecutionVisible] is set.
func (a *Adapter) RecordOutcome(ctx context.Context, o adapter.Observation) (adapter.Recorded, error) {
	if err := live(ctx, "record outcome"); err != nil {
		return nil, err
	}
	rec, err := installed.Record(a.cfg.Reporting, a.cfg.Realm, a.cfg.ExecutionVisible,
		"the gateway does not observe the execution of the read; the API reports it", o, a.cfg.Clock.Now())
	if err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}
	return rec, nil
}
