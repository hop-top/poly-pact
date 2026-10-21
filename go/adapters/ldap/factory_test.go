package ldap_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/adapters/ldap"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
)

// ldapFactory builds the LDAP adapter for a case: from the ldap/1 state of an
// LDAP case or from the common/1 state of a common case. The fixtures realize
// the gateway's native systems; the adapter is the package's.
func ldapFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	switch model {
	case ldapModel:
		return ldapSubject(env, nil)
	case memory.Model:
		return commonSubject(env)
	}
	return adaptertest.Subject{}, fmt.Errorf("model %q is not realized", model)
}

// fakeDirectory is a [ldap.Directory] over a fixture server. It fires the
// directory hook on every Open.
type fakeDirectory struct {
	srv   *server
	hooks *adaptertest.Hooks
}

func (d fakeDirectory) Open(context.Context) (ldap.Session, error) {
	d.hooks.Fire(hookDirectory)
	switch {
	case d.srv.state.Unreachable:
		return nil, errors.New("connection refused")
	case d.srv.state.TLSFails:
		return nil, errors.New("tls: handshake failure")
	}
	return &fakeSession{srv: d.srv}, nil
}

// fakeSession is one connection to a fixture server. It answers as RFC 4511
// describes: a bind compares userPassword, an empty password is the
// unauthenticated mechanism, which succeeds and leaves the session anonymous
// (RFC 4513, section 5.1.2), and a search returns what the filter matches in
// scope, without what the server's access control hides.
type fakeSession struct {
	srv    *server
	bound  string
	closed bool
}

func (s *fakeSession) Bind(_ context.Context, dn, password string) error {
	if s.closed {
		return errors.New("connection closed")
	}
	s.bound = ""
	if password == "" {
		return nil
	}
	e := s.srv.find(dn)
	if e == nil || len(e.get("userPassword")) == 0 || e.first("userPassword") != password {
		return &ldap.ResultError{Code: ldap.ResultInvalidCredentials}
	}
	s.bound = e.dn
	return nil
}

func (s *fakeSession) WhoAmI(context.Context) (string, bool, error) {
	if s.bound == "" {
		return "", true, nil
	}
	return "dn:" + s.bound, true, nil
}

func (s *fakeSession) Close() error {
	s.closed = true
	return nil
}

func (s *fakeSession) Search(_ context.Context, q ldap.Query) (ldap.Result, error) {
	if s.closed {
		return ldap.Result{}, errors.New("connection closed")
	}
	if q.Base == "" && q.Scope == ldap.ScopeBase {
		root := ldap.Entry{DN: ""}
		if s.srv.kind == kindOpenLDAP {
			root.Attributes = []ldap.Attribute{{Name: "supportedExtension", Values: [][]byte{[]byte(ldap.WhoAmIOID)}}}
		}
		return ldap.Result{Entries: []ldap.Entry{root}}, nil
	}
	base := normDN(q.Base)
	if s.srv.find(q.Base) == nil || s.hiddenEntry(base) {
		return ldap.Result{Code: ldap.ResultNoSuchObject}, nil
	}
	var res ldap.Result
	for _, e := range s.srv.entries {
		k := normDN(e.dn)
		inScope := k == base || q.Scope == ldap.ScopeSubtree && strings.HasSuffix(k, ","+base)
		if !inScope || s.hiddenEntry(k) || !s.match(e, q.Filter) {
			continue
		}
		if q.SizeLimit > 0 && len(res.Entries) == q.SizeLimit {
			res.Code = ldap.ResultSizeLimitExceeded
			return res, nil
		}
		res.Entries = append(res.Entries, s.project(e, q.Attributes))
	}
	return res, nil
}

// hiddenEntry reports whether the access control hides the entry dn.
func (s *fakeSession) hiddenEntry(dn string) bool {
	for _, h := range s.srv.state.Hidden {
		b := normDN(h.Base)
		if h.Entries && (dn == b || strings.HasSuffix(dn, ","+b)) {
			return true
		}
	}
	return false
}

// hiddenAttr reports whether the access control hides attr of the entry dn.
func (s *fakeSession) hiddenAttr(dn, attr string) bool {
	for _, h := range s.srv.state.Hidden {
		b := normDN(h.Base)
		if (dn == b || strings.HasSuffix(dn, ","+b)) && slices.ContainsFunc(h.Attributes, func(a string) bool { return strings.EqualFold(a, attr) }) {
			return true
		}
	}
	return false
}

// project returns the requested attributes of e that the session may read.
func (s *fakeSession) project(e *entry, attrs []string) ldap.Entry {
	out := ldap.Entry{DN: e.dn}
	for _, want := range attrs {
		if s.hiddenAttr(normDN(e.dn), want) || strings.EqualFold(want, "userPassword") {
			continue
		}
		if v := e.get(want); len(v) > 0 {
			out.Attributes = append(out.Attributes, ldap.Attribute{Name: want, Values: slices.Clone(v)})
		}
	}
	return out
}

// values returns the values of attr of e that a filter can see.
func (s *fakeSession) values(e *entry, attr string) [][]byte {
	if s.hiddenAttr(normDN(e.dn), attr) {
		return nil
	}
	return e.get(attr)
}

// match evaluates f against e. An item the server cannot evaluate, such as an
// extensible match with a matching rule it does not recognize, is Undefined
// and the entry is not returned (RFC 4511, section 4.5.1.7).
func (s *fakeSession) match(e *entry, f ldap.Filter) bool {
	switch f := f.(type) {
	case ldap.And:
		for _, x := range f {
			if !s.match(e, x) {
				return false
			}
		}
		return len(f) > 0
	case ldap.Present:
		return len(s.values(e, f.Attr)) > 0
	case ldap.Equal:
		for _, v := range s.values(e, f.Attr) {
			if strings.EqualFold(f.Attr, "objectGUID") && string(v) == string(f.Value) ||
				!strings.EqualFold(f.Attr, "objectGUID") && strings.EqualFold(string(v), string(f.Value)) {
				return true
			}
		}
		return false
	case ldap.InChain:
		inChain := s.srv.kind == kindAD
		if s.srv.state.InChain != nil {
			inChain = *s.srv.state.InChain
		}
		return inChain && s.reaches(e, f.Attr, normDN(f.DN), map[string]bool{})
	}
	return false
}

// reaches reports whether dn is reachable from e through attr values,
// transitively: the chain of ancestry that LDAP_MATCHING_RULE_IN_CHAIN walks.
func (s *fakeSession) reaches(e *entry, attr, dn string, seen map[string]bool) bool {
	if seen[normDN(e.dn)] {
		return false
	}
	seen[normDN(e.dn)] = true
	for _, v := range s.values(e, attr) {
		if normDN(string(v)) == dn {
			return true
		}
		if next := s.srv.find(string(v)); next != nil && s.reaches(next, attr, dn, seen) {
			return true
		}
	}
	return false
}

// referenceRegistry is the enrollment source of the records of a case: the
// lookup of the reference adapter over them, with dedicated workloads.
type referenceRegistry struct{ ref *memory.Adapter }

func (r referenceRegistry) Lookup(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	return r.ref.ResolveAgentBinding(ctx, realm, workload, agent)
}

func (referenceRegistry) Rotate(context.Context, enroll.Actor, string, core.Digest) error {
	return errors.New("the fixture registry is read-only")
}

func (referenceRegistry) MarkCompromised(context.Context, enroll.Actor, string) error {
	return errors.New("the fixture registry is read-only")
}

func unixTime(sec *int64) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(*sec, 0)
}

func reporting(r *memory.Reporting) (*ldap.Reporting, error) {
	if r == nil {
		return nil, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ldap.Reporting{Issuer: r.Issuer, Audience: r.Audience, KID: r.KID, Key: key}, nil
}

// permissionList is the native authorization of ldap/1.
type permissionList struct{ perms []permission }

func (l permissionList) Decide(_ context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	d := adapter.Decision{Effect: adapter.EffectDeny, SourceID: permissionSource, Reason: "no permission allows this"}
	for _, x := range l.perms {
		if x.Principal == p.ID && x.Action == op.Action && len(op.Resources) == 1 && op.Resources[0] == x.Resource {
			d.Effect, d.Reason = adapter.EffectAllow, ""
		}
	}
	return d, nil
}

// fixedExecutor reports the running identity of the case.
type fixedExecutor struct{ id string }

func (f fixedExecutor) RunningIdentity(context.Context, core.OperationContext) (string, error) {
	return f.id, nil
}

// realmConfig realizes a realm record of a world over dir.
func realmConfig(r realmState, dir ldap.Directory) ldap.RealmConfig {
	rc := ldap.RealmConfig{
		ID: r.RealmID, Kind: ldap.Kind(r.Kind), Directory: dir,
		UserBases: r.UserBases, GroupBases: r.GroupBases,
		AccountClass: r.AccountClass, GroupClass: r.GroupClass, LoginAttribute: r.LoginAttribute,
		LookupDN: r.Lookup.DN, LookupPassword: r.Lookup.Password, DeniedPrincipals: r.DeniedPrincipals,
		Sentinel:     ldap.Sentinel{Account: r.Sentinel.Account, Group: r.Sentinel.Group, ParentGroup: r.Sentinel.ParentGroup},
		DirectGroups: r.DirectGroups, Nested: ldap.Nesting(r.Nested),
	}
	if r.UniqueIDText == "rfc4122-octet-order" {
		rc.GUIDText = ldap.OctetOrderGUID
	}
	return rc
}

// ldapSubject realizes an ldap/1 state. directory, when not nil, gives the
// Directory of each server instead of the fixture fake.
func ldapSubject(env adaptertest.Env, directory func(*server) ldap.Directory) (adaptertest.Subject, error) {
	fsys, err := fixtures()
	if err != nil {
		return adaptertest.Subject{}, err
	}
	w, err := loadWorld(env.State, fsys)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	a, err := ldapAdapter(w, env, directory)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{
		Adapter:    a,
		Arrive:     ldap.Mark,
		Credential: func(r *http.Request, ref string) error { return attachCredential(w.st.Credentials, r, ref) },
	}, nil
}

func ldapAdapter(w *world, env adaptertest.Env, directory func(*server) ldap.Directory) (*ldap.Adapter, error) {
	ref, err := memory.New(w.commonState(), env.Clock)
	if err != nil {
		return nil, err
	}
	rp, err := reporting(w.st.Reporting)
	if err != nil {
		return nil, err
	}
	var realms []ldap.RealmConfig
	var denied []string
	for _, r := range w.st.Realms {
		srv := w.servers[r.Directory]
		var dir ldap.Directory = fakeDirectory{srv: srv, hooks: env.Hooks}
		if directory != nil {
			dir = directory(srv)
		}
		realms = append(realms, realmConfig(r, dir))
		denied = append(denied, r.DeniedPrincipals...)
	}
	checks := map[string]ldap.InstalledCheck{}
	if w.st.Execution != nil {
		checks[ldap.CheckIDExecutionIdentity] = ldap.InstalledCheck{
			Check: ldap.ExecutionIdentity(fixedExecutor{w.st.Execution.RunningIdentity}, "inventory-executor", denied, env.Clock),
		}
	}
	return ldap.New(ldap.Config{
		Realm:           w.pactRealm(),
		Origin:          w.st.Gateway.Origin,
		HeaderAllowlist: w.st.Gateway.HeaderAllowlist,
		Realms:          realms,
		LoginRealm:      w.st.LoginRealm,
		Checks:          checks,
		Registry:        referenceRegistry{ref},
		Permissions:     permissionList{w.st.Permissions},
		Reporting:       rp,
		Clock:           env.Clock,
	})
}

// commonUUID derives the entryUUID of a common/1 identity from its id.
func commonUUID(id string) string {
	h := sha256.Sum256([]byte(id))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// commonServer realizes the identities of a common/1 state as the accounts of
// one OpenLDAP realm: the login name is the ref and the password the secret.
func commonServer(st memory.State) *server {
	const suffix = "ou=people,dc=common,dc=example"
	srv := &server{kind: kindOpenLDAP}
	add := func(dn string, attrs ...attribute) {
		srv.entries = append(srv.entries, &entry{dn: dn, attrs: attrs})
	}
	val := func(name string, v ...string) attribute {
		a := attribute{name: name}
		for _, x := range v {
			a.values = append(a.values, []byte(x))
		}
		return a
	}
	add(suffix, val("objectClass", "organizationalUnit"), val("entryUUID", commonUUID(suffix)))
	for _, id := range st.Identities {
		add("uid="+id.Ref+","+suffix, val("objectClass", "inetOrgPerson"), val("uid", id.Ref),
			val("userPassword", id.Secret), val("entryUUID", commonUUID(id.ID)))
	}
	add("uid=pact-sentinel,"+suffix, val("objectClass", "inetOrgPerson"), val("uid", "pact-sentinel"),
		val("entryUUID", commonUUID("sentinel")), val("pwdAccountLockedTime", "000001010000Z"),
		val("pwdReset", "TRUE"), val("pwdStartTime", "20260101000000Z"), val("pwdEndTime", "20360101000000Z"))
	add("uid=pact-lookup,"+suffix, val("objectClass", "inetOrgPerson"), val("uid", "pact-lookup"),
		val("userPassword", "common-lookup-secret"), val("entryUUID", commonUUID("lookup")))
	add("cn=pact-sentinel-group,"+suffix, val("objectClass", "groupOfNames"),
		val("member", "uid=pact-sentinel,"+suffix), val("entryUUID", commonUUID("sentinel-group")))
	srv.deriveMemberOf()
	return srv
}

// commonSubject realizes a common/1 state.
func commonSubject(env adaptertest.Env) (adaptertest.Subject, error) {
	st, err := memory.ParseState(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	ref, err := memory.New(st, env.Clock)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	rp, err := reporting(st.Reporting)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	srv := commonServer(st)
	mappings := map[string][]ldap.Route{}
	for _, m := range st.Mappings {
		for _, rt := range m.Routes {
			mappings[m.Version] = append(mappings[m.Version], ldap.Route{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource})
		}
	}
	claims := map[string]ldap.ClaimSource{}
	for _, path := range st.ApprovedPaths {
		claims[path] = commonClaims{st: st}
	}
	checks := map[string]ldap.InstalledCheck{}
	for _, c := range st.Checks {
		ic := ldap.InstalledCheck{Check: commonCheck{rec: c, down: slices.Contains(st.UnavailableSources, c.SourceID)}, PinnedRevision: c.PinnedRevision}
		if f := c.Freshness; f != nil {
			ic.Freshness = &ldap.Freshness{MaxAgeSeconds: *f.MaxAgeSeconds, StatusMaxAgeSeconds: *f.StatusMaxAgeSeconds}
		}
		checks[c.ID] = ic
	}
	guard := freshness.NewMonotonic(len(st.Sightings) + 4096)
	for _, s := range st.Sightings {
		guard.Check(adapter.NativeClaim{SourceID: s.SourceID, SourceRef: s.SourceRef, ObservedAt: unixTime(s.ObservedAt)})
	}
	realm := adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID}
	cfg := ldap.Config{
		Realm:           realm,
		Origin:          st.Gateway.Origin,
		HeaderAllowlist: st.Gateway.HeaderAllowlist,
		Realms: []ldap.RealmConfig{{
			ID: "common", Kind: ldap.KindOpenLDAP, Directory: fakeDirectory{srv: srv, hooks: env.Hooks},
			UserBases: []string{"ou=people,dc=common,dc=example"}, GroupBases: []string{"ou=people,dc=common,dc=example"},
			AccountClass: "inetOrgPerson", GroupClass: "groupOfNames", LoginAttribute: "uid",
			LookupDN: "uid=pact-lookup,ou=people,dc=common,dc=example", LookupPassword: "common-lookup-secret",
			DeniedPrincipals: []string{ldap.PrincipalID("common", commonUUID("lookup"))},
			Sentinel:         ldap.Sentinel{Account: commonUUID("sentinel"), Group: commonUUID("sentinel-group")},
			DirectGroups:     true, Nested: ldap.NestingNone,
		}},
		LoginRealm:       "common",
		Claims:           claims,
		Checks:           checks,
		Guard:            guard,
		Registry:         referenceRegistry{ref},
		Permissions:      commonPolicy{rules: st.Policy},
		Reporting:        rp,
		ExecutionVisible: st.Visibility == "execution",
		Clock:            env.Clock,
	}
	if len(mappings) > 0 {
		cfg.Mappings = mappings
	}
	a, err := ldap.New(cfg)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	return adaptertest.Subject{Adapter: a, Arrive: ldap.Mark, Credential: func(r *http.Request, name string) error {
		for _, id := range st.Identities {
			if id.Ref == name {
				if r.Header.Get("Authorization") == "" {
					r.Header.Set("Authorization", basicCredential(id.Ref, id.Secret))
				}
				return nil
			}
		}
		return fmt.Errorf("no identity %q", name)
	}}, nil
}

// commonClaims is the claim source of a common/1 state.
type commonClaims struct{ st memory.State }

func (c commonClaims) Claims(_ context.Context, realm adapter.Realm, principal, path string) ([]ldap.ClaimRecord, error) {
	var out []ldap.ClaimRecord
	for _, r := range c.st.Claims {
		if r.Path != path || r.Principal != principal || r.Realm.TenantID != realm.TenantID || r.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		if slices.Contains(c.st.UnavailableSources, r.SourceID) {
			return nil, fmt.Errorf("source %s cannot answer: %w", r.SourceID, adapter.ErrDependencyUnavailable)
		}
		var v any
		if err := json.Unmarshal(r.Value, &v); err != nil {
			return nil, err
		}
		out = append(out, ldap.ClaimRecord{
			Value: v, Resource: r.Resource, TaskID: r.TaskID,
			ObservedAt: unixTime(r.ObservedAt), StatusCheckedAt: unixTime(r.StatusCheckedAt),
			SourceID: r.SourceID, SourceRef: r.SourceRef,
		})
	}
	return out, nil
}

// commonCheck is an installed check of a common/1 state.
type commonCheck struct {
	rec  memory.CheckRecord
	down bool
}

func (c commonCheck) Consult(_ context.Context, in adapter.CheckInput) (ldap.CheckRecord, error) {
	if !c.rec.Applies(in) {
		return ldap.CheckRecord{Result: adapter.VerdictFail, ReasonCode: memory.CodeApprovalScopeMismatch, SourceID: c.rec.SourceID}, nil
	}
	if c.down {
		return ldap.CheckRecord{SourceID: c.rec.SourceID}, fmt.Errorf("source %s cannot answer: %w", c.rec.SourceID, adapter.ErrDependencyUnavailable)
	}
	return ldap.CheckRecord{
		Result: adapter.Verdict(c.rec.Result), ReasonCode: c.rec.ReasonCode,
		SourceID: c.rec.SourceID, SourceRef: c.rec.SourceRef,
		ObservedAt: unixTime(c.rec.ObservedAt), StatusCheckedAt: unixTime(c.rec.StatusCheckedAt),
		Revision: c.rec.Revision,
	}, nil
}

// commonPolicy is the native policy of a common/1 state: a deny wins over an
// unknown and an unknown over an allow; no rule is a deny of the policy's own
// source.
type commonPolicy struct{ rules []memory.PolicyRule }

const ownPolicySource = "native-policy"

func (c commonPolicy) Decide(_ context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	rank := map[string]int{"DENY": 3, "UNKNOWN": 2, "ALLOW": 1}
	var best *memory.PolicyRule
	for i := range c.rules {
		r := &c.rules[i]
		if r.Principal != p.ID || r.Realm.TenantID != p.Realm.TenantID || r.Realm.EnvironmentID != p.Realm.EnvironmentID ||
			r.Action != op.Action || (r.Resource != "" && !slices.Contains(op.Resources, r.Resource)) {
			continue
		}
		if best == nil || rank[r.Effect] > rank[best.Effect] {
			best = r
		}
	}
	if best == nil {
		return adapter.Decision{Effect: adapter.EffectDeny, Reason: "no rule allows this principal", SourceID: ownPolicySource}, nil
	}
	d := adapter.Decision{
		Effect: adapter.Effect(best.Effect), Reason: best.Reason, SourceID: best.SourceID,
		SourceRef: best.SourceRef, DecidedAt: unixTime(best.DecidedAt), PolicyRevision: best.PolicyRevision,
	}
	if d.SourceID == "" {
		d.SourceID = ownPolicySource
	}
	for _, o := range best.Obligations {
		d.Obligations = append(d.Obligations, adapter.Obligation{ID: o.ID, Attributes: o.Attributes})
	}
	return d, nil
}
