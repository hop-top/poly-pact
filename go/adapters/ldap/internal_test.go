package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
	"hop.top/pact-go/core"
)

// TestFilterStrings checks the string representation of RFC 4515, section 3:
// the five octets the grammar reserves are written as \hh, and so is every
// octet outside printable ASCII, so that a name cannot change the filter.
func TestFilterStrings(t *testing.T) {
	for _, tc := range []struct {
		f    Filter
		want string
	}{
		{Equal{Attr: "uid", Value: []byte("inventory-assistant")}, `(uid=inventory-assistant)`},
		{Equal{Attr: "uid", Value: []byte("inventory-assistant-r*")}, `(uid=inventory-assistant-r\2a)`},
		{Equal{Attr: "cn", Value: []byte("a)(uid=*")}, `(cn=a\29\28uid=\2a)`},
		{Equal{Attr: "cn", Value: []byte("back\\slash\x00nul")}, `(cn=back\5cslash\00nul)`},
		{Equal{Attr: "cn", Value: []byte("Inventory Assistant")}, `(cn=Inventory Assistant)`},
		{Equal{Attr: "cn", Value: []byte("é\x07")}, `(cn=\c3\a9\07)`},
		{Equal{Attr: "objectGUID", Value: []byte{0x7a, 0x3f, 0x00, 0xff}, Binary: true}, `(objectGUID=\7a\3f\00\ff)`},
		{Present{Attr: "objectClass"}, `(objectClass=*)`},
		{And{Equal{Attr: "objectClass", Value: []byte("group")}, InChain{Attr: "member", DN: `CN=Inv \2c A,OU=U,DC=x`}},
			`(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=CN=Inv \5c2c A,OU=U,DC=x))`},
	} {
		if got := tc.f.String(); got != tc.want {
			t.Errorf("%#v.String() = %s, want %s", tc.f, got, tc.want)
		}
	}
}

// TestPreparePassword checks the SASLprep steps the adapter applies (RFC 4013,
// sections 2.1 and 2.3, with the tables of RFC 3454).
func TestPreparePassword(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		err      bool
	}{
		{"Wh7!lantern-stock-21", "Wh7!lantern-stock-21", false},
		{"", "", false},
		{"\u00ad᠋️", "", false},                // B.1 only: empty
		{"I\u00adX", "IX", false},              // the soft hyphen example of RFC 4013, section 3
		{"a b　c", "a b c", false},              // C.1.2 to SPACE
		{"a\u0007b", "", true},                 // C.2.1
		{"a\u0085b", "", true},                 // C.2.2
		{"ab", "", true},                      // C.3
		{"a﷐b", "", true},                      // C.4
		{"a�b", "", true},                      // C.6
		{"a⿰b", "", true},                      // C.7
		{"a\u200eb", "", true},                 // C.8
		{"a\U000E0001b", "", true},             // C.9
		{string([]byte{0x61, 0xff}), "", true}, // not UTF-8
		{"\u200b", "", false},                  // B.1 before C.1.2
	} {
		got, err := preparePassword(tc.in)
		if (err != nil) != tc.err || err == nil && got != tc.want {
			t.Errorf("preparePassword(%q) = %q, %v; want %q, error %v", tc.in, got, err, tc.want, tc.err)
		}
	}
}

// TestParseGeneralizedTime checks the GeneralizedTime forms of RFC 4517,
// section 3.3.13.
func TestParseGeneralizedTime(t *testing.T) {
	utc := func(y, mo, d, h, mi, s, ns int) time.Time {
		return time.Date(y, time.Month(mo), d, h, mi, s, ns, time.UTC)
	}
	for _, tc := range []struct {
		in   string
		want time.Time
	}{
		{"20261015120000Z", utc(2026, 10, 15, 12, 0, 0, 0)},
		{"202610151200Z", utc(2026, 10, 15, 12, 0, 0, 0)},
		{"2026101512Z", utc(2026, 10, 15, 12, 0, 0, 0)},
		{"20261015120000.5Z", utc(2026, 10, 15, 12, 0, 0, 500000000)},
		{"20261015120000+0200", utc(2026, 10, 15, 10, 0, 0, 0)},
		{"20261015120000-05", utc(2026, 10, 15, 17, 0, 0, 0)},
	} {
		got, err := parseGeneralizedTime(tc.in)
		if err != nil || !got.Equal(tc.want) {
			t.Errorf("parseGeneralizedTime(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "2026101512", "20261015120000", "2026-10-15T12:00:00Z", "20261015120000.Z", "20261015120000+2500", "202610151200001Z"} {
		if _, err := parseGeneralizedTime(bad); err == nil {
			t.Errorf("parseGeneralizedTime(%q) succeeded", bad)
		}
	}
}

func entryOf(attrs map[string]string) Entry {
	e := Entry{DN: "uid=x"}
	for k, v := range attrs {
		e.Attributes = append(e.Attributes, Attribute{Name: k, Values: [][]byte{[]byte(v)}})
	}
	return e
}

// TestOpenLDAPState checks the map pact-ldap-state-openldap-1 (LR-20, LR-22).
func TestOpenLDAPState(t *testing.T) {
	asOf := time.Date(2026, 10, 15, 16, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		attrs map[string]string
		want  string
	}{
		{nil, StateActive},
		{map[string]string{"pwdAccountLockedTime": "000001010000Z"}, StateDisabled},
		{map[string]string{"pwdAccountLockedTime": "20261015120000Z"}, StateLocked},
		{map[string]string{"pwdAccountLockedTime": "000001010000Z", "pwdReset": "TRUE"}, StateDisabled},
		{map[string]string{"pwdEndTime": "20261015160000Z"}, StateExpired},
		{map[string]string{"pwdEndTime": "20261015160001Z"}, StateActive},
		{map[string]string{"pwdStartTime": "20261015160001Z"}, StateExpired},
		{map[string]string{"pwdStartTime": "20261015160000Z"}, StateActive},
		{map[string]string{"pwdReset": "TRUE"}, StatePasswordChangeRequired},
		{map[string]string{"pwdReset": "FALSE"}, StateActive},
		{map[string]string{"pwdEndTime": "20260101000000Z", "pwdReset": "TRUE"}, StateExpired},
	} {
		got, err := openLDAPState(entryOf(tc.attrs), asOf)
		if err != nil || got != tc.want {
			t.Errorf("openLDAPState(%v) = %q, %v; want %q", tc.attrs, got, err, tc.want)
		}
	}
	for _, bad := range []map[string]string{{"pwdReset": "yes"}, {"pwdEndTime": "soon"}} {
		if _, err := openLDAPState(entryOf(bad), asOf); !errors.Is(err, adapter.ErrDependencyUnavailable) {
			t.Errorf("openLDAPState(%v) error %v, want dependency unavailable", bad, err)
		}
	}
	two := Entry{Attributes: []Attribute{{Name: "pwdReset", Values: [][]byte{[]byte("TRUE"), []byte("FALSE")}}}}
	if _, err := openLDAPState(two, asOf); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("two values: error %v, want dependency unavailable", err)
	}
}

// TestADState checks the map pact-ldap-state-ad-1 (LR-21).
func TestADState(t *testing.T) {
	asOf := time.Date(2026, 10, 15, 16, 0, 0, 0, time.UTC)
	// 2026-10-15T16:00:00Z in 100-nanosecond intervals since 1601-01-01.
	at := (asOf.Unix() + 11644473600) * 10_000_000
	base := map[string]string{"userAccountControl": "512", "msDS-User-Account-Control-Computed": "0",
		"accountExpires": "9223372036854775807", "pwdLastSet": "134049024000000000"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		m[k] = v
		return m
	}
	itoa := func(n int64) string { return strconv.FormatInt(n, 10) }
	for _, tc := range []struct {
		attrs map[string]string
		want  string
	}{
		{base, StateActive},
		{with("userAccountControl", "514"), StateDisabled},
		{with("msDS-User-Account-Control-Computed", "16"), StateLocked},
		{with("accountExpires", itoa(at)), StateExpired},
		{with("accountExpires", itoa(at+1)), StateActive},
		{with("accountExpires", "0"), StateActive},
		{with("pwdLastSet", "0"), StatePasswordChangeRequired},
		{with("msDS-User-Account-Control-Computed", "8388608"), StatePasswordChangeRequired},
	} {
		got, err := adState(entryOf(tc.attrs), asOf)
		if err != nil || got != tc.want {
			t.Errorf("adState(%v) = %q, %v; want %q", tc.attrs, got, err, tc.want)
		}
	}
	noExpire := with("pwdLastSet", "0")
	noExpire["userAccountControl"] = "66048"
	if got, _ := adState(entryOf(noExpire), asOf); got != StateActive {
		t.Errorf("pwdLastSet 0 with ADS_UF_DONT_EXPIRE_PASSWD: %q, want active", got)
	}
	missing := with("pwdLastSet", "")
	delete(missing, "pwdLastSet")
	for _, bad := range []map[string]string{missing, with("userAccountControl", "x")} {
		if _, err := adState(entryOf(bad), asOf); !errors.Is(err, adapter.ErrDependencyUnavailable) {
			t.Errorf("adState(%v) error %v, want dependency unavailable", bad, err)
		}
	}
}

// TestBindDenial checks the table of LR-9: the six refusals of the credential
// are denials, every other result an outage.
func TestBindDenial(t *testing.T) {
	deny := []ResultCode{49, 48, 53, 50, 32, 34}
	for c := ResultCode(0); c <= 123; c++ {
		want := false
		for _, d := range deny {
			want = want || c == d
		}
		if got := bindDenial(c); got != want {
			t.Errorf("bindDenial(%d) = %v, want %v", c, got, want)
		}
	}
}

// TestOctetOrderGUID checks the conversion of an objectGUID in the order
// received and back.
func TestOctetOrderGUID(t *testing.T) {
	b := []byte{0x7a, 0x3f, 0x0c, 0x52, 0x9d, 0x41, 0x4e, 0x8b, 0xa6, 0xf2, 0, 0, 0, 0, 0x31, 0x01}
	s, err := OctetOrderGUID.Text(b)
	if err != nil || s != "7a3f0c52-9d41-4e8b-a6f2-000000003101" {
		t.Fatalf("Text = %q, %v", s, err)
	}
	back, err := OctetOrderGUID.Octets(s)
	if err != nil || string(back) != string(b) {
		t.Fatalf("Octets = %x, %v", back, err)
	}
	if _, err := OctetOrderGUID.Text(b[:15]); err == nil {
		t.Error("15 octets converted")
	}
	if _, err := OctetOrderGUID.Octets("7A3F0C52-9D41-4E8B-A6F2-000000003101"); err == nil {
		t.Error("upper-case text converted")
	}
}

// TestParseID checks the identifier form of LR-2.
func TestParseID(t *testing.T) {
	r, u, ok := parseID("ldap:hq:5c0e8a1e-3b7d-4f2a-9c61-000000001101")
	if !ok || r != "hq" || u != "5c0e8a1e-3b7d-4f2a-9c61-000000001101" {
		t.Errorf("parseID = %q, %q, %v", r, u, ok)
	}
	for _, bad := range []string{"", "ldap:hq", "ldap::5c0e8a1e-3b7d-4f2a-9c61-000000001101", "ldap:hq:Inventory Assistant",
		"ldap:hq:5C0E8A1E-3B7D-4F2A-9C61-000000001101", "basic:hq:5c0e8a1e-3b7d-4f2a-9c61-000000001101"} {
		if _, _, ok := parseID(bad); ok {
			t.Errorf("parseID(%q) accepted", bad)
		}
	}
}

// TestServerRefusesUnverifiedTLS checks that [Server] opens nothing without a
// TLS configuration that verifies the server, or for a URL that is not ldap
// or ldaps (LR-4).
func TestServerRefusesUnverifiedTLS(t *testing.T) {
	for _, s := range []Server{
		{URL: "ldaps://directory.example"},
		{URL: "ldaps://directory.example", TLS: &tls.Config{InsecureSkipVerify: true}},
		{URL: "ldapi:///var/run/slapd", TLS: &tls.Config{}},
		{URL: "http://directory.example", TLS: &tls.Config{}},
	} {
		if _, err := s.Open(t.Context()); err == nil {
			t.Errorf("Open(%+v) succeeded", s)
		}
	}
}

// TestNewRefusesIncompleteRealms checks the realm record rules of Appendix A.
func TestNewRefusesIncompleteRealms(t *testing.T) {
	ok := RealmConfig{
		ID: "hq", Kind: KindOpenLDAP, Directory: Server{URL: "ldaps://directory.example", TLS: &tls.Config{}},
		UserBases: []string{"ou=people,dc=x"}, GroupBases: []string{"ou=groups,dc=x"},
		AccountClass: "inetOrgPerson", GroupClass: "groupOfNames", LoginAttribute: "uid",
		LookupDN: "uid=pact-lookup,dc=x", LookupPassword: "secret-value",
		Sentinel: Sentinel{Account: "5c0e8a1e-3b7d-4f2a-9c61-000000001108", Group: "5c0e8a1e-3b7d-4f2a-9c61-000000001204"},
		Nested:   NestingNone,
	}
	pact := adapter.Realm{TenantID: "t", EnvironmentID: "e"}
	if _, err := newRealm(ok, pact); err != nil {
		t.Fatalf("valid realm: %v", err)
	}
	for name, mut := range map[string]func(*RealmConfig){
		"realm id with a colon":     func(r *RealmConfig) { r.ID = "h:q" },
		"no directory":              func(r *RealmConfig) { r.Directory = nil },
		"openldap with ad-chain":    func(r *RealmConfig) { r.Nested = NestingADChain },
		"activedirectory, no codec": func(r *RealmConfig) { r.Kind = KindActiveDirectory },
		"no lookup password":        func(r *RealmConfig) { r.LookupPassword = "" },
		"no sentinel":               func(r *RealmConfig) { r.Sentinel = Sentinel{} },
		"sentinel id not a UUID":    func(r *RealmConfig) { r.Sentinel.Account = "pact-sentinel" },
		"bad base":                  func(r *RealmConfig) { r.UserBases = []string{"not a dn"} },
		"ad-chain without parent": func(r *RealmConfig) {
			r.Kind, r.GUIDText, r.Nested = KindActiveDirectory, OctetOrderGUID, NestingADChain
		},
		"no login attribute":          func(r *RealmConfig) { r.LoginAttribute = "" },
		"kind other than the profile": func(r *RealmConfig) { r.Kind = "ad-lds" },
	} {
		rc := ok
		mut(&rc)
		if _, err := newRealm(rc, pact); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// script is a Directory whose sessions answer from functions, for the
// answers a fixture server does not give: references, limits, result codes
// of a bind, and the forms of a "Who am I?" response.
type script struct {
	bind   func(dn, password string) error
	search func(q Query) (Result, error)
	whoami func() (string, bool, error)
}

func (s script) Open(context.Context) (Session, error) { return scriptSession{s}, nil }

type scriptSession struct{ s script }

func (s scriptSession) Bind(_ context.Context, dn, pw string) error { return s.s.bind(dn, pw) }
func (s scriptSession) Search(_ context.Context, q Query) (Result, error) {
	return s.s.search(q)
}
func (s scriptSession) WhoAmI(context.Context) (string, bool, error) { return s.s.whoami() }
func (s scriptSession) Close() error                                 { return nil }

const (
	scriptUser     = "uid=a,ou=people,dc=x"
	scriptUserID   = "5c0e8a1e-3b7d-4f2a-9c61-000000001101"
	scriptSentinel = "5c0e8a1e-3b7d-4f2a-9c61-000000001108"
	scriptGroup    = "5c0e8a1e-3b7d-4f2a-9c61-000000001204"
)

func entryWith(dn string, attrs ...string) Entry {
	e := Entry{DN: dn}
	for i := 0; i+1 < len(attrs); i += 2 {
		e.Attributes = append(e.Attributes, Attribute{Name: attrs[i], Values: [][]byte{[]byte(attrs[i+1])}})
	}
	return e
}

// scriptAdapter builds the adapter over one openldap realm of s.
func scriptAdapter(t *testing.T, s script) *Adapter {
	t.Helper()
	a, err := New(Config{
		Realm: adapter.Realm{TenantID: "t", EnvironmentID: "e"}, Origin: "https://gateway.example",
		Realms: []RealmConfig{{
			ID: "hq", Kind: KindOpenLDAP, Directory: s,
			UserBases: []string{"ou=people,dc=x"}, GroupBases: []string{"ou=groups,dc=x"},
			AccountClass: "inetOrgPerson", GroupClass: "groupOfNames", LoginAttribute: "uid",
			LookupDN: "uid=lookup,dc=x", LookupPassword: "lookup-secret-value",
			Sentinel:     Sentinel{Account: scriptSentinel, Group: scriptGroup},
			DirectGroups: true, Nested: NestingNone,
		}},
		LoginRealm: "hq", Registry: nilRegistry{}, Permissions: nilPermissions{},
		Clock: fixedClock{time.Unix(1792080000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type nilRegistry struct{}

func (nilRegistry) Lookup(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}
func (nilRegistry) Rotate(context.Context, enroll.Actor, string, core.Digest) error { return nil }
func (nilRegistry) MarkCompromised(context.Context, enroll.Actor, string) error     { return nil }

type nilPermissions struct{}

func (nilPermissions) Decide(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	return adapter.Decision{Effect: adapter.EffectDeny, SourceID: "p"}, nil
}

func basicRequest() *http.Request {
	r := Mark(httptest.NewRequest(http.MethodGet, "https://gateway.example/api/v1/warehouses/WH-7/stock", nil))
	r.SetBasicAuth("a", "user-secret-value")
	return r
}

// okScript answers a login and a bind for the user, the root DSE with the
// "Who am I?" operation, and that operation with the user's DN.
func okScript() script {
	return script{
		bind: func(string, string) error { return nil },
		search: func(q Query) (Result, error) {
			if q.Base == "" {
				return Result{Entries: []Entry{entryWith("", "supportedExtension", WhoAmIOID)}}, nil
			}
			return Result{Entries: []Entry{entryWith(scriptUser, "entryUUID", scriptUserID)}}, nil
		},
		whoami: func() (string, bool, error) { return "dn:" + scriptUser, true, nil },
	}
}

func codeOf(err error) string {
	var d *adapter.NativeDenial
	if errors.As(err, &d) {
		return "denied " + string(d.PublicReason())
	}
	if c, ok := adapter.CodeOf(err); ok {
		return string(c)
	}
	if err != nil {
		return "uncoded"
	}
	return "ok"
}

// TestAuthenticateAnswers checks the result tables of LR-8, LR-9 and LR-11 on
// answers a fixture server does not give.
func TestAuthenticateAnswers(t *testing.T) {
	login := func(r Result) func(Query) (Result, error) {
		ok := okScript().search
		return func(q Query) (Result, error) {
			if q.Base == "" {
				return ok(q)
			}
			return r, nil
		}
	}
	userBind := func(err error) func(string, string) error {
		return func(dn, _ string) error {
			if dn == "uid=lookup,dc=x" {
				return nil
			}
			return err
		}
	}
	for name, tc := range map[string]struct {
		mut  func(*script)
		want string
	}{
		"control": {func(*script) {}, "ok"},
		"reference in the login search": {func(s *script) {
			s.search = login(Result{Entries: []Entry{entryWith(scriptUser, "entryUUID", scriptUserID)}, References: []string{"ldap://other.example/"}})
		}, "DEPENDENCY_UNAVAILABLE"},
		"referral result":        {func(s *script) { s.search = login(Result{Code: ResultReferral}) }, "DEPENDENCY_UNAVAILABLE"},
		"time limit exceeded":    {func(s *script) { s.search = login(Result{Code: ResultTimeLimitExceeded}) }, "DEPENDENCY_UNAVAILABLE"},
		"size limit exceeded":    {func(s *script) { s.search = login(Result{Code: ResultSizeLimitExceeded}) }, "denied CREDENTIAL_REJECTED"},
		"no unique id":           {func(s *script) { s.search = login(Result{Entries: []Entry{entryWith(scriptUser)}}) }, "DEPENDENCY_UNAVAILABLE"},
		"invalid credentials":    {func(s *script) { s.bind = userBind(&ResultError{Code: ResultInvalidCredentials}) }, "denied CREDENTIAL_REJECTED"},
		"stronger auth required": {func(s *script) { s.bind = userBind(&ResultError{Code: ResultStrongerAuthRequired}) }, "DEPENDENCY_UNAVAILABLE"},
		"bind transport failure": {func(s *script) { s.bind = userBind(errors.New("reset")) }, "DEPENDENCY_UNAVAILABLE"},
		"anonymous after bind":   {func(s *script) { s.whoami = func() (string, bool, error) { return "", true, nil } }, "denied CREDENTIAL_REJECTED"},
		"no response field":      {func(s *script) { s.whoami = func() (string, bool, error) { return "", false, nil } }, "DEPENDENCY_UNAVAILABLE"},
		"who am I refused": {func(s *script) {
			s.whoami = func() (string, bool, error) { return "", false, &ResultError{Code: ResultUnwillingToPerform} }
		}, "DEPENDENCY_UNAVAILABLE"},
	} {
		s := okScript()
		tc.mut(&s)
		_, err := scriptAdapter(t, s).AuthenticateNative(t.Context(), basicRequest())
		if got := codeOf(err); got != tc.want {
			t.Errorf("%s: %s (%v), want %s", name, got, err, tc.want)
		}
	}
}

// TestReadAnswers checks LR-15 and LR-16 on answers a fixture server does not
// give: an incomplete answer is an outage, and a memberOf value that names no
// readable group is dropped.
func TestReadAnswers(t *testing.T) {
	sentinel := entryWith("uid=s,ou=people,dc=x", "entryUUID", scriptSentinel, "memberOf", "cn=sg,ou=groups,dc=x")
	user := entryWith(scriptUser, "entryUUID", scriptUserID, "memberOf", "cn=gone,ou=groups,dc=x")
	search := func(over func(q Query) (Result, bool)) func(Query) (Result, error) {
		return func(q Query) (Result, error) {
			if r, ok := over(q); ok {
				return r, nil
			}
			switch {
			case q.Base == "cn=sg,ou=groups,dc=x":
				return Result{Entries: []Entry{entryWith(q.Base, "entryUUID", scriptGroup)}}, nil
			case q.Base == "cn=gone,ou=groups,dc=x":
				return Result{Code: ResultNoSuchObject}, nil
			case strings.Contains(q.Filter.String(), scriptSentinel):
				return Result{Entries: []Entry{sentinel}}, nil
			}
			return Result{Entries: []Entry{user}}, nil
		}
	}
	cc := adapter.ClaimContext{Principal: adapter.Principal{ID: "ldap:hq:" + scriptUserID, Realm: adapter.Realm{TenantID: "t", EnvironmentID: "e"}}}
	for name, tc := range map[string]struct {
		over func(q Query) (Result, bool)
		want string
	}{
		"dangling memberOf dropped": {func(Query) (Result, bool) { return Result{}, false }, "ok []"},
		"reference in the subject read": {func(q Query) (Result, bool) {
			return Result{Entries: []Entry{user}, References: []string{"ldap://other.example/"}}, strings.Contains(q.Filter.String(), scriptUserID)
		}, "DEPENDENCY_UNAVAILABLE"},
		"admin limit in the group read": {func(q Query) (Result, bool) {
			return Result{Code: ResultAdminLimitExceeded}, q.Base == "cn=gone,ou=groups,dc=x"
		}, "DEPENDENCY_UNAVAILABLE"},
		"two entries for one unique id": {func(q Query) (Result, bool) {
			return Result{Entries: []Entry{user, user}}, strings.Contains(q.Filter.String(), scriptUserID)
		}, "DEPENDENCY_UNAVAILABLE"},
	} {
		s := okScript()
		s.search = search(tc.over)
		c, err := scriptAdapter(t, s).ReadNativeClaim(t.Context(), PathGroupIDs, cc)
		got := codeOf(err)
		if err == nil {
			got = fmt.Sprintf("ok %v", c.Value)
		}
		if got != tc.want {
			t.Errorf("%s: %s (%v), want %s", name, got, err, tc.want)
		}
	}
}
