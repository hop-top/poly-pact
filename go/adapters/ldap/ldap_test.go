package ldap_test

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/enroll"
	enrollmem "hop.top/pact-go/adapter/enroll/memory"
	"hop.top/pact-go/core"
)

// replaced are the common authenticate_native cases whose expected principal
// an LDAP account cannot carry, each with the LDAP case that shows the same
// property (profile section 10, "Replaced common cases").
var replaced = map[string]adaptertest.Replacement{
	"COMMON-01.credential-wins": {
		By:     "LDAP-01.identity-headers-ignored",
		Reason: "expects https://idp.acme.example/bob; LR-2 derives ldap:{realm_id}:{unique_id} from the bound entry",
	},
	"COMMON-02.via-enforcement-point": {
		By:     "LDAP-01.valid",
		Reason: "expects https://idp.acme.example/alice; LR-2 derives ldap:{realm_id}:{unique_id} from the bound entry",
	},
	"COMMON-09.authenticate-realm": {
		By:     "LDAP-09.branch-login",
		Reason: "expects a globex principal id that no directory entry yields; the realm is the realm record's (LR-1)",
	},
	"IDENT-01.authenticate": {
		By:     "LDAP-04.same-cn-other-login",
		Reason: "expects a basic: account identifier; another account of the directory authenticates as its own entryUUID (LR-2, LR-11)",
	},
	"IDENT-02.authenticate": {
		By:     "LDAP-09.branch-login",
		Reason: "expects an oauth: identifier of another tenant; the same login name in another realm is another principal under its realm id (LR-1, LR-2)",
	},
	"IDENT-03.authenticate": {
		By:     "LDAP-01.valid",
		Reason: "splits user and client; a dedicated directory account is both principal and workload (identity-mapping 3.4)",
	},
	"IDENT-05.authenticate": {
		By:     "LDAP-04.same-cn-other-login",
		Reason: "expects a basic: account identifier; an account with the same cn and display name authenticates as its own entryUUID (LR-11)",
	},
}

// TestConformance runs the conformance suite, the common cases and the LDAP
// cases of spec/v1.0/fixtures/adapters/ldap, with the seven replaced common cases
// declared. The LDAP profile does not support workloads shared by several
// agents, so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, ldapFactory, adaptertest.Options{Adapter: "ldap", Replaced: replaced})
}

// TestEnrollmentRefusesSecondAgentOnAccount is part (a) of LDAP-11: the
// enrollment that would add a second agent to one directory account is
// refused, so the account keeps one agent, which alone binds (identity
// mapping IM-19, profile section 7).
func TestEnrollmentRefusesSecondAgentOnAccount(t *testing.T) {
	ctx := context.Background()
	realm := adapter.Realm{TenantID: "northstar", EnvironmentID: "https://gateway.northstar.example/environments/inventory"}
	account := adapter.Workload("ldap:hq:5c0e8a1e-3b7d-4f2a-9c61-000000001101")
	admin := enroll.Actor{Kind: enroll.Admin, ID: "identity-admin-1", Realm: realm}
	agentA := "https://agents.northstar.example/inventory-assistant"
	agentB := "https://agents.northstar.example/inventory-auditor"
	reg := enrollmem.New()

	if err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentA, OperatorID: "https://operators.northstar.example/inventory-ops",
		Workload: account, HolderJKT: core.Digest("xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"),
	}); err != nil {
		t.Fatalf("first agent: Enroll() = %v", err)
	}
	err := reg.Enroll(ctx, admin, enrollmem.Enrollment{
		AgentID: agentB, OperatorID: "https://operators.northstar.example/inventory-ops",
		Workload: account, HolderJKT: core.Digest("ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg"),
	})
	if !errors.Is(err, enroll.ErrWorkloadInUse) {
		t.Fatalf("second agent on the account: Enroll() = %v, want ErrWorkloadInUse", err)
	}
	res := enroll.Resolver{Registry: reg}
	a, err := res.ResolveAgentBinding(ctx, realm, account, adapter.AgentID(agentA))
	if err != nil || a.Status != adapter.BindingActive || a.HolderJKT != "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M" {
		t.Errorf("agent A: binding %+v, error %v; want ACTIVE with A's key", a, err)
	}
	b, err := res.ResolveAgentBinding(ctx, realm, account, adapter.AgentID(agentB))
	if err != nil || b.Status != adapter.BindingUnknown || b.HolderJKT != "" {
		t.Errorf("agent B: binding %+v, error %v; want UNKNOWN with no key", b, err)
	}
}

// TestFixtureWorlds loads the native state of every LDAP case and checks what
// the cases rely on: each server's unique ids are unique, and each realm's
// sentinel account, group and parent group exist with the membership LR-14
// requires.
func TestFixtureWorlds(t *testing.T) {
	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	cases, err := adaptertest.Load(fsys, "ldap")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, c := range cases {
		if !strings.HasPrefix(c.ID, "LDAP-") {
			continue
		}
		seen++
		w, err := loadWorld(c.NativeState, fsys)
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		for name, srv := range w.servers {
			ids := map[string]string{}
			for _, e := range srv.entries {
				id := srv.uniqueID(e)
				if id == "" {
					t.Errorf("%s: %s: %s has no unique id", c.ID, name, e.dn)
				} else if prev, dup := ids[id]; dup {
					t.Errorf("%s: %s: %s and %s share %s", c.ID, name, prev, e.dn, id)
				}
				ids[id] = e.dn
			}
		}
		for _, r := range w.st.Realms {
			srv := w.servers[r.Directory]
			s, g := srv.byUniqueID(r.Sentinel.Account), srv.byUniqueID(r.Sentinel.Group)
			if s == nil || g == nil || !s.has("memberOf", g.dn) {
				t.Errorf("%s: realm %s: the sentinel account is missing or not a direct member of its group", c.ID, r.RealmID)
			}
			if r.Sentinel.ParentGroup != "" {
				if p := srv.byUniqueID(r.Sentinel.ParentGroup); p == nil || g == nil || !p.has("member", g.dn) {
					t.Errorf("%s: realm %s: the sentinel parent group does not hold the sentinel group", c.ID, r.RealmID)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no LDAP case loaded")
	}
	// Every asset parses.
	assets, err := fs.Glob(fsys, path.Join(casesDir, "assets", "*.ldif"))
	if err != nil || len(assets) == 0 {
		t.Fatalf("assets: %v, %d files", err, len(assets))
	}
	for _, a := range assets {
		if _, err := readLDIF(fsys, strings.TrimPrefix(a, casesDir+"/")); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
}

// TestParseLDIF checks the LDIF reader on the forms of RFC 2849 the assets
// use: folded lines, comments, base64 values and the three change types.
func TestParseLDIF(t *testing.T) {
	src := "version: 1\n# comment\ndn: cn=a,dc=x\nobjectClass: top\ndescription: one\n  two\nobjectGUID:: AAEC\n\n" +
		"dn: cn=g,dc=x\nchangetype: modify\ndelete: member\nmember: cn=a,dc=x\n-\nreplace: cn\ncn: g2\n-\n\n" +
		"dn: cn=a,dc=x\nchangetype: delete\n"
	recs, err := parseLDIF([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("%d records, want 3", len(recs))
	}
	e := &entry{dn: recs[0].dn, attrs: recs[0].attrs}
	if got := e.first("description"); got != "one two" {
		t.Errorf("folded line: %q", got)
	}
	if got := e.get("objectGUID"); len(got) != 1 || string(got[0]) != "\x00\x01\x02" {
		t.Errorf("base64 value: %q", got)
	}
	if recs[1].changeType != "modify" || len(recs[1].mods) != 2 || recs[1].mods[0].op != "delete" || recs[1].mods[1].op != "replace" {
		t.Errorf("modify record: %+v", recs[1])
	}
	if recs[2].changeType != "delete" {
		t.Errorf("delete record: %+v", recs[2])
	}
	for _, bad := range []string{
		"dn: cn=a\n",
		"version: 1\ndn: cn=a\njpegPhoto:< file:///x\n",
		"version: 1\ndn: cn=a\nchangetype: moddn\nnewrdn: cn=b\ndeleteoldrdn: 1\n",
		"version: 1\ndn: cn=a\nchangetype: modify\nadd: cn\ncn: b\n",
	} {
		if _, err := parseLDIF([]byte(bad)); err == nil {
			t.Errorf("parseLDIF(%q) succeeded", bad)
		}
	}
}
