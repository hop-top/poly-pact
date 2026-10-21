package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/scim"
	"hop.top/pact-go/core/clock"
)

const (
	prefix  = "oauth:https%3A%2F%2Fidp.example%2Ftenant-1:tenant-1:"
	token   = "provisioning-token-0001"
	roToken = "readonly-token-0002"
	base    = "/scim/v2"
	userURN = "urn:ietf:params:scim:schemas:core:2.0:User"
	grpURN  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	patchOp = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

var epoch = time.Unix(1792080000, 0)

type env struct {
	t     *testing.T
	srv   *scim.Server
	clk   *clock.Fake
	store source.Store
	logs  *bytes.Buffer
}

func config(clk clock.Clock, st source.Store) scim.Config {
	return scim.Config{
		Store: st, SourceID: "scim-test", BasePath: base,
		Join:        source.Join{Attribute: "externalId", Prefix: prefix},
		Credentials: []scim.Credential{{Token: token, Provisioning: true}, {Token: roToken}},
		Lag:         2400 * time.Second, Clock: clk,
	}
}

func newEnv(t *testing.T, mod ...func(*scim.Config)) *env {
	t.Helper()
	e := &env{t: t, clk: clock.NewFake(epoch), store: source.NewMemory(), logs: &bytes.Buffer{}}
	cfg := config(e.clk, e.store)
	cfg.ErrorLog = log.New(e.logs, "", 0)
	for _, m := range mod {
		m(&cfg)
	}
	srv, err := scim.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	return e
}

type reply struct {
	code int
	hdr  http.Header
	raw  string
	body map[string]any
}

func (e *env) do(method, path, auth, body string) reply {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	r := reply{code: res.StatusCode, hdr: res.Header, raw: string(b)}
	_ = json.Unmarshal(b, &r.body)
	return r
}

// do as the provisioning client.
func (e *env) pc(method, path, body string) reply {
	e.t.Helper()
	return e.do(method, base+path, "Bearer "+token, body)
}

func (e *env) want(r reply, code int, scimType string) reply {
	e.t.Helper()
	if r.code != code {
		e.t.Fatalf("status %d, want %d: %s", r.code, code, r.raw)
	}
	if scimType != "" && r.body["scimType"] != scimType {
		e.t.Fatalf("scimType %v, want %s: %s", r.body["scimType"], scimType, r.raw)
	}
	return r
}

func (e *env) createUser(name, ext string, extra string) string {
	e.t.Helper()
	b := fmt.Sprintf(`{"schemas":[%q],"userName":%q,"externalId":%q,"active":true%s}`, userURN, name, ext, extra)
	if ext == "" {
		b = fmt.Sprintf(`{"schemas":[%q],"userName":%q,"active":true%s}`, userURN, name, extra)
	}
	r := e.want(e.pc("POST", "/Users", b), 201, "")
	return r.body["id"].(string)
}

func (e *env) createGroup(name, ext string, members ...string) string {
	e.t.Helper()
	var ms []string
	for _, m := range members {
		ms = append(ms, fmt.Sprintf(`{"value":%q}`, m))
	}
	ex := ""
	if ext != "" {
		ex = fmt.Sprintf(`,"externalId":%q`, ext)
	}
	b := fmt.Sprintf(`{"schemas":[%q],"displayName":%q%s,"members":[%s]}`, grpURN, name, ex, strings.Join(ms, ","))
	return e.want(e.pc("POST", "/Groups", b), 201, "").body["id"].(string)
}

func (e *env) patch(kind, id string, ops ...string) reply {
	e.t.Helper()
	b := fmt.Sprintf(`{"schemas":[%q],"Operations":[%s]}`, patchOp, strings.Join(ops, ","))
	return e.pc("PATCH", "/"+kind+"/"+id, b)
}

func (e *env) read(ext, path string) (adapter.NativeClaim, error) {
	e.t.Helper()
	return e.srv.Reader().ReadNativeClaim(context.Background(), path,
		adapter.ClaimContext{Principal: adapter.Principal{ID: prefix + ext}})
}

func (e *env) value(ext, path string) string {
	e.t.Helper()
	c, err := e.read(ext, path)
	if err != nil {
		e.t.Fatalf("read %s %s: %v", ext, path, err)
	}
	b, _ := json.Marshal(c.Value)
	return string(b)
}

func (e *env) absent(ext, path string) {
	e.t.Helper()
	if c, err := e.read(ext, path); !errors.Is(err, adapter.ErrMissingField) {
		e.t.Fatalf("read %s %s = %v, %v; want ErrMissingField", ext, path, c.Value, err)
	}
}

// ---- construction ----

func TestNewRefusesBadConfig(t *testing.T) {
	clk := clock.NewFake(epoch)
	for name, mod := range map[string]func(*scim.Config){
		"no clock":                 func(c *scim.Config) { c.Clock = nil },
		"no source id":             func(c *scim.Config) { c.SourceID = "" },
		"zero lag":                 func(c *scim.Config) { c.Lag = 0 },
		"sub-second lag":           func(c *scim.Config) { c.Lag = time.Millisecond },
		"user name join":           func(c *scim.Config) { c.Join.Attribute = "userName" },
		"email join":               func(c *scim.Config) { c.Join.Attribute = "emails" },
		"no join attribute":        func(c *scim.Config) { c.Join.Attribute = "" },
		"prefix not an identifier": func(c *scim.Config) { c.Join.Prefix = "tenant-1:" },
		"prefix without colon":     func(c *scim.Config) { c.Join.Prefix = "oauth:iss:tid" },
		"no credentials":           func(c *scim.Config) { c.Credentials = nil },
		"empty token":              func(c *scim.Config) { c.Credentials = []scim.Credential{{Provisioning: true}} },
		"duplicate token": func(c *scim.Config) {
			c.Credentials = []scim.Credential{{Token: "a", Provisioning: true}, {Token: "a"}}
		},
		"token with space":            func(c *scim.Config) { c.Credentials = []scim.Credential{{Token: "a b", Provisioning: true}} },
		"no credential may provision": func(c *scim.Config) { c.Credentials = []scim.Credential{{Token: "a"}} },
		"base path without slash":     func(c *scim.Config) { c.BasePath = "scim" },
		"base path trailing slash":    func(c *scim.Config) { c.BasePath = "/scim/" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := config(clk, nil)
			mod(&cfg)
			if _, err := scim.New(cfg); err == nil {
				t.Fatal("New accepted the configuration")
			}
		})
	}
	if _, err := scim.New(config(clk, nil)); err != nil {
		t.Fatalf("New with a nil store: %v", err)
	}
	cfg := config(clk, nil)
	cfg.BasePath = ""
	if _, err := scim.New(cfg); err != nil {
		t.Fatalf("New with no base path: %v", err)
	}
}

// ---- authentication (RFC 7644 section 3.12, Table 8; RFC 6750 section 3) ----

func TestAuthentication(t *testing.T) {
	e := newEnv(t)
	body := `{"schemas":["` + userURN + `"],"userName":"a","externalId":"x1"}`
	for name, c := range map[string]struct {
		auth  string
		code  int
		wantE string
	}{
		"none":         {"", 401, ""},
		"wrong token":  {"Bearer nope", 401, "invalid_token"},
		"empty bearer": {"Bearer ", 401, "invalid_token"},
		"basic":        {"Basic YTpi", 401, ""},
		"token alone":  {token, 401, ""},
		"read only":    {"Bearer " + roToken, 403, "insufficient_scope"},
		"lower scheme": {"bearer " + token, 201, ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			r := e.do("POST", base+"/Users", c.auth, body)
			if r.code != c.code {
				t.Fatalf("status %d, want %d: %s", r.code, c.code, r.raw)
			}
			if c.code == 201 {
				return
			}
			h := r.hdr.Get("WWW-Authenticate")
			if !strings.HasPrefix(h, "Bearer ") {
				t.Fatalf("WWW-Authenticate %q is not a Bearer challenge", h)
			}
			if has := strings.Contains(h, `error="`+c.wantE+`"`); c.wantE != "" && !has || c.wantE == "" && strings.Contains(h, "error=") {
				t.Fatalf("WWW-Authenticate %q, want error %q", h, c.wantE)
			}
			if r.body["status"] != fmt.Sprint(c.code) || r.body["schemas"] == nil {
				t.Errorf("body %s is not a SCIM error", r.raw)
			}
			e.absent("x1", "/principal/account_state")
		})
	}
	// Every method and path under the base path needs the token.
	for _, p := range []string{"/Users", "/Users/zzz", "/Groups", "/Groups/zzz", "/Nothing", "/Users/zzz/extra"} {
		for _, m := range []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"} {
			if r := e.do(m, base+p, "", ""); r.code != 401 {
				t.Errorf("%s %s without a token = %d, want 401", m, p, r.code)
			}
			if r := e.do(m, base+p, "Bearer "+roToken, ""); r.code != 403 {
				t.Errorf("%s %s with a read-only token = %d, want 403", m, p, r.code)
			}
		}
	}
}

func TestServiceProviderConfigIsPublic(t *testing.T) {
	e := newEnv(t)
	r := e.want(e.do("GET", base+"/ServiceProviderConfig", "", ""), 200, "")
	if r.hdr.Get("Content-Type") != "application/scim+json" {
		t.Errorf("Content-Type %q", r.hdr.Get("Content-Type"))
	}
	for _, k := range []string{"schemas", "patch", "bulk", "filter", "changePassword", "sort", "etag", "authenticationSchemes"} {
		if r.body[k] == nil {
			t.Errorf("ServiceProviderConfig lacks %s", k)
		}
	}
	if p, _ := r.body["patch"].(map[string]any); p["supported"] != true {
		t.Errorf("patch = %v", r.body["patch"])
	}
	if b, _ := r.body["bulk"].(map[string]any); b["supported"] != false {
		t.Errorf("bulk = %v", r.body["bulk"])
	}
	schemes := r.body["authenticationSchemes"].([]any)
	if s := schemes[0].(map[string]any); s["type"] != "oauthbearertoken" {
		t.Errorf("authentication scheme %v", s)
	}
	e.want(e.do("POST", base+"/ServiceProviderConfig", "", "{}"), 405, "")
	e.want(e.do("GET", base+"/ServiceProviderConfig/x", "", ""), 401, "")
}

// ---- requests ----

func TestUnknownRoutesAndMethods(t *testing.T) {
	e := newEnv(t)
	e.want(e.pc("GET", "/Nothing", ""), 404, "")
	e.want(e.pc("GET", "/Users/", ""), 404, "")
	e.want(e.pc("GET", "/Users/a/b", ""), 404, "")
	e.want(e.do("GET", "/elsewhere/Users", "Bearer "+token, ""), 404, "")
	e.want(e.pc("GET", "/Users/nope", ""), 404, "")
	e.want(e.pc("PATCH", "/Users/nope", `{"schemas":["`+patchOp+`"],"Operations":[]}`), 404, "")
	e.want(e.pc("DELETE", "/Groups/nope", ""), 404, "")
	e.want(e.pc("PUT", "/Users/x", `{}`), 501, "")
	r := e.want(e.pc("OPTIONS", "/Users", ""), 405, "")
	if r.hdr.Get("Allow") == "" {
		t.Error("405 without Allow")
	}
	e.want(e.pc("DELETE", "/Users", ""), 405, "")
	e.want(e.pc("POST", "/Users/x", `{}`), 405, "")
	e.want(e.pc("PATCH", "/Users", `{}`), 405, "")
}

func TestCreateUser(t *testing.T) {
	e := newEnv(t)
	r := e.want(e.pc("POST", "/Users", `{"schemas":["`+userURN+`"],"id":"client-chosen","userName":"Avery","externalId":"oid-1","active":true,"displayName":"Avery Lin","emails":[{"value":"a@x.example"}],"meta":{"x":1}}`), 201, "")
	id := r.body["id"].(string)
	if id == "" || id == "client-chosen" {
		t.Fatalf("id %q: the service issues it", id)
	}
	if r.hdr.Get("Content-Type") != "application/scim+json" {
		t.Errorf("Content-Type %q", r.hdr.Get("Content-Type"))
	}
	meta := r.body["meta"].(map[string]any)
	loc := meta["location"].(string)
	if !strings.HasSuffix(loc, base+"/Users/"+id) || r.hdr.Get("Location") != loc || meta["resourceType"] != "User" {
		t.Errorf("meta %v, Location %q", meta, r.hdr.Get("Location"))
	}
	if meta["created"] != "2026-10-15T16:00:00Z" || meta["lastModified"] != meta["created"] {
		t.Errorf("meta times %v", meta)
	}
	for k, want := range map[string]any{"userName": "Avery", "externalId": "oid-1", "active": true, "displayName": "Avery Lin"} {
		if r.body[k] != want {
			t.Errorf("%s = %v, want %v", k, r.body[k], want)
		}
	}
	got := e.want(e.pc("GET", "/Users/"+id, ""), 200, "")
	if got.body["id"] != id {
		t.Errorf("GET = %s", got.raw)
	}
	id2 := e.createUser("other", "oid-2", "")
	if id2 == id {
		t.Error("two users share an id")
	}
}

func TestCreateValidation(t *testing.T) {
	e := newEnv(t)
	for name, c := range map[string]struct {
		body, kind string
		code       int
	}{
		"not JSON":         {`{`, "invalidSyntax", 400},
		"array":            {`[]`, "invalidSyntax", 400},
		"empty":            {``, "invalidSyntax", 400},
		"duplicate keys":   {`{"schemas":["` + userURN + `"],"userName":"a","userName":"b"}`, "invalidSyntax", 400},
		"no schemas":       {`{"userName":"a"}`, "invalidValue", 400},
		"wrong schema":     {`{"schemas":["` + grpURN + `"],"userName":"a"}`, "invalidValue", 400},
		"schemas not list": {`{"schemas":"` + userURN + `","userName":"a"}`, "invalidValue", 400},
		"no userName":      {`{"schemas":["` + userURN + `"]}`, "invalidValue", 400},
		"empty userName":   {`{"schemas":["` + userURN + `"],"userName":""}`, "invalidValue", 400},
		"userName number":  {`{"schemas":["` + userURN + `"],"userName":5}`, "invalidValue", 400},
		"externalId num":   {`{"schemas":["` + userURN + `"],"userName":"a","externalId":5}`, "invalidValue", 400},
		"active string":    {`{"schemas":["` + userURN + `"],"userName":"a","active":"false"}`, "invalidValue", 400},
		"too large":        {`{"schemas":["` + userURN + `"],"userName":"` + strings.Repeat("a", 1<<20) + `"}`, "", 413},
	} {
		t.Run(name, func(t *testing.T) {
			r := e.pc("POST", "/Users", c.body)
			if r.code != c.code {
				t.Fatalf("status %d, want %d: %.200s", r.code, c.code, r.raw)
			}
			if c.kind != "" && r.body["scimType"] != c.kind {
				t.Fatalf("scimType %v, want %s", r.body["scimType"], c.kind)
			}
			if r.body["status"] != fmt.Sprint(c.code) {
				t.Errorf("error status %v", r.body["status"])
			}
		})
	}
	e.want(e.pc("GET", "/Users", ""), 200, "")
	if tr := e.pc("GET", "/Users", ""); tr.body["totalResults"] != float64(0) {
		t.Errorf("a rejected create left %v users", tr.body["totalResults"])
	}
}

func TestCreateGroupValidation(t *testing.T) {
	e := newEnv(t)
	uid := e.createUser("a", "oid-1", "")
	gid := e.createGroup("G", "gid-1")
	_ = gid
	for name, c := range map[string]struct{ body, kind string }{
		"no displayName":   {`{"schemas":["` + grpURN + `"]}`, "invalidValue"},
		"wrong schema":     {`{"schemas":["` + userURN + `"],"displayName":"x"}`, "invalidValue"},
		"members not list": {`{"schemas":["` + grpURN + `"],"displayName":"x","members":{}}`, "invalidValue"},
		"member no value":  {`{"schemas":["` + grpURN + `"],"displayName":"x","members":[{}]}`, "invalidValue"},
		"unknown member":   {`{"schemas":["` + grpURN + `"],"displayName":"x","members":[{"value":"nope"}]}`, "invalidValue"},
		"group member":     {`{"schemas":["` + grpURN + `"],"displayName":"x","members":[{"value":"` + gid + `"}]}`, "invalidValue"},
		"duplicate extid":  {`{"schemas":["` + grpURN + `"],"displayName":"x","externalId":"gid-1"}`, "uniqueness"},
	} {
		t.Run(name, func(t *testing.T) {
			r := e.pc("POST", "/Groups", c.body)
			if r.code != 400 && r.code != 409 || r.body["scimType"] != c.kind {
				t.Fatalf("status %d: %s", r.code, r.raw)
			}
		})
	}
	// A repeated member in one create is one member.
	g := e.createGroup("dup", "gid-2", uid, uid)
	r := e.want(e.pc("GET", "/Groups/"+g, ""), 200, "")
	if m := r.body["members"].([]any); len(m) != 1 {
		t.Errorf("members %v", m)
	}
}

func TestListFilterAndPaging(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		e.createUser(fmt.Sprintf("User%d", i), fmt.Sprintf("oid-%d", i), "")
	}
	q := func(raw string) reply { return e.want(e.pc("GET", "/Users?"+raw, ""), 200, "") }
	if r := q(""); r.body["totalResults"] != float64(5) || len(r.body["Resources"].([]any)) != 5 {
		t.Errorf("list = %s", r.raw)
	}
	r := q("filter=" + "externalId%20eq%20%22oid-3%22")
	if r.body["totalResults"] != float64(1) || r.body["Resources"].([]any)[0].(map[string]any)["userName"] != "User3" {
		t.Errorf("externalId filter = %s", r.raw)
	}
	// userName is case-insensitive (RFC 7643 section 4.1.1); externalId is exact.
	if r := q("filter=userName%20eq%20%22uSeR2%22"); r.body["totalResults"] != float64(1) {
		t.Errorf("userName filter = %s", r.raw)
	}
	if r := q("filter=externalId%20eq%20%22OID-3%22"); r.body["totalResults"] != float64(0) {
		t.Errorf("externalId is case-exact: %s", r.raw)
	}
	// A filter that matches nothing is an empty list, not an error (the
	// provisioning client's connection test).
	r = q("filter=externalId%20eq%20%22nothing%22")
	if r.body["totalResults"] != float64(0) || r.body["Resources"] == nil || len(r.body["Resources"].([]any)) != 0 {
		t.Errorf("empty filter = %s", r.raw)
	}
	if r.body["schemas"].([]any)[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
		t.Errorf("schemas %v", r.body["schemas"])
	}
	// Paging.
	r = q("startIndex=2&count=2")
	rs := r.body["Resources"].([]any)
	if len(rs) != 2 || r.body["startIndex"] != float64(2) || r.body["itemsPerPage"] != float64(2) || r.body["totalResults"] != float64(5) {
		t.Errorf("page = %s", r.raw)
	}
	if rs[0].(map[string]any)["userName"] != "User1" || rs[1].(map[string]any)["userName"] != "User2" {
		t.Errorf("page order = %s", r.raw)
	}
	if r := q("count=0"); len(r.body["Resources"].([]any)) != 0 || r.body["totalResults"] != float64(5) {
		t.Errorf("count 0 = %s", r.raw)
	}
	if r := q("startIndex=-4&count=-1"); len(r.body["Resources"].([]any)) != 0 || r.body["startIndex"] != float64(1) {
		t.Errorf("negative = %s", r.raw)
	}
	if r := q("startIndex=9"); len(r.body["Resources"].([]any)) != 0 {
		t.Errorf("past the end = %s", r.raw)
	}
	for _, bad := range []string{
		"filter=userName%20co%20%22a%22",
		"filter=emails.value%20eq%20%22a%22",
		"filter=userName%20eq%20a",
		"filter=userName%20eq%20%22a%22%20and%20active%20eq%20true",
		"filter=",
		"startIndex=x",
		"count=x",
	} {
		e.want(e.pc("GET", "/Users?"+bad, ""), 400, "")
	}
	e.want(e.pc("GET", "/Users?filter=userName%20co%20%22a%22", ""), 400, "invalidFilter")
	e.createGroup("Finance", "gid-1")
	if r := e.want(e.pc("GET", "/Groups?filter=displayName%20eq%20%22Finance%22", ""), 200, ""); r.body["totalResults"] != float64(1) {
		t.Errorf("group filter = %s", r.raw)
	}
	e.want(e.pc("GET", "/Groups?filter=userName%20eq%20%22a%22", ""), 400, "invalidFilter")
}

// ---- facts ----

func TestFactsFollowTheRecords(t *testing.T) {
	e := newEnv(t)
	u := e.createUser("avery", "oid-1", "")
	fin := e.createGroup("Finance", "gid-fin")
	aud := e.createGroup("Audit", "gid-aud")
	e.value("oid-1", "/principal/account_state")
	if v := e.value("oid-1", "/principal/account_state"); v != `"active"` {
		t.Errorf("state %s", v)
	}
	if v := e.value("oid-1", "/principal/group_ids"); v != `[]` {
		t.Errorf("groups %s", v)
	}
	e.want(e.patch("Groups", fin, `{"op":"add","path":"members","value":[{"value":"`+u+`"}]}`), 200, "")
	e.want(e.patch("Groups", aud, `{"op":"add","path":"members","value":[{"value":"`+u+`"}]}`), 200, "")
	if v := e.value("oid-1", "/principal/group_ids"); v != `["gid-aud","gid-fin"]` {
		t.Errorf("groups %s, want them sorted", v)
	}
	c, _ := e.read("oid-1", "/principal/group_ids")
	if c.SourceID != "scim-test" || c.SourceRef != u {
		t.Errorf("claim %+v: source id and the SCIM id as source ref", c)
	}
	if want := epoch.Add(-2400 * time.Second); !c.ObservedAt.Equal(want) || !c.StatusCheckedAt.Equal(want) {
		t.Errorf("times %v %v, want %v", c.ObservedAt, c.StatusCheckedAt, want)
	}
	// Deleting a group drops it from its members' facts.
	e.want(e.pc("DELETE", "/Groups/"+fin, ""), 204, "")
	if v := e.value("oid-1", "/principal/group_ids"); v != `["gid-aud"]` {
		t.Errorf("after the group delete %s", v)
	}
	e.want(e.pc("GET", "/Groups/"+fin, ""), 404, "")
	// Time moves with the read, not with the push.
	e.clk.Advance(time.Hour)
	c, _ = e.read("oid-1", "/principal/group_ids")
	if want := epoch.Add(time.Hour - 2400*time.Second); !c.ObservedAt.Equal(want) {
		t.Errorf("observed %v, want %v", c.ObservedAt, want)
	}
	// Deleting the user answers no fact and clears the groups' member lists.
	e.want(e.pc("DELETE", "/Users/"+u, ""), 204, "")
	e.absent("oid-1", "/principal/account_state")
	e.absent("oid-1", "/principal/group_ids")
	r := e.want(e.pc("GET", "/Groups/"+aud, ""), 200, "")
	if m := r.body["members"].([]any); len(m) != 0 {
		t.Errorf("members %v after the user was deleted", m)
	}
	if _, err := e.read("someone-else", "/principal/roles"); !errors.Is(err, adapter.ErrUnsupportedRequirement) {
		t.Errorf("unserved path = %v", err)
	}
}

func TestRecordWithoutJoinAnswersNoFact(t *testing.T) {
	e := newEnv(t)
	e.createUser("nobody", "", "")
	if !strings.Contains(e.logs.String(), "externalId") {
		t.Errorf("the provisioning error is not logged: %q", e.logs.String())
	}
	e.absent("nobody", "/principal/account_state")
	e.createUser("empty", "", `,"externalId":""`)
	// Never joined by user name, even when the name is a valid component.
	e.absent("empty", "/principal/account_state")
	// A group with no externalId contributes no id and is logged.
	u := e.createUser("a", "oid-1", "")
	e.createGroup("NoId", "", u)
	if v := e.value("oid-1", "/principal/group_ids"); v != `[]` {
		t.Errorf("groups %s", v)
	}
	if !strings.Contains(e.logs.String(), "group") {
		t.Errorf("the group is not logged: %q", e.logs.String())
	}
}

func TestExternalIDChangeMovesFacts(t *testing.T) {
	e := newEnv(t)
	u := e.createUser("a", "oid-1", "")
	e.createUser("b", "oid-2", "")
	e.want(e.patch("Users", u, `{"op":"replace","path":"externalId","value":"oid-3"}`), 200, "")
	e.absent("oid-1", "/principal/account_state")
	if e.value("oid-3", "/principal/account_state") != `"active"` {
		t.Error("new principal has no state")
	}
	e.want(e.patch("Users", u, `{"op":"replace","path":"externalId","value":"oid-2"}`), 409, "uniqueness")
	if e.value("oid-3", "/principal/account_state") != `"active"` {
		t.Error("a refused change moved the facts")
	}
	// Removing the externalId removes the principal's facts.
	e.want(e.patch("Users", u, `{"op":"remove","path":"externalId"}`), 200, "")
	e.absent("oid-3", "/principal/account_state")
	// A value that is not an identifier component is written percent-encoded.
	e.want(e.patch("Users", u, `{"op":"replace","path":"externalId","value":"a:b/c"}`), 200, "")
	if _, err := e.srv.Reader().ReadNativeClaim(context.Background(), "/principal/account_state",
		adapter.ClaimContext{Principal: adapter.Principal{ID: prefix + "a%3Ab%2Fc"}}); err != nil {
		t.Errorf("percent-encoded join: %v", err)
	}
}

func TestActiveUnknownAnswersNoState(t *testing.T) {
	e := newEnv(t)
	r := e.want(e.pc("POST", "/Users", `{"schemas":["`+userURN+`"],"userName":"a","externalId":"oid-1"}`), 201, "")
	if _, ok := r.body["active"]; ok {
		t.Errorf("a user created with no active has %v", r.body["active"])
	}
	e.absent("oid-1", "/principal/account_state")
	if v := e.value("oid-1", "/principal/group_ids"); v != `[]` {
		t.Errorf("groups %s", v)
	}
	id := r.body["id"].(string)
	e.want(e.patch("Users", id, `{"op":"replace","path":"active","value":true}`), 200, "")
	if e.value("oid-1", "/principal/account_state") != `"active"` {
		t.Error("state not active")
	}
	e.want(e.patch("Users", id, `{"op":"remove","path":"active"}`), 200, "")
	e.absent("oid-1", "/principal/account_state")
	if v := e.value("oid-1", "/principal/group_ids"); v != `[]` {
		t.Errorf("groups %s", v)
	}
}

// ---- PATCH ----

func TestPatchUserForms(t *testing.T) {
	e := newEnv(t)
	u := e.createUser("a", "oid-1", "")
	for name, op := range map[string]string{
		"Replace path":           `{"op":"Replace","path":"active","value":false}`,
		"replace pathless":       `{"op":"replace","value":{"active":false}}`,
		"add path":               `{"op":"add","path":"active","value":false}`,
		"upper path":             `{"op":"REPLACE","path":"ACTIVE","value":false}`,
		"schema prefixed path":   `{"op":"replace","path":"` + userURN + `:active","value":false}`,
		"pathless, case":         `{"op":"replace","value":{"Active":false}}`,
		"pathless schema prefix": `{"op":"replace","value":{"` + userURN + `:active":false}}`,
	} {
		t.Run(name, func(t *testing.T) {
			e.want(e.patch("Users", u, `{"op":"replace","path":"active","value":true}`), 200, "")
			r := e.want(e.patch("Users", u, op), 200, "")
			if r.body["active"] != false {
				t.Fatalf("response active = %v", r.body["active"])
			}
			if v := e.value("oid-1", "/principal/account_state"); v != `"disabled"` {
				t.Fatalf("state %s", v)
			}
		})
	}
}

func TestPatchIsAtomic(t *testing.T) {
	e := newEnv(t)
	u := e.createUser("a", "oid-1", "")
	g := e.createGroup("G", "gid-1", u)
	e.want(e.patch("Users", u,
		`{"op":"replace","path":"active","value":false}`,
		`{"op":"replace","path":"externalId","value":5}`), 400, "invalidValue")
	if v := e.value("oid-1", "/principal/account_state"); v != `"active"` {
		t.Errorf("a failed PATCH changed the state to %s", v)
	}
	if r := e.want(e.pc("GET", "/Users/"+u, ""), 200, ""); r.body["active"] != true {
		t.Errorf("a failed PATCH changed the record: %s", r.raw)
	}
	e.want(e.patch("Groups", g,
		`{"op":"remove","path":"members"}`,
		`{"op":"add","path":"members","value":[{"value":"nope"}]}`), 400, "invalidValue")
	if v := e.value("oid-1", "/principal/group_ids"); v != `["gid-1"]` {
		t.Errorf("a failed PATCH changed the groups to %s", v)
	}
	// Operations apply in order.
	e.want(e.patch("Groups", g,
		`{"op":"remove","path":"members"}`,
		`{"op":"add","path":"members","value":[{"value":"`+u+`"}]}`), 200, "")
	if v := e.value("oid-1", "/principal/group_ids"); v != `["gid-1"]` {
		t.Errorf("groups %s", v)
	}
}

func TestPatchValidation(t *testing.T) {
	e := newEnv(t)
	u := e.createUser("a", "oid-1", "")
	g := e.createGroup("G", "gid-1", u)
	raw := func(kind, id, body string) reply { return e.pc("PATCH", "/"+kind+"/"+id, body) }
	for name, c := range map[string]struct {
		kind, id, body, scimType string
		code                     int
	}{
		"not JSON":           {"Users", u, `{`, "invalidSyntax", 400},
		"no schemas":         {"Users", u, `{"Operations":[]}`, "invalidSyntax", 400},
		"wrong schemas":      {"Users", u, `{"schemas":["x"],"Operations":[]}`, "invalidSyntax", 400},
		"no Operations":      {"Users", u, `{"schemas":["` + patchOp + `"]}`, "invalidSyntax", 400},
		"Operations object":  {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":{}}`, "invalidSyntax", 400},
		"unknown op":         {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"move","path":"active"}]}`, "invalidSyntax", 400},
		"op not string":      {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":[{"op":1}]}`, "invalidSyntax", 400},
		"remove no path":     {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"remove"}]}`, "noTarget", 400},
		"add no value":       {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"add","path":"active"}]}`, "invalidValue", 400},
		"active string":      {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"replace","path":"active","value":"False"}]}`, "invalidValue", 400},
		"pathless not obj":   {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"replace","value":false}]}`, "invalidValue", 400},
		"remove userName":    {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"remove","path":"userName"}]}`, "mutability", 400},
		"empty userName":     {"Users", u, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"replace","path":"userName","value":""}]}`, "invalidValue", 400},
		"group bad filter":   {"Groups", g, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"remove","path":"members[type eq \"User\"]"}]}`, "invalidPath", 400},
		"group filter value": {"Groups", g, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"remove","path":"members[value eq \"x\""}]}`, "invalidPath", 400},
		"group replace flt":  {"Groups", g, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"replace","path":"members[value eq \"x\"]","value":[]}]}`, "invalidPath", 400},
		"members not list":   {"Groups", g, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"add","path":"members","value":"x"}]}`, "invalidValue", 400},
		"nested group":       {"Groups", g, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"add","path":"members","value":[{"value":"` + g + `"}]}]}`, "invalidValue", 400},
		"remove displayName": {"Groups", g, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"remove","path":"displayName"}]}`, "mutability", 400},
		"dup group extid":    {"Groups", g, `{"schemas":["` + patchOp + `"],"Operations":[{"op":"replace","path":"externalId","value":"gid-1"}]}`, "", 200},
	} {
		t.Run(name, func(t *testing.T) {
			r := raw(c.kind, c.id, c.body)
			if r.code != c.code || c.scimType != "" && r.body["scimType"] != c.scimType {
				t.Fatalf("status %d scimType %v, want %d %s: %s", r.code, r.body["scimType"], c.code, c.scimType, r.raw)
			}
		})
	}
	// Paths the service does not hold are accepted and ignored: a
	// provisioning client sends them.
	e.want(e.patch("Users", u, `{"op":"replace","path":"emails[type eq \"work\"].value","value":"a@x.example"}`), 200, "")
	e.want(e.patch("Users", u, `{"op":"add","path":"name.givenName","value":"A"}`), 200, "")
	e.want(e.patch("Groups", g, `{"op":"replace","path":"description","value":"x"}`), 200, "")
	if v := e.value("oid-1", "/principal/account_state"); v != `"active"` {
		t.Errorf("state %s", v)
	}
}

func TestPatchGroupMembersByFilter(t *testing.T) {
	e := newEnv(t)
	a := e.createUser("a", "oid-1", "")
	b := e.createUser("b", "oid-2", "")
	g := e.createGroup("G", "gid-1", a, b)
	// A user that is not a member: success, no change (RFC 7644 section 3.5.2.2).
	e.want(e.patch("Groups", g, `{"op":"remove","path":"members[value eq \"nope\"]"}`), 200, "")
	e.want(e.patch("Groups", g, `{"op":"Remove","path":"MEMBERS[VALUE EQ \"`+a+`\"]"}`), 200, "")
	if e.value("oid-1", "/principal/group_ids") != `[]` || e.value("oid-2", "/principal/group_ids") != `["gid-1"]` {
		t.Error("filter remove removed the wrong member")
	}
	// Removing a member again is a success.
	e.want(e.patch("Groups", g, `{"op":"remove","path":"members[value eq \"`+a+`\"]"}`), 200, "")
	// Adding an existing member is a success.
	e.want(e.patch("Groups", g, `{"op":"add","path":"members","value":[{"value":"`+b+`"}]}`), 200, "")
	r := e.want(e.pc("GET", "/Groups/"+g, ""), 200, "")
	if m := r.body["members"].([]any); len(m) != 1 || m[0].(map[string]any)["value"] != b || m[0].(map[string]any)["type"] != "User" {
		t.Errorf("members %v", m)
	}
	// Pathless replace sets the group's attributes, members included.
	e.want(e.patch("Groups", g, `{"op":"replace","value":{"members":[{"value":"`+a+`"}],"displayName":"Renamed"}}`), 200, "")
	if e.value("oid-1", "/principal/group_ids") != `["gid-1"]` || e.value("oid-2", "/principal/group_ids") != `[]` {
		t.Error("pathless replace of members")
	}
	// Changing the group's externalId changes every member's fact.
	e.want(e.patch("Groups", g, `{"op":"replace","path":"externalId","value":"gid-9"}`), 200, "")
	if e.value("oid-1", "/principal/group_ids") != `["gid-9"]` {
		t.Error("group externalId change not published")
	}
	e.want(e.patch("Groups", g, `{"op":"remove","path":"externalId"}`), 200, "")
	if e.value("oid-1", "/principal/group_ids") != `[]` {
		t.Error("group externalId removal not published")
	}
}

func TestDeleteUserLeavesNoMembership(t *testing.T) {
	e := newEnv(t)
	a := e.createUser("a", "oid-1", "")
	g := e.createGroup("G", "gid-1", a)
	e.want(e.pc("DELETE", "/Users/"+a, ""), 204, "")
	// A new record with the same externalId does not inherit the old groups.
	a2 := e.createUser("a", "oid-1", "")
	if a2 == a {
		t.Fatal("an id was reused")
	}
	if e.value("oid-1", "/principal/group_ids") != `[]` {
		t.Error("a re-created user inherited a membership")
	}
	e.want(e.patch("Groups", g, `{"op":"add","path":"members","value":[{"value":"`+a+`"}]}`), 400, "invalidValue")
}

// ---- failing stores ----

type flaky struct {
	source.Store
	mu        sync.Mutex
	failPut   bool
	failDel   bool
	failedPut int
}

func (f *flaky) Put(ctx context.Context, p, path string, fa source.Fact) error {
	f.mu.Lock()
	fail := f.failPut
	if fail {
		f.failedPut++
	}
	f.mu.Unlock()
	if fail {
		return errors.New("store down")
	}
	return f.Store.Put(ctx, p, path, fa)
}

func (f *flaky) Delete(ctx context.Context, p string) error {
	f.mu.Lock()
	fail := f.failDel
	f.mu.Unlock()
	if fail {
		return errors.New("store down")
	}
	return f.Store.Delete(ctx, p)
}

func (f *flaky) set(put, del bool) { f.mu.Lock(); f.failPut, f.failDel = put, del; f.mu.Unlock() }

func (f *flaky) Get(ctx context.Context, p, path string) (source.Fact, bool, error) {
	f.mu.Lock()
	fail := f.failPut && f.failDel
	f.mu.Unlock()
	if fail {
		return source.Fact{}, false, errors.New("store down")
	}
	return f.Store.Get(ctx, p, path)
}

func TestStoreFailures(t *testing.T) {
	st := &flaky{Store: source.NewMemory()}
	e := newEnv(t, func(c *scim.Config) { c.Store = st })
	u := e.createUser("a", "oid-1", "")

	// A create whose facts cannot be written is rolled back.
	st.set(true, false)
	e.want(e.pc("POST", "/Users", `{"schemas":["`+userURN+`"],"userName":"b","externalId":"oid-2","active":true}`), 500, "")
	st.set(false, false)
	if r := e.pc("GET", "/Users?filter=externalId%20eq%20%22oid-2%22", ""); r.body["totalResults"] != float64(0) {
		t.Errorf("a create that failed left a record: %s", r.raw)
	}
	e.createUser("b", "oid-2", "") // and can be retried

	// A deactivation that cannot be written is an error, and a retry applies it.
	st.set(true, false)
	e.want(e.patch("Users", u, `{"op":"replace","path":"active","value":false}`), 500, "")
	st.set(false, false)
	e.want(e.patch("Users", u, `{"op":"replace","path":"active","value":false}`), 200, "")
	if e.value("oid-1", "/principal/account_state") != `"disabled"` {
		t.Error("retry did not publish")
	}

	// A delete whose facts cannot be removed keeps the record, so a retry works.
	st.set(false, true)
	e.want(e.pc("DELETE", "/Users/"+u, ""), 500, "")
	e.want(e.pc("GET", "/Users/"+u, ""), 200, "")
	st.set(false, false)
	e.want(e.pc("DELETE", "/Users/"+u, ""), 204, "")
	e.absent("oid-1", "/principal/account_state")

	// A store that cannot answer defers the read.
	st.set(true, true)
	if _, err := e.read("oid-2", "/principal/account_state"); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("read = %v, want ErrDependencyUnavailable", err)
	}
}

// ---- concurrency ----

func TestConcurrentUse(t *testing.T) {
	e := newEnv(t)
	const n = 20
	ids := make([]string, n)
	for i := range ids {
		ids[i] = e.createUser(fmt.Sprintf("u%d", i), fmt.Sprintf("oid-%d", i), "")
	}
	g := e.createGroup("G", "gid-1")
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(3)
		go func() {
			defer wg.Done()
			e.do("PATCH", base+"/Groups/"+g, "Bearer "+token, fmt.Sprintf(`{"schemas":[%q],"Operations":[{"op":"add","path":"members","value":[{"value":%q}]}]}`, patchOp, ids[i]))
		}()
		go func() {
			defer wg.Done()
			e.do("PATCH", base+"/Users/"+ids[i], "Bearer "+token, fmt.Sprintf(`{"schemas":[%q],"Operations":[{"op":"replace","path":"active","value":false}]}`, patchOp))
		}()
		go func() {
			defer wg.Done()
			_, _ = e.read(fmt.Sprintf("oid-%d", i), "/principal/group_ids")
			e.do("GET", base+"/Users", "Bearer "+token, "")
		}()
	}
	wg.Wait()
	for i := range ids {
		if v := e.value(fmt.Sprintf("oid-%d", i), "/principal/group_ids"); v != `["gid-1"]` {
			t.Errorf("user %d groups %s", i, v)
		}
		if v := e.value(fmt.Sprintf("oid-%d", i), "/principal/account_state"); v != `"disabled"` {
			t.Errorf("user %d state %s", i, v)
		}
	}
}
