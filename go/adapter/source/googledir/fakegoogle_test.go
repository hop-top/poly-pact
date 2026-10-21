package googledir_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core/clock"
)

// This file is a stand-in for the Google endpoints the source calls: the
// token endpoint, the Admin SDK Directory API (users.get, users.list,
// members.hasMember, users.watch, channels.stop) and the Cloud Identity
// Groups API (checkTransitiveMembership). It models what the vendor pages
// state (spec/v1.0/profiles/sources/googledir.md, section 2) and nothing else:
// a user key is a primary address, an alias or the unique ID; hasMember
// counts direct and nested membership; a channel lives for the shorter of
// the requested and the vendor's own lifetime.

type fakeUser struct {
	ID        string   `json:"id"`
	Email     string   `json:"primary_email"`
	Aliases   []string `json:"aliases"`
	Suspended bool     `json:"suspended"`
	Archived  bool     `json:"archived"`
	Deleted   bool     `json:"-"`
	Hidden    bool     `json:"-"` // omitted from users.list only
}

type fakeGroup struct {
	ID       string   `json:"id"`
	Members  []string `json:"members"`
	Children []string `json:"groups"`
}

type fakeChannel struct {
	ID, ResourceID, Token, Address string
	Expiration                     time.Time
	Stopped                        bool
}

type fakeGoogle struct {
	mu         sync.Mutex
	clk        clock.Clock
	hooks      *adaptertest.Hooks
	users      []*fakeUser
	groups     []*fakeGroup
	pageSize   int
	channelMax time.Duration
	fail       map[string]int
	channels   []*fakeChannel
	tokens     map[string]string // access token -> "directory" | "identity"
	issued     int
	assertions []string
	onList     func(pageToken string) int
	requests   []string
	srv        *httptest.Server
}

const (
	fakeClientEmail = "pact-reader@northstar-proj.iam.gserviceaccount.com"
	fakeSubject     = "directory-reader@northstar.example"
	dirScope        = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.member.readonly"
	ciScope         = "https://www.googleapis.com/auth/cloud-identity.groups.readonly"
)

var (
	keyOnce sync.Once
	keyPEM  []byte
	keyRSA  *rsa.PrivateKey
)

// testKey returns a service account key file with a throwaway RSA key.
func testKey(t testing.TB) []byte {
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		keyRSA = k
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	})
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": fakeClientEmail,
		"private_key": string(keyPEM), "private_key_id": "k1",
	})
	return b
}

func newFakeGoogle(t testing.TB, clk clock.Clock, hooks *adaptertest.Hooks) *fakeGoogle {
	f := &fakeGoogle{clk: clk, hooks: hooks, pageSize: 100, channelMax: 24 * time.Hour,
		fail: map[string]int{}, tokens: map[string]string{}}
	f.srv = httptest.NewUnstartedServer(f)
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGoogle) key(k string) *fakeUser {
	for _, u := range f.users {
		if u.Deleted {
			continue
		}
		if u.ID == k || u.Email == k || slices.Contains(u.Aliases, k) {
			return u
		}
	}
	return nil
}

func (f *fakeGoogle) group(id string) *fakeGroup {
	for _, g := range f.groups {
		if g.ID == id {
			return g
		}
	}
	return nil
}

// member reports direct or nested membership of the user in the group.
func (f *fakeGoogle) member(g *fakeGroup, uid string, seen map[string]bool) bool {
	if seen[g.ID] {
		return false
	}
	seen[g.ID] = true
	if slices.Contains(g.Members, uid) {
		return true
	}
	for _, c := range g.Children {
		if cg := f.group(c); cg != nil && f.member(cg, uid, seen) {
			return true
		}
	}
	return false
}

func (f *fakeGoogle) errJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "message": msg}})
}

func (f *fakeGoogle) ok(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (u *fakeUser) wire() map[string]any {
	return map[string]any{"kind": "admin#directory#user", "id": u.ID, "primaryEmail": u.Email,
		"suspended": u.Suspended, "archived": u.Archived}
}

// auth checks the bearer token against the API the path belongs to.
func (f *fakeGoogle) auth(r *http.Request, api string) bool {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	return ok && f.tokens[tok] == api
}

func (f *fakeGoogle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	p := r.URL.Path
	switch {
	case p == "/token":
		f.token(w, r)
	case strings.HasPrefix(p, "/directory/"):
		f.directory(w, r, strings.TrimPrefix(r.URL.EscapedPath(), "/directory/"))
	case strings.HasPrefix(p, "/identity/"):
		f.identity(w, r, strings.TrimPrefix(p, "/identity/"))
	case p == "/channels/stop":
		f.stop(w, r)
	default:
		f.errJSON(w, 404, "not found")
	}
}

func (f *fakeGoogle) token(w http.ResponseWriter, r *http.Request) {
	if f.fail["token"] != 0 {
		f.errJSON(w, f.fail["token"], "token endpoint failure")
		return
	}
	_ = r.ParseForm()
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		f.errJSON(w, 400, "bad grant_type")
		return
	}
	a := r.Form.Get("assertion")
	f.assertions = append(f.assertions, a)
	parts := strings.Split(a, ".")
	if len(parts) != 3 {
		f.errJSON(w, 400, "bad assertion")
		return
	}
	var claims struct {
		Scope string `json:"scope"`
	}
	raw, _ := b64(parts[1])
	_ = json.Unmarshal(raw, &claims)
	api := ""
	switch claims.Scope {
	case dirScope:
		api = "directory"
	case ciScope:
		api = "identity"
	default:
		f.errJSON(w, 400, "scope not authorized for delegation")
		return
	}
	f.issued++
	tok := fmt.Sprintf("%s-token-%d", api, f.issued)
	f.tokens[tok] = api
	f.ok(w, map[string]any{"access_token": tok, "expires_in": 3600, "token_type": "Bearer", "scope": claims.Scope})
}

func (f *fakeGoogle) directory(w http.ResponseWriter, r *http.Request, rest string) {
	if !f.auth(r, "directory") {
		f.errJSON(w, 401, "invalid credentials")
		return
	}
	if st := f.fail["directory"]; st != 0 {
		f.errJSON(w, st, "directory failure")
		return
	}
	segs := strings.Split(rest, "/")
	unesc := func(s string) string { v, _ := url.PathUnescape(s); return v }
	switch {
	case r.Method == http.MethodGet && len(segs) == 2 && segs[0] == "users":
		key := unesc(segs[1])
		if strings.Contains(key, "@") {
			f.hooks.Fire("email-key")
		}
		if u := f.key(key); u != nil {
			f.ok(w, u.wire())
			return
		}
		f.errJSON(w, 404, "Resource Not Found: userKey")
	case r.Method == http.MethodGet && rest == "users":
		f.listUsers(w, r)
	case r.Method == http.MethodGet && len(segs) == 4 && segs[0] == "groups" && segs[2] == "hasMember":
		g, key := f.group(unesc(segs[1])), unesc(segs[3])
		if strings.Contains(key, "@") {
			f.hooks.Fire("email-key")
		}
		if g == nil {
			f.errJSON(w, 404, "Resource Not Found: groupKey")
			return
		}
		u := f.key(key)
		if u == nil {
			f.errJSON(w, 404, "Resource Not Found: memberKey")
			return
		}
		f.ok(w, map[string]any{"isMember": f.member(g, u.ID, map[string]bool{})})
	case r.Method == http.MethodPost && rest == "users/watch":
		f.watch(w, r)
	default:
		f.errJSON(w, 404, "not found")
	}
}

func (f *fakeGoogle) listUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if f.onList != nil {
		if st := f.onList(q.Get("pageToken")); st != 0 {
			f.errJSON(w, st, "list failure")
			return
		}
	}
	if q.Get("customer") == "" {
		f.errJSON(w, 400, "Missing required parameter: customer or domain")
		return
	}
	var live []*fakeUser
	for _, u := range f.users {
		if !u.Deleted && !u.Hidden {
			live = append(live, u)
		}
	}
	size := f.pageSize
	if m, err := strconv.Atoi(q.Get("maxResults")); err == nil && m > 0 && m < size {
		size = m
	}
	start := 0
	if t := q.Get("pageToken"); t != "" {
		n, err := strconv.Atoi(strings.TrimPrefix(t, "page-"))
		if err != nil || !strings.HasPrefix(t, "page-") {
			f.errJSON(w, 400, "Invalid Input: pageToken")
			return
		}
		start = n
	}
	end := min(start+size, len(live))
	out := []any{}
	for _, u := range live[start:end] {
		out = append(out, u.wire())
	}
	resp := map[string]any{"kind": "admin#directory#users", "users": out}
	if end < len(live) {
		resp["nextPageToken"] = fmt.Sprintf("page-%d", end)
	}
	f.ok(w, resp)
}

func (f *fakeGoogle) watch(w http.ResponseWriter, r *http.Request) {
	if st := f.fail["watch"]; st != 0 {
		f.errJSON(w, st, "watch failure")
		return
	}
	var body struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Address string `json:"address"`
		Token   string `json:"token"`
		Params  struct {
			TTL string `json:"ttl"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" || body.Type != "web_hook" || !strings.HasPrefix(body.Address, "https://") {
		f.errJSON(w, 400, "bad channel")
		return
	}
	life := f.channelMax
	if body.Params.TTL != "" {
		if s, err := strconv.Atoi(body.Params.TTL); err == nil && time.Duration(s)*time.Second < life {
			life = time.Duration(s) * time.Second
		}
	}
	ch := &fakeChannel{ID: body.ID, ResourceID: fmt.Sprintf("res-%d", len(f.channels)+1),
		Token: body.Token, Address: body.Address, Expiration: f.clk.Now().Add(life)}
	f.channels = append(f.channels, ch)
	f.ok(w, map[string]any{"kind": "api#channel", "id": ch.ID, "resourceId": ch.ResourceID,
		"resourceUri": "https://admin.googleapis.com/admin/directory/v1/users?alt=json",
		"token":       ch.Token, "expiration": strconv.FormatInt(ch.Expiration.UnixMilli(), 10)})
}

func (f *fakeGoogle) stop(w http.ResponseWriter, r *http.Request) {
	if st := f.fail["stop"]; st != 0 {
		f.errJSON(w, st, "stop failure")
		return
	}
	var body struct {
		ID         string `json:"id"`
		ResourceID string `json:"resourceId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.errJSON(w, 400, "bad body")
		return
	}
	for _, c := range f.channels {
		if c.ID == body.ID && c.ResourceID == body.ResourceID {
			c.Stopped = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	f.errJSON(w, 404, "channel not found")
}

func (f *fakeGoogle) identity(w http.ResponseWriter, r *http.Request, rest string) {
	if !f.auth(r, "identity") {
		f.errJSON(w, 401, "invalid credentials")
		return
	}
	if st := f.fail["identity"]; st != 0 {
		f.errJSON(w, st, "identity failure")
		return
	}
	// groups/{group}/memberships:checkTransitiveMembership
	segs := strings.Split(rest, "/")
	if r.Method != http.MethodGet || len(segs) != 3 || segs[0] != "groups" || segs[2] != "memberships:checkTransitiveMembership" {
		f.errJSON(w, 404, "not found")
		return
	}
	g := f.group(segs[1])
	if g == nil {
		f.errJSON(w, 404, "group not found")
		return
	}
	q := r.URL.Query().Get("query")
	email, ok := strings.CutPrefix(q, "member_key_id == '")
	email, ok2 := strings.CutSuffix(email, "'")
	if !ok || !ok2 {
		f.errJSON(w, 400, "invalid query")
		return
	}
	u := f.key(email)
	if u == nil || u.ID == email {
		f.errJSON(w, 404, "member not found")
		return
	}
	f.ok(w, map[string]any{"hasMembership": f.member(g, u.ID, map[string]bool{})})
}
