package googledir_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter/source/googledir"
	"hop.top/pact-go/core/clock"
)

func jsonReply(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func TestNewClientRejects(t *testing.T) {
	clk := clock.NewFake(at(1))
	good := googledir.ClientConfig{DirectoryURL: "https://admin.example/directory", IdentityURL: "https://id.example/v1",
		ChannelsStopURL: "https://admin.example/stop", DirectoryTokens: staticTokens("a"), IdentityTokens: staticTokens("b"), Clock: clk}
	if _, err := googledir.NewClient(good); err != nil {
		t.Fatal(err)
	}
	mut := func(name string, f func(c *googledir.ClientConfig)) {
		t.Run(name, func(t *testing.T) {
			c := good
			f(&c)
			if _, err := googledir.NewClient(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	mut("http directory", func(c *googledir.ClientConfig) { c.DirectoryURL = "http://admin.example/d" })
	mut("http identity", func(c *googledir.ClientConfig) { c.IdentityURL = "http://id.example/v1" })
	mut("http stop", func(c *googledir.ClientConfig) { c.ChannelsStopURL = "http://admin.example/stop" })
	mut("no directory tokens", func(c *googledir.ClientConfig) { c.DirectoryTokens = nil })
	mut("no clock", func(c *googledir.ClientConfig) { c.Clock = nil })
	// Defaults are the vendor's own endpoints.
	d := googledir.ClientConfig{DirectoryTokens: staticTokens("a"), IdentityTokens: staticTokens("b"), Clock: clk}
	if _, err := googledir.NewClient(d); err != nil {
		t.Fatalf("defaults: %v", err)
	}
}

func TestUserRequestAndParse(t *testing.T) {
	var got *http.Request
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		got = r
		jsonReply(w, 200, `{"kind":"admin#directory#user","id":"42","primaryEmail":"a@b.example","suspended":true,"archived":false,"orgUnitPath":"/","name":{"fullName":"A B"}}`)
	})
	u, err := s.client(t, clock.NewFake(at(1))).User(t.Context(), "42")
	if err != nil {
		t.Fatal(err)
	}
	if u != (googledir.User{ID: "42", PrimaryEmail: "a@b.example", Suspended: true}) {
		t.Fatalf("user %+v", u)
	}
	if got.Method != "GET" || got.URL.Path != "/directory/users/42" || got.Header.Get("Authorization") != "Bearer dir-tok" {
		t.Errorf("request %s %s auth %q", got.Method, got.URL.Path, got.Header.Get("Authorization"))
	}
}

func TestUserKeyIsEscaped(t *testing.T) {
	var raw string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { raw = r.URL.EscapedPath(); jsonReply(w, 404, `{}`) })
	_, _ = s.client(t, clock.NewFake(at(1))).User(t.Context(), "a/../b?x=1")
	if raw != "/directory/users/a%2F..%2Fb%3Fx=1" {
		t.Fatalf("path %q", raw)
	}
}

func TestUserErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		notf   bool
		api    int
	}{
		{"not found", 404, `{"error":{"code":404}}`, true, 0},
		{"forbidden", 403, `{"error":{"code":403,"message":"Not Authorized"}}`, false, 403},
		{"rate", 429, `{}`, false, 429},
		{"server", 503, `oops`, false, 503},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, c.status, c.body) })
			_, err := s.client(t, clock.NewFake(at(1))).User(t.Context(), "42")
			if c.notf != errors.Is(err, googledir.ErrNotFound) {
				t.Fatalf("not-found = %v: %v", !c.notf, err)
			}
			var ae *googledir.APIError
			if c.api != 0 && (!errors.As(err, &ae) || ae.Status != c.api) {
				t.Fatalf("want APIError %d: %v", c.api, err)
			}
			if err == nil {
				t.Fatal("no error")
			}
		})
	}
}

// A response the source cannot rely on is an error, never a default: a
// missing or mistyped flag would otherwise read as an active account.
func TestUserUnusableResponses(t *testing.T) {
	for name, body := range map[string]string{
		"no id":            `{"suspended":false,"archived":false}`,
		"empty id":         `{"id":"","suspended":false,"archived":false}`,
		"no suspended":     `{"id":"1","archived":false}`,
		"no archived":      `{"id":"1","suspended":false}`,
		"string flag":      `{"id":"1","suspended":"false","archived":false}`,
		"null flag":        `{"id":"1","suspended":null,"archived":false}`,
		"numeric id":       `{"id":1,"suspended":false,"archived":false}`,
		"duplicate member": `{"id":"1","suspended":false,"suspended":true,"archived":false}`,
		"not an object":    `[]`,
		"empty":            ``,
	} {
		t.Run(name, func(t *testing.T) {
			s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, body) })
			if u, err := s.client(t, clock.NewFake(at(1))).User(t.Context(), "1"); err == nil {
				t.Fatalf("accepted %+v", u)
			}
		})
	}
}

func TestResponseSizeBound(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, 200, `{"id":"1","suspended":false,"archived":false,"pad":"`+strings.Repeat("x", 2<<20)+`"}`)
	})
	if _, err := s.client(t, clock.NewFake(at(1))).User(t.Context(), "1"); err == nil {
		t.Fatal("a 2 MiB response was read")
	}
}

func TestUsersPaging(t *testing.T) {
	clk := clock.NewFake(at(100))
	var queries []string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		clk.Set(clk.Now().Add(5 * time.Second))
		switch r.URL.Query().Get("pageToken") {
		case "":
			jsonReply(w, 200, `{"users":[{"id":"1","primaryEmail":"a@x","suspended":false,"archived":false}],"nextPageToken":"t2"}`)
		case "t2":
			jsonReply(w, 200, `{"users":[{"id":"2","primaryEmail":"b@x","suspended":true,"archived":false}]}`)
		}
	})
	var ids []string
	var when []int64
	err := s.client(t, clk).Users(t.Context(), "my_customer", 1, func(p []googledir.User, requested time.Time) error {
		for _, u := range p {
			ids = append(ids, u.ID)
		}
		when = append(when, requested.Unix())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "1,2" || len(when) != 2 || when[0] != 100 || when[1] != 105 {
		t.Fatalf("ids %v times %v", ids, when)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], "customer=my_customer") || !strings.Contains(queries[0], "maxResults=1") ||
		strings.Contains(queries[0], "showDeleted") || !strings.Contains(queries[1], "pageToken=t2") {
		t.Fatalf("queries %q", queries)
	}
}

func TestUsersPagingFailures(t *testing.T) {
	loop := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, 200, `{"users":[],"nextPageToken":"same"}`)
	})
	err := loop.client(t, clock.NewFake(at(1))).Users(t.Context(), "c", 10, func([]googledir.User, time.Time) error { return nil })
	if err == nil {
		t.Fatal("a repeated page token looped forever")
	}
	stopped := errors.New("stop")
	one := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, 200, `{"users":[],"nextPageToken":"n"}`)
	})
	err = one.client(t, clock.NewFake(at(1))).Users(t.Context(), "c", 10, func([]googledir.User, time.Time) error { return stopped })
	if !errors.Is(err, stopped) || one.count() != 1 {
		t.Fatalf("callback error: %v after %d requests", err, one.count())
	}
}

func TestMembershipCalls(t *testing.T) {
	var paths, queries []string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		queries = append(queries, r.URL.Query().Get("query"))
		if strings.Contains(r.URL.Path, "hasMember") {
			jsonReply(w, 200, `{"isMember":true}`)
			return
		}
		jsonReply(w, 200, `{"hasMembership":false}`)
	})
	c := s.client(t, clock.NewFake(at(1)))
	if ok, err := c.HasMember(t.Context(), "g/1", "42"); err != nil || !ok {
		t.Fatalf("hasMember %v %v", ok, err)
	}
	if ok, err := c.TransitiveMember(t.Context(), "g1", "a@b.example"); err != nil || ok {
		t.Fatalf("transitive %v %v", ok, err)
	}
	if paths[0] != "/directory/groups/g%2F1/hasMember/42" || paths[1] != "/identity/groups/g1/memberships:checkTransitiveMembership" ||
		queries[1] != "member_key_id == 'a@b.example'" {
		t.Fatalf("paths %q queries %q", paths, queries)
	}
}

func TestMembershipUnusable(t *testing.T) {
	for _, body := range []string{`{}`, `{"isMember":"yes"}`, `{"isMember":null}`, `{"isMember":true,"isMember":false}`} {
		s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, body) })
		c := s.client(t, clock.NewFake(at(1)))
		if _, err := c.HasMember(t.Context(), "g", "1"); err == nil {
			t.Errorf("hasMember accepted %s", body)
		}
		if _, err := c.TransitiveMember(t.Context(), "g", "a@b"); err == nil {
			t.Errorf("transitive accepted %s", body)
		}
	}
}

// The member key is placed in a CEL string literal: a key that could end the
// literal is refused before any request.
func TestTransitiveRefusesQueryInjection(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, `{"hasMembership":true}`) })
	c := s.client(t, clock.NewFake(at(1)))
	for _, k := range []string{"a'b@x", `a\b@x`, "a\nb@x", "", "a@b' || true || '"} {
		if _, err := c.TransitiveMember(t.Context(), "g", k); err == nil {
			t.Errorf("accepted %q", k)
		}
	}
	if s.count() != 0 {
		t.Fatalf("%d requests were made", s.count())
	}
}

func TestWatchAndStop(t *testing.T) {
	var body map[string]any
	var stopBody map[string]any
	var q string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/directory/users/watch":
			q = r.URL.RawQuery
			_ = json.NewDecoder(r.Body).Decode(&body)
			jsonReply(w, 200, `{"kind":"api#channel","id":"c1","resourceId":"r1","token":"tok-tok-tok-tok-1","expiration":"1792083600000"}`)
		case "/channels/stop":
			_ = json.NewDecoder(r.Body).Decode(&stopBody)
			w.WriteHeader(204)
		}
	})
	c := s.client(t, clock.NewFake(at(1)))
	ch, err := c.WatchUsers(t.Context(), "my_customer", "update", googledir.Channel{ID: "c1", Address: "https://x.example/n", Token: "tok-tok-tok-tok-1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ch.ID != "c1" || ch.ResourceID != "r1" || ch.Expiration.UnixMilli() != 1792083600000 {
		t.Fatalf("channel %+v", ch)
	}
	params, _ := body["params"].(map[string]any)
	if body["id"] != "c1" || body["type"] != "web_hook" || body["address"] != "https://x.example/n" || body["token"] != "tok-tok-tok-tok-1" || params["ttl"] != "3600" || !strings.Contains(q, "customer=my_customer") || !strings.Contains(q, "event=update") {
		t.Fatalf("body %v query %s", body, q)
	}
	if err := c.StopChannel(t.Context(), ch); err != nil {
		t.Fatal(err)
	}
	if stopBody["id"] != "c1" || stopBody["resourceId"] != "r1" {
		t.Fatalf("stop %v", stopBody)
	}
}

func TestWatchRefusals(t *testing.T) {
	reply := `{"id":"c1","resourceId":"r1","expiration":"1792083600000"}`
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, reply) })
	c := s.client(t, clock.NewFake(at(1)))
	ok := googledir.Channel{ID: "c1", Address: "https://x.example/n", Token: "tok-tok-tok-tok-1"}
	for name, ch := range map[string]googledir.Channel{
		"http address":   {ID: "c1", Address: "http://x.example/n", Token: ok.Token},
		"no id":          {Address: ok.Address, Token: ok.Token},
		"id over 64":     {ID: strings.Repeat("a", 65), Address: ok.Address, Token: ok.Token},
		"token over 256": {ID: "c1", Address: ok.Address, Token: strings.Repeat("t", 257)},
	} {
		if _, err := c.WatchUsers(t.Context(), "c", "update", ch, 0); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if s.count() != 0 {
		t.Fatalf("%d requests were made", s.count())
	}
	for _, r := range []string{
		`{"id":"other","resourceId":"r1","expiration":"1792083600000"}`,
		`{"id":"c1","expiration":"1792083600000"}`,
		`{"id":"c1","resourceId":"r1"}`,
		`{"id":"c1","resourceId":"r1","expiration":"soon"}`,
		`{"id":"c1","resourceId":"r1","expiration":"-5"}`,
	} {
		reply = r
		if _, err := c.WatchUsers(t.Context(), "c", "update", ok, 0); err == nil {
			t.Errorf("accepted reply %s", r)
		}
	}
}

// A redirect is not followed: the bearer token goes to the configured
// endpoint only.
func TestRedirectIsNotFollowed(t *testing.T) {
	var leaked string
	other := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
		jsonReply(w, 200, `{}`)
	})
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.srv.URL+"/x", http.StatusFound)
	})
	if _, err := s.client(t, clock.NewFake(at(1))).User(t.Context(), "1"); err == nil {
		t.Fatal("a redirect was taken as an answer")
	}
	if other.count() != 0 || leaked != "" {
		t.Fatalf("the redirect target was reached (%d requests, auth %q)", other.count(), leaked)
	}
}
