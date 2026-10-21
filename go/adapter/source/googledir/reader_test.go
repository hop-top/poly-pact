package googledir_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/googledir"
	"hop.top/pact-go/core/clock"
)

const pre = "oauth:https%3A%2F%2Faccounts.google.com:northstar.example:"

func readerFor(t *testing.T, s *stub, clk clock.Clock, mut func(c *googledir.Config)) *googledir.Reader {
	t.Helper()
	cfg := googledir.Config{SourceID: "gd", PrincipalPrefix: pre, Client: s.client(t, clk), Clock: clk,
		Groups: []string{"g1"}, TransitiveGroups: []string{"g2"}}
	if mut != nil {
		mut(&cfg)
	}
	r, err := googledir.NewReader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func read(r *googledir.Reader, path, who string) (adapter.NativeClaim, error) {
	return r.ReadNativeClaim(bg(), path, adapter.ClaimContext{Principal: adapter.Principal{ID: who}})
}

func wantCode(t *testing.T, err error, sentinel error) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("error %v does not wrap %v", err, sentinel)
	}
}

func TestNewReaderRejects(t *testing.T) {
	s := newStub(t, func(http.ResponseWriter, *http.Request) {})
	clk := clock.NewFake(at(1))
	good := googledir.Config{SourceID: "gd", PrincipalPrefix: pre, Client: s.client(t, clk), Clock: clk, Groups: []string{"g1"}}
	if _, err := googledir.NewReader(good); err != nil {
		t.Fatal(err)
	}
	mut := func(name string, f func(c *googledir.Config)) {
		t.Run(name, func(t *testing.T) {
			c := good
			f(&c)
			if _, err := googledir.NewReader(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	mut("no source id", func(c *googledir.Config) { c.SourceID = "" })
	mut("no client", func(c *googledir.Config) { c.Client = nil })
	mut("no clock", func(c *googledir.Config) { c.Clock = nil })
	mut("prefix without colon", func(c *googledir.Config) { c.PrincipalPrefix = "oauth:a:b" })
	mut("prefix not an identifier", func(c *googledir.Config) { c.PrincipalPrefix = "google:a:" })
	mut("group with a slash", func(c *googledir.Config) { c.Groups = []string{"a/b"} })
	mut("empty group", func(c *googledir.Config) { c.Groups = []string{""} })
	mut("group twice", func(c *googledir.Config) { c.Groups = []string{"g", "g"} })
	mut("transitive group with a quote", func(c *googledir.Config) { c.TransitiveGroups = []string{"a'b"} })
	mut("cache without max age", func(c *googledir.Config) { c.Cache = source.NewMemory() })
	mut("max age without cache", func(c *googledir.Config) { c.MaxAge = time.Minute })
}

func TestAccountStateLive(t *testing.T) {
	clk := clock.NewFake(at(1792080000))
	body := `{"id":"42","primaryEmail":"a@x.example","suspended":false,"archived":false}`
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		clk.Set(clk.Now().Add(3 * time.Second)) // the request takes time
		jsonReply(w, 200, body)
	})
	r := readerFor(t, s, clk, nil)
	c, err := read(r, googledir.PathAccountState, pre+"42")
	if err != nil {
		t.Fatal(err)
	}
	// The time of the state is no later than the start of the request.
	if c.Value != "active" || c.ObservedAt.Unix() != 1792080000 || c.StatusCheckedAt.Unix() != 1792080000 || c.SourceID != "gd" || c.SourceRef != "42" {
		t.Fatalf("claim %+v", c)
	}
}

func TestAccountStateValues(t *testing.T) {
	clk := clock.NewFake(at(1792080000))
	var body string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, body) })
	r := readerFor(t, s, clk, nil)
	for b, want := range map[string]string{
		`{"id":"42","primaryEmail":"a@x","suspended":true,"archived":false}`:  "disabled",
		`{"id":"42","primaryEmail":"a@x","suspended":false,"archived":true}`:  "disabled",
		`{"id":"42","primaryEmail":"a@x","suspended":true,"archived":true}`:   "disabled",
		`{"id":"42","primaryEmail":"a@x","suspended":false,"archived":false}`: "active",
	} {
		body = b
		c, err := read(r, googledir.PathAccountState, pre+"42")
		if err != nil || c.Value != want {
			t.Errorf("%s: %v %v, want %s", b, c.Value, err, want)
		}
	}
}

// A user key the API resolves through another attribute names another user:
// the reply is refused when its id is not the key.
func TestReplyForAnotherIDIsNoFact(t *testing.T) {
	clk := clock.NewFake(at(1))
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, 200, `{"id":"99","primaryEmail":"a@x","suspended":false,"archived":false}`)
	})
	r := readerFor(t, s, clk, nil)
	_, err := read(r, googledir.PathAccountState, pre+"42")
	wantCode(t, err, adapter.ErrMissingField)
	_, err = read(r, googledir.MemberPath("g1"), pre+"42")
	wantCode(t, err, adapter.ErrMissingField)
}

func TestNoRequestForAnAddressOrAnotherRealm(t *testing.T) {
	clk := clock.NewFake(at(1))
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, `{}`) })
	r := readerFor(t, s, clk, nil)
	for _, who := range []string{pre + "a%40x.example", pre + "A%40X.EXAMPLE", "oauth:https%3A%2F%2Faccounts.google.com:other.example:42", pre, "", "basic:x:42", pre + "4 2", pre + "42%2f"} {
		for _, p := range []string{googledir.PathAccountState, googledir.MemberPath("g1"), googledir.TransitiveMemberPath("g2")} {
			_, err := read(r, p, who)
			wantCode(t, err, adapter.ErrMissingField)
		}
	}
	if s.count() != 0 {
		t.Fatalf("%d requests were made", s.count())
	}
}

func TestOneSpellingOfTheLocalPart(t *testing.T) {
	clk := clock.NewFake(at(1))
	var path string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		jsonReply(w, 200, `{"id":"a-b","suspended":false,"archived":false}`)
	})
	r := readerFor(t, s, clk, nil)
	if _, err := read(r, googledir.PathAccountState, pre+"a-b"); err != nil {
		t.Fatal(err)
	}
	if path != "/directory/users/a-b" {
		t.Fatalf("path %q", path)
	}
	// IM-2: an unreserved octet is never written as %XX.
	_, err := read(r, googledir.PathAccountState, pre+"a%2Db")
	wantCode(t, err, adapter.ErrMissingField)
	// Lower-case hexadecimal is not the one spelling either.
	_, err = read(r, googledir.PathAccountState, pre+"a%2db")
	wantCode(t, err, adapter.ErrMissingField)
}

func TestMembershipReads(t *testing.T) {
	clk := clock.NewFake(at(1792080000))
	var seen []string
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		switch {
		case strings.HasPrefix(r.URL.Path, "/directory/users/"):
			jsonReply(w, 200, `{"id":"42","primaryEmail":"a@x.example","suspended":true,"archived":false}`)
		case strings.HasPrefix(r.URL.Path, "/directory/groups/g1/hasMember/"):
			jsonReply(w, 200, `{"isMember":true}`)
		case strings.HasPrefix(r.URL.Path, "/identity/groups/g2/"):
			if r.URL.Query().Get("query") != "member_key_id == 'a@x.example'" {
				w.WriteHeader(400)
				return
			}
			jsonReply(w, 200, `{"hasMembership":true}`)
		default:
			w.WriteHeader(500)
		}
	})
	r := readerFor(t, s, clk, nil)
	for _, p := range []string{googledir.MemberPath("g1"), googledir.TransitiveMemberPath("g2")} {
		c, err := read(r, p, pre+"42")
		if err != nil || c.Value != true || c.ObservedAt.Unix() != 1792080000 || c.StatusCheckedAt != c.ObservedAt {
			t.Fatalf("%s: %+v %v", p, c, err)
		}
	}
	// Membership is read by the verified id, never by the address: hasMember
	// is called with the user id and the user lookup comes first.
	want := []string{"/directory/users/42", "/directory/groups/g1/hasMember/42", "/directory/users/42", "/identity/groups/g2/memberships:checkTransitiveMembership"}
	if strings.Join(seen, " ") != strings.Join(want, " ") {
		t.Fatalf("requests %q", seen)
	}
}

func TestTransitiveNeedsAUsableAddress(t *testing.T) {
	for _, email := range []string{``, `"a'b@x"`, `"a\\nb@x"`} {
		clk := clock.NewFake(at(1))
		body := `{"id":"42","suspended":false,"archived":false,"primaryEmail":` + email + `}`
		if email == `` {
			body = `{"id":"42","suspended":false,"archived":false}`
		}
		s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, body) })
		_, err := read(readerFor(t, s, clk, nil), googledir.TransitiveMemberPath("g2"), pre+"42")
		wantCode(t, err, adapter.ErrDependencyUnavailable)
		if s.count() != 1 {
			t.Errorf("%s: %d requests", email, s.count())
		}
	}
}

func TestErrorMapping(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		want   error
	}{
		"not found":   {404, adapter.ErrMissingField},
		"forbidden":   {403, adapter.ErrDependencyUnavailable},
		"unauth":      {401, adapter.ErrDependencyUnavailable},
		"rate":        {429, adapter.ErrDependencyUnavailable},
		"server":      {500, adapter.ErrDependencyUnavailable},
		"unavailable": {503, adapter.ErrDependencyUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, c.status, `{}`) })
			_, err := read(readerFor(t, s, clock.NewFake(at(1)), nil), googledir.PathAccountState, pre+"42")
			wantCode(t, err, c.want)
		})
	}
	// A group the directory does not know cannot be answered, whichever
	// user is asked about.
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/directory/users/") {
			jsonReply(w, 200, `{"id":"42","primaryEmail":"a@x","suspended":false,"archived":false}`)
			return
		}
		jsonReply(w, 404, `{}`)
	})
	r := readerFor(t, s, clock.NewFake(at(1)), nil)
	for _, p := range []string{googledir.MemberPath("g1"), googledir.TransitiveMemberPath("g2")} {
		_, err := read(r, p, pre+"42")
		wantCode(t, err, adapter.ErrDependencyUnavailable)
	}
}

func TestUnservedPaths(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, `{}`) })
	r := readerFor(t, s, clock.NewFake(at(1)), nil)
	for _, p := range []string{"/principal/groups/other/member", "/principal/groups/g2/member", "/principal/groups/g1/transitive_member",
		"/principal/group_ids", "/principal/groups/g1/member/", "/principal/groups//member", "principal/account_state", ""} {
		_, err := read(r, p, pre+"42")
		wantCode(t, err, adapter.ErrUnsupportedRequirement)
	}
	if s.count() != 0 {
		t.Fatalf("%d requests were made", s.count())
	}
}

func TestCancelledContextIsUnavailable(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, `{}`) })
	r := readerFor(t, s, clock.NewFake(at(1)), nil)
	ctx, cancel := cancelled()
	defer cancel()
	_, err := r.ReadNativeClaim(ctx, googledir.PathAccountState, adapter.ClaimContext{Principal: adapter.Principal{ID: pre + "42"}})
	wantCode(t, err, adapter.ErrDependencyUnavailable)
}

func TestCachedAccountState(t *testing.T) {
	clk := clock.NewFake(at(1792080000))
	st := source.NewMemory()
	p := pre + "42"
	put := func(obs int64) {
		f := source.Fact{Value: "disabled", ObservedAt: at(obs), StatusCheckedAt: at(obs), SourceRef: "42"}
		if err := st.Put(t.Context(), p, googledir.PathAccountState, f); err != nil {
			t.Fatal(err)
		}
	}
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, `{}`) })
	r := readerFor(t, s, clk, func(c *googledir.Config) { c.Cache, c.MaxAge = st, 960*time.Second })
	put(1792079040) // exactly MaxAge old
	c, err := read(r, googledir.PathAccountState, p)
	if err != nil || c.Value != "disabled" || c.ObservedAt.Unix() != 1792079040 || c.StatusCheckedAt != c.ObservedAt || c.SourceRef != "42" || c.SourceID != "gd" {
		t.Fatalf("%+v %v", c, err)
	}
	put(1792079039) // one second too old
	_, err = read(r, googledir.PathAccountState, p)
	wantCode(t, err, adapter.ErrDependencyUnavailable)
	put(1792080000 + 61) // later than now plus the skew
	_, err = read(r, googledir.PathAccountState, p)
	wantCode(t, err, adapter.ErrDependencyUnavailable)
	_, err = read(r, googledir.PathAccountState, pre+"43")
	wantCode(t, err, adapter.ErrMissingField)
	if s.count() != 0 {
		t.Fatalf("a cached read made %d requests", s.count())
	}
}
