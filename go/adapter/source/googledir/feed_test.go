package googledir_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/adapter/source/googledir"
	"hop.top/pact-go/core/clock"
)

const (
	notifyURL   = "https://pact.northstar.example/google/notify"
	notifyToken = "channel-secret-0001"
	t0          = 1792080000
)

type feedEnv struct {
	fg    *fakeGoogle
	clk   *clock.Fake
	store *source.Memory
	feed  *googledir.Feed
}

func newFeedEnv(t *testing.T, mut func(c *googledir.FeedConfig)) *feedEnv {
	t.Helper()
	clk := clock.NewFake(at(t0))
	fg := newFakeGoogle(t, clk, &adaptertest.Hooks{})
	fg.users = []*fakeUser{
		{ID: "u1", Email: "u1@x.example"}, {ID: "u2", Email: "u2@x.example", Suspended: true}, {ID: "u3", Email: "u3@x.example"},
	}
	cl, err := fg.client(t, clk)
	if err != nil {
		t.Fatal(err)
	}
	st := source.NewMemory()
	n := 0
	cfg := googledir.FeedConfig{Client: cl, Store: st, Clock: clk, PrincipalPrefix: pre, Customer: "my_customer",
		Address: notifyURL, Token: notifyToken, PollInterval: 900 * time.Second, ChannelTTL: time.Hour,
		RenewBefore: 300 * time.Second, PageSize: 2, NewID: func() string { n++; return fmt.Sprintf("chan-%d", n) }}
	if mut != nil {
		mut(&cfg)
	}
	feed, err := googledir.NewFeed(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &feedEnv{fg, clk, st, feed}
}

func (e *feedEnv) state(t *testing.T, id string) (string, bool) {
	t.Helper()
	f, ok, err := e.store.Get(t.Context(), pre+id, googledir.PathAccountState)
	if err != nil || !ok {
		return "", false
	}
	v, _ := f.Value.(string)
	return v, true
}

func (e *feedEnv) notify(channel int, mut func(r *http.Request)) int {
	e.fg.mu.Lock()
	ch := e.fg.channels[channel-1]
	e.fg.mu.Unlock()
	r := httptest.NewRequest(http.MethodPost, notifyURL, strings.NewReader(`{"kind":"admin#directory#user","id":"u1","etag":"\"e\"","primaryEmail":"u1@x.example"}`))
	r.Header.Set("X-Goog-Channel-ID", ch.ID)
	r.Header.Set("X-Goog-Resource-ID", ch.ResourceID)
	r.Header.Set("X-Goog-Resource-State", "update")
	r.Header.Set("X-Goog-Message-Number", "2")
	r.Header.Set("X-Goog-Channel-Token", notifyToken)
	if mut != nil {
		mut(r)
	}
	rec := httptest.NewRecorder()
	e.feed.Handler().ServeHTTP(rec, r)
	return rec.Code
}

func TestNewFeedRejects(t *testing.T) {
	clk := clock.NewFake(at(t0))
	fg := newFakeGoogle(t, clk, &adaptertest.Hooks{})
	cl, _ := fg.client(t, clk)
	base := googledir.FeedConfig{Client: cl, Store: source.NewMemory(), Clock: clk, PrincipalPrefix: pre, Customer: "my_customer",
		Address: notifyURL, Token: notifyToken, PollInterval: time.Minute, ChannelTTL: time.Hour, RenewBefore: 5 * time.Minute}
	if _, err := googledir.NewFeed(base); err != nil {
		t.Fatal(err)
	}
	mut := func(name string, f func(c *googledir.FeedConfig)) {
		t.Run(name, func(t *testing.T) {
			c := base
			f(&c)
			if _, err := googledir.NewFeed(c); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	mut("no client", func(c *googledir.FeedConfig) { c.Client = nil })
	mut("no store", func(c *googledir.FeedConfig) { c.Store = nil })
	mut("no clock", func(c *googledir.FeedConfig) { c.Clock = nil })
	mut("no customer", func(c *googledir.FeedConfig) { c.Customer = "" })
	mut("bad prefix", func(c *googledir.FeedConfig) { c.PrincipalPrefix = "nope" })
	mut("http address", func(c *googledir.FeedConfig) { c.Address = "http://x.example/n" })
	mut("short token", func(c *googledir.FeedConfig) { c.Token = "short" })
	mut("long token", func(c *googledir.FeedConfig) { c.Token = strings.Repeat("t", 257) })
	mut("poll under a second", func(c *googledir.FeedConfig) { c.PollInterval = 500 * time.Millisecond })
	mut("negative ttl", func(c *googledir.FeedConfig) { c.ChannelTTL = -time.Second })
	mut("renew not before the end", func(c *googledir.FeedConfig) { c.RenewBefore = c.ChannelTTL })
	mut("negative page", func(c *googledir.FeedConfig) { c.PageSize = -1 })
}

func TestFirstTickOpensAChannelAndSweeps(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	st := e.feed.Status()
	if st.Mode != googledir.ModePush || st.ChannelID != "chan-1" || st.ChannelExpires.Unix() != t0+3600 || st.Sweeps != 1 || st.LastSweep.Unix() != t0 {
		t.Fatalf("status %+v", st)
	}
	for id, want := range map[string]string{"u1": "active", "u2": "disabled", "u3": "active"} {
		if got, ok := e.state(t, id); !ok || got != want {
			t.Errorf("%s: %q %v, want %s", id, got, ok, want)
		}
	}
	f, _, _ := e.store.Get(t.Context(), pre+"u2", googledir.PathAccountState)
	if f.ObservedAt.Unix() != t0 || f.StatusCheckedAt.Unix() != t0 || f.SourceRef != "u2" {
		t.Fatalf("fact %+v", f)
	}
	ch := e.fg.channels[0]
	if ch.ID != "chan-1" || ch.Address != notifyURL || ch.Token != notifyToken {
		t.Fatalf("channel %+v", ch)
	}
	// Nothing is due a second later.
	e.clk.Set(at(t0 + 1))
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if st := e.feed.Status(); st.Sweeps != 1 || len(e.fg.channels) != 1 {
		t.Fatalf("a tick with nothing due did work: %+v, %d channels", st, len(e.fg.channels))
	}
}

// The expiry the vendor returns decides renewal, not the one requested.
func TestVendorLifetimeShorterThanRequested(t *testing.T) {
	e := newFeedEnv(t, nil)
	e.fg.channelMax = 1800 * time.Second
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := e.feed.Status().ChannelExpires.Unix(); got != t0+1800 {
		t.Fatalf("expires %d", got)
	}
	e.clk.Set(at(t0 + 1500))
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if e.feed.Status().ChannelID != "chan-2" {
		t.Fatalf("not renewed: %+v", e.feed.Status())
	}
}

func TestSweepDropsVanishedUsersOnly(t *testing.T) {
	e := newFeedEnv(t, nil)
	other := pre + "someone-else"
	_ = e.store.Put(t.Context(), other, googledir.PathAccountState, source.Fact{Value: "active", ObservedAt: at(t0), StatusCheckedAt: at(t0)})
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = e.fg.admin(&gdAdmin{Op: "delete", User: "u3"})
	e.clk.Set(at(t0 + 900))
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.state(t, "u3"); ok {
		t.Error("a deleted user kept its fact")
	}
	if _, ok := e.state(t, "u1"); !ok {
		t.Error("a present user lost its fact")
	}
	if _, ok, _ := e.store.Get(t.Context(), other, googledir.PathAccountState); !ok {
		t.Error("a fact the feed did not write was removed")
	}
}

// A sweep that did not finish proves nothing about the users it did not
// reach: it deletes nothing, reports the error, and is tried again at the
// next tick.
func TestPartialSweepKeepsState(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = e.fg.admin(&gdAdmin{Op: "delete", User: "u3"})
	e.fg.mu.Lock()
	e.fg.pageSize = 1
	e.fg.mu.Unlock()
	failed := false
	e.fg.onList = func(token string) int {
		if token != "" && !failed {
			failed = true
			return 500
		}
		return 0
	}
	e.clk.Set(at(t0 + 900))
	err := e.feed.Tick(t.Context())
	if err == nil {
		t.Fatal("a failed sweep reported no error")
	}
	if _, ok := e.state(t, "u3"); !ok {
		t.Error("an unfinished sweep deleted a fact")
	}
	if st := e.feed.Status(); st.Sweeps != 1 {
		t.Errorf("sweeps %d after a failed sweep", st.Sweeps)
	}
	e.clk.Set(at(t0 + 901))
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, ok := e.state(t, "u3"); ok {
		t.Error("the retried sweep did not delete the vanished user")
	}
	if e.feed.Status().Sweeps != 2 {
		t.Errorf("sweeps %d", e.feed.Status().Sweeps)
	}
}

func TestNotificationChecks(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = e.fg.admin(&gdAdmin{Op: "suspend", User: "u1"})
	cases := map[string]struct {
		mut  func(r *http.Request)
		want int
	}{
		"ok":                {nil, 200},
		"get":               {func(r *http.Request) { r.Method = http.MethodGet }, 405},
		"no token":          {func(r *http.Request) { r.Header.Del("X-Goog-Channel-Token") }, 401},
		"wrong token":       {func(r *http.Request) { r.Header.Set("X-Goog-Channel-Token", notifyToken+"x") }, 401},
		"prefix of token":   {func(r *http.Request) { r.Header.Set("X-Goog-Channel-Token", notifyToken[:10]) }, 401},
		"no channel id":     {func(r *http.Request) { r.Header.Del("X-Goog-Channel-ID") }, 400},
		"no resource id":    {func(r *http.Request) { r.Header.Del("X-Goog-Resource-ID") }, 400},
		"no state":          {func(r *http.Request) { r.Header.Del("X-Goog-Resource-State") }, 400},
		"no message number": {func(r *http.Request) { r.Header.Del("X-Goog-Message-Number") }, 400},
		"unknown channel":   {func(r *http.Request) { r.Header.Set("X-Goog-Channel-ID", "nope") }, 404},
		"wrong resource":    {func(r *http.Request) { r.Header.Set("X-Goog-Resource-ID", "res-other") }, 404},
		"bad body":          {func(r *http.Request) { r.Body = http.NoBody }, 400},
		"wrong kind": {func(r *http.Request) {
			r.Body = nopBody(`{"kind":"admin#directory#group","id":"u1"}`)
		}, 400},
		"duplicate id": {func(r *http.Request) { r.Body = nopBody(`{"kind":"admin#directory#user","id":"u1","id":"u2"}`) }, 400},
		"numeric id":   {func(r *http.Request) { r.Body = nopBody(`{"kind":"admin#directory#user","id":1}`) }, 400},
		"sync, no body": {func(r *http.Request) {
			r.Header.Set("X-Goog-Resource-State", "sync")
			r.Header.Set("X-Goog-Message-Number", "1")
			r.Body = http.NoBody
		}, 200},
		"too large": {func(r *http.Request) {
			r.Body = nopBody(`{"kind":"admin#directory#user","id":"u1","x":"` + strings.Repeat("x", 70000) + `"}`)
		}, 413},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			before, _ := e.state(t, "u1")
			got := e.notify(1, c.mut)
			if got != c.want {
				t.Fatalf("status %d, want %d", got, c.want)
			}
			after, _ := e.state(t, "u1")
			if name != "ok" && after != before {
				t.Errorf("a refused notification changed the state: %q to %q", before, after)
			}
			if name == "ok" && after != "disabled" {
				t.Errorf("an accepted notification did not read the user back: %q", after)
			}
		})
	}
}

func TestNotificationForADeletedUser(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = e.fg.admin(&gdAdmin{Op: "delete", User: "u1"})
	if got := e.notify(1, nil); got != 200 {
		t.Fatalf("status %d", got)
	}
	if _, ok := e.state(t, "u1"); ok {
		t.Fatal("the fact of a deleted user stayed")
	}
}

func TestNotificationWhenTheDirectoryFails(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = e.fg.admin(&gdAdmin{Op: "fail", API: "directory", Status: 503})
	if got := e.notify(1, nil); got != http.StatusServiceUnavailable {
		t.Fatalf("status %d", got)
	}
}

func TestOldChannelAfterAFailedStop(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.fg.fail["stop"] = 500
	e.clk.Set(at(t0 + 3300))
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatalf("a failed stop is not a failed renewal: %v", err)
	}
	if e.feed.Status().ChannelID != "chan-2" {
		t.Fatalf("status %+v", e.feed.Status())
	}
	if got := e.notify(1, nil); got != 200 {
		t.Errorf("the old channel, not stopped, is refused before it expires: %d", got)
	}
	e.clk.Set(at(t0 + 3601))
	if got := e.notify(1, nil); got != 404 {
		t.Errorf("the old channel is accepted after it expired: %d", got)
	}
	if got := e.notify(2, nil); got != 200 {
		t.Errorf("the new channel: %d", got)
	}
}

func TestExpiredChannelIsRefused(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.clk.Set(at(t0 + 3600))
	if got := e.notify(1, nil); got != 404 {
		t.Fatalf("status %d at the expiry instant", got)
	}
}

func TestDefaultChannelIDs(t *testing.T) {
	e := newFeedEnv(t, func(c *googledir.FeedConfig) { c.NewID = nil })
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.clk.Set(at(t0 + 3400))
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	a, b := e.fg.channels[0].ID, e.fg.channels[1].ID
	if a == b || len(a) == 0 || len(a) > 64 || len(b) > 64 || strings.ContainsAny(a+b, " \n") {
		t.Fatalf("ids %q %q", a, b)
	}
}

func TestConcurrentTicksAndNotifications(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = e.feed.Tick(t.Context()); _ = e.feed.Status() }()
		go func() { defer wg.Done(); e.notify(1, nil) }()
	}
	wg.Wait()
}

func TestSweepFactsServeThroughTheReader(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	rd, err := googledir.NewReader(googledir.Config{SourceID: "gd", PrincipalPrefix: pre, Client: mustClient(t, e), Clock: e.clk,
		Cache: e.store, MaxAge: 960 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	c, err := read(rd, googledir.PathAccountState, pre+"u2")
	if err != nil || c.Value != "disabled" {
		t.Fatalf("%+v %v", c, err)
	}
	_, err = read(rd, googledir.PathAccountState, pre+"u9")
	if !errors.Is(err, adapter.ErrMissingField) {
		t.Fatal(err)
	}
}

func mustClient(t *testing.T, e *feedEnv) *googledir.Client {
	cl, err := e.fg.client(t, e.clk)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

// A fact the store holds from a later observation is never replaced by an
// older one (a sweep page requested before a notification was handled).
func TestAnOlderObservationNeverReplacesANewerOne(t *testing.T) {
	e := newFeedEnv(t, nil)
	newer := source.Fact{Value: "disabled", ObservedAt: at(t0 + 500), StatusCheckedAt: at(t0 + 500), SourceRef: "u1"}
	if err := e.store.Put(t.Context(), pre+"u1", googledir.PathAccountState, newer); err != nil {
		t.Fatal(err)
	}
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	f, _, _ := e.store.Get(t.Context(), pre+"u1", googledir.PathAccountState)
	if f.Value != "disabled" || f.ObservedAt.Unix() != t0+500 {
		t.Fatalf("the newer fact was replaced: %+v", f)
	}
}

// A user whose fact was written after the sweep began is not dropped by that
// sweep, though its listing did not include the user.
func TestSweepKeepsWhatAnotherWriterWroteDuringIt(t *testing.T) {
	e := newFeedEnv(t, nil)
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.fg.users[2].Hidden = true // u3 is not in the next listing
	e.clk.Set(at(t0 + 900))
	once := false
	e.fg.onList = func(token string) int {
		if !once {
			once = true
			e.clk.Set(at(t0 + 901))
			e.fg.mu.Unlock() // the stand-in holds its lock while serving
			e.feed.Handler().ServeHTTP(httptest.NewRecorder(), e.notifyRequest(t, 1, "u3"))
			e.fg.mu.Lock()
		}
		return 0
	}
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	f, ok, _ := e.store.Get(t.Context(), pre+"u3", googledir.PathAccountState)
	if !ok || f.ObservedAt.Unix() != t0+901 {
		t.Fatalf("the fact written during the sweep was dropped: %+v %v", f, ok)
	}
}

func (e *feedEnv) notifyRequest(t *testing.T, channel int, user string) *http.Request {
	e.fg.mu.Lock()
	ch := e.fg.channels[channel-1]
	e.fg.mu.Unlock()
	r := httptest.NewRequest(http.MethodPost, notifyURL, strings.NewReader(`{"kind":"admin#directory#user","id":"`+user+`"}`))
	r.Header.Set("X-Goog-Channel-ID", ch.ID)
	r.Header.Set("X-Goog-Resource-ID", ch.ResourceID)
	r.Header.Set("X-Goog-Resource-State", "update")
	r.Header.Set("X-Goog-Message-Number", "2")
	r.Header.Set("X-Goog-Channel-Token", notifyToken)
	return r
}

// The notification names a user; the directory answers for the key it is
// given, and a reply for another ID is not written under the notified one.
func TestNotificationForAnotherIDsReply(t *testing.T) {
	e := newFeedEnv(t, nil)
	e.fg.users[0].Aliases = []string{"old-key"} // resolves to u1, whose ID is not "old-key"
	if err := e.feed.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	_ = e.store.Delete(t.Context(), pre+"u1")
	rec := httptest.NewRecorder()
	e.feed.Handler().ServeHTTP(rec, e.notifyRequest(t, 1, "old-key"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	for _, id := range []string{"old-key", "u1"} {
		if _, ok := e.state(t, id); ok {
			t.Errorf("a fact was written for %s", id)
		}
	}
}
