package source_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/core/clock"
)

// now is the instant of the draft's worked example, 2026-10-15T16:00:00Z.
var now = time.Unix(1792080000, 0)

const (
	alice  = "oauth:entra:contoso:7a1f"
	groups = "/principal/groups"
	state  = "/principal/account_state"
)

func ctxOf(id string) adapter.ClaimContext {
	return adapter.ClaimContext{Principal: adapter.Principal{ID: id}}
}

// reader returns a reader over st with a 2400 second declared lag, the
// one-cycle lag of an Entra provisioning feed.
func reader(t *testing.T, st source.Store, c clock.Clock) *source.Reader {
	t.Helper()
	r, err := source.NewReader(source.Config{
		Store: st, SourceID: "scim-northstar", Paths: []string{groups, state},
		Lag: 2400 * time.Second, Clock: c,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func put(t *testing.T, st source.Store, principal, path string, f source.Fact) {
	t.Helper()
	if err := st.Put(context.Background(), principal, path, f); err != nil {
		t.Fatal(err)
	}
}

func wantCode(t *testing.T, err error, sentinel error) {
	t.Helper()
	if !errors.Is(err, sentinel) {
		t.Fatalf("error %v, want one that wraps %v", err, sentinel)
	}
}

func TestMemoryPutGetDelete(t *testing.T) {
	ctx := context.Background()
	st := source.NewMemory()
	put(t, st, alice, groups, source.Fact{Value: []string{"finance"}, SourceRef: "u-1"})
	put(t, st, alice, state, source.Fact{Value: "active", SourceRef: "u-1"})

	f, ok, err := st.Get(ctx, alice, groups)
	if err != nil || !ok {
		t.Fatalf("Get = %v %v", ok, err)
	}
	if b, _ := json.Marshal(f.Value); string(b) != `["finance"]` || f.SourceRef != "u-1" {
		t.Errorf("Get = %s %q", b, f.SourceRef)
	}
	if _, ok, _ := st.Get(ctx, alice, "/principal/roles"); ok {
		t.Error("a path never put is held")
	}
	if _, ok, _ := st.Get(ctx, "oauth:entra:contoso:other", groups); ok {
		t.Error("another principal's fact is held")
	}

	// A later push replaces the fact.
	put(t, st, alice, groups, source.Fact{Value: []string{}, SourceRef: "u-1"})
	f, _, _ = st.Get(ctx, alice, groups)
	if b, _ := json.Marshal(f.Value); string(b) != `[]` {
		t.Errorf("after the removal Get = %s", b)
	}

	// Delete removes every fact of the principal.
	if err := st.Delete(ctx, alice); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{groups, state} {
		if _, ok, _ := st.Get(ctx, alice, p); ok {
			t.Errorf("%s held after Delete", p)
		}
	}
	if err := st.Delete(ctx, alice); err != nil {
		t.Errorf("Delete of a principal with no record: %v", err)
	}
}

// TestMemoryKeepsNoAlias: a value is held as JSON data, so a caller that
// changes its value after Put or after Get changes nothing in the store.
func TestMemoryKeepsNoAlias(t *testing.T) {
	ctx := context.Background()
	st := source.NewMemory()
	v := []string{"finance"}
	put(t, st, alice, groups, source.Fact{Value: v})
	v[0] = "admin"
	f, _, _ := st.Get(ctx, alice, groups)
	got := f.Value.([]any)
	got[0] = "admin"
	f, _, _ = st.Get(ctx, alice, groups)
	if b, _ := json.Marshal(f.Value); string(b) != `["finance"]` {
		t.Errorf("Get = %s, want [\"finance\"]", b)
	}
}

func TestMemoryRefusesBadPut(t *testing.T) {
	st := source.NewMemory()
	for name, c := range map[string]struct {
		principal, path string
		v               any
	}{
		"no principal":   {"", groups, "x"},
		"no path":        {alice, "", "x"},
		"relative path":  {alice, "principal/groups", "x"},
		"not JSON value": {alice, groups, make(chan int)},
	} {
		if err := st.Put(context.Background(), c.principal, c.path, source.Fact{Value: c.v}); err == nil {
			t.Errorf("%s: Put accepted", name)
		}
	}
}

// TestReaderAsOfTime: a fact the push carries no time for is reported as of
// the read time minus the declared lag, for both times, never at the read
// time (freshness profile 4.1 directory row, 4.2 convention 1).
func TestReaderAsOfTime(t *testing.T) {
	st := source.NewMemory()
	put(t, st, alice, groups, source.Fact{Value: []string{"finance"}, SourceRef: "u-1"})
	r := reader(t, st, clock.NewFake(now))
	c, err := r.ReadNativeClaim(context.Background(), groups, ctxOf(alice))
	if err != nil {
		t.Fatal(err)
	}
	// 1792080000 - 2400.
	if c.ObservedAt.Unix() != 1792077600 || c.StatusCheckedAt.Unix() != 1792077600 {
		t.Errorf("times %d %d, want 1792077600 for both", c.ObservedAt.Unix(), c.StatusCheckedAt.Unix())
	}
	if c.SourceID != "scim-northstar" || c.SourceRef != "u-1" {
		t.Errorf("source %q %q", c.SourceID, c.SourceRef)
	}
	if b, _ := json.Marshal(c.Value); string(b) != `["finance"]` {
		t.Errorf("value %s", b)
	}
}

// TestReaderKeepsSourceTimes: a fact whose push carries its own times, such
// as the event time of a security event, is reported with them unchanged:
// a cached fact is not restamped with the time of the read (draft 8.3).
func TestReaderKeepsSourceTimes(t *testing.T) {
	st := source.NewMemory()
	at := time.Unix(1792070000, 0)
	put(t, st, alice, state, source.Fact{Value: "disabled", ObservedAt: at, StatusCheckedAt: at})
	c, err := reader(t, st, clock.NewFake(now)).ReadNativeClaim(context.Background(), state, ctxOf(alice))
	if err != nil {
		t.Fatal(err)
	}
	if !c.ObservedAt.Equal(at) || !c.StatusCheckedAt.Equal(at) {
		t.Errorf("times %v %v, want %v", c.ObservedAt, c.StatusCheckedAt, at)
	}
}

func TestReaderClockAhead(t *testing.T) {
	for name, c := range map[string]struct {
		at time.Time
		ok bool
	}{
		"at the skew":          {now.Add(5 * time.Second), true},
		"beyond the skew":      {now.Add(6 * time.Second), false},
		"status beyond skew":   {time.Time{}, false},
		"observed in the past": {now.Add(-time.Second), true},
	} {
		t.Run(name, func(t *testing.T) {
			st := source.NewMemory()
			f := source.Fact{Value: "active", ObservedAt: c.at, StatusCheckedAt: c.at}
			if c.at.IsZero() {
				f = source.Fact{Value: "active", ObservedAt: now, StatusCheckedAt: now.Add(6 * time.Second)}
			}
			put(t, st, alice, state, f)
			_, err := reader(t, st, clock.NewFake(now)).ReadNativeClaim(context.Background(), state, ctxOf(alice))
			if c.ok && err != nil {
				t.Fatal(err)
			}
			if !c.ok {
				wantCode(t, err, adapter.ErrDependencyUnavailable)
			}
		})
	}
}

// TestReaderPaths: a path the reader does not serve is refused, a principal
// with no record answers no fact, and so does one whose record was deleted.
func TestReaderPaths(t *testing.T) {
	ctx := context.Background()
	st := source.NewMemory()
	put(t, st, alice, groups, source.Fact{Value: []string{"finance"}})
	r := reader(t, st, clock.NewFake(now))

	_, err := r.ReadNativeClaim(ctx, "/principal/roles", ctxOf(alice))
	wantCode(t, err, adapter.ErrUnsupportedRequirement)
	_, err = r.ReadNativeClaim(ctx, state, ctxOf(alice))
	wantCode(t, err, adapter.ErrMissingField)
	_, err = r.ReadNativeClaim(ctx, groups, ctxOf("oauth:entra:contoso:bob"))
	wantCode(t, err, adapter.ErrMissingField)
	_, err = r.ReadNativeClaim(ctx, groups, ctxOf(""))
	wantCode(t, err, adapter.ErrMissingField)

	if err := st.Delete(ctx, alice); err != nil {
		t.Fatal(err)
	}
	_, err = r.ReadNativeClaim(ctx, groups, ctxOf(alice))
	wantCode(t, err, adapter.ErrMissingField)
}

// failing is a store that cannot answer.
type failing struct {
	source.Store
	err error
}

func (f failing) Get(context.Context, string, string) (source.Fact, bool, error) {
	return source.Fact{}, false, f.err
}

func TestReaderStoreUnavailable(t *testing.T) {
	ctx := context.Background()
	r := reader(t, failing{err: errors.New("disk")}, clock.NewFake(now))
	_, err := r.ReadNativeClaim(ctx, groups, ctxOf(alice))
	wantCode(t, err, adapter.ErrDependencyUnavailable)

	// An error that carries a code keeps it.
	r = reader(t, failing{err: fmt.Errorf("quarantined: %w", adapter.ErrDependencyUnavailable)}, clock.NewFake(now))
	_, err = r.ReadNativeClaim(ctx, groups, ctxOf(alice))
	wantCode(t, err, adapter.ErrDependencyUnavailable)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	st := source.NewMemory()
	put(t, st, alice, groups, source.Fact{Value: []string{}})
	_, err = reader(t, st, clock.NewFake(now)).ReadNativeClaim(cancelled, groups, ctxOf(alice))
	wantCode(t, err, adapter.ErrDependencyUnavailable)
}

func TestNewReaderRefusesBadConfig(t *testing.T) {
	good := source.Config{Store: source.NewMemory(), SourceID: "s", Paths: []string{groups}, Lag: time.Second, Clock: clock.NewFake(now)}
	for name, edit := range map[string]func(*source.Config){
		"no store":      func(c *source.Config) { c.Store = nil },
		"no source id":  func(c *source.Config) { c.SourceID = "" },
		"no paths":      func(c *source.Config) { c.Paths = nil },
		"empty path":    func(c *source.Config) { c.Paths = []string{""} },
		"negative lag":  func(c *source.Config) { c.Lag = -time.Second },
		"no clock":      func(c *source.Config) { c.Clock = nil },
		"relative path": func(c *source.Config) { c.Paths = []string{"principal/groups"} },
	} {
		c := good
		edit(&c)
		if _, err := source.NewReader(c); err == nil {
			t.Errorf("%s: NewReader accepted", name)
		}
	}
	if _, err := source.NewReader(good); err != nil {
		t.Errorf("good config: %v", err)
	}
}

// TestJoin: a record joins a principal only through the declared join
// attribute, written in the one spelling of identity mapping IM-2 after the
// configured realm prefix (IM-4, IM-5).
func TestJoin(t *testing.T) {
	j := source.Join{Attribute: "externalId", Prefix: "oauth:entra:contoso:"}
	for name, c := range map[string]struct {
		attrs map[string]string
		want  string
	}{
		"object id":      {map[string]string{"externalId": "7a1f-22", "userName": "alice@contoso.example"}, "oauth:entra:contoso:7a1f-22"},
		"colon encoded":  {map[string]string{"externalId": "a:b"}, "oauth:entra:contoso:a%3Ab"},
		"utf-8 encoded":  {map[string]string{"externalId": "é~"}, "oauth:entra:contoso:%C3%A9~"},
		"percent itself": {map[string]string{"externalId": "50%"}, "oauth:entra:contoso:50%25"},
	} {
		got, err := j.Principal(c.attrs)
		if err != nil || got != c.want {
			t.Errorf("%s: Principal = %q %v, want %q", name, got, err, c.want)
		}
	}
	for name, attrs := range map[string]map[string]string{
		"user name only":    {"userName": "alice@contoso.example"},
		"email only":        {"emails": "alice@contoso.example"},
		"empty join value":  {"externalId": ""},
		"invalid utf-8":     {"externalId": "\xff"},
		"no attributes":     nil,
		"case of attribute": {"externalid": "7a1f"},
	} {
		if got, err := j.Principal(attrs); !errors.Is(err, source.ErrNoJoin) {
			t.Errorf("%s: Principal = %q %v, want ErrNoJoin", name, got, err)
		}
	}
	for name, bad := range map[string]source.Join{
		"no attribute":         {Prefix: "oauth:entra:contoso:"},
		"prefix without colon": {Attribute: "externalId", Prefix: "oauth:entra:contoso"},
		"unknown namespace":    {Attribute: "externalId", Prefix: "scim:contoso:"},
		"unencoded prefix":     {Attribute: "externalId", Prefix: "oauth:https://idp:"},
		"lower-case escape":    {Attribute: "externalId", Prefix: "oauth:a%3a:"},
		"empty component":      {Attribute: "externalId", Prefix: "oauth::"},
	} {
		if _, err := bad.Principal(map[string]string{"externalId": "7a1f"}); err == nil || errors.Is(err, source.ErrNoJoin) {
			t.Errorf("%s: Principal error %v, want a configuration error", name, err)
		}
	}
	if got, err := (source.Join{Attribute: "id", Prefix: "x-scim:northstar:"}).Principal(map[string]string{"id": "1"}); err != nil || got != "x-scim:northstar:1" {
		t.Errorf("extension namespace: %q %v", got, err)
	}
}
