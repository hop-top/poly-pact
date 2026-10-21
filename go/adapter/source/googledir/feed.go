package googledir

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/strictjson"
)

// Mode is how the feed currently learns of changes.
type Mode string

const (
	// ModePush: a push channel is open. Notifications shorten the time a
	// change takes to be seen; the periodic sweep still runs.
	ModePush Mode = "push"
	// ModePoll: no channel is open (none could be created or renewed, or the
	// last one expired). The sweep alone keeps the cache within its bound.
	ModePoll Mode = "poll"
)

// Status is a snapshot of the feed.
type Status struct {
	Mode           Mode
	ChannelID      string
	ChannelExpires time.Time
	// LastSweep is the time the last complete sweep started; Sweeps counts
	// the complete sweeps.
	LastSweep time.Time
	Sweeps    int
}

// FeedConfig configures a [Feed].
type FeedConfig struct {
	// Client reads the directory and manages the channel.
	Client *Client
	// Store receives the account state of each user, at [PathAccountState];
	// the [Reader] of the same Store serves it.
	Store source.Store
	// Clock is the feed's only source of the current time.
	Clock clock.Clock
	// PrincipalPrefix is as in [Config].
	PrincipalPrefix string
	// Customer is the Google Workspace customer ID, or "my_customer".
	Customer string
	// Address is the https URL the API delivers notifications to: the URL
	// at which the deployment serves [Feed.Handler].
	Address string
	// Token is the secret the API echoes in every notification, 16 to 256
	// printable ASCII characters.
	Token string
	// PollInterval is the time between sweeps: the declared bound of the
	// cached state, less the time a sweep takes. At least one second.
	PollInterval time.Duration
	// ChannelTTL is the lifetime asked for a channel; zero asks for none and
	// leaves it to the API. The API's reply decides the real expiration.
	ChannelTTL time.Duration
	// RenewBefore is how long before its expiration a channel is replaced.
	RenewBefore time.Duration
	// PageSize is the page size of the sweep; zero for the API's default.
	PageSize int
	// NewID makes channel IDs, each at most 64 characters and never reused;
	// random when nil.
	NewID func() string
}

// watchEvent is the user event the channel subscribes to. Suspending and
// archiving a user are updates; creation, deletion and restoration are seen
// by the sweep.
const watchEvent = "update"

// maxNotification bounds a notification body.
const maxNotification = 64 << 10

type channel struct {
	Channel
}

// Feed keeps a [source.Store] of the account state of every user of a
// Workspace customer, from two sources of change: a push channel of the
// Directory API, and a periodic sweep of the user list. A notification names
// a user; the feed reads that user back from the API, so a lost, repeated or
// reordered notification costs nothing but time. The sweep does not depend on
// the channel, because the API states no delivery guarantee for
// notifications: the declared bound of the cached state is the poll
// interval, and a healthy channel only makes a change visible sooner.
//
// The feed makes no goroutine and reads no timer: the deployment calls
// [Feed.Tick] on its own schedule (at least as often as the poll interval and
// the renewal margin) and mounts [Feed.Handler].
type Feed struct {
	cfg  FeedConfig
	join source.Join
	tok  [sha256.Size]byte

	tick sync.Mutex // serializes Tick

	mu        sync.Mutex // guards the fields below
	cur       *channel
	prev      []*channel
	known     map[string]time.Time // principal -> time of the last write
	lastSweep time.Time
	sweeps    int
	write     sync.Mutex // serializes read-compare-write of a fact
}

// NewFeed returns a Feed for cfg.
func NewFeed(cfg FeedConfig) (*Feed, error) {
	switch {
	case cfg.Client == nil:
		return nil, errors.New("googledir: no client")
	case cfg.Store == nil:
		return nil, errors.New("googledir: no store")
	case cfg.Clock == nil:
		return nil, errors.New("googledir: no clock")
	case cfg.Customer == "":
		return nil, errors.New("googledir: no customer")
	case cfg.PollInterval < time.Second:
		return nil, errors.New("googledir: the poll interval is under a second")
	case cfg.ChannelTTL < 0 || cfg.RenewBefore < 0:
		return nil, errors.New("googledir: negative channel time")
	case cfg.ChannelTTL > 0 && cfg.RenewBefore >= cfg.ChannelTTL:
		return nil, errors.New("googledir: the renewal margin is not under the channel lifetime")
	case cfg.PageSize < 0 || cfg.PageSize > maxPageSize:
		return nil, fmt.Errorf("googledir: page size %d is not 0 to %d", cfg.PageSize, maxPageSize)
	case len(cfg.Token) < 16 || len(cfg.Token) > 256:
		return nil, errors.New("googledir: the channel token is 16 to 256 characters")
	}
	for _, c := range cfg.Token {
		if c < 0x21 || c > 0x7e {
			return nil, errors.New("googledir: the channel token is not printable ASCII")
		}
	}
	if err := requireHTTPS(cfg.Address); err != nil {
		return nil, fmt.Errorf("googledir: channel address: %w", err)
	}
	j := source.Join{Attribute: joinAttribute, Prefix: cfg.PrincipalPrefix}
	if _, err := j.Principal(map[string]string{joinAttribute: "x"}); err != nil {
		return nil, fmt.Errorf("googledir: principal prefix: %w", err)
	}
	if cfg.NewID == nil {
		cfg.NewID = randomID
	}
	return &Feed{cfg: cfg, join: j, tok: sha256.Sum256([]byte(cfg.Token)), known: map[string]time.Time{}}, nil
}

func randomID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on a supported platform
	}
	return "pact-" + hex.EncodeToString(b[:])
}

// Status returns a snapshot of the feed.
func (f *Feed) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := Status{Mode: ModePoll, LastSweep: f.lastSweep, Sweeps: f.sweeps}
	if f.cur != nil && f.cur.Expiration.After(f.cfg.Clock.Now()) {
		st.Mode, st.ChannelID, st.ChannelExpires = ModePush, f.cur.ID, f.cur.Expiration
	}
	return st
}

// Tick does what is due: it drops expired channels, opens or renews the
// channel when there is none or it expires within the renewal margin, and
// sweeps the user list when the poll interval has passed since the last
// complete sweep. A failure of one step does not stop the other; the errors
// are joined. A failed renewal leaves the channel in use until it expires, and
// the next Tick tries again.
func (f *Feed) Tick(ctx context.Context) error {
	f.tick.Lock()
	defer f.tick.Unlock()
	now := f.cfg.Clock.Now()
	f.expire(now)
	var errs []error
	if f.channelDue(now) {
		if err := f.renew(ctx, now); err != nil {
			errs = append(errs, err)
		}
	}
	if f.sweepDue(now) {
		if err := f.sweep(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (f *Feed) expire(now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cur != nil && !f.cur.Expiration.After(now) {
		f.cur = nil
	}
	f.prev = slices.DeleteFunc(f.prev, func(c *channel) bool { return !c.Expiration.After(now) })
}

func (f *Feed) channelDue(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur == nil || f.cur.Expiration.Sub(now) <= f.cfg.RenewBefore
}

func (f *Feed) sweepDue(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastSweep.IsZero() || !now.Before(f.lastSweep.Add(f.cfg.PollInterval))
}

// renew opens a channel under a new ID. The old channel is stopped once the
// new one is open; if it cannot be stopped it is still accepted until it
// expires.
func (f *Feed) renew(ctx context.Context, now time.Time) error {
	got, err := f.cfg.Client.WatchUsers(ctx, f.cfg.Customer, watchEvent,
		Channel{ID: f.cfg.NewID(), Address: f.cfg.Address, Token: f.cfg.Token}, f.cfg.ChannelTTL)
	if err != nil {
		return fmt.Errorf("googledir: opening a channel: %w", err)
	}
	nc := &channel{got}
	if !nc.Expiration.After(now) {
		_ = f.cfg.Client.StopChannel(ctx, nc.Channel)
		return errors.New("googledir: the API opened a channel that is already expired")
	}
	f.mu.Lock()
	old := f.cur
	f.cur = nc
	f.mu.Unlock()
	if old == nil {
		return nil
	}
	if err := f.cfg.Client.StopChannel(ctx, old.Channel); err != nil {
		f.mu.Lock()
		f.prev = append(f.prev, old)
		f.mu.Unlock()
	}
	return nil
}

// sweep lists every user and writes each one's state, then drops the facts
// of users the complete listing no longer holds. A listing that failed
// part-way deletes nothing and does not count as a sweep.
func (f *Feed) sweep(ctx context.Context) error {
	start := f.cfg.Clock.Now()
	seen := map[string]bool{}
	err := f.cfg.Client.Users(ctx, f.cfg.Customer, f.cfg.PageSize, func(page []User, requested time.Time) error {
		for _, u := range page {
			p, err := f.join.Principal(map[string]string{joinAttribute: u.ID})
			if err != nil {
				return fmt.Errorf("googledir: a listed user does not join: %w", err)
			}
			if err := f.put(ctx, p, u, requested); err != nil {
				return err
			}
			seen[p] = true
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("googledir: sweep: %w", err)
	}
	f.mu.Lock()
	var gone []string
	for p := range f.known {
		if !seen[p] {
			gone = append(gone, p)
		}
	}
	f.mu.Unlock()
	for _, p := range gone {
		if err := f.drop(ctx, p, start); err != nil {
			return fmt.Errorf("googledir: sweep: %w", err)
		}
	}
	f.mu.Lock()
	f.lastSweep = start
	f.sweeps++
	f.mu.Unlock()
	return nil
}

// put writes the state of u as of the time requested, unless the store
// already holds a newer one.
func (f *Feed) put(ctx context.Context, principal string, u User, requested time.Time) error {
	f.write.Lock()
	defer f.write.Unlock()
	if old, ok, err := f.cfg.Store.Get(ctx, principal, PathAccountState); err != nil {
		return err
	} else if ok && old.ObservedAt.After(requested) {
		return nil
	}
	err := f.cfg.Store.Put(ctx, principal, PathAccountState, source.Fact{
		Value: stateOf(u), ObservedAt: requested, StatusCheckedAt: requested, SourceRef: u.ID,
	})
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.known[principal] = requested
	f.mu.Unlock()
	return nil
}

// drop removes the facts of a principal unless they were written at or after
// at: a writer that ran while the sweep listed the users saw a newer state
// than the listing.
func (f *Feed) drop(ctx context.Context, principal string, at time.Time) error {
	f.write.Lock()
	defer f.write.Unlock()
	f.mu.Lock()
	written, ok := f.known[principal]
	f.mu.Unlock()
	if ok && !written.Before(at) {
		return nil
	}
	if err := f.cfg.Store.Delete(ctx, principal); err != nil {
		return err
	}
	f.mu.Lock()
	delete(f.known, principal)
	f.mu.Unlock()
	return nil
}

// refresh reads one user back and writes the state, or drops the facts when
// the directory no longer has the user.
func (f *Feed) refresh(ctx context.Context, id string) (status int, err error) {
	p, err := f.join.Principal(map[string]string{joinAttribute: id})
	if err != nil || strings.Contains(id, "@") {
		return http.StatusBadRequest, errors.New("the notification names no user ID")
	}
	start := f.cfg.Clock.Now()
	u, err := f.cfg.Client.User(ctx, id)
	switch {
	case errors.Is(err, ErrNotFound):
		if err := f.drop(ctx, p, start.Add(time.Nanosecond)); err != nil {
			return http.StatusServiceUnavailable, err
		}
		return http.StatusOK, nil
	case err != nil:
		return http.StatusServiceUnavailable, err
	case u.ID != id:
		return http.StatusBadGateway, errors.New("the directory resolved the notified ID to another user")
	}
	if err := f.put(ctx, p, u, start); err != nil {
		return http.StatusServiceUnavailable, err
	}
	return http.StatusOK, nil
}

// Handler is the endpoint the API delivers notifications to. A notification
// is accepted only with the configured token, from a channel the feed opened
// and that has not expired (or that was replaced and could not be stopped,
// until it expires). The sync message that follows a channel's creation is
// acknowledged and ignored. Any other notification must carry a body that
// names a user (kind admin#directory#user and an id); the user is read back
// from the API before the handler answers 200, and a failure to do so is a
// 5xx, so that a delivery that failed is a delivery that can be retried.
func (f *Feed) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		got := sha256.Sum256([]byte(r.Header.Get("X-Goog-Channel-Token")))
		if subtle.ConstantTimeCompare(got[:], f.tok[:]) != 1 {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		chID, resID := r.Header.Get("X-Goog-Channel-ID"), r.Header.Get("X-Goog-Resource-ID")
		state, num := r.Header.Get("X-Goog-Resource-State"), r.Header.Get("X-Goog-Message-Number")
		if n, err := strconv.ParseInt(num, 10, 64); chID == "" || resID == "" || state == "" || err != nil || n < 1 {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if !f.accepts(chID, resID) {
			http.Error(w, "", http.StatusNotFound)
			return
		}
		if state == "sync" {
			w.WriteHeader(http.StatusOK)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxNotification))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		id, ok := notifiedUser(body)
		if !ok {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if status, err := f.refresh(r.Context(), id); err != nil {
			http.Error(w, "", status)
			return
		} else if status != http.StatusOK {
			http.Error(w, "", status)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// accepts reports whether a channel and resource are one the feed holds open.
func (f *Feed) accepts(channelID, resourceID string) bool {
	now := f.cfg.Clock.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range append([]*channel{f.cur}, f.prev...) {
		if c != nil && c.ID == channelID && c.ResourceID == resourceID && c.Expiration.After(now) {
			return true
		}
	}
	return false
}

// notifiedUser reads the user ID of a user notification body.
func notifiedUser(body []byte) (string, bool) {
	var m map[string]json.RawMessage
	if strictjson.Unmarshal(body, strictjson.Limits{}, &m) != nil || m == nil {
		return "", false
	}
	var kind, id string
	if member(m, "kind", &kind) != nil || kind != "admin#directory#user" || member(m, "id", &id) != nil || id == "" {
		return "", false
	}
	return id, true
}
