package googledir

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapter/source"
	"hop.top/pact-go/core/clock"
)

// The native paths a [Reader] answers.
const (
	// PathAccountState is the account state of the principal: "active", or
	// "disabled" for a suspended or archived user.
	PathAccountState = "/principal/account_state"

	groupPrefix = "/principal/groups/"
)

// MemberPath is the native path of the membership fact of a group read with
// members.hasMember: a boolean, true for a direct member and for a member of
// a nested group of the same domain.
func MemberPath(group string) string { return groupPrefix + group + "/member" }

// TransitiveMemberPath is the native path of the membership fact of a group
// read with Cloud Identity checkTransitiveMembership: a boolean, true for a
// member through any chain of nested groups.
func TransitiveMemberPath(group string) string { return groupPrefix + group + "/transitive_member" }

// groupRE is the form of a group identifier in a native path and in a query.
var groupRE = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

// joinAttribute is the only attribute a Directory user joins a principal by:
// the user's unique ID.
const joinAttribute = "id"

// Config configures a [Reader].
type Config struct {
	// SourceID identifies the configured source in every claim.
	SourceID string
	// PrincipalPrefix is the principal identifier up to its local part: the
	// namespace and realm components of the authenticating mechanism and a
	// final ":" (identity mapping IM-4). The local part is the user's unique
	// ID, which the authenticating mechanism must carry (see the source
	// document, open items).
	PrincipalPrefix string
	// Client reads the directory.
	Client *Client
	// Clock is the reader's only source of the current time.
	Clock clock.Clock
	// Groups are the Directory group IDs whose membership is served at
	// [MemberPath]; TransitiveGroups the Cloud Identity group IDs served at
	// [TransitiveMemberPath]. No other group is read.
	Groups           []string
	TransitiveGroups []string
	// Cache, when set, is the store a [Feed] fills, and the account state is
	// answered from it instead of from the API. MaxAge is then the oldest
	// fact the reader serves: the declared bound of the cached state. Both
	// are set or neither is.
	Cache  source.Store
	MaxAge time.Duration
}

// Reader is the [adapter.ClaimReader] of a Google Workspace directory. The
// account state is read from the Directory API at each read, or from the
// cache a [Feed] keeps when a cache is configured; group membership is
// always read from the API.
type Reader struct {
	cfg  Config
	join source.Join
}

// NewReader returns a Reader for cfg.
func NewReader(cfg Config) (*Reader, error) {
	switch {
	case cfg.SourceID == "":
		return nil, errors.New("googledir: no source ID")
	case cfg.Client == nil:
		return nil, errors.New("googledir: no client")
	case cfg.Clock == nil:
		return nil, errors.New("googledir: no clock")
	case (cfg.Cache == nil) != (cfg.MaxAge == 0):
		return nil, errors.New("googledir: a cache and its maximum age are set together")
	case cfg.MaxAge < 0:
		return nil, errors.New("googledir: negative maximum age")
	}
	j := source.Join{Attribute: joinAttribute, Prefix: cfg.PrincipalPrefix}
	if _, err := j.Principal(map[string]string{joinAttribute: "x"}); err != nil {
		return nil, fmt.Errorf("googledir: principal prefix: %w", err)
	}
	for _, list := range [][]string{cfg.Groups, cfg.TransitiveGroups} {
		for i, g := range list {
			if !groupRE.MatchString(g) || slices.Contains(list[:i], g) {
				return nil, fmt.Errorf("googledir: %q is not a group identifier, or is repeated", g)
			}
		}
	}
	cfg.Groups, cfg.TransitiveGroups = slices.Clone(cfg.Groups), slices.Clone(cfg.TransitiveGroups)
	return &Reader{cfg: cfg, join: j}, nil
}

// fact is what a native path asks for.
type fact int

const (
	factNone fact = iota
	factState
	factMember
	factTransitive
)

// route resolves a native path to the fact it asks for and the group.
func (r *Reader) route(path string) (fact, string) {
	if path == PathAccountState {
		return factState, ""
	}
	rest, ok := strings.CutPrefix(path, groupPrefix)
	if !ok {
		return factNone, ""
	}
	if g, ok := strings.CutSuffix(rest, "/member"); ok && slices.Contains(r.cfg.Groups, g) {
		return factMember, g
	}
	if g, ok := strings.CutSuffix(rest, "/transitive_member"); ok && slices.Contains(r.cfg.TransitiveGroups, g) {
		return factTransitive, g
	}
	return factNone, ""
}

// localID returns the user ID that principal carries: the local part under
// the configured prefix, in the one spelling of identity mapping IM-2. An
// address is never an ID, and a principal of another realm has no ID here.
func (r *Reader) localID(principal string) (string, bool) {
	rest, ok := strings.CutPrefix(principal, r.cfg.PrincipalPrefix)
	if !ok || rest == "" {
		return "", false
	}
	id, err := url.PathUnescape(rest)
	if err != nil || id == "" || strings.Contains(id, "@") {
		return "", false
	}
	if p, err := r.join.Principal(map[string]string{joinAttribute: id}); err != nil || p != principal {
		return "", false
	}
	return id, true
}

// ReadNativeClaim implements [adapter.ClaimReader]. A principal that is not
// under the configured prefix, whose local part is not a user ID in its one
// spelling, or whom the directory does not know has no fact
// ([adapter.ErrMissingField]); a path or group that is not configured is
// [adapter.ErrUnsupportedRequirement]; a directory that cannot answer, or a
// cached fact older than the maximum age, is [adapter.ErrDependencyUnavailable].
//
// A live fact carries the time the first request was made, for both
// ObservedAt and StatusCheckedAt: the answer reflects the directory at some
// instant between the request and the reply, and the earlier is the one that
// is certain (freshness profile, section 4.2, convention 1).
func (r *Reader) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := installed.Live(ctx); err != nil {
		return adapter.NativeClaim{}, err
	}
	kind, group := r.route(nativePath)
	if kind == factNone {
		return adapter.NativeClaim{}, fmt.Errorf("source %s: %q is not a path it serves: %w", r.cfg.SourceID, nativePath, adapter.ErrUnsupportedRequirement)
	}
	if kind == factState && r.cfg.Cache != nil {
		return r.cached(ctx, cc.Principal.ID)
	}
	id, ok := r.localID(cc.Principal.ID)
	if !ok {
		return adapter.NativeClaim{}, r.absent("the principal carries no user ID of this directory")
	}
	start := r.cfg.Clock.Now()
	u, err := r.cfg.Client.User(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return adapter.NativeClaim{}, r.absent("the directory has no such user")
		}
		return adapter.NativeClaim{}, r.unavailable(err)
	}
	if u.ID != id {
		// The API resolved the key through another attribute: the reply
		// describes another user.
		return adapter.NativeClaim{}, r.absent("the directory resolved the key to another user")
	}
	var value any
	switch kind {
	case factState:
		value = stateOf(u)
	case factMember:
		is, err := r.cfg.Client.HasMember(ctx, group, u.ID)
		if err != nil {
			return adapter.NativeClaim{}, r.unavailable(err)
		}
		value = is
	case factTransitive:
		is, err := r.cfg.Client.TransitiveMember(ctx, group, u.PrimaryEmail)
		if err != nil {
			return adapter.NativeClaim{}, r.unavailable(err)
		}
		value = is
	}
	if err := installed.SourceTimes(r.cfg.Clock.Now(), start); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("source %s: %w", r.cfg.SourceID, err)
	}
	return adapter.NativeClaim{Value: value, ObservedAt: start, StatusCheckedAt: start, SourceID: r.cfg.SourceID, SourceRef: u.ID}, nil
}

// cached answers the account state from the cache.
func (r *Reader) cached(ctx context.Context, principal string) (adapter.NativeClaim, error) {
	f, ok, err := r.cfg.Cache.Get(ctx, principal, PathAccountState)
	if err != nil {
		return adapter.NativeClaim{}, r.unavailable(err)
	}
	if !ok {
		return adapter.NativeClaim{}, r.absent("the cache holds no state for the principal")
	}
	now := r.cfg.Clock.Now()
	if f.ObservedAt.IsZero() || f.StatusCheckedAt.IsZero() {
		return adapter.NativeClaim{}, r.unavailable(errors.New("a cached state without a time"))
	}
	if err := installed.SourceTimes(now, f.ObservedAt, f.StatusCheckedAt); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("source %s: %w", r.cfg.SourceID, err)
	}
	if now.Sub(f.StatusCheckedAt) > r.cfg.MaxAge || now.Sub(f.ObservedAt) > r.cfg.MaxAge {
		return adapter.NativeClaim{}, r.unavailable(errors.New("the cached state is older than the declared bound"))
	}
	return adapter.NativeClaim{Value: f.Value, ObservedAt: f.ObservedAt, StatusCheckedAt: f.StatusCheckedAt, SourceID: r.cfg.SourceID, SourceRef: f.SourceRef}, nil
}

func (r *Reader) absent(why string) error {
	return fmt.Errorf("source %s: %s: %w", r.cfg.SourceID, why, adapter.ErrMissingField)
}

func (r *Reader) unavailable(err error) error {
	return installed.Dependency(fmt.Errorf("source %s: %w", r.cfg.SourceID, err))
}

// stateOf is the account state of a user: "active" only for a user who is
// neither suspended nor archived.
func stateOf(u User) string {
	if u.Suspended || u.Archived {
		return "disabled"
	}
	return "active"
}
