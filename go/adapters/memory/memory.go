package memory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/freshness"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/internal/ascii"
)

// Adapter is the in-memory reference adapter: it implements the seven
// functions of draft 17.1 over a State and keeps nothing outside memory.
//
// It never reads the wall clock; the Clock passed to New is its only source of
// the current time. It is safe for concurrent use: after New it only reads its
// state.
type Adapter struct {
	st       State
	clk      clock.Clock
	mappings map[string]Mapping
	key      *ecdsa.PrivateKey
	// guard holds the observation time of every source record a bounded
	// check has consulted, starting with the sightings of the state.
	guard *freshness.Monotonic
	// shared says that a workload may serve several agents; see
	// [WithSharedWorkloads].
	shared bool
}

// Option configures an [Adapter].
type Option func(*Adapter)

// WithSharedWorkloads makes the adapter that of a profile that supports
// workloads shared by several agents (spec/v1.0/profiles/identity-mapping.md,
// IM-19): ResolveAgentBinding selects among the records of a workload by the
// agent ID alone, however many of them are in force. Without it, the default
// of every profile, a workload serves one agent, and a workload with more than
// one enrollment in force is a configuration error.
func WithSharedWorkloads() Option { return func(a *Adapter) { a.shared = true } }

// New returns an adapter over st, reading the current time from clk. It
// validates st.
func New(st State, clk clock.Clock, opts ...Option) (*Adapter, error) {
	if clk == nil {
		return nil, errors.New("memory: no clock")
	}
	if err := st.Validate(); err != nil {
		return nil, fmt.Errorf("memory: state: %w", err)
	}
	a := &Adapter{
		st:       st,
		clk:      clk,
		mappings: make(map[string]Mapping, len(st.Mappings)),
	}
	for _, o := range opts {
		o(a)
	}
	for _, m := range st.Mappings {
		// MapOperation applies the baseline HTTP mapping under each installed
		// version; its configuration must be usable before any request.
		if err := a.bindingConfig(m.Version).Validate(); err != nil {
			return nil, fmt.Errorf("memory: mapping %q: %w", m.Version, err)
		}
		a.mappings[m.Version] = m
	}
	a.guard = newGuard(st.Sightings)
	if st.Reporting != nil {
		var err error
		if a.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, fmt.Errorf("memory: signing key: %w", err)
		}
	}
	return a, nil
}

// FromJSON parses a state document with ParseState and calls New.
func FromJSON(raw []byte, clk clock.Clock, opts ...Option) (*Adapter, error) {
	st, err := ParseState(raw)
	if err != nil {
		return nil, err
	}
	return New(st, clk, opts...)
}

// State returns the adapter's state. The caller must not change it.
func (a *Adapter) State() State { return a.st }

// Describe returns the descriptor of the memory mechanism.
func (a *Adapter) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "memory", Version: "1", MappingRevision: "memory-map-1"}
}

// realm returns the realm of the gateway the adapter serves.
func (a *Adapter) realm() adapter.Realm {
	return adapter.Realm{TenantID: a.st.Gateway.TenantID, EnvironmentID: a.st.Gateway.EnvironmentID}
}

// live fails with a dependency error when ctx is already done: a call that
// cannot be completed is not an answer.
func (a *Adapter) live(ctx context.Context, fn string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("memory: %s: %w: %w", fn, adapter.ErrDependencyUnavailable, err)
	}
	return nil
}

// arrivedKey is the context key that marks a request as having come through
// the enforcement point. The type is unexported, so no client-supplied value
// can carry it.
type arrivedKey struct{}

// Arrive marks r as having arrived through the enforcement point and returns
// the request to use. A real enforcement point calls it after it has taken the
// request off the wire; a request that did not pass through it carries no
// mark, and AuthenticateNative refuses it.
func Arrive(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), arrivedKey{}, true))
}

// Arrived reports whether r carries the mark that Arrive sets.
func Arrived(r *http.Request) bool {
	v, _ := r.Context().Value(arrivedKey{}).(bool)
	return v
}

// Credential sets on r the bearer token of the identity named ref, unless r
// already carries an Authorization header.
func (a *Adapter) Credential(r *http.Request, ref string) error {
	for _, i := range a.st.Identities {
		if i.Ref != ref {
			continue
		}
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+i.Secret)
		}
		return nil
	}
	return fmt.Errorf("memory: no identity %q", ref)
}

// bearer returns the bearer token of r and whether r carries an Authorization
// header at all.
func bearer(r *http.Request) (token string, presented bool) {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return "", false
	}
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !ascii.EqualFold(scheme, "Bearer") {
		return "", true
	}
	return strings.TrimSpace(rest), true
}

// identityBySecret returns the identity that token authenticates. It compares
// against every identity so that the time taken does not depend on which one
// matches.
func (a *Adapter) identityBySecret(token string) (Identity, bool) {
	var found Identity
	ok := false
	for _, i := range a.st.Identities {
		if subtle.ConstantTimeCompare([]byte(i.Secret), []byte(token)) == 1 && token != "" {
			found, ok = i, true
		}
	}
	return found, ok
}

// sourceTime converts a Unix-seconds member of a source record to a time. An
// absent member is the zero time: the source gives none, and the adapter does
// not make one up.
func sourceTime(sec *int64) time.Time {
	if sec == nil {
		return time.Time{}
	}
	return time.Unix(*sec, 0)
}

// checkSourceTimes refuses times the adapter cannot pass on. No source
// observation or status-check time may be later than now plus the skew
// (draft A.2): such a time did not happen yet, and the source is not
// trustworthy at this moment, so the answer is that the dependency cannot be
// relied on, which defers the decision (freshness profile, section 3.2).
func (a *Adapter) checkSourceTimes(observed, checked time.Time) error {
	limit := a.clk.Now().Add(clock.BaselineSkew)
	if !observed.IsZero() && observed.After(limit) {
		return fmt.Errorf("memory: the source reports an observation later than now plus the skew: %w", adapter.ErrDependencyUnavailable)
	}
	if !checked.IsZero() && checked.After(limit) {
		return fmt.Errorf("memory: the source reports a status check later than now plus the skew: %w", adapter.ErrDependencyUnavailable)
	}
	return nil
}
