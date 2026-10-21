package source

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/core/clock"
)

// Config configures a [Reader].
type Config struct {
	// Store is the pushed state the reader answers from.
	Store Store
	// SourceID identifies the configured source in every claim.
	SourceID string
	// Paths are the approved native paths the source serves (draft 17.2).
	Paths []string
	// Lag is the declared push lag: the longest time the pushed state can
	// trail the identity system, such as one provisioning cycle. The
	// integration profile declares it as best_status_max_age_seconds.
	Lag time.Duration
	// Clock is the reader's only source of the current time.
	Clock clock.Clock
}

// Reader is the [adapter.ClaimReader] of a pushed store.
type Reader struct {
	c Config
}

// NewReader returns a Reader for c: a store, a source ID, at least one
// native path, a lag that is not negative and a clock.
func NewReader(c Config) (*Reader, error) {
	switch {
	case c.Store == nil:
		return nil, errors.New("source: no store")
	case c.SourceID == "":
		return nil, errors.New("source: no source ID")
	case len(c.Paths) == 0:
		return nil, errors.New("source: no native path")
	case c.Lag < 0:
		return nil, errors.New("source: negative lag")
	case c.Clock == nil:
		return nil, errors.New("source: no clock")
	}
	for _, p := range c.Paths {
		if !validPath(p) {
			return nil, fmt.Errorf("source: %q is not a native path", p)
		}
	}
	c.Paths = slices.Clone(c.Paths)
	return &Reader{c: c}, nil
}

// ReadNativeClaim implements [adapter.ClaimReader] for the facts of the
// principal of cc. It reports the as-of time of the state: the fact's own
// times when the push gave them, otherwise the read time minus the declared
// lag for both (package documentation, Times).
func (r *Reader) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := installed.Live(ctx); err != nil {
		return adapter.NativeClaim{}, err
	}
	if !slices.Contains(r.c.Paths, nativePath) {
		return adapter.NativeClaim{}, fmt.Errorf("source %s: %q is not a path it serves: %w", r.c.SourceID, nativePath, adapter.ErrUnsupportedRequirement)
	}
	principal := cc.Principal.ID
	if principal == "" {
		return adapter.NativeClaim{}, fmt.Errorf("source %s: no principal: %w", r.c.SourceID, adapter.ErrMissingField)
	}
	f, ok, err := r.c.Store.Get(ctx, principal, nativePath)
	if err != nil {
		return adapter.NativeClaim{}, installed.Dependency(fmt.Errorf("source %s: %w", r.c.SourceID, err))
	}
	if !ok {
		return adapter.NativeClaim{}, fmt.Errorf("source %s: no value at %q for the principal: %w", r.c.SourceID, nativePath, adapter.ErrMissingField)
	}
	now := r.c.Clock.Now()
	observed, checked := f.ObservedAt, f.StatusCheckedAt
	if observed.IsZero() && checked.IsZero() {
		asOf := now.Add(-r.c.Lag)
		observed, checked = asOf, asOf
	}
	if err := installed.SourceTimes(now, observed, checked); err != nil {
		return adapter.NativeClaim{}, fmt.Errorf("source %s: %w", r.c.SourceID, err)
	}
	return adapter.NativeClaim{
		Value:           f.Value,
		ObservedAt:      observed,
		StatusCheckedAt: checked,
		SourceID:        r.c.SourceID,
		SourceRef:       f.SourceRef,
	}, nil
}
