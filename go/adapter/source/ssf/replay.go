package ssf

import (
	"context"
	"sync"
	"time"

	"hop.top/pact-go/core/clock"
)

// ReplayStore remembers the SETs the receiver applied, by issuer and jti: a
// jti is unique within a transmitter's feed (RFC 8417 section 2.2). An
// implementation is safe for concurrent use.
type ReplayStore interface {
	// Lookup returns the digest recorded for the jti of the issuer, and false
	// when none is recorded or the record expired.
	Lookup(ctx context.Context, issuer, jti string) (digest string, ok bool, err error)
	// Record remembers digest for the jti until the given time. Recording
	// the same jti again replaces the record.
	Record(ctx context.Context, issuer, jti, digest string, until time.Time) error
}

// ReplayMemory is an in-memory [ReplayStore]. A restart forgets its records;
// a deployment that cannot tolerate that supplies a durable store.
type ReplayMemory struct {
	clock clock.Clock

	mu    sync.Mutex
	seen  map[[2]string]replayEntry
	prune time.Time
}

type replayEntry struct {
	digest string
	until  time.Time
}

// NewReplayMemory returns an empty ReplayMemory that expires records by clk.
func NewReplayMemory(clk clock.Clock) *ReplayMemory {
	return &ReplayMemory{clock: clk, seen: map[[2]string]replayEntry{}}
}

// Lookup implements [ReplayStore].
func (m *ReplayMemory) Lookup(_ context.Context, issuer, jti string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.seen[[2]string{issuer, jti}]
	if !ok || !e.until.After(m.clock.Now()) {
		return "", false, nil
	}
	return e.digest, true, nil
}

// Record implements [ReplayStore].
func (m *ReplayMemory) Record(_ context.Context, issuer, jti, digest string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	if !now.Before(m.prune) {
		for k, e := range m.seen {
			if !e.until.After(now) {
				delete(m.seen, k)
			}
		}
		m.prune = now.Add(time.Minute)
	}
	m.seen[[2]string{issuer, jti}] = replayEntry{digest, until}
	return nil
}
