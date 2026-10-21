package contract

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ReplayStore keeps the nonces of issued contracts and consumes each at most
// once (draft 7.5). Replicas of a gateway share one store; consumption is
// atomic across them. A store that is full or cannot answer returns an error
// that wraps ErrDependencyUnavailable, never success. A record is kept at
// least until the latest until it was given, and never evicted earlier,
// under load or otherwise.
type ReplayStore interface {
	// Register records the nonce of a contract the publisher issued, not
	// yet consumed, and keeps it at least until until. A nonce the store
	// already holds is ErrReplay.
	Register(ctx context.Context, r NonceRecord, now, until time.Time) error
	// Consume atomically marks the registered nonce r.Nonce consumed and
	// keeps it at least until until. A nonce consumed before, or never
	// registered, is ErrReplay; a record that differs from the registered
	// one is ErrContextMismatch and consumes nothing.
	Consume(ctx context.Context, r NonceRecord, now, until time.Time) error
}

// MemoryReplay is a ReplayStore in the memory of one process. It is safe
// for concurrent use. A record whose retention bound has passed is removed
// when the store needs room.
type MemoryReplay struct {
	mu      sync.Mutex
	max     int
	records map[string]*replayEntry
}

type replayEntry struct {
	record   NonceRecord
	consumed bool
	until    time.Time
}

// NewMemoryReplay returns an empty store that holds at most max records; max
// zero or less is no bound.
func NewMemoryReplay(max int) *MemoryReplay {
	return &MemoryReplay{max: max, records: make(map[string]*replayEntry)}
}

// Register implements ReplayStore.
func (m *MemoryReplay) Register(ctx context.Context, r NonceRecord, now, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrDependencyUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evict(r.Nonce, now)
	if _, ok := m.records[r.Nonce]; ok {
		return fmt.Errorf("%w: nonce already registered", ErrReplay)
	}
	if m.max > 0 && len(m.records) >= m.max {
		m.sweep(now)
		if len(m.records) >= m.max {
			return fmt.Errorf("%w: replay store full", ErrDependencyUnavailable)
		}
	}
	m.records[r.Nonce] = &replayEntry{record: r, until: until}
	return nil
}

// Consume implements ReplayStore.
func (m *MemoryReplay) Consume(ctx context.Context, r NonceRecord, now, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrDependencyUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evict(r.Nonce, now)
	e, ok := m.records[r.Nonce]
	switch {
	case !ok:
		return fmt.Errorf("%w: nonce not issued or no longer retained", ErrReplay)
	case e.consumed:
		return fmt.Errorf("%w: nonce already consumed", ErrReplay)
	case e.record != r:
		return fmt.Errorf("%w: nonce bound to another agent, key, realm, operation or contract", ErrContextMismatch)
	}
	e.consumed = true
	if until.After(e.until) {
		e.until = until
	}
	return nil
}

// evict removes the record of nonce when its retention bound has passed.
func (m *MemoryReplay) evict(nonce string, now time.Time) {
	if e, ok := m.records[nonce]; ok && now.After(e.until) {
		delete(m.records, nonce)
	}
}

// sweep removes every record whose retention bound has passed.
func (m *MemoryReplay) sweep(now time.Time) {
	for n, e := range m.records {
		if now.After(e.until) {
			delete(m.records, n)
		}
	}
}
