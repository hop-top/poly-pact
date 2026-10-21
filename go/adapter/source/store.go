package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Fact is the last pushed state of one native path of one principal.
type Fact struct {
	// Value is the value as JSON data; it must encode with encoding/json.
	Value any
	// ObservedAt and StatusCheckedAt are the times the push gives for the
	// state, such as the event time of a security event. Both zero: the push
	// gives none, and the Reader reports the read time minus the declared
	// lag.
	ObservedAt      time.Time
	StatusCheckedAt time.Time
	// SourceRef is the source's own reference to the record, such as the
	// SCIM id the service provider issued; empty when none.
	SourceRef string
}

// Store holds the last pushed state, by principal and native path. An
// implementation is safe for concurrent use.
type Store interface {
	// Put replaces the fact at path for principal.
	Put(ctx context.Context, principal, path string, f Fact) error
	// Get returns the fact at path for principal; ok is false when the store
	// holds none. An error means the store cannot answer.
	Get(ctx context.Context, principal, path string) (f Fact, ok bool, err error)
	// Delete removes every fact of principal, as when the identity system
	// deletes its record. Deleting a principal with no fact is not an error.
	Delete(ctx context.Context, principal string) error
}

// ErrInvalidFact: a principal, a path or a value that a Store does not hold.
var ErrInvalidFact = errors.New("source: invalid fact")

// Memory is an in-memory [Store]. It holds each value as JSON data, so a
// caller that changes a value after Put, or a value Get returned, changes
// nothing in the store.
type Memory struct {
	mu    sync.Mutex
	facts map[string]map[string]stored
}

type stored struct {
	value                json.RawMessage
	observedAt, statusAt time.Time
	sourceRef            string
}

// NewMemory returns an empty Memory store.
func NewMemory() *Memory { return &Memory{facts: map[string]map[string]stored{}} }

// Put implements [Store]. The principal is not empty, the path is an
// absolute native path, and the value encodes as JSON.
func (m *Memory) Put(_ context.Context, principal, path string, f Fact) error {
	if principal == "" {
		return fmt.Errorf("%w: no principal", ErrInvalidFact)
	}
	if !validPath(path) {
		return fmt.Errorf("%w: %q is not a native path", ErrInvalidFact, path)
	}
	b, err := json.Marshal(f.Value)
	if err != nil {
		return fmt.Errorf("%w: the value at %q is not JSON data: %v", ErrInvalidFact, path, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.facts[principal] == nil {
		m.facts[principal] = map[string]stored{}
	}
	m.facts[principal][path] = stored{b, f.ObservedAt, f.StatusCheckedAt, f.SourceRef}
	return nil
}

// Get implements [Store].
func (m *Memory) Get(_ context.Context, principal, path string) (Fact, bool, error) {
	m.mu.Lock()
	s, ok := m.facts[principal][path]
	m.mu.Unlock()
	if !ok {
		return Fact{}, false, nil
	}
	var v any
	if err := json.Unmarshal(s.value, &v); err != nil {
		return Fact{}, false, err
	}
	return Fact{Value: v, ObservedAt: s.observedAt, StatusCheckedAt: s.statusAt, SourceRef: s.sourceRef}, true, nil
}

// Delete implements [Store].
func (m *Memory) Delete(_ context.Context, principal string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.facts, principal)
	return nil
}

// validPath reports whether p is a native path: "/" followed by non-empty
// segments.
func validPath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) < 2 {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" {
			return false
		}
	}
	return true
}
