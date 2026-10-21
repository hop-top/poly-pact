package reputation

import (
	"errors"
	"sync"

	"hop.top/pact-go/core"
)

// ErrConflict is returned by Store.Append when the report's (iss, jti) or
// event_id is already stored, or the tuple it takes is already taken.
var ErrConflict = errors.New("reputation: stored report conflicts")

// Tuple is the deduplication tuple of Section 14.6 rule 4.
type Tuple struct {
	TaskID      string
	OperationID string
	EventKind   core.EventKind
	Dimension   core.Dimension
	Reporter    string
}

// TupleOf returns the deduplication tuple of a report; the reporter is its
// signer.
func TupleOf(r core.OutcomeReport) Tuple {
	return Tuple{TaskID: r.TaskID, OperationID: r.OperationID, EventKind: r.EventKind, Dimension: r.Dimension, Reporter: r.Issuer}
}

// Stored is an accepted report as the service keeps it: the verified
// payload and its object_digest, the service time it arrived, whether a
// trust record registers its signer for its reporter_role, and whether it
// repeats the tuple of an earlier registered report.
type Stored struct {
	Report        core.OutcomeReport
	PayloadDigest core.Digest
	ReceivedAt    int64
	Registered    bool
	Duplicate     bool
}

// Store is the durable state of the service: every accepted report, with
// the indexes of the Section 7.5 and 14.6 rule 4 deduplication. Its indexes
// must cover at least the ingestion window and any longer period needed to
// recompute retained reputation (Section 14.3).
type Store interface {
	// ByKey returns the report stored under (iss, jti).
	ByKey(iss, jti string) (Stored, bool, error)
	// TupleTaken reports whether a registered report took the tuple.
	TupleTaken(t Tuple) (bool, error)
	// Append stores s after the reports stored before, and, when takeTuple
	// is set, takes its tuple. It is atomic: it fails with ErrConflict and
	// stores nothing when the (iss, jti) or event_id is stored or the tuple
	// is taken.
	Append(s Stored, takeTuple bool) error
	// All returns every stored report in the order they were appended.
	All() ([]Stored, error)
}

// MemoryStore is a Store in memory, for tests and single-process
// deployments. Its zero value is ready to use and it is safe for
// concurrent use.
type MemoryStore struct {
	mu      sync.Mutex
	reports []Stored
	keys    map[[2]string]int
	events  map[string]int
	tuples  map[Tuple]bool
}

func (m *MemoryStore) init() {
	if m.keys == nil {
		m.keys, m.events, m.tuples = map[[2]string]int{}, map[string]int{}, map[Tuple]bool{}
	}
}

// ByKey implements Store.
func (m *MemoryStore) ByKey(iss, jti string) (Stored, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	i, ok := m.keys[[2]string{iss, jti}]
	if !ok {
		return Stored{}, false, nil
	}
	return m.reports[i], true, nil
}

// TupleTaken implements Store.
func (m *MemoryStore) TupleTaken(t Tuple) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	return m.tuples[t], nil
}

// Append implements Store.
func (m *MemoryStore) Append(s Stored, takeTuple bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	key := [2]string{s.Report.Issuer, s.Report.JTI}
	t := TupleOf(s.Report)
	if _, ok := m.keys[key]; ok {
		return ErrConflict
	}
	if _, ok := m.events[s.Report.EventID]; ok {
		return ErrConflict
	}
	if takeTuple && m.tuples[t] {
		return ErrConflict
	}
	m.reports = append(m.reports, s)
	m.keys[key] = len(m.reports) - 1
	m.events[s.Report.EventID] = len(m.reports) - 1
	if takeTuple {
		m.tuples[t] = true
	}
	return nil
}

// All implements Store.
func (m *MemoryStore) All() ([]Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Stored(nil), m.reports...), nil
}
