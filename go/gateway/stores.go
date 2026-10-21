package gateway

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/validator"
)

// RequirementSource gives the effective requirements of a contract request
// (draft 9.1, 9.4): the base revision, the selected and conservative sets,
// the field rules and context checks the publisher binds. The gateway sets
// the mode from the route of the proposed operation.
type RequirementSource interface {
	Requirements(ctx context.Context, p adapter.Principal, req core.ContractRequest) (contract.Requirements, error)
}

// RequirementsFunc is a RequirementSource that is a function.
type RequirementsFunc func(ctx context.Context, p adapter.Principal, req core.ContractRequest) (contract.Requirements, error)

// Requirements calls f.
func (f RequirementsFunc) Requirements(ctx context.Context, p adapter.Principal, req core.ContractRequest) (contract.Requirements, error) {
	return f(ctx, p, req)
}

// ErrNotRecorded is the error of ContractRecords.Lookup for a contract that
// has no record, or whose record's retention has ended.
var ErrNotRecorded = errors.New("gateway: contract not recorded")

// ContractRecord is what the gateway records with a contract it issues.
type ContractRecord struct {
	// MappingVersion is the operation mapping version installed at issuance
	// (draft 10.2; request binding RB-42).
	MappingVersion string
	// OperationID is the operation_id the ContractRequest proposed. The
	// actual operation of a request presented under the contract carries it
	// in place of the one map_operation returns (draft 10.2).
	OperationID string
}

// ContractRecords keeps, for each contract the gateway issued, its
// ContractRecord, at least until the contract expires (request binding
// RB-42). Replicas share one store.
type ContractRecords interface {
	// Record records, at now, the record of the contract whose
	// requirements_digest is d, until the given time. It returns only once
	// the record is durable.
	Record(ctx context.Context, d core.Digest, rec ContractRecord, now, until time.Time) error
	// Lookup returns the record, ErrNotRecorded when there is none at now,
	// or another error when the store cannot answer.
	Lookup(ctx context.Context, d core.Digest, now time.Time) (ContractRecord, error)
}

// MemoryRecords is a ContractRecords for one process. It is safe for
// concurrent use.
type MemoryRecords struct {
	mu      sync.Mutex
	max     int
	records map[core.Digest]record
}

type record struct {
	rec   ContractRecord
	until time.Time
}

// NewMemoryRecords returns a store of at most max live records; a full
// store refuses a record with an error that wraps
// adapter.ErrDependencyUnavailable.
func NewMemoryRecords(max int) *MemoryRecords {
	return &MemoryRecords{max: max, records: map[core.Digest]record{}}
}

// Record implements ContractRecords. A contract is recorded once.
func (m *MemoryRecords) Record(_ context.Context, d core.Digest, rec ContractRecord, now, until time.Time) error {
	if d == "" || rec.MappingVersion == "" || rec.OperationID == "" {
		return errors.New("gateway: a record needs a contract digest, a mapping version and an operation_id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.records[d]; ok && now.Before(r.until) {
		return fmt.Errorf("gateway: contract %s is already recorded", d)
	}
	if len(m.records) >= m.max {
		m.sweep(now)
	}
	if len(m.records) >= m.max {
		return fmt.Errorf("gateway: contract record store is full: %w", adapter.ErrDependencyUnavailable)
	}
	m.records[d] = record{rec: rec, until: until}
	return nil
}

// sweep drops the records whose retention has ended at now.
func (m *MemoryRecords) sweep(now time.Time) {
	for d, r := range m.records {
		if !now.Before(r.until) {
			delete(m.records, d)
		}
	}
}

// Lookup implements ContractRecords.
func (m *MemoryRecords) Lookup(_ context.Context, d core.Digest, now time.Time) (ContractRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[d]
	if !ok || !now.Before(r.until) {
		return ContractRecord{}, ErrNotRecorded
	}
	return r.rec, nil
}

// MemoryHolds is a validator.HoldStore for one process: the security holds
// in force for each agent of a realm (draft 15.4, 18). It is safe for
// concurrent use.
type MemoryHolds struct {
	mu          sync.Mutex
	holds       map[holdKey][]string
	unavailable bool
}

type holdKey struct {
	realm adapter.Realm
	agent string
}

// NewMemoryHolds returns a store with no holds.
func NewMemoryHolds() *MemoryHolds { return &MemoryHolds{holds: map[holdKey][]string{}} }

// Set replaces the holds of an agent in a realm; none clears them.
func (m *MemoryHolds) Set(realm adapter.Realm, agentID string, holdIDs ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(holdIDs) == 0 {
		delete(m.holds, holdKey{realm, agentID})
		return
	}
	m.holds[holdKey{realm, agentID}] = slices.Clone(holdIDs)
}

// SetUnavailable makes the store unable to answer, or able again.
func (m *MemoryHolds) SetUnavailable(down bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unavailable = down
}

// Holds implements validator.HoldStore.
func (m *MemoryHolds) Holds(_ context.Context, realm adapter.Realm, agentID string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable {
		return nil, fmt.Errorf("gateway: hold store: %w", adapter.ErrDependencyUnavailable)
	}
	return slices.Clone(m.holds[holdKey{realm, agentID}]), nil
}

// StaticPolicy is a validator.PolicyRegistry that answers with a fixed active
// policy and selection (draft 9.4): a gateway whose policy changes only with
// its configuration.
type StaticPolicy struct {
	ActivePolicy validator.ActivePolicy
	Selected     validator.Selection
}

// Active implements validator.PolicyRegistry.
func (s StaticPolicy) Active(context.Context) (validator.ActivePolicy, error) {
	return s.ActivePolicy, nil
}

// Selection implements validator.PolicyRegistry.
func (s StaticPolicy) Selection(context.Context, contract.Contract) (validator.Selection, error) {
	return s.Selected, nil
}

// MemoryStatus is a validator.StatusChecker for one process: the status of
// each evidence artifact by issuer and status reference (draft 8.3). An
// artifact it holds no status for has unknown status, which is an error,
// never validity. It is safe for concurrent use.
type MemoryStatus struct {
	mu       sync.Mutex
	statuses map[[2]string]validator.EvidenceStatus
}

// NewMemoryStatus returns a store that holds no status.
func NewMemoryStatus() *MemoryStatus {
	return &MemoryStatus{statuses: map[[2]string]validator.EvidenceStatus{}}
}

// Set records the status of one artifact.
func (m *MemoryStatus) Set(issuer, statusRef string, s validator.EvidenceStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses[[2]string{issuer, statusRef}] = s
}

// EvidenceStatus implements validator.StatusChecker.
func (m *MemoryStatus) EvidenceStatus(_ context.Context, issuer, statusRef string) (validator.EvidenceStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.statuses[[2]string{issuer, statusRef}]
	if !ok {
		return validator.EvidenceStatus{}, fmt.Errorf("gateway: no status for the artifact: %w", adapter.ErrDependencyUnavailable)
	}
	return s, nil
}
