package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/validator"
)

// replayStore is the gateway's replay store: a contract.MemoryReplay in
// which the publisher registered the nonce of each contract it issued,
// answering as availability.replay_store says, and able to evict the records
// whose retention has passed, as a store under load may (draft 7.5).
type replayStore struct {
	mu    sync.Mutex
	inner *contract.MemoryReplay
	mode  string
	recs  map[string]*replayRecord
}

type replayRecord struct {
	rec      contract.NonceRecord
	issued   time.Time
	until    time.Time
	consumed bool
}

func newReplayStore() *replayStore {
	return &replayStore{inner: contract.NewMemoryReplay(0), mode: "available", recs: map[string]*replayRecord{}}
}

func (s *replayStore) setMode(m string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m == "" {
		m = "available"
	}
	s.mode = m
}

// register records the nonce of a contract the gateway's publisher issued,
// until the later of its exp and iat + 65 s (draft 7.5, baseline skew).
func (s *replayStore) register(c contract.Contract) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[c.Claims.Nonce]; ok {
		return
	}
	issued := time.Unix(c.Claims.IssuedAt, 0)
	until := clock.ReplayRetention(c.Claims.Expiry, c.Claims.IssuedAt, clock.BaselineSkew)
	r := &replayRecord{rec: c.NonceRecord(), issued: issued, until: until}
	if s.inner.Register(context.Background(), r.rec, issued, until) == nil {
		s.recs[c.Claims.Nonce] = r
	}
}

// Consume implements contract.ReplayStore.
func (s *replayStore) Consume(ctx context.Context, r contract.NonceRecord, now, until time.Time) error {
	s.mu.Lock()
	mode := s.mode
	s.mu.Unlock()
	if mode != "available" {
		return fmt.Errorf("replay store %s: %w", mode, contract.ErrDependencyUnavailable)
	}
	err := s.inner.Consume(ctx, r, now, until)
	if err == nil {
		s.mu.Lock()
		if rec, ok := s.recs[r.Nonce]; ok {
			rec.consumed = true
			if until.After(rec.until) {
				rec.until = until
			}
		}
		s.mu.Unlock()
	}
	return err
}

// Register implements contract.ReplayStore.
func (s *replayStore) Register(ctx context.Context, r contract.NonceRecord, now, until time.Time) error {
	return s.inner.Register(ctx, r, now, until)
}

// evict drops every record whose retention bound has passed at now.
func (s *replayStore) evict(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fresh := contract.NewMemoryReplay(0)
	for nonce, r := range s.recs {
		if !r.until.After(now) {
			delete(s.recs, nonce)
			continue
		}
		_ = fresh.Register(context.Background(), r.rec, r.issued, r.until)
		if r.consumed {
			_ = fresh.Consume(context.Background(), r.rec, r.issued, r.until)
		}
	}
	s.inner = fresh
}

// holdStore is native_context.json's security_holds.
type holdStore []string

func (h holdStore) Holds(context.Context, adapter.Realm, string) ([]string, error) {
	return slices.Clone(h), nil
}

// statusChecker is native_context.json's evidence_status; a status
// reference listed in availability.sources cannot be checked.
type statusChecker struct {
	states      map[string]evalcase.EvidenceStatus
	unavailable []string
}

func (s statusChecker) EvidenceStatus(_ context.Context, _, ref string) (validator.EvidenceStatus, error) {
	st, ok := s.states[ref]
	switch {
	case slices.Contains(s.unavailable, ref):
		return validator.EvidenceStatus{}, fmt.Errorf("status source of %q: %w", ref, adapter.ErrDependencyUnavailable)
	case !ok:
		return validator.EvidenceStatus{}, fmt.Errorf("no status for %q: %w", ref, adapter.ErrDependencyUnavailable)
	case st.Status == "valid":
		return validator.EvidenceStatus{CheckedAt: time.Unix(st.CheckedAt, 0), SourceID: "fixture:evidence-status"}, nil
	case st.Status == "revoked":
		return validator.EvidenceStatus{Revoked: true, CheckedAt: time.Unix(st.CheckedAt, 0), SourceID: "fixture:evidence-status"}, nil
	}
	return validator.EvidenceStatus{}, fmt.Errorf("status %q of %q: %w", st.Status, ref, adapter.ErrDependencyUnavailable)
}

// defaultSelectionRecord is the selection record of the Appendix B exchange
// (B.7), the record of a case whose config.json names no selection.
const defaultSelectionRecord = "configured-selection-record:example-selection"

// registry is config.json's active_policy and selection.
type registry struct {
	active  validator.ActivePolicy
	sel     *evalcase.Selection
	current *core.ReputationValue
}

func newRegistry(fixtures string, x *evalcase.Exchange) (*registry, error) {
	ap := x.Config.ActivePolicy
	r := &registry{sel: x.Config.Selection, active: validator.ActivePolicy{
		Policy: contract.Policy{
			BaseRevision: ap.BaseRevision, LearningPolicyDigest: core.Digest(ap.LearningPolicyDigest),
			LearningArtifactDigest: core.Digest(ap.LearningArtifactDigest),
		},
		ConservativeSet:        ap.SelectedSet,
		ScoringPolicyRevisions: ap.AcceptedScoringRevisions(),
	}}
	if s := r.sel; s != nil {
		if len(s.Selector.Order) > 0 {
			r.active.ConservativeSet = s.Selector.Order[0]
		}
		if s.CurrentSnapshot != nil {
			b, err := readCase(fixtures, x, *s.CurrentSnapshot)
			if err != nil {
				return nil, err
			}
			var snap core.ReputationSnapshot
			if err := json.Unmarshal(b, &snap); err != nil {
				return nil, fmt.Errorf("%s: %w", *s.CurrentSnapshot, err)
			}
			r.current = &snap.Value
		}
	}
	return r, nil
}

func (r *registry) Active(context.Context) (validator.ActivePolicy, error) { return r.active, nil }

func (r *registry) Selection(_ context.Context, c contract.Contract) (validator.Selection, error) {
	if r.sel == nil {
		return validator.Selection{RecordRef: defaultSelectionRecord}, nil
	}
	out := validator.Selection{RecordRef: r.sel.Record.RecordRef, Current: r.current}
	if string(c.Claims.LearningArtifactDigest) == r.sel.Selector.LearningArtifactDigest {
		out.Selector = selector{s: r.sel.Selector, contractChecks: c.Claims.ContextChecks}
	}
	return out, nil
}

// selector is config.json's selection.selector: the last set of order whose
// threshold the snapshot meets, and the conservative set when it meets none,
// when there is no snapshot or when a hold is in force. contractChecks are
// the context_checks of the contract it was looked up for.
type selector struct {
	s              evalcase.Selector
	contractChecks []string
}

func (s selector) Order() []string { return slices.Clone(s.s.Order) }

func (s selector) Rules(set string) ([]core.FieldRule, bool) {
	r, ok := s.s.Sets[set]
	return r, ok
}

// Checks is selection.selector's checks for the set, or the contract's own
// context_checks for a set it does not list.
func (s selector) Checks(set string) ([]string, bool) {
	if c, ok := s.s.Checks[set]; ok {
		return slices.Clone(c), true
	}
	return slices.Clone(s.contractChecks), true
}

func (s selector) Select(in validator.SelectionInput) (string, error) {
	if len(s.s.Order) == 0 {
		return "", fmt.Errorf("selector has no sets")
	}
	chosen := s.s.Order[0]
	if in.Snapshot == nil || len(in.Holds) > 0 {
		return chosen, nil
	}
	for _, set := range s.s.Order[1:] {
		t, ok := s.s.Thresholds[set]
		if ok && meets(*in.Snapshot, t) {
			chosen = set
		}
	}
	return chosen, nil
}

func meets(v core.ReputationValue, t evalcase.Threshold) bool {
	if t.SecurityStatus != "" && string(v.SecurityStatus) != t.SecurityStatus {
		return false
	}
	dims := map[string]core.DimensionStats{
		"reliability": v.Dimensions.Reliability, "task_quality": v.Dimensions.TaskQuality, "policy_adherence": v.Dimensions.PolicyAdherence,
	}
	for name, m := range t.Dimensions {
		d, ok := dims[name]
		if !ok || d.ScoreBPS < m.ScoreBps || d.ConfidenceBPS < m.ConfidenceBps || d.IndependentTasks < m.IndependentTasks {
			return false
		}
	}
	return true
}

// contextMapper is config.json's reputation_context (B.6 by default): the
// action class is the operation's action, a resource has the class of the
// first entry whose prefix it starts with, and every resource of the
// operation must have the same class; the runtime class is the gateway's.
type contextMapper struct {
	realm adapter.Realm
	m     evalcase.ReputationContext
}

func (m contextMapper) ReputationContext(_ context.Context, in adapter.CheckInput) (core.ReputationContext, error) {
	op := in.Operation
	if len(op.Resources) == 0 || in.Binding.AgentID == "" {
		return core.ReputationContext{}, fmt.Errorf("no context: %w", adapter.ErrUnsupportedRequirement)
	}
	class := ""
	for _, r := range op.Resources {
		c, ok := m.classOf(r)
		switch {
		case !ok:
			return core.ReputationContext{}, fmt.Errorf("resource %q has no mapped class: %w", r, adapter.ErrUnsupportedRequirement)
		case class != "" && c != class:
			return core.ReputationContext{}, fmt.Errorf("resources of classes %q and %q: %w", class, c, adapter.ErrUnsupportedRequirement)
		}
		class = c
	}
	return core.ReputationContext{
		TenantID: m.realm.TenantID, EnvironmentID: m.realm.EnvironmentID, AgentID: in.Binding.AgentID,
		PurposeID: in.Intent.PurposeID, ActionClass: op.Action, ResourceClass: class,
		RuntimeClass: m.m.RuntimeClass,
	}, nil
}

func (m contextMapper) classOf(resource string) (string, bool) {
	for _, rc := range m.m.ResourceClasses {
		if strings.HasPrefix(resource, rc.Prefix) {
			return rc.Class, true
		}
	}
	return "", false
}
