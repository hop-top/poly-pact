package task

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// errNoOperation: the entry holds no operation record of that id.
var errNoOperation = errors.New("task: the entry holds no such operation record")

// lookup returns the entry of k and its record id; the caller holds m.mu.
func (m *Memory) lookup(k Key, id string) (*entry, *record, error) {
	e := m.entries[k]
	if e == nil {
		return nil, nil, ErrNoEntry
	}
	r := e.byID[id]
	if r == nil {
		return nil, nil, errNoOperation
	}
	return e, r, nil
}

// Record implements [TaskLedger.Record]. A request that provably was not
// sent is Released and its counters are restored (MO-22); no response is
// Unknown (MO-35); 201 and 202 are Accepted (MO-41); another success is
// Succeeded, and its response bytes are released only within max_bytes
// (MO-21, MO-59); a status the route lists as definitive is Failed (MO-37);
// every other status is Unknown (MO-35).
func (m *Memory) Record(_ context.Context, res Reservation, out Result) (Settled, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, r, err := m.lookup(res.Key, res.Operation.ID)
	if err != nil {
		return Settled{}, err
	}
	if r.op.State != OpReserved {
		return Settled{Operation: r.op}, fmt.Errorf("task: the operation %s is %s, not Reserved", r.op.ID, r.op.State)
	}
	if out.Bytes < 0 {
		return Settled{}, fmt.Errorf("task: negative response length: %w", adapter.ErrInvalidMessage)
	}
	r.op.NativeRef = out.NativeRef
	switch {
	case !out.Sent:
		r.op.State = OpReleased
		e.budget.Operations--
		if r.route.Page {
			e.budget.Pages--
		}
		e.budget.Bytes -= r.bodyLen
		return Settled{Operation: r.op}, nil
	case out.Status == 0:
		r.op.State = OpUnknown
		return Settled{Operation: r.op, Report: m.report(e, r, core.EventExecution, core.OutcomeUnknown, core.DimensionNone, "")}, nil
	case out.Status == 201 || out.Status == 202:
		r.op.State, r.op.Handle, r.op.RetryAfter = OpAccepted, out.Handle, out.RetryAfter
		return Settled{Operation: r.op, Report: m.report(e, r, core.EventExecution, core.OutcomeUnknown, core.DimensionNone, "")}, nil
	case out.Status >= 200 && out.Status < 300:
		r.op.State = OpSucceeded
		if past(e.budget.Limits.MaxBytes, e.budget.Bytes, out.Bytes) {
			// Not released; the reservation stays counted (MO-21) and the
			// continuation is not recorded (MO-59).
			return Settled{Operation: r.op}, refuse(LabelBudgetExhausted)
		}
		e.budget.Bytes += out.Bytes
		st := Settled{Operation: r.op}
		details := ""
		if out.Bytes == 0 && r.route.Class == ClassRead {
			details = "empty"
		}
		st.Report = m.report(e, r, core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, details)
		if out.NextLink != "" && m.cfg.Pager != nil && m.cfg.Pager.CheckNext(out.NextLink) == nil {
			tok, err := randomToken()
			if err != nil {
				return st, fmt.Errorf("task: no page token: %w", adapter.ErrDependencyUnavailable)
			}
			m.conts[tok] = continuation{key: e.key, binding: e.binding, route: r.route.ID, version: r.route.Version}
			st.PageToken = tok
		}
		return st, nil
	case slices.Contains(r.route.Definitive, out.Status):
		r.op.State = OpFailed
		return Settled{Operation: r.op, Report: m.report(e, r, core.EventAuthorization, core.OutcomeFailure, core.DimensionNone, "")}, nil
	}
	r.op.State = OpUnknown
	return Settled{Operation: r.op, Report: m.report(e, r, core.EventExecution, core.OutcomeUnknown, core.DimensionNone, "")}, nil
}

// Observe implements [TaskLedger.Observe]. For an Accepted record the read
// is completion tracking (MO-44): applied is Succeeded, none Failed,
// cancelled Failed under the cancelled-completion row of draft Section 14.5,
// and running or indeterminate leave it Accepted. For an Unknown record the
// read is reconciliation (MO-38): applied is Succeeded, a running operation
// with a handle Accepted, no effect from an authoritative read Failed, and
// anything else leaves it Unknown. A terminal record does not change. The
// task state and the deadline do not stop a read (MO-38, MO-50).
func (m *Memory) Observe(_ context.Context, k Key, opID string, s Status) (Settled, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, r, err := m.lookup(k, opID)
	if err != nil {
		return Settled{}, err
	}
	r.op.RetryAfter = s.RetryAfter
	switch r.op.State {
	case OpAccepted:
		switch s.Effect {
		case EffectApplied:
			r.op.State = OpSucceeded
			return Settled{Operation: r.op, Report: m.report(e, r, core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, "")}, nil
		case EffectNone:
			r.op.State = OpFailed
			return Settled{Operation: r.op, Report: m.report(e, r, core.EventExecution, core.OutcomeFailure, core.DimensionReliability, "")}, nil
		case EffectCancelled:
			r.op.State = OpFailed
			return Settled{Operation: r.op, Report: m.report(e, r, core.EventExecution, core.OutcomeFailure, core.DimensionReliability, "cancelled")}, nil
		}
	case OpUnknown:
		switch {
		case s.Effect == EffectApplied:
			r.op.State = OpSucceeded
			return Settled{Operation: r.op, Report: m.report(e, r, core.EventExecution, core.OutcomeSuccess, core.DimensionReliability, "")}, nil
		case s.Effect == EffectRunning && s.Handle != "":
			r.op.State, r.op.Handle = OpAccepted, s.Handle
			return Settled{Operation: r.op, Report: m.report(e, r, core.EventExecution, core.OutcomeUnknown, core.DimensionNone, "")}, nil
		case s.Authoritative && (s.Effect == EffectNone || s.Effect == EffectCancelled):
			r.op.State, r.reconciled = OpFailed, true
		}
	case OpReserved:
		return Settled{Operation: r.op}, fmt.Errorf("task: the operation %s has no recorded attempt", r.op.ID)
	}
	return Settled{Operation: r.op}, nil
}

// report is the observation of an event of the record, under the draft
// Section 14.5 row of profile section 11. Its task_id is the native task
// reference (MO-5), its independence group the task (draft Section 14.6
// rule 3), and every report has its own event_id. The caller holds m.mu.
func (m *Memory) report(e *entry, r *record, kind core.EventKind, result core.OutcomeResult, dim core.Dimension, details string) *adapter.Observation {
	m.seq++
	ref := string(e.key.Task)
	id, err := randomID()
	if err != nil {
		id = fmt.Sprintf("%s#%s#event-%d", ref, r.op.ID, m.seq)
	}
	o := &adapter.Observation{
		EventID:   id,
		EventKind: kind,
		Context: core.ReputationContext{
			TenantID: e.key.Realm.TenantID, EnvironmentID: e.key.Realm.EnvironmentID, AgentID: string(r.agent),
		},
		TaskID:      ref,
		OperationID: r.op.OperationID,
		ObservedAt:  m.cfg.Clock.Now(),
		Result:      result,
		Dimension:   dim,
		Severity:    core.SeverityInfo,
		Attribution: core.Attribution{NativeTaskRef: ref, IndependenceGroup: ref, CausalAssessment: core.CausalUnknown},
		Details:     details,
	}
	if r.op.NativeRef != "" {
		o.EvidenceRefs = []string{r.op.NativeRef}
	}
	return o
}
