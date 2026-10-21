package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// PolicySourceID is the source a decision names when the rule that decided
// names no source of its own, and when no rule applies: the adapter's own
// policy store.
const PolicySourceID = "memory-policy"

// ReadNativeClaim reads the value at nativePath in the context cc.
//
// Only a path in the approved list is readable. The record is looked up by
// realm, principal and path together, so a same-spelled principal of another
// realm has its own value. A record that names a resource is read only when
// cc.Operation lists that resource, and a record that names a task only when
// cc.Intent carries that task; nothing else in cc selects a record.
// ObservedAt and StatusCheckedAt are what the source recorded and nothing
// else: a source that gives no time yields the zero time, and the time of the
// read is never substituted.
func (a *Adapter) ReadNativeClaim(ctx context.Context, nativePath string, cc adapter.ClaimContext) (adapter.NativeClaim, error) {
	if err := a.live(ctx, "read claim"); err != nil {
		return adapter.NativeClaim{}, err
	}
	if !slices.Contains(a.st.ApprovedPaths, nativePath) {
		return adapter.NativeClaim{}, fmt.Errorf("memory: %q is not an approved native path: %w", nativePath, adapter.ErrUnsupportedRequirement)
	}
	for _, c := range a.st.Claims {
		if !c.Applies(nativePath, cc) {
			continue
		}
		if a.unavailable(c.SourceID) {
			return adapter.NativeClaim{}, outage("read claim", c.SourceID)
		}
		observed, checked := sourceTime(c.ObservedAt), sourceTime(c.StatusCheckedAt)
		if err := a.checkSourceTimes(observed, checked); err != nil {
			return adapter.NativeClaim{}, err
		}
		var v any
		if err := json.Unmarshal(c.Value, &v); err != nil {
			return adapter.NativeClaim{}, fmt.Errorf("memory: the value at %q is not JSON: %w", nativePath, adapter.ErrDependencyUnavailable)
		}
		return adapter.NativeClaim{
			Value:           v,
			ObservedAt:      observed,
			StatusCheckedAt: checked,
			SourceID:        c.SourceID,
			SourceRef:       c.SourceRef,
		}, nil
	}
	return adapter.NativeClaim{}, fmt.Errorf("memory: the source holds no value at %q in this context", nativePath)
}

// Applies reports whether the record is the check's native state in the call
// in: its principal, when it names one, is the authenticated principal of in,
// and its agent, when it names one, is the agent of in's binding. A call with
// no binding has no agent, so it never matches a record that names one.
func (c CheckRecord) Applies(in adapter.CheckInput) bool {
	switch {
	case c.Principal != "" && c.Principal != in.Principal.ID,
		c.AgentID != "" && c.AgentID != in.Binding.AgentID:
		return false
	}
	return true
}

// Applies reports whether the record is the value at nativePath in the context
// cc: the path, the principal and its realm are those of cc, and the resource
// and the task, when the record names them, are those of the operation and the
// intent of cc.
func (c ClaimRecord) Applies(nativePath string, cc adapter.ClaimContext) bool {
	p := cc.Principal
	switch {
	case c.Path != nativePath, c.Principal != p.ID,
		c.Realm.TenantID != p.Realm.TenantID, c.Realm.EnvironmentID != p.Realm.EnvironmentID:
		return false
	case c.Resource != "" && !slices.Contains(cc.Operation.Resources, c.Resource):
		return false
	case c.TaskID != "" && c.TaskID != cc.Intent.TaskID:
		return false
	}
	return true
}

// CheckContext runs the installed check whose id equals checkID exactly.
//
// A check that is not installed is UNKNOWN with UNSUPPORTED_REQUIREMENT: the
// adapter did not perform it, so it cannot report that it passed (draft 17.2).
// There is no prefix, case-insensitive or empty-id match. An installed check
// is the record of that id that applies to the principal and the agent
// binding of in ([CheckRecord.Applies]); when the check is installed and no
// record of it applies, it is FAIL with [CodeApprovalScopeMismatch], never
// PASS, and the outcome names the source without the record's reference
// (draft 17.1, 17.3.1). The record reports the verdict of its native state
// unless a finding of the source's availability, the record's freshness or
// the pinned revision comes first; see runCheck.
func (a *Adapter) CheckContext(ctx context.Context, checkID string, in adapter.CheckInput) adapter.CheckOutcome {
	if err := a.live(ctx, "check context"); err != nil {
		return adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: string(adapter.CodeDependencyUnavailable)}
	}
	var other *CheckRecord
	for i := range a.st.Checks {
		c := &a.st.Checks[i]
		if c.ID != checkID {
			continue
		}
		if c.Applies(in) {
			return a.runCheck(*c)
		}
		if other == nil {
			other = c
		}
	}
	if other != nil {
		return adapter.CheckOutcome{Result: adapter.VerdictFail, ReasonCode: CodeApprovalScopeMismatch, SourceID: other.SourceID}
	}
	return adapter.CheckOutcome{
		Result:     adapter.VerdictUnknown,
		ReasonCode: string(adapter.CodeUnsupportedRequirement),
	}
}

// AuthorizeNative evaluates the native policy for p and the operation, and
// returns the decision as the policy states it.
//
// The rules that name p, in p's realm, and the operation's action (and its
// resource, when the rule names one) apply. A deny wins over an unknown, and
// an unknown over an allow. When no rule applies the decision is a deny, so an
// absent rule is never an allow. The adapter evaluates p and no other
// principal, and it runs no downstream operation.
//
// The decision carries the provenance of the rule that decided as the rule
// gives it: its source, or [PolicySourceID] when it names none, its record,
// its decision time and its policy revision. The deny of no rule comes from
// [PolicySourceID] and has no record, time or revision. A decision time later
// than now plus the skew did not happen yet, so the decision is not passed on
// and the error wraps [adapter.ErrDependencyUnavailable].
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	if err := a.live(ctx, "authorize"); err != nil {
		return adapter.Decision{}, err
	}
	var allow, unknown, deny *PolicyRule
	for i := range a.st.Policy {
		r := &a.st.Policy[i]
		if r.Principal != p.ID || r.Realm.TenantID != p.Realm.TenantID || r.Realm.EnvironmentID != p.Realm.EnvironmentID ||
			r.Action != op.Action || (r.Resource != "" && !slices.Contains(op.Resources, r.Resource)) {
			continue
		}
		switch adapter.Effect(r.Effect) {
		case adapter.EffectDeny:
			if deny == nil {
				deny = r
			}
		case adapter.EffectUnknown:
			if unknown == nil {
				unknown = r
			}
		case adapter.EffectAllow:
			if allow == nil {
				allow = r
			}
		}
	}
	decided := deny
	if decided == nil {
		decided = unknown
	}
	if decided == nil {
		decided = allow
	}
	if decided == nil {
		return adapter.Decision{
			Effect:   adapter.EffectDeny,
			Reason:   "no rule of the policy allows this principal",
			SourceID: PolicySourceID,
		}, nil
	}
	d := decisionOf(decided)
	if !d.DecidedAt.IsZero() && d.DecidedAt.After(a.clk.Now().Add(clock.BaselineSkew)) {
		return adapter.Decision{}, fmt.Errorf("memory: the policy source reports a decision after now: %w", adapter.ErrDependencyUnavailable)
	}
	return d, nil
}

func decisionOf(r *PolicyRule) adapter.Decision {
	d := adapter.Decision{
		Effect:         adapter.Effect(r.Effect),
		Reason:         r.Reason,
		SourceID:       r.SourceID,
		SourceRef:      r.SourceRef,
		DecidedAt:      sourceTime(r.DecidedAt),
		PolicyRevision: r.PolicyRevision,
	}
	if d.SourceID == "" {
		d.SourceID = PolicySourceID
	}
	for _, o := range r.Obligations {
		d.Obligations = append(d.Obligations, adapter.Obligation{ID: o.ID, Attributes: o.Attributes})
	}
	return d
}
