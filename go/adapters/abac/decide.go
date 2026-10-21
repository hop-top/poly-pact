package abac

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// The fixed reasons of the decisions the adapter states. A reason never
// carries policy text (profile section 17).
const (
	reasonNotConsulted = "a policy input fact failed its freshness check; the PDP was not consulted"
	reasonUndefined    = "the PDP gave no decision: the decision document is undefined"
	reasonDecided      = "the PDP's decision"
)

// recheckPaths are the facts read again before release: F4, F7 and F8
// (profile ABAC-21).
var recheckPaths = []string{PathDeviceCompliant, PathNetworkZone, PathTime}

// Admission is a decision with the readings it rests on: what [Adapter.Decide]
// returns and what [Adapter.Recheck] takes at execution.
type Admission struct {
	// Principal and Operation are those the decision was made for.
	Principal adapter.Principal
	Operation core.OperationContext
	// Decision is the decision in force.
	Decision adapter.Decision

	readings facts
}

// Reading returns the fact at path that the decision rests on.
func (ad Admission) Reading(path string) (adapter.NativeClaim, bool) {
	r, ok := ad.readings[path]
	return r.claim, ok
}

// AuthorizeNative asks the PDP for the existing decision for the original
// principal and the actual operation and returns it as the PDP gave it, with
// every obligation unchanged and in order, its decision_id as SourceRef, its
// policy_version as PolicyRevision and no decision time (draft 4.3, 17.1;
// profile section 13). The adapter never converts a decision, never drops or
// edits an obligation, never caches a decision, and never runs the
// operation. See [Adapter.Decide] for what comes back when the PDP is not
// consulted or does not decide.
func (a *Adapter) AuthorizeNative(ctx context.Context, p adapter.Principal, op core.OperationContext) (adapter.Decision, error) {
	ad, err := a.Decide(ctx, p, op)
	if err != nil {
		return adapter.Decision{}, err
	}
	return ad.Decision, nil
}

// Decide is AuthorizeNative with the readings the decision rests on, which
// [Adapter.Recheck] needs at execution.
//
// The input holds the facts F1 to F8, read from their sources for the
// principal, its authenticated device and peer address, and the one resource
// of the operation (profile section 11); nothing comes from a header, an
// extension or the principal's other attributes. Each fact is evaluated with
// its limits; the first row of profile ABAC-8 that applies to any fact
// decides, and the PDP is not queried: a source that cannot answer is an
// error that wraps [adapter.ErrDependencyUnavailable]; a missing fact, a
// value outside its form or a source with no usable time wraps
// [adapter.ErrUnsupportedRequirement]; a stale, ahead or re-stamped fact is
// an unknown decision. The PDP's answer is classified by profile ABAC-14: no
// answer, a status other than 200, and an answer without decision_id wrap
// [adapter.ErrDependencyUnavailable]; a body that is not one strict JSON
// object, a result that is not an object, a missing policy_version, and a
// document that fails ABAC-15 wrap [adapter.ErrUnsupportedRequirement]; an
// undefined document is an unknown decision with no obligations.
func (a *Adapter) Decide(ctx context.Context, p adapter.Principal, op core.OperationContext) (Admission, error) {
	if err := live(ctx, "authorize"); err != nil {
		return Admission{}, err
	}
	if err := a.subjectOf(p, op); err != nil {
		return Admission{}, err
	}
	start := a.cfg.Clock.Now()
	f := a.readFacts(ctx, p, op, factPaths, start)
	ad := Admission{Principal: p, Operation: op, readings: f}
	d, err := a.decideOn(ctx, f, op)
	if err != nil {
		return Admission{}, err
	}
	ad.Decision = d
	return ad, nil
}

// subjectOf checks that the decision is asked for the original principal of
// the operation, in the gateway's realm (draft 17.5).
func (a *Adapter) subjectOf(p adapter.Principal, op core.OperationContext) error {
	switch {
	case p.ID == "":
		return fmt.Errorf("abac: authorize: no principal: %w", adapter.ErrContextMismatch)
	case p.Realm != a.cfg.Realm:
		return fmt.Errorf("abac: authorize: the principal does not belong to the gateway's realm: %w", adapter.ErrContextMismatch)
	case op.PrincipalID != p.ID:
		return fmt.Errorf("abac: authorize: the operation names another principal: %w", adapter.ErrContextMismatch)
	case op.Action == "":
		return fmt.Errorf("abac: authorize: the operation has no action: %w", adapter.ErrUnsupportedRequirement)
	}
	if _, err := oneResource(op); err != nil {
		return fmt.Errorf("abac: authorize: %w: %w", adapter.ErrUnsupportedRequirement, err)
	}
	return nil
}

// decideOn turns the readings into a decision: no query unless every fact is
// fresh and of its form, then the PDP's classified answer.
func (a *Adapter) decideOn(ctx context.Context, f facts, op core.OperationContext) (adapter.Decision, error) {
	worst, fresh := f.worst()
	if !fresh {
		if err := worst.fail(); err != nil {
			return adapter.Decision{}, err
		}
		return adapter.Decision{Effect: adapter.EffectUnknown, Reason: reasonNotConsulted, SourceID: a.cfg.PDP.SourceID}, nil
	}
	ans := a.pdp.query(ctx, input(f, op))
	return a.decisionOf(ans)
}

// decisionOf maps a classified answer to what authorize_native returns
// (profile ABAC-14, column "authorize_native returns").
func (a *Adapter) decisionOf(ans answer) (adapter.Decision, error) {
	src := a.cfg.PDP.SourceID
	switch ans.status {
	case answerTransport, answerUnattributed:
		return adapter.Decision{}, fmt.Errorf("abac: authorize: %w: %w", adapter.ErrDependencyUnavailable, ans.err)
	case answerMalformed, answerNotObject, answerNoVersion, answerBadDocument:
		return adapter.Decision{}, fmt.Errorf("abac: authorize: %w: %w", adapter.ErrUnsupportedRequirement, ans.err)
	case answerUndefined:
		return adapter.Decision{Effect: adapter.EffectUnknown, Reason: reasonUndefined, SourceID: src, SourceRef: ans.decisionID}, nil
	}
	d := adapter.Decision{
		Effect:         adapter.EffectDeny,
		Obligations:    ans.obligations,
		Reason:         reasonDecided,
		SourceID:       src,
		SourceRef:      ans.decisionID,
		PolicyRevision: ans.version,
	}
	if ans.allow {
		d.Effect = adapter.EffectAllow
	}
	return d, nil
}

// Recheck is the execution-time recheck of profile ABAC-21 to ABAC-23, which
// the executor side runs after it holds the content and before it releases
// any of it (ABAC-24).
//
// For each of F4 (device), F7 (zone) and F8 (time), when the clock minus the
// status time of the reading in force is greater than its status_max_age,
// the fact is read again; an age equal to the limit passes. When nothing was
// read again the admission stands unchanged. Otherwise the new readings are
// evaluated with the start of the recheck as the evaluation start, a new
// input is built from them and the unchanged readings, and the PDP is asked
// again: the new decision replaces the one in force, with its own
// obligations. A reread that fails is an error, or an unknown decision for a
// stale fact, as for [Adapter.Decide]; neither discloses anything. The
// facts F1 to F3, F5 and F6 are not read again.
func (a *Adapter) Recheck(ctx context.Context, prev Admission) (Admission, error) {
	if err := live(ctx, "recheck"); err != nil {
		return Admission{}, err
	}
	if prev.readings == nil {
		return Admission{}, errors.New("abac: recheck: the admission carries no readings")
	}
	start := a.cfg.Clock.Now()
	var due []string
	for _, path := range recheckPaths {
		r, ok := prev.readings[path]
		limit := time.Duration(a.limits[path].StatusMaxAgeSeconds) * time.Second
		if !ok || r.claim.StatusCheckedAt.IsZero() || start.Sub(r.claim.StatusCheckedAt) > limit {
			due = append(due, path)
		}
	}
	if len(due) == 0 {
		return prev, nil
	}
	fresh := a.readFacts(ctx, prev.Principal, prev.Operation, due, start)
	merged := maps.Clone(prev.readings)
	maps.Copy(merged, fresh)
	next := Admission{Principal: prev.Principal, Operation: prev.Operation, readings: merged}
	d, err := a.decideOn(ctx, merged, prev.Operation)
	if err != nil {
		return Admission{}, fmt.Errorf("abac: recheck: %w", err)
	}
	next.Decision = d
	return next, nil
}
