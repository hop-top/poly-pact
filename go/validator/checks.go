package validator

import (
	"context"
	"errors"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// outcome is one check result before it is stamped with its check id and
// evaluation time.
type outcome struct {
	result    core.CheckStatus
	reason    string
	observed  *int64
	status    *int64
	evidence  []string
	sourceID  string
	sourceRef *string
}

func pass() outcome                      { return outcome{result: core.CheckPass, reason: reasonSatisfied} }
func fail(reason string) outcome         { return outcome{result: core.CheckFail, reason: reason} }
func unknown(reason string) outcome      { return outcome{result: core.CheckUnknown, reason: reason} }
func notEvaluated() outcome              { return unknown(reasonNotEvaluated) }
func (o outcome) at(t time.Time) outcome { o.observed, o.status = unixOf(t), unixOf(t); return o }

// unixOf is the wire form of a source time: nil for the zero time, which the
// source does not give.
func unixOf(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	s := t.Unix()
	return &s
}

// set records the result of a check, at the current instant.
func (e *evaluation) set(id string, o outcome) {
	if o.evidence == nil {
		o.evidence = []string{}
	}
	if o.sourceID == "" {
		o.sourceID = e.v.Config.SourceID
	}
	e.checks[id] = core.CheckResult{
		CheckID: id, Result: o.result, ReasonCode: o.reason, CheckedAt: e.v.Clock.Now().Unix(),
		SourceObservedAt: o.observed, StatusCheckedAt: o.status, EvidenceIDs: o.evidence,
		SourceID: o.sourceID, SourceRef: o.sourceRef,
	}
}

// run evaluates every check of draft 11.3 steps 2 to 9 that the admission
// left to the evaluation. The checks on inputs the validator holds come
// first; the native reads (draft 12.1) last, so that an evaluation cancelled
// or expired while they are outstanding still records what it established.
func (e *evaluation) run(ctx context.Context) {
	e.active, e.activeErr = e.v.Policies.Active(ctx)
	e.sel, e.selErr = e.v.Policies.Selection(ctx, e.c)
	e.holds, e.holdsErr = e.v.Holds.Holds(ctx, e.v.Config.Realm, e.p.Subject)
	e.holdsAt = e.v.Clock.Now()

	e.set(CheckNativeAuthentication, e.nativeAuthentication())
	e.set(CheckAgentHolderBinding, e.agentHolderBinding())
	e.set(CheckContractValidity, e.contractValidity())
	e.set(CheckNonce, e.nonce)
	e.set(CheckOperationBinding, e.operationBinding())
	e.set(CheckIntentBinding, e.intentBinding())
	e.set(CheckProfileValidity, e.profileValidity())
	e.set(CheckEvidenceValidity, e.evidenceValidity(ctx))
	if e.p.Reputation != nil {
		e.set(CheckReputationContext, e.reputationContext(ctx))
	}
	e.set(CheckSecurityHold, e.securityHold())
	e.set(CheckActivePolicy, e.activePolicy())

	for _, r := range e.c.Claims.FieldRules {
		if r.Source != core.RuleSourceNative {
			e.set(r.RuleID, e.rule(r))
		}
	}
	for _, id := range e.c.Claims.ContextChecks {
		switch id {
		case CheckNativePrincipalBinding:
			e.set(id, e.nativePrincipalBinding())
		case CheckSelectionConsistency:
			e.set(id, e.selectionConsistency())
		}
	}
	for _, r := range e.c.Claims.FieldRules {
		if r.Source == core.RuleSourceNative {
			e.native(ctx, r.RuleID, func() outcome { return e.nativeRule(ctx, r) })
		}
	}
	for _, id := range e.c.Claims.ContextChecks {
		if id != CheckNativePrincipalBinding && id != CheckSelectionConsistency {
			e.native(ctx, id, func() outcome { return e.contextCheck(ctx, id) })
		}
	}
}

// native runs one check that needs a native read (draft 12.1). Once the
// evaluation is cancelled or past its deadline, no read is issued, and a
// read that completes after that is discarded: the check was not performed.
func (e *evaluation) native(ctx context.Context, id string, read func() outcome) {
	if e.over(ctx) {
		return
	}
	o := read()
	if e.over(ctx) {
		return
	}
	e.set(id, o)
}

// over reports whether the evaluation has ended: cancelled through ctx, or
// at or past its deadline (draft 12.2). The first end is kept.
func (e *evaluation) over(ctx context.Context) bool {
	if e.ended != "" {
		return true
	}
	now := e.v.Clock.Now()
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		e.ended, e.endedAt = core.TerminalCancelled, now
	case !now.Before(e.deadline), errors.Is(ctx.Err(), context.DeadlineExceeded):
		e.ended, e.endedAt = core.TerminalExpired, e.deadline
		if now.Before(e.deadline) {
			e.endedAt = now
		}
	default:
		return false
	}
	return true
}

func (e *evaluation) nativeAuthentication() outcome {
	pr := e.req.Principal
	if pr.Realm != e.v.Config.Realm {
		return fail(reasonContextMismatch)
	}
	return pass().at(pr.AuthenticatedAt)
}

func (e *evaluation) agentHolderBinding() outcome {
	if !e.bindingKnown {
		return unknown(reasonUnavailable)
	}
	b := e.binding
	o := pass()
	if b.Status == adapter.BindingCompromised {
		o = fail(reasonSecurityHold)
	}
	o.observed, o.status, o.sourceID = unixOf(b.ObservedAt), unixOf(b.StatusCheckedAt), b.SourceID
	if b.SourceRef != "" {
		o.sourceRef = &b.SourceRef
	}
	return o
}

// contractValidity is draft 11.3 step 3: the contract names this agent,
// gateway and realm, carries only supported extensions, lists
// selection-consistency-v1 when it selects a set other than the
// conservative one, and, when the validator holds the table of its pinned
// selector, holds exactly the authorized field rules and context checks of
// its set.
func (e *evaluation) contractValidity() outcome {
	cfg, c := e.v.Config, e.c
	err := c.Check(contract.Expect{AgentID: e.p.Subject, Audience: cfg.Audience, Realm: cfg.Realm, SupportedExtensions: cfg.SupportedExtensions})
	switch {
	case errors.Is(err, contract.ErrUnsupportedRequirement):
		return unknown(reasonUnsupported)
	case err != nil:
		return fail(reasonContextMismatch)
	case e.p.Audience != cfg.Audience || e.p.TenantID != c.Claims.TenantID:
		return fail(reasonContextMismatch)
	case e.activeErr != nil || e.selErr != nil:
		return unknown(reasonUnavailable)
	case c.Claims.SelectedSet != e.active.ConservativeSet && !slices.Contains(c.Claims.ContextChecks, CheckSelectionConsistency):
		return fail(reasonContextMismatch)
	}
	if s := e.sel.Selector; s != nil {
		// The validator holds the table: the contract's rules and checks
		// are exactly its entry for the set, array order significant.
		rules, ok := s.Rules(c.Claims.SelectedSet)
		if !ok || !jsonEqual(rules, c.Claims.FieldRules) {
			return fail(reasonContextMismatch)
		}
		checks, ok := s.Checks(c.Claims.SelectedSet)
		if !ok || !jsonEqual(checks, c.Claims.ContextChecks) {
			return fail(reasonContextMismatch)
		}
	}
	return pass()
}

// operationBinding is draft 11.3 step 5: the actual operation and the
// presented one are the operation the contract was issued for.
func (e *evaluation) operationBinding() outcome {
	want := e.c.Claims.OperationDigest
	if e.actualDigest() != want || objectDigest(e.opRaw) != want {
		return fail(reasonContextMismatch)
	}
	return pass()
}

func (e *evaluation) intentBinding() outcome {
	if objectDigest(e.intentRaw) != e.c.Claims.IntentDigest {
		return fail(reasonContextMismatch)
	}
	return pass()
}

// profileValidity is draft 11.3 step 6, but for the field rules: subject,
// tenant, age and lifetime, and the enrolled operator (Appendix A.2). The
// holder was bound before the evaluation began.
func (e *evaluation) profileValidity() outcome {
	pf, cfg := e.p.Profile, e.v.Config
	if pf.AgentID != e.p.Subject || pf.TenantID != e.c.Claims.TenantID || pf.TenantID != cfg.Realm.TenantID {
		return fail(reasonContextMismatch)
	}
	if err := clock.CheckWindow(pf.CreatedAt, pf.CreatedAt, pf.ExpiresAt, e.v.Clock.Now(), cfg.Skew); err != nil {
		if errors.Is(err, clock.ErrExpired) {
			return fail(reasonStaleEvidence)
		}
		return fail(reasonInvalidClaim)
	}
	if err := clock.CheckLifetime(clock.Profile, pf.CreatedAt, pf.ExpiresAt); err != nil {
		return fail(reasonInvalidClaim)
	}
	if !e.bindingKnown {
		return unknown(reasonUnavailable)
	}
	if pf.OperatorID != e.binding.OperatorID {
		return fail(reasonContextMismatch)
	}
	return pass().at(time.Unix(pf.CreatedAt, 0))
}

func (e *evaluation) securityHold() outcome {
	switch {
	case e.holdsErr != nil:
		return unknown(reasonUnavailable)
	case len(e.holds) > 0:
		o := fail(reasonSecurityHold)
		o.evidence = slices.Clone(e.holds)
		return o.at(e.v.Clock.Now())
	}
	return pass().at(e.v.Clock.Now())
}

// activePolicy is the active-policy check of draft 11.3 step 3 and 12.2: a
// contract invalidated by a policy change is FAIL with REQUIREMENTS_CHANGED,
// which defers.
func (e *evaluation) activePolicy() outcome {
	if e.activeErr != nil {
		return unknown(reasonUnavailable)
	}
	if e.c.CheckActive(e.active.Policy) != nil {
		return fail(reasonRequirementsChanged)
	}
	return pass().at(e.v.Clock.Now())
}

// nativePrincipalBinding is the check of draft 17.5: the principal the
// profile claims to act for is the one authenticate_native established.
func (e *evaluation) nativePrincipalBinding() outcome {
	v, ok := pointer(e.profile, principalPath)
	if !ok {
		return fail(reasonMissingField)
	}
	if s, isString := v.(string); !isString || s != e.req.Operation.PrincipalID {
		return fail(reasonContextMismatch)
	}
	return pass().at(e.req.Principal.AuthenticatedAt)
}

// contextCheck runs an installed check through check_context (draft 17.1),
// with the principal and binding this evaluation established. A check the
// gateway did not install, or one that needs a binding the enrollment
// source could not establish, is UNKNOWN: it was not performed.
func (e *evaluation) contextCheck(ctx context.Context, id string) outcome {
	if !slices.Contains(e.v.Config.InstalledChecks, id) {
		return unknown(reasonUnsupported)
	}
	if !e.bindingKnown {
		return unknown(reasonUnavailable)
	}
	got := e.v.Native.CheckContext(ctx, id, e.checkInput())
	o := outcome{result: got.Result.CheckStatus(), reason: got.ReasonCode, sourceID: got.SourceID}
	if o.result == core.CheckPass && o.reason == "" {
		o.reason = reasonSatisfied
	}
	if o.result != core.CheckPass && o.reason == "" {
		o = unknown(reasonUnavailable)
		o.sourceID = got.SourceID
	}
	if got.SourceRef != "" {
		o.sourceRef = &got.SourceRef
	}
	o.observed = unixOf(got.ObservedAt)
	return o
}

func (e *evaluation) checkInput() adapter.CheckInput {
	return adapter.CheckInput{
		Principal: e.req.Principal, Binding: e.binding, Intent: e.p.Intent,
		Operation: e.req.Operation, EvidenceRefs: slices.Clone(e.evidenceIDs),
	}
}
