package adaptertest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

func claimCase(outcome string, e Expect) *Case {
	e.Function, e.Outcome = fnClaim, outcome
	p := goodPrincipal()
	return &Case{
		Call:   Call{NativePath: "/attributes/environment/roles", Principal: &PrincipalJSON{ID: p.ID, Realm: acmeJS, Workload: "w-1"}},
		Expect: e,
	}
}

func claimFake(c adapter.NativeClaim, err error) *fake {
	return &fake{claim: func(context.Context, string, adapter.ClaimContext) (adapter.NativeClaim, error) { return c, err }}
}

func goodClaim() adapter.NativeClaim {
	return adapter.NativeClaim{
		Value:      []any{"approver"},
		ObservedAt: now.Add(-time.Hour), StatusCheckedAt: now.Add(-30 * time.Second),
		SourceID: "directory-1", SourceRef: "entry-17",
	}
}

func rawJSON(s string) json.RawMessage { return json.RawMessage(s) }

func TestClaimChecks(t *testing.T) {
	good := goodClaim()
	with := func(f func(*adapter.NativeClaim)) adapter.NativeClaim {
		c := good
		f(&c)
		return c
	}
	observed := fmt.Sprint(now.Add(-time.Hour).Unix())
	checked := fmt.Sprint(now.Add(-30 * time.Second).Unix())
	full := Expect{Claim: &ExpectClaim{
		Value: rawJSON(`["approver"]`), ObservedAt: rawJSON(observed), StatusCheckedAt: rawJSON(checked),
		SourceID: "directory-1", SourceRef: "entry-17",
	}}
	expectClaim := func(c ExpectClaim) Expect { return Expect{Claim: &c} }

	runRows(t, []row{
		{"claim", claimFake(good, nil), claimCase(outClaim, full), nil},
		{"claim but errors", claimFake(adapter.NativeClaim{}, adapter.ErrUnsupportedRequirement), claimCase(outClaim, full), []string{"want a claim"}},
		{"value in another order", claimFake(with(func(c *adapter.NativeClaim) { c.Value = []any{"a", "b"} }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{Value: rawJSON(`["b","a"]`)})), []string{"claim value is"}},
		{"object members in another order", claimFake(with(func(c *adapter.NativeClaim) {
			c.Value = map[string]any{"b": 1, "a": 2}
		}), nil), claimCase(outClaim, expectClaim(ExpectClaim{Value: rawJSON(`{"b": 1,  "a": 2}`)})), nil},
		{"null value", claimFake(with(func(c *adapter.NativeClaim) { c.Value = nil }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{Value: rawJSON(`null`)})), nil},
		{"value that does not encode", claimFake(with(func(c *adapter.NativeClaim) { c.Value = make(chan int) }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{Value: rawJSON(`null`)})), []string{"does not encode"}},
		{"restamped observation", claimFake(with(func(c *adapter.NativeClaim) { c.ObservedAt = now }), nil), claimCase(outClaim, full),
			[]string{"ObservedAt is", "not the time of the read"}},
		{"restamped status check", claimFake(with(func(c *adapter.NativeClaim) { c.StatusCheckedAt = now }), nil), claimCase(outClaim, full),
			[]string{"StatusCheckedAt is"}},
		{"observation supplied where the source gives none", claimFake(with(func(c *adapter.NativeClaim) { c.ObservedAt = now }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{ObservedAt: rawJSON(`null`)})), []string{"want the zero time"}},
		{"zero time where the source gives one", claimFake(with(func(c *adapter.NativeClaim) { c.ObservedAt = time.Time{} }), nil),
			claimCase(outClaim, full), []string{"ObservedAt is the zero time"}},
		{"zero times as the source gives none", claimFake(with(func(c *adapter.NativeClaim) {
			c.ObservedAt, c.StatusCheckedAt = time.Time{}, time.Time{}
		}), nil), claimCase(outClaim, expectClaim(ExpectClaim{ObservedAt: rawJSON(`null`), StatusCheckedAt: rawJSON(`null`)})), nil},
		{"observation in the future", claimFake(with(func(c *adapter.NativeClaim) { c.ObservedAt = now.Add(time.Hour) }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{})), []string{"ObservedAt is", "later than the allowed"}},
		{"observation at the skew edge", claimFake(with(func(c *adapter.NativeClaim) { c.ObservedAt = now.Add(skew) }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{})), nil},
		{"observation past the skew", claimFake(with(func(c *adapter.NativeClaim) { c.ObservedAt = now.Add(skew + time.Second) }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{})), []string{"later than the allowed"}},
		// Draft A.2: no status-check time may be later than now plus the skew.
		{"status check past the skew", claimFake(with(func(c *adapter.NativeClaim) { c.StatusCheckedAt = now.Add(skew + time.Second) }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{})), []string{"StatusCheckedAt is", "later than the allowed"}},
		{"status check at the skew edge", claimFake(with(func(c *adapter.NativeClaim) { c.StatusCheckedAt = now.Add(skew) }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{})), nil},
		{"status check at now", claimFake(with(func(c *adapter.NativeClaim) { c.StatusCheckedAt = now }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{})), nil},
		{"no source", claimFake(with(func(c *adapter.NativeClaim) { c.SourceID = "" }), nil),
			claimCase(outClaim, expectClaim(ExpectClaim{})), []string{"names no source"}},
		{"wrong source", claimFake(good, nil), claimCase(outClaim, expectClaim(ExpectClaim{SourceID: "other"})), []string{"source id is"}},
		{"wrong source ref", claimFake(good, nil), claimCase(outClaim, expectClaim(ExpectClaim{SourceRef: "other"})), []string{"source ref is"}},

		{"error", claimFake(adapter.NativeClaim{}, fmt.Errorf("x: %w", adapter.ErrUnsupportedRequirement)),
			claimCase(outError, Expect{ReasonCode: "UNSUPPORTED_REQUIREMENT"}), nil},
		{"error expected, claim returned", claimFake(good, nil), claimCase(outError, Expect{}), []string{"want an error"}},
	})

	// The claim context of draft 17.1 is the principal, the declared intent and
	// the actual operation of the case, passed as they are.
	t.Run("the context reaches the adapter", func(t *testing.T) {
		var got adapter.ClaimContext
		var gotPath string
		f := &fake{claim: func(_ context.Context, path string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
			gotPath, got = path, c
			return good, nil
		}}
		c := claimCase(outClaim, Expect{})
		op := goodOp()
		c.Call.Intent = &core.Intent{IntentID: "i-1", PurposeID: "p-1", TaskID: "task-7"}
		c.Call.Operation = &op
		wantClean(t, runFake(t, f, c))
		if gotPath != "/attributes/environment/roles" {
			t.Errorf("path = %q", gotPath)
		}
		if got.Principal.ID != goodPrincipal().ID || got.Principal.Realm != acme || got.Principal.Workload != "w-1" {
			t.Errorf("principal = %+v", got.Principal)
		}
		if got.Intent.TaskID != "task-7" || got.Intent.IntentID != "i-1" || got.Intent.PurposeID != "p-1" {
			t.Errorf("intent = %+v", got.Intent)
		}
		if got.Operation.OperationID != "op-1" || !slices.Equal(got.Operation.Resources, op.Resources) || got.Operation.PrincipalID != op.PrincipalID {
			t.Errorf("operation = %+v", got.Operation)
		}
	})

	t.Run("a case without intent or operation passes neither", func(t *testing.T) {
		got := adapter.ClaimContext{Intent: core.Intent{TaskID: "unset"}, Operation: core.OperationContext{OperationID: "unset"}}
		f := &fake{claim: func(_ context.Context, _ string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
			got = c
			return good, nil
		}}
		wantClean(t, runFake(t, f, claimCase(outClaim, Expect{})))
		if got.Principal.ID != goodPrincipal().ID {
			t.Errorf("principal = %+v", got.Principal)
		}
		if !reflect.DeepEqual(got.Intent, core.Intent{}) || !reflect.DeepEqual(got.Operation, core.OperationContext{}) {
			t.Errorf("intent %+v and operation %+v, want both zero", got.Intent, got.Operation)
		}
	})
}

func checkCase(id, outcome string, e Expect) *Case {
	e.Function, e.Outcome = fnCheck, outcome
	p, op := goodPrincipal(), goodOp()
	return &Case{
		Call:   Call{CheckID: &id, Principal: &PrincipalJSON{ID: p.ID, Realm: acmeJS, Workload: "w-1"}, Operation: &op},
		Expect: e,
	}
}

func checkFake(out adapter.CheckOutcome) *fake {
	return &fake{check: func(context.Context, string, adapter.CheckInput) adapter.CheckOutcome {
		return out
	}}
}

func TestCheckChecks(t *testing.T) {
	unknown := adapter.CheckOutcome{Result: adapter.VerdictUnknown, ReasonCode: "UNSUPPORTED_REQUIREMENT"}
	pass := adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "approvals", ObservedAt: now.Add(-time.Minute)}
	runRows(t, []row{
		{"unknown", checkFake(unknown), checkCase("x", outUnknown, Expect{ReasonCode: "UNSUPPORTED_REQUIREMENT"}), nil},
		{"unknown but pass", checkFake(pass), checkCase("x", outUnknown, Expect{}), []string{"never PASS"}},
		{"pass", checkFake(pass), checkCase("x", outPass, Expect{ReasonCode: "REQUIREMENT_SATISFIED"}), nil},
		{"pass expected, unknown returned", checkFake(unknown), checkCase("x", outPass, Expect{}), []string{"returned UNKNOWN"}},
		{"fail", checkFake(adapter.CheckOutcome{Result: adapter.VerdictFail, ReasonCode: "APPROVAL_REJECTED"}),
			checkCase("x", outFail, Expect{ReasonCode: "APPROVAL_REJECTED"}), nil},
		{"wrong reason", checkFake(unknown), checkCase("x", outUnknown, Expect{ReasonCode: "DEPENDENCY_UNAVAILABLE"}),
			[]string{"reason code is"}},
		{"no reason", checkFake(adapter.CheckOutcome{Result: adapter.VerdictUnknown}), checkCase("x", outUnknown, Expect{}),
			[]string{"no reason code"}},
		{"undefined verdict", checkFake(adapter.CheckOutcome{Result: "OK", ReasonCode: "X"}), checkCase("x", outUnknown, Expect{}),
			[]string{"not PASS, FAIL or UNKNOWN"}},
		{"observation in the future", checkFake(adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "X", ObservedAt: now.Add(time.Hour)}),
			checkCase("x", outPass, Expect{}), []string{"check ObservedAt"}},
	})

	t.Run("arguments reach the adapter", func(t *testing.T) {
		var gotID string
		var got adapter.CheckInput
		f := &fake{check: func(_ context.Context, id string, in adapter.CheckInput) adapter.CheckOutcome {
			gotID, got = id, in
			return unknown
		}}
		c := checkCase("", outUnknown, Expect{})
		c.Call.Intent = &core.Intent{IntentID: "i-1"}
		c.Call.EvidenceRefs = []string{"ref-1"}
		c.Call.Principal.Attributes = map[string]any{"device_id": "dev-1"}
		c.Call.Binding = &BindingJSON{AgentID: "https://agents.example/a", OperatorID: "https://ops.example/o", HolderJKT: "thumb-1"}
		wantClean(t, runFake(t, f, c))
		if gotID != "" || got.Intent.IntentID != "i-1" || len(got.EvidenceRefs) != 1 {
			t.Errorf("got %q %+v", gotID, got)
		}
		if p := got.Principal; p.ID != goodPrincipal().ID || p.Realm != acme || p.Workload != "w-1" || p.Attributes["device_id"] != "dev-1" {
			t.Errorf("principal = %+v, want the case's principal with its attributes", p)
		}
		if got.Operation.OperationID != "op-1" {
			t.Errorf("operation = %+v", got.Operation)
		}
		want := adapter.AgentBinding{AgentID: "https://agents.example/a", OperatorID: "https://ops.example/o", HolderJKT: "thumb-1", Status: adapter.BindingActive}
		if got.Binding != want {
			t.Errorf("binding = %+v, want %+v: a binding without status is ACTIVE", got.Binding, want)
		}
	})

	t.Run("a stated status reaches the adapter", func(t *testing.T) {
		var got adapter.CheckInput
		f := &fake{check: func(_ context.Context, _ string, in adapter.CheckInput) adapter.CheckOutcome {
			got = in
			return unknown
		}}
		c := checkCase("x", outUnknown, Expect{})
		c.Call.Binding = &BindingJSON{AgentID: "https://agents.example/a", Status: "REVOKED"}
		wantClean(t, runFake(t, f, c))
		if got.Binding.Status != adapter.BindingRevoked {
			t.Errorf("binding status = %q, want REVOKED", got.Binding.Status)
		}
	})

	t.Run("a case without a binding passes an empty one", func(t *testing.T) {
		got := adapter.CheckInput{Binding: adapter.AgentBinding{AgentID: "unset", Status: adapter.BindingActive}}
		f := &fake{check: func(_ context.Context, _ string, in adapter.CheckInput) adapter.CheckOutcome {
			got = in
			return unknown
		}}
		wantClean(t, runFake(t, f, checkCase("x", outUnknown, Expect{})))
		if !reflect.DeepEqual(got.Binding, adapter.AgentBinding{}) {
			t.Errorf("binding = %+v, want the zero binding: the caller established no agent", got.Binding)
		}
	})
}

func authzCase(outcome string, e Expect) *Case {
	e.Function, e.Outcome = fnAuthorize, outcome
	p, op := goodPrincipal(), goodOp()
	return &Case{
		Call:   Call{Principal: &PrincipalJSON{ID: p.ID, Realm: acmeJS, Workload: "w-1"}, Operation: &op},
		Expect: e,
	}
}

func authzFake(d adapter.Decision, err error) *fake {
	return &fake{authz: func(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
		return d, err
	}}
}

func TestAuthorizeChecks(t *testing.T) {
	// decision returns a decision with effect e that names its source, as
	// every decision must.
	decision := func(e adapter.Effect, f ...func(*adapter.Decision)) adapter.Decision {
		d := adapter.Decision{Effect: e, SourceID: "policy-1"}
		for _, m := range f {
			m(&d)
		}
		return d
	}
	deny := decision(adapter.EffectDeny, func(d *adapter.Decision) { d.Reason = "policy 7" })
	allow := decision(adapter.EffectAllow)
	unknown := decision(adapter.EffectUnknown)
	audit := adapter.Obligation{ID: "audit", Attributes: map[string]any{"level": "high"}}
	wantAudit := []ObligationJSON{{ID: "audit", Attributes: map[string]any{"level": "high"}}}
	none := []ObligationJSON{}
	withObligations := func(e adapter.Effect, o ...adapter.Obligation) adapter.Decision {
		return decision(e, func(d *adapter.Decision) { d.Obligations = o })
	}

	runRows(t, []row{
		{"deny", authzFake(deny, nil), authzCase(outDeny, Expect{}), nil},
		{"deny rewritten to allow", authzFake(allow, nil), authzCase(outDeny, Expect{}), []string{"cannot rewrite a denial"}},
		{"deny rewritten to unknown", authzFake(unknown, nil), authzCase(outDeny, Expect{}),
			[]string{"decision effect is UNKNOWN"}},
		{"deny but errors", authzFake(adapter.Decision{}, adapter.ErrDependencyUnavailable), authzCase(outDeny, Expect{}),
			[]string{"want effect DENY"}},
		{"allow", authzFake(allow, nil), authzCase(outAllow, Expect{}), nil},
		{"unknown", authzFake(unknown, nil), authzCase(outUnknown, Expect{}), nil},
		{"obligations kept", authzFake(withObligations(adapter.EffectDeny, audit), nil),
			authzCase(outDeny, Expect{Decision: &ExpectDecision{Obligations: &wantAudit}}), nil},
		{"obligations dropped", authzFake(deny, nil),
			authzCase(outDeny, Expect{Decision: &ExpectDecision{Obligations: &wantAudit}}), []string{"obligations are"}},
		{"obligation attributes changed", authzFake(withObligations(adapter.EffectDeny,
			adapter.Obligation{ID: "audit", Attributes: map[string]any{"level": "low"}}), nil),
			authzCase(outDeny, Expect{Decision: &ExpectDecision{Obligations: &wantAudit}}), []string{"obligations are"}},
		{"obligation added", authzFake(withObligations(adapter.EffectDeny, audit), nil),
			authzCase(outDeny, Expect{Decision: &ExpectDecision{Obligations: &none}}), []string{"obligations are"}},
		{"nil and empty attributes are the same", authzFake(withObligations(adapter.EffectDeny,
			adapter.Obligation{ID: "x", Attributes: map[string]any{}}), nil),
			authzCase(outDeny, Expect{Decision: &ExpectDecision{Obligations: &[]ObligationJSON{{ID: "x"}}}}), nil},
		{"undefined effect", authzFake(decision("PERMIT"), nil), authzCase(outNotAllowed, Expect{}),
			[]string{"not ALLOW, DENY or UNKNOWN"}},

		{"not allowed by a denial", authzFake(deny, nil), authzCase(outNotAllowed, Expect{}), nil},
		{"not allowed by an unknown", authzFake(unknown, nil), authzCase(outNotAllowed, Expect{}), nil},
		{"not allowed by an error", authzFake(adapter.Decision{}, errors.New("x")), authzCase(outNotAllowed, Expect{}), nil},
		{"not allowed but allowed", authzFake(allow, nil), authzCase(outNotAllowed, Expect{}), []string{"anything but ALLOW"}},

		{"error", authzFake(adapter.Decision{}, adapter.ErrDependencyUnavailable),
			authzCase(outError, Expect{ReasonCode: "DEPENDENCY_UNAVAILABLE"}), nil},
		{"error expected, decision returned", authzFake(deny, nil), authzCase(outError, Expect{}), []string{"want an error"}},
	})
}

// TestDecisionProvenance: every decision names the policy source that decided
// and a decision time that is not in the future beyond the skew, whatever the
// outcome the case expects; a case may pin the source, the record, the time and
// the policy revision the native source gave.
func TestDecisionProvenance(t *testing.T) {
	decidedAt := now.Add(-2 * time.Second)
	full := adapter.Decision{
		Effect: adapter.EffectAllow, SourceID: "pdp-1", SourceRef: "decision-8f0d",
		DecidedAt: decidedAt, PolicyRevision: "policy-2026-10-01",
	}
	with := func(f func(*adapter.Decision)) adapter.Decision {
		d := full
		f(&d)
		return d
	}
	pinned := func(e ExpectDecision) Expect { return Expect{Decision: &e} }
	all := pinned(ExpectDecision{
		SourceID: "pdp-1", SourceRef: rawJSON(`"decision-8f0d"`),
		DecidedAt: rawJSON(fmt.Sprint(decidedAt.Unix())), PolicyRevision: "policy-2026-10-01",
	})

	runRows(t, []row{
		{"provenance as the source gave it", authzFake(full, nil), authzCase(outAllow, all), nil},
		{"only a source", authzFake(adapter.Decision{Effect: adapter.EffectDeny, SourceID: "pdp-1"}, nil), authzCase(outDeny, Expect{}), nil},

		{"no source", authzFake(with(func(d *adapter.Decision) { d.SourceID = "" }), nil), authzCase(outAllow, Expect{}),
			[]string{"decision names no source"}},
		{"no source on a denial", authzFake(adapter.Decision{Effect: adapter.EffectDeny}, nil), authzCase(outDeny, Expect{}),
			[]string{"decision names no source"}},
		{"no source where only not allowed is required", authzFake(adapter.Decision{Effect: adapter.EffectDeny}, nil),
			authzCase(outNotAllowed, Expect{}), []string{"decision names no source"}},
		{"no source on an unknown", authzFake(adapter.Decision{Effect: adapter.EffectUnknown}, nil), authzCase(outUnknown, Expect{}),
			[]string{"decision names no source"}},
		{"an error carries no decision", authzFake(adapter.Decision{}, adapter.ErrDependencyUnavailable),
			authzCase(outNotAllowed, Expect{}), nil},

		{"decided in the future", authzFake(with(func(d *adapter.Decision) { d.DecidedAt = now.Add(time.Hour) }), nil),
			authzCase(outAllow, Expect{}), []string{"DecidedAt is", "later than the allowed"}},
		{"decided in the future, not allowed", authzFake(adapter.Decision{Effect: adapter.EffectDeny, SourceID: "pdp-1", DecidedAt: now.Add(time.Hour)}, nil),
			authzCase(outNotAllowed, Expect{}), []string{"DecidedAt is", "later than the allowed"}},
		{"decided at the skew edge", authzFake(with(func(d *adapter.Decision) { d.DecidedAt = now.Add(skew) }), nil),
			authzCase(outAllow, Expect{}), nil},
		{"decided past the skew", authzFake(with(func(d *adapter.Decision) { d.DecidedAt = now.Add(skew + time.Second) }), nil),
			authzCase(outAllow, Expect{}), []string{"later than the allowed"}},
		{"no decision time", authzFake(with(func(d *adapter.Decision) { d.DecidedAt = time.Time{} }), nil),
			authzCase(outAllow, Expect{}), nil},

		{"another source", authzFake(with(func(d *adapter.Decision) { d.SourceID = "pdp-2" }), nil), authzCase(outAllow, all),
			[]string{`decision source id is "pdp-2", want "pdp-1"`}},
		{"record dropped", authzFake(with(func(d *adapter.Decision) { d.SourceRef = "" }), nil), authzCase(outAllow, all),
			[]string{`decision source ref is "", want "decision-8f0d"`}},
		{"revision rewritten", authzFake(with(func(d *adapter.Decision) { d.PolicyRevision = "policy-2026-09-01" }), nil), authzCase(outAllow, all),
			[]string{`policy revision is "policy-2026-09-01", want "policy-2026-10-01"`}},
		{"revision dropped", authzFake(with(func(d *adapter.Decision) { d.PolicyRevision = "" }), nil), authzCase(outAllow, all),
			[]string{"policy revision is"}},
		{"decision restamped", authzFake(with(func(d *adapter.Decision) { d.DecidedAt = now }), nil), authzCase(outAllow, all),
			[]string{"DecidedAt is", "not the time of the read"}},
		{"decision time dropped", authzFake(with(func(d *adapter.Decision) { d.DecidedAt = time.Time{} }), nil), authzCase(outAllow, all),
			[]string{"DecidedAt is the zero time"}},
		{"decision time supplied where the source gives none", authzFake(full, nil),
			authzCase(outAllow, pinned(ExpectDecision{DecidedAt: rawJSON(`null`)})), []string{"want the zero time"}},
		{"record supplied where the source keeps none", authzFake(full, nil),
			authzCase(outAllow, pinned(ExpectDecision{SourceRef: rawJSON(`null`)})), []string{`decision source ref is "decision-8f0d", want none`}},
		{"no record where the source keeps none", authzFake(with(func(d *adapter.Decision) { d.SourceRef = "" }), nil),
			authzCase(outAllow, pinned(ExpectDecision{SourceRef: rawJSON(` null `)})), nil},
		{"an empty record is not checked", authzFake(full, nil),
			authzCase(outAllow, pinned(ExpectDecision{SourceRef: rawJSON(`""`)})), nil},
		{"a record that is not a string", authzFake(full, nil),
			authzCase(outAllow, pinned(ExpectDecision{SourceRef: rawJSON(`7`)})), []string{"source_ref: expected value 7 is not a string or null"}},
		{"provenance is checked with the effect", authzFake(with(func(d *adapter.Decision) { d.SourceID = "pdp-2" }), nil),
			authzCase(outAllow, pinned(ExpectDecision{SourceID: "pdp-1", Obligations: &[]ObligationJSON{}})), []string{"decision source id is"}},
	})
}
