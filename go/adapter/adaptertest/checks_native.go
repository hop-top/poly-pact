package adaptertest

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// claim runs a read_native_claim case.
func (r *run) claim(ctx context.Context) {
	k := &r.c.Call
	cc := adapter.ClaimContext{Principal: r.principal()}
	if k.Intent != nil {
		cc.Intent = *k.Intent
	}
	if k.Operation != nil {
		cc.Operation = *k.Operation
	}
	var (
		c   adapter.NativeClaim
		err error
	)
	if !r.guard("ReadNativeClaim", func() {
		c, err = r.subj.Adapter.ReadNativeClaim(ctx, k.NativePath, cc)
	}) {
		return
	}
	r.scanError("ReadNativeClaim", err)
	if err == nil {
		r.scanValue("ReadNativeClaim claim", c)
	}

	e := &r.c.Expect
	switch e.Outcome {
	case outClaim:
		if err != nil {
			r.failf("ReadNativeClaim returned %v, want a claim", err)
			return
		}
		r.checkClaimInvariants(c)
		r.checkClaim(c, e.Claim)
	case outError:
		if err == nil {
			r.failf("ReadNativeClaim returned a claim, want an error")
			return
		}
		r.wantReason("ReadNativeClaim", err)
	}
}

// checkClaimInvariants checks what holds for every claim an adapter returns:
// ObservedAt is the original observation and StatusCheckedAt a check that took
// place, and neither lies beyond the allowed skew in the future ("No source
// observation or status-check time may be later than now + clock_skew", draft
// A.2); and the source is named (draft 8.3, 17.1, 17.2).
func (r *run) checkClaimInvariants(c adapter.NativeClaim) {
	r.notAfter("ObservedAt", c.ObservedAt, r.now.Add(skew))
	r.notAfter("StatusCheckedAt", c.StatusCheckedAt, r.now.Add(skew))
	if c.SourceID == "" {
		r.failf("claim names no source")
	}
}

func (r *run) checkClaim(c adapter.NativeClaim, want *ExpectClaim) {
	if want == nil {
		return
	}
	if len(want.Value) > 0 {
		got, err := json.Marshal(c.Value)
		if err != nil {
			r.failf("claim value does not encode as JSON: %v", err)
		} else if eq, err := jsonEqual(want.Value, got); err != nil {
			r.failf("claim value: %v", err)
		} else if !eq {
			r.failf("claim value is %s, want %s", got, want.Value)
		}
	}
	r.wantTime("ObservedAt", want.ObservedAt, c.ObservedAt)
	r.wantTime("StatusCheckedAt", want.StatusCheckedAt, c.StatusCheckedAt)
	if want.SourceID != "" && c.SourceID != want.SourceID {
		r.failf("source id is %q, want %q", c.SourceID, want.SourceID)
	}
	if want.SourceRef != "" && c.SourceRef != want.SourceRef {
		r.failf("source ref is %q, want %q", c.SourceRef, want.SourceRef)
	}
}

// check runs a check_context case.
func (r *run) check(ctx context.Context) {
	k := &r.c.Call
	in := adapter.CheckInput{
		Principal:    r.principal(),
		Operation:    *k.Operation,
		EvidenceRefs: k.EvidenceRefs,
	}
	if k.Intent != nil {
		in.Intent = *k.Intent
	}
	if b := k.Binding; b != nil {
		in.Binding = adapter.AgentBinding{
			AgentID:    b.AgentID,
			OperatorID: b.OperatorID,
			HolderJKT:  core.Digest(b.HolderJKT),
			Status:     adapter.BindingStatus(b.Status),
		}
		if b.Status == "" {
			in.Binding.Status = adapter.BindingActive
		}
	}
	var out adapter.CheckOutcome
	if !r.guard("CheckContext", func() {
		out = r.subj.Adapter.CheckContext(ctx, *k.CheckID, in)
	}) {
		return
	}
	r.scanValue("CheckContext outcome", out)

	e := &r.c.Expect
	if !out.Result.Valid() {
		r.failf("check result %q is not PASS, FAIL or UNKNOWN", out.Result)
	} else if string(out.Result) != e.Outcome {
		r.failf("check %q returned %s (%s), want %s: a check the adapter did not perform is never PASS", *k.CheckID, out.Result, out.ReasonCode, e.Outcome)
	}
	if out.ReasonCode == "" {
		r.failf("check returned no reason code")
	}
	if e.ReasonCode != "" && out.ReasonCode != e.ReasonCode {
		r.failf("check reason code is %q, want %q", out.ReasonCode, e.ReasonCode)
	}
	r.notAfter("check ObservedAt", out.ObservedAt, r.now.Add(skew))
}

// authorize runs an authorize_native case.
func (r *run) authorize(ctx context.Context) {
	k := &r.c.Call
	p := r.principal()
	var (
		d   adapter.Decision
		err error
	)
	if !r.guard("AuthorizeNative", func() {
		d, err = r.subj.Adapter.AuthorizeNative(ctx, p, *k.Operation)
	}) {
		return
	}
	r.scanError("AuthorizeNative", err)
	if err == nil {
		r.scanValue("AuthorizeNative decision", d)
	}

	e := &r.c.Expect
	if err == nil {
		r.checkDecisionInvariants(d)
	}
	switch e.Outcome {
	case outAllow, outDeny, outUnknown:
		if err != nil {
			r.failf("AuthorizeNative returned %v, want effect %s", err, e.Outcome)
			return
		}
		if string(d.Effect) != e.Outcome {
			r.failf("decision effect is %s, want %s: a native decision is returned as it is, and PACT cannot rewrite a denial", d.Effect, e.Outcome)
		}
		r.checkDecision(d, e.Decision)
	case outNotAllowed:
		if err == nil && d.Permits() {
			r.failf("decision is %s, want anything but ALLOW: the policy holds no rule that allows this principal", d.Effect)
		}
	case outError:
		if err == nil {
			r.failf("AuthorizeNative returned %s, want an error", d.Effect)
			return
		}
		r.wantReason("AuthorizeNative", err)
	}
}

// checkDecisionInvariants checks what holds for every decision an adapter
// returns: the effect is one of the three, the policy source that decided is
// named, and the decision time cannot lie beyond the allowed skew in the
// future (draft 7.5, 17.1, A.2).
func (r *run) checkDecisionInvariants(d adapter.Decision) {
	if !d.Effect.Valid() {
		r.failf("decision effect %q is not ALLOW, DENY or UNKNOWN", d.Effect)
	}
	if d.SourceID == "" {
		r.failf("decision names no source: every native decision names the policy source that decided")
	}
	r.notAfter("DecidedAt", d.DecidedAt, r.now.Add(skew))
}

func (r *run) checkDecision(d adapter.Decision, want *ExpectDecision) {
	if want == nil {
		return
	}
	if want.SourceID != "" && d.SourceID != want.SourceID {
		r.failf("decision source id is %q, want %q", d.SourceID, want.SourceID)
	}
	r.wantRecord(want.SourceRef, d.SourceRef)
	r.wantTime("DecidedAt", want.DecidedAt, d.DecidedAt)
	if want.PolicyRevision != "" && d.PolicyRevision != want.PolicyRevision {
		r.failf("policy revision is %q, want %q: the revision is reported as the source gave it", d.PolicyRevision, want.PolicyRevision)
	}
	if want.Obligations == nil {
		return
	}
	var wantObs []adapter.Obligation
	for _, o := range *want.Obligations {
		wantObs = append(wantObs, adapter.Obligation{ID: o.ID, Attributes: o.Attributes})
	}
	if !sameObligations(d.Obligations, wantObs) {
		r.failf("obligations are %s, want %s", jsonText(d.Obligations), jsonText(wantObs))
	}
}

// sameObligations compares obligations as JSON data, in order; a nil and an
// empty attribute map are the same.
func sameObligations(a, b []adapter.Obligation) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
		aa, bb := a[i].Attributes, b[i].Attributes
		if len(aa) == 0 && len(bb) == 0 {
			continue
		}
		ja, errA := json.Marshal(aa)
		jb, errB := json.Marshal(bb)
		if errA != nil || errB != nil {
			return reflect.DeepEqual(aa, bb)
		}
		eq, err := jsonEqual(ja, jb)
		if err != nil || !eq {
			return false
		}
	}
	return true
}

// wantRecord compares the decision record of a decision with the expected
// source_ref: absent or an empty string is not checked, null requires an
// empty record, since the source keeps none, and any other string must be
// equal.
func (r *run) wantRecord(want json.RawMessage, got string) {
	if len(want) == 0 {
		return
	}
	if string(bytes.TrimSpace(want)) == "null" {
		if got != "" {
			r.failf("decision source ref is %q, want none: the source keeps no record of the decision and the adapter must not supply one", got)
		}
		return
	}
	var ref string
	if err := json.Unmarshal(want, &ref); err != nil {
		r.failf("source_ref: expected value %s is not a string or null", want)
		return
	}
	if ref != "" && got != ref {
		r.failf("decision source ref is %q, want %q", got, ref)
	}
}
