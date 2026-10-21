package adaptertest

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"

	"hop.top/pact-go/adapter"
)

// authenticate runs an authenticate_native case.
func (r *run) authenticate(ctx context.Context) {
	req, _ := r.request(ctx)
	if req == nil {
		return
	}
	var (
		p   adapter.Principal
		err error
	)
	if !r.guard("AuthenticateNative", func() {
		p, err = r.subj.Adapter.AuthenticateNative(req.Context(), req)
	}) {
		return
	}
	r.scanError("AuthenticateNative", err)
	if err == nil {
		r.scanValue("AuthenticateNative principal", p)
	}

	e := &r.c.Expect
	switch e.Outcome {
	case outAuthenticated:
		if err != nil {
			r.failf("AuthenticateNative returned %v, want an authenticated principal", err)
			return
		}
		r.checkPrincipal(p, e.Principal)
	case outDenied:
		r.wantDenial(p, err)
	case outError:
		if err == nil {
			r.failf("AuthenticateNative authenticated %q, want an error", p.ID)
			return
		}
		r.wantReason("AuthenticateNative", err)
		r.noPrincipal(p)
	}
	if err == nil && principalEmpty(p) {
		r.failf("AuthenticateNative returned a zero principal with a nil error")
	}
}

// noPrincipal fails when a principal comes back with an error.
func (r *run) noPrincipal(p adapter.Principal) {
	if !principalEmpty(p) {
		r.failf("AuthenticateNative returned principal %q together with an error", p.ID)
	}
}

// wantDenial checks a native denial: a *NativeDenial that is an INVALID_PROOF
// and carries no principal.
func (r *run) wantDenial(p adapter.Principal, err error) {
	if err == nil {
		r.failf("AuthenticateNative authenticated %q, want a native denial", p.ID)
		return
	}
	var d *adapter.NativeDenial
	if !errors.As(err, &d) {
		r.failf("AuthenticateNative returned %T (%v), want a *NativeDenial", err, err)
		return
	}
	if !errors.Is(err, adapter.ErrInvalidProof) {
		r.failf("denial is not an ErrInvalidProof")
	}
	if code, ok := adapter.CodeOf(err); !ok || code != adapter.CodeInvalidProof {
		r.failf("denial code is %q, want %s", code, adapter.CodeInvalidProof)
	}
	if want := r.c.Expect.ReasonCode; want != "" && string(d.PublicReason()) != want {
		r.failf("denial reason is %s, want %s", d.PublicReason(), want)
	}
	r.noPrincipal(p)
}

// checkPrincipal checks an authenticated principal against the case.
func (r *run) checkPrincipal(p adapter.Principal, want *ExpectPrincipal) {
	if principalEmpty(p) {
		return
	}
	if want.ID != "" && p.ID != want.ID {
		r.failf("principal id is %q, want %q", p.ID, want.ID)
	}
	if want.Realm != nil {
		got := RealmJSON{TenantID: p.Realm.TenantID, EnvironmentID: p.Realm.EnvironmentID}
		if got != *want.Realm {
			r.failf("principal realm is %+v, want %+v", got, *want.Realm)
		}
	}
	if want.Workload != "" && string(p.Workload) != want.Workload {
		r.failf("principal workload is %q, want %q", p.Workload, want.Workload)
	}
	if want.Mechanism != "" && string(p.Mechanism) != want.Mechanism {
		r.failf("principal mechanism is %q, want %q", p.Mechanism, want.Mechanism)
	}
	r.checkAttributes(p.Attributes, want.Attributes)
	r.notAfter("principal AuthenticatedAt", p.AuthenticatedAt, r.now.Add(skew))
}

// binding runs a resolve_agent_binding case.
func (r *run) binding(ctx context.Context) {
	k := &r.c.Call
	realm := adapter.Realm{TenantID: k.Realm.TenantID, EnvironmentID: k.Realm.EnvironmentID}
	var (
		b   adapter.AgentBinding
		err error
	)
	if !r.guard("ResolveAgentBinding", func() {
		b, err = r.subj.Adapter.ResolveAgentBinding(ctx, realm, adapter.Workload(k.Workload), adapter.AgentID(k.AgentID))
	}) {
		return
	}
	r.scanError("ResolveAgentBinding", err)

	e := &r.c.Expect
	if err == nil && !b.Status.Valid() {
		r.failf("binding status %q is not a defined status", b.Status)
	}
	r.checkElsewhereOnlyWithUnknown(b, err)
	switch e.Outcome {
	case outBound:
		if err != nil {
			r.failf("ResolveAgentBinding returned %v, want an active binding", err)
			return
		}
		r.checkBound(b, e.Binding)
	case outNotEnrolled:
		switch {
		case err != nil:
			r.failf("ResolveAgentBinding returned %v, want status UNKNOWN with no error", err)
		case b.Status != adapter.BindingUnknown:
			r.failf("binding status is %s, want UNKNOWN: no binding exists in this realm", b.Status)
		case !bindingEmpty(b):
			r.failf("binding of status UNKNOWN names agent %q and a holder key; it must name none", b.AgentID)
		default:
			r.checkElsewhere(b, e.Binding)
		}
	case outUnusable:
		r.checkUnusable(b, err)
	case outError:
		if err == nil {
			r.failf("ResolveAgentBinding returned a %s binding, want an error", b.Status)
			return
		}
		r.wantReason("ResolveAgentBinding", err)
		if !bindingEmpty(b) {
			r.failf("ResolveAgentBinding returned binding for agent %q together with an error", b.AgentID)
		}
	}
}

// checkElsewhereOnlyWithUnknown checks what holds for every result: only a
// nil-error UNKNOWN reports the agent ID enrolled for another workload of the
// realm (draft 17.1). A binding on the authenticated workload, revoked and
// compromised ones included, never carries the report, and neither does an
// error.
func (r *run) checkElsewhereOnlyWithUnknown(b adapter.AgentBinding, err error) {
	switch {
	case !b.EnrolledElsewhere:
	case err != nil:
		r.failf("ResolveAgentBinding reports the agent ID enrolled for another workload together with an error")
	case b.Status != adapter.BindingUnknown:
		r.failf("binding of status %s reports the agent ID enrolled for another workload; only an UNKNOWN result carries that report (draft 17.1)", b.Status)
	}
}

// checkElsewhere compares the report that the agent ID is enrolled for another
// workload of the realm with the case, when the case requires a value.
func (r *run) checkElsewhere(b adapter.AgentBinding, want *ExpectBinding) {
	if want == nil || want.EnrolledElsewhere == nil {
		return
	}
	if b.EnrolledElsewhere != *want.EnrolledElsewhere {
		r.failf("agent ID enrolled for another workload is %t, want %t (draft 17.1)", b.EnrolledElsewhere, *want.EnrolledElsewhere)
	}
}

// checkBound checks an active binding against the case and the invariants of
// every binding the adapter calls active.
func (r *run) checkBound(b adapter.AgentBinding, want *ExpectBinding) {
	if b.Status != adapter.BindingActive {
		r.failf("binding status is %s, want ACTIVE", b.Status)
	}
	r.checkRecord(b, want)
}

// checkRecord checks a binding that names an enrollment record, active,
// revoked or compromised, against the case: the record's agent, operator and
// holder key, a named source, and times within the skew.
func (r *run) checkRecord(b adapter.AgentBinding, want *ExpectBinding) {
	if u, err := url.Parse(b.AgentID); err != nil || !u.IsAbs() {
		r.failf("agent id %q is not an absolute URI (draft 6.1)", b.AgentID)
	}
	if err := b.HolderJKT.Validate(); err != nil {
		r.failf("holder key thumbprint: %v", err)
	}
	if b.SourceID == "" {
		r.failf("binding names no source")
	}
	// Draft A.2: no source observation or status-check time may be later
	// than now plus the skew.
	r.notAfter("binding ObservedAt", b.ObservedAt, r.now.Add(skew))
	r.notAfter("binding StatusCheckedAt", b.StatusCheckedAt, r.now.Add(skew))
	if want == nil {
		return
	}
	if want.AgentID != "" && b.AgentID != want.AgentID {
		r.failf("agent id is %q, want %q", b.AgentID, want.AgentID)
	}
	if want.OperatorID != "" && b.OperatorID != want.OperatorID {
		r.failf("operator id is %q, want %q", b.OperatorID, want.OperatorID)
	}
	if want.HolderJKT != "" && string(b.HolderJKT) != want.HolderJKT {
		r.failf("holder key thumbprint is %q, want %q", b.HolderJKT, want.HolderJKT)
	}
	if want.Status != "" && string(b.Status) != want.Status {
		r.failf("binding status is %s, want %s", b.Status, want.Status)
	}
	r.checkElsewhere(b, want)
}

// checkUnusable checks the result for a binding the source holds as revoked or
// compromised: no result that a caller can use as an active binding.
//
// Identity mapping IM-11 fixes the form: resolve_agent_binding returns the
// record's status, REVOKED or COMPROMISED, with the agent, operator and holder
// key, and no error, so that a validator can state the reason (IM-29) and
// tell a revocation from a compromise. An error is not accepted: it hides the
// status, and an unavailable source would defer a request that must be
// refused. The call must never return an ACTIVE binding.
func (r *run) checkUnusable(b adapter.AgentBinding, err error) {
	want := r.c.Expect.Binding
	if err != nil {
		status := "REVOKED or COMPROMISED"
		if want != nil && want.Status != "" {
			status = want.Status
		}
		if isDependencyUnavailable(err) {
			r.failf("a revoked or compromised binding was reported as an unavailable source (%v); that defers instead of refusing", err)
		}
		r.failf("ResolveAgentBinding returned %v, want the binding with status %s, its agent, operator and holder key, and no error (identity mapping IM-11)", err, status)
		return
	}
	switch b.Status {
	case adapter.BindingRevoked, adapter.BindingCompromised:
		r.checkRecord(b, want)
	case adapter.BindingActive:
		r.failf("ResolveAgentBinding returned an ACTIVE binding for agent %q whose binding the source holds as revoked or compromised", b.AgentID)
	default:
		r.failf("binding status is %s, want REVOKED or COMPROMISED with the agent, operator and holder key of the record (identity mapping IM-11)", b.Status)
	}
}

// checkAttributes compares the authenticated attributes the case names with
// those of the principal, each as JSON data: object member order is ignored,
// array order is not (draft 8.4). An attribute the case does not name is not
// checked.
func (r *run) checkAttributes(got map[string]any, want json.RawMessage) {
	if len(want) == 0 {
		return
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(want, &members); err != nil {
		r.failf("expect.principal.attributes: %v", err)
		return
	}
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		v, ok := got[name]
		if !ok {
			r.failf("principal has no attribute %q, want %s", name, members[name])
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			r.failf("principal attribute %q does not encode as JSON: %v", name, err)
			continue
		}
		if eq, err := jsonEqual(members[name], raw); err != nil {
			r.failf("principal attribute %q: %v", name, err)
		} else if !eq {
			r.failf("principal attribute %q is %s, want %s", name, raw, members[name])
		}
	}
}
