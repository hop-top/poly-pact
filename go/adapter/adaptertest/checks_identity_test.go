package adaptertest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
)

func authCase(outcome string, e Expect) *Case {
	e.Function, e.Outcome = fnAuthenticate, outcome
	return &Case{
		Request: &Request{Method: "GET", URL: "https://gateway.example/invoices/1", NativeStateRef: "alice"},
		Expect:  e,
	}
}

func authFake(p adapter.Principal, err error) *fake {
	return &fake{auth: func(context.Context, *http.Request) (adapter.Principal, error) { return p, err }}
}

func TestAuthenticateChecks(t *testing.T) {
	good := goodPrincipal()
	want := &ExpectPrincipal{ID: good.ID, Realm: &acmeJS, Workload: "w-1", Mechanism: "bearer"}
	with := func(f func(*adapter.Principal)) adapter.Principal {
		p := good
		f(&p)
		return p
	}
	denial := &adapter.NativeDenial{Reason: adapter.DenialNoCredential}

	runRows(t, []row{
		{"authenticated", authFake(good, nil), authCase(outAuthenticated, Expect{Principal: want}), nil},
		{"authenticated but errors", authFake(adapter.Principal{}, denial), authCase(outAuthenticated, Expect{Principal: want}),
			[]string{"want an authenticated principal"}},
		{"wrong id", authFake(with(func(p *adapter.Principal) { p.ID = "other" }), nil),
			authCase(outAuthenticated, Expect{Principal: want}), []string{"principal id"}},
		{"wrong tenant", authFake(with(func(p *adapter.Principal) { p.Realm.TenantID = "globex" }), nil),
			authCase(outAuthenticated, Expect{Principal: want}), []string{"principal realm"}},
		{"wrong environment", authFake(with(func(p *adapter.Principal) { p.Realm.EnvironmentID = "other" }), nil),
			authCase(outAuthenticated, Expect{Principal: want}), []string{"principal realm"}},
		{"wrong workload", authFake(with(func(p *adapter.Principal) { p.Workload = "w-2" }), nil),
			authCase(outAuthenticated, Expect{Principal: want}), []string{"principal workload"}},
		{"wrong mechanism", authFake(with(func(p *adapter.Principal) { p.Mechanism = "mtls" }), nil),
			authCase(outAuthenticated, Expect{Principal: want}), []string{"principal mechanism"}},
		{"authenticated in the future", authFake(with(func(p *adapter.Principal) { p.AuthenticatedAt = now.Add(time.Minute) }), nil),
			authCase(outAuthenticated, Expect{Principal: want}), []string{"AuthenticatedAt"}},
		{"authenticated at the skew edge", authFake(with(func(p *adapter.Principal) { p.AuthenticatedAt = now.Add(skew) }), nil),
			authCase(outAuthenticated, Expect{Principal: want}), nil},
		{"zero principal without error", authFake(adapter.Principal{}, nil),
			authCase(outAuthenticated, Expect{Principal: &ExpectPrincipal{}}), []string{"zero principal"}},

		{"denied", authFake(adapter.Principal{}, denial), authCase(outDenied, Expect{ReasonCode: "NO_CREDENTIAL"}), nil},
		{"denied through wrapping", authFake(adapter.Principal{}, fmt.Errorf("authn: %w", denial)),
			authCase(outDenied, Expect{ReasonCode: "NO_CREDENTIAL"}), nil},
		{"denied but authenticated", authFake(good, nil), authCase(outDenied, Expect{}), []string{"want a native denial"}},
		{"denied with a plain error", authFake(adapter.Principal{}, errors.New("no")), authCase(outDenied, Expect{}),
			[]string{"want a *NativeDenial"}},
		{"denied with the wrong reason", authFake(adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}),
			authCase(outDenied, Expect{ReasonCode: "NO_CREDENTIAL"}), []string{"denial reason is CREDENTIAL_REJECTED"}},
		{"denied with free text is a rejection", authFake(adapter.Principal{}, &adapter.NativeDenial{Reason: "user alice unknown"}),
			authCase(outDenied, Expect{ReasonCode: "NO_CREDENTIAL"}), []string{"denial reason is CREDENTIAL_REJECTED"}},
		{"denied with a principal attached", authFake(good, denial), authCase(outDenied, Expect{}),
			[]string{"together with an error"}},

		{"error with a code", authFake(adapter.Principal{}, fmt.Errorf("x: %w", adapter.ErrDependencyUnavailable)),
			authCase(outError, Expect{ReasonCode: "DEPENDENCY_UNAVAILABLE"}), nil},
		{"error expected, none returned", authFake(good, nil), authCase(outError, Expect{}), []string{"want an error"}},
		{"error with the wrong code", authFake(adapter.Principal{}, adapter.ErrContextMismatch),
			authCase(outError, Expect{ReasonCode: "DEPENDENCY_UNAVAILABLE"}), []string{"error code is CONTEXT_MISMATCH"}},
		{"error without a code", authFake(adapter.Principal{}, errors.New("boom")),
			authCase(outError, Expect{ReasonCode: "DEPENDENCY_UNAVAILABLE"}), []string{"carries no draft 13.4 code"}},
		{"error with a principal", authFake(good, adapter.ErrContextMismatch), authCase(outError, Expect{}),
			[]string{"together with an error"}},
	})
}

func bindCase(outcome string, e Expect) *Case {
	e.Function, e.Outcome = fnBinding, outcome
	return &Case{Call: Call{Realm: &acmeJS, Workload: "w-1", AgentID: "https://identity.example/agents/a"}, Expect: e}
}

func bindFake(b adapter.AgentBinding, err error) *fake {
	return &fake{bind: func(context.Context, adapter.Realm, adapter.Workload, adapter.AgentID) (adapter.AgentBinding, error) {
		return b, err
	}}
}

// TestBindingCallArguments: the suite hands ResolveAgentBinding the realm, the
// workload and the agent ID of the call, unchanged (draft 17.1).
func TestBindingCallArguments(t *testing.T) {
	var (
		gotRealm    adapter.Realm
		gotWorkload adapter.Workload
		gotAgent    adapter.AgentID
		calls       int
	)
	f := &fake{bind: func(_ context.Context, r adapter.Realm, w adapter.Workload, a adapter.AgentID) (adapter.AgentBinding, error) {
		gotRealm, gotWorkload, gotAgent = r, w, a
		calls++
		return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
	}}
	c := bindCase(outNotEnrolled, Expect{})
	c.Call.Workload = "k8s:prod-eu-1:system:serviceaccount:payments:agent-runner"
	c.Call.AgentID = "https://identity.example/agents/payments-runner-b"
	wantClean(t, runFake(t, f, c))
	if calls != 1 {
		t.Fatalf("ResolveAgentBinding called %d times, want once", calls)
	}
	if gotRealm != acme {
		t.Errorf("realm = %+v, want %+v", gotRealm, acme)
	}
	if gotWorkload != "k8s:prod-eu-1:system:serviceaccount:payments:agent-runner" {
		t.Errorf("workload = %q", gotWorkload)
	}
	if gotAgent != "https://identity.example/agents/payments-runner-b" {
		t.Errorf("agent = %q, want the call's agent_id", gotAgent)
	}
}

func goodBinding() adapter.AgentBinding {
	return adapter.AgentBinding{
		AgentID: "https://identity.example/agents/a", OperatorID: "https://identity.example/operators/o",
		HolderJKT: "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M", Status: adapter.BindingActive,
		ObservedAt: now.Add(-time.Hour), StatusCheckedAt: now.Add(-time.Minute), SourceID: "registry",
	}
}

func TestBindingChecks(t *testing.T) {
	good := goodBinding()
	wantBound := Expect{Binding: &ExpectBinding{
		AgentID: good.AgentID, OperatorID: good.OperatorID, HolderJKT: string(good.HolderJKT), Status: "ACTIVE",
	}}
	with := func(f func(*adapter.AgentBinding)) adapter.AgentBinding {
		b := good
		f(&b)
		return b
	}
	revoked := with(func(b *adapter.AgentBinding) { b.Status = adapter.BindingRevoked })
	compromised := with(func(b *adapter.AgentBinding) { b.Status = adapter.BindingCompromised })
	wantStatus := func(s string) Expect {
		return Expect{Binding: &ExpectBinding{
			AgentID: good.AgentID, OperatorID: good.OperatorID, HolderJKT: string(good.HolderJKT), Status: s,
		}}
	}
	wantRevoked, wantCompromised := wantStatus("REVOKED"), wantStatus("COMPROMISED")
	boundErr := fmt.Errorf("binding: %w", adapter.ErrInvalidProof)

	runRows(t, []row{
		{"bound", bindFake(good, nil), bindCase(outBound, wantBound), nil},
		{"bound but errors", bindFake(adapter.AgentBinding{}, boundErr), bindCase(outBound, wantBound), []string{"want an active binding"}},
		{"bound but revoked", bindFake(revoked, nil), bindCase(outBound, wantBound), []string{"want ACTIVE"}},
		{"agent id is not a URI", bindFake(with(func(b *adapter.AgentBinding) { b.AgentID = "agent-1" }), nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{}}), []string{"not an absolute URI"}},
		{"holder key is not a thumbprint", bindFake(with(func(b *adapter.AgentBinding) { b.HolderJKT = "short" }), nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{}}), []string{"holder key thumbprint"}},
		{"no source", bindFake(with(func(b *adapter.AgentBinding) { b.SourceID = "" }), nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{}}), []string{"names no source"}},
		{"observed in the future", bindFake(with(func(b *adapter.AgentBinding) { b.ObservedAt = now.Add(time.Hour) }), nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{}}), []string{"binding ObservedAt"}},
		// Draft A.2: no status-check time may be later than now plus the skew.
		{"status checked past the skew", bindFake(with(func(b *adapter.AgentBinding) { b.StatusCheckedAt = now.Add(skew + time.Second) }), nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{}}), []string{"binding StatusCheckedAt"}},
		{"status checked at the skew edge", bindFake(with(func(b *adapter.AgentBinding) { b.StatusCheckedAt = now.Add(skew) }), nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{}}), nil},
		{"wrong agent", bindFake(good, nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{AgentID: "https://other.example/a"}}), []string{"agent id is"}},
		{"wrong operator", bindFake(good, nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{OperatorID: "https://other.example/o"}}), []string{"operator id is"}},
		{"wrong holder key", bindFake(good, nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{HolderJKT: "yy0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}}),
			[]string{"holder key thumbprint is"}},
		{"undefined status", bindFake(with(func(b *adapter.AgentBinding) { b.Status = "SUSPENDED" }), nil),
			bindCase(outBound, Expect{Binding: &ExpectBinding{}}), []string{"not a defined status"}},

		{"not enrolled", bindFake(adapter.AgentBinding{Status: adapter.BindingUnknown}, nil), bindCase(outNotEnrolled, Expect{}), nil},
		{"not enrolled but active", bindFake(good, nil), bindCase(outNotEnrolled, Expect{}), []string{"want UNKNOWN"}},
		{"not enrolled but errors", bindFake(adapter.AgentBinding{}, boundErr), bindCase(outNotEnrolled, Expect{}), []string{"status UNKNOWN with no error"}},
		{"not enrolled but names an agent", bindFake(with(func(b *adapter.AgentBinding) { b.Status = adapter.BindingUnknown }), nil),
			bindCase(outNotEnrolled, Expect{}), []string{"names agent"}},

		// Identity mapping IM-11: a REVOKED or COMPROMISED binding comes back
		// as its status, with the agent, operator and holder key of the
		// record, and a nil error.
		{"unusable as REVOKED", bindFake(revoked, nil), bindCase(outUnusable, wantRevoked), nil},
		{"unusable as COMPROMISED", bindFake(compromised, nil), bindCase(outUnusable, wantCompromised), nil},
		{"unusable as an error", bindFake(adapter.AgentBinding{}, boundErr), bindCase(outUnusable, wantRevoked),
			[]string{"want the binding with status REVOKED", "IM-11"}},
		{"unusable but ACTIVE", bindFake(good, nil), bindCase(outUnusable, wantRevoked), []string{"returned an ACTIVE binding"}},
		{"unusable but UNKNOWN", bindFake(adapter.AgentBinding{Status: adapter.BindingUnknown}, nil),
			bindCase(outUnusable, wantRevoked), []string{"want REVOKED or COMPROMISED"}},
		{"unusable as unavailable", bindFake(adapter.AgentBinding{}, fmt.Errorf("x: %w", adapter.ErrDependencyUnavailable)),
			bindCase(outUnusable, wantRevoked), []string{"unavailable source"}},
		{"unusable with a binding next to the error", bindFake(revoked, boundErr),
			bindCase(outUnusable, wantRevoked), []string{"IM-11"}},
		{"unusable with the wrong status", bindFake(revoked, nil),
			bindCase(outUnusable, wantCompromised), []string{"binding status is REVOKED, want COMPROMISED"}},
		{"unusable status without the agent", bindFake(with(func(b *adapter.AgentBinding) { b.Status, b.AgentID = adapter.BindingRevoked, "" }), nil),
			bindCase(outUnusable, Expect{Binding: &ExpectBinding{Status: "REVOKED"}}), []string{"not an absolute URI"}},
		{"unusable status without the holder key", bindFake(with(func(b *adapter.AgentBinding) { b.Status, b.HolderJKT = adapter.BindingRevoked, "" }), nil),
			bindCase(outUnusable, Expect{Binding: &ExpectBinding{Status: "REVOKED"}}), []string{"holder key thumbprint"}},
		{"unusable status that names no source", bindFake(with(func(b *adapter.AgentBinding) { b.Status, b.SourceID = adapter.BindingRevoked, "" }), nil),
			bindCase(outUnusable, Expect{Binding: &ExpectBinding{Status: "REVOKED"}}), []string{"names no source"}},
		{"unusable status checked past the skew", bindFake(with(func(b *adapter.AgentBinding) {
			b.Status, b.StatusCheckedAt = adapter.BindingRevoked, now.Add(skew+time.Second)
		}), nil), bindCase(outUnusable, Expect{Binding: &ExpectBinding{Status: "REVOKED"}}), []string{"binding StatusCheckedAt"}},
		{"unusable status of another agent", bindFake(with(func(b *adapter.AgentBinding) {
			b.Status, b.AgentID = adapter.BindingRevoked, "https://identity.example/agents/b"
		}), nil), bindCase(outUnusable, wantRevoked), []string{"agent id is"}},
		{"unusable status with another operator", bindFake(with(func(b *adapter.AgentBinding) {
			b.Status, b.OperatorID = adapter.BindingRevoked, "https://identity.example/operators/p"
		}), nil), bindCase(outUnusable, wantRevoked), []string{"operator id is"}},
		{"unusable status with another key", bindFake(with(func(b *adapter.AgentBinding) {
			b.Status, b.HolderJKT = adapter.BindingRevoked, "lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU"
		}), nil), bindCase(outUnusable, wantRevoked), []string{"holder key thumbprint is"}},

		{"error", bindFake(adapter.AgentBinding{}, boundErr), bindCase(outError, Expect{ReasonCode: "INVALID_PROOF"}), nil},
		{"error expected, binding returned", bindFake(good, nil), bindCase(outError, Expect{}), []string{"want an error"}},
		{"error with a binding", bindFake(good, boundErr), bindCase(outError, Expect{}), []string{"together with an error"}},
	})
}

// TestBindingEnrolledElsewhere: draft 17.1 has UNKNOWN come with whether the
// agent ID is enrolled for another workload of the realm. A case can require
// the value; the suite requires it false for every result that is not a
// nil-error UNKNOWN.
func TestBindingEnrolledElsewhere(t *testing.T) {
	yes, no := true, false
	unknown := adapter.AgentBinding{Status: adapter.BindingUnknown}
	elsewhere := adapter.AgentBinding{Status: adapter.BindingUnknown, EnrolledElsewhere: true}
	flagged := func(b adapter.AgentBinding) adapter.AgentBinding { b.EnrolledElsewhere = true; return b }
	good := goodBinding()
	revoked := good
	revoked.Status = adapter.BindingRevoked
	want := func(v *bool) Expect { return Expect{Binding: &ExpectBinding{EnrolledElsewhere: v}} }
	wantRecord := func(s string, v *bool) Expect {
		return Expect{Binding: &ExpectBinding{
			AgentID: good.AgentID, OperatorID: good.OperatorID, HolderJKT: string(good.HolderJKT), Status: s, EnrolledElsewhere: v,
		}}
	}
	boundErr := fmt.Errorf("binding: %w", adapter.ErrInvalidProof)

	runRows(t, []row{
		{"unknown, enrolled elsewhere as required", bindFake(elsewhere, nil), bindCase(outNotEnrolled, want(&yes)), nil},
		{"unknown, not enrolled elsewhere as required", bindFake(unknown, nil), bindCase(outNotEnrolled, want(&no)), nil},
		{"unknown, enrolled elsewhere not reported", bindFake(unknown, nil), bindCase(outNotEnrolled, want(&yes)),
			[]string{"enrolled for another workload is false, want true"}},
		{"unknown, enrolled elsewhere reported wrongly", bindFake(elsewhere, nil), bindCase(outNotEnrolled, want(&no)),
			[]string{"enrolled for another workload is true, want false"}},
		{"unknown, not required either way", bindFake(elsewhere, nil), bindCase(outNotEnrolled, Expect{}), nil},
		{"bound, false as required", bindFake(good, nil), bindCase(outBound, wantRecord("ACTIVE", &no)), nil},
		{"bound with the flag", bindFake(flagged(good), nil), bindCase(outBound, wantRecord("ACTIVE", nil)),
			[]string{"status ACTIVE reports the agent ID enrolled for another workload"}},
		{"unusable with the flag", bindFake(flagged(revoked), nil), bindCase(outUnusable, wantRecord("REVOKED", nil)),
			[]string{"status REVOKED reports the agent ID enrolled for another workload"}},
		{"error with the flag", bindFake(flagged(adapter.AgentBinding{}), boundErr), bindCase(outError, Expect{ReasonCode: "INVALID_PROOF"}),
			[]string{"enrolled for another workload together with an error"}},
		{"flag next to an error, outcome unknown", bindFake(flagged(adapter.AgentBinding{}), boundErr), bindCase(outNotEnrolled, Expect{}),
			[]string{"enrolled for another workload together with an error"}},
	})
}
