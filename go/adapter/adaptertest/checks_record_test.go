package adaptertest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

var enc = base64.RawURLEncoding

// parts are the pieces of a signed outcome that a test changes before they are
// put together.
type parts struct {
	hdr     map[string]any
	rep     core.OutcomeReport
	payload []byte // when set, replaces the marshaled report
}

func reportOf(o adapter.Observation) core.OutcomeReport {
	refs, sup := o.EvidenceRefs, o.Supersedes
	if refs == nil {
		refs = []string{}
	}
	if sup == nil {
		sup = []string{}
	}
	return core.OutcomeReport{
		PactVersion: core.Version, Issuer: "https://gateway.example/reporters/finance", Subject: o.Context.AgentID,
		Audience: "https://reputation.example/service", JTI: "AAAAAAAAAAAAAAAAAAAAAA",
		IssuedAt: now.Unix(), NotBefore: now.Unix(), Expiry: now.Unix() + 300,
		TenantID: o.Context.TenantID, EventID: o.EventID, EnvironmentID: o.Context.EnvironmentID,
		TaskID: o.TaskID, OperationID: o.OperationID, ObservedAt: o.ObservedAt.Unix(),
		ReporterRole: core.ReporterExecutor, Context: o.Context, EventKind: o.EventKind,
		Result: o.Result, Dimension: o.Dimension, Severity: o.Severity,
		EvidenceRefs: refs, Attribution: o.Attribution, Supersedes: sup, Details: o.Details,
	}
}

func (p parts) jws() string {
	hdr, _ := json.Marshal(p.hdr)
	payload := p.payload
	if payload == nil {
		payload, _ = json.Marshal(p.rep)
	}
	return enc.EncodeToString(hdr) + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("signature"))
}

// signedFake returns a fake that signs the observation it gets, after mod has
// changed the pieces.
func signedFake(mod func(*parts)) *fake {
	return &fake{record: func(_ context.Context, o adapter.Observation) (adapter.Recorded, error) {
		p := parts{
			hdr: map[string]any{"alg": "ES256", "kid": "reporter-key-1", "typ": "pact-outcome+jwt"},
			rep: reportOf(o),
		}
		if mod != nil {
			mod(&p)
		}
		return adapter.Signed{JWS: p.jws()}, nil
	}}
}

func recordFake(rec adapter.Recorded, err error) *fake {
	return &fake{record: func(context.Context, adapter.Observation) (adapter.Recorded, error) { return rec, err }}
}

func recordCase(outcome string, e Expect, kind core.EventKind, result core.OutcomeResult) *Case {
	e.Function, e.Outcome = fnRecord, outcome
	return &Case{
		Call: Call{Observation: &ObservationJSON{
			EventID: "event-1", EventKind: kind,
			Context: core.ReputationContext{TenantID: "acme", EnvironmentID: acme.EnvironmentID, AgentID: "https://identity.example/agents/a",
				PurposeID: "p", ActionClass: "a", ResourceClass: "r", RuntimeClass: "managed"},
			TaskID: "task-1", OperationID: "op-1", ObservedAt: now.Unix() - 5, Result: result,
			Dimension: core.DimensionReliability, Severity: core.SeverityInfo,
			EvidenceRefs: []string{"native-record:1"}, Supersedes: []string{},
			Attribution: core.Attribution{NativeTaskRef: "task-1", IndependenceGroup: "g", CausalAssessment: core.CausalUnknown},
		}},
		Expect: e,
	}
}

func TestRecordSignedChecks(t *testing.T) {
	exec := func(outcome string) *Case {
		return recordCase(outcome, Expect{}, core.EventExecution, core.OutcomeSuccess)
	}
	signedCase := exec(outSigned)

	runRows(t, []row{
		{"signed", signedFake(nil), signedCase, nil},
		{"signed but declares no visibility", recordFake(adapter.NoVisibility{Reason: "r"}, nil), signedCase, []string{"want a signed outcome"}},
		{"signed but errors", recordFake(nil, adapter.ErrDependencyUnavailable), signedCase, []string{"want signed"}},
		{"signed but nil", recordFake(nil, nil), signedCase, []string{"nil result"}},
		{"signed through a pointer", recordFake(&adapter.Signed{JWS: "a.b.c"}, nil), signedCase, []string{"not a pointer"}},
		{"not a compact JWS", recordFake(adapter.Signed{JWS: "abc"}, nil), signedCase, []string{"not a compact JWS"}},
		{"header is not base64url", recordFake(adapter.Signed{JWS: "!.e30.c2ln"}, nil), signedCase, []string{"header is not unpadded base64url"}},
		{"payload is not base64url", recordFake(adapter.Signed{JWS: "e30.!.c2ln"}, nil), signedCase, []string{"payload is not unpadded base64url"}},
		{"wrong typ", signedFake(func(p *parts) { p.hdr["typ"] = "JWT" }), signedCase, []string{"JWS typ is JWT"}},
		{"alg none", signedFake(func(p *parts) { p.hdr["alg"] = "none" }), signedCase, []string{"JWS alg is none"}},
		{"alg HS256", signedFake(func(p *parts) { p.hdr["alg"] = "HS256" }), signedCase, []string{"JWS alg is HS256"}},
		{"alg EdDSA", signedFake(func(p *parts) { p.hdr["alg"] = "EdDSA" }), signedCase, []string{"JWS alg is EdDSA"}},
		{"alg Ed25519", signedFake(func(p *parts) { p.hdr["alg"] = "Ed25519" }), signedCase, nil},
		{"no kid", signedFake(func(p *parts) { delete(p.hdr, "kid") }), signedCase, []string{"no kid"}},
		{"jku in header", signedFake(func(p *parts) { p.hdr["jku"] = "https://x.example/keys" }), signedCase, []string{`carries "jku"`}},
		{"payload is not an object", signedFake(func(p *parts) { p.payload = []byte(`[1]`) }), signedCase, []string{"not an outcome report"}},
		{"unknown member", signedFake(func(p *parts) {
			p.payload = []byte(`{"pact_version":"0.1","surprise":1}`)
		}), signedCase, []string{"not an outcome report"}},
		{"duplicate member", signedFake(func(p *parts) { p.payload = []byte(`{"jti":"a","jti":"b"}`) }), signedCase, []string{"not an outcome report"}},
		{"required member missing", signedFake(func(p *parts) {
			b, _ := json.Marshal(p.rep)
			var m map[string]json.RawMessage
			_ = json.Unmarshal(b, &m)
			delete(m, "evidence_refs")
			p.payload, _ = json.Marshal(m)
		}), signedCase, []string{`lacks the required member "evidence_refs"`}},
		{"array member null", signedFake(func(p *parts) { p.rep.Supersedes = nil }), signedCase, []string{"not an outcome report", "/supersedes"}},
		{"wrong pact version", signedFake(func(p *parts) { p.rep.PactVersion = "0.2" }), signedCase, []string{"pact_version"}},
		{"wrong event id", signedFake(func(p *parts) { p.rep.EventID = "other" }), signedCase, []string{"event_id"}},
		{"wrong operation id", signedFake(func(p *parts) { p.rep.OperationID = "other" }), signedCase, []string{"operation_id"}},
		{"wrong task id", signedFake(func(p *parts) { p.rep.TaskID = "other" }), signedCase, []string{"task_id"}},
		{"wrong kind", signedFake(func(p *parts) { p.rep.EventKind = core.EventQuality }), signedCase, []string{"event_kind"}},
		{"assumed result", signedFake(func(p *parts) { p.rep.Result = core.OutcomeFailure }), signedCase, []string{"result is"}},
		{"wrong dimension", signedFake(func(p *parts) { p.rep.Dimension = core.DimensionNone }), signedCase, []string{"dimension"}},
		{"wrong severity", signedFake(func(p *parts) { p.rep.Severity = core.SeverityHigh }), signedCase, []string{"severity"}},
		{"wrong tenant", signedFake(func(p *parts) { p.rep.TenantID = "globex" }), signedCase, []string{"tenant_id"}},
		{"wrong environment", signedFake(func(p *parts) { p.rep.EnvironmentID = "other" }), signedCase, []string{"environment_id"}},
		{"wrong subject", signedFake(func(p *parts) { p.rep.Subject = "https://x.example/agents/other" }), signedCase, []string{"sub is"}},
		{"restamped observation", signedFake(func(p *parts) { p.rep.ObservedAt = now.Unix() }), signedCase, []string{"original observation time"}},
		{"wrong context", signedFake(func(p *parts) { p.rep.Context.PurposeID = "other" }), signedCase, []string{"context is"}},
		{"undefined reporter role", signedFake(func(p *parts) { p.rep.ReporterRole = "robot" }), signedCase, []string{"reporter_role"}},
		{"short jti", signedFake(func(p *parts) { p.rep.JTI = "short" }), signedCase, []string{"jti has 5 characters"}},
		{"expired", signedFake(func(p *parts) { p.rep.Expiry = now.Unix() }), signedCase, []string{"validity"}},
		{"issued in the future", signedFake(func(p *parts) { p.rep.IssuedAt = now.Unix() + 60 }), signedCase, []string{"validity"}},
		{"valid for too long", signedFake(func(p *parts) { p.rep.Expiry = p.rep.IssuedAt + 301 }), signedCase, []string{"lifetime"}},
		{"no issuer", signedFake(func(p *parts) { p.rep.Issuer = "" }), signedCase, []string{"iss is empty"}},
		{"no audience", signedFake(func(p *parts) { p.rep.Audience = "" }), signedCase, []string{"aud is empty"}},
	})
}

func TestRecordOutcomes(t *testing.T) {
	exec := func(outcome string, result core.OutcomeResult) *Case {
		return recordCase(outcome, Expect{}, core.EventExecution, result)
	}
	noVis := adapter.NoVisibility{Reason: "execution happens in a system the adapter cannot observe"}

	runRows(t, []row{
		{"no visibility", recordFake(noVis, nil), exec(outNoVisibility, core.OutcomeUnknown), nil},
		{"no visibility but signed", signedFake(nil), exec(outNoVisibility, core.OutcomeUnknown), []string{"want a declared absence"}},
		{"no visibility without a reason", recordFake(adapter.NoVisibility{Reason: " "}, nil), exec(outNoVisibility, core.OutcomeUnknown),
			[]string{"no-visibility declaration"}},
		{"no visibility through a pointer", recordFake(&noVis, nil), exec(outNoVisibility, core.OutcomeUnknown), []string{"not a pointer"}},

		{"no success, declared", recordFake(noVis, nil), exec(outNoExecSuccess, core.OutcomeSuccess), nil},
		{"no success, assumed", signedFake(nil), exec(outNoExecSuccess, core.OutcomeSuccess), []string{"although the case gives the adapter no execution visibility"}},
		{"no success, unknown signed", signedFake(nil), exec(outNoExecSuccess, core.OutcomeUnknown), nil},
		{"no success, failure signed", signedFake(nil), exec(outNoExecSuccess, core.OutcomeFailure), nil},
		{"no success, admission signed", signedFake(nil), recordCase(outNoExecSuccess, Expect{}, core.EventAdmission, core.OutcomeSuccess), nil},
		{"no success, bad declaration", recordFake(adapter.NoVisibility{}, nil), exec(outNoExecSuccess, core.OutcomeSuccess),
			[]string{"no-visibility declaration"}},

		{"error", recordFake(nil, adapter.ErrUnsupportedRequirement), exec(outError, core.OutcomeSuccess), nil},
		{"error with a code", recordFake(nil, adapter.ErrUnsupportedRequirement),
			recordCase(outError, Expect{ReasonCode: "UNSUPPORTED_REQUIREMENT"}, core.EventQuality, core.OutcomeSuccess), nil},
		{"error expected, recorded", signedFake(nil), exec(outError, core.OutcomeSuccess), []string{"want an error"}},
		{"error of another code", recordFake(nil, errors.New("x")),
			recordCase(outError, Expect{ReasonCode: "UNSUPPORTED_REQUIREMENT"}, core.EventQuality, core.OutcomeSuccess), []string{"carries no draft 13.4 code"}},
	})

	t.Run("verification", func(t *testing.T) {
		f := signedFake(nil)
		verify := func(err error) Factory {
			return func(testing.TB, Env) (Subject, error) {
				s, _ := factoryFor(f)(t, Env{})
				s.VerifyOutcome = func(string) error { return err }
				return s, nil
			}
		}
		c := exec(outSigned, core.OutcomeSuccess)
		c.NativeState = []byte(`{}`)
		c.ID = "T-01"
		wantClean(t, runCase(t, verify(nil), c))
		wantFails(t, runCase(t, verify(errors.New("bad signature")), c), "signature of the outcome does not verify")
	})
}
