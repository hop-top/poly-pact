package adaptertest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/strictjson"
)

// outcomeTyp is the JWS typ of an outcome report (draft 7.3).
const outcomeTyp = "pact-outcome+jwt"

// observation returns the case's observation argument as the adapter type.
func (r *run) observation() adapter.Observation {
	o := r.c.Call.Observation
	return adapter.Observation{
		EventID:            o.EventID,
		EventKind:          o.EventKind,
		Context:            o.Context,
		TaskID:             o.TaskID,
		OperationID:        o.OperationID,
		AdmissionReceiptID: o.AdmissionReceiptID,
		ObservedAt:         time.Unix(o.ObservedAt, 0),
		Result:             o.Result,
		Dimension:          o.Dimension,
		Severity:           o.Severity,
		EvidenceRefs:       o.EvidenceRefs,
		Attribution:        o.Attribution,
		Supersedes:         o.Supersedes,
		Details:            o.Details,
	}
}

// record runs a record_outcome case.
func (r *run) record(ctx context.Context) {
	obs := r.observation()
	var (
		rec adapter.Recorded
		err error
	)
	if !r.guard("RecordOutcome", func() {
		rec, err = r.subj.Adapter.RecordOutcome(ctx, obs)
	}) {
		return
	}
	r.scanError("RecordOutcome", err)

	e := &r.c.Expect
	if e.Outcome == outError {
		if err == nil {
			r.failf("RecordOutcome recorded the observation, want an error")
			return
		}
		r.wantReason("RecordOutcome", err)
		return
	}
	if err != nil {
		r.failf("RecordOutcome returned %v, want %s", err, e.Outcome)
		return
	}
	switch v := rec.(type) {
	case nil:
		r.failf("RecordOutcome returned a nil result with a nil error")
	case adapter.Signed:
		r.signed(v, obs)
	case adapter.NoVisibility:
		r.noVisibility(v)
	default:
		r.failf("RecordOutcome returned %T; return the Signed or NoVisibility value, not a pointer or another type", rec)
	}
}

func (r *run) noVisibility(n adapter.NoVisibility) {
	r.scanText("RecordOutcome declaration", n.Reason)
	if err := n.Validate(); err != nil {
		r.failf("no-visibility declaration: %v", err)
	}
	switch r.c.Expect.Outcome {
	case outSigned:
		r.failf("RecordOutcome declared no visibility (%q), want a signed outcome", n.Reason)
	}
}

func (r *run) signed(s adapter.Signed, obs adapter.Observation) {
	e := &r.c.Expect
	if e.Outcome == outNoVisibility {
		r.failf("RecordOutcome returned a signed outcome, want a declared absence of visibility")
		return
	}
	if err := s.Validate(); err != nil {
		r.failf("signed outcome: %v", err)
		return
	}
	r.scanJWS("signed outcome", s.JWS)
	if r.subj.VerifyOutcome != nil {
		if err := r.subj.VerifyOutcome(s.JWS); err != nil {
			r.failf("signature of the outcome does not verify: %v", err)
		}
	}
	rep, ok := r.checkOutcomeJWS(s.JWS, obs)
	if !ok {
		return
	}
	if e.Outcome == outNoExecSuccess && rep.EventKind == core.EventExecution && rep.Result == core.OutcomeSuccess {
		r.failf("RecordOutcome signed an EXECUTION report with result SUCCESS although the case gives the adapter no execution visibility (draft 14.1: missing visibility is declared, never assumed to be success)")
	}
}

// checkOutcomeJWS decodes a compact JWS and checks it as an outcome report of
// the observation: the JOSE header of draft 7.2, a payload that strict-parses
// as a core.OutcomeReport with every required member, the fields the adapter
// does not choose, and the time rules of draft 7.5 and 14.3.
func (r *run) checkOutcomeJWS(jws string, obs adapter.Observation) (core.OutcomeReport, bool) {
	var rep core.OutcomeReport
	parts := strings.Split(jws, ".")
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		r.failf("JWS header is not unpadded base64url: %v", err)
		return rep, false
	}
	payRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		r.failf("JWS payload is not unpadded base64url: %v", err)
		return rep, false
	}

	var hdr map[string]any
	if err := strictjson.Unmarshal(hdrRaw, strictjson.Limits{MaxBytes: 4 << 10}, &hdr); err != nil {
		r.failf("JWS header: %v", err)
		return rep, false
	}
	if hdr["typ"] != outcomeTyp {
		r.failf("JWS typ is %v, want %s", hdr["typ"], outcomeTyp)
	}
	if alg := hdr["alg"]; alg != "ES256" && alg != "Ed25519" {
		r.failf("JWS alg is %v, want ES256 or Ed25519 (draft 7.2)", alg)
	}
	if kid, _ := hdr["kid"].(string); kid == "" {
		r.failf("JWS header has no kid: a service-signed artifact names its key")
	}
	for _, banned := range []string{"jku", "x5u", "jwk", "crit"} {
		if _, has := hdr[banned]; has {
			r.failf("JWS header carries %q, which an outcome report must not (draft 7.2)", banned)
		}
	}

	if err := strictjson.Unmarshal(payRaw, strictjson.Limits{MaxBytes: core.Defaults().ArtifactPayloadBytes}, &rep); err != nil {
		r.failf("JWS payload is not an outcome report: %v", err)
		return rep, false
	}
	r.requireMembers(payRaw)
	r.checkReport(rep, obs)
	return rep, true
}

// requireMembers fails for each member of the outcome report schema that the
// payload lacks. strictjson has already rejected a null where the schema wants
// an array or an object, but it does not require members to be present.
func (r *run) requireMembers(payload []byte) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		r.failf("JWS payload: %v", err)
		return
	}
	for f := range reflect.TypeFor[core.OutcomeReport]().Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" || strings.Contains(opts, "omitzero") || strings.Contains(opts, "omitempty") {
			continue
		}
		if _, ok := members[name]; !ok {
			r.failf("outcome report lacks the required member %q", name)
		}
	}
}

// checkReport checks the members of the report that the adapter does not
// choose against the observation, and the validity window.
func (r *run) checkReport(rep core.OutcomeReport, obs adapter.Observation) {
	if rep.PactVersion != core.Version {
		r.failf("pact_version is %q, want %q", rep.PactVersion, core.Version)
	}
	for _, c := range []struct {
		name      string
		got, want string
	}{
		{"event_id", rep.EventID, obs.EventID},
		{"operation_id", rep.OperationID, obs.OperationID},
		{"task_id", rep.TaskID, obs.TaskID},
		{"event_kind", string(rep.EventKind), string(obs.EventKind)},
		{"result", string(rep.Result), string(obs.Result)},
		{"dimension", string(rep.Dimension), string(obs.Dimension)},
		{"severity", string(rep.Severity), string(obs.Severity)},
		{"tenant_id", rep.TenantID, obs.Context.TenantID},
		{"environment_id", rep.EnvironmentID, obs.Context.EnvironmentID},
		{"sub", rep.Subject, obs.Context.AgentID},
	} {
		if c.got != c.want {
			r.failf("outcome report %s is %q, want %q from the observation", c.name, c.got, c.want)
		}
	}
	if rep.ObservedAt != obs.ObservedAt.Unix() {
		r.failf("outcome report observed_at is %d, want %d: the original observation time", rep.ObservedAt, obs.ObservedAt.Unix())
	}
	if !reflect.DeepEqual(rep.Context, obs.Context) {
		r.failf("outcome report context is %s, want the observation's %s", jsonText(rep.Context), jsonText(obs.Context))
	}
	if !rep.ReporterRole.Valid() {
		r.failf("reporter_role %q is not a defined role", rep.ReporterRole)
	}
	if len(rep.JTI) < 22 || len(rep.JTI) > 128 {
		r.failf("jti has %d characters, want 22 to 128", len(rep.JTI))
	}
	if err := clock.CheckWindow(rep.IssuedAt, rep.NotBefore, rep.Expiry, r.now, skew); err != nil {
		r.failf("outcome report validity: %v", err)
	}
	if err := clock.CheckLifetime(clock.Outcome, rep.IssuedAt, rep.Expiry); err != nil {
		r.failf("outcome report lifetime: %v", err)
	}
	for _, s := range []struct {
		name  string
		value string
	}{{"iss", rep.Issuer}, {"aud", rep.Audience}} {
		if s.value == "" {
			r.failf("outcome report %s is empty", s.name)
		}
	}
}
