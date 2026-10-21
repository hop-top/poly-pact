package learning

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
)

// trustResolver resolves the keys of a verification from the trust records
// of a case: the keys of the records of the typ's signer role whose iss is
// the payload's (draft Section 7.3).
type trustResolver struct {
	records []trustKeys
}

type trustKeys struct {
	iss  string
	role jws.Role
	keys []jws.JWK
}

func loadTrust(fixtures string, trust []evalcase.TrustRecord) (trustResolver, error) {
	var r trustResolver
	for _, t := range trust {
		tk := trustKeys{iss: t.Iss, role: t.Role}
		for _, k := range t.Keys {
			b, err := os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(k)))
			if err != nil {
				return r, err
			}
			jwk, err := jws.ParseJWK(b)
			if err != nil {
				return r, fmt.Errorf("%s: %w", k, err)
			}
			tk.keys = append(tk.keys, jwk)
		}
		r.records = append(r.records, tk)
	}
	return r, nil
}

func (r trustResolver) TrustedKeys(req jws.KeyRequest) (*jws.KeySet, error) {
	var claims struct {
		Iss string `json:"iss"`
	}
	var members map[string]any
	if err := strictjson.Unmarshal(req.Payload, strictjson.Limits{}, &members); err != nil {
		return nil, err
	}
	claims.Iss, _ = members["iss"].(string)
	var set []jws.JWK
	for _, rec := range r.records {
		if rec.role != req.Role || rec.iss != claims.Iss {
			continue
		}
		for _, k := range rec.keys {
			if !slices.ContainsFunc(set, func(s jws.JWK) bool { return s.Kid == k.Kid }) {
				set = append(set, k)
			}
		}
	}
	return jws.NewKeySet(set...)
}

func (trustResolver) HolderJKT(jws.KeyRequest) (core.Digest, error) {
	return "", fmt.Errorf("a learning message is service-signed")
}

// reporterRole returns the reporter_role claimed when a trust record of the
// reporter iss registers it, and "" otherwise (Appendix A.2): a signer
// registered for several roles has one record per role.
func reporterRole(trust []evalcase.TrustRecord, iss, claimed string) string {
	for _, t := range trust {
		if t.Role == jws.RoleReporter && t.Iss == iss && t.ReporterRole != nil && *t.ReporterRole == claimed {
			return claimed
		}
	}
	return ""
}

// signatureReasons are the reasons of a verification failure that mean the
// signer could not be authenticated (INVALID_PROOF, draft Section 13.4); any
// other failure, a typ other than the endpoint's among them, is a message
// that is not a well-formed JWS of the endpoint (INVALID_MESSAGE).
var signatureReasons = []jws.Reason{jws.ErrSignatureInvalid, jws.ErrKidUnknown, jws.ErrKeyUnavailable}

var stepTyp = map[evalcase.StepKind]string{
	evalcase.StepPolicy:   jws.TypLearningPolicy,
	evalcase.StepArtifact: jws.TypLearningArtifact,
	evalcase.StepEvent:    jws.TypLearningEvent,
	evalcase.StepOutcome:  jws.TypOutcome,
}

// Replay applies the steps of the case to a fresh Machine, as a learning
// service would: it verifies each signed input under the case's trust
// records (a failure is INVALID_PROOF, or INVALID_MESSAGE for a malformed
// message), decodes it and hands it to the machine at the step's
// received_at. It returns the registry that results, in the format of
// registry.json: artifacts are named by the path of their signed manifest. It
// fails only when the case cannot be replayed (a key file is missing).
func Replay(fixtures string, c *evalcase.LearningCase) (evalcase.Registry, error) {
	res, err := loadTrust(fixtures, c.Config.Trust)
	if err != nil {
		return evalcase.Registry{}, err
	}
	m := NewMachine(c.Config)
	reg := evalcase.Registry{
		Artifacts: map[string]core.LifecycleState{}, Active: []evalcase.ActiveEntry{}, Acknowledgments: []evalcase.AckEntry{},
		Rejections: []evalcase.RejectionEntry{}, Holds: []string{}, ReevaluationRequired: []string{},
	}
	pathOf := map[core.Digest]string{}
	for i, s := range c.Steps {
		var r Result
		var artifact core.Digest
		if s.Kind == evalcase.StepAssessment {
			r = m.Assessment(c.Assessments[s.File])
		} else {
			r, artifact = replayStep(m, res, c, s)
		}
		switch {
		case r.Rejection != nil:
			codes := r.Rejection.ReasonCodes
			if codes == nil {
				codes = []string{}
			}
			reg.Rejections = append(reg.Rejections, evalcase.RejectionEntry{Step: i, Code: r.Rejection.Code, ReasonCodes: codes})
		case r.Ack != "":
			reg.Acknowledgments = append(reg.Acknowledgments, evalcase.AckEntry{Step: i, Status: r.Ack})
			if s.Kind == evalcase.StepArtifact && r.Ack == core.AckAccepted {
				pathOf[artifact] = s.File
			}
		}
	}
	st := m.State()
	for _, a := range st.Artifacts {
		reg.Artifacts[pathOf[a.Digest]] = a.State
	}
	for _, a := range st.Active {
		e := evalcase.ActiveEntry{Context: a.Context}
		if a.Artifact != nil {
			p := pathOf[*a.Artifact]
			e.Artifact = &p
		}
		reg.Active = append(reg.Active, e)
	}
	reg.Holds = append(reg.Holds, st.Holds...)
	for _, d := range st.Reevaluate {
		reg.ReevaluationRequired = append(reg.ReevaluationRequired, pathOf[d])
	}
	return reg, nil
}

// replayStep verifies and decodes the input of the step and applies it. It
// returns the artifact_digest of a signed input.
func replayStep(m *Machine, res trustResolver, c *evalcase.LearningCase, s evalcase.LearningStep) (Result, core.Digest) {
	compact := c.Signed[s.File]
	parsed, err := jws.Verifier{Keys: res, Typ: stepTyp[s.Kind]}.Verify(compact)
	if err != nil {
		if slices.Contains(signatureReasons, jws.ReasonOf(err)) {
			return reject(CodeInvalidProof), ""
		}
		return reject(CodeInvalidMessage), ""
	}
	ad, err := digest.ArtifactDigest(compact)
	if err != nil {
		return reject(CodeInvalidMessage), ""
	}
	decode := func(v any) bool { return strictjson.Unmarshal(parsed.Payload, strictjson.Limits{}, v) == nil }
	switch s.Kind {
	case evalcase.StepPolicy:
		var p core.LearningPolicy
		if !decode(&p) {
			return reject(CodeInvalidMessage), ad
		}
		return m.InstallPolicy(Msg[core.LearningPolicy]{Claims: p, ArtifactDigest: ad}, s.ReceivedAt), ad
	case evalcase.StepArtifact:
		var a core.LearningArtifact
		if !decode(&a) {
			return reject(CodeInvalidMessage), ad
		}
		return m.Register(Msg[core.LearningArtifact]{Claims: a, ArtifactDigest: ad}, s.ReceivedAt), ad
	case evalcase.StepEvent:
		var e core.LearningEvent
		if !decode(&e) {
			return reject(CodeInvalidMessage), ad
		}
		return m.Event(Msg[core.LearningEvent]{Claims: e, ArtifactDigest: ad}, s.ReceivedAt), ad
	default:
		var r core.OutcomeReport
		if !decode(&r) {
			return reject(CodeInvalidMessage), ad
		}
		return m.Report(Msg[core.OutcomeReport]{Claims: r, ArtifactDigest: ad, ReporterRole: reporterRole(c.Config.Trust, r.Issuer, string(r.ReporterRole))}, s.ReceivedAt), ad
	}
}
