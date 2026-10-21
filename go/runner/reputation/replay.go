package reputation

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/evalcase"
)

// StepResult is the oracle's answer to one step of a case: Answer for an
// ingestion; Snapshot, or the code of the query's refusal, for a query.
type StepResult struct {
	Answer    Answer
	Snapshot  *Snapshot
	QueryCode string
}

// Outcome is the replay of a case: the answer to each step, in order, and
// the classification of every report at the end of the case, by event_id.
type Outcome struct {
	Steps    []StepResult
	Verdicts map[string]Verdict
}

// trust resolves the keys of a report from the case's trust records: the
// keys of the reporter records whose iss is the payload's.
type trust struct {
	byIss map[string][]jws.JWK
}

func loadTrust(fixtures string, records []evalcase.TrustRecord) (trust, error) {
	t := trust{byIss: map[string][]jws.JWK{}}
	for _, rec := range records {
		if rec.Role != jws.RoleReporter {
			continue
		}
		for _, k := range rec.Keys {
			b, err := os.ReadFile(filepath.Join(fixtures, filepath.FromSlash(k)))
			if err != nil {
				return t, err
			}
			jwk, err := jws.ParseJWK(b)
			if err != nil {
				return t, fmt.Errorf("%s: %w", k, err)
			}
			if !slices.ContainsFunc(t.byIss[rec.Iss], func(s jws.JWK) bool { return s.Kid == jwk.Kid }) {
				t.byIss[rec.Iss] = append(t.byIss[rec.Iss], jwk)
			}
		}
	}
	return t, nil
}

func (t trust) TrustedKeys(req jws.KeyRequest) (*jws.KeySet, error) {
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(req.Payload, &claims); err != nil {
		return nil, err
	}
	return jws.NewKeySet(t.byIss[claims.Iss]...)
}

func (trust) HolderJKT(jws.KeyRequest) (core.Digest, error) {
	return "", fmt.Errorf("an outcome report is service-signed")
}

// signatureReasons are the verification failures that mean the signer could
// not be authenticated (INVALID_PROOF); any other failure is a message that
// is not a well-formed report JWS (INVALID_MESSAGE).
var signatureReasons = []jws.Reason{jws.ErrSignatureInvalid, jws.ErrKidUnknown, jws.ErrKeyUnavailable}

// Replay runs the steps of the case against a fresh Oracle, as a reputation
// service would: it verifies each signed report under the case's trust
// records, decodes it strictly and ingests it at the step's received_at,
// and answers each query at the step's now. It fails only when the case
// cannot be replayed, such as when a key file is missing.
func Replay(fixtures string, c *evalcase.OutcomesCase) (*Outcome, error) {
	t, err := loadTrust(fixtures, c.Config.Trust)
	if err != nil {
		return nil, err
	}
	o := NewOracle(c.Config, c.Native)
	out := &Outcome{}
	for _, s := range c.Steps {
		if s.Query != nil {
			snap, code := o.Query(*s.Query, s.Now)
			out.Steps = append(out.Steps, StepResult{Snapshot: snap, QueryCode: code})
			continue
		}
		out.Steps = append(out.Steps, StepResult{Answer: ingest(o, t, c.Signed[s.Ingest], s.Ingest, s.ReceivedAt)})
	}
	out.Verdicts = o.Verdicts()
	return out, nil
}

func ingest(o *Oracle, t trust, compact, event string, now int64) Answer {
	parsed, err := jws.Verifier{Keys: t, Typ: jws.TypOutcome}.Verify(compact)
	if err != nil {
		if slices.Contains(signatureReasons, jws.ReasonOf(err)) {
			return o.Refuse(event, CodeInvalidProof)
		}
		return o.Refuse(event, CodeInvalidMessage)
	}
	var r core.OutcomeReport
	if err := strictjson.Unmarshal(parsed.Payload, strictjson.Limits{}, &r); err != nil {
		return o.Refuse(event, CodeInvalidMessage)
	}
	return o.Ingest(r, now)
}
