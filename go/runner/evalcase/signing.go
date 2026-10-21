package evalcase

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/runner/manifest"
)

// FixedTime is the default iat, and so nbf, of every generated artifact: the
// sample time of draft Appendix B, 2026-10-15T16:00:00Z.
const FixedTime int64 = 1792080000

// PresentationLifetime is the default exp - iat of a generated
// presentation, the most draft Section 7.5 allows.
const PresentationLifetime int64 = 60

// Signing is a directory's signing.json (spec/v1.0/fixtures/README.md, section
// Generator contract: signing.json): the artifacts the generator signs, in
// order, then the presentations it builds and signs.
type Signing struct {
	Artifacts     []Artifact
	Presentations []Presentation
}

// Artifact is one service-signed artifact: its decoded payload, the signed
// file, its typ, the role of its signing key in KeysFile, and the claims
// its payload must carry.
type Artifact struct {
	Decoded string `json:"decoded"`
	Signed  string `json:"signed"`
	Typ     string `json:"typ"`
	Signer  string `json:"signer"`
	JTI     string `json:"jti"`
	// Iat defaults to FixedTime, Nbf to the iat; Exp is checked only when
	// set.
	Iat *int64 `json:"iat"`
	Nbf *int64 `json:"nbf"`
	Exp *int64 `json:"exp"`
	// Digests maps an RFC 6901 pointer into the decoded payload to the signed
	// file of an earlier entry whose artifact_digest the member gets.
	Digests map[string]string `json:"digests"`
	// PayloadSigned, when set, is the decoded file the signature covers; the
	// compact JWS still carries Decoded, so it does not verify by design.
	PayloadSigned *string `json:"payload_signed"`
}

// Presentation is a presentation, which has no decoded file: the generator
// builds its payload from the case files.
type Presentation struct {
	Signed string `json:"signed"`
	Signer string `json:"signer"`
	JTI    string `json:"jti"`
	// Iat defaults to FixedTime, Nbf to the iat, Exp to iat +
	// PresentationLifetime.
	Iat *int64 `json:"iat"`
	Nbf *int64 `json:"nbf"`
	Exp *int64 `json:"exp"`
	// Contract defaults to signed/contract.jws; Evidence to the evidence
	// artifacts in order; Reputation (absent, null or a path) to the
	// reputation artifact, or null when there is none.
	Contract   *string         `json:"contract"`
	Evidence   *[]string       `json:"evidence"`
	Reputation json.RawMessage `json:"reputation"`
	Profile    *string         `json:"profile"`
	Intent     *string         `json:"intent"`
	Operation  *string         `json:"operation"`
}

var relPath = regexp.MustCompile(manifest.PathPattern)

// parseSigning reads a signing.json strictly and checks it.
func parseSigning(b []byte) (Signing, error) {
	var raw struct {
		Artifacts     *[]Artifact    `json:"artifacts"`
		Presentations []Presentation `json:"presentations"`
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{}, &raw); err != nil {
		return Signing{}, err
	}
	if raw.Artifacts == nil {
		return Signing{}, errors.New("artifacts is required")
	}
	s := Signing{Artifacts: *raw.Artifacts, Presentations: raw.Presentations}
	return s, s.validate()
}

func (s Signing) validate() error {
	paths := func(where string, ps ...string) error {
		for _, p := range ps {
			if !relPath.MatchString(p) {
				return fmt.Errorf("%s: %q is not a relative path inside the case", where, p)
			}
		}
		return nil
	}
	seen := map[string]bool{}
	for i, a := range s.Artifacts {
		where := fmt.Sprintf("artifacts[%d]", i)
		if a.Decoded == "" || a.Signed == "" || a.Typ == "" || a.Signer == "" || a.JTI == "" {
			return fmt.Errorf("%s: decoded, signed, typ, signer and jti are required", where)
		}
		if err := paths(where, a.Decoded, a.Signed); err != nil {
			return err
		}
		if a.PayloadSigned != nil {
			if err := paths(where, *a.PayloadSigned); err != nil {
				return err
			}
		}
		if _, ok := jws.TypRole(a.Typ); !ok || a.Typ == jws.TypPresentation {
			return fmt.Errorf("%s: typ %q is not a typ of draft Section 7.3 for a service-signed artifact", where, a.Typ)
		}
		for ptr, p := range a.Digests {
			if !strings.HasPrefix(ptr, "/") {
				return fmt.Errorf("%s: digests: %q is not a JSON Pointer to a member", where, ptr)
			}
			if !seen[p] {
				return fmt.Errorf("%s: digests %s: %s is not the signed file of an earlier entry", where, ptr, p)
			}
		}
		if seen[a.Signed] {
			return fmt.Errorf("%s: signed file %s is named twice", where, a.Signed)
		}
		seen[a.Signed] = true
	}
	for i, p := range s.Presentations {
		where := fmt.Sprintf("presentations[%d]", i)
		if p.Signed == "" || p.Signer == "" || p.JTI == "" {
			return fmt.Errorf("%s: signed, signer and jti are required", where)
		}
		if err := paths(where, p.Signed); err != nil {
			return err
		}
		if seen[p.Signed] {
			return fmt.Errorf("%s: signed file %s is named twice", where, p.Signed)
		}
		seen[p.Signed] = true
	}
	return nil
}
