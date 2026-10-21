package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
	pactmanifest "hop.top/pact-go/runner/manifest"
)

// The array files of vectors/jws; every other file holds one verify vector
// (spec/v1.0/fixtures/vectors/jws/README.md).
const (
	jwsThumbprintID = "vectors/jws/thumbprint"
	jwsJWKRejectID  = "vectors/jws/jwk-reject"
	jwsKeysID       = "vectors/jws/appendix-c-keys"
)

type jwsVerifyVector struct {
	ID                string                       `json:"id"`
	Description       string                       `json:"description"`
	Compact           string                       `json:"compact"`
	ExpectedTyp       *string                      `json:"expected_typ"`
	TrustedKeysets    map[string][]json.RawMessage `json:"trusted_keysets"`
	ExpectedHolderJKT *core.Digest                 `json:"expected_holder_jkt"`
	DecodeAs          *string                      `json:"decode_as"`
	Expect            string                       `json:"expect"`
	RejectReason      *string                      `json:"reject_reason"`
	SignerJWK         json.RawMessage              `json:"signer_jwk"`
	SignatureValid    *bool                        `json:"signature_valid"`
	ExpectedPayload   *string                      `json:"expected_payload"`
}

var jwsVerifyMembers = []string{
	"compact", "decode_as", "description", "expect", "expected_holder_jkt", "expected_payload",
	"expected_typ", "id", "reject_reason", "signature_valid", "signer_jwk", "trusted_keysets",
}

// jwsAlgorithms returns the algorithms an entry runs with: ES256 and
// Ed25519 when it lists the capability jws-ed25519, so Ed25519 is
// negotiated (draft 7.2), and otherwise nil, the baseline, ES256 alone. An
// entry runs only when its capabilities are declared.
func (e vectorEntry) jwsAlgorithms() jws.Algorithms {
	if slices.Contains(e.Capabilities, pactmanifest.CapabilityJWSEd25519) {
		return jws.Algorithms{jws.AlgES256, jws.AlgEd25519}
	}
	return nil
}

// runJWSEntry runs a vectors/jws entry through core/jws.
func runJWSEntry(root string, e vectorEntry) error {
	if err := singleFile(e); err != nil {
		return err
	}
	switch e.ID {
	case jwsThumbprintID:
		return runJWSThumbprints(root, e)
	case jwsJWKRejectID:
		return runJWKRejects(root, e)
	case jwsKeysID:
		return runJWSKeys(root, e)
	}
	var v jwsVerifyVector
	raw, err := readFixtureJSON(root, e.Path, &v)
	if err != nil {
		return err
	}
	if err := checkMembers(raw, jwsVerifyMembers...); err != nil {
		return err
	}
	if v.ID != e.ID {
		return fmt.Errorf("vector id %q, manifest id %q", v.ID, e.ID)
	}
	switch {
	case v.Expect == "accept" && v.RejectReason == nil && e.outcome() == "ACCEPTED":
	case v.Expect == "reject" && v.RejectReason != nil && e.outcome() == "REJECTED":
	default:
		return fmt.Errorf("expect %q, reject_reason and outcome %q do not agree", v.Expect, e.outcome())
	}

	algs := e.jwsAlgorithms()
	res := jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{}}
	for role, keys := range v.TrustedKeysets {
		var set []jws.JWK
		for _, raw := range keys {
			k, err := algs.ParseJWK(raw)
			if err != nil {
				return fmt.Errorf("trusted key for %s: %w", role, err)
			}
			set = append(set, k)
		}
		ks, err := algs.NewKeySet(set...)
		if err != nil {
			return fmt.Errorf("key set for %s: %w", role, err)
		}
		res.KeySets[jws.Role(role)] = ks
	}
	if v.ExpectedHolderJKT != nil {
		res.ExpectedHolderJKT = *v.ExpectedHolderJKT
	}
	verifier := jws.Verifier{Keys: res, Algorithms: algs}
	if v.ExpectedTyp != nil {
		verifier.Typ = *v.ExpectedTyp
	}
	p, err := verifier.Verify(v.Compact)
	reason := string(jws.ReasonOf(err))
	if err != nil && reason == "" {
		return fmt.Errorf("error without a reason: %w", err)
	}
	if err == nil && v.DecodeAs != nil {
		if reason, err = decodeArtifact(*v.DecodeAs, p.Payload); err != nil {
			return err
		}
	}
	if v.Expect == "accept" {
		if reason != "" {
			return fmt.Errorf("rejected (%s), want accept", reason)
		}
		if v.ExpectedPayload == nil || string(p.Payload) != *v.ExpectedPayload {
			return fmt.Errorf("payload %q differs from expected_payload", p.Payload)
		}
		return nil
	}
	if reason != *v.RejectReason {
		return fmt.Errorf("reason %q, want %q", reason, *v.RejectReason)
	}
	return nil
}

// decodeArtifact applies the artifact layer after verification: a strict
// decode as the named type and its pact_version. It returns
// "payload-schema" when the artifact is refused.
func decodeArtifact(typ string, payload []byte) (string, error) {
	if typ != "Evidence" {
		return "", fmt.Errorf("decode_as %q is not handled", typ)
	}
	var ev core.Evidence
	if err := strictjson.Unmarshal(payload, core.Defaults().ArtifactJSON(), &ev); err != nil || ev.PactVersion != core.Version {
		return "payload-schema", nil
	}
	return "", nil
}

func runJWSThumbprints(root string, e vectorEntry) error {
	var vs []struct {
		ID                 string          `json:"id"`
		Description        string          `json:"description"`
		JWK                json.RawMessage `json:"jwk"`
		ExpectedThumbprint core.Digest     `json:"expected_thumbprint"`
		Source             string          `json:"source"`
	}
	if _, err := readFixtureJSON(root, e.Path, &vs); err != nil {
		return err
	}
	if len(vs) == 0 || e.outcome() != "ACCEPTED" {
		return fmt.Errorf("no thumbprint vectors, or outcome %q is not ACCEPTED", e.outcome())
	}
	for _, v := range vs {
		k, err := e.jwsAlgorithms().ParseJWK(v.JWK)
		if err != nil {
			return fmt.Errorf("%s: %w", v.ID, err)
		}
		got, err := jws.Thumbprint(k)
		if err != nil || got != v.ExpectedThumbprint {
			return fmt.Errorf("%s: thumbprint %s (%v), want %s", v.ID, got, err, v.ExpectedThumbprint)
		}
	}
	return nil
}

func runJWKRejects(root string, e vectorEntry) error {
	var vs []struct {
		ID           string          `json:"id"`
		Description  string          `json:"description"`
		JWK          json.RawMessage `json:"jwk"`
		RejectReason jws.Reason      `json:"reject_reason"`
	}
	if _, err := readFixtureJSON(root, e.Path, &vs); err != nil {
		return err
	}
	if len(vs) == 0 || e.outcome() != "REJECTED" {
		return fmt.Errorf("no jwk-reject vectors, or outcome %q is not REJECTED", e.outcome())
	}
	for _, v := range vs {
		k, err := e.jwsAlgorithms().ParseJWK(v.JWK)
		if err == nil {
			_, err = jws.Thumbprint(k)
		}
		if got := jws.ReasonOf(err); got != v.RejectReason {
			return fmt.Errorf("%s: reason %q (%v), want %q", v.ID, got, err, v.RejectReason)
		}
	}
	return nil
}

func runJWSKeys(root string, e vectorEntry) error {
	var vs []struct {
		ID                 string      `json:"id"`
		Description        string      `json:"description"`
		D                  string      `json:"d"`
		ExpectedX          string      `json:"expected_x"`
		ExpectedY          string      `json:"expected_y"`
		ExpectedThumbprint core.Digest `json:"expected_thumbprint"`
	}
	if _, err := readFixtureJSON(root, e.Path, &vs); err != nil {
		return err
	}
	if len(vs) == 0 {
		return fmt.Errorf("no key vectors")
	}
	for _, v := range vs {
		d, err := base64.RawURLEncoding.DecodeString(v.D)
		if err != nil || len(d) != 32 {
			return fmt.Errorf("%s: d is not 32 octets of base64url", v.ID)
		}
		key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
		if err != nil {
			return fmt.Errorf("%s: %w", v.ID, err)
		}
		k, err := jws.PublicJWK(&key.PublicKey)
		if err != nil {
			return fmt.Errorf("%s: %w", v.ID, err)
		}
		if k.X != v.ExpectedX || k.Y != v.ExpectedY {
			return fmt.Errorf("%s: derived x=%s y=%s, want x=%s y=%s", v.ID, k.X, k.Y, v.ExpectedX, v.ExpectedY)
		}
		tp, err := jws.Thumbprint(k)
		if err != nil || tp != v.ExpectedThumbprint {
			return fmt.Errorf("%s: thumbprint %s (%v), want %s", v.ID, tp, err, v.ExpectedThumbprint)
		}
	}
	return nil
}
