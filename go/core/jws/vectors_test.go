package jws_test

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/core/strictjson"
)

const vectorPrefix = "vectors/jws/"

// The array files; every other file under vectors/jws holds one verify vector.
const (
	thumbprintID = vectorPrefix + "thumbprint"
	jwkRejectID  = vectorPrefix + "jwk-reject"
	keysID       = vectorPrefix + "appendix-c-keys"
)

type manifestEntry struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Scope              string   `json:"scope"`
	Path               string   `json:"path"`
	Expected           optional `json:"expected"`
	Outcome            optional `json:"outcome"`
	SpecMapRow         string   `json:"spec_map_row"`
	DraftSection       string   `json:"draft_section"`
	Capabilities       []string `json:"capabilities"`
	ConformanceProfile []string `json:"conformance_profile"`
	Transport          []string `json:"transport"`
	Layer              string   `json:"layer"`
}

// optional is an entry member that is null in key and adapter-asset entries
// (spec/v1.0/fixtures/README.md); null reads as "".
type optional string

func (o *optional) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*o = ""
		return nil
	}
	return json.Unmarshal(b, (*string)(o))
}

type manifest struct {
	ManifestVersion int             `json:"manifest_version"`
	Entries         []manifestEntry `json:"entries"`
}

// verifyVector is one verify vector file. Every member is present in every
// file; members that do not apply are null.
type verifyVector struct {
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

var verifyFields = []string{
	"compact", "decode_as", "description", "expect", "expected_holder_jkt", "expected_payload",
	"expected_typ", "id", "reject_reason", "signature_valid", "signer_jwk", "trusted_keysets",
}

type thumbprintVector struct {
	ID                 string          `json:"id"`
	Description        string          `json:"description"`
	JWK                json.RawMessage `json:"jwk"`
	ExpectedThumbprint core.Digest     `json:"expected_thumbprint"`
	Source             string          `json:"source"`
}

type jwkRejectVector struct {
	ID           string          `json:"id"`
	Description  string          `json:"description"`
	JWK          json.RawMessage `json:"jwk"`
	RejectReason jws.Reason      `json:"reject_reason"`
}

type keyVector struct {
	ID                 string      `json:"id"`
	Description        string      `json:"description"`
	D                  string      `json:"d"`
	ExpectedX          string      `json:"expected_x"`
	ExpectedY          string      `json:"expected_y"`
	ExpectedThumbprint core.Digest `json:"expected_thumbprint"`
}

func readJSON(t testing.TB, rel string, v any) []byte {
	t.Helper()
	b := readFile(t, filepath.Join(fixturesRoot, filepath.FromSlash(rel)))
	if err := strictjson.Unmarshal(b, strictjson.Limits{MaxBytes: 1 << 20}, v); err != nil {
		t.Fatalf("strict-parse %s: %v", rel, err)
	}
	return b
}

func jwsEntries(t testing.TB) map[string]manifestEntry {
	t.Helper()
	var m manifest
	readJSON(t, "manifest.json", &m)
	out := map[string]manifestEntry{}
	for _, e := range m.Entries {
		if strings.HasPrefix(e.ID, vectorPrefix) {
			out[e.ID] = e
		}
	}
	if len(out) == 0 {
		t.Fatal("manifest lists no vectors/jws entries")
	}
	return out
}

func TestManifestListsEveryJWSFile(t *testing.T) {
	entries := jwsEntries(t)
	listed := map[string]bool{}
	for id, e := range entries {
		if e.Kind != "vector" || e.Scope != "core" || e.SpecMapRow == "" || e.DraftSection == "" {
			t.Errorf("%s: kind/scope/row/section = %q/%q/%q/%q", id, e.Kind, e.Scope, e.SpecMapRow, e.DraftSection)
		}
		if e.Path != id+".json" || string(e.Expected) != e.Path {
			t.Errorf("%s: path %q expected %q, want %s.json for both", id, e.Path, e.Expected, id)
		}
		listed[e.Path] = true
	}
	root := filepath.Join(fixturesRoot, filepath.FromSlash(vectorPrefix))
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(fixturesRoot, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if path.Base(rel) == "README.md" {
			return nil
		}
		if !listed[rel] {
			t.Errorf("%s is not listed in manifest.json", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// requiredVectors pins the vectors the task and the draft require, with
// their expected result, so deleting one or changing its expectation fails
// here.
var requiredVectors = map[string]string{
	"appendix-c":                     "accept",
	"appendix-c-version-mismatch":    "payload-schema",
	"rfc7515-a3":                     "typ-unsupported",
	"header-alg-none":                "alg-unsupported",
	"header-alg-hs256":               "alg-unsupported",
	"header-alg-rs256":               "alg-unsupported",
	"header-alg-ps256":               "alg-unsupported",
	"header-alg-eddsa":               "alg-unsupported",
	"header-jwk-private":             "jwk-private",
	"header-jku":                     "header-jku",
	"header-x5u":                     "header-x5u",
	"header-x5c":                     "header-x5c",
	"header-crit":                    "header-crit",
	"header-b64-false":               "header-b64",
	"payload-detached":               "payload-detached",
	"header-jwk-p384":                "jwk-curve",
	"header-jwk-off-curve":           "jwk-off-curve",
	"holder-jkt-mismatch":            "holder-jkt-mismatch",
	"es256-valid":                    "accept",
	"es256-noncanonical-payload":     "accept",
	"es256-noncanonical-header":      "accept",
	"es256-leading-zero-r":           "accept",
	"es256-signature-63-bytes":       "signature-length",
	"es256-signature-der":            "signature-length",
	"es256-signature-padded":         "base64url",
	"es256-high-s":                   "accept",
	"typ-requirements":               "accept",
	"typ-evidence":                   "accept",
	"typ-presentation":               "accept",
	"typ-admission":                  "accept",
	"typ-outcome":                    "accept",
	"typ-reputation":                 "accept",
	"typ-learning-policy":            "accept",
	"typ-learning-artifact":          "accept",
	"typ-learning-event":             "accept",
	"typ-admission-signed-by-issuer": "kid-unknown",
}

func TestRequiredVectors(t *testing.T) {
	entries := jwsEntries(t)
	for stem, want := range requiredVectors {
		e, ok := entries[vectorPrefix+stem]
		if !ok {
			t.Errorf("required vector %s is missing", stem)
			continue
		}
		var v verifyVector
		readJSON(t, e.Path, &v)
		got := v.Expect
		if v.RejectReason != nil {
			got = *v.RejectReason
		}
		if got != want {
			t.Errorf("%s: expects %q, want %q", stem, got, want)
		}
	}
	// Every typ of the draft 7.3 table has a required accept vector.
	for _, typ := range jws.Typs() {
		stem := "typ-" + strings.TrimSuffix(strings.TrimPrefix(typ, "pact-"), "+jwt")
		if requiredVectors[stem] != "accept" {
			t.Errorf("no required accept vector %s for typ %s", stem, typ)
		}
	}
}

func TestVerifyVectors(t *testing.T) {
	entries := jwsEntries(t)
	n := 0
	for id, e := range entries {
		if id == thumbprintID || id == jwkRejectID || id == keysID {
			continue
		}
		n++
		t.Run(strings.TrimPrefix(id, vectorPrefix), func(t *testing.T) {
			var v verifyVector
			raw := readJSON(t, e.Path, &v)
			checkMembers(t, raw, verifyFields)
			if v.ID != id {
				t.Errorf("id %q, manifest %q", v.ID, id)
			}
			runVerifyVector(t, v, e)
		})
	}
	if n < 40 {
		t.Errorf("only %d verify vectors", n)
	}
}

func checkMembers(t testing.TB, raw []byte, want []string) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range m {
		got = append(got, k)
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("members %q, want exactly %q", got, want)
	}
}

func runVerifyVector(t *testing.T, v verifyVector, e manifestEntry) {
	switch {
	case v.Expect == "accept" && v.RejectReason == nil && e.Outcome == "ACCEPTED":
	case v.Expect == "reject" && v.RejectReason != nil && e.Outcome == "REJECTED":
	default:
		t.Fatalf("expect %q, reject_reason %v, manifest outcome %q do not agree", v.Expect, v.RejectReason, e.Outcome)
	}
	res := jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{}}
	for role, keys := range v.TrustedKeysets {
		var set []jws.JWK
		for _, raw := range keys {
			k, err := jws.ParseJWK(raw)
			if err != nil {
				t.Fatalf("trusted key for %s: %v", role, err)
			}
			set = append(set, k)
		}
		res.KeySets[jws.Role(role)] = keySet(t, set...)
	}
	if v.ExpectedHolderJKT != nil {
		res.ExpectedHolderJKT = *v.ExpectedHolderJKT
	}
	verifier := jws.Verifier{Keys: res}
	if v.ExpectedTyp != nil {
		verifier.Typ = *v.ExpectedTyp
	}
	checkSignatureValid(t, v)

	p, err := verifier.Verify(v.Compact)
	reason := string(jws.ReasonOf(err))
	if err != nil && reason == "" {
		t.Fatalf("error without a reason: %v", err)
	}
	if err == nil && v.DecodeAs != nil {
		reason = decodeAs(t, *v.DecodeAs, p.Payload)
	}
	if v.Expect == "accept" {
		if reason != "" {
			t.Fatalf("rejected (%s: %v), want accept", reason, err)
		}
		if v.ExpectedPayload == nil || string(p.Payload) != *v.ExpectedPayload {
			t.Errorf("payload %q, want %v", p.Payload, v.ExpectedPayload)
		}
		return
	}
	if reason != *v.RejectReason {
		t.Fatalf("reason %q (%v), want %q", reason, err, *v.RejectReason)
	}
}

// decodeAs applies the artifact layer after a successful verification: a
// strict decode as the named type and the pact_version constant of the
// schema. It returns "payload-schema" when the artifact is rejected.
func decodeAs(t *testing.T, typ string, payload []byte) string {
	t.Helper()
	if typ != "Evidence" {
		t.Fatalf("decode_as %q is not handled", typ)
	}
	var ev core.Evidence
	if err := strictjson.Unmarshal(payload, core.Defaults().ArtifactJSON(), &ev); err != nil || ev.PactVersion != core.Version {
		return "payload-schema"
	}
	return ""
}

// checkSignatureValid recomputes signature_valid with crypto/ecdsa alone: the
// signature octets, decoded leniently, over the received signing input under
// signer_jwk. It shows that a vector rejected for another reason does not
// also carry a bad signature by accident.
func checkSignatureValid(t *testing.T, v verifyVector) {
	t.Helper()
	parts := strings.Split(v.Compact, ".")
	var got *bool
	if len(parts) == 3 && string(v.SignerJWK) != "null" {
		var m map[string]any
		if err := json.Unmarshal(v.SignerJWK, &m); err != nil {
			t.Fatal(err)
		}
		if m["kty"] == "EC" && m["crv"] == "P-256" {
			k, err := jws.ParseJWK(v.SignerJWK)
			if err != nil {
				t.Fatalf("signer_jwk: %v", err)
			}
			pub, err := k.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			ok := lenientVerify(pub, parts[0]+"."+parts[1], parts[2])
			got = &ok
		}
	}
	switch {
	case got == nil && v.SignatureValid == nil:
	case got != nil && v.SignatureValid != nil && *got == *v.SignatureValid:
	default:
		t.Errorf("signature_valid %v, recomputed %v", ptrStr(v.SignatureValid), ptrStr(got))
	}
}

func ptrStr(b *bool) string {
	if b == nil {
		return "null"
	}
	if *b {
		return "true"
	}
	return "false"
}

func lenientVerify(pub *ecdsa.PublicKey, signingInput, sigSeg string) bool {
	s := strings.NewReplacer("\r", "", "\n", "", "=", "", "+", "-", "/", "_").Replace(sigSeg)
	sig, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(sig) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(signingInput))
	return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

func entryPath(t testing.TB, id string) manifestEntry {
	t.Helper()
	e, ok := jwsEntries(t)[id]
	if !ok {
		t.Fatalf("manifest lacks %s", id)
	}
	return e
}

func TestThumbprintVectors(t *testing.T) {
	e := entryPath(t, thumbprintID)
	if e.Outcome != "ACCEPTED" {
		t.Errorf("outcome %q", e.Outcome)
	}
	var vs []thumbprintVector
	readJSON(t, e.Path, &vs)
	seen := map[string]bool{}
	for _, v := range vs {
		t.Run(v.ID, func(t *testing.T) {
			seen[v.ID] = true
			k, err := jws.ParseJWK(v.JWK)
			if err != nil {
				t.Fatal(err)
			}
			got, err := jws.Thumbprint(k)
			if err != nil || got != v.ExpectedThumbprint {
				t.Errorf("thumbprint %q (%v), want %q", got, err, v.ExpectedThumbprint)
			}
		})
	}
	for _, id := range []string{"appendix-c-holder", "holder-with-optional-members", "holder-reordered-extra-member", "leading-zero-x"} {
		if !seen[id] {
			t.Errorf("thumbprint vector %s missing", id)
		}
	}
	for _, v := range vs {
		if strings.HasPrefix(v.ID, "appendix-c-holder") && v.ExpectedThumbprint != holderJKT {
			t.Errorf("%s: %q is not the Appendix C holder_jkt", v.ID, v.ExpectedThumbprint)
		}
	}
}

func TestJWKRejectVectors(t *testing.T) {
	e := entryPath(t, jwkRejectID)
	if e.Outcome != "REJECTED" {
		t.Errorf("outcome %q", e.Outcome)
	}
	var vs []jwkRejectVector
	readJSON(t, e.Path, &vs)
	if len(vs) < 10 {
		t.Errorf("only %d jwk-reject vectors", len(vs))
	}
	for _, v := range vs {
		t.Run(v.ID, func(t *testing.T) {
			k, err := jws.ParseJWK(v.JWK)
			if err == nil {
				_, err = jws.Thumbprint(k)
			}
			if got := jws.ReasonOf(err); got != v.RejectReason {
				t.Errorf("reason %q (%v), want %q", got, err, v.RejectReason)
			}
		})
	}
}

func TestAppendixCKeyVectors(t *testing.T) {
	e := entryPath(t, keysID)
	var vs []keyVector
	readJSON(t, e.Path, &vs)
	if len(vs) != 2 {
		t.Fatalf("%d key vectors, want holder and issuer", len(vs))
	}
	for _, v := range vs {
		t.Run(v.ID, func(t *testing.T) {
			d, err := b64.DecodeString(v.D)
			if err != nil || len(d) != 32 {
				t.Fatalf("d: %v", err)
			}
			key, err := ecdsaKey(d)
			if err != nil {
				t.Fatal(err)
			}
			k, err := jws.PublicJWK(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if k.X != v.ExpectedX || k.Y != v.ExpectedY {
				t.Errorf("derived x=%s y=%s, want x=%s y=%s", k.X, k.Y, v.ExpectedX, v.ExpectedY)
			}
			tp, err := jws.Thumbprint(k)
			if err != nil || tp != v.ExpectedThumbprint {
				t.Errorf("thumbprint %q (%v), want %q", tp, err, v.ExpectedThumbprint)
			}
		})
	}
	if vs[0].ExpectedThumbprint != holderJKT {
		t.Errorf("holder thumbprint %q is not the Appendix C holder_jkt", vs[0].ExpectedThumbprint)
	}
}
