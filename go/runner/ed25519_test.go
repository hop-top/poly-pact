package runner

// Ed25519 receipts. Draft 7.2: ES256 is the baseline, Ed25519 (RFC 9864)
// MAY be negotiated explicitly with the RFC 8037 key representation, and the
// EdDSA identifier is not accepted. A case negotiates Ed25519 by listing it
// in config.json gateway.jws_algorithms, the GatewayMetadata.jws_algorithms
// the gateway publishes (draft 13.1, A.3; default ["ES256"]), and naming an
// OKP Ed25519 key as its validator key (receipt.signer, else config.json
// validator.key). A receipt alg passes only when it is listed and is the
// algorithm of that key. The committed case admission/valid-ed25519 is
// admission/valid with Ed25519 negotiated, and its manifest entry tests the
// optional capability jws-ed25519. testdata/fixtures-ed25519 is a synthetic
// tree with one such case. The goldens are the receipt of admission/valid
// signed with the Ed25519 test key, with the claims of admission/valid-ed25519
// for that case. Ed25519 signatures are deterministic (RFC 8032 section
// 5.1.6), so the goldens are compared byte for byte.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
)

// ed25519Root is the synthetic tree of the negotiated case.
var ed25519Root = filepath.Join("testdata", "fixtures-ed25519")

const (
	ed25519Case = "ed25519/negotiated"
	ed25519Kid  = "test-ed25519-key-1"
)

// ed25519TestKey returns the private Ed25519 test key of the fixtures: the
// seed d of the ed25519 record of keys/test-private-scalars.json, checked
// against keys/ed25519.jwk.json.
func ed25519TestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	var scalars struct {
		Keys []struct {
			Role string `json:"role"`
			D    string `json:"d"`
		} `json:"keys"`
	}
	b, err := os.ReadFile(filepath.Join(repoFixtures, "keys", "test-private-scalars.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &scalars); err != nil {
		t.Fatal(err)
	}
	for _, k := range scalars.Keys {
		if k.Role != "ed25519" {
			continue
		}
		seed, err := base64.RawURLEncoding.Strict().DecodeString(k.D)
		if err != nil || len(seed) != ed25519.SeedSize {
			t.Fatalf("ed25519 seed %q: %v", k.D, err)
		}
		key := ed25519.NewKeyFromSeed(seed)
		pb, err := os.ReadFile(filepath.Join(repoFixtures, "keys", "ed25519.jwk.json"))
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := jws.Algorithms{jws.AlgEd25519}.ParseJWK(pb)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := jwk.Ed25519PublicKey()
		if err != nil || !pub.Equal(key.Public()) {
			t.Fatalf("keys/ed25519.jwk.json is not the public key of the seed (%v)", err)
		}
		return key
	}
	t.Fatal("no ed25519 record in keys/test-private-scalars.json")
	return nil
}

// edResign signs the payload segment of a golden receipt line again with
// the Ed25519 test key under the protected header header, written as given
// so that it may carry an identifier the signers refuse to write.
func edResign(t *testing.T, line, header string) string {
	t.Helper()
	parts := strings.Split(line, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %.40s", line)
	}
	si := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + parts[1]
	return si + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519TestKey(t), []byte(si)))
}

// committedEd25519Case is the committed case that negotiates Ed25519.
const committedEd25519Case = "admission/valid-ed25519"

// validEd25519Line is the golden receipt line of admission/valid with the
// claims in which admission/valid-ed25519 differs, presentation_id and
// requirements_digest, set to the values its expected decision.json names.
// The signature is that of admission/valid; edResign signs it again.
func validEd25519Line(t *testing.T, valid string) string {
	t.Helper()
	var want struct {
		Receipt struct {
			Claims map[string]json.RawMessage `json:"claims"`
		} `json:"receipt"`
	}
	b, err := os.ReadFile(filepath.Join(repoFixtures, "expected", filepath.FromSlash(committedEd25519Case), "decision.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, ".")
	var p map[string]json.RawMessage
	if err := json.Unmarshal(decodePart(t, parts[1]), &p); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"presentation_id", "requirements_digest"} {
		v, ok := want.Receipt.Claims[k]
		if !ok {
			t.Fatalf("%s: expected receipt names no %s", committedEd25519Case, k)
		}
		p[k] = v
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := jcs.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(canon) + "." + parts[2]
}

func admissionHeader(alg, kid string) string {
	return `{"alg":"` + alg + `","typ":"pact-admission+jwt","kid":"` + kid + `"}`
}

// ed25519Goldens are the Ed25519 goldens of testdata/fakeimpl, by file
// under the golden directory: the receipt of admission/valid
//   - signed with alg Ed25519 under the Ed25519 kid, the good answer of the
//     negotiated case;
//   - the same with alg EdDSA, mode alg-eddsa: a valid Ed25519 signature
//     under the identifier draft 7.2 does not accept;
//   - signed with alg Ed25519 under the validator's kid, mode
//     ed25519-unnegotiated of admission/valid: an Ed25519 receipt from a
//     gateway that publishes ES256 alone;
//   - with the claims of admission/valid-ed25519, signed with alg Ed25519
//     under the Ed25519 kid, its good answer, and with alg EdDSA, its mode
//     alg-eddsa.
func ed25519Goldens(t *testing.T) map[string]string {
	t.Helper()
	valid := readLines(t, filepath.Join(goldenDir, "admission", "valid", "evaluate.out"))[0]
	committed := validEd25519Line(t, valid)
	return map[string]string{
		committedEd25519Case + "/evaluate.out":              edResign(t, committed, admissionHeader(jws.AlgEd25519, ed25519Kid)),
		committedEd25519Case + "/evaluate.alg-eddsa.out":    edResign(t, committed, admissionHeader("EdDSA", ed25519Kid)),
		"ed25519/negotiated/evaluate.out":                   edResign(t, valid, admissionHeader(jws.AlgEd25519, ed25519Kid)),
		"ed25519/negotiated/evaluate.alg-eddsa.out":         edResign(t, valid, admissionHeader("EdDSA", ed25519Kid)),
		"admission/valid/evaluate.ed25519-unnegotiated.out": edResign(t, valid, admissionHeader(jws.AlgEd25519, "test-validator-key-1")),
	}
}

// TestEd25519Goldens checks the committed Ed25519 goldens byte for byte;
// -update-mutants writes them again.
func TestEd25519Goldens(t *testing.T) {
	for rel, want := range ed25519Goldens(t) {
		p := filepath.Join(goldenDir, filepath.FromSlash(rel))
		if *updateMutants {
			writeFile(t, p, want+"\n")
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSuffix(string(b), "\n"); got != want {
			t.Errorf("%s = %s, want %s", rel, got, want)
		}
	}
	// The good golden is what the library writes for that header.
	valid := readLines(t, filepath.Join(goldenDir, "admission", "valid", "evaluate.out"))[0]
	payload := decodePart(t, strings.Split(valid, ".")[1])
	signed, err := jws.SignEd25519(jws.Header{Typ: jws.TypAdmission, Kid: ed25519Kid}, payload, ed25519TestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if want := ed25519Goldens(t)["ed25519/negotiated/evaluate.out"]; signed != want {
		t.Errorf("SignEd25519 = %s, want %s", signed, want)
	}
}

// TestEvaluateEd25519Negotiated: the case that lists Ed25519 in
// gateway.jws_algorithms and names an Ed25519 validator key accepts a
// receipt signed with alg Ed25519 under that key.
func TestEvaluateEd25519Negotiated(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "good", ed25519Root))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Manifest.Status != StatusPass {
		t.Errorf("manifest = %+v, want PASS", rep.Manifest)
	}
	if r := result(t, rep, ed25519Case); r.Status != StatusPass {
		t.Errorf("%s = %+v, want PASS", ed25519Case, r)
	}
}

// TestEvaluateEd25519BadModes: the EdDSA identifier fails even with a valid
// Ed25519 signature under the negotiated key, and an Ed25519 receipt fails
// a case whose gateway publishes ES256 alone, while the other cases of the
// mode pass.
func TestEvaluateEd25519BadModes(t *testing.T) {
	rep, err := Run(fakeImplCfg(t, "alg-eddsa", ed25519Root))
	if err != nil {
		t.Fatal(err)
	}
	if r := result(t, rep, ed25519Case); r.Status != StatusFail || !detailsContain(r.Details, "receipt signature", "alg-unsupported", "EdDSA", "jws_algorithms [ES256, Ed25519]") {
		t.Errorf("alg-eddsa: %s = %+v, want FAIL naming the EdDSA alg", ed25519Case, r)
	}
	for id, r := range runMode(t, "ed25519-unnegotiated", goodCases...) {
		if id != validCase {
			if r.Status != StatusPass {
				t.Errorf("ed25519-unnegotiated: %s = %+v, want PASS: the mode does not touch it", id, r)
			}
			continue
		}
		if r.Status != StatusFail || !detailsContain(r.Details, "receipt signature", "alg-unsupported", "Ed25519", "jws_algorithms [ES256]") {
			t.Errorf("ed25519-unnegotiated: %s = %+v, want FAIL naming the unnegotiated alg", id, r)
		}
	}
}

// TestEvaluateEd25519KeyMismatch: the receipt's alg must be the algorithm of
// the key the case names, in both directions and whatever kid it carries.
// The Ed25519 case lists both algorithms, so listing alone does not pass.
func TestEvaluateEd25519KeyMismatch(t *testing.T) {
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	m := mutator{keys: keys}
	valid := readLines(t, filepath.Join(goldenDir, "admission", "valid", "evaluate.out"))[0]
	tests := []struct {
		name, root, id, line string
		subs                 []string
	}{
		{"ES256 receipt, Ed25519 kid, Ed25519 case", ed25519Root, ed25519Case,
			m.resign(t, valid, "", func(h *jws.Header) { h.Kid = ed25519Kid }, nil),
			[]string{"receipt signature", "jwk-usage", "alg ES256", "a key for Ed25519"}},
		{"ES256 receipt, validator kid, Ed25519 case", ed25519Root, ed25519Case,
			valid, []string{"receipt signature", "test-validator-key-1"}},
		{"Ed25519 receipt, Ed25519 kid, ES256 case", subsetRoot(t, validCase), validCase,
			edResign(t, valid, admissionHeader(jws.AlgEd25519, ed25519Kid)),
			[]string{"receipt signature", "alg-unsupported", "Ed25519", "jws_algorithms [ES256]"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r := runPrinted(t, tt.root, tt.id, []string{tt.line}); r.Status != StatusFail || !detailsContain(r.Details, tt.subs...) {
				t.Errorf("= %+v, want FAIL naming %q", r, tt.subs)
			}
		})
	}
	// The good Ed25519 receipt, printed by a plain command, passes.
	good := ed25519Goldens(t)["ed25519/negotiated/evaluate.out"]
	if r := runPrinted(t, ed25519Root, ed25519Case, []string{good}); r.Status != StatusPass {
		t.Errorf("good Ed25519 receipt = %+v, want PASS", r)
	}
}

// withJWSAlgorithms sets gateway.jws_algorithms of the config.json of case
// id in root to algs, or removes it when algs is nil, and returns root.
func withJWSAlgorithms(t *testing.T, root, id string, algs any) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(id), "config.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	gw, _ := cfg["gateway"].(map[string]any)
	if gw == nil {
		gw = map[string]any{}
	}
	if algs == nil {
		delete(gw, "jws_algorithms")
	} else {
		gw["jws_algorithms"] = algs
	}
	cfg["gateway"] = gw
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, string(out))
	return root
}

// ed25519Copy is a copy of the synthetic Ed25519 tree.
func ed25519Copy(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	copyTree(t, ed25519Root, root)
	return root
}

// TestEvaluateJWSAlgorithms: config.json gateway.jws_algorithms is the
// GatewayMetadata.jws_algorithms the gateway publishes (draft 13.1, A.3),
// default ["ES256"]. A receipt passes only when its alg is listed and is the
// algorithm of the validator key (draft 7.2): the key type alone does not
// negotiate Ed25519, and EdDSA is never accepted.
func TestEvaluateJWSAlgorithms(t *testing.T) {
	valid := readLines(t, filepath.Join(goldenDir, "admission", "valid", "evaluate.out"))[0]
	edGood := ed25519Goldens(t)["ed25519/negotiated/evaluate.out"]
	edValidatorKid := edResign(t, valid, admissionHeader(jws.AlgEd25519, "test-validator-key-1"))
	edDSA := edResign(t, valid, admissionHeader("EdDSA", ed25519Kid))
	both := []string{"ES256", "Ed25519"}
	tests := []struct {
		name, id string
		algs     any
		line     string
		want     Status
		subs     []string
	}{
		{"Ed25519 key, list absent", ed25519Case, nil, edGood, StatusFail,
			[]string{"keys/ed25519.jwk.json", "Ed25519 key", "gateway.jws_algorithms [ES256]", "7.2"}},
		{"Ed25519 key, ES256 listed", ed25519Case, []string{"ES256"}, edGood, StatusFail,
			[]string{"keys/ed25519.jwk.json", "Ed25519 key", "gateway.jws_algorithms [ES256]"}},
		{"Ed25519 key, Ed25519 listed", ed25519Case, []string{"Ed25519"}, edGood, StatusPass, nil},
		{"Ed25519 key, both listed", ed25519Case, both, edGood, StatusPass, nil},
		{"Ed25519 key, both listed, EdDSA receipt", ed25519Case, both, edDSA, StatusFail,
			[]string{"receipt signature", "alg-unsupported", "EdDSA"}},
		{"P-256 key, list absent, ES256 receipt", validCase, nil, valid, StatusPass, nil},
		{"P-256 key, both listed, ES256 receipt", validCase, both, valid, StatusPass, nil},
		{"P-256 key, list absent, Ed25519 receipt", validCase, nil, edValidatorKid, StatusFail,
			[]string{"receipt signature", "alg-unsupported", "Ed25519", "jws_algorithms [ES256]"}},
		{"P-256 key, both listed, Ed25519 receipt", validCase, both, edValidatorKid, StatusFail,
			[]string{"receipt signature", "jwk-usage", "alg Ed25519", "a key for ES256"}},
		{"P-256 key, Ed25519 listed alone", validCase, []string{"Ed25519"}, valid, StatusFail,
			[]string{"keys/validator.jwk.json", "ES256 key", "gateway.jws_algorithms [Ed25519]"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := subsetRoot(t, validCase)
			if tt.id == ed25519Case {
				root = ed25519Copy(t)
			}
			withJWSAlgorithms(t, root, tt.id, tt.algs)
			r := runPrinted(t, root, tt.id, []string{tt.line})
			if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.subs)
			}
		})
	}
}

// TestEvaluateJWSAlgorithmsInvalid: gateway.jws_algorithms has the type of
// GatewayMetadata.jws_algorithms (draft A.3), an array of one or two
// distinct algorithms out of ES256 and Ed25519. Any other value fails the
// case, naming the member, whatever the implementation prints.
func TestEvaluateJWSAlgorithmsInvalid(t *testing.T) {
	edGood := ed25519Goldens(t)["ed25519/negotiated/evaluate.out"]
	for name, tt := range map[string]struct {
		algs any
		sub  string
	}{
		"empty":      {[]string{}, "gateway.jws_algorithms is empty"},
		"EdDSA":      {[]string{"ES256", "Ed25519", "EdDSA"}, `gateway.jws_algorithms[2] "EdDSA" is not ES256 or Ed25519`},
		"EdDSA only": {[]string{"EdDSA"}, `gateway.jws_algorithms[0] "EdDSA" is not ES256 or Ed25519`},
		"none":       {[]string{"none"}, `gateway.jws_algorithms[0] "none" is not ES256 or Ed25519`},
		"HS256":      {[]string{"Ed25519", "HS256"}, `gateway.jws_algorithms[1] "HS256" is not ES256 or Ed25519`},
		"duplicate":  {[]string{"Ed25519", "Ed25519"}, `gateway.jws_algorithms[1] "Ed25519" repeats`},
		"string":     {"Ed25519", "jws_algorithms"},
		"null item":  {[]any{nil}, "/gateway/jws_algorithms/0"},
		"empty item": {[]string{""}, `gateway.jws_algorithms[0] "" is not ES256 or Ed25519`},
	} {
		t.Run(name, func(t *testing.T) {
			root := withJWSAlgorithms(t, ed25519Copy(t), ed25519Case, tt.algs)
			if r := runPrinted(t, root, ed25519Case, []string{edGood}); r.Status != StatusFail || !detailsContain(r.Details, "ed25519/negotiated/config.json", tt.sub) {
				t.Errorf("= %+v, want FAIL naming %q", r, tt.sub)
			}
		})
	}
}

// TestEvaluateCommittedEd25519Case: admission/valid-ed25519 tests the
// optional capability jws-ed25519. An implementation that declares it must
// return the Ed25519 receipt; EdDSA fails. One that does not declare it is
// never judged on the case: SKIP, not PASS. The ES256-only gateway of
// admission/valid that emits Ed25519 is TestEvaluateEd25519BadModes.
func TestEvaluateCommittedEd25519Case(t *testing.T) {
	root := subsetRoot(t, committedEd25519Case, "keys/ed25519")
	for _, tt := range []struct {
		mode     string
		declared bool
		want     Status
		subs     []string
	}{
		{"good", true, StatusPass, nil},
		{"good", false, StatusSkip, []string{"jws-ed25519", "not declared"}},
		{"alg-eddsa", true, StatusFail, []string{"receipt signature", "alg-unsupported", "EdDSA", "jws_algorithms [ES256, Ed25519]"}},
		{"alg-eddsa", false, StatusSkip, []string{"jws-ed25519", "not declared"}},
		{"ed25519-unnegotiated", true, StatusPass, nil},
	} {
		cfg := fakeImplCfg(t, tt.mode, root)
		if !tt.declared {
			cfg.Capabilities = nil
		}
		rep, err := Run(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Manifest.Status != StatusPass {
			t.Fatalf("manifest = %+v", rep.Manifest)
		}
		r := result(t, rep, committedEd25519Case)
		if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
			t.Errorf("%s, declared %v: %+v, want %s naming %q", tt.mode, tt.declared, r, tt.want, tt.subs)
		}
	}
	// The receipt of admission/valid, ES256 under the validator key, fails
	// the case: the case names the Ed25519 key.
	valid := readLines(t, filepath.Join(goldenDir, "admission", "valid", "evaluate.out"))[0]
	if r := runPrinted(t, root, committedEd25519Case, []string{validEd25519Line(t, valid)}); r.Status != StatusFail || !detailsContain(r.Details, "receipt signature", "test-validator-key-1") {
		t.Errorf("ES256 receipt = %+v, want FAIL", r)
	}
}
