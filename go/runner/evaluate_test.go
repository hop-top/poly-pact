package runner

// Tests of the evaluate check beyond the decision: the receipt's signature,
// typ, claims, expiry and check results against the committed expected
// results (spec/v1.0/fixtures/README.md, decision.json), and the Problem and
// transport rules of draft Sections 12.2 and 13.4. The cases are committed
// fixtures; the bad implementations are the modes of testdata/fakeimpl.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/manifest"
)

// runMode runs the fake implementation in mode over the committed cases ids
// and returns the result of each.
func runMode(t *testing.T, mode string, ids ...string) map[string]Result {
	t.Helper()
	rep, err := Run(fakeImplCfg(t, mode, subsetRoot(t, ids...)))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Manifest.Status != StatusPass {
		t.Fatalf("manifest = %+v, want PASS", rep.Manifest)
	}
	out := map[string]Result{}
	for _, id := range ids {
		out[id] = result(t, rep, id)
	}
	return out
}

// goodCases are the committed cases the bad modes are run against, with the
// mode that breaks each.
var goodCases = []string{
	"admission/valid",
	"admission/old-holder-key",
	"admission/replay-same-nonce-two-replicas",
	"admission/wrong-audience",
	"admission/cancelled-evaluation",
	"selection/conservative-set-no-check",
	"selection/same-snapshot",
}

func TestEvaluateGoodReceiptsPass(t *testing.T) {
	for id, r := range runMode(t, "good", goodCases...) {
		if r.Status != StatusPass {
			t.Errorf("%s = %+v, want PASS", id, r)
		}
	}
}

// TestEvaluateBadModes: each bad implementation fails the case it breaks,
// naming the difference, and only that difference. The other cases of a
// mode print their good golden and pass.
func TestEvaluateBadModes(t *testing.T) {
	tests := []struct {
		mode, id string
		// details are the substrings of the one difference reported (every
		// string in one detail line); more than one entry means that many
		// difference lines.
		details [][]string
		// also are further cases the mode breaks, with their details.
		also map[string][][]string
	}{
		{"wrong-decision", "admission/valid", [][]string{{"decision INADMISSIBLE", "want ADMISSIBLE"}}, nil},
		{"problem", "admission/valid", [][]string{{"no receipt", "Problem", "INVALID_PROOF", "ADMISSIBLE"}}, nil},
		{"receipt-for-rejected", "admission/old-holder-key", [][]string{{"receipt", "INVALID_PROOF", "12.2"}}, nil},
		{"bad-signature", "admission/valid", [][]string{{"signature", "signature-invalid"}}, nil},
		{"bad-typ", "admission/valid", [][]string{{"typ", "pact-evidence+jwt", "pact-admission+jwt"}}, nil},
		{"bad-aud", "admission/valid", [][]string{{"aud", "https://gateway.example/other", "https://gateway.example/finance"}}, nil},
		{"bad-sub", "admission/valid", [][]string{{"sub", "other-agent", "invoice-assistant"}}, nil},
		{"bad-holder-jkt", "admission/valid", [][]string{{"holder_jkt", "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"}}, nil},
		{"bad-digest", "admission/valid", [][]string{{"profile_digest", "b6pNI8i5pX5MtuxkaBw0M-4tmzdkGsHVS_Kyji7_uOU"}}, nil},
		{"bad-exp", "admission/valid", [][]string{{"exp", "exp_max", "1792080060"}, {"exp", "60 seconds", "iat"}}, nil},
		{"bad-terminal-reason", "admission/valid", [][]string{{"terminal_reason", "EXPIRED", "COMPLETED"}}, nil},
		{"bad-check-result", "admission/valid", [][]string{{"check nonce", "result FAIL", "want PASS"}}, nil},
		{"bad-reason-code", "admission/valid", [][]string{{"check nonce", "UNSPECIFIED_REASON", "REQUIREMENT_SATISFIED"}}, nil},
		{"missing-check", "admission/valid", [][]string{{"check intent-binding", "receipt carries no such check"}}, nil},
		{"absent-check-present", "selection/conservative-set-no-check", [][]string{{"selection-consistency-v1", "must not carry"}}, nil},
		{"omit-context-check", "admission/wrong-audience", [][]string{{"check security-hold-v1", "context_checks", "no result", "12.1"}}, nil},
		{"unperformed-check-passed", "admission/cancelled-evaluation", [][]string{{"check roles", "PASS", "not performed", "12.1"}}, nil},
		{"bad-evidence-ids", "selection/same-snapshot", [][]string{{"check reputation-context", "evidence_ids", "VW7HSF227CWWBU7wN09Q5A"}}, nil},
		{"bad-source-ref", "selection/same-snapshot", [][]string{{"check selection-consistency-v1", "source_ref", "selection-record:other"}}, map[string][][]string{
			"admission/valid": {{"check reputation-context", `source_ref "configured-validation-record:example-reputation-context"`, `want "configured-selection-record:example-selection"`}},
		}},
		{"two-admissible", "admission/replay-same-nonce-two-replicas", [][]string{{"concurrent batch", "decision ADMISSIBLE, decision ADMISSIBLE", "Problem REPLAY"}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			got := runMode(t, tt.mode, goodCases...)
			for id, r := range got {
				details, broken := tt.also[id]
				if id == tt.id {
					details, broken = tt.details, true
				}
				if !broken {
					if r.Status != StatusPass {
						t.Errorf("%s = %+v, want PASS: the mode does not touch it", id, r)
					}
					continue
				}
				if r.Status != StatusFail {
					t.Fatalf("%s = %+v, want FAIL", id, r)
				}
				// The details end with the command summary line, which no
				// difference line is.
				diffs := r.Details
				if n := len(diffs); n > 0 && strings.HasPrefix(diffs[n-1], "[") {
					diffs = diffs[:n-1]
				}
				if len(diffs) != len(details) {
					t.Fatalf("%s details %q, want %d difference lines", id, r.Details, len(details))
				}
				for i, subs := range details {
					if !detailsContain(diffs[i:i+1], subs...) {
						t.Errorf("%s detail %d = %q, want it to name %q", id, i+1, diffs[i], subs)
					}
				}
			}
		})
	}
}

// customRun runs the case id with an implementation that prints the good
// golden of id with its receipt line i re-signed after edit (and with kid or
// the signing key role changed by role).
func customRun(t *testing.T, id string, i int, role string, header func(*jws.Header), edit func(map[string]any)) Result {
	t.Helper()
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	lines := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(id), "evaluate.out"))
	lines[i] = mutator{keys: keys}.resign(t, lines[i], role, header, edit)
	return runPrinted(t, subsetRoot(t, id), id, lines)
}

// runPrinted runs the case id of root with a command that prints lines.
func runPrinted(t *testing.T, root, id string, lines []string) Result {
	t.Helper()
	out := filepath.Join(t.TempDir(), "stdout")
	writeFile(t, out, strings.Join(lines, "\n")+"\n")
	rep, err := Run(Config{FixturesRoot: root, Fixtures: []string{id}, EvaluateCmd: script(t, "cat "+out) + " {dir}", Capabilities: manifest.Capabilities()})
	if err != nil {
		t.Fatal(err)
	}
	return result(t, rep, id)
}

// TestEvaluateReceiptExpiry: the receipt's exp is at most the expected
// exp_max and at most 60 seconds after its iat (draft 12.1), each rule on
// its own. admission/cancelled-evaluation has exp_max 1792080070 and a
// receipt issued at the cancellation, iat 1792080010 and exp 1792080070.
func TestEvaluateReceiptExpiry(t *testing.T) {
	const id = "admission/cancelled-evaluation"
	tests := []struct {
		name string
		edit func(map[string]any)
		want Status
		subs []string
	}{
		{"as printed", func(p map[string]any) {}, StatusPass, nil},
		{"exp at exp_max, iat 60 earlier", func(p map[string]any) { p["exp"], p["iat"] = int64(1792080070), int64(1792080010) }, StatusPass, nil},
		{"exp one past exp_max", func(p map[string]any) { p["exp"], p["iat"] = int64(1792080071), int64(1792080011) }, StatusFail, []string{"exp 1792080071", "exp_max 1792080070"}},
		{"exp 61 after iat", func(p map[string]any) { p["iat"] = int64(1792080009) }, StatusFail, []string{"exp 1792080070", "60 seconds", "iat 1792080009"}},
		{"no exp", func(p map[string]any) { delete(p, "exp") }, StatusFail, []string{"exp"}},
		{"no iat", func(p map[string]any) { delete(p, "iat") }, StatusFail, []string{"iat"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := customRun(t, id, 0, "", nil, tt.edit)
			if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.subs)
			}
		})
	}
}

// TestEvaluateReceiptClaims: a claim the expected result names must be in
// the payload with that exact value; the signature must verify under the
// key the case names with the receipt's own kid; a payload that is not an
// AdmissionAttestation (a member of another type or an unknown one, draft 7.1)
// is no receipt.
func TestEvaluateReceiptClaims(t *testing.T) {
	const id = "admission/valid"
	tests := []struct {
		name   string
		role   string
		header func(*jws.Header)
		edit   func(map[string]any)
		want   Status
		subs   []string
	}{
		{"as printed", "", nil, func(p map[string]any) {}, StatusPass, nil},
		{"claim missing", "", nil, func(p map[string]any) { delete(p, "aud") }, StatusFail, []string{"claim aud", "missing"}},
		{"claim of another JSON type", "", nil, func(p map[string]any) { p["tenant_id"] = 7 }, StatusFail, []string{"receipt payload"}},
		{"unnamed claim changed", "", nil, func(p map[string]any) { p["jti"] = "another" }, StatusPass, nil},
		{"unknown member added", "", nil, func(p map[string]any) { p["extra"] = true }, StatusFail, []string{"receipt payload"}},
		{"kid unknown", "", func(h *jws.Header) { h.Kid = "test-validator-key-9" }, func(p map[string]any) {}, StatusFail, []string{"signature", "kid-unknown"}},
		{"signed by the issuer key", "issuer", nil, func(p map[string]any) {}, StatusFail, []string{"signature", "signature-invalid"}},
		{"same check twice, one wrong", "", nil, func(p map[string]any) {
			c := map[string]any{}
			for k, v := range check(t, p, "nonce") {
				c[k] = v
			}
			c["result"] = "FAIL"
			p["checks"] = append(p["checks"].([]any), c)
		}, StatusFail, []string{"check nonce", "FAIL"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := customRun(t, id, 0, tt.role, tt.header, tt.edit)
			if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.subs)
			}
		})
	}
}

// TestEvaluateContextChecks: a receipt carries exactly one result for each
// check the contract's context_checks names, whether decision.json lists it
// or not (draft 12.1); the result of a check decision.json does not list is
// not judged, and a check outside context_checks may be repeated or left out.
// admission/wrong-audience lists contract-validity only; its contract names
// native-principal-binding-v1, purpose-operation-v1, native-delegation-v1
// and security-hold-v1 (Appendix B.3). admission/valid lists every check of
// B.7, so a context check it lacks is reported once, as a listed check.
func TestEvaluateContextChecks(t *testing.T) {
	const negative, positive = "admission/wrong-audience", "admission/valid"
	without := func(ids ...string) func(map[string]any) {
		return func(p map[string]any) {
			var kept []any
			for _, c := range p["checks"].([]any) {
				if !slices.Contains(ids, c.(map[string]any)["check_id"].(string)) {
					kept = append(kept, c)
				}
			}
			p["checks"] = kept
		}
	}
	twice := func(id string) func(map[string]any) {
		return func(p map[string]any) { p["checks"] = append(p["checks"].([]any), check(t, p, id)) }
	}
	tests := []struct {
		name, id string
		edit     func(map[string]any)
		want     Status
		// subs are the substrings of each difference line, in order.
		subs [][]string
	}{
		{"as printed", negative, func(p map[string]any) {}, StatusPass, nil},
		{"unlisted context check omitted", negative, without("native-delegation-v1"), StatusFail, [][]string{{"check native-delegation-v1", "context_checks", "no result", "12.1"}}},
		{"two context checks omitted", negative, without("purpose-operation-v1", "security-hold-v1"), StatusFail, [][]string{
			{"check purpose-operation-v1", "no result"}, {"check security-hold-v1", "no result"}}},
		{"context check repeated with the same result", negative, twice("native-principal-binding-v1"), StatusFail, [][]string{{"check native-principal-binding-v1", "context_checks", "2 results", "exactly one", "12.1"}}},
		{"listed context check repeated", positive, twice("security-hold-v1"), StatusFail, [][]string{{"check security-hold-v1", "2 results", "exactly one"}}},
		{"listed context check omitted", positive, without("native-delegation-v1"), StatusFail, [][]string{{"check native-delegation-v1", "receipt carries no such check", "want result PASS"}}},
		{"unlisted context check not evaluated", negative, func(p map[string]any) {
			c := check(t, p, "security-hold-v1")
			c["result"], c["reason_code"] = "UNKNOWN", "NOT_EVALUATED"
		}, StatusPass, nil},
		{"check outside context_checks omitted", negative, without("isolation"), StatusPass, nil},
		{"check outside context_checks repeated", negative, twice("nonce"), StatusPass, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := customRun(t, tt.id, 0, "", nil, tt.edit)
			if r.Status != tt.want {
				t.Fatalf("= %+v, want %s", r, tt.want)
			}
			diffs := r.Details
			if n := len(diffs); n > 0 && strings.HasPrefix(diffs[n-1], "[") {
				diffs = diffs[:n-1]
			}
			if tt.want == StatusFail && len(diffs) != len(tt.subs) {
				t.Fatalf("details %q, want %d difference lines", r.Details, len(tt.subs))
			}
			for i, subs := range tt.subs {
				if !detailsContain(diffs[i:i+1], subs...) {
					t.Errorf("detail %d = %q, want it to name %q", i+1, diffs[i], subs)
				}
			}
		})
	}
}

// editExpected rewrites the expected decision.json of the case id in root
// through f.
func editExpected(t *testing.T, root, id string, f func(map[string]any)) {
	t.Helper()
	p := filepath.Join(root, "expected", filepath.FromSlash(id), "decision.json")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	f(v)
	if b, err = json.Marshal(v); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, string(b))
}

// TestEvaluateDigestsOfTheCaseFiles: the receipt's profile, intent and
// requirements digests are those of the case's own files (draft 7.4:
// object_digest of profile.json and intent.json, artifact_digest of the
// signed contract), also when the expected result does not name them.
func TestEvaluateDigestsOfTheCaseFiles(t *testing.T) {
	const id = "admission/valid"
	other := "b6pNI8i5pX5MtuxkaBw0M-4tmzdkGsHVS_Kyji7_uOU" // the profile digest: a digest of some other object
	for _, member := range []string{"profile_digest", "intent_digest", "requirements_digest"} {
		t.Run(member, func(t *testing.T) {
			keys, err := evalcase.LoadKeys(repoFixtures)
			if err != nil {
				t.Fatal(err)
			}
			root := subsetRoot(t, id)
			editExpected(t, root, id, func(d map[string]any) {
				delete(d["receipt"].(map[string]any)["claims"].(map[string]any), member)
			})
			good := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(id), "evaluate.out"))
			if r := runPrinted(t, root, id, good); r.Status != StatusPass {
				t.Fatalf("good receipt = %+v, want PASS", r)
			}
			bad := mutator{keys: keys}.resign(t, good[0], "", nil, func(p map[string]any) {
				if p[member] == other {
					p[member] = "x" + other[1:]
				} else {
					p[member] = other
				}
			})
			r := runPrinted(t, root, id, []string{bad})
			if r.Status != StatusFail || !detailsContain(r.Details, member, "case files") {
				t.Errorf("= %+v, want FAIL naming %s and the case files", r, member)
			}
		})
	}
}

// TestEvaluateBatchChecksTheReceipt: the responses of a concurrent batch
// match the expected entries in any order, but each is judged in full, not
// by its decision alone.
func TestEvaluateBatchChecksTheReceipt(t *testing.T) {
	const id = "admission/replay-same-nonce-two-replicas"
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	good := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(id), "evaluate.out"))
	root := subsetRoot(t, id)
	if r := runPrinted(t, root, id, good); r.Status != StatusPass {
		t.Fatalf("good = %+v, want PASS", r)
	}
	if r := runPrinted(t, root, id, []string{good[1], good[0]}); r.Status != StatusPass {
		t.Errorf("swapped = %+v, want PASS: a concurrent batch is unordered", r)
	}
	bad := mutator{keys: keys}.resign(t, good[0], "", nil, set("aud", "https://gateway.example/other"))
	for _, lines := range [][]string{{bad, good[1]}, {good[1], bad}} {
		if r := runPrinted(t, root, id, lines); r.Status != StatusFail || !detailsContain(r.Details, "aud", "https://gateway.example/other") {
			t.Errorf("%v = %+v, want FAIL naming the aud", lines[0][:10], r)
		}
	}
	// A wrong kind and a wrong receipt: both are reported.
	invalid := `{"type":"about:blank","title":"Rejected","status":401,"code":"INVALID_PROOF","request_id":"r-1"}`
	r := runPrinted(t, root, id, []string{bad, invalid})
	if r.Status != StatusFail || !detailsContain(r.Details, "Problem INVALID_PROOF", "Problem REPLAY") || !detailsContain(r.Details, "line 1", "aud") {
		t.Errorf("= %+v, want FAIL naming the kinds and the aud", r)
	}
}

// TestEvaluateNeedsAValidatorKey: a receipt is never accepted unverified.
// The key is the expected result's receipt.signer, else config.json's
// validator.key; a case that names neither fails.
func TestEvaluateNeedsAValidatorKey(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(goldenDir, "admission", "valid", "evaluate.out"))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(golden))
	ok := `{"decision":"ADMISSIBLE","transport_code":null}`
	withSigner := `{"decision":"ADMISSIBLE","transport_code":null,"receipt":{"typ":"pact-admission+jwt","signer":"keys/validator.jwk.json"}}`
	badSigner := `{"decision":"ADMISSIBLE","transport_code":null,"receipt":{"typ":"pact-admission+jwt","signer":"keys/issuer.jwk.json"}}`
	badTyp := `{"decision":"ADMISSIBLE","transport_code":null,"receipt":{"typ":"pact-evidence+jwt","signer":"keys/validator.jwk.json"}}`
	escape := `{"decision":"ADMISSIBLE","transport_code":null,"receipt":{"signer":"../keys/validator.jwk.json"}}`
	notKey := `{"decision":"ADMISSIBLE","transport_code":null,"receipt":{"signer":"admission/ok/native_context.json"}}`
	tests := []struct {
		name, config, decision string
		want                   Status
		subs                   []string
	}{
		{"key in config", validatorConfig, ok, StatusPass, nil},
		{"key in the expected receipt", `{}`, withSigner, StatusPass, nil},
		{"expected receipt names the key, config another", validatorConfig, badSigner, StatusFail, []string{"signature"}},
		{"no key anywhere", `{}`, ok, StatusFail, []string{"validator key", "receipt.signer", "validator.key"}},
		{"expected typ is not the admission typ", validatorConfig, badTyp, StatusFail, []string{"receipt typ pact-admission+jwt", "pact-evidence+jwt"}},
		{"key path leaves the fixture directory", validatorConfig, escape, StatusFail, []string{"validator key", "inside the fixture directory"}},
		{"key file is no JWK", validatorConfig, notKey, StatusFail, []string{"validator key", "admission/ok/native_context.json"}},
		{"key file missing", `{"validator":{"key":"keys/none.jwk.json"}}`, ok, StatusFail, []string{"keys/none.jwk.json"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{
				"admission/ok/config.json":            tt.config,
				"admission/ok/native_context.json":    `{}`,
				"expected/admission/ok/decision.json": tt.decision,
			}
			root := evalTree(t, []entry{evalEntry("admission/ok", "ADMISSIBLE")}, files)
			// Add the issuer key too, for the case that names the wrong one.
			b, err := os.ReadFile(filepath.Join(repoFixtures, "keys", "issuer.jwk.json"))
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(root, "keys", "issuer.jwk.json"), string(b))
			r := runPrinted(t, root, "admission/ok", []string{line})
			if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.subs)
			}
		})
	}
}

// TestEvaluateClaimsCompareByValue: a claim is compared as a JSON value
// (draft 7.4 canonical form), not as text: the payload may write the same
// string with escapes.
func TestEvaluateClaimsCompareByValue(t *testing.T) {
	const id = "admission/valid"
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	good := readLines(t, filepath.Join(goldenDir, filepath.FromSlash(id), "evaluate.out"))
	parts := strings.Split(good[0], ".")
	payload := string(decodePart(t, parts[1]))
	const plain, escaped = `"aud":"https://gateway.example/finance"`, `"aud":"https:\/\/gateway.example\/\u0066inance"`
	if strings.Count(payload, plain) != 1 {
		t.Fatalf("payload does not hold %s once", plain)
	}
	line, err := jws.Sign(jws.Header{Typ: jws.TypAdmission, Kid: keys["validator"].Public.Kid}, []byte(strings.Replace(payload, plain, escaped, 1)), keys["validator"].Private)
	if err != nil {
		t.Fatal(err)
	}
	if r := runPrinted(t, subsetRoot(t, id), id, []string{line}); r.Status != StatusPass {
		t.Errorf("= %+v, want PASS: the escaped aud is the same string", r)
	}
}

// TestEvaluateCheckFields: evidence_ids_include and source_ref are compared
// when the expected check names them. selection/same-snapshot expects
// evidence_ids to include the presented snapshot's jti on both checks and a
// source_ref on selection-consistency-v1 (draft 12.1, A.2).
func TestEvaluateCheckFields(t *testing.T) {
	const id = "selection/same-snapshot"
	tests := []struct {
		name string
		edit func(map[string]any)
		want Status
		subs []string
	}{
		{"as printed", func(p map[string]any) {}, StatusPass, nil},
		{"source_ref null", func(p map[string]any) { check(t, p, "selection-consistency-v1")["source_ref"] = nil }, StatusFail, []string{"check selection-consistency-v1", "source_ref null"}},
		{"evidence_ids empty", func(p map[string]any) { check(t, p, "selection-consistency-v1")["evidence_ids"] = []any{} }, StatusFail, []string{"check selection-consistency-v1", "evidence_ids"}},
		{"evidence_ids also hold another id", func(p map[string]any) {
			c := check(t, p, "reputation-context")
			c["evidence_ids"] = append([]any{"another"}, c["evidence_ids"].([]any)...)
		}, StatusPass, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := customRun(t, id, 0, "", nil, tt.edit)
			if r.Status != tt.want || (tt.subs != nil && !detailsContain(r.Details, tt.subs...)) {
				t.Errorf("= %+v, want %s naming %q", r, tt.want, tt.subs)
			}
		})
	}
}
