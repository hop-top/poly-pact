package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
)

// manifestEntry is the part of a manifest entry these tests read.
type manifestEntry struct {
	ID, Kind, Path string
	Expected       *string
	Outcome        *string
}

// manifestEntries reads the committed manifest.
func manifestEntries(t testing.TB) []manifestEntry {
	t.Helper()
	var m struct {
		Entries []manifestEntry `json:"entries"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(repoFixtures, "manifest.json")), &m); err != nil {
		t.Fatal(err)
	}
	return m.Entries
}

// evaluateRuns returns the signed cases of the evaluate entries of the
// manifest: the admission, approval, delegation, selection and transport
// cases.
func evaluateRuns(t testing.TB) []evalcase.Dir {
	t.Helper()
	kind := map[string]string{}
	for _, e := range manifestEntries(t) {
		kind[e.ID] = e.Kind
	}
	var out []evalcase.Dir
	for _, prefix := range []string{"admission/", "approval/", "delegation/", "selection/", "transport/"} {
		for _, r := range repoRuns(t, prefix) {
			if kind[r.Entry] == "evaluate" {
				out = append(out, r)
			}
		}
	}
	return out
}

// TestCasesAreRegistered: generate signs exactly the committed admission,
// approval, delegation and selection evaluation cases, each an evaluate
// entry of the manifest whose directory, or for a multi-exchange case each
// of its exchange directories, holds a signing.json with one presentation.
func TestCasesAreRegistered(t *testing.T) {
	entries := manifestEntries(t)
	runs := evaluateRuns(t)
	signed := map[string]bool{}
	for _, r := range runs {
		signed[r.Entry] = true
		i := slices.IndexFunc(entries, func(e manifestEntry) bool { return e.ID == r.Entry })
		if i < 0 {
			t.Errorf("%s: no manifest entry", r.Entry)
			continue
		}
		if e := entries[i]; e.Kind != "evaluate" || e.Path+strings.TrimPrefix(r.ID, r.Entry) != r.Path {
			t.Errorf("%s: manifest entry kind %q path %q", r.ID, e.Kind, e.Path)
		}
		if len(r.Signing.Presentations) != 1 {
			t.Errorf("%s: %d presentations, want 1", r.Entry, len(r.Signing.Presentations))
		}
	}
	n := 0
	for _, e := range entries {
		if e.Kind == "evaluate" {
			n++
		}
	}
	if n != len(signed) {
		t.Errorf("%d evaluate entries, %d signed evaluation cases", n, len(signed))
	}
}

// expectedResponse is one expected response of decision.json
// (spec/v1.0/fixtures/README.md): a transport rejection or a receipt.
type expectedResponse struct {
	Decision      string  `json:"decision"`
	TransportCode *string `json:"transport_code"`
	Checks        []struct {
		CheckID    string `json:"check_id"`
		Result     string `json:"result"`
		ReasonCode string `json:"reason_code"`
	} `json:"checks"`
	Receipt *struct {
		Typ    string                     `json:"typ"`
		Signer string                     `json:"signer"`
		Claims map[string]json.RawMessage `json:"claims"`
		ExpMax int64                      `json:"exp_max"`
	} `json:"receipt"`
	Executed *bool `json:"executed"`
}

// outcome is the manifest outcome token of the response.
func (r expectedResponse) outcome() string {
	if r.TransportCode != nil {
		return "REJECTED"
	}
	return r.Decision
}

// expectedDecision is decision.json: one response at the top level or, in
// format v2, one per submission under responses, the handoff results, and
// the subject pointer that names the response the manifest outcome sums up.
type expectedDecision struct {
	expectedResponse
	Responses []expectedResponse `json:"responses"`
	Handoff   []struct {
		TransportCode *string `json:"transport_code"`
	} `json:"handoff"`
	Subject string `json:"subject"`
}

// subjectOutcome is the outcome of the response or handoff entry that
// subject names (spec/v1.0/fixtures/README.md, decision.json additions).
func (d expectedDecision) subjectOutcome() (string, bool) {
	switch s := d.Subject; {
	case s == "":
		return d.outcome(), d.Responses == nil
	case strings.HasPrefix(s, "/responses/"):
		for i, r := range d.Responses {
			if s == "/responses/"+strconv.Itoa(i) {
				return r.outcome(), true
			}
		}
	case strings.HasPrefix(s, "/handoff/"):
		for i, h := range d.Handoff {
			if s == "/handoff/"+strconv.Itoa(i) {
				if h.TransportCode == nil {
					return "ACCEPTED", true
				}
				return "REJECTED", true
			}
		}
	}
	return "", false
}

func quoted(s string) string { return `"` + s + `"` }

// TestExpectedResultsBindTheirCase: each case's decision.json, or each
// exchange's of a multi-exchange case, agrees with its manifest outcome when
// it is the entry's expected file and, when it expects a receipt, names the
// digests of that case's or exchange's own committed files (draft Sections
// 7.4 and 12.1), so a re-signed contract or an edited profile cannot leave a
// stale expectation.
func TestExpectedResultsBindTheirCase(t *testing.T) {
	entries := manifestEntries(t)
	for _, c := range evaluateRuns(t) {
		t.Run(c.ID, func(t *testing.T) {
			i := slices.IndexFunc(entries, func(e manifestEntry) bool {
				return e.ID == c.Entry
			})
			if i < 0 || entries[i].Expected == nil || entries[i].Outcome == nil {
				t.Fatalf("no manifest entry with an expected result")
			}
			e := entries[i]
			exp := "expected/" + c.ID + "/decision.json"
			subject := *e.Expected == exp
			if !subject && c.ID == c.Entry {
				t.Errorf("expected %q", *e.Expected)
			}
			raw := readFile(t, filepath.Join(repoFixtures, filepath.FromSlash(exp)))
			strictObject(t, raw)
			var got expectedDecision
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if o, ok := got.subjectOutcome(); !ok || (subject && o != *e.Outcome) {
				t.Errorf("subject %q names outcome %q (found %v), manifest outcome %q", got.Subject, o, ok, *e.Outcome)
			}
			responses := got.Responses
			if responses == nil {
				responses = []expectedResponse{got.expectedResponse}
			}
			dir := filepath.Join(repoFixtures, filepath.FromSlash(c.Path))
			for _, r := range responses {
				checkResponse(t, c, dir, r)
			}
		})
	}
}

// checkResponse checks one expected response of the case c, whose
// directory is dir.
func checkResponse(t *testing.T, c evalcase.Dir, dir string, got expectedResponse) {
	t.Helper()
	if got.TransportCode != nil {
		if got.Decision != "" || got.Receipt != nil || got.Checks != nil || got.Executed != nil {
			t.Errorf("transport rejection %s carries receipt members", *got.TransportCode)
		}
		return
	}
	if got.Receipt == nil || got.Executed == nil {
		t.Fatalf("decision %q, receipt %v, executed %v", got.Decision, got.Receipt != nil, got.Executed != nil)
	}
	r := got.Receipt
	// A cancelled or expired evaluation is DEFERRED by its terminal reason
	// (draft Section 12.2), whatever checks completed before it ended.
	terminal := string(r.Claims["terminal_reason"])
	ended := terminal == quoted("EXPIRED") || terminal == quoted("CANCELLED")
	if ended && got.Decision != "DEFERRED" {
		t.Errorf("terminal_reason %s with decision %s, want DEFERRED", terminal, got.Decision)
	}
	if len(got.Checks) == 0 && !ended {
		t.Fatalf("decision %q with no checks", got.Decision)
	}
	want := map[string]string{"PASS": "", "FAIL": "", "UNKNOWN": "", "NOT_APPLICABLE": ""}
	results := map[string]bool{}
	for _, ch := range got.Checks {
		if _, ok := want[ch.Result]; !ok || ch.CheckID == "" || ch.ReasonCode == "" {
			t.Errorf("check %+v", ch)
		}
		results[ch.Result] = true
	}
	switch got.Decision {
	case "ADMISSIBLE":
		if results["FAIL"] || results["UNKNOWN"] {
			t.Error("ADMISSIBLE with a FAIL or UNKNOWN check")
		}
	case "INADMISSIBLE":
		if !results["FAIL"] {
			t.Error("INADMISSIBLE without a FAIL check")
		}
	case "DEFERRED":
		if !results["UNKNOWN"] && !results["FAIL"] && !ended {
			t.Error("DEFERRED without an UNKNOWN or FAIL check or a terminal reason")
		}
	default:
		t.Errorf("decision %q", got.Decision)
	}
	var native struct {
		Authorize bool `json:"authorize"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, "native_context.json")), &native); err != nil {
		t.Fatal(err)
	}
	// Execution needs both admission and native authorization
	// (draft Sections 5, invariant 1, and 11.1, step 7).
	if *got.Executed != (got.Decision == "ADMISSIBLE" && native.Authorize) {
		t.Errorf("executed %v with decision %s and authorize %v", *got.Executed, got.Decision, native.Authorize)
	}
	// The receipt signer is the validator key of config.json: the ES256
	// validator test key, or the Ed25519 test key in a case whose gateway
	// publishes Ed25519 in jws_algorithms (draft Sections 7.2, 13.1).
	var cfg struct {
		Gateway struct {
			JWSAlgorithms []string `json:"jws_algorithms"`
		} `json:"gateway"`
		Validator struct {
			Key string `json:"key"`
		} `json:"validator"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, "config.json")), &cfg); err != nil {
		t.Fatal(err)
	}
	signer := "keys/validator.jwk.json"
	if slices.Contains(cfg.Gateway.JWSAlgorithms, jws.AlgEd25519) {
		signer = "keys/ed25519.jwk.json"
	}
	if r.Typ != jws.TypAdmission || r.Signer != signer || cfg.Validator.Key != signer || r.ExpMax <= 0 {
		t.Errorf("receipt typ %q signer %q (config.json validator.key %q, want %q) exp_max %d", r.Typ, r.Signer, cfg.Validator.Key, signer, r.ExpMax)
	}
	if string(r.Claims["decision"]) != quoted(got.Decision) {
		t.Errorf("claims decision %s, want %s", r.Claims["decision"], got.Decision)
	}
	if string(r.Claims["presentation_id"]) != quoted(c.Signing.Presentations[0].JTI) {
		t.Errorf("presentation_id %s, want %s", r.Claims["presentation_id"], c.Signing.Presentations[0].JTI)
	}
	reqDigest, err := digest.ArtifactDigest(string(readFile(t, filepath.Join(dir, "signed", "contract.jws"))))
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Claims["requirements_digest"]) != quoted(string(reqDigest)) {
		t.Errorf("requirements_digest %s, want %s", r.Claims["requirements_digest"], reqDigest)
	}
	// A receipt's operation_digest hashes the operation the validator
	// evaluated, the actual one when the case has it (draft Section 12.1).
	operation := "operation.json"
	if _, err := os.Stat(filepath.Join(dir, "actual_operation.json")); err == nil {
		operation = "actual_operation.json"
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for k, file := range map[string]string{"profile_digest": "profile.json", "intent_digest": "intent.json", "operation_digest": operation} {
		v, ok := r.Claims[k]
		if !ok {
			continue // not pinned by this case
		}
		d, err := digest.ObjectDigest(json.RawMessage(readFile(t, filepath.Join(dir, file))))
		if err != nil {
			t.Fatal(err)
		}
		if string(v) != quoted(string(d)) {
			t.Errorf("%s %s is not the object digest of %s (%s)", k, v, file, d)
		}
	}
	// Its operation_id and principal_id are those of the same operation,
	// the principal being the one authenticate_native established (draft
	// Sections 12.1 and 17.1).
	var evaluated struct {
		OperationID string `json:"operation_id"`
		PrincipalID string `json:"principal_id"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(dir, operation)), &evaluated); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"operation_id": evaluated.OperationID, "principal_id": evaluated.PrincipalID} {
		v, ok := r.Claims[k]
		if !ok {
			continue // not pinned by this case
		}
		var got string
		if err := json.Unmarshal(v, &got); err != nil || want == "" || got != want {
			t.Errorf("%s %s is not the %s of %s (%q)", k, v, k, operation, want)
		}
	}
}

// TestPresentationKeys: a case signed by the holder key presents the key
// its profile and contract name; a case signed by another key presents one
// they do not name, so the case exercises the holder binding of draft
// Sections 6.2 and 7.2.
func TestPresentationKeys(t *testing.T) {
	holder, err := jws.Thumbprint(fixtureJWK(t, "holder"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range evaluateRuns(t) {
		dir := filepath.Join(repoFixtures, filepath.FromSlash(c.Path))
		pres := c.Signing.Presentations[0]
		p := verifyAs(t, string(readFile(t, filepath.Join(dir, filepath.FromSlash(pres.Signed)))), jws.TypPresentation, pres.Signer)
		if p.Header.JWK == nil {
			t.Fatalf("%s: presentation embeds no jwk", c.Entry)
		}
		presented, err := jws.Thumbprint(*p.Header.JWK)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"profile.json", "contract.json"} {
			b := readFile(t, filepath.Join(dir, file))
			named := strings.Contains(string(b), quoted(string(presented)))
			if (pres.Signer == "holder") != named || !strings.Contains(string(b), quoted(string(holder))) {
				t.Errorf("%s: %s names the holder key %v, the presented key %v (signer %s)", c.Entry, file,
					strings.Contains(string(b), quoted(string(holder))), named, pres.Signer)
			}
		}
	}
}

// objectDigestOf is the object_digest (draft Section 7.4) of the JSON value b.
func objectDigestOf(t testing.TB, b []byte) string {
	t.Helper()
	d, err := digest.ObjectDigest(json.RawMessage(b))
	if err != nil {
		t.Fatal(err)
	}
	return string(d)
}

// payloadOf returns the payload of a compact JWS without verifying it.
func payloadOf(t testing.TB, compact string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(segments(t, strings.TrimSpace(compact))[1])
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// operationBindingProblems checks that the operation the case presents,
// operation.json, is the one the contract was issued for: the
// operation_digest of contract.json and of signed/contract.jws is the
// object_digest of operation.json, and so is the digest of the operation the
// signed presentation embeds (draft Sections 9.1, 11.3 step 5 and A.2).
// actual_operation.json is the gateway's own mapping of the request and is
// what the contract is compared with; it is not hashed into the contract.
func operationBindingProblems(t testing.TB, dir string) []string {
	t.Helper()
	want := objectDigestOf(t, readFile(t, filepath.Join(dir, "operation.json")))
	var out []string
	// digest is the operation_digest member of the contract object b.
	digest := func(b []byte) string {
		var got string
		_ = json.Unmarshal(strictObject(t, b)["operation_digest"], &got)
		return got
	}
	contract := readFile(t, filepath.Join(dir, "contract.json"))
	signed := payloadOf(t, string(readFile(t, filepath.Join(dir, "signed", "contract.jws"))))
	presented := strictObject(t, payloadOf(t, string(readFile(t, filepath.Join(dir, "signed", "presentation.jws")))))["operation"]
	for _, g := range []struct{ label, got string }{
		{"contract.json operation_digest", digest(contract)},
		{"signed contract operation_digest", digest(signed)},
		{"presentation operation, as object_digest,", objectDigestOf(t, presented)},
	} {
		if g.got != want {
			out = append(out, fmt.Sprintf("%s %s, want object_digest of operation.json %s", g.label, g.got, want))
		}
	}
	return out
}

// TestContractBindsPresentedOperation: in every evaluation case the contract
// is issued for the presented operation, whatever the gateway later maps
// from the actual request, so a case that modifies the operation does so in
// actual_operation.json and leaves the contract's operation_digest alone.
func TestContractBindsPresentedOperation(t *testing.T) {
	for _, c := range evaluateRuns(t) {
		t.Run(c.ID, func(t *testing.T) {
			for _, p := range operationBindingProblems(t, filepath.Join(repoFixtures, filepath.FromSlash(c.Path))) {
				t.Error(p)
			}
		})
	}
}

// TestOperationBindingMutants: the check reports each way a case can pair a
// contract with an operation other than the presented one.
func TestOperationBindingMutants(t *testing.T) {
	const caseDir = "admission/modified-body"
	other := objectDigestOf(t, readFile(t, filepath.Join(repoFixtures, caseDir, "actual_operation.json")))
	resign := func(t *testing.T, path string, edit func(map[string]any)) {
		t.Helper()
		parts := segments(t, strings.TrimSpace(string(readFile(t, path))))
		var m map[string]any
		if err := json.Unmarshal(payloadOf(t, strings.Join(parts[:], ".")), &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		parts[1] = base64.RawURLEncoding.EncodeToString(b)
		writeFile(t, path, []byte(strings.Join(parts[:], ".")))
	}
	actual := func(t *testing.T, dir string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(readFile(t, filepath.Join(dir, "actual_operation.json")), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	for _, mu := range []struct {
		name string
		edit func(t *testing.T, dir string)
	}{
		{"contract.json hashes the actual operation", func(t *testing.T, dir string) {
			p := filepath.Join(dir, "contract.json")
			b := bytes.Replace(readFile(t, p), []byte(objectDigestOf(t, readFile(t, filepath.Join(dir, "operation.json")))), []byte(other), 1)
			writeFile(t, p, b)
		}},
		{"signed contract hashes the actual operation", func(t *testing.T, dir string) {
			resign(t, filepath.Join(dir, "signed", "contract.jws"), func(m map[string]any) { m["operation_digest"] = other })
		}},
		{"presentation embeds the actual operation", func(t *testing.T, dir string) {
			a := actual(t, dir)
			resign(t, filepath.Join(dir, "signed", "presentation.jws"), func(m map[string]any) { m["operation"] = a })
		}},
		{"operation.json is replaced by the actual operation", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "operation.json"), readFile(t, filepath.Join(dir, "actual_operation.json")))
		}},
	} {
		t.Run(mu.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "case")
			copyDir(t, filepath.Join(repoFixtures, caseDir), dir)
			if p := operationBindingProblems(t, dir); len(p) != 0 {
				t.Fatalf("committed case: %v", p)
			}
			mu.edit(t, dir)
			if p := operationBindingProblems(t, dir); len(p) == 0 {
				t.Error("mutant not reported")
			}
		})
	}
}
