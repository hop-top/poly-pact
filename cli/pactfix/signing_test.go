package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
)

// The generator contract of spec/v1.0/fixtures/README.md, section Format v2:
// signing.json, per-artifact times, payload_signed, digests, and the four
// format v2 test keys.

// canonical is v in RFC 8785 form.
func canonical(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if b, err = jcs.Canonicalize(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// editSigning rewrites signing.json of the case dir under root.
func editSigning(t testing.TB, root, dir string, edit func(s map[string]any)) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(dir), "signing.json")
	var s map[string]any
	if err := json.Unmarshal(readFile(t, p), &s); err != nil {
		t.Fatal(err)
	}
	edit(s)
	writeFile(t, p, canonical(t, s))
}

// artifactAt returns artifacts[i] of a signing.json being edited.
func artifactAt(s map[string]any, i int) map[string]any {
	return s["artifacts"].([]any)[i].(map[string]any)
}

func presentationAt(s map[string]any, i int) map[string]any {
	return s["presentations"].([]any)[i].(map[string]any)
}

// editDecoded replaces old by repl, once, in a decoded file, which stays
// canonical when old and repl are canonical member texts.
func editDecoded(t testing.TB, root, rel, old, repl string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	b := readFile(t, p)
	if bytes.Count(b, []byte(old)) != 1 {
		t.Fatalf("%s holds %q %d times, want once", rel, old, bytes.Count(b, []byte(old)))
	}
	writeFile(t, p, bytes.Replace(b, []byte(old), []byte(repl), 1))
}

// addEntry adds a manifest entry of kind to the tree root, with its case
// directory dir holding files (decoded objects are canonicalized) and a
// signing.json.
func addEntry(t testing.TB, root, kind, dir string, files map[string]any, signing map[string]any) {
	t.Helper()
	p := filepath.Join(root, "manifest.json")
	var m map[string]any
	if err := json.Unmarshal(readFile(t, p), &m); err != nil {
		t.Fatal(err)
	}
	m["entries"] = append(m["entries"].([]any), map[string]any{
		"id": dir, "kind": kind, "scope": "runner", "path": dir,
		"expected": "expected/" + dir + "/x.json", "outcome": "MATCH",
		"spec_map_row": "CL-C", "draft_section": "C",
	})
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, b)
	for rel, v := range files {
		writeFile(t, filepath.Join(root, filepath.FromSlash(dir), filepath.FromSlash(rel)), canonical(t, v))
	}
	writeFile(t, filepath.Join(root, filepath.FromSlash(dir), "signing.json"), canonical(t, signing))
}

func changedFiles(res []genResult) []string {
	var out []string
	for _, r := range res {
		if r.Changed {
			out = append(out, r.File)
		}
	}
	return out
}

func generateErr(t *testing.T, root, want string) {
	t.Helper()
	_, err := generate(root, false, nil)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error %v, want one mentioning %q", err, want)
	}
}

// TestGenerateNeedsSigningJSON: a case directory with a signed file and no
// signing.json stops the run; one with neither is not signed.
func TestGenerateNeedsSigningJSON(t *testing.T) {
	root := unsignedTree(t)
	removeFile(t, filepath.Join(root, validCase, "signing.json"))
	for _, r := range mustGenerate(t, root, false) {
		if strings.HasPrefix(r.File, validCase+"/") {
			t.Errorf("%s generated without a signing.json", r.File)
		}
	}
	writeFile(t, filepath.Join(root, validCase, "signed", "contract.jws"), []byte("e30.e30.e30"))
	generateErr(t, root, "no signing.json")
	generateErr(t, root, "signed/contract.jws")
}

// TestGenerateUnnamedSignedFile: a signed file that no entry of the case's
// signing.json names stops the run.
func TestGenerateUnnamedSignedFile(t *testing.T) {
	root := unsignedTree(t)
	writeFile(t, filepath.Join(root, validCase, "signed", "evidence", "extra.jws"), []byte("e30.e30.e30"))
	generateErr(t, root, "signed/evidence/extra.jws")
	generateErr(t, root, "named by no entry")
}

// TestGenerateWalksManifest: generate signs the cases the manifest lists and
// never walks the tree for others.
func TestGenerateWalksManifest(t *testing.T) {
	root := unsignedTree(t)
	const other = "admission/zz-unlisted"
	copyDir(t, filepath.Join(root, validCase), filepath.Join(root, other))
	for _, r := range mustGenerate(t, root, false) {
		if strings.HasPrefix(r.File, other+"/") {
			t.Fatalf("%s generated: the case is not in the manifest", r.File)
		}
	}
	if _, err := os.Stat(filepath.Join(root, other, "signed")); err == nil {
		t.Fatal("an unlisted case was signed")
	}
	if _, err := generate(root, false, []string{other}); err == nil {
		t.Error("an unlisted case was accepted by name")
	}
	// Only entries of kind evaluate, outcomes and learning are cases.
	const vector = "vectors/zz-case"
	addEntry(t, root, "vector", vector, nil, map[string]any{"artifacts": []any{}})
	copyDir(t, filepath.Join(root, validCase), filepath.Join(root, vector))
	if err := os.RemoveAll(filepath.Join(root, vector, "signed")); err != nil {
		t.Fatal(err)
	}
	mustGenerate(t, root, false)
	if _, err := os.Stat(filepath.Join(root, vector, "signed")); err == nil {
		t.Fatal("a vector entry was signed as a case")
	}
	addEntry(t, root, "evaluate", other, nil, map[string]any{"artifacts": []any{}})
	removeFile(t, filepath.Join(root, other, "signing.json"))
	copyDir(t, filepath.Join(root, validCase), filepath.Join(root, other))
	res, err := generate(root, false, []string{other})
	if err != nil || len(res) != len(signedFiles) {
		t.Fatalf("listed case: %d results (%v)", len(res), err)
	}
}

// TestGeneratePerArtifactTimes: an artifact entry's iat, nbf and exp are
// what its decoded payload must carry (nbf defaults to the iat), and a
// presentation entry's are those of the built presentation (exp defaults to
// iat + 60).
func TestGeneratePerArtifactTimes(t *testing.T) {
	issued := func(t *testing.T) string {
		root := unsignedTree(t)
		editDecoded(t, root, validCase+"/contract.json", `"iat":1792080000`, `"iat":1792080030`)
		editDecoded(t, root, validCase+"/contract.json", `"nbf":1792080000`, `"nbf":1792080030`)
		editDecoded(t, root, validCase+"/contract.json", `"exp":1792080060`, `"exp":1792080090`)
		editSigning(t, root, validCase, func(s map[string]any) {
			c := artifactAt(s, 0)
			c["iat"], c["exp"] = 1792080030, 1792080090
			presentationAt(s, 0)["iat"] = 1792080030
		})
		return root
	}
	t.Run("stated times", func(t *testing.T) {
		root := issued(t)
		mustGenerate(t, root, false)
		c := verifyAs(t, string(readCase(t, root, "signed/contract.jws")), jws.TypRequirements, "issuer")
		if !bytes.Equal(c.Payload, readCase(t, root, "contract.json")) {
			t.Error("contract payload is not contract.json")
		}
		p := verifyAs(t, string(readCase(t, root, "signed/presentation.jws")), jws.TypPresentation, "holder")
		var got struct{ Iat, Nbf, Exp int64 }
		if err := json.Unmarshal(p.Payload, &got); err != nil {
			t.Fatal(err)
		}
		if got.Iat != 1792080030 || got.Nbf != 1792080030 || got.Exp != 1792080090 {
			t.Errorf("presentation iat %d nbf %d exp %d, want 1792080030, 1792080030, 1792080090", got.Iat, got.Nbf, got.Exp)
		}
	})
	t.Run("presentation nbf and exp", func(t *testing.T) {
		root := issued(t)
		editSigning(t, root, validCase, func(s map[string]any) {
			p := presentationAt(s, 0)
			p["nbf"], p["exp"] = 1792080025, 1792080050
		})
		mustGenerate(t, root, false)
		p := verifyAs(t, string(readCase(t, root, "signed/presentation.jws")), jws.TypPresentation, "holder")
		var got struct{ Iat, Nbf, Exp int64 }
		if err := json.Unmarshal(p.Payload, &got); err != nil {
			t.Fatal(err)
		}
		if got.Iat != 1792080030 || got.Nbf != 1792080025 || got.Exp != 1792080050 {
			t.Errorf("presentation iat %d nbf %d exp %d", got.Iat, got.Nbf, got.Exp)
		}
	})
	for name, c := range map[string]struct {
		edit func(s map[string]any)
		want string
	}{
		"decoded iat is not the stated one": {func(s map[string]any) { artifactAt(s, 0)["iat"] = 1792080031 }, "iat"},
		"stated iat on another artifact":    {func(s map[string]any) { artifactAt(s, 1)["iat"] = 1792080030 }, "iat"},
		"stated nbf":                        {func(s map[string]any) { artifactAt(s, 0)["nbf"] = 1792080000 }, "nbf"},
		"stated exp":                        {func(s map[string]any) { artifactAt(s, 0)["exp"] = 1792080060 }, "exp"},
	} {
		t.Run(name, func(t *testing.T) {
			root := issued(t)
			editSigning(t, root, validCase, c.edit)
			generateErr(t, root, c.want)
		})
	}
	t.Run("nbf alone", func(t *testing.T) {
		root := unsignedTree(t)
		editDecoded(t, root, validCase+"/reputation.json", `"nbf":1792080000`, `"nbf":1792079990`)
		generateErr(t, root, "nbf")
		editSigning(t, root, validCase, func(s map[string]any) { artifactAt(s, 2)["nbf"] = 1792079990 })
		mustGenerate(t, root, false)
	})
}

// TestGeneratePayloadSigned: with payload_signed the JWS carries the decoded
// file while its signature covers another: it does not verify as it is,
// verifies over payload_signed, is embedded as it is, and is kept by a
// second run.
func TestGeneratePayloadSigned(t *testing.T) {
	root := unsignedTree(t)
	ev := readCase(t, root, "evidence/runtime.json")
	if !bytes.Contains(ev, []byte(`"exp":1792080300`)) {
		t.Fatal("evidence/runtime.json changed")
	}
	writeFile(t, filepath.Join(root, validCase, "evidence", "runtime-as-signed.json"),
		bytes.Replace(ev, []byte(`"exp":1792080300`), []byte(`"exp":1792080200`), 1))
	editSigning(t, root, validCase, func(s map[string]any) {
		artifactAt(s, 1)["payload_signed"] = "evidence/runtime-as-signed.json"
	})
	mustGenerate(t, root, false)
	compact := string(readCase(t, root, "signed/evidence/runtime.jws"))
	seg := segments(t, compact)
	if got, _ := base64.RawURLEncoding.DecodeString(seg[1]); !bytes.Equal(got, ev) {
		t.Error("the JWS does not carry evidence/runtime.json")
	}
	set, err := jws.NewKeySet(fixtureJWK(t, "issuer"))
	if err != nil {
		t.Fatal(err)
	}
	v := jws.Verifier{Keys: jws.StaticResolver{KeySets: map[jws.Role]*jws.KeySet{jws.RoleIssuer: set}}, Typ: jws.TypEvidence}
	if _, err := v.Verify(compact); err == nil {
		t.Error("an edited payload verifies")
	}
	over := seg[0] + "." + base64.RawURLEncoding.EncodeToString(readCase(t, root, "evidence/runtime-as-signed.json")) + "." + seg[2]
	if _, err := v.Verify(over); err != nil {
		t.Errorf("the signature does not verify over payload_signed: %v", err)
	}
	p := verifyAs(t, string(readCase(t, root, "signed/presentation.jws")), jws.TypPresentation, "holder")
	if !bytes.Contains(p.Payload, []byte(compact)) {
		t.Error("the presentation does not embed the edited JWS")
	}
	for _, check := range []bool{true, false} {
		if got := changedFiles(mustGenerate(t, root, check)); len(got) > 0 {
			t.Errorf("check=%v: second run changed %v", check, got)
		}
	}
	if string(readCase(t, root, "signed/evidence/runtime.jws")) != compact {
		t.Error("the second run rewrote the JWS")
	}
}

// learningCase is a learning case: a policy, an artifact, and an event whose
// digest members name them.
func learningCase(t *testing.T, root string, digests map[string]any) {
	t.Helper()
	claims := func(jti string, extra map[string]any) map[string]any {
		m := map[string]any{"iat": evalcase.FixedTime, "nbf": evalcase.FixedTime, "exp": evalcase.FixedTime + 300, "jti": jti}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	addEntry(t, root, "learning", "learning/zz-digests", map[string]any{
		"policies/finance.json":   claims("cG9saWN5LWp0aS0wMDAwMQ", nil),
		"artifacts/baseline.json": claims("YXJ0aWZhY3QtanRpLTAwMQ", nil),
		"events/event-0001.json": claims("ZXZlbnQtanRpLTAwMDAwMQ", map[string]any{
			"artifact_digest": "", "policy_digest": "", "lineage": []any{map[string]any{"a/b": ""}},
		}),
	}, map[string]any{"artifacts": []any{
		map[string]any{"decoded": "policies/finance.json", "signed": "signed/policies/finance.jws", "typ": jws.TypLearningPolicy, "signer": "issuer", "jti": "cG9saWN5LWp0aS0wMDAwMQ", "exp": evalcase.FixedTime + 300},
		map[string]any{"decoded": "artifacts/baseline.json", "signed": "signed/artifacts/baseline.jws", "typ": jws.TypLearningArtifact, "signer": "learning-controller", "jti": "YXJ0aWZhY3QtanRpLTAwMQ"},
		map[string]any{"decoded": "events/event-0001.json", "signed": "signed/events/event-0001.jws", "typ": jws.TypLearningEvent, "signer": "learning-controller", "jti": "ZXZlbnQtanRpLTAwMDAwMQ", "digests": digests},
	}})
}

// TestGenerateDigests: digests fill the members their pointers name with the
// artifact_digest of earlier signed files, the decoded file is written back
// in canonical form, and the learning objects carry their own typ.
func TestGenerateDigests(t *testing.T) {
	root := unsignedTree(t)
	learningCase(t, root, map[string]any{
		"/artifact_digest":  "signed/artifacts/baseline.jws",
		"/policy_digest":    "signed/policies/finance.jws",
		"/lineage/0/a~1b":   "signed/artifacts/baseline.jws",
		"/added_by_pointer": "signed/policies/finance.jws",
	})
	mustGenerate(t, root, false)
	dir := filepath.Join(root, "learning", "zz-digests")
	read := func(rel string) string { return string(readFile(t, filepath.Join(dir, filepath.FromSlash(rel)))) }
	policy := verifyAs(t, read("signed/policies/finance.jws"), jws.TypLearningPolicy, "issuer")
	artifact := verifyAs(t, read("signed/artifacts/baseline.jws"), jws.TypLearningArtifact, "learning-controller")
	event := verifyAs(t, read("signed/events/event-0001.jws"), jws.TypLearningEvent, "learning-controller")
	for name, p := range map[string]jws.ParsedJWS{"policy": policy, "artifact": artifact, "event": event} {
		if p.Header.Kid == "" {
			t.Errorf("%s: no kid", name)
		}
	}
	if !bytes.Equal(event.Payload, []byte(read("events/event-0001.json"))) {
		t.Error("the event JWS does not carry the written-back decoded file")
	}
	ad, _ := digest.ArtifactDigest(read("signed/artifacts/baseline.jws"))
	pd, _ := digest.ArtifactDigest(read("signed/policies/finance.jws"))
	var got struct {
		ArtifactDigest string              `json:"artifact_digest"`
		PolicyDigest   string              `json:"policy_digest"`
		Lineage        []map[string]string `json:"lineage"`
		Added          string              `json:"added_by_pointer"`
	}
	if err := json.Unmarshal(event.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.ArtifactDigest != string(ad) || got.PolicyDigest != string(pd) || got.Lineage[0]["a/b"] != string(ad) || got.Added != string(pd) {
		t.Errorf("digests %+v, want artifact %s policy %s", got, ad, pd)
	}
	canon, _ := jcs.Canonicalize(event.Payload)
	if !bytes.Equal(canon, event.Payload) {
		t.Error("the written-back decoded file is not canonical")
	}
	if got := changedFiles(mustGenerate(t, root, true)); len(got) > 0 {
		t.Errorf("second run changed %v", got)
	}

	// A stale digest member: check mode reports the decoded file and writes
	// nothing. The signed event already carries the filled payload, so it is
	// kept.
	stale := strings.Replace(read("events/event-0001.json"), string(pd), strings.Repeat("A", 43), 2)
	writeFile(t, filepath.Join(dir, "events", "event-0001.json"), []byte(stale))
	want := []string{"learning/zz-digests/events/event-0001.json"}
	if got := changedFiles(mustGenerate(t, root, true)); !slices.Equal(got, want) {
		t.Errorf("check mode changed %v, want %v", got, want)
	}
	if read("events/event-0001.json") != stale {
		t.Error("check mode wrote the decoded file")
	}
	if got := changedFiles(mustGenerate(t, root, false)); !slices.Equal(got, want) {
		t.Errorf("changed %v, want %v", got, want)
	}
	if strings.Contains(read("events/event-0001.json"), strings.Repeat("A", 43)) {
		t.Error("the stale digest was not filled")
	}

	// A re-signed artifact changes its artifact_digest, so the event that
	// names it changes too.
	removeFile(t, filepath.Join(dir, "signed", "artifacts", "baseline.jws"))
	want = []string{"learning/zz-digests/signed/artifacts/baseline.jws", "learning/zz-digests/events/event-0001.json", "learning/zz-digests/signed/events/event-0001.jws"}
	if got := changedFiles(mustGenerate(t, root, false)); !slices.Equal(got, want) {
		t.Errorf("after re-signing the artifact: changed %v, want %v", got, want)
	}
	ad, _ = digest.ArtifactDigest(read("signed/artifacts/baseline.jws"))
	if !strings.Contains(read("events/event-0001.json"), `"artifact_digest":"`+string(ad)+`"`) {
		t.Error("the event does not name the re-signed artifact")
	}
}

func TestGenerateDigestsNeedAnEarlierEntry(t *testing.T) {
	for name, digests := range map[string]map[string]any{
		"own signed file": {"/artifact_digest": "signed/events/event-0001.jws"},
		"unknown file":    {"/artifact_digest": "signed/artifacts/other.jws"},
	} {
		t.Run(name, func(t *testing.T) {
			root := unsignedTree(t)
			learningCase(t, root, digests)
			generateErr(t, root, "earlier entry")
		})
	}
	root := unsignedTree(t)
	learningCase(t, root, map[string]any{"/missing/member": "signed/artifacts/baseline.jws"})
	generateErr(t, root, "missing")
}

// TestGenerateOutcomeReportsWithV2Keys: outcome reports are signed as
// pact-outcome+jwt with the key of the role signing.json names, so an
// executor, an evaluator and a security authority are different signers.
func TestGenerateOutcomeReportsWithV2Keys(t *testing.T) {
	root := unsignedTree(t)
	report := func(jti string) map[string]any {
		return map[string]any{"iat": evalcase.FixedTime, "nbf": evalcase.FixedTime, "exp": evalcase.FixedTime + 300, "jti": jti}
	}
	roles := []string{"executor", "evaluator", "security-authority"}
	files := map[string]any{}
	var arts []any
	for i, role := range roles {
		jti := strings.Repeat(string(rune('a'+i)), 22)
		files["reports/"+role+"-event.json"] = report(jti)
		arts = append(arts, map[string]any{"decoded": "reports/" + role + "-event.json", "signed": "signed/" + role + "-event.jws",
			"typ": jws.TypOutcome, "signer": role, "jti": jti})
	}
	addEntry(t, root, "outcomes", "outcomes/zz-keys/case", files, map[string]any{"artifacts": arts})
	mustGenerate(t, root, false)
	for _, role := range roles {
		p := verifyAs(t, string(readFile(t, filepath.Join(root, "outcomes", "zz-keys", "case", "signed", role+"-event.jws"))), jws.TypOutcome, role)
		if p.Header.Kid != fixtureJWK(t, role).Kid {
			t.Errorf("%s: kid %q", role, p.Header.Kid)
		}
	}
}

// TestV2Keys: the four format v2 keys are the P-256 keys of scalars 7 to 10
// with their kids, registered in the manifest under CL-C, and holder-2's
// thumbprint is the one keys/README.md records; a presentation it signs
// embeds it.
func TestV2Keys(t *testing.T) {
	signers, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readFile(t, filepath.Join(repoFixtures, "keys", "README.md")))
	entries := manifestEntries(t)
	for i, k := range []struct{ role, kid string }{
		{"executor", "test-executor-key-1"}, {"evaluator", "test-evaluator-key-1"},
		{"security-authority", "test-security-authority-key-1"}, {"holder-2", "test-holder-key-2"},
	} {
		s, ok := signers[k.role]
		if !ok {
			t.Errorf("no test key for role %s", k.role)
			continue
		}
		d, err := s.Private.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if want := new(big.Int).SetInt64(int64(7 + i)).FillBytes(make([]byte, 32)); s.Public.Kid != k.kid || !bytes.Equal(d, want) {
			t.Errorf("%s: kid %s, scalar %x; want %s, %d", k.role, s.Public.Kid, d, k.kid, 7+i)
		}
		j := slices.IndexFunc(entries, func(e manifestEntry) bool { return e.ID == "keys/"+k.role })
		if j < 0 || entries[j].Kind != "key" || entries[j].Path != "keys/"+k.role+".jwk.json" || entries[j].Expected != nil {
			t.Errorf("keys/%s: manifest entry missing or wrong", k.role)
		}
	}
	var keyEntries struct {
		Entries []struct {
			ID, Scope    string
			SpecMapRow   string `json:"spec_map_row"`
			DraftSection string `json:"draft_section"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(repoFixtures, "manifest.json")), &keyEntries); err != nil {
		t.Fatal(err)
	}
	for _, e := range keyEntries.Entries {
		if slices.Contains([]string{"keys/executor", "keys/evaluator", "keys/security-authority", "keys/holder-2"}, e.ID) &&
			(e.Scope != "core" || e.SpecMapRow != "CL-C" || e.DraftSection != "C") {
			t.Errorf("%s: scope %s row %s section %s", e.ID, e.Scope, e.SpecMapRow, e.DraftSection)
		}
	}
	tp, err := jws.Thumbprint(fixtureJWK(t, "holder-2"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readme, "`"+string(tp)+"`") {
		t.Errorf("keys/README.md does not record the holder-2 thumbprint %s", tp)
	}

	root := unsignedTree(t)
	editSigning(t, root, validCase, func(s map[string]any) { presentationAt(s, 0)["signer"] = "holder-2" })
	mustGenerate(t, root, false)
	p := verifyAs(t, string(readCase(t, root, "signed/presentation.jws")), jws.TypPresentation, "holder-2")
	if got, _ := jws.Thumbprint(*p.Header.JWK); got != tp {
		t.Errorf("embedded jwk thumbprint %s, want %s", got, tp)
	}
}

// TestGenerateRejectsBadSigningJSON: signing.json is strict and every path,
// typ and signer it names must make sense.
func TestGenerateRejectsBadSigningJSON(t *testing.T) {
	for name, c := range map[string]struct {
		edit func(s map[string]any)
		want string
	}{
		"unknown member":        {func(s map[string]any) { s["note"] = "x" }, "signing.json"},
		"no artifacts":          {func(s map[string]any) { delete(s, "artifacts") }, "artifacts is required"},
		"no jti":                {func(s map[string]any) { delete(artifactAt(s, 0), "jti") }, "required"},
		"unknown typ":           {func(s map[string]any) { artifactAt(s, 0)["typ"] = "pact-contract+jwt" }, "typ"},
		"presentation typ":      {func(s map[string]any) { artifactAt(s, 0)["typ"] = jws.TypPresentation }, "typ"},
		"unknown signer":        {func(s map[string]any) { artifactAt(s, 0)["signer"] = "notary" }, "notary"},
		"path outside the case": {func(s map[string]any) { artifactAt(s, 0)["decoded"] = "../valid/contract.json" }, "relative path"},
		"signed file twice":     {func(s map[string]any) { artifactAt(s, 1)["signed"] = "signed/contract.jws" }, "twice"},
		"contract not signed":   {func(s map[string]any) { presentationAt(s, 0)["contract"] = "signed/other.jws" }, "signed/other.jws"},
		"reputation not a path": {func(s map[string]any) { presentationAt(s, 0)["reputation"] = 1 }, "reputation"},
	} {
		t.Run(name, func(t *testing.T) {
			root := unsignedTree(t)
			editSigning(t, root, validCase, c.edit)
			generateErr(t, root, c.want)
		})
	}
	t.Run("null decoded file", func(t *testing.T) {
		root := unsignedTree(t)
		writeFile(t, filepath.Join(root, validCase, "reputation.json"), []byte("null"))
		generateErr(t, root, "null")
		editSigning(t, root, validCase, func(s map[string]any) {
			s["artifacts"] = s["artifacts"].([]any)[:2]
		})
		mustGenerate(t, root, false)
		p := verifyAs(t, string(readCase(t, root, "signed/presentation.jws")), jws.TypPresentation, "holder")
		if !bytes.Contains(p.Payload, []byte(`"reputation":null`)) {
			t.Error("a case without a snapshot artifact presents reputation null")
		}
	})
}
