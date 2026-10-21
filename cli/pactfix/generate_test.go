package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/jws"
)

// Values the draft fixes: the sample time of Appendix B and the jti values of
// B.4, B.5, B.6 and the presentation_id of B.7.
const (
	sampleTime      = 1792080000
	contractJTI     = "zIMh1jdcSU0EP90CYPIbwA"
	evidenceJTI     = "7oJQ-3bglLNLRx8Tpz275Q"
	reputationJTI   = "VW7HSF227CWWBU7wN09Q5A"
	presentationJTI = "v6wxT-_cB0Ua8Xkqgcuu2g"
)

// TestGenerateSignsTheCase: on a tree without signed files, generate writes
// every signed file, each verifies under the key its role requires, and each
// payload is the decoded file byte for byte.
func TestGenerateSignsTheCase(t *testing.T) {
	root := unsignedTree(t)
	res := mustGenerate(t, root, false)
	var files []string
	for _, r := range res {
		files = append(files, r.File)
		if !r.Changed {
			t.Errorf("%s: not reported as changed on a tree without signed files", r.File)
		}
	}
	for _, f := range signedFiles {
		if !slices.Contains(files, validCase+"/"+f) {
			t.Errorf("result lacks %s: %v", f, files)
		}
	}
	for _, c := range []struct{ signed, decoded, typ, key, jti string }{
		{"signed/contract.jws", "contract.json", jws.TypRequirements, "issuer", contractJTI},
		{"signed/evidence/runtime.jws", "evidence/runtime.json", jws.TypEvidence, "issuer", evidenceJTI},
		{"signed/reputation.jws", "reputation.json", jws.TypReputation, "reputation-service", reputationJTI},
	} {
		p := verifyAs(t, string(readCase(t, root, c.signed)), c.typ, c.key)
		if !bytes.Equal(p.Payload, readCase(t, root, c.decoded)) {
			t.Errorf("%s: payload is not %s byte for byte", c.signed, c.decoded)
		}
		claims := strictObject(t, p.Payload)
		if string(claims["jti"]) != `"`+c.jti+`"` {
			t.Errorf("%s: jti %s, want %s", c.signed, claims["jti"], c.jti)
		}
		if p.Header.Kid != "test-"+c.key+"-key-1" {
			t.Errorf("%s: kid %q", c.signed, p.Header.Kid)
		}
	}
}

// TestGeneratePresentation: the presentation embeds the signed contract,
// evidence and reputation and the decoded profile, intent and operation, and
// carries the fixed time and jti (draft Sections 7.5 and 11.2).
func TestGeneratePresentation(t *testing.T) {
	root := unsignedTree(t)
	mustGenerate(t, root, false)
	p := verifyAs(t, string(readCase(t, root, "signed/presentation.jws")), jws.TypPresentation, "holder")
	if p.Header.JWK == nil {
		t.Fatal("presentation header embeds no jwk")
	}
	canon, err := jcs.Canonicalize(p.Payload)
	if err != nil || !bytes.Equal(canon, p.Payload) {
		t.Errorf("presentation payload is not RFC 8785 canonical (%v)", err)
	}
	var got struct {
		PactVersion string          `json:"pact_version"`
		Iss         string          `json:"iss"`
		Sub         string          `json:"sub"`
		Aud         string          `json:"aud"`
		JTI         string          `json:"jti"`
		Iat         int64           `json:"iat"`
		Nbf         int64           `json:"nbf"`
		Exp         int64           `json:"exp"`
		TenantID    string          `json:"tenant_id"`
		Contract    string          `json:"contract"`
		Profile     json.RawMessage `json:"profile"`
		Intent      json.RawMessage `json:"intent"`
		Operation   json.RawMessage `json:"operation"`
		Evidence    []string        `json:"evidence"`
		Reputation  *string         `json:"reputation"`
		Nonce       string          `json:"nonce"`
	}
	if err := json.Unmarshal(p.Payload, &got); err != nil {
		t.Fatal(err)
	}
	const agent = "https://identity.example/agents/invoice-assistant"
	want := map[string][2]any{
		"pact_version": {got.PactVersion, "0.1"},
		"iss":          {got.Iss, agent},
		"sub":          {got.Sub, agent},
		"aud":          {got.Aud, "https://gateway.example/finance"},
		"jti":          {got.JTI, presentationJTI},
		"iat":          {got.Iat, int64(sampleTime)},
		"nbf":          {got.Nbf, int64(sampleTime)},
		"exp":          {got.Exp, int64(sampleTime + 60)},
		"tenant_id":    {got.TenantID, "acme"},
		"nonce":        {got.Nonce, "N8WrKpg8XNb9Wh_QuWlHbw"},
		"contract":     {got.Contract, string(readCase(t, root, "signed/contract.jws"))},
	}
	for k, v := range want {
		if v[0] != v[1] {
			t.Errorf("%s = %v, want %v", k, v[0], v[1])
		}
	}
	if !slices.Equal(got.Evidence, []string{string(readCase(t, root, "signed/evidence/runtime.jws"))}) {
		t.Errorf("evidence %v", got.Evidence)
	}
	if got.Reputation == nil || *got.Reputation != string(readCase(t, root, "signed/reputation.jws")) {
		t.Errorf("reputation %v", got.Reputation)
	}
	for name, raw := range map[string]json.RawMessage{"profile": got.Profile, "intent": got.Intent, "operation": got.Operation} {
		if !bytes.Equal(raw, readCase(t, root, name+".json")) {
			t.Errorf("%s is not %s.json", name, name)
		}
	}
}

// TestGenerateKeepsVerifiedFiles: a second run changes nothing, byte for
// byte, and the check mode agrees.
func TestGenerateKeepsVerifiedFiles(t *testing.T) {
	root := unsignedTree(t)
	mustGenerate(t, root, false)
	before := map[string][]byte{}
	for _, f := range signedFiles {
		before[f] = readCase(t, root, f)
	}
	for _, check := range []bool{false, true} {
		for _, r := range mustGenerate(t, root, check) {
			if r.Changed {
				t.Errorf("check=%v: %s reported as changed", check, r.File)
			}
		}
	}
	for _, f := range signedFiles {
		if !bytes.Equal(before[f], readCase(t, root, f)) {
			t.Errorf("%s changed on the second run", f)
		}
	}
}

// TestGenerateDeterministicApartFromSignatures: two independent runs write
// the same headers and payloads; only ECDSA signature octets differ, and in
// the presentation only the signatures of the embedded artifacts.
func TestGenerateDeterministicApartFromSignatures(t *testing.T) {
	a, b := unsignedTree(t), unsignedTree(t)
	mustGenerate(t, a, false)
	mustGenerate(t, b, false)
	sigs := map[string]string{}
	for _, f := range signedFiles {
		sa, sb := segments(t, string(readCase(t, a, f))), segments(t, string(readCase(t, b, f)))
		if sa[0] != sb[0] {
			t.Errorf("%s: headers differ", f)
		}
		if f != "signed/presentation.jws" {
			if sa[1] != sb[1] {
				t.Errorf("%s: payloads differ", f)
			}
			sigs[sa[2]] = "<sig>"
			sigs[sb[2]] = "<sig>"
		}
	}
	// ECDSA signing is randomized (draft Appendix C), so the two runs
	// signed the contract differently.
	if segments(t, string(readCase(t, a, signedFiles[0])))[2] == segments(t, string(readCase(t, b, signedFiles[0])))[2] {
		t.Error("two runs produced the same contract signature")
	}
	mask := func(root string) string {
		p := verifyAs(t, string(readCase(t, root, "signed/presentation.jws")), jws.TypPresentation, "holder")
		s := string(p.Payload)
		for sig, repl := range sigs {
			s = strings.ReplaceAll(s, sig, repl)
		}
		return s
	}
	if mask(a) != mask(b) {
		t.Error("presentation payloads differ beyond the embedded signatures")
	}
}

// TestGenerateResignsStaleFiles: a signed file that no longer verifies, or
// whose payload is not the decoded file, is signed again; check mode reports
// it and writes nothing.
func TestGenerateResignsStaleFiles(t *testing.T) {
	cases := map[string]func(root string){
		"signature broken": func(root string) {
			path := filepath.Join(root, validCase, "signed", "contract.jws")
			s := segments(t, string(readFile(t, path)))
			sig := []byte(s[2])
			sig[3] ^= 1
			writeFile(t, path, []byte(s[0]+"."+s[1]+"."+string(sig)))
		},
		"payload replaced": func(root string) {
			// A valid signature over another payload: the evidence JWS in
			// place of the contract.
			ev := readFile(t, filepath.Join(root, validCase, "signed", "evidence", "runtime.jws"))
			writeFile(t, filepath.Join(root, validCase, "signed", "contract.jws"), ev)
		},
		"trailing newline": func(root string) {
			path := filepath.Join(root, validCase, "signed", "contract.jws")
			writeFile(t, path, append(readFile(t, path), '\n'))
		},
		"missing": func(root string) {
			removeFile(t, filepath.Join(root, validCase, "signed", "contract.jws"))
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			root := unsignedTree(t)
			mustGenerate(t, root, false)
			breakIt(root)
			broken, _ := readFileMaybe(filepath.Join(root, validCase, "signed", "contract.jws"))
			changed := func(res []genResult) []string {
				var out []string
				for _, r := range res {
					if r.Changed {
						out = append(out, r.File)
					}
				}
				return out
			}
			// The presentation embeds the contract, so it changes too.
			want := []string{validCase + "/signed/contract.jws", validCase + "/signed/presentation.jws"}
			if got := changed(mustGenerate(t, root, true)); !slices.Equal(got, want) {
				t.Errorf("check mode: changed %v, want %v", got, want)
			}
			if now, _ := readFileMaybe(filepath.Join(root, validCase, "signed", "contract.jws")); !bytes.Equal(now, broken) {
				t.Error("check mode wrote a file")
			}
			if got := changed(mustGenerate(t, root, false)); !slices.Equal(got, want) {
				t.Errorf("changed %v, want %v", got, want)
			}
			verifyAs(t, string(readCase(t, root, "signed/contract.jws")), jws.TypRequirements, "issuer")
			if got := changed(mustGenerate(t, root, true)); len(got) > 0 {
				t.Errorf("after regeneration, check mode reports %v", got)
			}
		})
	}
}

// TestGenerateRefusesDriftingInputs: a decoded file that is not canonical, or
// whose jti or time is not the fixed one, stops the run.
func TestGenerateRefusesDriftingInputs(t *testing.T) {
	replace := func(file, old, repl string) func(root string) {
		return func(root string) {
			path := filepath.Join(root, validCase, filepath.FromSlash(file))
			b := readFile(t, path)
			if !bytes.Contains(b, []byte(old)) {
				t.Fatalf("%s lacks %s", file, old)
			}
			writeFile(t, path, bytes.Replace(b, []byte(old), []byte(repl), 1))
		}
	}
	cases := map[string]struct {
		edit func(root string)
		want string
	}{
		"not canonical": {func(root string) {
			path := filepath.Join(root, validCase, "contract.json")
			var buf bytes.Buffer
			if err := json.Indent(&buf, readFile(t, path), "", "  "); err != nil {
				t.Fatal(err)
			}
			writeFile(t, path, buf.Bytes())
		}, "canonical"},
		"trailing newline": {func(root string) {
			path := filepath.Join(root, validCase, "evidence", "runtime.json")
			writeFile(t, path, append(readFile(t, path), '\n'))
		}, "canonical"},
		"other jti":    {replace("contract.json", contractJTI, "AAAAAAAAAAAAAAAAAAAAAA"), "jti"},
		"other iat":    {replace("evidence/runtime.json", `"iat":1792080000`, `"iat":1792080001`), "iat"},
		"other nbf":    {replace("reputation.json", `"nbf":1792080000`, `"nbf":1792079999`), "nbf"},
		"missing file": {func(root string) { removeFile(t, filepath.Join(root, validCase, "intent.json")) }, "intent.json"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root := unsignedTree(t)
			c.edit(root)
			_, err := generate(root, false, []string{validCase})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one mentioning %q", err, c.want)
			}
		})
	}
}

func TestGenerateSelectsCases(t *testing.T) {
	root := unsignedTree(t)
	if _, err := generate(root, false, []string{"admission/nope"}); err == nil {
		t.Error("an unknown case was accepted")
	}
	// One result per signed file, plus one per decoded file whose entry
	// fills digests (genResult).
	want := 0
	for _, r := range repoRuns(t, "") {
		want += len(r.Signing.Artifacts) + len(r.Signing.Presentations)
		for _, a := range r.Signing.Artifacts {
			if len(a.Digests) > 0 {
				want++
			}
		}
	}
	if res := mustGenerate(t, root, false); len(res) != want {
		t.Errorf("%d results, want %d", len(res), want)
	}
	if res, err := generate(root, false, []string{validCase}); err != nil || len(res) != len(signedFiles) {
		t.Errorf("only %s: %d results (%v)", validCase, len(res), err)
	}
}

// TestCommittedCaseIsCurrent: the committed signed files of every case
// verify and match the committed decoded files, so CI never needs to
// regenerate them.
func TestCommittedCaseIsCurrent(t *testing.T) {
	res, err := generate(repoFixtures, true, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for _, r := range res {
		if r.Changed {
			t.Errorf("%s is stale: run pactfix generate", r.File)
		}
	}
}

// TestDecodedFilesAreAppendixB: the decoded files are the Appendix B objects
// in RFC 8785 canonical form, with no trailing newline.
func TestDecodedFilesAreAppendixB(t *testing.T) {
	blocks := appendixB(t)
	for file, section := range map[string]string{
		"profile.json": "B.1", "intent.json": "B.2", "operation.json": "B.3", "actual_operation.json": "B.3",
		"contract.json": "B.4", "evidence/runtime.json": "B.5", "reputation.json": "B.6",
	} {
		want, err := jcs.Canonicalize(blocks[section])
		if err != nil {
			t.Fatalf("%s: %v", section, err)
		}
		if got := readCase(t, repoFixtures, file); !bytes.Equal(got, want) {
			t.Errorf("%s is not the canonical form of the %s block", file, section)
		}
	}
}

// TestExpectedDecisionFollowsB7: decision.json carries the B.7 decision and
// checks, the B.7 digests, and the requirements digest of the committed
// contract.
func TestExpectedDecisionFollowsB7(t *testing.T) {
	var b7 struct {
		Decision string `json:"decision"`
		Exp      int64  `json:"exp"`
		Checks   []struct {
			CheckID    string `json:"check_id"`
			Result     string `json:"result"`
			ReasonCode string `json:"reason_code"`
		} `json:"checks"`
	}
	block := appendixB(t)["B.7"]
	if err := json.Unmarshal(block, &b7); err != nil {
		t.Fatal(err)
	}
	b7claims := strictObject(t, block)
	raw := readFile(t, filepath.Join(repoFixtures, "expected", validCase, "decision.json"))
	strictObject(t, raw)
	var got struct {
		Decision      string  `json:"decision"`
		TransportCode *string `json:"transport_code"`
		Checks        []struct {
			CheckID    string `json:"check_id"`
			Result     string `json:"result"`
			ReasonCode string `json:"reason_code"`
		} `json:"checks"`
		Receipt struct {
			Typ    string                     `json:"typ"`
			Signer string                     `json:"signer"`
			Claims map[string]json.RawMessage `json:"claims"`
			ExpMax int64                      `json:"exp_max"`
		} `json:"receipt"`
		Executed bool `json:"executed"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != "ADMISSIBLE" || got.Decision != b7.Decision || got.TransportCode != nil || !got.Executed {
		t.Errorf("decision %q transport %v executed %v", got.Decision, got.TransportCode, got.Executed)
	}
	if !slices.Equal(got.Checks, b7.Checks) || len(got.Checks) != 20 {
		t.Errorf("checks differ from B.7: %d vs %d", len(got.Checks), len(b7.Checks))
	}
	if got.Receipt.Typ != jws.TypAdmission || got.Receipt.Signer != "keys/validator.jwk.json" || got.Receipt.ExpMax != b7.Exp {
		t.Errorf("receipt %+v", got.Receipt)
	}
	contract := string(readCase(t, repoFixtures, "signed/contract.jws"))
	reqDigest, err := digest.ArtifactDigest(contract)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range got.Receipt.Claims {
		want := b7claims[k]
		if k == "requirements_digest" {
			want = json.RawMessage(`"` + string(reqDigest) + `"`)
		}
		if want == nil || string(v) != string(want) {
			t.Errorf("claim %s = %s, want %s", k, v, want)
		}
	}
	for k, file := range map[string]string{"profile_digest": "profile.json", "intent_digest": "intent.json", "operation_digest": "operation.json"} {
		d, err := digest.ObjectDigest(json.RawMessage(readCase(t, repoFixtures, file)))
		if err != nil {
			t.Fatal(err)
		}
		if string(got.Receipt.Claims[k]) != `"`+string(d)+`"` {
			t.Errorf("%s %s is not the object digest of %s (%s)", k, got.Receipt.Claims[k], file, d)
		}
	}
	if string(got.Receipt.Claims["presentation_id"]) != `"`+presentationJTI+`"` {
		t.Errorf("presentation_id %s", got.Receipt.Claims["presentation_id"])
	}
}

// TestGeneratePresentationIsCanonical: the presentation payload is RFC 8785
// canonical even when a member holds a character encoding/json escapes.
func TestGeneratePresentationIsCanonical(t *testing.T) {
	root := unsignedTree(t)
	path := filepath.Join(root, validCase, "intent.json")
	b := readFile(t, path)
	const old = "Read the approved September invoice"
	if !bytes.Contains(b, []byte(old)) {
		t.Fatal("intent.json changed")
	}
	writeFile(t, path, bytes.Replace(b, []byte(old), []byte("Read <the> approved & September invoice"), 1))
	mustGenerate(t, root, false)
	p := verifyAs(t, string(readCase(t, root, "signed/presentation.jws")), jws.TypPresentation, "holder")
	canon, err := jcs.Canonicalize(p.Payload)
	if err != nil || !bytes.Equal(canon, p.Payload) {
		t.Errorf("presentation payload is not RFC 8785 canonical (%v)", err)
	}
	if !bytes.Contains(p.Payload, []byte("Read <the> approved & September")) {
		t.Error("the intent is not embedded as written")
	}
}
