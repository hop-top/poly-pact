package learning_test

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/learning"
)

// copyCase copies the manifest, the keys and the case and expected
// directories of id into a fresh fixture directory.
func copyCase(t *testing.T, id string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{"manifest.json", "keys", id, "expected/" + id} {
		src := filepath.Join(repoFixtures, filepath.FromSlash(rel))
		err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			r, err := filepath.Rel(repoFixtures, p)
			if err != nil {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			dst := filepath.Join(root, r)
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			return os.WriteFile(dst, b, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func readCompact(t *testing.T, root, id, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(id), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeCompact(t *testing.T, root, id, rel, compact string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(id), filepath.FromSlash(rel)), []byte(compact), 0o644); err != nil {
		t.Fatal(err)
	}
}

// resign decodes the payload of compact, applies edit and signs it again
// with the test key of role under typ.
func resign(t *testing.T, root, compact, role, typ string, edit func(map[string]any)) string {
	t.Helper()
	keys, err := evalcase.LoadKeys(root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(compact, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	edit(p)
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.Sign(jws.Header{Typ: typ, Kid: keys[role].Public.Kid}, b, keys[role].Private)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func replay(t *testing.T, root, id string) evalcase.Registry {
	t.Helper()
	c, err := evalcase.ReadLearning(root, id)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := learning.Replay(root, c)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func rejection(t *testing.T, reg evalcase.Registry, step int) evalcase.RejectionEntry {
	t.Helper()
	for _, r := range reg.Rejections {
		if r.Step == step {
			return r
		}
	}
	t.Fatalf("step %d is not rejected: %+v", step, reg)
	return evalcase.RejectionEntry{}
}

// TestReplayRejectsWhatItCannotAuthenticate: a signed input that does not
// verify under the case's trust records, or is not a well-formed JWS or
// payload, is rejected before the state machine sees it, and the state
// machine never learns of it.
func TestReplayRejectsWhatItCannotAuthenticate(t *testing.T) {
	const id = "learning/happy-path"
	const event = "signed/events/learning-evaluated-event-0001.jws" // step 2
	const typEvent = jws.TypLearningEvent
	tests := []struct {
		name string
		edit func(t *testing.T, root string)
		code string
	}{
		{"a flipped signature", func(t *testing.T, root string) {
			p := strings.Split(readCompact(t, root, id, event), ".")
			sig, _ := base64.RawURLEncoding.DecodeString(p[2])
			sig[5] ^= 1
			p[2] = base64.RawURLEncoding.EncodeToString(sig)
			writeCompact(t, root, id, event, strings.Join(p, "."))
		}, learning.CodeInvalidProof},
		{"a signer the trust records do not hold", func(t *testing.T, root string) {
			c := readCompact(t, root, id, event)
			writeCompact(t, root, id, event, resign(t, root, c, "learning-controller", typEvent, func(p map[string]any) { p["iss"] = "https://learning.example/controllers/other" }))
		}, learning.CodeInvalidProof},
		{"the key of another role under the controller's name", func(t *testing.T, root string) {
			c := readCompact(t, root, id, event)
			writeCompact(t, root, id, event, resign(t, root, c, "holder", typEvent, func(map[string]any) {}))
		}, learning.CodeInvalidProof},
		// Section 13.4: a typ other than the endpoint's is INVALID_MESSAGE,
		// not a failure to authenticate the signer.
		{"another typ", func(t *testing.T, root string) {
			c := readCompact(t, root, id, event)
			writeCompact(t, root, id, event, resign(t, root, c, "learning-controller", jws.TypLearningArtifact, func(map[string]any) {}))
		}, learning.CodeInvalidMessage},
		{"not a compact JWS", func(t *testing.T, root string) {
			writeCompact(t, root, id, event, "e30.e30")
		}, learning.CodeInvalidMessage},
		{"a payload member the schema does not know", func(t *testing.T, root string) {
			c := readCompact(t, root, id, event)
			writeCompact(t, root, id, event, resign(t, root, c, "learning-controller", typEvent, func(p map[string]any) { p["bogus"] = 1 }))
		}, learning.CodeInvalidMessage},
		{"a payload that fails the schema", func(t *testing.T, root string) {
			c := readCompact(t, root, id, event)
			writeCompact(t, root, id, event, resign(t, root, c, "learning-controller", typEvent, func(p map[string]any) { p["transition"] = "LIVE" }))
		}, learning.CodeInvalidMessage},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := copyCase(t, id)
			tc.edit(t, root)
			reg := replay(t, root, id)
			if r := rejection(t, reg, 2); r.Code != tc.code || len(r.ReasonCodes) != 0 {
				t.Errorf("step 2 rejected %+v, want %s", r, tc.code)
			}
			// The evaluation never happened, so the later events find the
			// artifact still a CANDIDATE.
			for p, st := range reg.Artifacts {
				if string(st) != "CANDIDATE" {
					t.Errorf("%s is %s, want CANDIDATE", p, st)
				}
			}
			if rejection(t, reg, 3).Code != learning.CodeLearningRejected {
				t.Errorf("step 3 rejected %+v", rejection(t, reg, 3))
			}
		})
	}
}

// A policy that is not authenticated is not installed: nothing registers.
func TestReplayUnsignedPolicyInstallsNothing(t *testing.T) {
	const id = "learning/happy-path"
	root := copyCase(t, id)
	c := readCompact(t, root, id, "signed/policies/finance.jws")
	writeCompact(t, root, id, "signed/policies/finance.jws", resign(t, root, c, "learning-controller", jws.TypLearningPolicy, func(map[string]any) {}))
	reg := replay(t, root, id)
	if r := rejection(t, reg, 0); r.Code != learning.CodeInvalidProof {
		t.Errorf("step 0 rejected %+v", r)
	}
	if len(reg.Artifacts) != 0 {
		t.Errorf("artifacts %v registered without a policy", reg.Artifacts)
	}
}

// The reference machine reads the trust records of the case, so a case can
// register another signer.
func TestReplaySignatureOfThePolicyAuthorityIsRequired(t *testing.T) {
	const id = "learning/happy-path"
	root := copyCase(t, id)
	c := readCompact(t, root, id, "signed/policies/finance.jws")
	// Signed by the issuer key (the policy authority's) with a changed claim:
	// authentic.
	writeCompact(t, root, id, "signed/policies/finance.jws", resign(t, root, c, "issuer", jws.TypLearningPolicy, func(p map[string]any) { p["policy_id"] = "renamed" }))
	reg := replay(t, root, id)
	for _, r := range reg.Rejections {
		if r.Step == 0 {
			t.Fatalf("an authentic policy was rejected: %+v", r)
		}
	}
	// The events bind the digest of the first policy: with the policy
	// replaced they are rejected (Section 16.5: a changed policy_digest).
	if rejection(t, reg, 2).Code != learning.CodeLearningRejected {
		t.Errorf("step 2 rejected %+v", rejection(t, reg, 2))
	}
}

// editTrust rewrites the trust records of the case's config.json.
func editTrust(t *testing.T, root, id string, edit func([]any) []any) {
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
	cfg["trust"] = edit(cfg["trust"].([]any))
	if b, err = json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A key is trusted for the role of its trust record only: the issuer key,
// registered for the policy authority, does not sign as a controller even
// when the controller's iss is also registered with it.
func TestReplayTrustIsPerRole(t *testing.T) {
	const id = "learning/happy-path"
	const event = "signed/events/learning-evaluated-event-0001.jws"
	root := copyCase(t, id)
	editTrust(t, root, id, func(trust []any) []any {
		// The controller's iss is also registered as a policy authority with the
		// issuer key.
		return append(trust, map[string]any{"iss": "https://learning.example/controllers/finance", "role": "policy-authority", "keys": []any{"keys/issuer.jwk.json"}})
	})
	c := readCompact(t, root, id, event)
	writeCompact(t, root, id, event, resign(t, root, c, "issuer", jws.TypLearningEvent, func(map[string]any) {}))
	reg := replay(t, root, id)
	if r := rejection(t, reg, 2); r.Code != learning.CodeInvalidProof {
		t.Errorf("step 2 rejected %+v, want INVALID_PROOF: the issuer key is no controller key", r)
	}
}

// The reporter_role of a report is that of its signer's trust record, found
// by iss and not by position.
func TestReplayReporterRoleIsThatOfTheSigner(t *testing.T) {
	const id = "learning/rollback-preserves-hold"
	root := copyCase(t, id)
	editTrust(t, root, id, func(trust []any) []any {
		// Another reporter, an executor, listed before the security authority.
		other := map[string]any{"iss": "https://executor.example/finance", "role": "reporter", "reporter_role": "executor", "keys": []any{"keys/executor.jwk.json"}}
		return append([]any{other}, trust...)
	})
	reg := replay(t, root, id)
	if len(reg.Holds) != 1 || reg.Holds[0] != "security-event-0001" {
		t.Errorf("holds %v, want [security-event-0001]", reg.Holds)
	}
	for _, r := range reg.Rejections {
		t.Errorf("unexpected rejection %+v", r)
	}
}
