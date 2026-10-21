package reputation_test

import (
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/runner/evalcase"
	"hop.top/pact-go/runner/reputation"
)

// caseTree copies the manifest, the keys and the case and expected
// directories of id into a fresh fixture directory.
func caseTree(t *testing.T, id string) string {
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

// TestReplayVerifiesReports: a report is verified under the trust records
// of its signer before it is ingested (Sections 7.2, 7.3 and 13.4): a
// signature that does not verify is INVALID_PROOF; another typ, or a
// payload with a member the OutcomeReport schema does not define, is
// INVALID_MESSAGE.
func TestReplayVerifiesReports(t *testing.T) {
	const id = "outcomes/qualification/correction-recompute"
	keys, err := evalcase.LoadKeys(repoFixtures)
	if err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(filepath.FromSlash(id), "signed", "execution-event-0001.jws")
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, compact string) string
		code string
	}{
		{"flipped signature", func(t *testing.T, compact string) string {
			seg := strings.Split(compact, ".")
			sig, err := base64.RawURLEncoding.DecodeString(seg[2])
			if err != nil {
				t.Fatal(err)
			}
			sig[7] ^= 1
			seg[2] = base64.RawURLEncoding.EncodeToString(sig)
			return strings.Join(seg, ".")
		}, reputation.CodeInvalidProof},
		{"another signer", func(t *testing.T, compact string) string {
			return resign(t, compact, jws.TypOutcome, keys["evaluator"], "")
		}, reputation.CodeInvalidProof},
		{"another typ", func(t *testing.T, compact string) string {
			return resign(t, compact, jws.TypEvidence, keys["executor"], "")
		}, reputation.CodeInvalidMessage},
		{"unknown member", func(t *testing.T, compact string) string {
			return resign(t, compact, jws.TypOutcome, keys["executor"], `,"surprise":true}`)
		}, reputation.CodeInvalidMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := caseTree(t, id)
			p := filepath.Join(root, signed)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(tc.edit(t, string(b))), 0o644); err != nil {
				t.Fatal(err)
			}
			c, err := evalcase.ReadOutcomes(root, id)
			if err != nil {
				t.Fatal(err)
			}
			out, err := reputation.Replay(root, c)
			if err != nil {
				t.Fatal(err)
			}
			if a := out.Steps[0].Answer; a.Code != tc.code {
				t.Errorf("answer %+v, want %s", a, tc.code)
			}
			if v := out.Verdicts["execution-event-0001"]; !v.Refused || v.Code != tc.code {
				t.Errorf("verdict %+v, want refused %s", v, tc.code)
			}
			// The correction then names an event the service never accepted.
			if v := out.Verdicts["correction-event-0002"]; v.Qualification != "UNQUALIFIED" || v.Reason != reputation.ReasonCorrectionMismatch {
				t.Errorf("correction %+v, want UNQUALIFIED correction-mismatch", v)
			}
		})
	}
}

// resign signs the payload of compact again under typ with key, whose kid
// the header carries; a non-empty tail replaces the payload's closing brace.
func resign(t *testing.T, compact, typ string, key evalcase.Key, tail string) string {
	t.Helper()
	seg := strings.Split(compact, ".")
	payload, err := base64.RawURLEncoding.DecodeString(seg[1])
	if err != nil {
		t.Fatal(err)
	}
	if tail != "" {
		payload = append(payload[:len(payload)-1], tail...)
	}
	out, err := jws.Sign(jws.Header{Typ: typ, Kid: key.Public.Kid}, payload, key.Private)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
