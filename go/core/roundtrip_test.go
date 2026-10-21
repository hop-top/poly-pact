package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"hop.top/pact-go/core/strictjson"
)

const draftPath = "../../spec/v1.0/draft.md"

// draftBlock returns the first json fence under the Appendix B heading that
// starts with "### <section> ". It fails when the draft or the block is absent.
func draftBlock(t *testing.T, section string) []byte {
	t.Helper()
	b, err := os.ReadFile(draftPath)
	if err != nil {
		t.Fatalf("read draft: %v", err)
	}
	re := regexp.MustCompile(`(?m)^### ` + regexp.QuoteMeta(section) + ` [^\n]*\n(?:[^\n#][^\n]*\n|\n)*?` + "```json\n" + `((?s:.*?))\n` + "```\n")
	m := re.FindSubmatch(b)
	if m == nil {
		t.Fatalf("draft has no json block under %s", section)
	}
	return m[1]
}

// encode re-encodes v with encoding/json only: no canonicalization, no HTML
// escaping, two-space indent as in the draft examples.
func encode(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func TestRoundTripByteStable(t *testing.T) {
	tests := []struct {
		section string
		target  func() any
	}{
		{"B.3", func() any { return new(OperationContext) }},
		{"B.4", func() any { return new(RequirementContract) }},
	}
	for _, tc := range tests {
		t.Run(tc.section, func(t *testing.T) {
			src := draftBlock(t, tc.section)
			v := tc.target()
			if err := strictjson.Unmarshal(src, strictjson.Limits{}, v); err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			if got := encode(t, v); !bytes.Equal(got, src) {
				t.Fatalf("re-encode differs from the draft\n--- draft\n%s\n--- got\n%s", src, got)
			}
		})
	}
}

// generic decodes JSON into any, keeping numbers exact.
func generic(t *testing.T, b []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("generic decode: %v", err)
	}
	return v
}

// TestAppendixBDecodes decodes every Appendix B artifact strictly into its
// type and checks that re-encoding loses and adds nothing.
func TestAppendixBDecodes(t *testing.T) {
	tests := []struct {
		section string
		target  func() any
	}{
		{"B.1", func() any { return new(AgentProfile) }},
		{"B.2", func() any { return new(Intent) }},
		{"B.3", func() any { return new(OperationContext) }},
		{"B.4", func() any { return new(RequirementContract) }},
		{"B.5", func() any { return new(Evidence) }},
		{"B.6", func() any { return new(ReputationSnapshot) }},
		{"B.7", func() any { return new(AdmissionAttestation) }},
		{"B.8", func() any { return new(OutcomeReport) }},
		{"B.9", func() any { return new(LearningPolicy) }},
		{"B.10", func() any { return new(LearningArtifact) }},
		{"B.11", func() any { return new(LearningEvent) }},
		{"B.13", func() any { return new(GatewayMetadata) }},
	}
	for _, tc := range tests {
		t.Run(tc.section, func(t *testing.T) {
			src := draftBlock(t, tc.section)
			v := tc.target()
			if err := strictjson.Unmarshal(src, strictjson.Limits{}, v); err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			if !reflect.DeepEqual(generic(t, encode(t, v)), generic(t, src)) {
				t.Fatalf("re-encoded value differs from the draft\n--- draft\n%s\n--- got\n%s", src, encode(t, v))
			}
		})
	}
}

func TestDraftDigestsValidate(t *testing.T) {
	var c RequirementContract
	if err := strictjson.Unmarshal(draftBlock(t, "B.4"), strictjson.Limits{}, &c); err != nil {
		t.Fatal(err)
	}
	for name, d := range map[string]Digest{
		"holder_jkt": c.HolderJKT, "operation_digest": c.OperationDigest, "intent_digest": c.IntentDigest,
		"learning_policy_digest": c.LearningPolicyDigest, "learning_artifact_digest": c.LearningArtifactDigest,
	} {
		if err := d.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if c.Mode != ModeEnforced || !c.Mode.Valid() {
		t.Errorf("mode = %q", c.Mode)
	}
}

func TestDuplicateKeyRejected(t *testing.T) {
	src := strings.Replace(string(draftBlock(t, "B.3")), `"action": "invoice.read",`, `"action": "invoice.read", "action": "invoice.write",`, 1)
	if !strings.Contains(src, `"invoice.write"`) {
		t.Fatal("could not build the duplicate-key input")
	}
	var op OperationContext
	if err := strictjson.Unmarshal([]byte(src), strictjson.Limits{}, &op); !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Fatalf("got %v, want ErrDuplicateKey", err)
	}
}

func TestCoreIntegersAreRangeChecked(t *testing.T) {
	profile := func(revision string) string {
		return `{"profile_id":"p","revision":` + revision + `,"agent_id":"https://a.example/x","operator_id":"https://o.example/x",` +
			`"tenant_id":"t","holder_jkt":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","created_at":1,"expires_at":2,"attributes":{}}`
	}
	for _, ok := range []string{"1", "0", "9007199254740991"} {
		var p AgentProfile
		if err := strictjson.Unmarshal([]byte(profile(ok)), strictjson.Limits{}, &p); err != nil {
			t.Errorf("revision %s: %v", ok, err)
		}
	}
	for _, bad := range []string{"-1", "9007199254740992", "1.5", "1e3", "null", `"1"`} {
		var p AgentProfile
		if err := strictjson.Unmarshal([]byte(profile(bad)), strictjson.Limits{}, &p); err == nil {
			t.Errorf("revision %s accepted", bad)
		}
	}
}

func TestOpenMapsAcceptAdditionalMembers(t *testing.T) {
	src := `{"operation_id":"o","environment_id":"https://e.example/x","principal_id":"https://p.example/x","action":"a",` +
		`"resources":["https://r.example/x"],"method":"GET","target_uri":"https://t.example/x",` +
		`"body_digest":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","headers":{"x-extra":"1"},"extensions":{"https://x.example/ext":{"k":[1,2]}}}`
	var op OperationContext
	if err := strictjson.Unmarshal([]byte(src), strictjson.Limits{}, &op); err != nil {
		t.Fatal(err)
	}
	if op.Headers["x-extra"] != "1" || string(op.Extensions["https://x.example/ext"]) != `{"k":[1,2]}` {
		t.Fatalf("open maps lost data: %+v", op)
	}
	bare := strings.Replace(src, `,"extensions":{"https://x.example/ext":{"k":[1,2]}}`, "", 1)
	var op2 OperationContext
	if err := strictjson.Unmarshal([]byte(bare), strictjson.Limits{}, &op2); err != nil {
		t.Fatal(err)
	}
	if op2.Extensions != nil {
		t.Fatalf("absent extensions decoded as %v", op2.Extensions)
	}
	if !strings.Contains(string(encode(t, op)), `"extensions"`) || strings.Contains(string(encode(t, op2)), `"extensions"`) {
		t.Fatal("extensions presence not preserved on re-encode")
	}
}
