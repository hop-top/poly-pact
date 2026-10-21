package adapter

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"hop.top/pact-go/core"
)

func TestSignedValidate(t *testing.T) {
	tests := []struct {
		name string
		jws  string
		ok   bool
	}{
		{"three segments", "eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln", true},
		{"empty", "", false},
		{"two segments", "aaa.bbb", false},
		{"four segments", "aaa.bbb.ccc.ddd", false},
		{"empty header", ".bbb.ccc", false},
		{"empty payload", "aaa..ccc", false},
		{"empty signature", "aaa.bbb.", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Signed{JWS: tc.jws}.Validate()
			if (err == nil) != tc.ok {
				t.Errorf("Validate() = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestNoVisibilityValidate(t *testing.T) {
	tests := []struct {
		reason string
		ok     bool
	}{
		{"execution happens in a system the adapter cannot observe", true},
		{"", false},
		{"   \t", false},
	}
	for _, tc := range tests {
		err := NoVisibility{Reason: tc.reason}.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("NoVisibility{%q}.Validate() = %v, want ok=%v", tc.reason, err, tc.ok)
		}
	}
}

// kind is the exhaustive switch a consumer writes over the sum type.
func kind(r Recorded) string {
	switch r.(type) {
	case Signed:
		return "signed"
	case NoVisibility:
		return "no-visibility"
	default:
		return "unknown"
	}
}

func TestRecordedHoldsExactlyOne(t *testing.T) {
	if got := kind(Signed{JWS: "a.b.c"}); got != "signed" {
		t.Errorf("Signed kind = %q", got)
	}
	if got := kind(NoVisibility{Reason: "r"}); got != "no-visibility" {
		t.Errorf("NoVisibility kind = %q", got)
	}
}

// TestRecordedIsSealed: the marker method is unexported, so no package outside
// adapter can add a third variant to the sum type.
func TestRecordedIsSealed(t *testing.T) {
	rt := reflect.TypeFor[Recorded]()
	sealed, validate := false, false
	for m := range rt.Methods() {
		sealed = sealed || !m.IsExported()
		validate = validate || m.Name == "Validate"
	}
	if !sealed {
		t.Error("Recorded has no unexported method")
	}
	if !validate {
		t.Error("Recorded lacks Validate")
	}
}

// TestDescriptorConvertsToNativeAdapter checks the conversion against the
// adapters entry of the draft's gateway metadata example (B.13).
func TestDescriptorConvertsToNativeAdapter(t *testing.T) {
	sec := draftSection(t, "### B.13 Gateway metadata with baseline limits")
	const open, closing = "```json\n", "\n```"
	_, rest, ok := strings.Cut(sec, open)
	if !ok {
		t.Fatal("B.13 has no json block")
	}
	body, _, ok := strings.Cut(rest, closing)
	if !ok {
		t.Fatal("B.13 json block is not closed")
	}
	var md core.GatewayMetadata
	if err := json.Unmarshal([]byte(body), &md); err != nil {
		t.Fatalf("decode B.13: %v", err)
	}
	if len(md.Adapters) != 1 {
		t.Fatalf("B.13 has %d adapters, want 1", len(md.Adapters))
	}
	d := Descriptor{Protocol: "mcp", Version: "2025-11-25", MappingRevision: "finance-mcp-1"}
	if got := d.NativeAdapter(); !reflect.DeepEqual(got, md.Adapters[0]) {
		t.Errorf("NativeAdapter() = %+v, want %+v", got, md.Adapters[0])
	}
}
