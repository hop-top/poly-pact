package digest_test

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/strictjson"
)

const (
	// bodyDigestOfEmpty is the body_digest of draft Appendix B.3, the digest of
	// zero bytes.
	bodyDigestOfEmpty = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

	// operationDigestB3 and intentDigestB2 are the operation_digest and
	// intent_digest of draft Appendix B.4, the digests of the B.3 and B.2
	// objects.
	operationDigestB3 = "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0"
	intentDigestB2    = "t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M"

	// digestOfABC is SHA-256("abc"), the FIPS 180-4 example (hex
	// ba7816bf...15ad), written as base64url without padding.
	digestOfABC = "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"

	// shortJWS has the payload "{}" (e30) and the header {"alg":"ES256"}. The
	// digest is SHA-256 over its 29 ASCII bytes, computed outside Go. Hashing
	// the decoded segments gives a different value.
	shortJWS       = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
	digestOfShortJ = "E2ttONh1sD1zwHXFE8fH21SGQ5my65IRYl87KWSpu9o"
)

// checkShape fails when d is not a 43 character base64url value without
// padding or any character of the standard alphabet.
func checkShape(t *testing.T, d core.Digest) {
	t.Helper()
	if err := d.Validate(); err != nil {
		t.Errorf("digest %q: %v", d, err)
	}
	if strings.ContainsAny(string(d), "=+/") {
		t.Errorf("digest %q uses padding or the standard alphabet", d)
	}
}

func TestBytesDigest(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want core.Digest
	}{
		{"nil", nil, bodyDigestOfEmpty},
		{"empty", []byte{}, bodyDigestOfEmpty},
		{"abc", []byte("abc"), digestOfABC},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := digest.BytesDigest(tc.in)
			if got != tc.want {
				t.Errorf("BytesDigest(%q) = %q, want %q", tc.in, got, tc.want)
			}
			checkShape(t, got)
		})
	}
}

func TestArtifactDigest(t *testing.T) {
	t.Run("hashes the ASCII bytes of the string", func(t *testing.T) {
		got, err := digest.ArtifactDigest(shortJWS)
		if err != nil {
			t.Fatal(err)
		}
		if got != digestOfShortJ {
			t.Errorf("ArtifactDigest(%q) = %q, want %q", shortJWS, got, digestOfShortJ)
		}
		checkShape(t, got)
		if want := digest.BytesDigest([]byte(shortJWS)); got != want {
			t.Errorf("ArtifactDigest = %q, BytesDigest of the same bytes = %q", got, want)
		}
	})

	t.Run("exact string, no trimming", func(t *testing.T) {
		a, err := digest.ArtifactDigest(shortJWS)
		if err != nil {
			t.Fatal(err)
		}
		b, err := digest.ArtifactDigest(shortJWS + "\n")
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Error("a trailing newline did not change the digest")
		}
	})

	t.Run("empty string is the empty input", func(t *testing.T) {
		got, err := digest.ArtifactDigest("")
		if err != nil || got != bodyDigestOfEmpty {
			t.Errorf("ArtifactDigest(\"\") = %q, %v; want %q", got, err, bodyDigestOfEmpty)
		}
	})

	t.Run("non-ASCII is rejected", func(t *testing.T) {
		for _, s := range []string{"é", shortJWS + "é", "a\x80b", "\xff", "a b"} {
			got, err := digest.ArtifactDigest(s)
			if err == nil {
				t.Errorf("ArtifactDigest(%q) = %q, nil; want an error", s, got)
			}
			if got != "" {
				t.Errorf("ArtifactDigest(%q) returned %q with an error", s, got)
			}
		}
	})
}

// canonical returns the digest of a hand-written RFC 8785 text, the check
// that ObjectDigest hashes the canonical form and not another encoding.
func canonical(text string) core.Digest { return digest.BytesDigest([]byte(text)) }

func TestObjectDigestCanonicalForm(t *testing.T) {
	type unsorted struct {
		Z int    `json:"z"`
		A string `json:"a"`
	}
	negZero := math.Copysign(0, -1)

	tests := []struct {
		name string
		in   any
		want string // RFC 8785 text of in
	}{
		{"map members sorted", map[string]any{"b": 2, "a": 1}, `{"a":1,"b":2}`},
		{"struct members sorted", unsorted{Z: 1, A: "x"}, `{"a":"x","z":1}`},
		{"pointer to struct", &unsorted{Z: 1, A: "x"}, `{"a":"x","z":1}`},
		{"no HTML escaping", map[string]any{"s": "<a>&b"}, `{"s":"<a>&b"}`},
		{"line separator is literal", map[string]any{"s": " "}, "{\"s\":\" \"}"},
		{
			// U+1F600 is the surrogate pair D83D DE00 in UTF-16 and sorts before
			// U+FF5E, while encoding/json orders keys by UTF-8 bytes.
			"member names sort by UTF-16 code units",
			map[string]any{"～": 2, "\U0001F600": 1},
			"{\"\U0001F600\":1,\"～\":2}",
		},
		{
			"ECMAScript numbers",
			map[string]any{"n": []float64{negZero, 1e21, 4.5, 100, 1e-7}},
			`{"n":[0,1e+21,4.5,100,1e-7]}`,
		},
		{"largest safe integer", map[string]any{"n": int64(1<<53 - 1)}, `{"n":9007199254740991}`},
		{"empty containers", map[string]any{"b": []any{}, "a": map[string]any{}}, `{"a":{},"b":[]}`},
		{
			"nested objects and null",
			map[string]any{"z": nil, "a": []any{map[string]any{"y": true, "x": false}}},
			`{"a":[{"x":false,"y":true}],"z":null}`,
		},
		{
			"string escapes",
			map[string]any{"s": "q\"\\\n\t\x01\x7f"},
			"{\"s\":\"q\\\"\\\\\\n\\t\\u0001\x7f\"}",
		},
		{
			"raw JSON text is canonicalized, not copied",
			json.RawMessage(" {\n  \"b\" : [ 1 , 2 ],\r\n  \"a\" : \"x\" }\n"),
			`{"a":"x","b":[1,2]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := digest.ObjectDigest(tc.in)
			if err != nil {
				t.Fatalf("ObjectDigest: %v", err)
			}
			if want := canonical(tc.want); got != want {
				t.Errorf("ObjectDigest = %q, want %q (digest of %q)", got, want, tc.want)
			}
			checkShape(t, got)
		})
	}
}

// TestObjectDigestAppendixBStructs hashes the core types, whose field order is
// not the sorted order, and compares with the values of the draft.
func TestObjectDigestAppendixBStructs(t *testing.T) {
	op := core.OperationContext{
		OperationID:   "invoice-read-operation-0001",
		EnvironmentID: "https://gateway.example/environments/finance",
		PrincipalID:   "https://identity.example/principals/alice",
		Action:        "invoice.read",
		Resources:     []string{"https://invoices.example/invoices/INV-1042"},
		Method:        "GET",
		TargetURI:     "https://gateway.example/invoices/INV-1042",
		BodyDigest:    bodyDigestOfEmpty,
		Headers:       map[string]string{},
	}
	if got, err := digest.ObjectDigest(op); err != nil || got != operationDigestB3 {
		t.Errorf("ObjectDigest(OperationContext) = %q, %v; want %q", got, err, operationDigestB3)
	}
	if got, err := digest.ObjectDigest(&op); err != nil || got != operationDigestB3 {
		t.Errorf("ObjectDigest(*OperationContext) = %q, %v; want %q", got, err, operationDigestB3)
	}

	intent := core.Intent{
		IntentID:    "intent-september-invoices-007",
		PurposeID:   "https://policies.example/purposes/invoice-summary/v1",
		Description: "Read the approved September invoice to prepare the department summary.",
		TaskID:      "native-task:september-summary-007",
	}
	if got, err := digest.ObjectDigest(intent); err != nil || got != intentDigestB2 {
		t.Errorf("ObjectDigest(Intent) = %q, %v; want %q", got, err, intentDigestB2)
	}
}

func TestObjectDigestRejectsNonObjects(t *testing.T) {
	tests := map[string]any{
		"nil":            nil,
		"nil map":        map[string]any(nil),
		"nil pointer":    (*core.Intent)(nil),
		"array":          []any{map[string]any{"a": 1}},
		"empty array":    []string{},
		"string":         "x",
		"number":         1,
		"boolean":        true,
		"raw array":      json.RawMessage(`[{}]`),
		"raw string":     json.RawMessage(`"x"`),
		"raw number":     json.RawMessage(`1`),
		"raw null":       json.RawMessage(`null`),
		"nil raw":        json.RawMessage(nil),
		"byte slice":     []byte(`{"a":1}`),
		"padded scalar":  json.RawMessage(" 1 "),
		"object in list": []json.RawMessage{json.RawMessage(`{}`)},
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := digest.ObjectDigest(in)
			if !errors.Is(err, digest.ErrNotObject) {
				t.Errorf("ObjectDigest(%v) = %q, %v; want ErrNotObject", in, got, err)
			}
			if got != "" {
				t.Errorf("returned %q with an error", got)
			}
		})
	}
}

func nested(depth int) json.RawMessage {
	return json.RawMessage(strings.Repeat(`{"a":`, depth-1) + `{}` + strings.Repeat(`}`, depth-1))
}

func TestObjectDigestLimits(t *testing.T) {
	type ch struct{ C chan int }
	tests := []struct {
		name string
		in   any
		want error // nil: any error
	}{
		{"NaN", map[string]any{"n": math.NaN()}, nil},
		{"Infinity", map[string]any{"n": math.Inf(1)}, nil},
		{"unsupported type", ch{}, nil},
		{"duplicate member", json.RawMessage(`{"a":1,"a":2}`), strictjson.ErrDuplicateKey},
		{"duplicate member, escaped", json.RawMessage(`{"a":1,"a":2}`), strictjson.ErrDuplicateKey},
		{"integer above 2^53-1", map[string]any{"n": int64(1 << 53)}, strictjson.ErrInteger},
		{"integer below -(2^53-1)", map[string]any{"n": -int64(1 << 53)}, strictjson.ErrInteger},
		{"nesting depth 17", nested(17), strictjson.ErrDepth},
		{"invalid UTF-8", json.RawMessage("{\"a\":\"\xff\"}"), strictjson.ErrInvalidUTF8},
		{"lone surrogate escape", json.RawMessage(`{"a":"\ud800"}`), strictjson.ErrLoneSurrogate},
		{"float of integer value 2^53", map[string]any{"n": float64(1 << 53)}, strictjson.ErrInteger},
		{"over 256 KiB", map[string]any{"s": strings.Repeat("a", strictjson.DefaultMaxBytes)}, strictjson.ErrSize},
		{"malformed raw JSON", json.RawMessage(`{"a":`), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := digest.ObjectDigest(tc.in)
			if err == nil {
				t.Fatalf("ObjectDigest = %q, nil; want an error", got)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error = %v; want it to wrap %v", err, tc.want)
			}
			if got != "" {
				t.Errorf("returned %q with an error", got)
			}
		})
	}

	t.Run("HTML characters do not count against the size limit", func(t *testing.T) {
		// 100 KiB of '<' is 600 KiB when escaped as \u003c, over the limit, and
		// 100 KiB canonical.
		in := map[string]any{"s": strings.Repeat("<", 100<<10)}
		if got, err := digest.ObjectDigest(in); err != nil || got == "" {
			t.Errorf("ObjectDigest = %q, %v; want a digest", got, err)
		}
	})

	t.Run("nesting depth 16 is accepted", func(t *testing.T) {
		if got, err := digest.ObjectDigest(nested(16)); err != nil || got == "" {
			t.Errorf("ObjectDigest(depth 16) = %q, %v", got, err)
		}
	})
}

// TestObjectDigestIgnoresInputShape confirms the digest depends on the value,
// not on the Go type or the text layout it came from.
func TestObjectDigestIgnoresInputShape(t *testing.T) {
	const text = `{"headers":{"x":"1"},"a":[3,2,1],"b":{"d":null,"c":1.5}}`
	var decoded any
	if err := strictjson.Unmarshal([]byte(text), strictjson.Limits{}, &decoded); err != nil {
		t.Fatal(err)
	}
	viaMap, err := digest.ObjectDigest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	viaRaw, err := digest.ObjectDigest(json.RawMessage(text))
	if err != nil {
		t.Fatal(err)
	}
	if want := canonical(`{"a":[3,2,1],"b":{"c":1.5,"d":null},"headers":{"x":"1"}}`); viaMap != want || viaRaw != want {
		t.Errorf("viaMap = %q, viaRaw = %q, want %q", viaMap, viaRaw, want)
	}
}
