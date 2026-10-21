package jcs_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/strictjson"
)

// Expected values below were produced by the RFC 8785 Appendix A reference
// canonicalizer running on V8, not by this package.

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"whitespace dropped", " { \"b\" : [ { \"z\" : 1 , \"y\" : [ ] } , { } ] , \"a\" : { \"d\" : null , \"c\" : true , \"e\" : false } } \n",
			`{"a":{"c":true,"d":null,"e":false},"b":[{"y":[],"z":1},{}]}`},
		{"array order kept", `[3,1,2,"b","a"]`, `[3,1,2,"b","a"]`},
		{"empty containers", `[[],{}]`, `[[],{}]`},
		{"top-level string", `"x"`, `"x"`},
		{"top-level number", `1.50`, `1.5`},
		{"top-level null", `null`, `null`},
		{"top-level true", `true`, `true`},
		{"top-level false", `false`, `false`},
		{"top-level minus zero", `-0`, `0`},

		// Property names sort by UTF-16 code units. U+10000 is the surrogate
		// pair D800 DC00, which sorts before U+FFFF; by code point or by
		// UTF-8 bytes it would sort after.
		{"keys by UTF-16 units", `{"\uffff":1,"\ud800\udc00":2,"a":3,"ab":4,"":5,"B":6}`,
			"{\"\":5,\"B\":6,\"a\":3,\"ab\":4,\"\U00010000\":2,\"\uffff\":1}"},
		{"keys are compared unescaped", `{"\u0062":1,"a":2}`, `{"a":2,"b":1}`},
		{"key escapes follow string rules", `{"\u000a":1,"\"":2,"\\":3,"/":4}`, `{"\n":1,"\"":2,"/":4,"\\":3}`},

		{"string escapes",
			`"\u0000\u0001\u0008\u0009\u000a\u000b\u000c\u000d\u001f \" \\ / \u007f \u2028 \u2029 \u00e9 \ud83d\ude02 <>&'"`,
			"\"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f \\\" \\\\ / \x7f \u2028 \u2029 \u00e9 \U0001F602 <>&'\""},
		{"string literal chars kept", "\"\u00e9\u20ac\U0001F602\"", "\"\u00e9\u20ac\U0001F602\""},
		{"no unicode normalization", `"A\u030a"`, "\"A\u030a\""},

		{"numbers", `[1.0, -0, -0.0, 1E+2, 0.1, 1e21, 1e-7, 1.5e300, 5e-324, 1e-400, 0.000001, 0.0000001, 1e20, 123456789.125, 4.35, 0.30000000000000004, 1e22, 1e23, 12345678901234567890e0, 100e-2, 9007199254740991, -9007199254740991, 1.7976931348623157e308, 2.5e-5]`,
			`[1,0,0,100,0.1,1e+21,1e-7,1.5e+300,5e-324,0,0.000001,1e-7,100000000000000000000,123456789.125,4.35,0.30000000000000004,1e+22,1e+23,12345678901234567000,1,9007199254740991,-9007199254740991,1.7976931348623157e+308,0.000025]`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(tc.in)
			orig := bytes.Clone(in)
			got, err := jcs.Canonicalize(in)
			if err != nil {
				t.Fatalf("Canonicalize(%q): %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Errorf("Canonicalize(%q)\n got: %q\nwant: %q", tc.in, got, tc.want)
			}
			if !bytes.Equal(in, orig) {
				t.Error("input was modified")
			}
			// A canonical form is canonical. The one exception: a float such
			// as 1e20 is written without an exponent, and strictjson rejects
			// an integer literal that large (see TestCanonicalOutputBeyondSafeInteger).
			again, err := jcs.Canonicalize(got)
			if err != nil && !errors.Is(err, strictjson.ErrInteger) || err == nil && !bytes.Equal(again, got) {
				t.Errorf("not idempotent: Canonicalize(%q) = %q, %v", got, again, err)
			}
		})
	}
}

// Canonicalize rejects what strictjson rejects, and says why.
func TestCanonicalizeRejects(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty input", ``, strictjson.ErrSyntax},
		{"only whitespace", ` `, strictjson.ErrSyntax},
		{"truncated", `{"a":`, strictjson.ErrSyntax},
		{"trailing comma", `[1,]`, strictjson.ErrSyntax},
		{"duplicate key", `{"a":1,"a":2}`, strictjson.ErrDuplicateKey},
		{"duplicate key in escaped form", `{"a":1,"\u0061":2}`, strictjson.ErrDuplicateKey},
		{"duplicate key nested", `{"o":{"k":1,"k":1}}`, strictjson.ErrDuplicateKey},
		{"NaN", `NaN`, strictjson.ErrNonFinite},
		{"Infinity", `[Infinity]`, strictjson.ErrNonFinite},
		{"negative Infinity", `-Infinity`, strictjson.ErrNonFinite},
		{"overflowing literal", `1e999`, strictjson.ErrNonFinite},
		{"negative overflowing literal", `{"a":-1e999}`, strictjson.ErrNonFinite},
		{"integer 2^53", `9007199254740992`, strictjson.ErrInteger},
		{"integer -2^53", `[-9007199254740992]`, strictjson.ErrInteger},
		{"integer far outside", `{"a":123456789012345678901234567890}`, strictjson.ErrInteger},
		{"lone high surrogate", `"\ud800"`, strictjson.ErrLoneSurrogate},
		{"lone low surrogate", `"\udc00"`, strictjson.ErrLoneSurrogate},
		{"invalid UTF-8", "\"\xff\"", strictjson.ErrInvalidUTF8},
		{"encoded surrogate", "\"\xed\xa0\x80\"", strictjson.ErrInvalidUTF8},
		{"trailing data", `{} {}`, strictjson.ErrTrailingData},
		{"too deep", strings.Repeat("[", 17) + strings.Repeat("]", 17), strictjson.ErrDepth},
		{"too large", `"` + strings.Repeat("a", strictjson.DefaultMaxBytes) + `"`, strictjson.ErrSize},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := jcs.Canonicalize([]byte(tc.in))
			if err == nil {
				t.Fatalf("Canonicalize(%.40q) = %q, want an error", tc.in, got)
			}
			if got != nil {
				t.Errorf("result %q alongside error", got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
			var se *strictjson.Error
			if !errors.As(err, &se) {
				t.Errorf("error %T does not carry a *strictjson.Error", err)
			}
		})
	}
}

// Integer literals beyond ±(2^53-1) are rejected on input, but a float such as
// 1e20 is accepted and its canonical form is a plain integer literal, which
// Canonicalize in turn rejects. Section 7.1 of the draft is silent on feeding
// canonical output back in; the digest of an object never needs to.
func TestCanonicalOutputBeyondSafeInteger(t *testing.T) {
	out, err := jcs.Canonicalize([]byte(`[1e20,1e21,9007199254740993.0]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `[100000000000000000000,1e+21,9007199254740992]`; string(out) != want {
		t.Fatalf("Canonicalize = %q, want %q", out, want)
	}
	if _, err := jcs.Canonicalize(out); !errors.Is(err, strictjson.ErrInteger) {
		t.Errorf("Canonicalize(%q) error = %v, want %v", out, err, strictjson.ErrInteger)
	}
}

// The deepest document strictjson accepts must canonicalize.
func TestCanonicalizeAtDepthLimit(t *testing.T) {
	in := strings.Repeat(`{"a":`, 16) + `1` + strings.Repeat(`}`, 16)
	got, err := jcs.Canonicalize([]byte(in))
	if err != nil || string(got) != in {
		t.Fatalf("Canonicalize(depth 16) = %q, %v", got, err)
	}
}

// A large object comes out with its keys in ascending order.
func TestCanonicalizeSortsManyKeys(t *testing.T) {
	const n = 200
	var in, want strings.Builder
	in.WriteString("{")
	want.WriteString("{")
	for i := range n {
		if i > 0 {
			in.WriteString(",")
			want.WriteString(",")
		}
		// Zero-padded keys: written in descending order, sorted ascending.
		fmt.Fprintf(&in, `"k%03d":%d`, n-1-i, i)
		fmt.Fprintf(&want, `"k%03d":%d`, i, n-1-i)
	}
	in.WriteString("}")
	want.WriteString("}")
	got, err := jcs.Canonicalize([]byte(in.String()))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want.String() {
		t.Errorf("keys not sorted:\n got: %.120s...\nwant: %.120s...", got, want.String())
	}
}
