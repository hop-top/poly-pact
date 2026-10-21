package strictjson_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"hop.top/pact-go/core/strictjson"
)

type inner struct {
	N int64 `json:"n"`
}

type sample struct {
	Name       string                     `json:"name"`
	Count      int64                      `json:"count"`
	Ratio      float64                    `json:"ratio"`
	Opt        *string                    `json:"opt"`
	OptCount   *int64                     `json:"opt_count"`
	Inner      *inner                     `json:"inner,omitzero"`
	Items      []inner                    `json:"items,omitzero"`
	Raw        json.RawMessage            `json:"raw,omitzero"`
	Headers    map[string]string          `json:"headers,omitzero"`
	Extensions map[string]json.RawMessage `json:"extensions,omitzero"`
}

func decode(t *testing.T, in string, lim strictjson.Limits, v any) error {
	t.Helper()
	return strictjson.Decode(strings.NewReader(in), lim, v)
}

func TestDecodeValid(t *testing.T) {
	in := `{"name":"a","count":9007199254740991,"ratio":1.5e3,"opt":null,"opt_count":7,` +
		`"inner":{"n":0},"items":[{"n":1},{"n":2}],"raw":{"x":[1,2,{"y":null}]},` +
		`"headers":{"x-a":"1"},"extensions":{"k":{"deep":[true,false,null]}}}`
	var got sample
	if err := decode(t, in, strictjson.Limits{}, &got); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Name != "a" || got.Count != 9007199254740991 || got.Ratio != 1500 {
		t.Fatalf("scalars: %+v", got)
	}
	if got.Opt != nil || got.OptCount == nil || *got.OptCount != 7 {
		t.Fatalf("nullable: %+v", got)
	}
	if got.Inner == nil || len(got.Items) != 2 || got.Items[1].N != 2 {
		t.Fatalf("nested: %+v", got)
	}
	if string(got.Raw) != `{"x":[1,2,{"y":null}]}` {
		t.Fatalf("raw: %s", got.Raw)
	}
	if string(got.Extensions["k"]) != `{"deep":[true,false,null]}` {
		t.Fatalf("extensions: %s", got.Extensions["k"])
	}
}

func TestDecodeRejects(t *testing.T) {
	deep := func(n int) string {
		return `{"extensions":{"a":` + strings.Repeat("[", n-2) + strings.Repeat("]", n-2) + `}}`
	}
	tests := []struct {
		name string
		in   string
		lim  strictjson.Limits
		want error
	}{
		{"duplicate top level", `{"name":"a","name":"b"}`, strictjson.Limits{}, strictjson.ErrDuplicateKey},
		{"duplicate same value", `{"name":"a","name":"a"}`, strictjson.Limits{}, strictjson.ErrDuplicateKey},
		{"duplicate nested struct", `{"inner":{"n":1,"n":2}}`, strictjson.Limits{}, strictjson.ErrDuplicateKey},
		{"duplicate in open map", `{"extensions":{"a":{"b":1,"b":2}}}`, strictjson.Limits{}, strictjson.ErrDuplicateKey},
		{"duplicate in headers", `{"headers":{"x":"1","x":"2"}}`, strictjson.Limits{}, strictjson.ErrDuplicateKey},
		{"duplicate in raw", `{"raw":{"a":1,"a":2}}`, strictjson.Limits{}, strictjson.ErrDuplicateKey},
		{"duplicate in array element", `{"items":[{"n":1},{"n":1,"n":1}]}`, strictjson.Limits{}, strictjson.ErrDuplicateKey},
		{"duplicate after unescape", `{"name":"a","name":"b"}`, strictjson.Limits{}, strictjson.ErrDuplicateKey},
		{"unknown field", `{"name":"a","bogus":1}`, strictjson.Limits{}, strictjson.ErrUnknownField},
		{"unknown nested field", `{"inner":{"n":1,"m":2}}`, strictjson.Limits{}, strictjson.ErrUnknownField},
		{"unknown field in array element", `{"items":[{"n":1,"m":2}]}`, strictjson.Limits{}, strictjson.ErrUnknownField},
		{"case variant is unknown", `{"Name":"a"}`, strictjson.Limits{}, strictjson.ErrUnknownField},
		{"case variant beside real field", `{"name":"a","NAME":"b"}`, strictjson.Limits{}, strictjson.ErrUnknownField},
		{"depth 17 objects", `{"extensions":` + strings.Repeat(`{"a":`, 15) + `{}` + strings.Repeat("}", 15) + `}`, strictjson.Limits{}, strictjson.ErrDepth},
		{"depth 17 arrays", deep(17), strictjson.Limits{}, strictjson.ErrDepth},
		{"custom depth", `{"raw":[[1]]}`, strictjson.Limits{MaxDepth: 2}, strictjson.ErrDepth},
		{"1e999", `{"ratio":1e999}`, strictjson.Limits{}, strictjson.ErrNonFinite},
		{"-1e999 in raw", `{"raw":-1e999}`, strictjson.Limits{}, strictjson.ErrNonFinite},
		{"NaN", `{"raw":NaN}`, strictjson.Limits{}, strictjson.ErrNonFinite},
		{"Infinity", `{"raw":Infinity}`, strictjson.Limits{}, strictjson.ErrNonFinite},
		{"-Infinity", `{"raw":-Infinity}`, strictjson.Limits{}, strictjson.ErrNonFinite},
		{"invalid utf8 byte", "{\"name\":\"\xff\"}", strictjson.Limits{}, strictjson.ErrInvalidUTF8},
		{"invalid utf8 in key", "{\"na\xc0me\":1}", strictjson.Limits{}, strictjson.ErrInvalidUTF8},
		{"lone high surrogate", `{"name":"\ud800"}`, strictjson.Limits{}, strictjson.ErrLoneSurrogate},
		{"lone low surrogate", `{"name":"\udc00"}`, strictjson.Limits{}, strictjson.ErrLoneSurrogate},
		{"high then bmp", `{"name":"\ud800A"}`, strictjson.Limits{}, strictjson.ErrLoneSurrogate},
		{"reversed pair", `{"name":"\udc00\ud800"}`, strictjson.Limits{}, strictjson.ErrLoneSurrogate},
		{"surrogate in key", `{"extensions":{"\ud800":1}}`, strictjson.Limits{}, strictjson.ErrLoneSurrogate},
		{"escaped backslash is not a surrogate escape guard", `{"name":"\\\ud800"}`, strictjson.Limits{}, strictjson.ErrLoneSurrogate},
		{"integer 2^53", `{"raw":9007199254740992}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"integer -2^53", `{"raw":-9007199254740992}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"integer huge", `{"raw":123456789012345678901234567890}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"typed integer overflow", `{"count":9007199254740992}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"typed integer negative", `{"count":-1}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"typed integer fraction", `{"count":1.5}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"typed integer exponent form", `{"count":1e3}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"typed integer 1.0", `{"count":1.0}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"nullable integer negative", `{"opt_count":-5}`, strictjson.Limits{}, strictjson.ErrInteger},
		{"trailing text", `{"name":"a"} x`, strictjson.Limits{}, strictjson.ErrTrailingData},
		{"trailing value", `{"name":"a"}{}`, strictjson.Limits{}, strictjson.ErrTrailingData},
		{"trailing brace", `{"name":"a"}}`, strictjson.Limits{}, strictjson.ErrTrailingData},
		{"empty input", ``, strictjson.Limits{}, strictjson.ErrSyntax},
		{"whitespace only", " \n", strictjson.Limits{}, strictjson.ErrSyntax},
		{"truncated", `{"name":"a"`, strictjson.Limits{}, strictjson.ErrSyntax},
		{"bom", "\xef\xbb\xbf{}", strictjson.Limits{}, strictjson.ErrSyntax},
		{"leading zero", `{"raw":01}`, strictjson.Limits{}, strictjson.ErrSyntax},
		{"single quotes", `{'name':'a'}`, strictjson.Limits{}, strictjson.ErrSyntax},
		{"trailing comma", `{"name":"a",}`, strictjson.Limits{}, strictjson.ErrSyntax},
		{"too large", `{"name":"` + strings.Repeat("a", 64) + `"}`, strictjson.Limits{MaxBytes: 32}, strictjson.ErrSize},
		{"null for string", `{"name":null}`, strictjson.Limits{}, strictjson.ErrNull},
		{"null for integer", `{"count":null}`, strictjson.Limits{}, strictjson.ErrNull},
		{"null for slice", `{"items":null}`, strictjson.Limits{}, strictjson.ErrNull},
		{"null for map", `{"headers":null}`, strictjson.Limits{}, strictjson.ErrNull},
		{"null document", `null`, strictjson.Limits{}, strictjson.ErrNull},
		{"type mismatch", `{"name":5}`, strictjson.Limits{}, strictjson.ErrType},
		{"type mismatch object", `{"name":{}}`, strictjson.Limits{}, strictjson.ErrType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got sample
			err := decode(t, tc.in, tc.lim, &got)
			if err == nil {
				t.Fatalf("Decode(%q) = nil, want %v", tc.in, tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Decode(%q) = %v, want %v", tc.in, err, tc.want)
			}
		})
	}
}

func TestDecodeAccepts(t *testing.T) {
	arrays := func(n int) string {
		return `{"extensions":{"a":` + strings.Repeat("[", n-2) + strings.Repeat("]", n-2) + `}}`
	}
	tests := []struct {
		name string
		in   string
		lim  strictjson.Limits
	}{
		{"depth 16 objects", `{"extensions":` + strings.Repeat(`{"a":`, 14) + `{}` + strings.Repeat("}", 14) + `}`, strictjson.Limits{}},
		{"depth 16 arrays", arrays(16), strictjson.Limits{}},
		{"max safe integer", `{"count":9007199254740991,"raw":9007199254740991}`, strictjson.Limits{}},
		{"negative max safe in raw", `{"raw":-9007199254740991}`, strictjson.Limits{}},
		{"zero count", `{"count":0}`, strictjson.Limits{}},
		{"negative zero in raw", `{"raw":-0}`, strictjson.Limits{}},
		{"largest finite float", `{"ratio":1.7976931348623157e308}`, strictjson.Limits{}},
		{"negative float", `{"ratio":-12.5}`, strictjson.Limits{}},
		{"float underflow is finite", `{"ratio":1e-999}`, strictjson.Limits{}},
		{"surrogate pair", `{"name":"😀"}`, strictjson.Limits{}},
		{"escaped backslash then u", `{"name":"\\ud800"}`, strictjson.Limits{}},
		{"replacement char literal", `{"name":"` + "�" + `"}`, strictjson.Limits{}},
		{"case distinct keys in open map", `{"extensions":{"a":1,"A":2}}`, strictjson.Limits{}},
		{"same key in sibling objects", `{"items":[{"n":1},{"n":2}],"inner":{"n":3}}`, strictjson.Limits{}},
		{"trailing whitespace", "{\"name\":\"a\"}\n \t\r\n", strictjson.Limits{}},
		{"leading whitespace", " \n{\"name\":\"a\"}", strictjson.Limits{}},
		{"null in raw", `{"raw":null}`, strictjson.Limits{}},
		{"null in nullable", `{"opt":null,"opt_count":null}`, strictjson.Limits{}},
		{"null in nullable struct pointer", `{"inner":null}`, strictjson.Limits{}},
		{"custom depth", `{"raw":[[1]]}`, strictjson.Limits{MaxDepth: 3}},
		{"exact size", `{"name":"a"}`, strictjson.Limits{MaxBytes: 12}},
		{"empty object", `{}`, strictjson.Limits{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got sample
			if err := decode(t, tc.in, tc.lim, &got); err != nil {
				t.Fatalf("Decode(%q): %v", tc.in, err)
			}
		})
	}
}

func TestDecodeFreeFormTarget(t *testing.T) {
	var any1 any
	if err := decode(t, `{"a":[1,{"b":null}],"A":2}`, strictjson.Limits{}, &any1); err != nil {
		t.Fatalf("Decode into any: %v", err)
	}
	if err := decode(t, `{"a":1,"a":2}`, strictjson.Limits{}, &any1); !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Fatalf("duplicate into any: %v", err)
	}
	var m map[string]any
	if err := decode(t, `{"x":9007199254740992}`, strictjson.Limits{}, &m); !errors.Is(err, strictjson.ErrInteger) {
		t.Fatalf("overflow into map: %v", err)
	}
}

func TestDecodeDoesNotFillTargetOnFailure(t *testing.T) {
	for name, in := range map[string]string{
		"walk failure":   `{"name":"new","count":-1}`,
		"decode failure": `{"name":"new","count":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := sample{Name: "keep"}
			if err := decode(t, in, strictjson.Limits{}, &got); err == nil {
				t.Fatal("want error")
			}
			if got.Name != "keep" {
				t.Fatalf("target modified on failure: %+v", got)
			}
		})
	}
}

func TestDecodeReplacesTarget(t *testing.T) {
	got := sample{Name: "old", Headers: map[string]string{"old": "1"}}
	if err := decode(t, `{"headers":{"new":"2"}}`, strictjson.Limits{}, &got); err != nil {
		t.Fatal(err)
	}
	if got.Name != "" || len(got.Headers) != 1 || got.Headers["new"] != "2" {
		t.Fatalf("target merged instead of replaced: %+v", got)
	}
}

func TestDecodeBadTarget(t *testing.T) {
	var s sample
	for _, v := range []any{nil, s, (*sample)(nil)} {
		if err := decode(t, `{}`, strictjson.Limits{}, v); !errors.Is(err, strictjson.ErrTarget) {
			t.Fatalf("Decode into %T: %v, want ErrTarget", v, err)
		}
	}
}

func TestUnmarshalMatchesDecode(t *testing.T) {
	in := []byte(`{"name":"a","name":"b"}`)
	var s sample
	if err := strictjson.Unmarshal(in, strictjson.Limits{}, &s); !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := strictjson.Decode(bytes.NewReader(in), strictjson.Limits{}, &s); !errors.Is(err, strictjson.ErrDuplicateKey) {
		t.Fatalf("Decode: %v", err)
	}
}

func TestErrorNamesPathAndOffset(t *testing.T) {
	var s sample
	err := decode(t, `{"inner":{"n":1,"m":2}}`, strictjson.Limits{}, &s)
	if err == nil || !strings.Contains(err.Error(), "/inner/m") {
		t.Fatalf("error should name the member path: %v", err)
	}
}

func TestDepthIsCheckedBeforeBodyIsRead(t *testing.T) {
	// A hostile document opens many containers; the walk must stop at the
	// limit instead of tracking the whole input.
	in := strings.Repeat("[", 100000)
	var v any
	err := decode(t, in, strictjson.Limits{MaxBytes: 1 << 20}, &v)
	if !errors.Is(err, strictjson.ErrDepth) {
		t.Fatalf("got %v, want ErrDepth", err)
	}
}

func ExampleDecode() {
	var v struct {
		Name string `json:"name"`
	}
	err := strictjson.Decode(strings.NewReader(`{"name":"a","name":"b"}`), strictjson.Limits{}, &v)
	fmt.Println(errors.Is(err, strictjson.ErrDuplicateKey))
	// Output: true
}

func TestErrorFields(t *testing.T) {
	var s sample
	err := decode(t, `{"items":[{"n":1},{"n":1,"x~/":2}]}`, strictjson.Limits{}, &s)
	var se *strictjson.Error
	if !errors.As(err, &se) {
		t.Fatalf("not a *strictjson.Error: %v", err)
	}
	if se.Kind != strictjson.ErrUnknownField || se.Path != "/items/1/x~0~1" || se.Offset <= 0 {
		t.Fatalf("got %+v", se)
	}
}

func FuzzUnmarshal(f *testing.F) {
	for _, seed := range []string{
		`{}`, `{"name":"a"}`, `{"name":"a","name":"b"}`, `{"count":9007199254740992}`,
		`{"raw":[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]}`, `{"name":"\ud800"}`, "{\"name\":\"\xff\"}",
		`{"ratio":1e999}`, `{"raw":NaN}`, `{} x`, ``, `[`, `{"inner":{"n":1}}`, `{"extensions":{"a":{"a":1}}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var s sample
		if err := strictjson.Unmarshal(data, strictjson.Limits{}, &s); err != nil {
			return
		}
		// Accepted input must be well-formed JSON and well-formed UTF-8, and
		// must survive a second strict decode of its own re-encoding.
		if !json.Valid(data) {
			t.Fatalf("accepted invalid JSON %q", data)
		}
		out, err := json.Marshal(&s)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		var again sample
		if err := strictjson.Unmarshal(out, strictjson.Limits{}, &again); err != nil {
			t.Fatalf("re-decode of %s: %v", out, err)
		}
	})
}
