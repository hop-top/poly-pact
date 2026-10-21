package jcs_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"unicode/utf8"

	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/strictjson"
)

// FuzzCanonicalize checks that no input makes Canonicalize panic and that an
// accepted input yields a canonical document: valid UTF-8, the same JSON value
// as the input, and unchanged by a second pass. Run it for thirty seconds with
//
//	go test -run '^$' -fuzz '^FuzzCanonicalize$' -fuzztime 30s ./core/jcs
func FuzzCanonicalize(f *testing.F) {
	for _, e := range jcsEntries(f) {
		if e.ID != numbersID {
			f.Add(readFixture(f, e.Path))
		}
	}
	for _, s := range []string{
		``, `null`, `0`, `-0`, `1e21`, `1e-7`, `5e-324`, `1.7976931348623157e308`, `1e999`, `9007199254740992`,
		`"😂"`, `"\ud800"`, `{"b":1,"a":[1.5,{"d":null,"c":"\u0000"}]}`, `{"a":1,"a":2}`,
		`{"￿":1,"𐀀":2}`, "\"\xff\"", `[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := jcs.Canonicalize(in)
		if err != nil {
			if out != nil {
				t.Fatalf("result %q alongside error %v", out, err)
			}
			return
		}
		if !utf8.Valid(out) {
			t.Fatalf("output is not UTF-8: %q", out)
		}
		// encoding/json, not strictjson, reads the output: a float such as
		// 1e20 is written as an integer literal that strictjson refuses.
		var a, b any
		if err := strictjson.Unmarshal(in, strictjson.Limits{}, &a); err != nil {
			t.Fatalf("input accepted by Canonicalize but not by strictjson: %v", err)
		}
		if err := json.Unmarshal(out, &b); err != nil {
			t.Fatalf("output %q is not JSON: %v", out, err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("value changed:\n in: %q\nout: %q", in, out)
		}
		again, err := jcs.Canonicalize(out)
		if err != nil {
			if errors.Is(err, strictjson.ErrInteger) {
				return // integer-form float beyond ±(2^53-1): see TestCanonicalOutputBeyondSafeInteger
			}
			t.Fatalf("output %q rejected: %v", out, err)
		}
		if !bytes.Equal(again, out) {
			t.Fatalf("not idempotent: %q -> %q", out, again)
		}
	})
}
