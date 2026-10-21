package jcs

import (
	"fmt"
	"slices"
	"unicode/utf16"

	"hop.top/pact-go/core/strictjson"
)

// Canonicalize returns the RFC 8785 canonical form of the JSON text in data:
// UTF-8 without insignificant white space, object members sorted by name,
// strings and numbers in the ECMAScript serialization.
//
// data is first read by strictjson with its default limits, so a document
// that strictjson rejects is rejected here with the same *strictjson.Error:
// duplicate member names, nesting over 16, input over 256 KiB, invalid UTF-8,
// unpaired surrogate escapes, text after the value, NaN and Infinity, number
// literals that overflow binary64, and integer literals outside ±(2^53-1).
// Any JSON value may be canonicalized, not only an object. The input is not
// modified, and an error returns a nil result.
func Canonicalize(data []byte) ([]byte, error) {
	var v any
	if err := strictjson.Unmarshal(data, strictjson.Limits{}, &v); err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	out, err := appendValue(make([]byte, 0, len(data)), v)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// appendValue appends the canonical form of v, a value as encoding/json
// decodes it into an any.
func appendValue(b []byte, v any) ([]byte, error) {
	switch v := v.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		if v {
			return append(b, "true"...), nil
		}
		return append(b, "false"...), nil
	case float64:
		return appendNumber(b, v)
	case string:
		return appendString(b, v), nil
	case []any:
		b = append(b, '[')
		for i, e := range v {
			if i > 0 {
				b = append(b, ',')
			}
			var err error
			if b, err = appendValue(b, e); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case map[string]any:
		return appendObject(b, v)
	default:
		return nil, fmt.Errorf("jcs: unexpected %T in decoded JSON", v)
	}
}

// member is one object member with its name in UTF-16 code units, the unit
// RFC 8785 Section 3.2.3 sorts by.
type member struct {
	name  string
	units []uint16
}

func appendObject(b []byte, m map[string]any) ([]byte, error) {
	members := make([]member, 0, len(m))
	for name := range m {
		members = append(members, member{name, utf16.Encode([]rune(name))})
	}
	slices.SortFunc(members, func(x, y member) int { return slices.Compare(x.units, y.units) })

	b = append(b, '{')
	for i, mem := range members {
		if i > 0 {
			b = append(b, ',')
		}
		b = appendString(b, mem.name)
		b = append(b, ':')
		var err error
		if b, err = appendValue(b, m[mem.name]); err != nil {
			return nil, err
		}
	}
	return append(b, '}'), nil
}

const hexDigits = "0123456789abcdef"

// appendString appends s as a JSON string the way ECMAScript JSON.stringify
// writes it (RFC 8785 Section 3.2.2.2): the quotation mark and the reverse
// solidus are escaped, the control characters U+0008, U+0009, U+000A, U+000C
// and U+000D use their short forms, every other control character below
// U+0020 becomes \u00xx in lower-case hex, and everything else, including
// U+007F, U+2028 and U+2029, is written as is. s is valid UTF-8 without
// unpaired surrogates, which strictjson guarantees.
func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' {
			continue
		}
		b = append(b, s[start:i]...)
		start = i + 1
		switch c {
		case '"', '\\':
			b = append(b, '\\', c)
		case '\b':
			b = append(b, '\\', 'b')
		case '\t':
			b = append(b, '\\', 't')
		case '\n':
			b = append(b, '\\', 'n')
		case '\f':
			b = append(b, '\\', 'f')
		case '\r':
			b = append(b, '\\', 'r')
		default:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		}
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}
