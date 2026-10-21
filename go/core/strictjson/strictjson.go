// Package strictjson decodes PACT JSON with the checks Section 7.1 of the
// draft requires and encoding/json does not make.
//
// Decode and Unmarshal reject, before they touch the target:
//   - duplicate member names, compared after unescaping, in any object, including
//     the open "extensions" and "attributes" objects and free-form values;
//   - member names that are not an exact, case-sensitive match of a JSON tag of
//     the target struct (encoding/json would fold case), except inside map and
//     free-form values such as extensions, attributes and headers;
//   - nesting deeper than Limits.MaxDepth (16 by default);
//   - non-finite numbers: NaN, Infinity and literals that overflow binary64;
//   - invalid UTF-8 and unpaired surrogate escapes;
//   - integer literals outside ±(2^53-1), anywhere in the document, and, for
//     an integer-typed target field, negative or non-integer numbers;
//   - null for any target that cannot hold it (only pointers, interfaces and
//     json.Unmarshaler types such as json.RawMessage can);
//   - empty input, text after the JSON value, and input over Limits.MaxBytes.
//
// The decoder checks syntax and shape. It does not apply the schema's
// patterns, lengths, enum sets or required members; a schema validator does.
//
// On error the target is unchanged. On success it holds exactly the decoded
// document: it is replaced, not merged.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"unicode/utf8"
)

const (
	// MaxSafeInteger is the largest integer a core field may carry: 2^53-1.
	MaxSafeInteger = 1<<53 - 1

	// DefaultMaxBytes is the decoded presentation limit of Section 20.1.
	DefaultMaxBytes = 256 << 10

	// DefaultMaxDepth is the JSON nesting limit of Section 20.1. The outermost
	// object or array has depth 1.
	DefaultMaxDepth = 16
)

// Limits bounds one decode. A field that is zero or negative selects its
// default.
type Limits struct {
	// MaxBytes is the largest input in bytes.
	MaxBytes int
	// MaxDepth is the deepest nesting of objects and arrays.
	MaxDepth int
}

func (l Limits) resolved() Limits {
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	return l
}

// Reasons a decode fails. An *Error wraps exactly one of them, so test with
// errors.Is.
var (
	ErrTarget        = errors.New("strictjson: target must be a non-nil pointer")
	ErrSize          = errors.New("strictjson: input too large")
	ErrSyntax        = errors.New("strictjson: invalid JSON")
	ErrInvalidUTF8   = errors.New("strictjson: invalid UTF-8")
	ErrLoneSurrogate = errors.New("strictjson: unpaired surrogate escape")
	ErrDepth         = errors.New("strictjson: nesting too deep")
	ErrDuplicateKey  = errors.New("strictjson: duplicate member name")
	ErrUnknownField  = errors.New("strictjson: unknown field")
	ErrNonFinite     = errors.New("strictjson: non-finite number")
	ErrInteger       = errors.New("strictjson: integer out of range or not an integer")
	ErrNull          = errors.New("strictjson: null not allowed")
	ErrTrailingData  = errors.New("strictjson: data after the JSON value")
	ErrType          = errors.New("strictjson: value does not fit the target type")
)

// Error describes where and why a decode failed.
type Error struct {
	// Kind is one of the Err values above.
	Kind error
	// Path is the JSON Pointer (RFC 6901) of the offending member, empty for
	// the document root.
	Path string
	// Offset is the byte offset in the input at which the problem was found.
	// It is approximate for errors found after the whole input was read.
	Offset int64
	// Detail adds specifics, such as the member name.
	Detail string
}

func (e *Error) Error() string {
	s := e.Kind.Error()
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Path != "" {
		s += " at " + e.Path
	}
	return fmt.Sprintf("%s (offset %d)", s, e.Offset)
}

func (e *Error) Unwrap() error { return e.Kind }

// Decode reads one JSON value from r, enforces the rules in the package
// documentation and stores the result in v, a non-nil pointer.
func Decode(r io.Reader, limits Limits, v any) error {
	lim := limits.resolved()
	data, err := io.ReadAll(io.LimitReader(r, int64(lim.MaxBytes)+1))
	if err != nil {
		return fmt.Errorf("strictjson: read: %w", err)
	}
	return Unmarshal(data, limits, v)
}

// Unmarshal is Decode for input already in memory.
func Unmarshal(data []byte, limits Limits, v any) error {
	lim := limits.resolved()
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return &Error{Kind: ErrTarget, Detail: fmt.Sprintf("got %T", v)}
	}
	if len(data) > lim.MaxBytes {
		return &Error{Kind: ErrSize, Offset: int64(lim.MaxBytes), Detail: fmt.Sprintf("limit is %d bytes", lim.MaxBytes)}
	}
	if !utf8.Valid(data) {
		return &Error{Kind: ErrInvalidUTF8, Offset: int64(firstInvalidUTF8(data))}
	}

	if err := walk(data, lim.MaxDepth, rv.Type().Elem()); err != nil {
		return err
	}
	if err := checkSurrogates(data); err != nil {
		return err
	}

	// Everything the walk could not see is now ruled out; decode into a fresh
	// value so that a failure leaves v untouched.
	fresh := reflect.New(rv.Type().Elem())
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(fresh.Interface()); err != nil {
		return &Error{Kind: ErrType, Offset: dec.InputOffset(), Detail: err.Error()}
	}
	rv.Elem().Set(fresh.Elem())
	return nil
}

func firstInvalidUTF8(data []byte) int {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return len(data)
}

// checkSurrogates rejects \uD800-\uDFFF escapes that are not a high surrogate
// immediately followed by a low surrogate. It expects syntactically valid JSON:
// walk has run first.
func checkSurrogates(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			i++
			if i >= len(data) || data[i] != 'u' {
				continue
			}
			r, ok := hex4(data, i+1)
			if !ok {
				return nil // not valid JSON; walk reports it
			}
			i += 4
			switch {
			case r >= 0xDC00 && r <= 0xDFFF:
				return &Error{Kind: ErrLoneSurrogate, Offset: int64(i - 5), Detail: fmt.Sprintf(`low surrogate \u%04x without a high surrogate before it`, r)}
			case r >= 0xD800 && r <= 0xDBFF:
				next, ok := uint16(0), false
				if i+6 < len(data) && data[i+1] == '\\' && data[i+2] == 'u' {
					var n rune
					if n, ok = hex4(data, i+3); ok {
						next = uint16(n)
					}
				}
				if !ok || next < 0xDC00 || next > 0xDFFF {
					return &Error{Kind: ErrLoneSurrogate, Offset: int64(i - 5), Detail: fmt.Sprintf(`high surrogate \u%04x without a low surrogate after it`, r)}
				}
				i += 6
			}
		}
	}
	return nil
}

// hex4 parses four hex digits at data[at:].
func hex4(data []byte, at int) (rune, bool) {
	if at+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[at : at+4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}
