package validator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"unicode/utf8"

	"hop.top/pact-go/core/jcs"
)

// errUnsupportedSchema is the error of a field-rule schema the validator
// cannot evaluate as published: a keyword outside the restricted set of
// Appendix A.1, or a keyword with a malformed value. Such a rule is UNKNOWN
// with UNSUPPORTED_REQUIREMENT, never a permissive fallback (draft 22.2).
var errUnsupportedSchema = errors.New("validator: unsupported field-rule schema")

// maxSchemaDepth bounds the nesting of a field-rule schema (Appendix A.1:
// the document's depth limits).
const maxSchemaDepth = 16

// schemaKeywords is the restricted Draft 2020-12 keyword set of Appendix
// A.1.
var schemaKeywords = map[string]bool{
	"type": true, "enum": true, "const": true, "properties": true, "required": true,
	"additionalProperties": true, "items": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "contains": true, "minContains": true, "maxContains": true,
	"minLength": true, "maxLength": true, "minimum": true, "maximum": true,
	"exclusiveMinimum": true, "exclusiveMaximum": true, "allOf": true, "anyOf": true,
	"oneOf": true, "not": true,
}

var schemaTypes = map[string]bool{
	"null": true, "boolean": true, "object": true, "array": true, "number": true, "string": true, "integer": true,
}

// decodeJSON decodes raw into generic JSON data, numbers kept as json.Number.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	return v, nil
}

// compileSchema decodes a field-rule schema and checks that every keyword,
// at every depth, is one of Appendix A.1 with a well-formed value.
func compileSchema(raw json.RawMessage) (any, error) {
	s, err := decodeJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnsupportedSchema, err)
	}
	if err := checkSchema(s, 1); err != nil {
		return nil, err
	}
	return s, nil
}

func checkSchema(s any, depth int) error {
	if depth > maxSchemaDepth {
		return fmt.Errorf("%w: nested deeper than %d", errUnsupportedSchema, maxSchemaDepth)
	}
	switch s := s.(type) {
	case bool:
		return nil
	case map[string]any:
		for k, v := range s {
			if !schemaKeywords[k] {
				return fmt.Errorf("%w: keyword %q", errUnsupportedSchema, k)
			}
			if err := checkKeyword(k, v, depth); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("%w: a schema is an object or a boolean", errUnsupportedSchema)
}

func checkKeyword(k string, v any, depth int) error {
	bad := func() error { return fmt.Errorf("%w: malformed %q", errUnsupportedSchema, k) }
	switch k {
	case "type":
		names, ok := v.([]any)
		if !ok {
			names = []any{v}
		}
		for _, n := range names {
			if s, ok := n.(string); !ok || !schemaTypes[s] {
				return bad()
			}
		}
	case "enum":
		if _, ok := v.([]any); !ok {
			return bad()
		}
	case "properties":
		m, ok := v.(map[string]any)
		if !ok {
			return bad()
		}
		for _, sub := range m {
			if err := checkSchema(sub, depth+1); err != nil {
				return err
			}
		}
	case "required":
		names, ok := v.([]any)
		if !ok {
			return bad()
		}
		for _, n := range names {
			if _, ok := n.(string); !ok {
				return bad()
			}
		}
	case "additionalProperties", "items", "contains", "not":
		return checkSchema(v, depth+1)
	case "allOf", "anyOf", "oneOf":
		subs, ok := v.([]any)
		if !ok || len(subs) == 0 {
			return bad()
		}
		for _, sub := range subs {
			if err := checkSchema(sub, depth+1); err != nil {
				return err
			}
		}
	case "minItems", "maxItems", "minLength", "maxLength", "minContains", "maxContains":
		if n, ok := ratOf(v); !ok || !n.IsInt() || n.Sign() < 0 {
			return bad()
		}
	case "uniqueItems":
		if _, ok := v.(bool); !ok {
			return bad()
		}
	case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
		if _, ok := ratOf(v); !ok {
			return bad()
		}
	}
	return nil
}

// matches reports whether the instance v satisfies the compiled schema s
// (JSON Schema Draft 2020-12, restricted to Appendix A.1).
func matches(s any, v any) bool {
	switch s := s.(type) {
	case bool:
		return s
	case map[string]any:
		for k, kv := range s {
			if !keywordHolds(s, k, kv, v) {
				return false
			}
		}
		return true
	}
	return false
}

func keywordHolds(s map[string]any, k string, kv, v any) bool {
	switch k {
	case "type":
		names, ok := kv.([]any)
		if !ok {
			names = []any{kv}
		}
		for _, n := range names {
			if isType(v, n.(string)) {
				return true
			}
		}
		return false
	case "enum":
		for _, e := range kv.([]any) {
			if jsonEqual(e, v) {
				return true
			}
		}
		return false
	case "const":
		return jsonEqual(kv, v)
	case "not":
		return !matches(kv, v)
	case "allOf", "anyOf", "oneOf":
		n := 0
		for _, sub := range kv.([]any) {
			if matches(sub, v) {
				n++
			}
		}
		subs := len(kv.([]any))
		return (k == "allOf" && n == subs) || (k == "anyOf" && n > 0) || (k == "oneOf" && n == 1)
	}
	switch v := v.(type) {
	case map[string]any:
		return objectHolds(s, k, kv, v)
	case []any:
		return arrayHolds(s, k, kv, v)
	case string:
		n, _ := ratOf(kv)
		switch k {
		case "minLength":
			return big.NewRat(int64(utf8.RuneCountInString(v)), 1).Cmp(n) >= 0
		case "maxLength":
			return big.NewRat(int64(utf8.RuneCountInString(v)), 1).Cmp(n) <= 0
		}
	case json.Number:
		x, ok := ratOf(v)
		bound, _ := ratOf(kv)
		if !ok {
			return false
		}
		switch k {
		case "minimum":
			return x.Cmp(bound) >= 0
		case "maximum":
			return x.Cmp(bound) <= 0
		case "exclusiveMinimum":
			return x.Cmp(bound) > 0
		case "exclusiveMaximum":
			return x.Cmp(bound) < 0
		}
	}
	return true
}

func objectHolds(s map[string]any, k string, kv any, v map[string]any) bool {
	switch k {
	case "properties":
		for name, sub := range kv.(map[string]any) {
			if pv, ok := v[name]; ok && !matches(sub, pv) {
				return false
			}
		}
	case "additionalProperties":
		props, _ := s["properties"].(map[string]any)
		for name, pv := range v {
			if _, declared := props[name]; !declared && !matches(kv, pv) {
				return false
			}
		}
	case "required":
		for _, name := range kv.([]any) {
			if _, ok := v[name.(string)]; !ok {
				return false
			}
		}
	}
	return true
}

func arrayHolds(s map[string]any, k string, kv any, v []any) bool {
	count := func(key string, def int64) *big.Rat {
		if n, ok := ratOf(s[key]); ok {
			return n
		}
		return big.NewRat(def, 1)
	}
	length := big.NewRat(int64(len(v)), 1)
	switch k {
	case "items":
		for _, item := range v {
			if !matches(kv, item) {
				return false
			}
		}
	case "minItems":
		return length.Cmp(count(k, 0)) >= 0
	case "maxItems":
		return length.Cmp(count(k, 0)) <= 0
	case "uniqueItems":
		if kv.(bool) {
			seen := map[string]bool{}
			for _, item := range v {
				c, err := canonical(item)
				if err != nil || seen[c] {
					return false
				}
				seen[c] = true
			}
		}
	case "contains":
		n := int64(0)
		for _, item := range v {
			if matches(kv, item) {
				n++
			}
		}
		found := big.NewRat(n, 1)
		if found.Cmp(count("minContains", 1)) < 0 {
			return false
		}
		if _, ok := s["maxContains"]; ok && found.Cmp(count("maxContains", 0)) > 0 {
			return false
		}
	}
	return true
}

func isType(v any, name string) bool {
	switch name {
	case "null":
		return v == nil
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(json.Number)
		return ok
	case "integer":
		n, ok := ratOf(v)
		return ok && n.IsInt()
	}
	return false
}

// ratOf returns the exact value of a JSON number.
func ratOf(v any) (*big.Rat, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, false
	}
	r, ok := new(big.Rat).SetString(string(n))
	return r, ok
}

// canonical returns the RFC 8785 form of JSON data: two values are equal as
// JSON data (draft 8.4) exactly when their canonical forms are.
func canonical(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	c, err := jcs.Canonicalize(b)
	if err != nil {
		return "", err
	}
	return string(c), nil
}

func jsonEqual(a, b any) bool {
	ca, err := canonical(a)
	if err != nil {
		return false
	}
	cb, err := canonical(b)
	return err == nil && ca == cb
}
