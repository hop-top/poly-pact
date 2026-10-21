package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/strictjson"
)

// bindingVector is a vectors/binding file (spec/v1.0/fixtures/vectors/README.md).
type bindingVector struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Config      struct {
		Origin          string   `json:"origin"`
		HeaderAllowlist []string `json:"header_allowlist"`
		NormalizationID string   `json:"normalization_id"`
		MappingVersion  string   `json:"mapping_version"`
		EnvironmentID   string   `json:"environment_id"`
	} `json:"config"`
	Request struct {
		Method        string `json:"method"`
		RawRequestURI string `json:"raw_request_uri"`
		Headers       []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"headers"`
		BodyB64 string `json:"body_b64"`
	} `json:"request"`
	OperationID string   `json:"operation_id"`
	PrincipalID string   `json:"principal_id"`
	Action      string   `json:"action"`
	Resources   []string `json:"resources"`
	Expect      struct {
		OperationContext json.RawMessage `json:"operation_context,omitzero"`
		RejectReason     string          `json:"reject_reason,omitzero"`
		ConfigError      *bool           `json:"config_error,omitzero"`
	} `json:"expect"`
	ExpectOperationDigest *core.Digest `json:"expect_operation_digest"`
}

var bindingMembers = []string{
	"action", "config", "description", "expect", "expect_operation_digest", "id",
	"operation_id", "principal_id", "request", "resources",
}

// bindingMaxBody is the body limit the harness configures; no vector tests
// a limit.
const bindingMaxBody = 1 << 20

// runBindingEntry runs a binding vector through core/binding twice: with
// the request written as HTTP/1.1 text and parsed by the net/http server
// parser, and with the request built field line by field line, as a program
// would, so that the normalization of core/binding runs and not only that of
// the parser. Each is bound with FromRequest; the caller's operation_id and
// environment_id complete the context, whose object_digest is compared.
func runBindingEntry(root string, e vectorEntry) error {
	if err := singleFile(e); err != nil {
		return err
	}
	var v bindingVector
	raw, err := readFixtureJSON(root, e.Path, &v)
	if err != nil {
		return err
	}
	if err := checkMembers(raw, bindingMembers...); err != nil {
		return err
	}
	if v.ID != e.ID {
		return fmt.Errorf("vector id %q, manifest id %q", v.ID, e.ID)
	}
	accept := len(v.Expect.OperationContext) > 0
	configError := v.Expect.ConfigError != nil
	switch {
	case accept && v.Expect.RejectReason == "" && !configError && e.outcome() == "ACCEPTED" && v.ExpectOperationDigest != nil:
	case !accept && v.Expect.RejectReason == "INVALID_MESSAGE" && !configError && e.outcome() == "REJECTED" && v.ExpectOperationDigest == nil:
	case !accept && v.Expect.RejectReason == "" && configError && *v.Expect.ConfigError && e.outcome() == "REJECTED" && v.ExpectOperationDigest == nil:
	default:
		return fmt.Errorf("expect, expect_operation_digest and outcome %q do not agree", e.outcome())
	}
	if configError {
		return checkConfigError(v)
	}

	body, err := base64.StdEncoding.DecodeString(v.Request.BodyB64)
	if err != nil {
		return fmt.Errorf("body_b64: %w", err)
	}
	// The server parser refuses some requests itself, as it does a second
	// Host field line (RFC 9112 3.2); that is allowed only for a vector that
	// expects a refusal, and the built request still reaches the binding.
	parsed, err := parsedBindingRequest(v, body)
	switch {
	case err != nil && accept:
		return err
	case err == nil:
		if err := bindOne(v, parsed, accept); err != nil {
			return fmt.Errorf("parsed request: %w", err)
		}
	}
	if err := bindOne(v, builtBindingRequest(v, body), accept); err != nil {
		return fmt.Errorf("built request: %w", err)
	}
	return nil
}

// checkConfigError requires the vector's configuration to fail
// Config.Validate with ErrInvalidConfig, never with a refused request
// (INVALID_MESSAGE).
func checkConfigError(v bindingVector) error {
	err := bindingConfig(v).Validate()
	switch {
	case err == nil:
		return fmt.Errorf("configuration accepted, want a configuration error")
	case errors.Is(err, binding.ErrInvalidRequest) || !errors.Is(err, binding.ErrInvalidConfig):
		return fmt.Errorf("got %v, want a configuration error (ErrInvalidConfig)", err)
	}
	return nil
}

func bindingConfig(v bindingVector) binding.Config {
	return binding.Config{
		Origin:                v.Config.Origin,
		HeaderAllowlist:       v.Config.HeaderAllowlist,
		HeaderNormalizationID: v.Config.NormalizationID,
		MappingVersion:        v.Config.MappingVersion,
		MaxBody:               bindingMaxBody,
	}
}

// bindOne binds r under the vector's configuration and compares the result
// with the vector's expectation.
func bindOne(v bindingVector, r *http.Request, accept bool) error {
	op, err := binding.FromRequest(bindingConfig(v), r, v.PrincipalID, v.Action, v.Resources)
	if !accept {
		if !errors.Is(err, binding.ErrInvalidRequest) {
			return fmt.Errorf("got %v, want a refusal (INVALID_MESSAGE)", errOrMapped(err))
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("refused (%v), want an operation context", err)
	}
	op.OperationID = v.OperationID
	op.EnvironmentID = v.Config.EnvironmentID
	got, err := json.Marshal(op)
	if err != nil {
		return err
	}
	if err := sameCanonical(got, v.Expect.OperationContext); err != nil {
		return fmt.Errorf("operation context: %w", err)
	}
	d, err := digest.ObjectDigest(op)
	if err != nil {
		return err
	}
	if d != *v.ExpectOperationDigest {
		return fmt.Errorf("object_digest %s, want %s", d, *v.ExpectOperationDigest)
	}
	return nil
}

func errOrMapped(err error) string {
	if err == nil {
		return "an operation context"
	}
	return err.Error()
}

// parsedBindingRequest writes the vector's request as HTTP/1.1 text, each
// header as "name: value", and parses it as a net/http server does.
func parsedBindingRequest(v bindingVector, body []byte) (*http.Request, error) {
	var raw bytes.Buffer
	raw.WriteString(v.Request.Method + " " + v.Request.RawRequestURI + " HTTP/1.1\r\n")
	for _, h := range v.Request.Headers {
		raw.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	raw.WriteString("\r\n")
	raw.Write(body)
	r, err := http.ReadRequest(bufio.NewReader(&raw))
	if err != nil {
		return nil, fmt.Errorf("parse the request: %w", err)
	}
	return r, nil
}

// builtBindingRequest builds the vector's request as a program would: the
// request-target as RequestURI, and each field line added under its name
// with its value unchanged. A Host line also sets Request.Host.
func builtBindingRequest(v bindingVector, body []byte) *http.Request {
	u, err := url.ParseRequestURI(v.Request.RawRequestURI)
	if err != nil {
		u = &url.URL{}
	}
	r := &http.Request{
		Method:        v.Request.Method,
		RequestURI:    v.Request.RawRequestURI,
		URL:           u,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	for _, h := range v.Request.Headers {
		if asciiEqualFold(h.Name, "host") {
			r.Host = h.Value
		}
		r.Header.Add(h.Name, h.Value)
	}
	return r
}

// asciiEqualFold reports whether s and t are equal when the ASCII letters
// A-Z and a-z are compared without regard to case; every other byte must
// match exactly. Field names are ASCII tokens compared that way (RFC 9110
// 5.1), and strings.EqualFold would also fold U+017F LATIN SMALL LETTER
// LONG S to "s". The library's internal/ascii is out of reach of this
// module.
func asciiEqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		a, b := s[i], t[i]
		if 'A' <= a && a <= 'Z' {
			a += 'a' - 'A'
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// sameCanonical compares two JSON texts by their RFC 8785 form.
func sameCanonical(got, want []byte) error {
	g, err := jcs.Canonicalize(got)
	if err != nil {
		return err
	}
	w, err := jcs.Canonicalize(want)
	if err != nil {
		return err
	}
	if !bytes.Equal(g, w) {
		return fmt.Errorf("got %s, want %s", g, w)
	}
	return nil
}

// digestVector is one element of a vectors/digest file.
type digestVector struct {
	ID             string          `json:"id"`
	InputKind      string          `json:"input_kind"`
	Input          json.RawMessage `json:"input"`
	ExpectedDigest core.Digest     `json:"expected_digest"`
	SpecDefect     bool            `json:"spec_defect"`
	AppendixValue  *string         `json:"appendix_value"`
}

var digestMembers = []string{"appendix_value", "expected_digest", "id", "input", "input_kind", "spec_defect"}

// runDigestEntry runs a vectors/digest file through core/digest: every
// vector's digest equals expected_digest, and a value the draft prints
// equals it too unless the vector marks a spec defect, which is a SKIP.
func runDigestEntry(root string, e vectorEntry) error {
	if err := singleFile(e); err != nil {
		return err
	}
	var vs []digestVector
	if _, err := readFixtureJSON(root, e.Path, &vs); err != nil {
		return err
	}
	var raws []json.RawMessage
	if _, err := readFixtureJSON(root, e.Path, &raws); err != nil {
		return err
	}
	if len(vs) == 0 {
		return fmt.Errorf("%s has no vectors", e.Path)
	}
	var defects []string
	var values []specDefect
	seen := map[string]bool{}
	for i, v := range vs {
		if err := checkMembers(raws[i], digestMembers...); err != nil {
			return fmt.Errorf("vector %d: %w", i, err)
		}
		if v.ID == "" || seen[v.ID] {
			return fmt.Errorf("vector %d: id %q is empty or repeated", i, v.ID)
		}
		seen[v.ID] = true
		got, err := computeDigest(v)
		if err != nil {
			return fmt.Errorf("%s: %w", v.ID, err)
		}
		if got != v.ExpectedDigest {
			return fmt.Errorf("%s: digest %s, want expected_digest %s", v.ID, got, v.ExpectedDigest)
		}
		switch {
		case v.AppendixValue == nil && v.SpecDefect:
			return fmt.Errorf("%s: spec_defect is set but appendix_value is null", v.ID)
		case v.AppendixValue == nil:
		case *v.AppendixValue == string(got) && v.SpecDefect:
			return fmt.Errorf("%s: spec_defect is set but appendix_value matches", v.ID)
		case *v.AppendixValue == string(got):
		case v.SpecDefect:
			defects = append(defects, fmt.Sprintf("%s: the draft states %s, computed %s", v.ID, *v.AppendixValue, got))
			values = append(values, specDefect{Vector: v.ID, AppendixValue: *v.AppendixValue, ExpectedDigest: string(got)})
		default:
			return fmt.Errorf("%s: appendix_value %s differs from %s and spec_defect is not set", v.ID, *v.AppendixValue, got)
		}
	}
	if len(defects) > 0 {
		return skipped{reason: reasonSpecDefect, msg: "spec defect: " + strings.Join(defects, "; "), defects: values}
	}
	return nil
}

func computeDigest(v digestVector) (core.Digest, error) {
	switch v.InputKind {
	case "object":
		return digest.ObjectDigest(v.Input)
	case "artifact":
		var s string
		if err := strictjson.Unmarshal(v.Input, strictjson.Limits{}, &s); err != nil {
			return "", fmt.Errorf("input is not a string: %w", err)
		}
		return digest.ArtifactDigest(s)
	case "bytes":
		var s string
		if err := strictjson.Unmarshal(v.Input, strictjson.Limits{}, &s); err != nil {
			return "", fmt.Errorf("input is not a string: %w", err)
		}
		b, err := hex.DecodeString(s)
		if err != nil || s != strings.ToLower(s) {
			return "", fmt.Errorf("input %q is not lowercase hex", s)
		}
		return digest.BytesDigest(b), nil
	}
	return "", fmt.Errorf("input_kind %q is not object, artifact or bytes", v.InputKind)
}

// runJCSEntry runs a vectors/jcs entry through core/jcs: an input and output
// pair, whose canonical form is the output byte for byte, or the number list,
// each IEEE 754 value written as an exponent literal and canonicalized.
func runJCSEntry(root string, e vectorEntry) error {
	if e.Expected == nil {
		return fmt.Errorf("expected is null")
	}
	if e.Path == *e.Expected {
		return runJCSNumbers(root, e.Path)
	}
	in, err := readFixture(root, e.Path)
	if err != nil {
		return err
	}
	want, err := readFixture(root, *e.Expected)
	if err != nil {
		return err
	}
	got, err := jcs.Canonicalize(in)
	if err != nil {
		return fmt.Errorf("canonicalize the input: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("canonical form %q, want %q", got, want)
	}
	if again, err := jcs.Canonicalize(want); err != nil || !bytes.Equal(again, want) {
		return fmt.Errorf("the expected output is not canonical")
	}
	return nil
}

func runJCSNumbers(root, rel string) error {
	var vs []struct {
		IEEE754Hex string `json:"ieee754_hex"`
		Expected   string `json:"expected"`
	}
	if _, err := readFixtureJSON(root, rel, &vs); err != nil {
		return err
	}
	if len(vs) == 0 {
		return fmt.Errorf("%s has no numbers", rel)
	}
	for i, v := range vs {
		bits, err := strconv.ParseUint(v.IEEE754Hex, 16, 64)
		if err != nil || len(v.IEEE754Hex) != 16 || v.Expected == "" {
			return fmt.Errorf("number %d is malformed", i)
		}
		literal := strconv.FormatFloat(math.Float64frombits(bits), 'e', -1, 64)
		got, err := jcs.Canonicalize([]byte(literal))
		if err != nil || string(got) != v.Expected {
			return fmt.Errorf("%s: canonical form %q (%v), want %q", v.IEEE754Hex, got, err, v.Expected)
		}
	}
	return nil
}

// runStrictJSONEntry runs a vectors/strictjson vector through
// core/strictjson: the input is decoded as an OperationContext and accepted
// or rejected as expect says.
func runStrictJSONEntry(root string, e vectorEntry) error {
	if err := singleFile(e); err != nil {
		return err
	}
	var v struct {
		ID        string `json:"id"`
		InputText string `json:"input_text,omitzero"`
		InputB64  string `json:"input_b64,omitzero"`
		Expect    string `json:"expect"`
		Reason    string `json:"reason"`
	}
	if _, err := readFixtureJSON(root, e.Path, &v); err != nil {
		return err
	}
	if v.ID != e.ID || v.Reason == "" {
		return fmt.Errorf("vector id %q (manifest %q) or empty reason", v.ID, e.ID)
	}
	var input []byte
	switch {
	case v.InputText != "" && v.InputB64 != "":
		return fmt.Errorf("both input_text and input_b64 are set")
	case v.InputB64 != "":
		b, err := base64.StdEncoding.DecodeString(v.InputB64)
		if err != nil {
			return fmt.Errorf("input_b64: %w", err)
		}
		input = b
	case v.InputText != "":
		input = []byte(v.InputText)
	default:
		return fmt.Errorf("no input")
	}
	want := map[string]string{"accept": "ACCEPTED", "reject": "REJECTED"}[v.Expect]
	if want == "" || want != e.outcome() {
		return fmt.Errorf("expect %q does not agree with outcome %q", v.Expect, e.outcome())
	}
	var op core.OperationContext
	err := strictjson.Unmarshal(input, strictjson.Limits{}, &op)
	switch {
	case v.Expect == "accept" && err != nil:
		return fmt.Errorf("rejected (%v), want accept", err)
	case v.Expect == "reject" && err == nil:
		return fmt.Errorf("accepted, want reject")
	}
	return nil
}
