package binding_test

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/binding"
	"hop.top/pact-go/core/digest"
	"hop.top/pact-go/core/jcs"
	"hop.top/pact-go/core/strictjson"
)

// fixturesRoot is spec/v1.0/fixtures relative to this package directory.
var fixturesRoot = filepath.Join("..", "..", "..", "spec", "v1.0", "fixtures")

const vectorPrefix = "vectors/binding/"

type manifestEntry struct {
	ID                 string   `json:"id"`
	Kind               string   `json:"kind"`
	Scope              string   `json:"scope"`
	Path               string   `json:"path"`
	Expected           optional `json:"expected"`
	Outcome            optional `json:"outcome"`
	SpecMapRow         string   `json:"spec_map_row"`
	DraftSection       string   `json:"draft_section"`
	Capabilities       []string `json:"capabilities"`
	ConformanceProfile []string `json:"conformance_profile"`
	Transport          []string `json:"transport"`
	Layer              string   `json:"layer"`
}

// optional is an entry member that is null in key and adapter-asset entries
// (spec/v1.0/fixtures/README.md); null reads as "".
type optional string

func (o *optional) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*o = ""
		return nil
	}
	return json.Unmarshal(b, (*string)(o))
}

type manifest struct {
	ManifestVersion int             `json:"manifest_version"`
	Entries         []manifestEntry `json:"entries"`
}

// bindingVector is one file of spec/v1.0/fixtures/vectors/binding, in the format
// of spec/v1.0/fixtures/vectors/README.md. The strict decode refuses any other
// member.
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

// requiredVectors are the vectors the binding vector set must hold, with the
// outcome each expects.
var requiredVectors = map[string]string{
	"bind-01-appendix-b3":                "ACCEPTED",
	"bind-02-query-order-ab":             "ACCEPTED",
	"bind-02-query-order-ba":             "ACCEPTED",
	"bind-03-space-percent-20":           "ACCEPTED",
	"bind-03-space-plus":                 "ACCEPTED",
	"bind-04-duplicate-key":              "ACCEPTED",
	"bind-05-fragment":                   "REJECTED",
	"bind-06-userinfo":                   "REJECTED",
	"bind-07-content-encoding-gzip":      "REJECTED",
	"bind-08-body-compact":               "ACCEPTED",
	"bind-08-body-spaced":                "ACCEPTED",
	"bind-09-header-plain":               "ACCEPTED",
	"bind-09-header-case-and-whitespace": "ACCEPTED",
	"bind-10-header-not-allowlisted":     "ACCEPTED",
	"bind-11-forwarding-headers":         "ACCEPTED",
	"bind-12-default-port":               "ACCEPTED",
	"bind-13-encoded-unreserved":         "REJECTED",
	"bind-14-encoded-slash-path":         "REJECTED",
	"bind-15-non-ascii-host":             "REJECTED",
	"bind-16-repeated-header":            "ACCEPTED",
	"bind-17-lowercase-hex-path":         "REJECTED",
	"bind-17-lowercase-hex-query":        "REJECTED",
	"bind-18-overlong-utf8":              "REJECTED",
	"bind-18-invalid-utf8-query":         "REJECTED",
	"bind-19-normal-form-query":          "ACCEPTED",
	"bind-20-dot-segment":                "REJECTED",
	"bind-20-dots-in-segment":            "ACCEPTED",
	"bind-21-duplicate-host":             "REJECTED",
	"bind-22-host-allowlisted":           "REJECTED",
	"bind-23-missing-host":               "REJECTED",
	"bind-24-invalid-host":               "REJECTED",
}

// vectorRule pins the rule this package names for each refused vector. The
// files carry only the draft 13.4 code, INVALID_MESSAGE.
var vectorRule = map[string]binding.Rule{
	"bind-05-fragment":              binding.RuleFragment,
	"bind-06-userinfo":              binding.RuleUserinfo,
	"bind-07-content-encoding-gzip": binding.RuleContentEncoding,
	"bind-13-encoded-unreserved":    binding.RuleEncodedUnreserved,
	"bind-14-encoded-slash-path":    binding.RuleEncodedSlash,
	"bind-15-non-ascii-host":        binding.RuleNonASCIIHost,
	"bind-17-lowercase-hex-path":    binding.RuleLowercaseHex,
	"bind-17-lowercase-hex-query":   binding.RuleLowercaseHex,
	"bind-18-overlong-utf8":         binding.RuleInvalidUTF8,
	"bind-18-invalid-utf8-query":    binding.RuleInvalidUTF8,
	"bind-20-dot-segment":           binding.RuleDotSegment,
	"bind-21-duplicate-host":        binding.RuleDuplicateHost,
	"bind-23-missing-host":          binding.RuleMissingHost,
	"bind-24-invalid-host":          binding.RuleInvalidHost,
}

var specMapRow = regexp.MustCompile(`^BIND-[0-9]{2}$`)

func readJSON(t *testing.T, rel string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixturesRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	if err := strictjson.Unmarshal(b, strictjson.Limits{MaxBytes: 1 << 20}, v); err != nil {
		t.Fatalf("strict-parse %s: %v", rel, err)
	}
}

func bindingEntries(t *testing.T) []manifestEntry {
	t.Helper()
	var m manifest
	readJSON(t, "manifest.json", &m)
	if m.ManifestVersion != 1 {
		t.Fatalf("manifest_version = %d, want 1", m.ManifestVersion)
	}
	var out []manifestEntry
	for _, e := range m.Entries {
		if strings.HasPrefix(e.ID, vectorPrefix) {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		t.Fatal("manifest lists no binding vectors")
	}
	return out
}

// TestBindingVectorsListed: every file under vectors/binding is in the
// manifest, every required vector is there with its outcome, and each entry
// has the form the vectors README gives.
func TestBindingVectorsListed(t *testing.T) {
	listed := map[string]bool{}
	for _, e := range bindingEntries(t) {
		stem := strings.TrimPrefix(e.ID, vectorPrefix)
		listed[stem] = true
		if e.Kind != "vector" || e.Scope != "adapter" {
			t.Errorf("%s: kind/scope %q/%q, want vector/adapter", e.ID, e.Kind, e.Scope)
		}
		if e.Path != e.ID+".json" || string(e.Expected) != e.Path {
			t.Errorf("%s: path %q expected %q, want %s.json for both", e.ID, e.Path, e.Expected, e.ID)
		}
		if !specMapRow.MatchString(e.SpecMapRow) || e.DraftSection != "10.2" {
			t.Errorf("%s: spec_map_row/draft_section %q/%q, want BIND-NN/10.2", e.ID, e.SpecMapRow, e.DraftSection)
		}
		if want, ok := requiredVectors[stem]; ok && string(e.Outcome) != want {
			t.Errorf("%s: outcome %q, want %q", e.ID, e.Outcome, want)
		}
	}
	for stem := range requiredVectors {
		if !listed[stem] {
			t.Errorf("required vector %s%s is missing", vectorPrefix, stem)
		}
	}
	files, err := os.ReadDir(filepath.Join(fixturesRoot, filepath.FromSlash(vectorPrefix)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if path.Ext(f.Name()) == ".json" && !listed[strings.TrimSuffix(f.Name(), ".json")] {
			t.Errorf("%s%s is not listed in manifest.json", vectorPrefix, f.Name())
		}
	}
}

// TestBindingVectors runs every binding vector through FromRequest twice:
// with the request parsed by the net/http server parser from its HTTP/1.1
// text, and with the request built field line by field line, so that the
// normalization of this package is exercised and not only that of the
// parser. The parser refuses some requests itself, as it does a second Host
// field line (RFC 9112 3.2); that is allowed only for a vector that expects
// a refusal, and the built request still reaches FromRequest.
func TestBindingVectors(t *testing.T) {
	for _, e := range bindingEntries(t) {
		t.Run(strings.TrimPrefix(e.ID, vectorPrefix), func(t *testing.T) {
			var v bindingVector
			readJSON(t, e.Path, &v)
			if v.ID != e.ID {
				t.Fatalf("vector id %q, manifest id %q", v.ID, e.ID)
			}
			t.Run("parsed", func(t *testing.T) {
				r, err := parsedRequest(t, v)
				if err != nil {
					if len(v.Expect.OperationContext) > 0 {
						t.Fatalf("parse the request: %v", err)
					}
					t.Logf("the parser refused the request: %v", err)
					return
				}
				runBindingVector(t, e, v, r)
			})
			t.Run("built", func(t *testing.T) { runBindingVector(t, e, v, builtRequest(t, v)) })
		})
	}
}

func runBindingVector(t *testing.T, e manifestEntry, v bindingVector, r *http.Request) {
	t.Helper()
	accept := len(v.Expect.OperationContext) > 0
	configError := v.Expect.ConfigError != nil
	switch {
	case accept && v.Expect.RejectReason == "" && !configError && e.Outcome == "ACCEPTED" && v.ExpectOperationDigest != nil:
	case !accept && v.Expect.RejectReason == "INVALID_MESSAGE" && !configError && e.Outcome == "REJECTED" && v.ExpectOperationDigest == nil:
	case !accept && v.Expect.RejectReason == "" && configError && *v.Expect.ConfigError && e.Outcome == "REJECTED" && v.ExpectOperationDigest == nil:
	default:
		t.Fatalf("expect %+v, digest %v and outcome %q do not agree", v.Expect, v.ExpectOperationDigest, e.Outcome)
	}

	cfg := binding.Config{
		Origin:                v.Config.Origin,
		HeaderAllowlist:       v.Config.HeaderAllowlist,
		HeaderNormalizationID: v.Config.NormalizationID,
		MappingVersion:        v.Config.MappingVersion,
		MaxBody:               1 << 20,
	}
	op, err := binding.FromRequest(cfg, r, v.PrincipalID, v.Action, v.Resources)
	if configError {
		// A configuration error, never a refused request (INVALID_MESSAGE).
		for _, err := range []error{cfg.Validate(), err} {
			if !errors.Is(err, binding.ErrInvalidConfig) || errors.Is(err, binding.ErrInvalidRequest) {
				t.Fatalf("got %v, want ErrInvalidConfig", err)
			}
		}
		return
	}
	if !accept {
		var re *binding.RequestError
		if !errors.As(err, &re) || !errors.Is(err, binding.ErrInvalidRequest) {
			t.Fatalf("got %v, want a refused request (INVALID_MESSAGE)", err)
		}
		if want, ok := vectorRule[strings.TrimPrefix(e.ID, vectorPrefix)]; ok && re.Rule != want {
			t.Fatalf("refused under rule %q (%v), want %q", re.Rule, err, want)
		}
		return
	}
	if err != nil {
		t.Fatalf("FromRequest: %v", err)
	}
	op.OperationID = v.OperationID
	op.EnvironmentID = v.Config.EnvironmentID

	got, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	gotC, err := jcs.Canonicalize(got)
	if err != nil {
		t.Fatal(err)
	}
	wantC, err := jcs.Canonicalize(v.Expect.OperationContext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotC, wantC) {
		t.Errorf("operation context\n got %s\nwant %s", gotC, wantC)
	}
	d, err := digest.ObjectDigest(op)
	if err != nil {
		t.Fatal(err)
	}
	if d != *v.ExpectOperationDigest {
		t.Errorf("object_digest %s, want %s", d, *v.ExpectOperationDigest)
	}
}

func vectorBody(t *testing.T, v bindingVector) []byte {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(v.Request.BodyB64)
	if err != nil {
		t.Fatalf("body_b64: %v", err)
	}
	return body
}

// parsedRequest writes the request of v as HTTP/1.1 text, each header as
// "name: value", and parses it as a server would.
func parsedRequest(t *testing.T, v bindingVector) (*http.Request, error) {
	t.Helper()
	body := vectorBody(t, v)
	var raw bytes.Buffer
	raw.WriteString(v.Request.Method + " " + v.Request.RawRequestURI + " HTTP/1.1\r\n")
	for _, h := range v.Request.Headers {
		raw.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	raw.WriteString("\r\n")
	raw.Write(body)
	return http.ReadRequest(bufio.NewReader(&raw))
}

// builtRequest builds the request of v as a program would: the
// request-target as RequestURI, and each field line added under its name
// with its value unchanged. A Host line also sets Request.Host.
func builtRequest(t *testing.T, v bindingVector) *http.Request {
	t.Helper()
	body := vectorBody(t, v)
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
		if strings.EqualFold(h.Name, "host") {
			r.Host = h.Value
		}
		r.Header.Add(h.Name, h.Value)
	}
	return r
}
