package core

import (
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"hop.top/pact-go/core/strictjson"
)

// limitFields names every Limits field with its Section 20.1 metadata key and
// baseline, written out here from the draft table and not derived from Defaults.
var limitFields = []struct {
	key      string
	baseline int
	field    func(*Limits) *int
}{
	{"max_presentation_bytes", 262144, func(l *Limits) *int { return &l.PresentationBytes }},
	{"max_artifact_payload_bytes", 32768, func(l *Limits) *int { return &l.ArtifactPayloadBytes }},
	{"max_profile_bytes", 32768, func(l *Limits) *int { return &l.ProfileBytes }},
	{"max_evidence_artifacts", 32, func(l *Limits) *int { return &l.EvidenceArtifacts }},
	{"max_field_rules", 128, func(l *Limits) *int { return &l.FieldRules }},
	{"max_json_depth", 16, func(l *Limits) *int { return &l.Depth }},
	{"max_resources", 256, func(l *Limits) *int { return &l.Resources }},
	{"max_description_bytes", 4096, func(l *Limits) *int { return &l.DescriptionBytes }},
}

func TestDefaults(t *testing.T) {
	d := Defaults()
	for _, f := range limitFields {
		if got := *f.field(&d); got != f.baseline {
			t.Errorf("Defaults().%s = %d, want %d", f.key, got, f.baseline)
		}
	}
	if err := d.Check(); err != nil {
		t.Errorf("Defaults().Check() = %v, want nil", err)
	}
}

// TestDefaultsMatchTheDraft reads the second table of Section 20.1, so a change
// to a baseline value in the draft fails here.
func TestDefaultsMatchTheDraft(t *testing.T) {
	b, err := os.ReadFile(draftPath)
	if err != nil {
		t.Fatalf("read draft: %v", err)
	}
	d := Defaults()
	for _, f := range limitFields {
		m := regexp.MustCompile("(?m)^\\| `" + f.key + "` \\| (\\d+) \\|").FindSubmatch(b)
		if m == nil {
			t.Errorf("draft 20.1 has no row for %s", f.key)
			continue
		}
		want, _ := strconv.Atoi(string(m[1]))
		if got := *f.field(&d); got != want {
			t.Errorf("Defaults().%s = %d, draft 20.1 says %d", f.key, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	for _, f := range limitFields {
		t.Run(f.key, func(t *testing.T) {
			for _, v := range []int{1, f.baseline - 1, f.baseline} {
				l := Defaults()
				*f.field(&l) = v
				if err := l.Check(); err != nil {
					t.Errorf("%s = %d: %v, want a tighter or equal value to pass", f.key, v, err)
				}
			}
			for _, v := range []int{f.baseline + 1, 2 * f.baseline, 0, -1} {
				l := Defaults()
				*f.field(&l) = v
				err := l.Check()
				if !errors.Is(err, ErrLimitsInvalid) {
					t.Errorf("%s = %d: got %v, want ErrLimitsInvalid", f.key, v, err)
					continue
				}
				var le *LimitError
				if !errors.As(err, &le) || le.Key != f.key {
					t.Errorf("%s = %d: error %v does not name the key", f.key, v, err)
				}
			}
		})
	}
	if err := (Limits{}).Check(); !errors.Is(err, ErrLimitsInvalid) {
		t.Errorf("zero Limits: got %v, want ErrLimitsInvalid", err)
	}
}

// boundary describes how to build an object that holds exactly n units of one
// limited quantity and validate it.
type boundary struct {
	key string
	run func(l Limits, n int) error
}

var boundaries = []boundary{
	{"max_presentation_bytes", func(l Limits, n int) error { return l.ValidatePresentation(&Presentation{}, n) }},
	{"max_artifact_payload_bytes", func(l Limits, n int) error { return l.ValidateArtifactSize(n) }},
	{"max_profile_bytes", func(l Limits, n int) error { return l.ValidateProfileSize(n) }},
	{"max_evidence_artifacts", func(l Limits, n int) error {
		return l.ValidatePresentation(&Presentation{Evidence: make([]string, n)}, 0)
	}},
	{"max_field_rules", func(l Limits, n int) error {
		return l.ValidateContract(&RequirementContract{FieldRules: make([]FieldRule, n)})
	}},
	{"max_resources", func(l Limits, n int) error {
		return l.ValidateOperation(&OperationContext{Resources: make([]string, n)})
	}},
	{"max_resources", func(l Limits, n int) error {
		return l.ValidatePresentation(&Presentation{Operation: OperationContext{Resources: make([]string, n)}}, 0)
	}},
	{"max_description_bytes", func(l Limits, n int) error {
		return l.ValidateIntent(&Intent{Description: strings.Repeat("a", n)})
	}},
	{"max_description_bytes", func(l Limits, n int) error {
		return l.ValidatePresentation(&Presentation{Intent: Intent{Description: strings.Repeat("a", n)}}, 0)
	}},
}

func baselineOf(t *testing.T, key string) (baseline int, field func(*Limits) *int) {
	t.Helper()
	for _, f := range limitFields {
		if f.key == key {
			return f.baseline, f.field
		}
	}
	t.Fatalf("no limit field for key %q", key)
	return 0, nil
}

func TestBoundaries(t *testing.T) {
	for i, b := range boundaries {
		t.Run(b.key+"/"+strconv.Itoa(i), func(t *testing.T) {
			baseline, field := baselineOf(t, b.key)
			d := Defaults()

			// Equal passes, plus one fails.
			if err := b.run(d, baseline); err != nil {
				t.Fatalf("exactly %d: %v, want nil", baseline, err)
			}
			if err := b.run(d, 0); err != nil {
				t.Fatalf("empty: %v, want nil", err)
			}
			err := b.run(d, baseline+1)
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("%d: got %v, want ErrLimitExceeded", baseline+1, err)
			}
			var le *LimitError
			if !errors.As(err, &le) {
				t.Fatalf("%d: %v is not a *LimitError", baseline+1, err)
			}
			if le.Key != b.key || le.Max != baseline || le.Got != baseline+1 {
				t.Fatalf("LimitError = {Key:%q Max:%d Got:%d}, want {%q %d %d}", le.Key, le.Max, le.Got, b.key, baseline, baseline+1)
			}
			if !strings.Contains(err.Error(), b.key) {
				t.Errorf("message %q does not name %s", err, b.key)
			}

			// A tighter configured limit moves the boundary down.
			tight := Defaults()
			*field(&tight) = baseline - 1
			if err := b.run(tight, baseline-1); err != nil {
				t.Fatalf("tightened, exactly %d: %v, want nil", baseline-1, err)
			}
			if err := b.run(tight, baseline); !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("tightened, %d: got %v, want ErrLimitExceeded", baseline, err)
			}
		})
	}
}

func TestEachLimitIsIndependent(t *testing.T) {
	// Lowering one limit must not affect the others.
	for _, f := range limitFields {
		l := Defaults()
		*f.field(&l) = 1
		for _, b := range boundaries {
			if b.key == f.key {
				continue
			}
			baseline, _ := baselineOf(t, b.key)
			if err := b.run(l, baseline); err != nil {
				t.Errorf("limiting %s to 1 broke %s at %d: %v", f.key, b.key, baseline, err)
			}
		}
	}
}

func TestDescriptionLimitCountsBytesNotCharacters(t *testing.T) {
	d := Defaults()
	tests := []struct {
		name string
		desc string
		ok   bool
	}{
		{"2048 two-byte characters are 4096 bytes", strings.Repeat("é", 2048), true},
		{"2049 two-byte characters are 4098 bytes", strings.Repeat("é", 2049), false},
		{"1024 four-byte characters are 4096 bytes", strings.Repeat("😀", 1024), true},
		{"1025 four-byte characters are 4100 bytes", strings.Repeat("😀", 1025), false},
		{"4095 ASCII plus one two-byte character is 4097 bytes", strings.Repeat("a", 4095) + "é", false},
	}
	for _, tc := range tests {
		err := d.ValidateIntent(&Intent{Description: tc.desc})
		if tc.ok != (err == nil) {
			t.Errorf("%s: got %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestValidateRejectsNil(t *testing.T) {
	d := Defaults()
	for name, err := range map[string]error{
		"presentation": d.ValidatePresentation(nil, 0),
		"contract":     d.ValidateContract(nil),
		"operation":    d.ValidateOperation(nil),
		"intent":       d.ValidateIntent(nil),
	} {
		if !errors.Is(err, ErrNilObject) {
			t.Errorf("%s: got %v, want ErrNilObject", name, err)
		}
	}
}

func TestValidateOnTheZeroLimitsFailsClosed(t *testing.T) {
	var zero Limits
	if err := zero.ValidateContract(&RequirementContract{FieldRules: make([]FieldRule, 1)}); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("zero Limits accepted a field rule: %v", err)
	}
	if err := zero.ValidateArtifactSize(1); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("zero Limits accepted a payload: %v", err)
	}
}

// docOfSize returns a JSON object of exactly n bytes.
func docOfSize(n int) []byte {
	const overhead = len(`{"a":""}`)
	return []byte(`{"a":"` + strings.Repeat("x", n-overhead) + `"}`)
}

// docOfDepth returns a JSON document whose nesting depth is exactly d.
func docOfDepth(d int) []byte {
	return []byte(`{"a":` + strings.Repeat("[", d-1) + strings.Repeat("]", d-1) + `}`)
}

func TestStrictJSONLimits(t *testing.T) {
	forms := []struct {
		name     string
		lim      func(Limits) strictjson.Limits
		key      string
		baseline int
	}{
		{"presentation", Limits.PresentationJSON, "max_presentation_bytes", 262144},
		{"artifact", Limits.ArtifactJSON, "max_artifact_payload_bytes", 32768},
		{"profile", Limits.ProfileJSON, "max_profile_bytes", 32768},
	}
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			var o Object
			lim := f.lim(Defaults())
			if err := strictjson.Unmarshal(docOfSize(f.baseline), lim, &o); err != nil {
				t.Fatalf("%d bytes: %v, want nil", f.baseline, err)
			}
			if err := strictjson.Unmarshal(docOfSize(f.baseline+1), lim, &o); !errors.Is(err, strictjson.ErrSize) {
				t.Fatalf("%d bytes: got %v, want ErrSize", f.baseline+1, err)
			}

			_, field := baselineOf(t, f.key)
			tight := Defaults()
			*field(&tight) = 1000
			if err := strictjson.Unmarshal(docOfSize(1000), f.lim(tight), &o); err != nil {
				t.Fatalf("tightened, 1000 bytes: %v, want nil", err)
			}
			if err := strictjson.Unmarshal(docOfSize(1001), f.lim(tight), &o); !errors.Is(err, strictjson.ErrSize) {
				t.Fatalf("tightened, 1001 bytes: got %v, want ErrSize", err)
			}
		})
	}
}

func TestStrictJSONDepthComesFromLimitsDepth(t *testing.T) {
	forms := map[string]func(Limits) strictjson.Limits{
		"presentation": Limits.PresentationJSON,
		"artifact":     Limits.ArtifactJSON,
		"profile":      Limits.ProfileJSON,
	}
	for name, lim := range forms {
		t.Run(name, func(t *testing.T) {
			var o Object
			if err := strictjson.Unmarshal(docOfDepth(16), lim(Defaults()), &o); err != nil {
				t.Fatalf("depth 16: %v, want nil", err)
			}
			if err := strictjson.Unmarshal(docOfDepth(17), lim(Defaults()), &o); !errors.Is(err, strictjson.ErrDepth) {
				t.Fatalf("depth 17: got %v, want ErrDepth", err)
			}

			tight := Defaults()
			tight.Depth = 3
			if err := strictjson.Unmarshal(docOfDepth(3), lim(tight), &o); err != nil {
				t.Fatalf("Depth 3, depth 3: %v, want nil", err)
			}
			if err := strictjson.Unmarshal(docOfDepth(4), lim(tight), &o); !errors.Is(err, strictjson.ErrDepth) {
				t.Fatalf("Depth 3, depth 4: got %v, want ErrDepth", err)
			}
		})
	}
}

// TestStrictJSONDefaultsAgree keeps the decoder's own defaults, used when a
// caller passes a zero strictjson.Limits, equal to the baseline.
func TestStrictJSONDefaultsAgree(t *testing.T) {
	d := Defaults()
	if strictjson.DefaultMaxDepth != d.Depth {
		t.Errorf("strictjson.DefaultMaxDepth = %d, baseline Depth = %d", strictjson.DefaultMaxDepth, d.Depth)
	}
	if strictjson.DefaultMaxBytes != d.PresentationBytes {
		t.Errorf("strictjson.DefaultMaxBytes = %d, baseline PresentationBytes = %d", strictjson.DefaultMaxBytes, d.PresentationBytes)
	}
}
