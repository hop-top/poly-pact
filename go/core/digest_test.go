package core

import (
	"strings"
	"testing"
)

func TestDigestValidate(t *testing.T) {
	valid := []Digest{
		"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
		Digest(strings.Repeat("A", 43)),
		Digest(strings.Repeat("-", 43)),
		Digest(strings.Repeat("_", 43)),
		Digest(strings.Repeat("0", 43)),
	}
	for _, d := range valid {
		if err := d.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v", d, err)
		}
	}

	invalid := map[string]Digest{
		"empty":            "",
		"42 chars":         Digest(strings.Repeat("A", 42)),
		"44 chars":         Digest(strings.Repeat("A", 44)),
		"padded":           Digest(strings.Repeat("A", 42) + "="),
		"standard plus":    Digest(strings.Repeat("A", 42) + "+"),
		"standard slash":   Digest(strings.Repeat("A", 42) + "/"),
		"space":            Digest(strings.Repeat("A", 42) + " "),
		"newline suffix":   Digest(strings.Repeat("A", 43) + "\n"),
		"newline in place": Digest(strings.Repeat("A", 42) + "\n"),
		"non-ascii":        Digest(strings.Repeat("A", 42) + "é"),
		"43 bytes unicode": Digest(strings.Repeat("A", 41) + "é"),
		"nul":              Digest(strings.Repeat("A", 42) + "\x00"),
	}
	for name, d := range invalid {
		if err := d.Validate(); err == nil {
			t.Errorf("%s: Validate(%q) = nil", name, d)
		}
	}
}
