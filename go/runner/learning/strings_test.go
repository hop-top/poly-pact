package learning

import (
	"strings"
	"testing"

	"hop.top/pact-go/core"
)

// TestStringLengthsInCharacters: the 1 to 1024 bound of a string member
// counts characters (Unicode code points), as JSON Schema maxLength does
// (Appendix A.3), not bytes: 1024 two-byte characters are within it, 1025
// are not, and so are 1024 and 1025 four-byte ones.
func TestStringLengthsInCharacters(t *testing.T) {
	for _, tc := range []struct {
		name, s string
		ok      bool
	}{
		{"1024 ASCII", strings.Repeat("x", 1024), true},
		{"1025 ASCII", strings.Repeat("x", 1025), false},
		{"1024 two-byte", strings.Repeat("é", 1024), true},
		{"1025 two-byte", strings.Repeat("é", 1025), false},
		{"1024 four-byte", strings.Repeat("😀", 1024), true},
		{"1025 four-byte", strings.Repeat("😀", 1025), false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for member, edit := range map[string]func(*core.LearningPolicy){
				"policy_id":               func(p *core.LearningPolicy) { p.PolicyID = tc.s },
				"base_revision":           func(p *core.LearningPolicy) { p.BaseRevision = tc.s },
				"adaptive_fields control": func(p *core.LearningPolicy) { p.AdaptiveFields[0].ControlID = tc.s },
			} {
				p := basePolicy()
				edit(&p)
				if err := ValidatePolicy(p); (err == nil) != tc.ok {
					t.Errorf("%s: ValidatePolicy = %v, want ok %v", member, err, tc.ok)
				}
			}
		})
	}
}
