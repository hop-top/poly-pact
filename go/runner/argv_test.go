package runner

import (
	"slices"
	"testing"
)

func TestBuildArgv(t *testing.T) {
	subs := map[string]string{"dir": "/f/admission/valid", "state": "/w/state"}
	tests := []struct {
		name, tmpl string
		want       []string
	}{
		{"evaluate shape", "tool evaluate {dir}", []string{"tool", "evaluate", "/f/admission/valid"}},
		{"outcomes shape", "tool outcomes {dir} {state}", []string{"tool", "outcomes", "/f/admission/valid", "/w/state"}},
		{"token inside an argument", "tool --case={dir} --db={state}", []string{"tool", "--case=/f/admission/valid", "--db=/w/state"}},
		{"repeated token", "tool {dir} {dir}", []string{"tool", "/f/admission/valid", "/f/admission/valid"}},
		{"no tokens", "tool version", []string{"tool", "version"}},
		{"runs of white space", " tool \t learning   {dir}  {state} ", []string{"tool", "learning", "/f/admission/valid", "/w/state"}},
		{"no shell: quotes and operators are literal", `tool "a b" | x;`, []string{"tool", `"a`, `b"`, "|", "x;"}},
		{"unknown token kept", "tool {db}", []string{"tool", "{db}"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildArgv(tt.tmpl, subs); !slices.Equal(got, tt.want) {
				t.Errorf("BuildArgv(%q) = %q, want %q", tt.tmpl, got, tt.want)
			}
		})
	}
}

// A value is substituted after the split, so it stays one argument even
// with white space in it, and a token in a value is not expanded again.
func TestBuildArgvValues(t *testing.T) {
	got := BuildArgv("tool {dir} {state}", map[string]string{"dir": "/a b/{state}", "state": "/s"})
	if want := []string{"tool", "/a b/{state}", "/s"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildArgvBlank(t *testing.T) {
	for _, tmpl := range []string{"", "  \t "} {
		if got := BuildArgv(tmpl, nil); got != nil {
			t.Errorf("BuildArgv(%q) = %q, want nil", tmpl, got)
		}
	}
}
