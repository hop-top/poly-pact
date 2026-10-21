package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string // substrings that must appear on stdout
		wantStderr []string // substrings that must appear on stderr
		stdoutLine bool     // stdout must be exactly one line
		stdoutNone bool     // stdout must be empty
		stderrNone bool     // stderr must be empty
	}{
		{
			name:       "no args",
			args:       nil,
			wantCode:   2,
			wantStderr: []string{"USAGE: missing command", "pactconf --help", "vectors", "profile"},
			stdoutNone: true,
		},
		{
			name:       "empty args",
			args:       []string{},
			wantCode:   2,
			wantStderr: []string{"USAGE: missing command", "pactconf --help"},
			stdoutNone: true,
		},
		{
			name:       "unknown subcommand",
			args:       []string{"bogus"},
			wantCode:   2,
			wantStderr: []string{`unknown command "bogus"`, "pactconf --help"},
			stdoutNone: true,
		},
		{
			name:       "vectors without subcommand",
			args:       []string{"vectors"},
			wantCode:   2,
			wantStderr: []string{`missing command for "pactconf vectors"`, "verify"},
			stdoutNone: true,
		},
		{
			name:       "profile without subcommand",
			args:       []string{"profile"},
			wantCode:   2,
			wantStderr: []string{`missing command for "pactconf profile"`, "validate"},
			stdoutNone: true,
		},
		{
			name:       "short help",
			args:       []string{"-h"},
			wantCode:   0,
			wantStdout: []string{"pactconf [command]", "vectors", "profile"},
			stderrNone: true,
		},
		{
			name:       "long help",
			args:       []string{"--help"},
			wantCode:   0,
			wantStdout: []string{"pactconf [command]", "vectors", "profile"},
			stderrNone: true,
		},
		{
			name:       "single-dash help",
			args:       []string{"-help"},
			wantCode:   0,
			wantStdout: []string{"pactconf [command]", "vectors", "profile"},
			stderrNone: true,
		},
		{
			name:       "version",
			args:       []string{"--version"},
			wantCode:   0,
			wantStdout: []string{"pactconf v"},
			stdoutLine: true,
			stderrNone: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			for _, s := range tt.wantStdout {
				if !strings.Contains(stdout.String(), s) {
					t.Errorf("stdout %q missing %q", stdout.String(), s)
				}
			}
			for _, s := range tt.wantStderr {
				if !strings.Contains(stderr.String(), s) {
					t.Errorf("stderr %q missing %q", stderr.String(), s)
				}
			}
			if tt.stdoutNone && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			if tt.stderrNone && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
			if tt.stdoutLine {
				out := stdout.String()
				if !strings.HasSuffix(out, "\n") || strings.Count(out, "\n") != 1 {
					t.Errorf("stdout = %q, want exactly one newline-terminated line", out)
				}
			}
		})
	}
}

// TestKitValidate: the command tree passes the kit validation that Execute
// runs before every command (annotations, help text, shape).
func TestKitValidate(t *testing.T) {
	if err := newCLI().Root.Validate(); err != nil {
		t.Fatal(err)
	}
}
