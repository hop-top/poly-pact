package cliroot

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"hop.top/kit/go/console/cli"
)

// tree is a command tree with the flag kinds LongFlags tells apart: a
// string flag, a bool flag, a repeatable flag, and three shorthands. With
// -c, pflag reads -check as -c heck.
func tree() *cobra.Command {
	root := &cobra.Command{Use: "tool"}
	root.PersistentFlags().StringP("chdir", "C", "", "")
	root.PersistentFlags().CountP("verbose", "V", "")
	root.PersistentFlags().StringArrayP("config", "c", nil, "")
	leaf := &cobra.Command{Use: "leaf"}
	leaf.Flags().String("spec", "", "")
	leaf.Flags().Bool("check", false, "")
	leaf.Flags().StringArray("fixture", nil, "")
	root.AddCommand(leaf)
	return root
}

func TestLongFlags(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{nil, []string{}},
		{[]string{"leaf", "-spec", "DIR", "f"}, []string{"leaf", "--spec", "DIR", "f"}},
		{[]string{"leaf", "-spec=DIR"}, []string{"leaf", "--spec=DIR"}},
		{[]string{"leaf", "-check", "-spec", "-check"}, []string{"leaf", "--check", "--spec", "-check"}},
		{[]string{"leaf", "-check=false", "case"}, []string{"leaf", "--check=false", "case"}},
		{[]string{"leaf", "--fixture", "-check"}, []string{"leaf", "--fixture", "-check"}},
		{[]string{"leaf", "-fixture", "-spec", "-fixture=-spec"}, []string{"leaf", "--fixture", "-spec", "--fixture=-spec"}},
		{[]string{"leaf", "spec", "check", "-check"}, []string{"leaf", "spec", "check", "--check"}},
		{[]string{"leaf", "-bogus"}, []string{"leaf", "--bogus"}},
		{[]string{"-C", "dir", "-VV", "-Cdir", "-ck=v", "leaf"}, []string{"-C", "dir", "-VV", "-Cdir", "-ck=v", "leaf"}},
		{[]string{"-h", "-help", "-v", "-version"}, []string{"-h", "--help", "-v", "--version"}},
		{[]string{"leaf", "-", "--", "-spec", "-check"}, []string{"leaf", "-", "--", "-spec", "-check"}},
		{[]string{"help"}, []string{"--help"}},
		{[]string{"help", "leaf"}, []string{"help", "leaf"}},
	} {
		if got := LongFlags(tree(), tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("LongFlags(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// testCLI is a root with a group, a leaf under the group that records the
// exit status of its --code flag, and a leaf at the top.
func testCLI() *CLI {
	c := New("tool", "A test tool", "tool tests the root.")
	grp := c.Group(c.Root.Cmd, "grp", "A group", "The group.")
	var code int
	leaf := &cobra.Command{Use: "leaf", Short: "A leaf", Long: "The leaf.", Args: cobra.NoArgs}
	leaf.Flags().IntVar(&code, "code", 0, "exit status")
	c.Leaf(grp, leaf, cli.SideEffectRead, func(cmd *cobra.Command, _ []string) int {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "leaf ran")
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "leaf note")
		return code
	})
	c.Leaf(c.Root.Cmd, &cobra.Command{Use: "top", Short: "A top verb", Long: "The top verb.", Args: cobra.NoArgs},
		cli.SideEffectWriteLocal, func(*cobra.Command, []string) int { return 0 })
	return c
}

func TestValidate(t *testing.T) {
	if err := testCLI().Root.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	for _, tc := range []struct {
		name               string
		args               []string
		code               int
		stdout, stderr     string // substrings
		stdoutNo, stderrNo bool   // the stream must be empty
	}{
		{name: "no command", args: nil, code: 2, stderr: `USAGE: missing command for "tool": one of grp, top`, stdoutNo: true},
		{name: "group without command", args: []string{"grp"}, code: 2, stderr: `USAGE: missing command for "tool grp": one of leaf`, stdoutNo: true},
		{name: "unknown command", args: []string{"nope"}, code: 2, stderr: `unknown command "nope" for "tool"`, stdoutNo: true},
		{name: "unknown command in group", args: []string{"grp", "nope"}, code: 2, stderr: `unknown command "nope" for "tool grp"`, stdoutNo: true},
		{name: "unknown flag", args: []string{"grp", "leaf", "-nope"}, code: 2, stderr: "unknown flag --nope", stdoutNo: true},
		{name: "extra argument", args: []string{"grp", "leaf", "extra"}, code: 2, stderr: "USAGE: ", stdoutNo: true},
		{name: "leaf exit 0", args: []string{"grp", "leaf"}, code: 0, stdout: "leaf ran\n", stderr: "leaf note\n"},
		{name: "leaf exit 1", args: []string{"grp", "leaf", "-code", "1"}, code: 1, stdout: "leaf ran\n", stderr: "leaf note\n"},
		{name: "leaf exit 2", args: []string{"grp", "leaf", "--code=2"}, code: 2, stdout: "leaf ran\n", stderr: "leaf note\n"},
		{name: "top verb", args: []string{"top"}, code: 0, stdoutNo: true, stderrNo: true},
		{name: "help", args: []string{"help"}, code: 0, stdout: "tool tests the root.", stderrNo: true},
		{name: "group help", args: []string{"grp", "-h"}, code: 0, stdout: "The group.", stderrNo: true},
		{name: "version", args: []string{"--version"}, code: 0, stdout: "tool v" + Version() + "\n", stderrNo: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := testCLI().Run(tc.args, &stdout, &stderr)
			if code != tc.code {
				t.Errorf("exit %d, want %d\nstdout %q\nstderr %q", code, tc.code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.stdout) {
				t.Errorf("stdout %q lacks %q", stdout.String(), tc.stdout)
			}
			if !strings.Contains(stderr.String(), tc.stderr) {
				t.Errorf("stderr %q lacks %q", stderr.String(), tc.stderr)
			}
			if tc.stdoutNo && stdout.Len() > 0 {
				t.Errorf("stdout %q, want empty", stdout.String())
			}
			if tc.stderrNo && stderr.Len() > 0 {
				t.Errorf("stderr %q, want empty", stderr.String())
			}
		})
	}
}

func TestVersion(t *testing.T) {
	if v := Version(); v == "" || strings.HasPrefix(v, "v") {
		t.Errorf("Version() = %q, want a version without the v prefix", v)
	}
}
