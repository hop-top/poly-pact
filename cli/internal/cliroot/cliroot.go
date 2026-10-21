// Package cliroot builds the command root shared by pactconf, pactc and
// pactfix on the hop.top/kit console framework (hop.top/kit/go/console/cli).
//
// The commands keep the output and exit status contract they had before
// the framework: a leaf writes its own result lines to standard output and
// its own diagnostics to standard error, then records its exit status with
// [CLI.Exit] instead of returning an error, so no framework layer adds a
// second report to either stream. Usage errors (an unknown or missing
// command, an unknown flag, a wrong number of arguments) are kit USAGE
// errors, rendered on standard error, exit status 2.
package cliroot

import (
	"context"
	"errors"
	"io"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"hop.top/kit/go/console/cli"
	"hop.top/kit/go/console/output"
)

// CLI is a kit root and the exit status recorded by the leaf that ran.
type CLI struct {
	// Root is the kit root. Add commands with [CLI.Group] and [CLI.Leaf].
	Root *cli.Root

	exit int
}

// New returns the root of the command name. short is the one-line
// summary; long, the text of name --help.
//
// The kit --format suite and the global --dry-run are disabled: every
// command fixes its own output format (pactc run --json is the one
// alternative), and no command previews its effects through --dry-run.
// A bare name, without a command, is a usage error.
func New(name, short, long string) *CLI {
	c := &CLI{}
	c.Root = cli.New(cli.Config{
		Name:              name,
		Version:           Version(),
		Short:             short,
		Disable:           cli.Disable{Format: true, DryRun: true},
		QuietBootWarnings: true,
	}, cli.WithStatus(cli.StatusConfig{}))
	c.Root.Cmd.Long = long
	c.group(c.Root.Cmd)
	return c
}

// Group adds the command group use under parent. A group runs no work
// of its own: without a command it is a usage error.
func (c *CLI) Group(parent *cobra.Command, use, short, long string) *cobra.Command {
	cmd := &cobra.Command{Use: use, Short: short, Long: long}
	c.group(cmd)
	if parent == c.Root.Cmd {
		// Kit's shape pass reads a runnable depth-1 node as a top-level
		// verb, which needs this annotation.
		cli.SetTopLevelVerb(cmd)
	}
	parent.AddCommand(cmd)
	return cmd
}

// group makes cmd runnable so that a missing command reaches kit's usage
// classification: cobra prints the help of a command without a RunE and
// exits 0. cobra.NoArgs refuses an unknown command.
func (c *CLI) group(cmd *cobra.Command) {
	cmd.Args = cobra.NoArgs
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		var names []string
		for _, sub := range cmd.Commands() {
			if sub.IsAvailableCommand() && sub.Name() != "status" {
				names = append(names, sub.Name())
			}
		}
		e := output.UsageError("missing command for \"" + cmd.CommandPath() + "\": one of " + strings.Join(names, ", "))
		e.SuggestedFix = "run '" + cmd.CommandPath() + " --help' for usage"
		return e
	}
	cli.SetSideEffect(cmd, cli.SideEffectRead)
	cli.SetIdempotency(cmd, cli.IdempotencyYes)
}

// Leaf adds cmd under parent. run does the work and returns the exit
// status, writing to cmd.OutOrStdout and cmd.ErrOrStderr. effect is the
// kit side-effect class of the command; every command here is
// idempotent. A command placed directly under the root is a kit top-level
// verb.
func (c *CLI) Leaf(parent, cmd *cobra.Command, effect cli.SideEffect, run func(cmd *cobra.Command, args []string) int) {
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		c.exit = run(cmd, args)
		return nil
	}
	cli.SetSideEffect(cmd, effect)
	cli.SetIdempotency(cmd, cli.IdempotencyYes)
	if parent == c.Root.Cmd {
		cli.SetTopLevelVerb(cmd)
	}
	parent.AddCommand(cmd)
}

// Run executes the root with args (without the program name), writing to
// stdout and stderr, and returns the process exit status. A CLI runs once:
// the first run adds commands (fang's man) that the kit validation of a
// second run refuses.
func (c *CLI) Run(args []string, stdout, stderr io.Writer) int {
	c.Root.Cmd.SetOut(stdout)
	c.Root.Cmd.SetErr(stderr)
	// A nil argument list makes kit and cobra read os.Args.
	c.Root.SetArgs(append([]string{}, LongFlags(c.Root.Cmd, args)...))
	return c.resolve(c.Root.Execute(context.Background()))
}

// resolve folds the error of an Execute and the status the leaf recorded
// into one exit status: a kit error carries its own (2 for a usage
// error), any other error is 1, and nil defers to the leaf.
func (c *CLI) resolve(err error) int {
	if err == nil {
		return c.exit
	}
	var ce interface{ AsCLIError() *output.Error }
	if errors.As(err, &ce) {
		if e := ce.AsCLIError(); e != nil && e.ExitCode != 0 {
			return e.ExitCode
		}
	}
	return 1
}

// LongFlags rewrites the single-dash long flags of args (-spec DIR,
// -spec=DIR, -check) to their double-dash form. The commands were built on
// the standard flag package, which reads both forms and has no shorthand
// flags; pflag reads -spec as the shorthand cluster -s -p -e -c. A token
// of more than one letter after a single dash is rewritten when it names a
// long flag of the command tree, or when its first letter is not a
// shorthand of the tree (-bogus is then reported as the unknown flag
// --bogus, not -b). A token that is the value of the flag before it, and
// every token after "--", is left as it is. A bare "help" becomes
// "--help": the root help, as before.
func LongFlags(root *cobra.Command, args []string) []string {
	if len(args) == 1 && args[0] == "help" {
		return []string{"--help"}
	}
	takesValue := map[string]bool{"help": false, "version": false}
	shorthand := map[byte]bool{'h': true, 'v': true}
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		add := func(f *pflag.Flag) {
			if len(f.Name) > 1 {
				takesValue[f.Name] = takesValue[f.Name] || f.NoOptDefVal == ""
			}
			if len(f.Shorthand) == 1 {
				shorthand[f.Shorthand[0]] = true
			}
		}
		cmd.Flags().VisitAll(add)
		cmd.PersistentFlags().VisitAll(add)
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(root)

	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(out, args[i:]...)
		}
		var name string // the flag a names, with any =value
		switch {
		case strings.HasPrefix(a, "--"):
			name = a[2:]
		case len(a) > 2 && a[0] == '-':
			n, _, _ := strings.Cut(a[1:], "=")
			if _, known := takesValue[n]; known || !shorthand[a[1]] {
				name = a[1:]
				a = "-" + a
			}
		}
		out = append(out, a)
		if n, _, hasValue := strings.Cut(name, "="); name != "" && !hasValue && takesValue[n] && i+1 < len(args) {
			i++
			out = append(out, args[i])
		}
	}
	return out
}

// Version is the version of the running binary: the module version it was
// built at (go install hop.top/pact/<tool>@<version>), or 0.0.0-devel
// for a build from a source tree.
func Version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return strings.TrimPrefix(v, "v")
		}
	}
	return "0.0.0-devel"
}
