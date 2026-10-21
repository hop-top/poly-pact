// Command pactfix maintains the conformance fixtures under spec/v1.0/fixtures:
//
//	pactfix generate [-check] [-spec DIR] [case ...]
//	pactfix check manifest [-spec DIR]
//	pactfix check links [-spec DIR]
//
// generate signs the decoded objects of each evaluation, outcomes or learning
// case of the manifest that has a signing.json, as that file states, with the
// test keys of spec/v1.0/fixtures/keys. It reads no clock and draws
// no identifier, and it keeps a committed signed file that still verifies and
// matches its decoded file, so a second run changes nothing. With -check it
// writes nothing and fails when a signed file would change.
//
// check manifest runs every rule of package hop.top/pact-go/runner/manifest
// over spec/v1.0/fixtures and spec/v1.0/spec-map.md. check links checks that
// every relative link in spec/**/*.md resolves inside spec/, in place and in a
// copy laid out as the spec mirror, which holds spec/ at its root.
//
// The fixture format is defined in spec/v1.0/fixtures/README.md. The command
// tree, flags, help and version are those of hop.top/kit (package cliroot).
// Flags take one or two dashes: -spec and --spec are the same flag.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"hop.top/kit/go/console/cli"

	"hop.top/pact-go/runner/manifest"
	"hop.top/pact/internal/cliroot"
)

const help = `pactfix maintains the conformance fixtures under spec/v1.0/fixtures.

commands:
  generate [--check] [--spec DIR] [case ...]
      sign each case of the manifest that has a signing.json (all by
      default), as that file states; --check writes nothing and fails when a
      signed file is missing, does not verify, or does not match its decoded
      files, or a digests member would change
  check manifest [--spec DIR]
      check spec/v1.0/fixtures/manifest.json against the fixture files and
      spec/v1.0/spec-map.md
  check links [--spec DIR]
      check that every relative link in spec/**/*.md resolves inside spec/,
      in place and in a copy laid out as the spec mirror (spec/ at its root)

--spec of generate and check manifest is the spec version directory:
./spec/v1.0 by default, or ../spec/v1.0 when that is the one that exists
(running from cli/). --spec of check links is the spec tree, the root of the
mirror: ./spec or ../spec in the same way. Flags take one or two dashes.

exit status: 0 clean, 1 problems found, 2 usage error or cannot run`

// specVersion is the spec version directory under spec/.
const specVersion = "v1.0"

// specUsage is the help of the --spec flag of generate and check manifest.
const specUsage = "spec version `DIR`ectory (default ./spec/v1.0, or ../spec/v1.0 when only that exists)"

// specRootUsage is the help of the --spec flag of check links.
const specRootUsage = "spec tree `DIR`ectory, the mirror root (default ./spec, or ../spec when only that exists)"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes pactfix with args (without the program name) and returns the
// exit status.
func run(args []string, stdout, stderr io.Writer) int {
	return newCLI().Run(args, stdout, stderr)
}

func newCLI() *cliroot.CLI {
	c := cliroot.New("pactfix", "Maintain the PACT conformance fixtures", help)

	var genSpec string
	var check bool
	gen := &cobra.Command{
		Use:   "generate [--check] [--spec DIR] [case ...]",
		Short: "Sign the decoded objects of the evaluation, outcomes and learning cases",
		Long: `Signs each evaluation, outcomes or learning case of the manifest that
has a signing.json (all by default, or the cases named by manifest id), as
that file states, with the test keys of spec/v1.0/fixtures/keys. A case
directory with a signed file but no signing.json, or a signed file that its
signing.json does not name, is an error. It reads no clock and draws no
identifier, and it keeps a
committed signed file that still verifies and matches its decoded file, so a
second run changes nothing.

--check writes nothing and fails when a signed file is missing, does not
verify, or does not match its decoded files, or when a decoded member that
signing.json fills with a digest would change.

exit status: 0 clean, 1 stale signed files (--check), 2 usage error or
cannot run`,
		Args: cobra.ArbitraryArgs,
	}
	gen.Flags().BoolVar(&check, "check", false, "write nothing; fail when a signed file would change")
	gen.Flags().StringVar(&genSpec, "spec", "", specUsage)
	c.Leaf(c.Root.Cmd, gen, cli.SideEffectWriteLocal, func(cmd *cobra.Command, cases []string) int {
		return runGenerate(specDir(genSpec), check, cases, cmd.OutOrStdout(), cmd.ErrOrStderr())
	})

	group := c.Group(c.Root.Cmd, "check", "Check the fixture tree",
		"Checks of spec/v1.0/fixtures and the spec Markdown files.")

	var manifestSpec string
	checkManifest := &cobra.Command{
		Use:   "manifest [--spec DIR]",
		Short: "Check the fixture manifest against the fixture files and the spec map",
		Long: `Checks spec/v1.0/fixtures/manifest.json against the fixture files and
spec/v1.0/spec-map.md: every rule of package hop.top/pact-go/runner/manifest.

exit status: 0 clean, 1 problems found, 2 usage error`,
		Args: cobra.NoArgs,
	}
	checkManifest.Flags().StringVar(&manifestSpec, "spec", "", specUsage)
	c.Leaf(group, checkManifest, cli.SideEffectRead, func(cmd *cobra.Command, _ []string) int {
		return runCheckManifest(specDir(manifestSpec), cmd.OutOrStdout(), cmd.ErrOrStderr())
	})

	var linksSpec string
	checkLinks := &cobra.Command{
		Use:   "links [--spec DIR]",
		Short: "Check the relative links of the spec Markdown files",
		Long: `Checks that every relative link in spec/**/*.md resolves inside spec/, in
place and in a copy laid out as the spec mirror, which holds spec/ at its
root.

exit status: 0 clean, 1 problems found, 2 usage error or cannot run`,
		Args: cobra.NoArgs,
	}
	checkLinks.Flags().StringVar(&linksSpec, "spec", "", specRootUsage)
	c.Leaf(group, checkLinks, cli.SideEffectRead, func(cmd *cobra.Command, _ []string) int {
		return runCheckLinks(specRoot(linksSpec), cmd.OutOrStdout(), cmd.ErrOrStderr())
	})
	return c
}

// specDir returns the spec version directory: dir when set, otherwise
// spec/v1.0, or ../spec/v1.0 when only that one exists (running from cli/).
func specDir(dir string) string {
	if dir != "" {
		return dir
	}
	return nearest(filepath.Join("spec", specVersion))
}

// specRoot returns the spec tree, the root of the mirror: dir when set,
// otherwise spec, or ../spec when only that one exists (running from cli/).
func specRoot(dir string) string {
	if dir != "" {
		return dir
	}
	return nearest("spec")
}

// nearest returns rel, or ../rel when only that one exists.
func nearest(rel string) string {
	if _, err := os.Stat(rel); err != nil {
		if _, err := os.Stat(filepath.Join("..", rel)); err == nil {
			return filepath.Join("..", rel)
		}
	}
	return rel
}

func runGenerate(spec string, check bool, cases []string, stdout, stderr io.Writer) int {
	res, err := generate(filepath.Join(spec, "fixtures"), check, cases)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pactfix generate: %v\n", err)
		return 2
	}
	changed := 0
	for _, r := range res {
		if !r.Changed {
			continue
		}
		changed++
		if check {
			_, _ = fmt.Fprintf(stderr, "  stale %s\n", r.File)
		} else {
			_, _ = fmt.Fprintf(stdout, "  signed %s\n", r.File)
		}
	}
	if check {
		if changed > 0 {
			_, _ = fmt.Fprintf(stderr, "pactfix generate -check: %d of %d signed files stale; run pactfix generate\n", changed, len(res))
			return 1
		}
		_, _ = fmt.Fprintf(stdout, "pactfix generate -check: ok (%d signed files, 0 stale)\n", len(res))
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "pactfix generate: %d signed files, %d written\n", len(res), changed)
	return 0
}

func runCheckManifest(spec string, stdout, stderr io.Writer) int {
	fixtures := filepath.Join(spec, "fixtures")
	ps := manifest.Check(fixtures, filepath.Join(spec, "spec-map.md"))
	if len(ps) > 0 {
		return report(stderr, "check manifest", ps)
	}
	m, err := manifest.Load(fixtures)
	if err != nil {
		return report(stderr, "check manifest", manifest.Problems{{Rule: manifest.RuleJSON, Where: manifest.FileName, Msg: err.Error()}})
	}
	_, _ = fmt.Fprintf(stdout, "pactfix check manifest: ok (%d entries)\n", len(m.Entries))
	return 0
}

func runCheckLinks(spec string, stdout, stderr io.Writer) int {
	ps, st, err := checkLinks(spec)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pactfix check links: %v\n", err)
		return 2
	}
	if len(ps) > 0 {
		return report(stderr, "check links", ps)
	}
	_, _ = fmt.Fprintf(stdout, "pactfix check links: ok (%d markdown files, %d local links, %d allow-listed)\n",
		st.files, st.links, st.allowed)
	return 0
}

func report(stderr io.Writer, name string, ps manifest.Problems) int {
	_, _ = fmt.Fprintf(stderr, "pactfix %s: %d problem(s)\n", name, len(ps))
	for _, p := range ps {
		_, _ = fmt.Fprintf(stderr, "  %s\n", p)
	}
	return 1
}
