// Command pactconf validates PACT conformance inputs. Commands:
//
//	vectors verify     shared test vectors
//	profile validate   integration profiles
//
// vectors verify [--ndjson] [--capability NAME]... [manifest.json] reads the
// fixture manifest, by default ../spec/v1.0/fixtures/manifest.json as seen from
// the cli/ directory, and runs every entry of kind vector of the binding,
// digest, jcs, jws and strictjson groups (spec/v1.0/fixtures/vectors/README.md)
// through the matching go/core package, of the schema group through the JSON
// Schema library with the shared uri checker (package internal/pactschema),
// every entry of kind schema of scope core through the verdict of
// spec/v1.0/fixtures/schema/README.md, and every entry
// of kind key through the key rule of vectors_keys.go. It prints one PASS,
// FAIL or SKIP row per entry, then a summary line. A SKIP is a known spec
// defect, reported with both values, the Ed25519 key, an entry whose
// optional capabilities (manifest member capabilities) are not all declared
// with --capability, which is not run, or a vector entry of scope runner in
// a group without a runner here, which the Go conformance runner runs. With
// --ndjson, stdout carries only one {"id","kind","result"} line per vector,
// key and schema entry, the result grammar of docs/sdk/ports-plan.md section 5.1,
// and the other rows go to stderr. It also fails when an id repeats, when a
// path or expected file of any entry is missing, when a .json file under
// vectors/ is not registered, when a vector entry of scope core or adapter
// belongs to a group without a runner, and when a .go file sits under the
// fixture directory or the profiles directory beside it. The exit code is 1
// when any row fails.
//
// profile validate checks integration profiles (spec/v1.0/profiles/README.md) in
// three steps, and a step runs only when the one before it passed:
//
//  1. parse: the file is strict JSON (draft section 7.1), so a duplicate
//     member name, which a schema validator cannot see, is an error;
//  2. schema: the document validates against
//     spec/v1.0/profiles/integration-profile.schema.json (JSON Schema Draft
//     2020-12), compiled with github.com/santhosh-tekuri/jsonschema/v6;
//  3. lint: the schema-valid document passes the checks the schema cannot
//     express, listed in lint.go and in spec/v1.0/profiles/README.md.
//
// Every failure carries the RFC 6901 JSON Pointer of the failing location.
//
// The command tree, flags, help and version are those of hop.top/kit
// (package cliroot). Flags take one or two dashes: -spec and --spec are the
// same flag.
package main

import (
	"io"
	"os"

	"github.com/spf13/cobra"
	"hop.top/kit/go/console/cli"

	"hop.top/pact/internal/cliroot"
)

const help = `pactconf validates PACT conformance inputs: the shared test vectors
(vectors verify) and integration profiles (profile validate).

Exit status: 0 success; 1 an input fails validation; 2 usage error, or an
input that cannot be read.`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes pactconf with args (without the program name) and returns the
// process exit code: 0 on success, 1 when an input fails validation, 2 on a
// usage error or an input that cannot be read.
func run(args []string, stdout, stderr io.Writer) int {
	return newCLI().Run(args, stdout, stderr)
}

func newCLI() *cliroot.CLI {
	c := cliroot.New("pactconf", "Validate PACT conformance inputs", help)

	vectors := c.Group(c.Root.Cmd, "vectors", "Shared test vectors",
		"Commands on the shared test vectors of spec/v1.0/fixtures/vectors.")
	var ndjson bool
	var caps []string
	verify := &cobra.Command{
		Use:   "verify [--ndjson] [--capability NAME]... [manifest.json]",
		Short: "Run the shared test vectors",
		Long:  vectorsHelp,
		Args:  cobra.MaximumNArgs(1),
	}
	verify.Flags().BoolVar(&ndjson, "ndjson", false, "print one JSON line per vector and key entry on stdout, details on stderr")
	verify.Flags().StringArrayVar(&caps, "capability", nil,
		"declare the optional capability `NAME` of the implementation, such as jws-ed25519; entries that test a capability not declared are SKIP; repeatable")
	c.Leaf(vectors, verify, cli.SideEffectRead, func(cmd *cobra.Command, args []string) int {
		manifest := defaultManifest
		if len(args) == 1 {
			manifest = args[0]
		}
		return runVectors(manifest, ndjson, caps, cmd.OutOrStdout(), cmd.ErrOrStderr())
	})

	profile := c.Group(c.Root.Cmd, "profile", "Integration profiles",
		"Commands on integration profiles (spec/v1.0/profiles/README.md).")
	var spec string
	validate := &cobra.Command{
		Use:   "validate [--spec DIR] FILE...",
		Short: "Validate integration profiles",
		Long:  profileHelp,
		Args:  cobra.MinimumNArgs(1),
	}
	validate.Flags().StringVar(&spec, "spec", "", "spec directory, the base of fixture paths (default: the nearest above FILE)")
	c.Leaf(profile, validate, cli.SideEffectRead, func(cmd *cobra.Command, args []string) int {
		return runValidate(spec, args, cmd.OutOrStdout(), cmd.ErrOrStderr())
	})
	return c
}
