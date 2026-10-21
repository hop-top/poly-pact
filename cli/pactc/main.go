// Command pactc runs the PACT conformance fixtures against an implementation
// under test through the adapter contract of package hop.top/pact-go/runner:
//
//	pactc run [--fixtures-root DIR] [--fixture SEL]... [--json] \
//	  --evaluate-cmd "tool evaluate {dir} {state}" \
//	  --outcomes-cmd "tool outcomes {dir} {state}" \
//	  --learning-cmd "tool learning {dir} {state}" \
//	  [--receipt-cmd "tool receipt {state} {id}"] \
//	  [--schema-cmd "tool schema {dir}"] [--schema FILE] [--schema-check gate|off] \
//	  [--capability NAME]... [--profile ID] [--transport ID]...
//
// pactc run --help states the contract. The command is a thin front end:
// selection, checks and the report are in package runner. The command tree,
// flags, help and version are those of hop.top/kit (package cliroot).
package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"hop.top/kit/go/console/cli"

	"hop.top/pact-go/runner"
	"hop.top/pact/internal/cliroot"
	"hop.top/pact/internal/pactschema"
)

const help = `pactc runs the PACT conformance fixtures against an implementation under
test, written in any language, through the adapter contract of pactc run.
Nothing of the implementation is imported or linked.`

const runHelp = `pactc runs the PACT conformance fixtures against an implementation under
test, written in any language, through the adapter contract below. Nothing
of the implementation is imported or linked.

example:
  pactc run --fixtures-root spec/v1.0/fixtures \
    --evaluate-cmd "tool evaluate {dir} {state}" \
    --receipt-cmd "tool receipt {state} {id}" \
    --outcomes-cmd "tool outcomes {dir} {state}" \
    --learning-cmd "tool learning {dir} {state}"

adapter contract:
  Each command is an argv template. It is split on white space, then {dir},
  {state} and {id} are replaced inside each argument. There is no shell:
  quotes, pipes and globs are passed on literally, and a replaced value
  stays one argument.

  {dir}     absolute path of the entry's case directory under the fixtures
            root; its files are described in spec/v1.0/fixtures/README.md
  {state}   scratch path for the case, fresh for each entry; it does not
            exist yet, and the command may create a file or a directory
            there. The evaluate and receipt commands of an entry share it;
            an evaluate template may leave it out when no receipt command
            is given.
  {id}      the jti of a receipt, for the receipt command

  evaluate  stdin none. stdout: the compact pact-admission+jwt receipt of
            the evaluation, or an RFC 9457 Problem JSON object (draft Section
            13.4) when the request is rejected before an authenticated
            evaluation (draft Section 12.2). The exit status is
            informational: printing neither is a FAIL. A receipt is verified
            under the validator key of the case and compared with its
            expected decision, claims, expiry and check results; a case with
            several submissions, handoff attempts or exchanges prints one
            response per line. A case of several exchanges is judged across
            them too: its receipts have distinct jti values (draft Section
            12.2). The reputation-context and selection-consistency-v1
            checks of every receipt name the presented snapshot jti in
            evidence_ids and, in source_ref, the selection record of
            config.json, or the Appendix B record when it names none (draft
            Appendix A.2, B.7). A selection case is evaluated twice with the
            same inputs and a fresh {state}: the decision, terminal reason
            and check results of the second run must be those of the first
            (draft Section 11.3, step 9).
  receipt   optional. stdout: the compact receipt with the jti {id} that
            the evaluate command of the case printed. After a case with
            several exchanges has run, the receipt of each earlier exchange
            is asked for again and must come back unchanged: a sealed
            receipt is never reopened, amended or converted (draft Section
            12.2). Without --receipt-cmd that sub-check is skipped and the
            report says so; the entry is judged without it.
  outcomes  run the ingestions and queries of the case. stdout: the
            outcomes result object: an Acknowledgment or a Problem for each
            ingestion, compared with acks.json when the case has one, and
            the original acknowledgment or DUPLICATE for an identical retry
            of an (iss, jti) (draft Section 7.5); for each query the signed
            ReputationSnapshot, verified
            under the case's reputation key and bound to the query, with
            score_bps and confidence_bps within one basis point of
            snapshot.json and every other member exactly, and its
            provenance manifest, whose object_digest is the snapshot's
            provenance_digest (draft Section 15.2). The qualifications are
            compared with classifications.json when the command prints
            them; otherwise that sub-check is skipped and the report says
            so. The exit status is informational.
  learning  apply the policy and events of the case. stdout: the
            registry state JSON, compared with the expected registry.json:
            the state of each artifact, the artifact in force in each
            context, the acknowledgment or rejection of each step with its
            code and reason codes, the holds and the artifacts that require
            re-evaluation. The exit status is informational.
  schema    optional: --schema-cmd "tool schema {dir}", where {dir} is
            the absolute path of the entry's file, a compact JWS or an
            object list (spec/v1.0/fixtures/schema/README.md).
            stdout: one line per document, in order: the decoded object the
            implementation accepts, as JSON (for a compact JWS its
            payload), or an RFC 9457 Problem JSON object (draft Section
            13.4) for a document it rejects. Each line of a REJECTED entry
            must be a Problem with the transport_code of its decision.json;
            each line of an ACCEPTED entry its document, compared as
            RFC 8785 canonical JSON. The exit status is informational. pactc also applies the verdict of
            that README to the input itself with the Appendix A.3 schema,
            --schema FILE or schemas/pact.schema.json beside the fixtures
            root, and an entry whose expectation the schema contradicts
            fails. Without that file the fixture schema check is skipped and
            the report says so.
            --schema-check MODE sets that check: gate, the default, runs it;
            off does not run it, judges each entry on the command alone and
            lists the check in the entry's skipped sub-checks, naming
            --schema-check. Off is a local diagnostic, not a conformance
            run. Any other MODE is a usage error.

  A verb whose command is not given is SKIP for every entry, never FAIL.

fixture selection:
  Entries come only from manifest.json in the fixtures root: pactc never
  walks the tree to find cases, and it runs only the entries of kind
  evaluate, outcomes, learning and schema. --fixture selects entries by
  manifest id or id prefix, such as admission/valid or admission/. A
  fixture file that no manifest entry covers is a FAIL of the manifest
  check (manifest-incomplete), not a skipped case.

optional capabilities:
  A manifest entry with capabilities tests a feature the draft makes
  optional; jws-ed25519 is Ed25519 negotiation (draft Section 7.2).
  --capability NAME, repeatable, declares that the implementation has it.
  An entry is judged only when every capability it lists is declared;
  otherwise it is SKIP with the missing capabilities, and a skipped entry
  is never counted as passed: a conformance claim that includes a
  capability needs its entries to pass. Entries without capabilities are
  mandatory and always run. An unknown NAME is a usage error.

conformance profile and transport:
  --profile ID runs the fixtures of one conformance profile, an entry of
  kind conformance in spec/v1.0/profiles/registry.json: full (the default) or
  single-owner. --transport ID, repeatable, names the transport profiles
  of the run, ids as in spec/v1.0/profiles/registry.json: https (the baseline,
  the default) or stdio-ipc. Only the entries that list the profile in
  conformance_profile (absent: full) and share a transport with the run
  (absent: https) run; the others are not applicable, counted in
  the report and never run, so a single-owner run never reports PASS for
  an entry that does not list single-owner (spec/v1.0/fixtures/README.md,
  Manifest entry fields). An entry over stdio-ipc may name a layer,
  transcript or os; one without a layer applies to every layer. An unknown
  ID is a usage error. A run
  that selects no entry is never green: it exits 3.

report:
  A table by default; --json writes the pactc/v1 report as JSON instead.
  Both state the profile and the transports of the run, and for the
  profile the entries selected, not applicable and skipped as unsupported.

exit status: 0 when no check is FAIL, 1 when one is, 2 on a usage error or
when the run cannot start (an unreadable manifest, or a --fixture that
selects no entry, or an unknown --capability, --profile, --transport or
--schema-check),
and 3 when no check is FAIL but the profile and transports of the run
select no entry`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes pactc with args (without the program name) and returns the
// exit status.
func run(args []string, stdout, stderr io.Writer) int {
	return newCLI().Run(args, stdout, stderr)
}

func newCLI() *cliroot.CLI {
	c := cliroot.New("pactc", "Run the PACT conformance fixtures against an implementation", help)

	var cfg runner.Config
	var asJSON bool
	var schema string
	cmd := &cobra.Command{
		Use:   "run [flags]",
		Short: "Run the conformance fixtures through the adapter contract",
		Long:  runHelp,
		Args:  cobra.NoArgs,
	}
	f := cmd.Flags()
	f.StringVar(&cfg.FixturesRoot, "fixtures-root", "spec/v1.0/fixtures", "fixture `DIR`ectory that holds manifest.json")
	f.StringArrayVar(&cfg.Fixtures, "fixture", nil,
		"run only the entries whose manifest id is `SEL` or starts with it: a manifest id or id prefix, such as admission/valid or admission/; repeatable")
	f.BoolVar(&asJSON, "json", false, "write the pactc/v1 report as JSON instead of a table")
	f.StringVar(&cfg.EvaluateCmd, "evaluate-cmd", "", "evaluate command template (`TMPL`)")
	f.StringVar(&cfg.ReceiptCmd, "receipt-cmd", "", "receipt command template (`TMPL`, optional)")
	f.StringVar(&cfg.OutcomesCmd, "outcomes-cmd", "", "outcomes command template (`TMPL`)")
	f.StringVar(&cfg.LearningCmd, "learning-cmd", "", "learning command template (`TMPL`)")
	f.StringVar(&cfg.SchemaCmd, "schema-cmd", "", "schema command template (`TMPL`, optional)")
	f.StringVar(&schema, "schema", "",
		"the Appendix A.3 schema `FILE` for the fixture schema check of the schema verb; default schemas/pact.schema.json beside the fixtures root, skipped when that file does not exist")
	f.StringVar(&cfg.SchemaCheck, "schema-check", runner.SchemaCheckGate,
		"the fixture schema check of the schema verb, `MODE` gate (default: a case whose expectation the schema contradicts fails) or off (a local diagnostic: the check is not run, the entry is judged on --schema-cmd alone and the report lists it as skipped)")
	f.StringArrayVar(&cfg.Capabilities, "capability", nil,
		"declare the optional capability `NAME` of the implementation, such as jws-ed25519; entries that test a capability not declared are SKIP; repeatable")
	f.StringVar(&cfg.Profile, "profile", "full",
		"run the entries of the conformance profile `ID` of spec/v1.0/profiles/registry.json: full or single-owner")
	f.StringArrayVar(&cfg.Transport, "transport", nil,
		"run the entries over the transport profile `ID`: https (default) or stdio-ipc; repeatable")
	c.Leaf(c.Root.Cmd, cmd, cli.SideEffectRead, func(cmd *cobra.Command, _ []string) int {
		mode, err := runner.ParseSchemaCheck(cfg.SchemaCheck)
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pactc run: %v\n", err)
			return 2
		}
		cfg.SchemaCheck = mode
		if mode == runner.SchemaCheckGate {
			v, err := loadSchema(schema, cfg.FixturesRoot)
			if err != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "pactc run: %v\n", err)
				return 2
			}
			if v != nil {
				cfg.Validator = v
			}
		}
		return runRun(cfg, asJSON, cmd.OutOrStdout(), cmd.ErrOrStderr())
	})
	return c
}

// loadSchema loads the schema of the fixture schema check: the file of
// --schema, or schemas/pact.schema.json beside the fixtures root when the
// flag is empty. It returns nil, and no error, when the default file does not
// exist; a file that cannot be loaded is an error.
func loadSchema(flag, fixturesRoot string) (*pactschema.Validator, error) {
	file := flag
	if file == "" {
		file = filepath.Join(fixturesRoot, "..", "schemas", "pact.schema.json")
		if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
	}
	v, err := pactschema.Load(file)
	if err != nil {
		if flag != "" {
			return nil, fmt.Errorf("--schema: %w", err)
		}
		return nil, err
	}
	return v, nil
}

// runRun runs the fixtures selected by cfg and writes the report, a table
// or, with asJSON, the pactc/v1 JSON report.
func runRun(cfg runner.Config, asJSON bool, stdout, stderr io.Writer) int {
	rep, err := runner.Run(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "pactc run: %v\n", err)
		return 2
	}
	if asJSON {
		if err := rep.WriteJSON(stdout); err != nil {
			_, _ = fmt.Fprintf(stderr, "pactc run: %v\n", err)
			return 2
		}
	} else {
		rep.WriteTable(stdout)
	}
	switch {
	case rep.Failed():
		return 1
	case rep.Empty():
		_, _ = fmt.Fprintf(stderr, "pactc run: no entry selected under profile %s over transport %s: an empty run is not a pass\n",
			rep.Profile, strings.Join(rep.Transport, ", "))
		return 3
	}
	return 0
}
