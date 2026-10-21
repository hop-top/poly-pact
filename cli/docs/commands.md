# Command reference

The `--help` output of every command of `hop.top/pact`, as the commands print it.
`<tool> <command> --help-all` adds the global flags that `--help` folds away.
The overview is the [README](../README.md); the templates and judging rules of `pactc run` are
the [adapter contract](adapter-contract.md).

## Table of contents

- [`pactc run`](#pactc-run)
- [`pactconf vectors verify`](#pactconf-vectors-verify)
- [`pactconf profile validate`](#pactconf-profile-validate)
- [`pactfix generate`](#pactfix-generate)
- [`pactfix check manifest`](#pactfix-check-manifest)
- [`pactfix check links`](#pactfix-check-links)
- [`pactvalidate`](#pactvalidate)
- [Global flags](#global-flags)

## `pactc run`

```
$ pactc run --help

  pactc runs the PACT conformance fixtures against an implementation under
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
  select no entry

  USAGE

    pactc run [--flags]

  FLAGS

    --capability     Declare the optional capability `NAME` of the implementation, such as jws-ed25519; entries that test a capability not declared are SKIP; repeatable
    --evaluate-cmd   Evaluate command template (`TMPL`)
    --fixture        Run only the entries whose manifest id is `SEL` or starts with it: a manifest id or id prefix, such as admission/valid or admission/; repeatable
    --fixtures-root  Fixture `DIR`ectory that holds manifest.json (spec/v1.0/fixtures)
    -h --help        Help for run
    --json           Write the pactc/v1 report as JSON instead of a table
    --learning-cmd   Learning command template (`TMPL`)
    --outcomes-cmd   Outcomes command template (`TMPL`)
    --profile        Run the entries of the conformance profile `ID` of spec/v1.0/profiles/registry.json: full or single-owner (full)
    --receipt-cmd    Receipt command template (`TMPL`, optional)
    --schema         The Appendix A.3 schema `FILE` for the fixture schema check of the schema verb; default schemas/pact.schema.json beside the fixtures root, skipped when that file does not exist
    --schema-check   The fixture schema check of the schema verb, `MODE` gate (default: a case whose expectation the schema contradicts fails) or off (a local diagnostic: the check is not run, the entry is judged on --schema-cmd alone and the report lists it as skipped) (gate)
    --schema-cmd     Schema command template (`TMPL`, optional)
    --transport      Run the entries over the transport profile `ID`: https (default) or stdio-ipc; repeatable


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactc run --help-all` to list them
```

## `pactconf vectors verify`

```
$ pactconf vectors verify --help

  Reads the fixture manifest, by default ../spec/v1.0/fixtures/manifest.json as
  seen from the cli/ directory, and runs every entry of kind vector of the
  binding, digest, jcs, jws and strictjson groups through the matching go/core
  package, of the schema group through the JSON Schema library (format
  assertion on, uri checked per RFC 3986 by the expression the SDKs share),
  every entry of kind schema of scope core through the verdict of
  spec/v1.0/fixtures/schema/README.md, with ../schemas/pact.schema.json beside the
  fixture directory, and every entry of kind key through the key rule. Prints
  one PASS,
  FAIL or SKIP row per entry, then a summary line. A SKIP is a known spec
  defect, reported with both values, the Ed25519 key (optional, draft section
  7.2), an entry whose optional capabilities are not all declared, or a vector
  entry of scope runner in a group without a runner here: the Go conformance
  runner runs it.

  Optional capabilities (spec/v1.0/fixtures/README.md): a manifest entry with
  capabilities tests a feature the draft makes optional; jws-ed25519 is
  Ed25519 negotiation (draft section 7.2). --capability NAME, repeatable,
  declares it. An entry runs only when every capability it lists is declared;
  otherwise it is SKIP naming the missing ones, and a skipped entry is never
  counted as passed. A JWS entry that lists jws-ed25519 runs with Ed25519
  negotiated besides ES256; every other entry runs with ES256 alone. Entries
  without capabilities always run. An unknown NAME is a usage error.

  The key rule: every P-256 JWK under keys/ parses as a public key, and its
  point is the scalar of its record in keys/test-private-scalars.json times the
  base point; the record of role holder names the key whose RFC 7638
  thumbprint is the holder_jkt of draft Appendix C. The entry of
  keys/test-private-scalars.json passes when every P-256 record derives.

  With --ndjson, standard output carries only one JSON line per vector, key and
  schema entry, {"id","kind","result"}, the result being pass, fail,
  skipped:out-of-scope, skipped:spec-defect or skipped:capability; a
  spec-defect line also carries spec_defects, each
  {"vector","appendix_value","expected_digest"}, and a capability line
  missing_capabilities, the capabilities of the entry not declared. An entry of
  scope runner is skipped:out-of-scope; one whose group has a runner still
  runs, and its failure still fails the run. Every row that is not a PASS,
  with its detail, and the summary line go to standard error.

  The run also fails when an id repeats, when a path or expected file of any
  entry is missing, when a .json file under vectors/ is not registered, when a
  vector entry of scope core or adapter belongs to a group without a runner,
  and when a .go file sits under the fixture directory or the profiles
  directory beside it.

  Exit status: 0 no row fails; 1 a row fails; 2 usage error (an unknown
  --capability included), or the manifest cannot be read or has an entry of
  unknown kind, scope, capability, conformance profile, transport or layer.

  USAGE

    pactconf vectors verify [--ndjson] [--capability NAME]... [manifest.json] [--flags]

  FLAGS

    --capability  Declare the optional capability `NAME` of the implementation, such as jws-ed25519; entries that test a capability not declared are SKIP; repeatable
    -h --help     Help for verify
    --ndjson      Print one JSON line per vector and key entry on stdout, details on stderr


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactconf vectors verify --help-all` to list them
```

## `pactconf profile validate`

```
$ pactconf profile validate --help

  Validates each integration profile FILE: strict JSON parse, then
  DIR/profiles/integration-profile.schema.json, then the profile lint of
  DIR/profiles/README.md. DIR is the spec directory and the base of fixture
  paths. Without --spec it is the nearest directory above FILE that holds
  profiles/integration-profile.schema.json.

  A valid FILE prints "FILE: ok" on stdout. Each failure prints one line on
  stderr, FILE#POINTER: CHECK [RULE]: MESSAGE, where POINTER is an RFC 6901
  JSON Pointer in URI fragment form, CHECK is parse, schema or lint, and RULE
  is the failing JSON Schema keyword or lint rule.

  Exit status: 0 every FILE is valid; 1 a FILE fails; 2 usage error, or a FILE
  or the spec directory cannot be read.

  USAGE

    pactconf profile validate FILE... [--spec DIR] [--flags]

  FLAGS

    -h --help  Help for validate
    --spec     Spec directory, the base of fixture paths (default: the nearest above FILE)


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactconf profile validate --help-all` to list them
```

## `pactfix generate`

```
$ pactfix generate --help

  Signs each evaluation, outcomes or learning case of the manifest that
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
  cannot run

  Dry-run support: this command honors --dry-run.

  USAGE

    pactfix generate [--check] [--spec DIR] [case ...] [--flags]

  FLAGS

    --check    Write nothing; fail when a signed file would change
    -h --help  Help for generate
    --spec     Spec version `DIR`ectory (default ./spec/v1.0, or ../spec/v1.0 when only that exists)


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactfix generate --help-all` to list them
```

## `pactfix check manifest`

```
$ pactfix check manifest --help

  Checks spec/v1.0/fixtures/manifest.json against the fixture files and
  spec/v1.0/spec-map.md: every rule of package hop.top/pact-go/runner/manifest.

  exit status: 0 clean, 1 problems found, 2 usage error

  USAGE

    pactfix check manifest [--spec DIR] [--flags]

  FLAGS

    -h --help  Help for manifest
    --spec     Spec version `DIR`ectory (default ./spec/v1.0, or ../spec/v1.0 when only that exists)


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactfix check manifest --help-all` to list them
```

## `pactfix check links`

```
$ pactfix check links --help

  Checks that every relative link in spec/**/*.md resolves inside spec/, in
  place and in a copy laid out as the spec mirror, which holds spec/ at its
  root.

  exit status: 0 clean, 1 problems found, 2 usage error or cannot run

  USAGE

    pactfix check links [--spec DIR] [--flags]

  FLAGS

    -h --help  Help for links
    --spec     Spec tree `DIR`ectory, the mirror root (default ./spec, or ../spec when only that exists)


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactfix check links --help-all` to list them
```

## `pactvalidate`

`pactvalidate` is the harness of the reference validator, the implementation that
`pactc run` drives in the examples. It takes plain arguments and no flags, and prints its
usage line, exit status 2, on any other input:

```
$ pactvalidate --help
usage: pactvalidate evaluate DIR [STATE] | pactvalidate receipt STATE ID
```

## Global flags

`pactc`, `pactconf` and `pactfix` share the global flags of their command framework. All of
them, from `pactc --help-all`:

```
$ pactc --help-all

  pactc runs the PACT conformance fixtures against an implementation under
  test, written in any language, through the adapter contract of pactc run.
  Nothing of the implementation is imported or linked.

  USAGE

    pactc [command] [--flags]

  COMMANDS

    run [--flags]         Run the conformance fixtures through the adapter contract
    status [--flags]      Show kit runtime status (profile, env, workspace, auth, config)

  MANAGEMENT

    completion [command]  Generate the autocompletion script for the specified shell

  FLAGS

    -h --help             Help for pactc
    --help-all            Show all commands and global flags
    --help-management     Show only management commands
    -v --version          Version for pactc


  GLOBAL FLAGS

    --api-version      Request a specific CLI schema version (MAJOR.MINOR) for compatibility-mode filtering.
    --autocorrect      Act on a mistyped flag's correction (off|prompt|read). Default: off (suggest only). read applies it on read-only commands; prompt asks on a TTY.
    -C --chdir         Change directory before running (path or tool-specific target)
    -c --config        Layer extra config (repeatable). key=value overrides a single value (dotted keys for nesting; value parses as YAML, falls back to literal). A bare path loads an additional config file after the discovered ones. -c tokens win over file layers.
    --confirm          Confirmation policy for destructive commands (auto|yes|no|prompt). Default: prompt on a TTY, no otherwise.
    --max-ops          Cap mutating operations per invocation. 0 = unlimited.
    --no-color         Disable ANSI color
    --no-hints         Suppress next-step hints after command output
    --offline          Disable network access
    --policy           Named delegation policy (loaded from $XDG_CONFIG_HOME/<tool>/policies/<name>.yaml).
    --progress-format  Progress output format (human or json). Defaults to json when --format=json unless explicitly set. (human)
    --quiet            Suppress non-essential output
    -V --verbose       Increase log verbosity (-V=debug, -VV=trace)
```
