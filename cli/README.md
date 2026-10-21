# PACT (CLI)

Purpose-bound Access Control & Trust: AI agents prove who they act for and why, on every request — on top of the auth you already run, from HTTP Basic and files to OAuth, LDAP, Entra, Kubernetes and AWS.

Command-line tools: the conformance runner `pactc`, and `pactconf`, `pactfix` and `pactvalidate`.

Read-only mirror of the `pact` component (`cli/`) of [hop-top/poly-pact](https://github.com/hop-top/poly-pact); open issues and pull requests there.

Status: prerelease. The protocol is a [draft](https://github.com/hop-top/spec-pact), and commands, flags and the report format may change between prerelease versions.

[![ci-go](https://github.com/hop-top/poly-pact/actions/workflows/ci-go.yml/badge.svg)](https://github.com/hop-top/poly-pact/actions/workflows/ci-go.yml)

## Table of contents

- [Demo](#demo)
- [Quick start](#quick-start)
- [Install](#install)
- [Usage](#usage)
- [Commands](#commands)
- [Flags](#flags)
- [Exit codes](#exit-codes)
- [Agent usage](#agent-usage)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

`pactc` runs the language-neutral conformance fixtures of the
[PACT specification](https://github.com/hop-top/spec-pact) against an implementation written in
any language, through commands given on its command line; it never imports or links the
implementation. The module path is `hop.top/pact`; the commands are built on the Go library
[hop.top/pact-go](https://github.com/hop-top/pact-go).

## Demo

`pactc` against `pactvalidate`, the harness of the reference validator, on one fixture:

```
$ pactc run --fixtures-root spec-pact/v1.0/fixtures --fixture admission/valid \
    --evaluate-cmd "pactvalidate evaluate {dir} {state}" \
    --receipt-cmd "pactvalidate receipt {state} {id}"
manifest.json  PASS
capabilities   none
profile        full
transport      https

FIXTURE                  VERB      STATUS
-----------------------------------------
admission/valid          evaluate  PASS
admission/valid-ed25519  evaluate  SKIP

pass 2, fail 0, skip 1
full: selected 2, not applicable 0, unsupported 1, roles Holder, Gateway, Validator, Reputation, Learning
```

`admission/valid-ed25519` is skipped because it tests the optional Ed25519 capability, which the
run did not declare (`--capability jws-ed25519`).

## Quick start

```sh
go install hop.top/pact/pactc@latest hop.top/pact/pactvalidate@latest
git clone https://github.com/hop-top/spec-pact
pactc run --fixtures-root spec-pact/v1.0/fixtures --fixture admission/valid \
  --evaluate-cmd "pactvalidate evaluate {dir} {state}" \
  --receipt-cmd "pactvalidate receipt {state} {id}"
```

To test your own implementation, replace the `pactvalidate` templates with the commands of your
implementation ([adapter contract](docs/adapter-contract.md)).

## Install

Each tool is its own main package:

```sh
go install hop.top/pact/pactc@latest
go install hop.top/pact/pactconf@latest
go install hop.top/pact/pactfix@latest
go install hop.top/pact/pactvalidate@latest
```

From source, build all four into `bin/`: `go build -o bin/ ./...` in a clone of this mirror, or
`go -C cli build -o bin/ ./...` from the root of a clone of
[hop-top/poly-pact](https://github.com/hop-top/poly-pact) (into `cli/bin/`).

Requirements: Go 1.26.1 or later. Build with the latest Go 1.26 patch release: later patches
fix vulnerabilities in the standard-library HTTP, TLS and X.509 code the commands link.

Shell completion: `pactc completion bash|fish|powershell|zsh` prints the script; `pactconf` and
`pactfix` have the same command.

The fixtures ship with the specification: clone
[hop-top/spec-pact](https://github.com/hop-top/spec-pact) and pass its `v1.0/fixtures` directory
to `--fixtures-root`, or its manifest to `pactconf vectors verify`.

## Usage

Run every admission case against the reference validator, Ed25519 included:

```
$ pactc run --fixtures-root spec-pact/v1.0/fixtures --capability jws-ed25519 --fixture admission/ \
    --evaluate-cmd "pactvalidate evaluate {dir} {state}" \
    --receipt-cmd "pactvalidate receipt {state} {id}"
...
admission/wrong-tenant                      evaluate  PASS

pass 38, fail 0, skip 0
full: selected 37, not applicable 0, unsupported 0, roles Holder, Gateway, Validator, Reputation, Learning
```

Write the `pactc/v1` report as JSON instead of a table:

```
$ pactc run --fixtures-root spec-pact/v1.0/fixtures --fixture admission/valid --json \
    --evaluate-cmd "pactvalidate evaluate {dir} {state}" \
    --receipt-cmd "pactvalidate receipt {state} {id}"
{
  "schema": "pactc/v1",
  "summary": {
    "pass": 2,
    "fail": 0,
    "skip": 1
  },
  ...
```

Run the shared test vectors through the Go core packages:

```
$ pactconf vectors verify --capability jws-ed25519 spec-pact/v1.0/fixtures/manifest.json
...
PASS    vectors/strictjson/unknown-core-field-case-variant
182 passed, 0 failed, 2 skipped
```

Validate an integration profile:

```
$ pactconf profile validate spec-pact/v1.0/profiles/basic/profile.json
spec-pact/v1.0/profiles/basic/profile.json: ok
```

### Conformance run in the source repository

In a clone of [hop-top/poly-pact](https://github.com/hop-top/poly-pact), `make conformance`
builds `pactc`, runs every entry of `spec/v1.0/fixtures` and writes the `pactc/v1` report to
`bin/conformance/pactc.json`. Without adapter commands it drives the fake implementation of the
runner tests; `PACTC_ARGS` names the implementation under test instead:

```sh
go -C cli build -o "$PWD/bin/pactvalidate" ./pactvalidate
make conformance PACTC_ARGS='--capability jws-ed25519 --fixture admission/ \
  --evaluate-cmd "bin/pactvalidate evaluate {dir} {state}" \
  --receipt-cmd "bin/pactvalidate receipt {state} {id}"'
```

The target fails when `pactc` does, with its [exit status](#exit-codes).

## Commands

| Command | Purpose |
|---|---|
| `pactc run` | run the conformance fixtures against an implementation, through the adapter contract |
| `pactconf vectors verify [manifest.json]` | run the shared test vectors, key entries and core schema entries through the Go core packages |
| `pactconf profile validate FILE...` | validate integration profiles: strict JSON, the profile schema, then the profile lint |
| `pactfix generate [case ...]` | sign the evaluation, outcomes and learning cases that have a `signing.json`; `--check` writes nothing |
| `pactfix check manifest` | check the fixture manifest against the fixture files and the spec map |
| `pactfix check links` | check that every relative link of the spec Markdown files resolves inside the spec tree |
| `pactvalidate evaluate DIR [STATE]` | print the reference validator's responses to the evaluation case in `DIR` |
| `pactvalidate receipt STATE ID` | print the receipt whose `jti` is `ID` |

`pactc`, `pactconf` and `pactfix` also have `status`, which shows the runtime status of the
command framework, and `completion`. The `--help` output of every command is in the
[command reference](docs/commands.md).

### pactc

The conformance runner. It judges an implementation under test on the fixture manifest, through
the argv templates of the [adapter contract](docs/adapter-contract.md), and prints a table or the
`pactc/v1` JSON report.

```
$ pactc --help

  pactc runs the PACT conformance fixtures against an implementation under
  test, written in any language, through the adapter contract of pactc run.
  Nothing of the implementation is imported or linked.

  USAGE

    pactc [command] [--flags]

  COMMANDS

    run [--flags]      Run the conformance fixtures through the adapter contract
    status [--flags]   Show kit runtime status (profile, env, workspace, auth, config)

  FLAGS

    -h --help          Help for pactc
    --help-all         Show all commands and global flags
    --help-management  Show only management commands
    -v --version       Version for pactc


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactc --help-all` to list them
```

### pactconf

Validates conformance inputs: `vectors verify` runs the shared test vectors of the fixture
manifest through the Go core packages, and `profile validate` checks integration profiles.

```
$ pactconf --help

  pactconf validates PACT conformance inputs: the shared test vectors
  (vectors verify) and integration profiles (profile validate).

  Exit status: 0 success; 1 an input fails validation; 2 usage error, or an
  input that cannot be read.

  USAGE

    pactconf [command] [--flags]

  COMMANDS

    profile [command]  Integration profiles
    status [--flags]   Show kit runtime status (profile, env, workspace, auth, config)
    vectors [command]  Shared test vectors

  FLAGS

    -h --help          Help for pactconf
    --help-all         Show all commands and global flags
    --help-management  Show only management commands
    -v --version       Version for pactconf


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactconf --help-all` to list them
```

### pactfix

Maintains the fixtures in a clone of the source repository and runs from its root (or from
`cli/`): it signs the fixture cases, and checks the manifest and the links of the spec tree.

```
$ pactfix check manifest
pactfix check manifest: ok (1240 entries)
$ pactfix --help

  pactfix maintains the conformance fixtures under spec/v1.0/fixtures.

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

  exit status: 0 clean, 1 problems found, 2 usage error or cannot run

  USAGE

    pactfix [command] [--flags]

  COMMANDS

    check [command]                                       Check the fixture tree
    generate [--check] [--spec DIR] [case ...] [--flags]  Sign the decoded objects of the evaluation, outcomes and learning cases
    status [--flags]                                      Show kit runtime status (profile, env, workspace, auth, config)

  FLAGS

    -h --help                                             Help for pactfix
    --help-all                                            Show all commands and global flags
    --help-management                                     Show only management commands
    -v --version                                          Version for pactfix


  GLOBAL FLAGS

    --no-color    Disable ANSI color
    --no-hints    Suppress next-step hints after command output
    --offline     Disable network access
    --quiet       Suppress non-essential output
    -V --verbose  Increase log verbosity (-V=debug, -VV=trace)

    +8 more global flags — run `pactfix --help-all` to list them
```

### pactvalidate

The conformance harness of the reference validator: the evaluate and receipt commands of the
adapter contract, as `pactc run` calls them. It takes plain arguments and no flags, and prints
its usage line on a usage error.

```
$ pactvalidate --help
usage: pactvalidate evaluate DIR [STATE] | pactvalidate receipt STATE ID
```

## Flags

Global flags of `pactc`, `pactconf` and `pactfix` (`<tool> --help-all` lists all thirteen, as
does the [command reference](docs/commands.md#global-flags)):

| Flag | Effect |
|---|---|
| `-h`, `--help` | help for the command |
| `-v`, `--version` | print the version |
| `--no-color` | disable ANSI color |
| `--no-hints` | suppress next-step hints after command output |
| `--offline` | disable network access |
| `--quiet` | suppress non-essential output |
| `-V`, `--verbose` | increase log verbosity (`-V` debug, `-VV` trace) |

Flags take one or two dashes (`-spec` and `--spec`).

`pactc run`:

| Flag | Default | Effect |
|---|---|---|
| `--fixtures-root DIR` | `spec/v1.0/fixtures` | fixture directory that holds `manifest.json` |
| `--evaluate-cmd TMPL` | none | evaluate command template |
| `--receipt-cmd TMPL` | none | receipt command template |
| `--outcomes-cmd TMPL` | none | outcomes command template |
| `--learning-cmd TMPL` | none | learning command template |
| `--schema-cmd TMPL` | none | schema command template |
| `--fixture SEL` | all entries | run only the entries whose manifest id is `SEL` or starts with it; repeatable |
| `--capability NAME` | none | declare an optional capability, such as `jws-ed25519`; repeatable |
| `--profile ID` | `full` | run the entries of a conformance profile: `full` or `single-owner` |
| `--transport ID` | `https` | run the entries over a transport profile: `https` or `stdio-ipc`; repeatable |
| `--schema FILE` | `schemas/pact.schema.json` beside the fixtures root | the Appendix A.3 schema of the schema verb's fixture check |
| `--schema-check MODE` | `gate` | `gate` runs that check; `off` skips it, a local diagnostic |
| `--json` | off | write the `pactc/v1` report as JSON instead of a table |

A verb whose command is not given is `SKIP` for every entry, never `FAIL`. The templates, the
placeholders `{dir}`, `{state}` and `{id}`, and what each command prints are the
[adapter contract](docs/adapter-contract.md); `pactc run --help` prints it too.

Other commands:

| Command | Flag | Default | Effect |
|---|---|---|---|
| `pactconf vectors verify` | `--capability NAME` | none | declare an optional capability; repeatable |
| `pactconf vectors verify` | `--ndjson` | off | one JSON line per vector, key and schema entry on stdout, details on stderr |
| `pactconf profile validate` | `--spec DIR` | the nearest directory above `FILE` that holds `profiles/integration-profile.schema.json` | the spec directory, base of fixture paths |
| `pactfix generate` | `--check` | off | write nothing; fail when a signed file would change |
| `pactfix generate`, `check manifest` | `--spec DIR` | `./spec/v1.0`, or `../spec/v1.0` when only that exists | the spec version directory |
| `pactfix check links` | `--spec DIR` | `./spec`, or `../spec` when only that exists | the spec tree, the mirror root |

## Exit codes

| Code | `pactc run` | `pactconf` | `pactfix` | `pactvalidate` |
|---|---|---|---|---|
| 0 | no check is `FAIL` | success | clean | responses printed |
| 1 | a check is `FAIL` | an input fails validation | problems found, or stale signed files (`generate --check`) | the case cannot be run |
| 2 | usage error, or the run cannot start | usage error, or an input cannot be read | usage error, or cannot run | usage error |
| 3 | no check is `FAIL`, but the profile and transports select no entry | | | |

## Agent usage

`pactc run --json` writes the `pactc/v1` report, whose JSON Schema
is [runner/schemas/pactc-report.v1.schema.json](https://github.com/hop-top/pact-go/blob/main/runner/schemas/pactc-report.v1.schema.json)
in the library. `pactconf vectors verify --ndjson` prints one line per entry on stdout,
`{"id","kind","result"}`, with `result` one of `pass`, `fail`, `skipped:out-of-scope`,
`skipped:spec-defect` or `skipped:capability`:

```
$ pactconf vectors verify --ndjson spec-pact/v1.0/fixtures/manifest.json 2>/dev/null | head -2
{"id":"keys/adversarial","kind":"key","result":"pass"}
{"id":"keys/ed25519","kind":"key","result":"skipped:out-of-scope"}
```

The exit codes above tell a failed check (1) from a run that could not start (2) and from a run
that selected nothing (3).

## Documentation

- [docs/adapter-contract.md](docs/adapter-contract.md): the argv templates, placeholders, verbs,
  rules and report of `pactc run`.
- [docs/commands.md](docs/commands.md): the `--help` output of every command.
- The fixtures, their manifest and the runner contract they define:
  [v1.0/fixtures/README.md](https://github.com/hop-top/spec-pact/blob/main/v1.0/fixtures/README.md)
  in the specification.
- The Go library the commands are built on: [hop-top/pact-go](https://github.com/hop-top/pact-go).

## Contributing

Changes land in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) under `cli/`; this
mirror accepts no issues or pull requests. See its
[contributing guide](https://github.com/hop-top/poly-pact/blob/HEAD/CONTRIBUTING.md) and
[code of conduct](https://github.com/hop-top/poly-pact/blob/HEAD/CODE_OF_CONDUCT.md). In the
source repository, `make go-test go-vet go-lint` checks this module and `make conformance` runs
`pactc` over the fixtures.

## Security

Report vulnerabilities to security@hop.top, not in a public issue; see
[SECURITY.md](https://github.com/hop-top/poly-pact/blob/HEAD/SECURITY.md).

## License

MIT, © 2026 Idea Crafters LLC and jadb. See [LICENSE](LICENSE).
