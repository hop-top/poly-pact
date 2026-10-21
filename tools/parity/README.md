# Cross-language parity

The Go library module `hop.top/pact-go` (`go/`) is the reference. The TypeScript (`ts/`) and Python (`py/`) SDKs port it package by package; the Rust (`rs/`) and PHP (`php/`) SDKs are core-only. This document states how the repository keeps every SDK honest against Go: what each harness prints, how the gates file classifies the shared fixtures per language, how `make parity` judges the results, how the API ledger tracks names, and how mutation patches prove that the tests can fail.

| Piece | File | Make target |
|---|---|---|
| Gates file | [`gates.json`](gates.json) | `make parity-rows` |
| Orchestrator | [`parity.py`](parity.py) | `make parity` |
| Orchestrator self-test | [`selftest.py`](selftest.py) | `make parity-selftest` |
| API ledger and its check | [`docs/sdk/parity-ledger.md`](../../docs/sdk/parity-ledger.md), [`api_ledger.py`](api_ledger.py) | `ci-go` step |
| Mutation runner | [`tools/mutants.py`](../mutants.py) | `make ts-mutants`, `py-mutants`, `rs-mutants`, `php-mutants` |

## What parity means

A port is at parity with Go for a capability when all of these hold:

1. **Same capability.** The [API ledger](#api-ledger) maps every exported Go symbol to a name in each port, or records a [deviation](#deviations).
2. **Same shared evidence.** Every manifest entry whose gate is `required` for the language passes in that language's vectors harness or adapter suite.
3. **Same unit-test matrix.** The Go unit tests are ported one-to-one under the same names, including the tests that read `spec/v1.0/draft.md`, the schema or the profile documents at test time.
4. **Same mutation proofs.** The broken-adapter catalogue and the per-module [mutation patches](#mutation-checks) show that the tests fail when the behaviour is broken.

The Rust and PHP SDKs implement no adapter contract, no adapter suite and no HTTP binding. They follow the same gates file, result grammar and ledger; their adapter-scope gates are `n/a`, so adapter support would be a column change, not a redesign.

## Runners and entry points

- Go `pactc` is the single cross-language conformance runner. It drives an implementation in any language through argv templates and never links it. `pactconf` and `pactfix` stay Go-only.
- Each port ships its manifest module, its vectors harness (`make ts-vectors`, `make py-vectors`, `make rs-vectors`, `make php-vectors`, the counterparts of `pactconf vectors verify`) and, for TypeScript and Python, a case loader for the evaluation-case layout with a `tool evaluate {dir}` skeleton, so a validator in that language runs under `make conformance PACTC_ARGS=...`.
- An SDK package never depends on the kit console framework. The internal entry points that `make` or `pactc` drive (the vectors harness, the manifest check, the `tool evaluate {dir}` skeleton) take plain argv and use no command-line framework. A user-facing command-line tool of a port is a separate package built on the kit console framework of that language.

## Result grammar

Every harness prints one NDJSON line per manifest entry, `{"id","kind","result"}`, and nothing else on standard output:

```
result ::= "pass" | "fail" | "skipped:" reason
reason ::= "out-of-scope" | "spec-defect" | "os-layer" | "capability"
```

### Skipped reasons

| Reason | Meaning | Extra member |
|---|---|---|
| `out-of-scope` | the language does not run this entry: scope `runner`, an entry under an `n/a` gate, or a gate exception such as `keys/ed25519` | none |
| `spec-defect` | valid only for a vector whose file sets `spec_defect: true` (the digest protocol of [spec/v1.0/fixtures/vectors/digest/README.md](../../spec/v1.0/fixtures/vectors/digest/README.md)) | `spec_defects`: a non-empty array of `{"vector","appendix_value","expected_digest"}` |
| `os-layer` | reserved for the manifest `layer` field | none |
| `capability` | the entry's manifest `capabilities` ([spec/v1.0/fixtures/README.md](../../spec/v1.0/fixtures/README.md), section Optional capabilities) are not all declared by the harness run (`pactconf vectors verify --capability NAME`, repeatable); the entry is not run | `missing_capabilities`: the undeclared ones |

Example: `{"id":"…","kind":"vector","result":"skipped:capability","missing_capabilities":["jws-ed25519"]}`. A scope `runner` entry stays `skipped:out-of-scope`. No other member is allowed on a line.

## Entry handling

Every harness applies the same rules:

- Kinds and scopes are a closed set: the 13 kinds and 3 scopes of `runner/manifest` (`Kinds()`, `Scopes()`). An unknown kind or scope fails the harness.
- Scope `runner` is always `skipped:out-of-scope`. Runner-scope entries belong to `pactc` and an implementation under test (the evaluation groups such as `admission`, `approval` and `outcomes`, and the `reputation/beta-decay-v1` vectors).
- Scope `core` and `adapter`: the harness must know the entry's [prefix](#gates-file). An unknown prefix fails the harness.
- A `schema` entry under a typed decode applies Go's `decode_as` rule (strict typed decode plus the `pact_version` constant), so no verdict depends on the schema validator; a typed-decode failure is reported as `payload-schema`, as Go's vector tests do.

### Key rule

For `key` entries: every P-256 JWK parses, and its public point equals `scalar × G` for its scalar in `keys/test-private-scalars.json`; the holder thumbprint equals Appendix C `holder_jkt`; `test-private-scalars.json` passes once every derivation holds. `keys/ed25519` is `skipped:out-of-scope` (Ed25519 is optional, draft section 7.2) and is listed as an exception of its gate row. Go's leg applies the same rule.

### Exit status

Non-zero on a harness error (unreadable or malformed manifest, unknown kind, scope or prefix), and on a `fail` under a gate that is `required` for the language. A `fail` under a `planned` gate is printed and counted, so unfinished work can merge while the branch stays green.

## Go legs

The Go side produces the same lines from three legs:

| Leg | Entries | Producer |
|---|---|---|
| vectors, keys and schema cases | every `vector`, `key` and `schema` entry of scope `core` and `adapter`; scope `runner` vectors print `skipped:out-of-scope`, matching the `pactconf` SKIP | `pactconf vectors verify --ndjson --capability jws-ed25519` |
| adapter cases | every `adapters/_common` case, from `adaptertest.Evaluate` on `adapters/memory` | the test binary of `adapters/memory`, built with `go test -c` and run with `-ndjson` (a command binary does not import `testing`) |
| runner | scope `runner` entries of kind `evaluate`, `outcomes` and `learning`, from the `pactc/v1` report that `make conformance` writes, against the fake implementation `go/runner/testdata/fakeimpl/impl.sh` or the implementation `PACTC_ARGS` names | `make parity` passes the report as `--runner-report go=FILE`: `PASS` is `pass`, `FAIL` is `fail`, `SKIP` is `skipped:capability` when the entry lists a capability the report does not declare and `skipped:out-of-scope` otherwise; a report whose manifest check is not `PASS` fails |

`make go-vectors` runs the first two legs. An entry that no Go leg prints (a native adapter case outside `adapters/_common`, an adapter asset, a `profile-invalid` entry) is recorded `skipped:out-of-scope` by `--fill-na go` where its gate is `n/a` for Go, and is missing under any other gate.

## Gates file

[`gates.json`](gates.json) has one row per (scope, kind, prefix) of the manifest. The prefix is the entry id's first segment, the fixture group as [spec/v1.0/spec-map.md](../../spec/v1.0/spec-map.md) defines it, except under `vectors/`, `adapters/` and `sources/`, where it is the first two segments (`vectors/jcs`, `adapters/_common`, `sources/scim`), because those groups hold independent families.

Each row has:

- a column per language (`go`, `ts`, `py`, `rs`, `php`) with the value `required`, `planned` or `n/a`;
- `flipped_by`, the label of the work that changes the row;
- an optional `exceptions` list, each `{"id","reason"}`.

The rows are sorted by scope, kind and prefix. A language flips its own gates; it never waits for another SDK.

### Native adapters and sources

The rows of a native adapter (`adapters/<name>` other than `_common`) and of a membership source (`sources/<name>`) are `n/a` for every language until Go prints NDJSON for that adapter's or source's cases. Whether a port implements a native adapter or source is decided per adapter when it lands in Go; `files` (Windows impersonation) stays Go-only. Adapter assets are data that their adapter's cases read, not results, and stay `n/a`.

### Orchestrator rules

`make parity` runs every language's harness, then `parity.py check`:

1. A `required` gate fails on any entry whose result is not `pass`, except a sanctioned skip: `spec-defect` on a flagged vector, `capability` on an entry that lists the missing capabilities (an optional capability the language does not declare), or an `exceptions` entry.
2. A manifest (scope, kind, prefix) without a gate row fails. `ci-spec` runs the same check (`make parity-rows`), so a fixture change cannot merge without classifying its rows for every language.
3. Under an `n/a` gate every entry must be `skipped:out-of-scope` (or `skipped:capability` on a capability entry); a language that reports `pass` or `fail` there fails, since it claims coverage it does not declare.
4. Under a `planned` gate any valid result is accepted and counted in the report.
5. A missing id, a duplicate id, or an id not in the manifest fails.

The rule ids `parity.py` reports for each case are listed in its docstring.

### Self-test

`make parity-selftest` feeds synthetic NDJSON to `parity.py` and must see exit status 1, with the matching rule id, for each of: a wrong outcome under a required gate, a missing id, a manifest prefix without a row, a `skipped:spec-defect` on a vector without the flag, and a `pass` under an `n/a` gate. Further cases cover the other rules of `parity.py`.

## Fixture changes

A change that adds a manifest kind, scope, prefix or entry field updates, in the same change, `gates.json` (rows `planned` or `n/a` per language), every harness's kind table, and the ported manifest modules. The language CI path filters include `spec/v1.0/fixtures/**`, so such a change runs the port harnesses. When a fixture change alters a manifest rule, it adds the rule's mutation case to the shared case table [`tools/spec/manifest-parity-cases.json`](../spec/manifest-parity-cases.json), which the ported manifest modules read.

## API ledger

[`docs/sdk/parity-ledger.md`](../../docs/sdk/parity-ledger.md) has one row per exported symbol of the Go library packages in scope, with its TypeScript name, Python name, status (`planned`, `done`, `deviation`, `SDK extra`) and note, plus per-package name sections for Rust and PHP.

### Scope

The packages that `go list ./core/... ./adapter/... ./adapters/memory ./contract ./gateway ./holder ./runner/manifest ./validator` names in `go/` (`SCOPE` in `api_ledger.py`). A new package under `core/` or `adapter/` enters the scope, and the check, as soon as it exists. The native adapters and `adapters/internal/broken` are outside it.

`api_ledger.py` (standard library) parses `go doc -all` and fails on an exported symbol without a row, a stale or duplicate row, and a malformed row. It runs in `ci-go`.

### Naming rules

The ledger's section [Naming rules](../../docs/sdk/parity-ledger.md#naming-rules) gives the per-language rules. In short: Go initialisms stay one word, upper case inside a TypeScript name (`parseJWK`, `fromJSON`, `JWSError`, `TLSPeer`, `subjectCN`, `rawRequestURI`) and lower case in a Python name (`parse_jwk`, `from_json`); in TypeScript only, `ID` inside a lowerCamel name is written `Id` (`sourceId`, `principalId`, `checkId`); type names keep the Go spelling (`AgentID`, `TLSPeer`); `UPPER_SNAKE` names are unchanged. A port that names a symbol differently changes its row in the same change.

Module paths mirror the Go import paths: TypeScript export subpaths (`./core/jws`, `./adapter/adaptertest`, `./adapters/memory`, `./runner/manifest`) and Python subpackages under `hop_top_pact` (`hop_top_pact.core.jws`, `hop_top_pact.adapter.enroll_memory`). The Python import name is `hop_top_pact`, since `pact` collides with `pact-python`.

### Deviations

Every ledger row a deviation touches has status `deviation` and names it in its note.

| Area | Go | TypeScript | Python |
|---|---|---|---|
| Time precision | nanoseconds | milliseconds | microseconds |
| Raw member values (`core.Object`) | `json.RawMessage` | raw text kept by the in-house tokenizer | parsed immutable values; JCS over the parsed tree equals JCS over the text because strict parse admits only losslessly parsed values |
| Adapter calls | synchronous with `context.Context` | `Promise` with `AbortSignal` | synchronous `Protocol`, no context argument |
| Schema validation module | none in the library | SDK extra | SDK extra |

Time across languages: wire timestamps are integer seconds checked against `0..2^53-1`. TypeScript instants are `number` milliseconds; Python instants are aware UTC `datetime`. Comparisons are exact: an instant is split once into whole seconds (floor) and a sub-second remainder, and a wire integer is compared against that pair. A wire value is never scaled to milliseconds or turned into a date object (`2^53-1` seconds overflows both).

`format: uri`: Go and every port use one in-house RFC 3986 expression, published in [spec/v1.0/fixtures/vectors/schema/README.md](../../spec/v1.0/fixtures/vectors/schema/README.md) and pinned by the vectors of `spec/v1.0/fixtures/vectors/schema/uri-format.json`. It is registered before schema compilation (`RegisterFormat` in Go `pactconf`, `addFormat` in TypeScript, a package `FormatChecker` carrying only `uri` in Python). `ajv-formats` is a TypeScript development dependency only, the in-process oracle for the matcher, expected to differ exactly on the vectors marked `ajv_formats_differs`.

Signatures: Go always writes low-S ES256 signatures; Node and `cryptography` do not, so every port normalizes S on signing (`s > n/2` becomes `n - s`) and accepts high-S on verification, as Go does.

## Adapter contract

The rows of `adapter`, `adapter/enroll`, `adapter/enroll/memory`, `adapter/freshness` and the `adapter/adaptertest` case model are frozen for the ports. `python3 -I tools/parity/api_ledger.py --list` prints the symbols of those packages.

The `adaptertest` case model is the types `Request`, `TLSPeer`, `Subject`, `Env`, `Options`, `Case` and the `Expect*` types, the types their fields reach (`Call`, `RealmJSON`, `PrincipalJSON`, `BindingJSON`, `ObservationJSON`, `ObligationJSON`, `LeakScan`, `Hooks`, `Replacement`), `Factory`, which turns an `Env` into a `Subject`, and `Load`, which reads the cases. A field with a `json` tag reads the case-file member of that name. The suite entry points (`DefaultFixtures`, `Run`, `Evaluate`, `Result`) are outside the frozen set: their port shapes differ by design (`runConformance` and `evaluateConformance` in TypeScript; `run_case`, `conformance_cases` and `evaluate_conformance` in Python), and the ledger tracks them.

A change to a frozen symbol (added, removed, renamed, a changed signature, field type or constant value, or a changed documented behaviour) does, in the same change:

1. update the symbol's ledger rows; a `done` row whose ports no longer match the Go symbol goes back to `planned`, since `done` means both ports have it under those names with its tests ported;
2. bring each port back to the Go symbol, or leave the row `planned` until it does.

An exported symbol added to a frozen package is frozen from the change that adds it. `api_ledger.py` fails when a symbol has no ledger row; the reviewer of a change to these packages checks the rest. The language-neutral adapter case files (`spec/v1.0/fixtures/adapters/`) follow the [fixture changes](#fixture-changes) rule; where a change adds a member, the `adaptertest` field that reads it is a frozen symbol.

`RawRequest` is a port type with no Go symbol: Go passes the `*http.Request`; the ports pass the method, the raw request-target, the ordered header pairs, the body and an optional TLS peer (TypeScript `{method, rawRequestURI, headers, body, tlsPeer?}`; Python `RawRequest(method, raw_request_uri, headers, body, tls_peer=None)`). It is frozen with the contract. Its TLS peer has the attributes of `adaptertest.TLSPeer`: `subjectCN`, `issuerCN`, `dnsNames`, `uris` in TypeScript and `subject_cn`, `issuer_cn`, `dns_names`, `uris` in Python; the case files spell them `subject_cn`, `issuer_cn`, `dns_names`, `uris`. The binding vectors' `request` object (`raw_request_uri`, ordered `headers`, `body_b64`) is the literal wire form of each port's `RawRequest`.

## Mutation checks

Every mutation check is a committed patch under the package's mutants directory: `ts/test/mutants/`, `py/tests/mutants/`, `rs/tests/mutants/`, `php/tests/mutants/`, named `<module>-<name>.patch`. [`tools/mutants.py`](../mutants.py) (standard library):

- copies the package source to a fresh temporary directory per patch, without installed dependencies, caches and build outputs;
- runs the unpatched copy first, which must pass, so a red run means the patch, not the setup;
- applies the patch with `git apply`, runs the package's test command and requires a non-zero exit; a patch whose tests still pass survives, and the run fails naming it;
- never modifies the source tree.

A patch's context lines must match the source it patches: a change to a patched source file updates the patch in the same change, and `make <lang>-mutants` shows that every patch still applies and still fails the tests. The language CI workflows run the mutation targets. The broken-adapter catalogue (`adapters/internal/broken` in Go, `test/broken/` in TypeScript, `tests/broken/` in Python) is the same idea at the adapter level: each defect fails its cases, all defects together fail all cases, no defect passes all, and every case is targeted.
