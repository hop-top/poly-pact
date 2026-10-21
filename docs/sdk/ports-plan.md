# TypeScript and Python ports: shared plan

Status: approved 2026-10-16. Basis: `main` at `6908c33` (270 manifest entries). Per-language detail: [ports-plan-ts.md](ports-plan-ts.md) and [ports-plan-py.md](ports-plan-py.md).

This plan takes the TypeScript and Python SDKs from the core primitives planned so far to parity with the Go library module. It records the scope, the meaning of parity, the command-line decision, the parity mechanism that keeps the ports honest while Go keeps moving, the Go work the ports need first, and the phase order. Paths that do not exist yet are marked "planned".

## 1. Scope

### 1.1 Target

Every package of the Go library module `hop.top/pact-go` (`go/`) gets a module with the same public capability in each port, under the language's idiomatic names. The command module `hop.top/pact` (`cli/`) is covered by the decision in section 4.

| Go package | Capability | Go tests | Port |
|---|---|---|---|
| `core` | wire types (31 `$defs` structs plus the helpers `GatewayEndpoints`, `ReputationDimensions`), 23 string enums, `Digest`, `Object`, `Limits`, `Version`, `DigestLen`, `KeyMax*` | 20 | phase 2 |
| `core/strictjson` | strict decode (13 reasons, RFC 6901 paths) | 14 | phase 2 |
| `core/jcs` | RFC 8785 canonical form | 13 | phase 2 |
| `core/digest` | object, artifact and bytes digests | 11 | phase 2 |
| `core/jws` | ES256 compact JWS profile, JWK, RFC 7638 thumbprint, key resolution, 29 `Reason` values | 35 | phase 2 |
| `core/clock` | time windows and lifetimes | 13 | phase 2 |
| `core/binding` | baseline HTTP mapping, 20 rules | 29 | phase 2 |
| `adapter` | native adapter contract (seven interfaces, value types, codes) | 23 | phase 3 |
| `adapter/enroll`, `adapter/enroll/memory` | enrollment registry contract and in-memory registry | 4, 28 | phase 3 |
| `adapter/freshness` | age limits and re-stamp guard | 17 | phase 3 |
| `adapter/adaptertest` | adapter conformance suite (88 common cases) | 40 | phase 3 |
| `adapters/memory` | reference adapter over the `common/1` state | 29 | phase 3 |
| `adapters/internal/broken` | 83-defect proof that the suite can fail | 6 | phase 3, test tree only |
| `runner/manifest` | manifest reading, 30 rules, spec-map checks | 31 | phase 2 (module), phase 4 (parity join) |
| `runner` | conformance runner library behind `pactc` | 25 | not ported (section 4) |
| `internal/depcheck` | dependency guard | 2 | phase 1 |

Test counts are from `go test -list` at the basis commit; the case, defect and rule counts are those of `main` at `8f33d10`. The `jws.Reason` and enum tables are generated or copied from the Go files (`go/core/jws/errors.go`, `go/core/enums.go`), never from a count in this document.

### 1.2 Out of scope until Go lands them

Native adapters other than `memory`, the task ledger, the single-owner profile, transport (stdio, IPC, peer credentials), MCP, and runner verbs beyond those that exist. Section 6 says how each joins once Go has it.

### 1.3 Rust and PHP

The Rust and PHP SDKs are core-only. Adapter-scope gates are `n/a` for them: they implement no adapter contract, no adapter suite and no HTTP binding. They follow the same gates file, result grammar and ledger, so adapter support would be a column change, not a redesign. The PHP SDK passes every core vector, key and schema entry; its gates are `required` for those rows and `n/a` for every other row.

The Rust and PHP SDKs have landed in `rs/` (crate `hop-top-pact`) and `php/` (package `hop-top/pact`): their key, vector and schema-case gates are `required` in `tools/parity/gates.json`, and their names are in the ledger's [Rust](parity-ledger.md#rust) and [PHP](parity-ledger.md#php) sections.

## 2. What parity means

A port is at parity with Go for a capability when all of these hold:

1. **Same capability.** The ledger (section 5.5) maps every exported Go symbol to a name in each port, or records a deviation.
2. **Same shared evidence.** Every manifest entry whose gate is `required` for the language passes in that language's vectors harness or adapter suite.
3. **Same unit-test matrix.** The Go unit tests are ported one-to-one under the same names, including the tests that read `spec/v1.0/draft.md`, the schema or the profile documents at test time.
4. **Same mutation proofs.** The broken-adapter catalogue and the per-module mutation patches (section 5.6) show that the tests fail when the behaviour is broken.

Documented deviations (each has a ledger row):

| Area | Go | TypeScript | Python |
|---|---|---|---|
| Time precision | nanoseconds | milliseconds | microseconds |
| Raw member values (`core.Object`) | `json.RawMessage` | raw text kept by the in-house tokenizer | parsed immutable values; JCS over the parsed tree equals JCS over the text because strict parse admits only losslessly parsed values |
| Adapter calls | synchronous with `context.Context` | `Promise` with `AbortSignal` | synchronous `Protocol` |
| Schema validation module | none in the library | SDK extra | SDK extra |

## 3. Decisions

Owner decisions of 2026-10-16. Each replaces an open question of the draft plan.

| Topic | Decision |
|---|---|
| Scope | 1-1 parity is the committed target, in the phase order of section 8. The adapter contract, conformance suite, memory adapter, broken proof, manifest and case loader are tasks, not a roadmap. |
| Command line | Go `pactc` is the single cross-language runner; `pactconf` and `pactfix` stay Go-only. The ports ship the manifest module, the vectors harness and a case loader (section 4). Go emits the same NDJSON as the ports for the core and adapter scopes (section 5.1). |
| HTTP baseline binding | Included in phase 2 as its own task per language. The binding vectors keep `scope: adapter`. The vectors' `request` object (`raw_request_uri`, ordered `headers`, `body_b64`) is the literal wire form of each port's `RawRequest`. |
| Schema validation module | Kept as an SDK extra with a ledger row. It accepts only values that came through the port's strict parser. The vectors harness applies Go's `decode_as` rule (strict typed decode plus the `pact_version` constant), so no verdict depends on the validator; a typed-decode failure is reported as `payload-schema`, as Go's vector tests do. |
| `format: uri` | One in-house RFC 3986 expression in Go and both ports, derived from the `ajv-formats` 3.0.1 `uri` expression (MIT, attributed in the source) with ASCII classes in place of the case-insensitive flag and two deviations (an empty path without authority accepted, RFC 3986 section 3; `//` always opens the authority, sections 3 and 3.3), registered before compilation (`RegisterFormat` in Go `pactconf`; `addFormat` in TypeScript; a package `FormatChecker` carrying only `uri` in Python). The expression is published in [spec/v1.0/fixtures/vectors/schema/README.md](../../spec/v1.0/fixtures/vectors/schema/README.md). `ajv-formats` stays as a TypeScript development dependency, the in-process oracle for the matcher, expected to differ exactly on the vectors marked `ajv_formats_differs`. No `rfc3986-validator`. A shared vector file pins all three (section 7). |
| Time | Wire timestamps are integer seconds checked against `0..2^53-1`. TypeScript instants are `number` milliseconds; Python instants are aware UTC `datetime`. Comparisons are exact: an instant is split once into whole seconds (floor) and a sub-second remainder, and a wire integer is compared against that pair. A wire value is never scaled to milliseconds or turned into a date object (`2^53-1` seconds overflows both). |
| Toolchain floors | Node `>=22.18`, CI matrix `{22, 24, 26}`. Python `>=3.11` (forced by `rpds-py`, `StrEnum`, `tomllib`), CI matrix `{3.11, latest 3.x}`. |
| Go case loader | A Go library package for the evaluation-case layout lands first (section 7); the ports' loaders mirror it. |
| Adapter contract freeze | Declared before phase 3 starts (section 5.5). Later Go changes go through the ledger and a port task. Pre-release breaking changes stay allowed; they become visible. |
| Manifest-rule parity | The standard-library scripts under `scripts/` stay the independent oracle. The mutation case table moves to a JSON file; the ported manifest modules check it from their own test suites, never from `ci-spec`. |
| Publishing the adapter suite | `adapters/memory` and `adapter/adaptertest` are published in both packages; the broken catalogue stays in the test tree. No published module imports a test framework. |
| Gate graduation | Per language, per gate. A language flips its own gates; it never waits for another SDK. Each package README's supported-kinds table is generated from the gates file. |
| Further native adapters | Decided per adapter when it lands in Go, from the phase-6 template. First candidates `basic`, `oauth`, `mtls`, `abac`, `rebac`; `files` (Windows impersonation) stays Go-only. |
| This document | Committed as this file and the two language files. It replaces the planned adapter-SDK roadmap document. |

## 4. Command-line decision

Option A, porting `pactc`, `pactconf` and `pactfix`, was rejected. Three runners could disagree on a verdict with no fixture to pin the disagreement. The kit console framework that gives the Go commands their tree, help and exit contract exists for TypeScript as a CommonJS package with 18 runtime dependencies (one native) and for Python with typer, rich, pydantic, structlog, jinja2 and more, against SDKs with two and three runtime dependencies. And `pactfix generate` in three languages would re-sign fixtures with fresh random nonces, churning committed bytes.

Option B is adopted. `pactc` drives an implementation in any language through argv templates and never links it. Each port ships:

- the manifest module (needed by its own harness and by the manifest-rule parity check);
- the vectors harness (`make ts-vectors`, `make py-vectors`), the counterpart of `pactconf vectors verify`;
- a case loader that reads an evaluation case directory into typed values and verifies its signed artifacts against the trust records, plus a `tool evaluate {dir}` skeleton, so a future validator in that language runs under `make conformance PACTC_ARGS=...`.

Owner rule of 2026-10-19: an SDK package never depends on the kit console framework. A user-facing command-line tool that a port ships later is a separate package built on the kit console framework of that language. The internal entry points that `make` or `pactc` drive (the vectors harness, the manifest check, the `tool evaluate {dir}` skeleton) take plain argv and use no command-line framework.

Outside the source repository, `pactc` installs as `go install hop.top/pact/pactc@vX.Y.Z` once the command module is tagged (see [cli/README.md](../../cli/README.md)), and runs against the spec mirror's fixture tree.

## 5. Parity mechanism

### 5.1 Result grammar and the Go legs

Every harness prints one NDJSON line per manifest entry: `{"id","kind","result"}`, with

```
result ::= "pass" | "fail" | "skipped:" reason
reason ::= "out-of-scope" | "spec-defect" | "os-layer" | "capability"
```

- `spec-defect` is valid only for a vector whose file sets `spec_defect: true` (the digest protocol of [spec/v1.0/fixtures/vectors/digest/README.md](../../spec/v1.0/fixtures/vectors/digest/README.md)); the line also carries both values.
- `os-layer` is reserved for the manifest `layer` field planned by the manifest-fields work.
- `capability` is for an entry whose manifest `capabilities` ([spec/v1.0/fixtures/README.md](../../spec/v1.0/fixtures/README.md), section Optional capabilities) are not all declared by the harness run (`pactconf vectors verify --capability NAME`, repeatable); the entry is not run, and the line also carries `missing_capabilities`, the undeclared ones, for example `{"id":"…","kind":"vector","result":"skipped:capability","missing_capabilities":["jws-ed25519"]}`. A scope `runner` entry stays `skipped:out-of-scope`.
- A harness prints nothing else on standard output.

The Go side produces the same lines from three legs:

| Leg | Entries | Producer |
|---|---|---|
| vectors, keys and schema cases | every `vector`, `key` and `schema` entry of scope `core` and `adapter`; scope `runner` vectors print `skipped:out-of-scope`, matching the `pactconf` SKIP | `pactconf vectors verify --ndjson --capability jws-ed25519` |
| adapter cases | every `adapters/_common` case, from `adaptertest.Evaluate` on `adapters/memory` | the test binary of `adapters/memory`, built with `go test -c` and run with `-ndjson` (a command binary does not import `testing`) |
| runner | scope `runner` entries of kind `evaluate`, `outcomes` and `learning`, from the `pactc/v1` report that `make conformance` writes: against the fake implementation `go/runner/testdata/fakeimpl/impl.sh`, or against the implementation `PACTC_ARGS` names | `make parity` passes the report to `tools/parity/parity.py check` as `--runner-report go=FILE`: `PASS` is `pass`, `FAIL` is `fail`, `SKIP` is `skipped:capability` when the entry lists a capability the report does not declare and `skipped:out-of-scope` otherwise; a report whose manifest check is not `PASS` fails |

`make go-vectors` runs the first two legs. An entry that no Go leg prints (a native adapter case outside `adapters/_common`, an adapter asset, a `profile-invalid` entry) is recorded `skipped:out-of-scope` by `--fill-na go` where its gate is `n/a` for Go, and is missing under any other gate.

### 5.2 Entry handling in every harness

- Kinds and scopes are a closed set: the 13 kinds and 3 scopes of `runner/manifest` (`Kinds()`, `Scopes()`). An unknown kind or scope fails the harness.
- Scope `runner`: always `skipped:out-of-scope`. Runner-scope entries belong to `pactc` and an implementation under test (this covers the `admission`, `approval` and `outcomes` evaluation groups and the `reputation/beta-decay-v1` vectors).
- Scope `core` and `adapter`: the harness must know the entry's prefix (section 5.3). An unknown prefix fails the harness.
- `key` entries: every P-256 JWK parses, and its public point equals `scalar × G` for its scalar in `keys/test-private-scalars.json`; the holder thumbprint equals Appendix C `holder_jkt`; `test-private-scalars.json` passes once every derivation holds; `keys/ed25519` is `skipped:out-of-scope` (Ed25519 is optional in draft section 7.2) and is listed as an exception of its gate row. Go's leg applies the same rule.
- Exit status: non-zero on a harness error (unreadable or malformed manifest, unknown kind, scope or prefix), and on a `fail` under a gate that is `required` for the language. A `fail` under a `planned` gate is printed and counted, so red work can merge while `main` stays green.

### 5.3 Gates file

`tools/parity/gates.json` has one row per (scope, kind, prefix). The prefix is the entry id's first segment, the fixture group as [spec/v1.0/spec-map.md](../../spec/v1.0/spec-map.md) defines it, except under `vectors/`, `adapters/` and `sources/`, where it is the first two segments (`vectors/jcs`, `adapters/_common`, `sources/scim`) because those groups hold independent families. Each row has a column per language (`go`, `ts`, `py`, `rs`, `php`) with the value `required`, `planned` or `n/a`, the label of the work that flips it, and an optional `exceptions` list (entry id and reason).

Rows on `main` at `8f33d10` (1211 manifest entries, every (scope, kind, prefix) with a row; the `core/key/keys` row lists `keys/ed25519` as an exception), with the `rs` and `php` columns as the Rust and PHP SDKs set them:

| Row | Entries | `go` | `ts`, `py` | `rs` | `php` | Flipped by |
|---|---|---|---|---|---|---|
| `adapter/adapter-asset/adapters/abac` | 1 | n/a | n/a | n/a | n/a | none: an asset is data read by its adapter's cases, not a result |
| `adapter/adapter-asset/adapters/aws` | 2 | n/a | n/a | n/a | n/a | none: an asset is data read by its adapter's cases, not a result |
| `adapter/adapter-asset/adapters/basic` | 1 | n/a | n/a | n/a | n/a | none: an asset is data read by its adapter's cases, not a result |
| `adapter/adapter-asset/adapters/db` | 1 | n/a | n/a | n/a | n/a | none: an asset is data read by its adapter's cases, not a result |
| `adapter/adapter-asset/adapters/k8s` | 1 | n/a | n/a | n/a | n/a | none: an asset is data read by its adapter's cases, not a result |
| `adapter/adapter-asset/adapters/ldap` | 4 | n/a | n/a | n/a | n/a | none: an asset is data read by its adapter's cases, not a result |
| `adapter/adapter-asset/adapters/rebac` | 2 | n/a | n/a | n/a | n/a | none: an asset is data read by its adapter's cases, not a result |
| `adapter/adapter-case/adapters/_common` | 88 | required | required | n/a | n/a | memory adapter task |
| `adapter/adapter-case/adapters/abac` | 85 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/aws` | 66 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/basic` | 28 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/db` | 19 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/files` | 52 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/graph` | 61 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/k8s` | 63 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/ldap` | 45 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/mtls` | 71 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/oauth` | 227 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/rebac` | 33 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/adapter-case/adapters/saml` | 35 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this adapter's cases; ports: a per-adapter decision (section 3) |
| `adapter/source-case/sources/googledir` | 14 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this source's cases; ports: a per-source decision (section 3) |
| `adapter/source-case/sources/scim` | 14 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this source's cases (they run as `go test` in `adapter/source/scim` today); ports: a per-source decision (section 3) |
| `adapter/source-case/sources/ssf` | 25 | n/a | n/a | n/a | n/a | Go: an NDJSON printer for this source's cases; ports: a per-source decision (section 3) |
| `adapter/vector/vectors/binding` | 27 | required | required | n/a | n/a | core binding task |
| `core/key/keys` | 12 | required | required | required | required | core JWS task |
| `core/schema/parse` | 1 | required | planned | required | required | schema harness of each port ([spec/v1.0/fixtures/schema/README.md](../../spec/v1.0/fixtures/schema/README.md)) |
| `core/schema/schema` | 1 | required | planned | required | required | schema harness of each port ([spec/v1.0/fixtures/schema/README.md](../../spec/v1.0/fixtures/schema/README.md)) |
| `core/vector/vectors/digest` | 1 | required | required | required | required | core primitives task |
| `core/vector/vectors/jcs` | 7 | required | required | required | required | core primitives task |
| `core/vector/vectors/jws` | 70 | required | required | required | required | core JWS task |
| `core/vector/vectors/schema` | 1 | required | required | required | required | schema module task (format: uri) |
| `core/vector/vectors/strictjson` | 36 | required | required | required | required | core primitives task |
| `runner/evaluate/admission` | 37 | required | n/a | n/a | n/a | an implementation under test |
| `runner/evaluate/approval` | 13 | required | n/a | n/a | n/a | an implementation under test |
| `runner/evaluate/delegation` | 8 | required | n/a | n/a | n/a | an implementation under test |
| `runner/evaluate/selection` | 10 | required | n/a | n/a | n/a | an implementation under test |
| `runner/learning/learning` | 15 | required | n/a | n/a | n/a | an implementation under test |
| `runner/outcomes/delegation` | 1 | required | n/a | n/a | n/a | an implementation under test |
| `runner/outcomes/outcomes` | 25 | required | n/a | n/a | n/a | an implementation under test |
| `runner/outcomes/reputation` | 3 | required | n/a | n/a | n/a | an implementation under test |
| `runner/profile-invalid/profiles` | 4 | n/a | n/a | n/a | n/a | tooling only (`pactconf profile validate`) |
| `runner/vector/reputation` | 1 | n/a | n/a | n/a | n/a | an implementation under test |

Orchestrator rules (`make parity`):

1. A `required` gate fails on any entry whose result is not `pass`, except a sanctioned skip: `spec-defect` on a flagged vector, `capability` on an entry that lists the missing capabilities (an optional capability the language does not declare), or an `exceptions` entry.
2. A manifest (scope, kind, prefix) without a gate row fails. `ci-spec` runs the same check, so a fixture change cannot merge without classifying its rows for every language.
3. Under an `n/a` gate every entry must be `skipped:out-of-scope` (or `skipped:capability` on a capability entry); a language that reports `pass` or `fail` there fails (it claims coverage it does not declare).
4. Under a `planned` gate any result is accepted and counted in the report.
5. A missing id, a duplicate id, or an id not in the manifest fails.

`make parity-selftest` feeds synthetic NDJSON and must exit 1 for each of: a wrong outcome under a required gate, a missing id, a manifest prefix without a row, a `skipped:spec-defect` on a vector without the flag, and a `pass` under an `n/a` gate.

### 5.4 Fixture changes and the gates

A change that adds a manifest kind, scope, prefix or entry field updates, in the same change, `gates.json` (rows `planned` or `n/a` per language), every harness's kind table, and the ported manifest modules. The `ci-ts` and `ci-py` path filters include `spec/v1.0/fixtures/**`, so such a change runs the port harnesses. When a fixture change alters a manifest rule (as fixture format v2 does, section 6), it adds the rule's mutation case to the shared JSON case table, which the ported manifest modules read.

### 5.5 Ledger and freeze

- **API ledger** [`docs/sdk/parity-ledger.md`](parity-ledger.md): one row per exported symbol of the Go library packages (`go/core/...`, `go/adapter/...`, `go/adapters/memory`, `go/contract`, `go/gateway`, `go/holder`, `go/runner/manifest`, `go/validator`), with its TypeScript name, Python name, status (`planned`, `done`, `deviation`, `SDK extra`) and note. `tools/parity/api_ledger.py` (standard library) parses `go doc -all` and fails on an exported symbol without a row; it runs in `ci-go`.
- **Adapter contract freeze** [`docs/sdk/adapter-contract-freeze.md`](adapter-contract-freeze.md): the exported symbols of `go/adapter`, `go/adapter/enroll`, `go/adapter/enroll/memory`, `go/adapter/freshness`, and the `adaptertest` case model (`Request`, `TLSPeer`, `Subject`, `Env`, `Options`, `Case`, the `Expect*` types), with the design decisions they rest on ([docs/design/adapter-inputs-and-attribute-sources.md](../design/adapter-inputs-and-attribute-sources.md)). It is written before phase 3; after it, a change to a listed symbol updates the ledger and opens a port task.

### 5.6 Mutation patches

Every mutation check named in a task is a committed patch: `ts/test/mutants/<module>-<name>.patch` and `py/tests/mutants/<module>-<name>.patch` (planned). `tools/mutants.py` (planned, standard library) copies the package source to a temporary directory, applies each patch, runs the package's test command and requires a non-zero exit. `make ts-mutants` and `make py-mutants` run it; it runs nightly and on the pull request that adds a patch. The broken-adapter proof is the same idea at the adapter level.

## 6. Moving Go target: work in flight

| Go or fixture work | Effect on the ports | Handled by |
|---|---|---|
| Admission, approval and outcome-mapping cases (landed) | runner scope: `skipped:out-of-scope`; gate rows `n/a` | sections 5.2, 5.3 |
| `reputation/beta-decay-v1` vectors (landed; `pactconf` skips scope-runner vectors in groups it has no runner for) | the ports skip them the same way; Go's NDJSON prints `skipped:out-of-scope` | sections 5.1, 5.2 |
| Fixture format v2 (design pending) | the generator reads a per-case `signing.json` instead of its built-in case list; expected files move under `expected/<id>/` with a new manifest coverage rule; evaluate prints one line per submission | the Go case-loader package lands after the generator v2 and reads v1 and v2 cases; the coverage rule enters the ported manifest modules through the shared case table (section 5.4) |
| Manifest fields `profiles`, `transport`, `layer` and kinds `transport`, `mcp`, `profile` (planned) | the strict manifest loaders reject unknown members; the harnesses fail on unknown kinds | same-change rule of section 5.4; `os-layer` reserved in the grammar |
| Native adapters | new `adapters/<name>` prefixes, `n/a` or `planned` per language | phase-6 template |
| Schema delta (planned) | regenerated types in every port | the schema-drift tests fail until the generator is re-run |
| Transport, peer credentials, MCP (planned) | later phases; vectors first | the transport and adapter SDK roadmap |
| Adapter contract changes | port tasks | freeze and ledger (section 5.5) |

## 7. Go-side prerequisites

These land in Go or in shared tooling; the ports depend on them.

| Work | Deliverable | Acceptance | Needed by |
|---|---|---|---|
| Go NDJSON legs | `pactconf vectors verify --ndjson [manifest]`; the adapter-case printer test; `make go-vectors` | one line per `core` and `adapter` `vector` and `key` entry, the key rule of section 5.2, nothing else on stdout; a `spec_defect` vector prints `skipped:spec-defect`; scope-runner vectors print `skipped:out-of-scope`; one line per `adapter-case` id; mutation: a vector forced to fail in a scratch copy prints `fail` | the ci-parity orchestrator, the parity proof |
| Evaluation-case loader | a library package in the Go module (for example `go/runner/evalcase`; distinct from the adapter case files that `adaptertest` reads), extracted from `pactfix generate` (`decoded`, `verifies`, `loadSigners` in `cli/pactfix/generate.go`) after the generator v2 lands | `pactfix generate` uses it; it loads every committed v1 and v2 case and verifies every signed artifact; a case with a stale signature fails | the ports' case loaders |
| API ledger | `docs/sdk/parity-ledger.md`, `tools/parity/api_ledger.py`, a `ci-go` step | every current exported symbol has a row; removing a row makes the check red | the freeze |
| Adapter contract freeze | `docs/sdk/adapter-contract-freeze.md` | lists the symbols of section 5.5; ledger rows complete for the adapter packages | phase 3 in both ports |
| Shared manifest case table | the mutation cases of `scripts/check-manifest-parity.py` moved to `tools/spec/manifest-parity-cases.json`; the script accepts extra checkers on its command line | the script's own results are unchanged; an edit to the case file is seen by the script and by the ported suites | the ported manifest modules |
| `uri` format vectors | `spec/v1.0/fixtures/vectors/schema/uri-format.json` (accept and reject strings for `format: uri` per RFC 3986), registered as `vector`, scope `core`, gate row `core/vector/vectors/schema`; `pactconf vectors verify` runs the group with the command module's JSON Schema library with format assertion and the shared `uri` expression registered in place of the library's checker, which accepts characters outside RFC 3986 | expected values come from the RFC 3986 grammar (sections 2.1, 2.3, 3.2.3, 3.3), including the five discriminating strings recorded in [deps-ts.md](deps-ts.md); the vectors mark the rows where `ajv-formats` 3.0.1 as published differs | the ports' schema modules |
| ci-parity orchestrator | `.github/workflows/ci-parity.yml`, `tools/parity/parity.py`, `tools/parity/gates.json` built per section 5.3 from the start (no per-language `required` flag), the `ci-spec` row check, the selftest of section 5.3 | as in section 5.3 | the parity proof |

## 8. Phases

Both ports follow the same phases, so the gates flip for both languages together where possible. Every task: tests first, the red run attached to the pull request, mutation patches before merge, no tracking identifiers in the repository, one pull request per task. Sizes: S up to 1 day, M 2 to 4 days, L 1 to 2 weeks.

| Phase | Content | Exit |
|---|---|---|
| 0 | dependency vet completion; probes of the remaining unknowns | vet and probe records committed |
| 1 | scaffold: layout, exports, generator script, dependency guard, harness entry, mutants runner wiring, CI | lint, test, build and schema checks green with no functional tests |
| 2 | core: harness (red), types, primitives, JWS, binding, manifest module | core and binding gates `required`; manifest module in the harness |
| 3 | adapter contract, conformance suite, memory adapter, broken catalogue | `adapters/_common` gate `required` |
| 4 | case loader and `tool evaluate {dir}` skeleton | skeleton runs under `pactc` and fails cleanly |
| 5 | docs, cross-language proof | README tables generated; proof report committed |
| 6 | repeatable: one task per Go capability that lands | its gate row flipped |

Task order inside each port (detail and acceptance in the language files):

```
vet ─► scaffold ─► harness ─► core-types ─► core-primitives ─┬─► core-jws ─┬─► core-binding ─► adapter-contract ─► adaptertest ─► memory-adapter ─► broken-mutants
                                                             │             └─► iut-case (also needs the Go case loader)
                                                             └─► manifest (also needs the shared case table)
probe-2 (after vet) ─► core-types
uri vectors ─► core-primitives          adapter freeze ─► adapter-contract
docs after memory-adapter and iut-case
```

Shared tasks:

| Task | Change |
|---|---|
| ci-parity orchestrator | built on the gates file and result grammar of section 5; Go legs per section 5.1; depends on the Go NDJSON legs |
| parity proof (core) | compares per gate: every entry under a gate `required` for a language passes there; no entry under an `n/a` gate is run; covers the core and binding rows for TypeScript and Python and the core rows for Rust and PHP; mutation checks: flip one expected outcome in a manifest copy (parity exits 1 naming the id), make one SDK accept a duplicate-key document (parity exits 1 naming the vector and language); report lists counts per gate |
| parity proof (adapter) | after both broken catalogues land; it flips no gate: each language's memory adapter task already made `adapters/_common` `required` for TypeScript and Python (`tools/parity/gates.json`); mutation checks: flip the `expect.outcome` of one adapter case in a scratch copy (both ported suites fail naming the case), disable one mutant in a ported broken catalogue (its proof fails) |
| transport and adapter SDK roadmap | keeps the later phases; its graduation rule becomes the per-language gate flip of this plan; the per-language peer-credential probes are its first tasks |
| release rehearsal and publish map | the first npm publish is checked as public (`publishConfig.access`); the Python publish entry's test command installs with the constraints file |

## 9. Risks

| Risk | Mitigation |
|---|---|
| Adapter contract still moving (decision provenance fields landed 2026-10-16; `check_context` inputs, principal and binding, landed 2026-10-18) | freeze before phase 3, ledger check in `ci-go` |
| Fixture format v2 reshapes evaluation cases | Go case loader after the generator v2; the ports mirror it |
| A port claims coverage it does not have | gates rule 3; README tables generated from the gates file |
| Mutation checks done by hand and lost | committed patches, nightly runner |
| Signature form differs (Go always writes low-S; Node and `cryptography` do not) | low-S normalization is a stated requirement with a sign test and a mutation patch in both ports |
| `format: uri` semantics differ between ports | one matcher expression, one vector file, a Go column |
| Two manifest checkers drift from the oracle scripts | shared JSON case table read by all checkers |
| Mirror checkouts lack `spec/` | `PACT_REQUIRE_VECTORS=1` in the source repository; a notice only in a mirror |
