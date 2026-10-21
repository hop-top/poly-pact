# Conformance fixtures

This directory holds the language-neutral conformance fixtures of PACT: test keys, test vectors, adapter cases and evaluation cases, each with the result the draft requires. The Go conformance runner and the test harnesses of every SDK read the same files. [`manifest.json`](manifest.json) lists every fixture; no consumer walks the directory tree to find one.

This README defines the layout, the manifest and the per-case files that every fixture task uses. The groups that have their own format describe it in their own README:

| Directory | Contents | Format |
|---|---|---|
| `keys/` | Public test keys of Appendix C and eight more roles | [keys/README.md](keys/README.md) |
| `vectors/jcs/` | RFC 8785 canonicalization vectors | [vectors/jcs/LICENSE-NOTE.md](vectors/jcs/LICENSE-NOTE.md) |
| `vectors/digest/` | Section 7.4 digest vectors | [vectors/digest/README.md](vectors/digest/README.md) |
| `vectors/jws/` | Section 7.2 and 7.3 JWS profile vectors | [vectors/jws/README.md](vectors/jws/README.md) |
| `vectors/strictjson/` | Section 7.1 strict-parse vectors | one vector per file: `id`, `input_text` or `input_b64`, `expect`, `reason` |
| `vectors/binding/` | Section 10.2 baseline HTTP mapping vectors | [vectors/README.md](vectors/README.md) |
| `vectors/schema/` | Appendix A.3 JSON Schema format `uri` vectors (RFC 3986) | [vectors/schema/README.md](vectors/schema/README.md) |
| `adapters/` | Native adapter cases of Section 17.1 | [adapters/README.md](adapters/README.md) |
| `parse/`, `schema/` | Schema cases: compact JWS and decoded objects against the Appendix A.3 schema | [schema/README.md](schema/README.md) |
| `<group>/<case>/` | Evaluation, outcomes and learning cases, with results under `expected/` | this file; format v2 in section Format v2 |

The canonical case groups (`admission`, `approval`, `selection`, `delegation`, `outcomes`, `reputation`, `learning`, `privacy`, `containment`, `capacity` and `parse`), the other groups, the status of each group and the fixture ids reserved for them are listed in [../spec-map.md](../spec-map.md).

## Neutrality

`spec/` is mirrored to `hop-top/spec-pact` as the root of that repository, so this directory is `v1.0/fixtures/` there, and the TypeScript, Python, Rust and PHP harnesses read it there. It therefore holds only language-neutral files:

- `.json`, `.yaml` and `.md` files, and `.jws` files, each holding one compact JWS as ASCII text (the generator writes them without a trailing newline);
- `.sql`, `.rego`, `.fga` and `.ldif` files, which an external service consumes verbatim, only inside the path of a manifest entry of kind `adapter-asset`.

Extensions are lowercase, exactly as listed: `config.JSON` and `schema.SQL` are on neither list.

No source code, scripts or build files. The fixture generator and the cross-checks live in the source repository, outside the mirrored tree. Inputs that are not valid JSON text, such as invalid UTF-8 or duplicate member names, are stored as base64 inside a JSON file.

## Manifest

`manifest.json` is one JSON object, `{"manifest_version": 1, "entries": [...]}`, with the entries sorted by `id` (byte order). [`manifest.schema.json`](manifest.schema.json) is its JSON Schema (2020-12). `manifest_version` is written `1`: JSON Schema compares numbers by value, so the schema also accepts `1.0` and `1e0`, but the checks below read the number as written and reject them, as intended. Every entry has these members, all required except `capabilities`, `conformance_profile`, `transport` and `layer`:

| Member | Value |
|---|---|
| `id` | Unique fixture id: two segments `<group>/<case>`, or three `<group>/<subgroup>/<case>` for groups that nest, such as `admission/valid`, `keys/holder` or `outcomes/qualification/correction-recompute`. A segment is one or more runs of lowercase letters and digits joined by single hyphens, so it neither starts nor ends with a hyphen and has no two hyphens in a row. Only adapter case ids (kind `adapter-case`), which follow their file names, also allow a segment that starts with `_` and runs joined by a single `.`. An adapter case is the file `adapters/<adapter>/<case>.json` with the id `adapters/<adapter>/<case>`, the same shape for every adapter as for `adapters/_common`; there is no `cases/` subdirectory. A source case id (kind `source-case`) follows its file name likewise: the file `sources/<source>/<case>.json` has the id `sources/<source>/<case>`, whose case segment also allows runs joined by a single `.`. |
| `kind` | What the entry is, which also says which harness verb runs it: `key`, `vector`, `schema`, `evaluate`, `outcomes`, `learning`, `adapter-case`, `adapter-asset`, `source-case`, `profile-invalid`, `transport`, `mcp` or `profile` (section Manifest entry fields). |
| `scope` | Who must pass it: `core` (every language harness), `runner` (only the Go conformance runner) or `adapter` (the adapter conformance harnesses). An entry of kind `transport` or `profile` has scope `runner`, one of kind `mcp` or `source-case` scope `adapter`. |
| `path` | The case directory or the single file of the entry. For an adapter case or a source case, its id followed by `.json`. |
| `expected` | The file that holds the expected result. It equals `path` when that file carries its expectations inline. `null` for `key`, `adapter-asset` and `source-case` entries. |
| `outcome` | One token summarizing the expected result: a decision (`ADMISSIBLE`, `INADMISSIBLE`, `DEFERRED`), `ACCEPTED`, `REJECTED`, a qualification result of draft Section 14.3 (`QUALIFIED`, `UNQUALIFIED`, `DISPUTED`), or `MATCH` for a value comparison. `null` for `key`, `adapter-asset` and `source-case` entries. |
| `spec_map_row` | The `ID` of the row of [../spec-map.md](../spec-map.md) that the entry supports. |
| `draft_section` | The draft section the entry tests, as a string: a section number such as `"11.3"` or an appendix letter such as `"C"`. |
| `capabilities` | Optional. The optional capabilities the entry tests: an array of one or more distinct tokens of section Optional capabilities below. An entry without it is mandatory. |
| `conformance_profile` | Optional. The conformance profiles the entry runs under; absent means `["full"]` (section Manifest entry fields). |
| `transport` | Optional. The transport profiles the entry exercises; absent means `["https"]` (section Manifest entry fields). |
| `layer` | Optional. `transcript` or `os`, only on an entry whose `transport` has `stdio-ipc`; absent means every layer (section Manifest entry fields). |

Paths are relative to this directory and use `/` between segments, with no leading `/`. A segment is ASCII letters, digits, `.`, `_` and `-`, and does not start with `.`, so there is no empty, `.` or `..` segment. Paths therefore resolve in the source repository and in the mirror alike.

### Optional capabilities

Draft Section 22.1 lists the mandatory capabilities of each conformance role, and Section 22.2 requires a role implementation to pass all applicable cases before it claims conformance. A feature the draft makes optional, such as Ed25519 negotiation (Section 7.2: `Ed25519` MAY be negotiated), is applicable only to an implementation that implements it. An entry that tests such a feature names it in `capabilities`. An entry without `capabilities` applies to every implementation of its role; an entry with it applies only to an implementation that declares every capability it lists. A harness judges an entry only when the implementation declares its capabilities, and otherwise reports it `SKIP` with the capabilities that are missing. A skipped entry is never counted as passed: a conformance claim that includes an optional capability needs the entries of that capability to pass.

| Token | Capability | Draft |
|---|---|---|
| `jws-ed25519` | `Ed25519` (RFC 9864) negotiated explicitly for signed artifacts, with RFC 8037 keys; the gateway publishes it in `GatewayMetadata.jws_algorithms`. | 7.2, 13.1 |

### Manifest entry fields

Three optional members say under which conformance profile and over which transport an entry runs. Each has a default, so an entry written without them needs no edit:

| Member | Value | Absent means |
|---|---|---|
| `conformance_profile` | An array of one or more distinct conformance profile ids, the entries of kind `conformance` in [../profiles/registry.json](../profiles/registry.json): `full` and `single-owner` (draft Section 22.1). | `["full"]` |
| `transport` | An array of one or more distinct transport profile ids, as in `claim.transport` of [../profiles/integration-profile.schema.json](../profiles/integration-profile.schema.json): `https`, the HTTPS baseline (draft Section 13), which has no registry entry, and `stdio-ipc`, the local IPC and stdio profile of draft Section 13.3, the entry of kind `transport` in [../profiles/registry.json](../profiles/registry.json). | `["https"]` |
| `layer` | `transcript` or `os`. Only on an entry whose `transport` contains `stdio-ipc`; required on an entry of kind `transport`; an entry with `layer` and no `transport` has the default `["https"]` and breaks this rule. | every layer |

A run under a conformance profile executes only the entries that list that profile, and an entry without `conformance_profile` lists `full`. No entry runs under a profile silently: an entry that does not list the profile of the run is not applicable to it and is never reported `PASS` in it. A run over a set of transports likewise executes only the entries whose `transport` shares one with the set. A transport is identified as every profile is, by its id (draft Section 21; [../profiles/README.md](../profiles/README.md)). The channels within `stdio-ipc`, such as standard input and output, a socket or a named pipe, are not a manifest field.

`layer` says who executes an entry over `stdio-ipc`; an entry without `layer` applies to every layer:

- `transcript`: a language-neutral sequence of frames that the runner executes, with the facts about the peer supplied through the test seam that the transcript format documents.
- `os`: the entry needs real operating-system facilities, such as a second user, a user namespace or handle inheritance, and a language-specific harness executes it. The harnesses of other languages report it `skipped:os-layer`.

Three kinds hold the entries of the local transports and of the profiles, each with one scope and never `core`:

| Kind | Entries | Scope |
|---|---|---|
| `transport` | Transport transcripts | `runner` |
| `mcp` | MCP adapter vectors and cases | `adapter` |
| `profile` | Conformance-profile cases | `runner` |

The non-Go SDK harnesses and the parity orchestrator select entries by scope, so they report all three kinds `skipped:out-of-scope`, identically in all four SDKs.

Entries of kind `source-case` are the cases of a membership or status source that is not an adapter (a SCIM 2.0 service provider, a directory push channel, a Shared Signals receiver), under `sources/<source>/`, scope `adapter`, run by the source harness of the source repository ([sources/README.md](sources/README.md)); the SDK harnesses report them `skipped:out-of-scope`.

[`testdata/manifest/`](testdata/manifest/index.json) holds four valid and nine invalid test manifests for these fields and for the source-case layout, indexed in `index.json` with the schema errors and the field rules of section Checks that each one breaks. They are test data of the checks, not fixtures.

### Checks

`pactfix check manifest`, a command of the source repository, enforces the following, and every fixture task runs it:

- the manifest parses strictly (draft Section 7.1) and every entry follows the table above, with each token of `capabilities`, `conformance_profile` and `transport` at most once, and the rules of section Manifest entry fields;
- an entry of kind `transport` names `layer`, and an entry with `layer` lists `stdio-ipc` in `transport`;
- ids are unique and sorted, every `path` and `expected` exists, and an expected result is a file;
- every file in this directory is covered by an entry, either inside its `path`, named as its `expected`, or under `expected/<id>/`, where `<id>` is the entry's id (section Format v2), except `manifest.json`, `manifest.schema.json`, the files under `testdata/` (the test data of these checks), files named `README.md` and files whose name starts with `LICENSE`, such as [vectors/jcs/LICENSE-NOTE.md](vectors/jcs/LICENSE-NOTE.md);
- every file has an extension of the neutrality list, in lower case, and a native-format extension only inside an `adapter-asset` entry;
- every `spec_map_row` is a row of the spec map;
- every group, the first segment of an id, that an entry or a spec-map row names has a status in the spec map's Fixture groups table, and the status holds: a `planned` group has no entries; a `partial` group has at least one, and some fixture id its rows name does not exist yet; a `landed` group has at least one, and every fixture id its rows name is in the manifest;
- a fixture id that a spec-map row names and whose fixture is here (a file or directory at the id, or a file at the id followed by `.json`, `.yaml`, `.md` or `.jws`) is in the manifest, whatever the status of its group. The other ids of a `planned` or `partial` group are reserved.

`pactfix check links` checks that every relative link in `spec/**/*.md` resolves inside `spec/`, both in place and in a copy laid out as the mirror, which holds `spec/` at its root.

## Runner contract

A conformance runner, such as `pactc run` in the source repository, drives an implementation under test, written in any language, through commands given on its command line, one per harness verb. It judges what the commands print and never imports or links the implementation.

- Discovery. The runner reads `manifest.json` from the fixtures root and runs only the entries of kind `evaluate`, `outcomes`, `learning` and `schema`, each with the verb of that name, in manifest order. It never walks the tree to find a case. A selector, a manifest id or an id prefix such as `admission/valid` or `admission/`, narrows the run; a selector that selects no entry is a usage error.
- Profile and transport. A run has one conformance profile (`pactc run --profile`, default `full`) and one or more transports (`--transport`, default `https`), and executes only the entries that list the profile and share a transport with it (section Manifest entry fields). The other entries the selectors select are not applicable: they are counted in the report, under `by_profile`, and never run, so none of them is reported `PASS`. The `by_profile` member also lists `roles_claimed`: the roles of draft Section 22.1 the profile claims, all five for `full`, all but Reputation and Learning for `single-owner`. A profile that is not a conformance profile of [../profiles/registry.json](../profiles/registry.json), or a transport that is not `https` or `stdio-ipc`, is a usage error. An entry that names an unknown profile breaks a manifest rule, so it fails the run.
- Manifest check. The runner also checks the manifest against this directory, as `pactfix check manifest` does (section Checks above). A file that no entry covers is reported under the rule `manifest-incomplete` and fails the run; it is not a skipped case.
- Commands. The command of a verb is an argv template. It is split on white space, then `{dir}`, `{state}` and `{id}` are replaced inside each argument, so `--case={dir}` works. No shell is involved: quotes, pipes and globs reach the command literally, and a replaced value stays one argument even when it holds white space. `{dir}` is the absolute path of the entry's case directory under the fixtures root. `{state}` is a scratch path for the entry, fresh for each entry and the same for every command the runner runs for that entry, the evaluate and the receipt command alike, so the gateway state of a multi-exchange case carries over to the receipt query; only the second evaluation of a selection case (below) gets a fresh one. It does not exist before the first command, which may create a file or a directory there. `{id}` is the `jti` of a receipt, for the receipt command.

| Verb | Template | The command | Standard output |
|---|---|---|---|
| `evaluate` | `tool evaluate {dir} {state}`, `{state}` optional | evaluates the case; standard input is empty | the compact `pact-admission+jwt` receipt, or an RFC 9457 Problem JSON object (draft Section 13.4) when the request is rejected before an authenticated evaluation (draft Section 12.2); one per line for a case with several submissions (section Format v2, Evaluate output) |
| `receipt` | `tool receipt {state} {id}`, optional | returns a receipt that the evaluate command of the entry printed; no manifest entry has this kind | the compact receipt whose `jti` is `{id}` |
| `outcomes` | `tool outcomes {dir} {state}` | runs the ingestions and queries of the case | the outcomes result object (section Format v2, Outcomes output) |
| `learning` | `tool learning {dir} {state}` | applies the steps of the case | the registry state JSON (section Format v2, Learning output) |
| `schema` | `tool schema {dir}`, optional; `{dir}` is the absolute path of the entry's file | reads the documents of the schema case ([schema/README.md](schema/README.md)) | one line per document, in order: the decoded object it accepts as JSON, the payload for a compact JWS, or an RFC 9457 Problem JSON object (draft Section 13.4) for a document it rejects |

- Results. Each entry is `PASS`, `FAIL` or `SKIP`. Every command is optional: the entries of a verb whose command is not given are `SKIP`, never `FAIL`, and so are the entries of a verb the runner has no check for yet, with that reason. An entry with `capabilities` is judged only when the implementation declares each of them (`pactc run --capability`, section Optional capabilities); otherwise it is `SKIP` with the missing capabilities, never `PASS`.
- Evaluate. The exit status of an evaluate command is informational; the response on standard output is judged. A command that prints neither a receipt nor a Problem fails, whatever its exit status. The response is compared with the entry's `decision.json` (section decision.json below). When the expected file names a `transport_code`, the response must be a Problem with that code and no receipt, and a receipt there fails (draft Section 12.2); otherwise it must be a receipt, and a Problem fails. A receipt is judged on every point below, and each difference is a detail of the `FAIL`:
  - Signature and type. The compact JWS has `typ` `pact-admission+jwt` and verifies under the public key of `receipt.signer`, else of `config.json` `validator.key`, with the receipt's `kid` in that key set. Its `alg` must be listed in `config.json` `gateway.jws_algorithms` (default `["ES256"]`, section config.json additions) and be the algorithm of that key (draft Section 7.2): ES256 for an EC P-256 key, `Ed25519` (RFC 9864) for an OKP Ed25519 key (RFC 8037). A case negotiates Ed25519 by listing it and naming an Ed25519 key. A key whose algorithm the list lacks fails the case, and any other `alg`, `EdDSA` included, fails. A case that names neither key fails: a receipt is never accepted unverified. The payload must be an `AdmissionAttestation`, so an unknown member fails (draft Section 7.1).
  - Decision and claims. The receipt's `decision` is the expected one, and every member of `receipt.claims` is in the payload with an equal value, compared as RFC 8785 canonical JSON (draft Section 7.4), so only the value counts.
  - Derived digests. When `receipt.claims` does not name them, `profile_digest` and `intent_digest` must be the `object_digest` of `profile.json` and `intent.json`, and `requirements_digest` the `artifact_digest` of `signed/contract.jws` (draft Section 7.4). `operation_digest` is judged only when named.
  - Expiry. `exp` is at most `receipt.exp_max` when that is given, and at most 60 seconds after `iat` (draft Section 12.1); a receipt without `exp` or `iat` fails.
  - Checks. Each listed check is found by `check_id` and must carry the listed `result` and `reason_code`, `evidence_ids` that include `evidence_ids_include`, and, when `source_ref` is listed, that `source_ref`. When the receipt repeats a `check_id`, every occurrence must agree. No check named in `absent_checks` may appear. The receipt carries exactly one result for each check that the `context_checks` of the exchange's `signed/contract.jws` names, whether `decision.json` lists it or not: a missing or repeated one fails (draft Section 12.1). A check whose native read had not completed when the evaluation ended was not performed and is never recorded `PASS` (draft Section 12.1, which defines a native read). The runner applies that rule with `native_reads_at` (section exchange.json): when the native reads of a submission were outstanding at the end of its evaluation, a receipt check that needs a native read and that `decision.json` does not list fails as `PASS`. The runner takes as needing a native read the contract's field rules of source `native` and its `context_checks` other than `native-principal-binding-v1` (draft Sections 12.1, 17.1, 17.5). A field rule whose mapping names a source (`native_mappings[].source`, section config.json additions) is judged by the capability rule there: a receipt check of such a rule that `decision.json` does not list fails when the rule requires `UNKNOWN` `UNSUPPORTED_REQUIREMENT` or `UNKNOWN` `DEPENDENCY_UNAVAILABLE` and the receipt carries another result. Beyond that, a receipt check that `decision.json` does not list is not judged, and neither is the order of the checks.
  - Several responses. A case with several submissions, handoff attempts or exchanges prints one line per response and per handoff attempt (section Format v2, Evaluate output), and every line is judged against its expected entry in the way above. The responses of a concurrent batch may come in any order, each line matching one expected entry in full.
  - Several exchanges. Each exchange of a multi-exchange case produces its own receipt, so the receipts of different exchanges carry distinct `jti` values, and a receipt without `jti` fails (draft Sections 7.3, 12.2). After the last exchange, the runner asks the receipt command, with the entry's `{state}`, for each receipt an earlier exchange printed, by its `jti`; it must print that compact JWS byte for byte, as a sealed receipt is never reopened, amended or converted (draft Section 12.2). Without a receipt command this sub-check is not run: the entry is judged without it, and the report lists the sub-check as skipped with its reason.
  - Selection record. Every `reputation-context` and `selection-consistency-v1` check of a receipt carries the presented snapshot's `jti` in `evidence_ids` and, as `source_ref`, the `record_ref` of the exchange's selection record: `config.json` `selection.record`, or the Appendix B record of section config.json additions when `config.json` names no `selection` (draft Appendix A.2, B.7); unless `decision.json` lists `evidence_ids_include` or `source_ref` for that check. The presented snapshot is the one `pact-reputation+jwt` artifact of the exchange's `signing.json`; with none or several, `evidence_ids` is not audited, and an exchange with a concurrent batch is not audited.
  - Selection cases. A case whose gateway installs `selection-consistency-v1` or names a `selection` in `config.json` is evaluated a second time with a fresh `{state}`. Each line of the second run must carry the decision, `terminal_reason` and, check by check, the `result` and `reason_code` of the first, or the same Problem code; `jti` and signatures are not compared (draft Section 11.3, step 9).
  - Not judged. `executed`, `rejected_before_crypto` and `reason` cannot be judged from what the command prints, since a receipt or a Problem says nothing of what the gateway does after it or of the order in which it checked; the runner does not compare them.
- Outcomes. The exit status of an outcomes command is informational; the outcomes result object on standard output is judged (section Format v2, Outcomes output), and each difference is a detail of the `FAIL`:
  - Steps. `steps` has one entry per step of `steps.json`. An ingest step's entry is an `Acknowledgment` with a `request_id`, an `artifact_id` and a `received_at`, or an RFC 9457 Problem with its `type`, `title`, `status`, `code` and `request_id` (draft Section 13.4); unknown members fail (draft Section 7.1). When the case has `acks.json`, each entry carries its status or its code. A step that submits a signed report already acknowledged, the same file again, is an identical retry: it must get the original acknowledgment or one with status `DUPLICATE` (draft Section 7.5), whatever the case's expected files say.
  - Snapshots. A query step's snapshot is a compact JWS of `typ` `pact-reputation+jwt` that verifies under `reputation_service.key` with ES256, and its payload is a `ReputationSnapshot`. Its `iss`, `tenant_id` and `environment_id` are the service's; its `sub`, `aud`, `holder_jkt` and `value.context` the query's; its `jti` has at least 22 base64url characters; `iat` and `nbf` are no later than the query's `now` plus the clock skew, `exp` is later than `now`, at most 300 seconds after `iat` and at most `exp_max`; `evidence_cutoff` is no later than `iat`; the scoring pins are `config.json`'s; and `security_status` is `HOLD` exactly when `hold_refs` is not empty (draft Sections 15.2, 15.4 and Appendix A.2). The `value` and `claims` of `snapshot.json` are compared as section snapshot.json states.
  - Provenance. The printed manifest has the five members of draft Section 15.2. Its `qualified_event_ids` and `superseded_event_ids` are those of `snapshot.json`, sorted, and name reports that earlier steps acknowledged; each dimension's `qualified_events` is the number of listed reports of that dimension; `qualification_policy_id` is `data_policy`'s; `scoring_policy_revision` and `evidence_cutoff` are the value's; and `provenance_digest` is the manifest's `object_digest`.
  - Qualifications. When the command prints `classifications`, every report of `classifications.json` whose `qualification` is not `null` has that qualification, and no other `event_id` and no other value appears. A report that breaks a dimension rule of Appendix A.2 is refused at ingestion ([outcomes/mapping/README.md](outcomes/mapping/README.md)), so `null` for a refused report meets an expected `UNQUALIFIED` of reason `invalid-report`. Without `classifications`, the sub-check is reported skipped with its reason and the entry is judged without it.
- Schema. The exit status of a schema command is informational; its lines are judged, and each difference is a detail of the `FAIL`:
  - Lines. There is one line per document of the input: one for a compact JWS, one per element of `objects` for an object list. A command that prints nothing fails.
  - Rejected. For an entry of outcome `REJECTED`, every line is a Problem whose `code` is the `transport_code` of the entry's `decision.json`.
  - Accepted. For an entry of outcome `ACCEPTED`, every line is a JSON object equal, compared as RFC 8785 canonical JSON (draft Section 7.4), to its document: the decoded payload of a compact JWS, or the `object` of an element of an object list.
  - Fixture. The runner applies the verdict of [schema/README.md](schema/README.md) to the input itself, with the Appendix A.3 schema, and an entry whose outcome or code does not hold under it fails, whatever the command printed: a case whose expectation contradicts the schema judges nothing. A runner without a schema validator does not run this sub-check, and the report lists it as skipped with its reason.
  - Turning the fixture check off. The fixture sub-check is on by default. A conforming runner MAY offer a way to turn it off for local diagnosis, such as the `--schema-check off` of `pactc run` (`gate`, the default, runs it); with it off, each entry is judged on the schema command's lines alone, and the report lists the sub-check as skipped, with a reason that names the option. A run with the sub-check off is a diagnostic, not a conformance run.
  - Not judged. `rejected_before_crypto` and `reason` cannot be judged from what the command prints.
- Exit status. `pactc run` exits 0 when no check is `FAIL`, 1 when one is, 2 on a usage error or when the run cannot start, and 3 when no check is `FAIL` but the profile and transports of the run select no entry: an empty run is never a pass.

## Evaluation cases

An evaluation case (kind `evaluate`) is a directory `<group>/<case>/`. Its expected result is `expected/<group>/<case>/decision.json`. Decoded objects are written in their RFC 8785 canonical form (draft Section 7.4), with no trailing newline, so each is byte for byte the payload of its signed form. A case holds the files its scenario needs:

| File | Content |
|---|---|
| `config.json` | Trusted configuration of the gateway (draft Section 4.2), below. |
| `native_context.json` | What the native environment establishes (draft Section 17.1), below. |
| `profile.json` | The agent profile. |
| `intent.json` | The declared intent. |
| `operation.json` | The operation context the agent presents. |
| `actual_operation.json` | The operation context the gateway maps from the actual request; the evaluate request carries it beside the presentation (draft Section 13.2). |
| `contract.json` | The requirement contract, decoded. |
| `evidence/<name>.json` | Each evidence artifact, decoded. |
| `reputation.json` | The reputation snapshot, decoded, or `null` when the presentation carries none. |
| `signed/contract.jws` | The signed contract. |
| `signed/evidence/<name>.jws` | Each signed evidence artifact. |
| `signed/reputation.jws` | The signed reputation snapshot, when there is one. |
| `signed/presentation.jws` | The signed presentation. |

The presentation has no decoded file: its payload embeds the compact contract, evidence and reputation, and the profile, intent and operation above (draft Section 11.2).

The `operation_digest` of `contract.json`, and so of `signed/contract.jws`, is the `object_digest` of `operation.json` (draft Sections 9.1 and A.2), the operation the agent presents and the contract was issued for; the presentation embeds that same object. `actual_operation.json` is what the gateway maps from the request and compares with the contract's digest (draft Section 11.3, step 5): a case in which the operation is modified before presentation changes `actual_operation.json` and leaves the contract alone. A receipt's `operation_digest` is the `object_digest` of the operation the validator evaluated (draft Section 12.1), so an expected receipt that names it names the `object_digest` of `actual_operation.json`, or of `operation.json` in a case without one; for an `ADMISSIBLE` receipt the two are equal. The cases with a differing `actual_operation.json` name the claim, so a receipt that carries the presented operation's digest fails them. Likewise, the `operation_id` and `principal_id` an expected receipt names are those of the same operation, the principal being the one `authenticate_native` established (draft Sections 12.1 and 17.1).

### config.json

| Member | Content |
|---|---|
| `mode` | `enforced` or `observe`. |
| `now` | The evaluation time, Unix seconds. A harness holds its clock at this value. |
| `clock_skew_seconds` | The allowed clock skew (draft Section 7.5). |
| `gateway` | `gateway_id` (the audience), `environment_id`, `tenant_id` and `operation_mapping_version`. |
| `trust` | Array of trust records: `iss`, the signer `role` (the role names of [vectors/jws/README.md](vectors/jws/README.md)), `keys` (paths of public JWK files under `keys/`) and, for evidence issuers and reputation services, the `claim_paths` they may assert. |
| `validator` | The validator that signs the admission attestation: `iss`, `source_id` and `key`. |
| `native_mappings` | Array of `{path, native_path}`: the profile path and the native path that is authoritative for it (draft Section 17.2), each with an optional `source` (section config.json additions). |
| `installed_checks` | The context check ids the gateway has installed (draft Section 9.3). |
| `active_policy` | `base_revision`, `selected_set`, `learning_policy_digest`, `learning_artifact_digest` and the optional `scoring_policy_revisions` (section config.json additions): the active requirement and learning versions and the accepted scoring revisions. |
| `limits` | The limits of draft Section 20.1, by their metadata keys. |

### native_context.json

| Member | Content |
|---|---|
| `authenticated` | Result of `authenticate_native` and `resolve_agent_binding` for the presented agent: `principal_id`, `agent_id`, `operator_id`, `tenant_id`, `holder_jkt`, `binding_status` (`active`, `revoked`, `compromised` or `unknown`), `authenticated_at`, and the optional `enrolled_elsewhere` and `binding_error`. With `binding_status` `unknown` the agent has no record on the authenticated workload in the realm (identity mapping IM-11): `agent_id`, `operator_id` and `holder_jkt` are `null`, and `enrolled_elsewhere` (boolean, default `false`) is the Section 17.1 report that the realm holds a record of the presented agent ID for another workload; it is `false` for every other status. `binding_error` (default `null`) is `UNSUPPORTED_REQUIREMENT` when the workload holds more than one enrollment in force under a profile without shared workloads (IM-19); `binding_status` is then `unknown` with the three members `null`. The members state what the enrollment source holds; whether it answers is `exchange.json`'s `availability.enrollment_source`. |
| `native_claims` | Array of `{native_path, value, observed_at, status_checked_at, source_id}`: what `read_native_claim` returns. |
| `approval` | Native approval state: `ref`, `state`, the bound `agent_id`, `principal_id`, `purpose_id` and `task_id`, and `status_checked_at`; `null` when there is none. |
| `delegation` | Native delegation state: `authority_ref`, `principal_id`, `task_id`, `state` and `observed_at`; `null` when there is none. |
| `executor` | The executor identity: `class` (draft Section 17.5) and `principal_id`; `null` when not established. |
| `evidence_status` | Object from evidence `status_ref` to `{status, checked_at}`. |
| `security_holds` | The holds in force for the agent. |
| `authorize` | The result of `authorize_native` for the operation: `true` or `false`. |

`admission/valid` uses the state `approved` for its approval and `active` for its delegation. The fixture tasks that need the other native states of draft Section 17.3.1 name them in lower case.

What the validator concludes from `authenticated` (identity mapping section 8) takes two forms. A presentation is rejected before an authenticated evaluation, with a transport error and no receipt (draft Section 12.2), when no binding in force with the presentation's key exists: `binding_status` `unknown` is `INVALID_PROOF`, or `CONTEXT_MISMATCH` when `enrolled_elsewhere` is `true`; `revoked` is `INVALID_PROOF`; a `holder_jkt` that is not the presentation's key is `INVALID_PROOF`; `binding_error` `UNSUPPORTED_REQUIREMENT` is `UNSUPPORTED_REQUIREMENT`. It is evaluated, with a receipt, when the binding is in force and the key matches: `compromised` is `agent-holder-binding` `FAIL` `SECURITY_HOLD` and `INADMISSIBLE` (draft Sections 6.4 and 13.4), `security_holds` unchanged, since the binding's status alone carries the hold; an enrollment source that cannot answer is `agent-holder-binding` `UNKNOWN` `DEPENDENCY_UNAVAILABLE` and `DEFERRED` (draft Section 18).

### decision.json

| Member | Content |
|---|---|
| `transport_code` | The Section 13.4 code when the request is rejected before an authenticated evaluation, otherwise `null`. Such a request gets no receipt (draft Section 12.2), and the members below are absent. |
| `decision` | `ADMISSIBLE`, `INADMISSIBLE` or `DEFERRED`. |
| `checks` | The required check results, each `{check_id, result, reason_code}`. Every listed check must appear in the receipt with that result and reason code; a harness matches them by `check_id`. Listed or not, each check the contract's `context_checks` names appears in the receipt exactly once; one the validator did not evaluate is `UNKNOWN` with reason code `NOT_EVALUATED` (draft Section 12.1). |
| `receipt` | `typ`, `signer` (the public JWK file of the validator key), `claims` (members the receipt payload must carry with exactly these values) and `exp_max` (the latest permitted `exp`, draft Section 12.1). |
| `executed` | Whether the operation runs after native authorization. A runner that sees only the command's output does not judge it. |

Two optional members may accompany a transport rejection: `rejected_before_crypto` (`true` when the input must be refused before any signature is checked) and `reason`, a note for readers. A runner judges neither.

## Signed artifacts

Signed files are made by `pactfix generate` from the decoded files of a case. The generator reads no clock and draws no identifier: every `iat` and `nbf` is `1792080000` (2026-10-15T16:00:00Z, the sample time of Appendix B) unless a format v2 `signing.json` states another time for the artifact, and every `jti` is fixed in advance. It signs with the test keys of `keys/`, using the private values of [keys/test-private-scalars.json](keys/test-private-scalars.json).

ES256 signatures are randomized, so a signed file is not reproducible byte for byte. The generator keeps a signed file whose signature verifies and whose header and payload are what it would write, and signs again only when they differ. Running it twice therefore changes nothing. A harness verifies the committed signatures and never regenerates them.

## admission/valid

The positive control of row `CL-11.3`: the worked exchange of Appendix B, which yields `ADMISSIBLE` with every required check `PASS`.

| File | Source | Signed by | `jti` | `exp` |
|---|---|---|---|---|
| `profile.json` | B.1 | | | |
| `intent.json` | B.2 | | | |
| `operation.json`, `actual_operation.json` | B.3 | | | |
| `contract.json` | B.4 | issuer key, standing in for the requirement publisher | `zIMh1jdcSU0EP90CYPIbwA` | `1792080060` |
| `evidence/runtime.json` | B.5 | issuer key | `7oJQ-3bglLNLRx8Tpz275Q` | `1792080300` |
| `reputation.json` | B.6 | reputation-service key | `VW7HSF227CWWBU7wN09Q5A` | `1792080300` |
| `signed/presentation.jws` | built from the files above | holder key, embedded as `jwk` | `v6wxT-_cB0Ua8Xkqgcuu2g` (the `presentation_id` of B.7) | `1792080060` |

The expected result follows B.7: the decision, the 20 check results in B.7 order, and the receipt claims. B.7 prints a `requirements_digest` for a contract signature that is not reproducible, so `decision.json` carries the `artifact_digest` of `signed/contract.jws` instead. The other digests are the values B.7 prints.

## Format v2

Format v2 extends the case formats above so that the remaining cases of Section 22.2 and the outcomes, reputation and learning groups can be written as data. It adds members and files. It removes nothing, except that three members of the outcome `config.json` move into `data_policy` and the outcome mapping expected file is renamed (section Migration of committed cases). Every member a v2 table marks optional has a default, and the default is the v1 behaviour, so a committed v1 case reads the same under v2.

`pactfix generate` implements the generator contract below. The committed cases were migrated to it as section Migration of committed cases lists; every case with signed files has a `signing.json`.

Every table below has the columns: member, JSON type, whether it is required, the default when it is absent, its meaning, and the draft section it serves. "Path" means a path relative to the case directory, with the segment rules of section Manifest. A draft section cited for a member is the section whose rule the member lets a case exercise; it does not mean the draft defines the member. All member names are fixture vocabulary.

### Expected directories and the manifest

A v2 case may have more than one expected file. They all sit under `expected/<id>/`, where `<id>` is the entry's id. The entry's `expected` names the file that carries the manifest `outcome`, as each kind below states. The coverage check of section Checks gains one rule: a file under `expected/<id>/` is covered by the entry `<id>`. A v1 entry, whose expected directory holds only its `expected` file, passes the old and the new rule alike. The entry's `expected` is always under `expected/<id>/`. The rule is item 1 of the spec map's list of checks ([../spec-map.md](../spec-map.md)); `pactfix check manifest`, the runner's manifest check and the source repository's second manifest checker enforce it, and a parity case covers each direction.

### Generator contract: signing.json

Every v2 case that has signed files carries `signing.json`. The generator has no case list of its own: it signs every manifest entry of kind `evaluate`, `outcomes` or `learning` whose case directory has a `signing.json`, and every exchange directory that a `sequence.json` names (section Multi-exchange cases). The keep rule of section Signed artifacts is unchanged: a signed file whose signature verifies, and whose header and payload are what the generator would write, is kept.

A case directory that holds signed files but no `signing.json`, or a signed file that no entry of its `signing.json` names, is an error of `pactfix generate`. A decoded file whose content is `null`, such as the `reputation.json` of a case without a snapshot, has no artifact entry. In check mode, a decoded file whose `digests` members would change counts as changed.

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `artifacts` | array of artifact entries | yes | | The service-signed artifacts, signed in array order. | 7.2, 7.3 |
| `presentations` | array of presentation entries | no | `[]` | The presentations the generator builds and signs after the artifacts. | 11.2 |

An artifact entry:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `decoded` | path | yes | | The decoded payload, RFC 8785 canonical with no trailing newline. | 7.4 |
| `signed` | path | yes | | The compact JWS file the generator writes. | 7.2 |
| `typ` | string | yes | | The JWS `typ`: one of the values of the Section 7.3 table. Outcome reports use `pact-outcome+jwt`; learning policies, artifacts and events use `pact-learning-policy+jwt`, `pact-learning-artifact+jwt` and `pact-learning-event+jwt`. | 7.2, 7.3 |
| `signer` | string | yes | | The `role` of the signing key in [keys/test-private-scalars.json](keys/test-private-scalars.json). The header carries that key's `kid`. | 7.2, C |
| `jti` | string | yes | | The `jti` the decoded payload must carry, fixed in advance. | 7.5, A.2 |
| `iat` | integer | no | `1792080000` | The `iat` the decoded payload must carry. The generator checks it and never writes it. | 7.5 |
| `nbf` | integer | no | the entry's `iat` | The `nbf` the decoded payload must carry. | 7.5 |
| `exp` | integer | no | not checked | When present, the `exp` the decoded payload must carry. | 7.5, 12.1, 14.3, 15.2, 16.5 |
| `digests` | object from JSON Pointer to path | no | `{}` | Before signing, the generator sets the member of the decoded payload that each RFC 6901 pointer names to the `artifact_digest` of the signed file the path names, and writes the decoded file back in canonical form. The signed file must come from an earlier entry of the same `signing.json`. A learning event names its policy and artifacts this way, since an ES256 signature, and so an `artifact_digest`, is fixed only once the file is signed. | 7.4, 16.3, A.2 |
| `payload_signed` | path or `null` | no | `null` | When set, the signature is computed over the protected header and the bytes of this decoded file, while the compact JWS carries the bytes of `decoded`: the payload was edited after signing, and the signed file does not verify by design. The generator keeps such a file when its signature verifies over `payload_signed` and its payload is `decoded`. | 7.2, 11.3 step 3 |

A presentation entry. A presentation has no decoded file. The generator builds its payload from the files below: `iss` and `sub` are the profile's `agent_id`, `tenant_id` is the profile's, `pact_version`, `aud` and `nonce` are the contract's, and `jti`, `iat`, `nbf` and `exp` are the entry's (draft Section 11.2).

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `signed` | path | yes | | The compact JWS file. | 11.2 |
| `signer` | string | yes | | The key role that signs the presentation and whose public JWK it embeds as `jwk`. | 6.2, 7.2 |
| `jti` | string | yes | | The presentation's `jti`, which the receipt carries as `presentation_id`. | 7.5, 12.1 |
| `iat` | integer | no | `1792080000` | The presentation's `iat`. | 7.5 |
| `nbf` | integer | no | the entry's `iat` | The presentation's `nbf`. | 7.5 |
| `exp` | integer | no | `iat + 60` | The presentation's `exp`. | 7.5 |
| `contract` | path | no | `signed/contract.jws` | The embedded compact contract. | 7.5, 11.2 |
| `evidence` | array of paths | no | the `signed` paths of the artifact entries of typ `pact-evidence+jwt`, in order | The embedded compact evidence. | 11.2 |
| `reputation` | path or `null` | no | the `signed` path of the artifact entry of typ `pact-reputation+jwt`, or `null` when there is none | The embedded compact snapshot. | 11.2 |
| `profile`, `intent`, `operation` | path | no | `profile.json`, `intent.json`, `operation.json` | The embedded objects. | 11.2 |

### Keys

Format v2 adds four test keys: `executor`, `evaluator`, `security-authority` and `holder-2`, private scalars 7 to 10. [keys/README.md](keys/README.md) lists them. In v2 cases an executor, evaluator or security authority signs its outcome reports with its own key, so that a case can register them as different signers. The gateway reporter and the policy authority keep the issuer key, as [vectors/jws/README.md](vectors/jws/README.md) describes. `holder-2` is a second holder key of the same agent: the key after a rotation that the service has not recorded, under which a query gets the cold-start values (Section 6.4).

### Evaluation cases v2

An evaluation case keeps the files of section Evaluation cases and may add `signing.json` (above) and `exchange.json`. A multi-exchange case replaces them all with `sequence.json` and `exchanges/<n>/` (section Multi-exchange cases).

#### exchange.json

`exchange.json` says how the harness drives the case. It is optional; without it the case is one presentation, `signed/presentation.jws`, evaluated at `config.json`'s `now`, with every source and the replay store available and no handoff.

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `presentations` | array of submissions | no | one submission of `signed/presentation.jws` | The presentations the harness submits, in array order. | 11.1, 13.2 |
| `availability` | object | no | all available | What does not answer during the case, below. | 7.5, 18 |
| `handoff` | array of handoff attempts | no | `[]` | Sidecar handoffs of an issued attestation, attempted in order after every presentation. | 11.5 |

A submission:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `signed` | path | yes | | The signed presentation. Two submissions may name the same file: the second is a replay. | 11.2, 7.5 |
| `jti` | string | yes | | The presentation's `jti`, equal to its `signing.json` entry. It ties the submission to its expected response. | 7.5, 12.1 |
| `replica` | string | no | `"r1"` | The validator replica that evaluates the submission. Every replica of a case shares one replay store. | 7.5 |
| `concurrent` | boolean | no | `false` | `true`: the harness submits this presentation at the same time as every other submission whose `concurrent` is `true`, and waits for all of them before the next submission. | 7.5 |
| `evict_replay_records` | boolean | no | `false` | `true`: before this submission arrives, the harness evicts every replay record whose retention bound (the later of the artifact expiry and `iat + 60 + clock_skew`) has passed at the submission's `started_at`, as a store under load may. | 7.5, 18 |
| `actual_operation` | path | no | `actual_operation.json` | The actual operation the evaluate request carries beside the presentation. | 13.2 |
| `transport` | string | no | `"https"` | `https` or `stdio-ipc`: the transport profile the presentation arrives over, as the gateway established it. | 13.3.1, 17.1 |
| `evaluation` | object | no | below | The timing of the evaluation. | 12.2 |

`evaluation`:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `started_at` | integer | no | `config.json`'s `now` | The harness clock when the presentation arrives; the evaluation starts at that time. | 7.5, 12.2 |
| `native_reads_at` | integer or `null` | no | `null` | The harness answers no native read (Section 12.1) before this time; a read issued earlier completes then. A value later than the Section 12.2 deadline (the earliest of the contract `exp`, the presentation `exp` and `started_at` plus `limits.evaluation_seconds`, the evaluation time of Section 20.1, at most 30 seconds) makes the evaluation expire. When the evaluation ends, at `cancelled_at` or at that deadline, before this time, the native reads are outstanding, and Section 12.1 applies to the checks that need them. | 12.1, 12.2, 17.1, 20.1 |
| `cancelled_at` | integer or `null` | no | `null` | The requestor cancels the evaluation through native authenticated session control at this time. `native_reads_at` is later than it, so the cancellation arrives during the evaluation. | 12.2 |

`availability`:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `sources` | array of strings | no | `[]` | Reads that report the source unavailable. An entry that starts with `/` is a native path: `read_native_claim` for it reports the source unavailable, which is distinct from a source that answers with no value. Any other entry is a status reference, a key of `native_context.json`'s `evidence_status`: its status check reports the status source unavailable. | 17.1, 18 |
| `replay_store` | string | no | `"available"` | `available`, `unavailable` or `full`. A store that is unavailable or full defers, never admits. | 7.5, 18 |
| `enrollment_source` | string | no | `"available"` | `available` or `unavailable`: the enrollment source behind `resolve_agent_binding` (Section 17.1). Unavailable: the binding is not established, `agent-holder-binding` is `UNKNOWN` with `DEPENDENCY_UNAVAILABLE`, the decision is `DEFERRED`, and the record `native_context.json` states is never read. | 11.3 step 2, 17.1, 18 |

A handoff attempt:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `presentation` | string | no | the `jti` of the first submission | The submission whose attestation the gateway verifies at handoff. | 11.5 |
| `actual_operation` | path | no | `actual_operation.json` | The request the attestation is presented for. | 11.5 |
| `at` | integer | no | the submission's `started_at` | The harness clock at handoff. | 11.5, 12.1 |

#### config.json additions

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `gateway.extensions_supported` | array of URI strings | no | `[]` | The extensions the gateway supports, as `GatewayMetadata.extensions_supported` publishes them. | 7.1, 13.1, 21, A.3 |
| `gateway.jws_algorithms` | array of strings | no | `["ES256"]` | The algorithms the gateway publishes in `GatewayMetadata.jws_algorithms`: one or two distinct values out of `ES256` and `Ed25519`. A receipt `alg` outside it fails, and so does one that is not the algorithm of the validator key (section Runner contract). | 7.2, 13.1, A.3 |
| `executor_classes` | array | no | `[]` | The installed execution-identity mapping, the shape of the outcome cases (section Outcomes cases) plus `executor_id`: `principal_id`, `task_id`, `operation_id`, `class` (`delegated-user`, `registered-app-executor`, `dedicated-role` or `impersonated-user`) and `executor_id`, the identity the declared binding names. `execution-identity-v1` compares `class` and `executor_id` with `native_context.json`'s `executor.class` and `executor.principal_id`. `executor_id` is optional, default `null`: only the class is compared, as in the outcomes cases. | 9.3, 17.5 |
| `check_freshness` | object from check id to integer seconds | no | `{}` | The maximum source age (`max_age_seconds`, draft Section 9.2) for an installed check that no field rule bounds. A check whose source a field rule maps through `native_path` is bounded by that rule's `max_age_seconds`, as the delegation is by B.4. A check with neither uses 30 seconds, the source age of every B.4 rule, not the cached-status default of Section 18. The cases give the status of an installed hold or native-authority check an age of zero, as Section 18 recommends: `native_context.json` states an approval's `status_checked_at` at the exchange's `now`, or `null` when its status is unavailable, and `security_holds` lists the holds in force at `now`. | 9.2, 18 |
| `selection` | object or `null` | no | `null` | The requirement-set selection the gateway performed, below. `null`: the contract's set is the conservative set, no selection input is re-derived, and the exchange's selection record is that of the Appendix B exchange: `record_ref` `configured-selection-record:example-selection` (B.7), the B.4 `learning_policy_digest` and `learning_artifact_digest`, `snapshot_jti` `null`, `hold_refs` `[]`, `base_revision` `finance-base-3`. A gateway records that selection like any other (draft Section 9.4). | 9.4, 11.3 step 9, A.2 |
| `native_mappings[].source` | object or `null` | no | `null` | The declared capability of the mapping's native source, as the integration profile declares it (its `membership_sources` row; [../profiles/freshness.md](../profiles/freshness.md), section 4.2): `source_id` (the `source_id` of the source's `native_claims`), `best_max_age_seconds`, `best_status_max_age_seconds`, `live_check` (boolean: whether the source can be asked for its current state at evaluation time) and `change_feed` (`none`, `poll_delta` or `push`; informative), all required. A source with `live_check` `false` has a `best_status_max_age_seconds` of at least 1. `null`: no declared bound; v1 behaviour. | 9.2, 17.2, 18 |
| `purposes` | object from purpose id to array of action tokens | no | `{"https://policies.example/purposes/invoice-summary/v1": ["invoice.read"]}` (B.2, B.3) | The installed purpose mapping of draft Section 10.1: the actions each `Intent.purpose_id` covers. `purpose-operation-v1` is `PASS` when the actual operation's `action` is listed for the intent's purpose, `FAIL` `CONTEXT_MISMATCH` when it is not, and `UNKNOWN` `UNSUPPORTED_PURPOSE` when the purpose is not a key. | 10.1, 11.3 step 8 |
| `reputation_context` | object or `null` | no | `null` | The installed reputation-context mapping of draft Section 15.1 for the actual operation: `resource_classes`, an array of `{prefix, class}` (a resource whose URI starts with `prefix` has that `resource_class`; a resource that matches no entry makes `reputation-context` `UNKNOWN` `UNSUPPORTED_REQUIREMENT`), and `runtime_class`. `action_class` is the operation's `action`, `purpose_id` the intent's, `agent_id` the bound agent's, and the realm the gateway's. `null`: the Appendix B mapping, `[{"prefix": "https://invoices.example/invoices/", "class": "department-finance-invoice"}]` and `managed-v1` (B.6). | 15.1, 15.2, A.2 |
| `active_policy.scoring_policy_revisions` | array of strings | no | `["finance-scoring-1"]` (B.6) | The scoring-policy revisions the gateway currently accepts in a presented snapshot (draft Appendix A.2); a snapshot whose `scoring_policy_revision` is not listed is rejected by `reputation-context` (draft Section 11.3, step 9). | 15.2, A.2, 11.3 step 9 |
| `owner` | object or `null` | no | `null` | The owner trust configuration of a case of the conformance profile `single-owner` ([../profiles/conformance/single-owner/profile.md](../profiles/conformance/single-owner/profile.md), section 1), below. Only a run under that profile reads it; there, `null` means the case holds no single-owner claim, and the run fails. | 4.2, 6.1, 22.1 |

A native field rule whose mapping names a source is compared with it before the claim is read: a `max_age_seconds` or `status_max_age_seconds` below the declared bound cannot be met, so its check is `UNKNOWN` `UNSUPPORTED_REQUIREMENT`, never `PASS` (draft Section 17.2). For an achievable rule, a claim from a source whose `live_check` is `false` and whose status age exceeds `status_max_age_seconds` is a cached answer the source cannot refresh, such as a stopped push feed: `UNKNOWN` `DEPENDENCY_UNAVAILABLE` (draft Section 18), not `FAIL`. The status age is the start of the evaluation minus the claim's `status_checked_at`; a source time later than that start plus the clock skew is `CLOCK_AHEAD` first ([../profiles/freshness.md](../profiles/freshness.md), section 3.1, rule 2). A source that can check live refreshes the answer, so a stale claim from it fails as stale.

`selection`:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `selector` | object | yes | | The selector the contract pins, below. | 9.4, 16.5 |
| `current_snapshot` | path or `null` | no | `null` | The gateway's own current trusted selection input: a decoded `ReputationSnapshot` in the case; it is trusted input and need not be signed. `null`: the gateway's current input is the presented snapshot. The current hold status is `native_context.json`'s `security_holds`. | 11.3 step 9 |
| `record` | object | yes | | The selection record, below. | 9.4, A.2 |

`selection.selector`:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `implementation_id` | string | yes | | The installed selector, a `permitted_implementation_ids` value of the learning policy, such as `finance-selector-v1` (B.9). | 16.5, B.9 |
| `learning_artifact_digest` | string | yes | | The selector artifact the contract pins; it equals the contract's `learning_artifact_digest`. | 9.4, 16.5 |
| `order` | array of set ids | yes | | The allowed sets, strictest first. The first is the policy's `conservative_set`. "Stricter" in Section 11.3, step 9 means earlier in this array. | 9.4, 11.3 step 9 |
| `sets` | object from set id to array of `FieldRule` | yes | | The authorized field rules of each set, which contract validity compares with the contract's `field_rules` (and `checks` with its `context_checks`). | 9.4, 11.3 step 3 |
| `checks` | object from set id to array of check ids | no | the contract's own `context_checks` | The authorized `context_checks` of each set, which contract validity compares with the contract's `context_checks` as JSON data, array order significant; a difference is `contract-validity` `FAIL` `CONTEXT_MISMATCH`. A set that is not a key has the contract's own `context_checks`, so a case that names no `checks` reads unchanged. | 9.4, 11.3 step 3 |
| `thresholds` | object from set id to threshold | yes | | What a snapshot must meet for each set except the conservative set: `dimensions`, an object from dimension to `{score_bps, confidence_bps, independent_tasks}` minimums, and `security_status`, the status the snapshot's value must have. The selector yields the last set of `order` whose threshold the snapshot meets, and the conservative set when it meets none, when there is no snapshot, or when a hold is in force. Each minimum is also a field rule under `/attributes/reputation` in the set's rules. | 9.4, 15.3, E |

`selection.record`:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `record_ref` | string | yes | | The immutable reference of the record; the expected `source_ref` of `reputation-context` and `selection-consistency-v1`. | 9.4, A.2 |
| `learning_policy_digest` | string | yes | | The active learning policy at selection. | 9.4 |
| `learning_artifact_digest` | string | yes | | The selector artifact at selection. | 9.4 |
| `snapshot_jti` | string or `null` | yes | | The `jti` of the snapshot used, `null` when there was none. | 9.4 |
| `hold_refs` | array of strings | yes | | The holds in force at selection. | 9.4, 15.4 |
| `base_revision` | string | yes | | The base revision at selection. | 9.4 |

`owner`:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `owner_issuers` | array of URI strings | yes | | The issuer URIs of the owner trust root. The `owner` of the deployment's `ConformanceDeclaration` is one of them. | 4.2, 21 |
| `environment_ids` | array of URI strings | yes | | Every environment the deployment trusts configuration, evidence or enrollments for. | 4.2, 21 |
| `realms` | array of `{tenant_id, environment_id}` | yes | | Every realm the deployment serves. | 4.2, 9.1 |
| `enrollments` | array of `{agent_id, enrolled_by}` | yes | | Every agent enrollment in force and the `iss` of the authority that made it, a `trust` record of role `enrollment-authority`. | 6.1 |
| `self_registration` | boolean | yes | | Whether an agent can enroll itself. | 6.1, 13.2 |
| `evidence_issuers` | array of `{iss, claim_paths, owner_trusted}` | yes | | The evidence issuers outside `owner_issuers` that the owner trusts, each with the claim paths it may assert and `owner_trusted` (boolean). | 4.2, 9.2 |

#### native_context.json additions

`approval` gains four members. Each defaults to a value under which the approval matches, so the committed approval cases are unchanged.

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `approval.approver_id` | string or `null` | no | `null` | The native identity that decided the approval. | 17.3, 17.3.1 |
| `approval.approver_authority` | object or `null` | no | `null` | What the native environment establishes about the approver's authority: `required_role`, the native role the approval of this scope requires, and `approver_roles`, the native roles the approver holds. The approver lacks authority when `required_role` is not in `approver_roles`. `null`: the authority is established. | 17.3, 17.3.1 |
| `approval.amount` | object or `null` | no | `null` | `approved`, the amount the approval covers, `requested`, the amount of the actual operation as the native environment establishes it, both decimal strings, and `currency`. `null`: the approval bounds no amount. | 7.1, 17.3.1 |
| `approval.resources` | array of URI strings or `null` | no | `null` | The resources the approval covers; every resource of the actual operation must be one of them. `null`: the approval bounds no resource. | 10.2, 17.3.1 |

#### decision.json additions

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `checks[].evidence_ids_include` | array of strings | no | `[]` | Ids the receipt's `CheckResult.evidence_ids` must include, such as the presented snapshot `jti`. | 12.1, A.2 |
| `checks[].source_ref` | string | no | not compared | The receipt's `CheckResult.source_ref`, exactly, such as the selection record's `record_ref`. | 12.1, A.2 |
| `absent_checks` | array of check ids | no | `[]` | Checks the receipt must not carry. | 9.3, 9.4, 12.1 |
| `responses` | array of responses | no | | One expected response per submission, in the order of `exchange.json`. Each response has the members of a v1 `decision.json` (`transport_code`, `decision`, `checks`, `receipt`, `executed`, `absent_checks`), which are then absent at the top level. For the submissions whose `concurrent` is `true`, a harness matches the responses to the expected entries in any order. | 7.5, 12.2 |
| `handoff` | array | no | `[]` | One entry per handoff attempt: `transport_code`, `null` when the gateway accepts the attestation, otherwise the Section 13.4 code of its rejection, such as `REPLAY` for a consumed attestation. | 11.5, 13.4 |
| `subject` | string | no | `""` | An RFC 6901 pointer into this file naming the expected response that the manifest `outcome` summarizes: `""` for the top level, `/responses/1` or `/handoff/1`. The outcome is that response's decision, or `REJECTED` when it names a `transport_code`; a handoff entry's outcome is `ACCEPTED` when its `transport_code` is `null`, otherwise `REJECTED`. For a concurrent batch the pointer names an expected entry, whichever submission it matches. | 11.4 |

#### Multi-exchange cases

A case that spans several admission exchanges, such as an approval granted after a `DEFERRED` evaluation and a fresh exchange (B.12), is a directory with `sequence.json` and one directory per exchange, `exchanges/1/`, `exchanges/2/`, and so on, numbered from 1. Each exchange directory is a complete evaluation case directory: its own `config.json`, `native_context.json`, decoded and signed files, `signing.json` and, when needed, `exchange.json`. The harness runs the exchanges in order against one gateway state: the replay store, the receipt store and the consumed attestations carry over; each exchange's `config.json` and `native_context.json` replace the previous ones, which is how a change of native state between exchanges is written.

`sequence.json`:

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `exchanges` | array of paths | yes | | The exchange directories, in order. | 11.1, 12.2 |
| `subject` | path | yes | | The exchange whose expected response is the manifest `outcome`. | 12.2 |

The expected result of each exchange is `expected/<id>/exchanges/<n>/decision.json`. The entry's `expected` is the subject exchange's.

#### Evaluate output

The evaluate command prints one response per line. A v1 case, with one submission, prints one line, as before. A v2 case prints the responses of its submissions in order, those of a concurrent batch in any order, then one line per handoff attempt, and a multi-exchange case does so for each exchange in turn. A response is the compact receipt or a Problem JSON object on one line. A handoff that the gateway accepts prints `{"handoff":"accepted"}`; a rejected one prints its Problem.

#### Example: approval/approved-fresh-exchange

The reserved case of row `CL-17.3.1` in which an approval granted after a `DEFERRED` evaluation supports a fresh exchange (Section 12.2, B.12).

```text
approval/approved-fresh-exchange/
  sequence.json
  exchanges/1/   the approval/pending-established-request exchange, with its own jti and nonce values
  exchanges/2/   a fresh contract and presentation; the approval is approved
expected/approval/approved-fresh-exchange/exchanges/1/decision.json
expected/approval/approved-fresh-exchange/exchanges/2/decision.json
```

`sequence.json`:

```json
{"exchanges":["exchanges/1","exchanges/2"],"subject":"exchanges/2"}
```

`exchanges/2/config.json` is that of `exchanges/1/` with `now` 1792080030. `exchanges/2/native_context.json` changes the approval, and puts every native observation and status check at 1792080030:

```json
{"approval":{"ref":"native-approval:inv-1042-supervisor-review","state":"approved","agent_id":"https://identity.example/agents/invoice-assistant","principal_id":"https://identity.example/principals/alice","purpose_id":"https://policies.example/purposes/invoice-summary/v1","task_id":"native-task:september-summary-007","status_checked_at":1792080030}}
```

`exchanges/2/signing.json`, with the contract, the evidence and the snapshot issued at the new time, so that no source is exactly as old as its 30-second bound:

```json
{
  "artifacts": [
    {"decoded":"contract.json","signed":"signed/contract.jws","typ":"pact-requirements+jwt","signer":"issuer","jti":"kyq2TCRnRItNFHdrUfXKxA","iat":1792080030,"exp":1792080090},
    {"decoded":"evidence/runtime.json","signed":"signed/evidence/runtime.jws","typ":"pact-evidence+jwt","signer":"issuer","jti":"hQtcv2V_brf9MH6TxOZylg","iat":1792080030,"exp":1792080330},
    {"decoded":"reputation.json","signed":"signed/reputation.jws","typ":"pact-reputation+jwt","signer":"reputation-service","jti":"MoZ-mHLvX6ejmptnhuxwjw","iat":1792080030,"exp":1792080330}
  ],
  "presentations": [
    {"signed":"signed/presentation.jws","signer":"holder","jti":"nWg944-mo-EBEgbKQUYgCA","iat":1792080030}
  ]
}
```

The expected results, abridged to the members that differ between the two exchanges:

```json
{"decision":"DEFERRED","transport_code":null,"checks":[{"check_id":"native-approval-v1","result":"UNKNOWN","reason_code":"APPROVAL_PENDING"}],"executed":false}
```

```json
{"decision":"ADMISSIBLE","transport_code":null,"checks":[{"check_id":"native-approval-v1","result":"PASS","reason_code":"REQUIREMENT_SATISFIED"}],"executed":true}
```

The evaluate command prints two lines, the receipt of each exchange. The manifest entry has `expected` `expected/approval/approved-fresh-exchange/exchanges/2/decision.json` and `outcome` `ADMISSIBLE`. The first receipt stays `DEFERRED`; the second exchange produces its own receipt.

### Outcomes cases

An outcomes case (kind `outcomes`) tests what the reputation service does with a sequence of signed `OutcomeReport`s and reputation queries: the acknowledgments, the qualification of each report, and the snapshots. The format serves every group whose cases have that shape: `outcomes/mapping/`, `outcomes/qualification/`, the scenario cases of `reputation/`, and the outcome cases of `delegation/`. A case is a directory:

| File | Required | Content | Draft |
|---|---|---|---|
| `config.json` | yes | Trusted configuration of the reputation service, below. | 4.2, 14.6 |
| `native_context.json` | yes | The authoritative task records and native records, below. | 14.2, 14.6 |
| `reports/<event_id>.json` | yes | Each report, decoded. | 14.1 |
| `signed/<event_id>.jws` | yes | Each signed report, typ `pact-outcome+jwt`. | 7.3, 14.3 |
| `signing.json` | yes | The generator contract above. | 7.5 |
| `steps.json` | yes | The ingestions and queries, in order, below. | 13.2 |

The expected results are under `expected/<id>/`:

| File | Required | Content | Draft |
|---|---|---|---|
| `classifications.json` | when the case is about a report | The qualification of every report at the end of the case, below. The entry's `expected` names it, and its `outcome` is the subject report's qualification. | 14.3 |
| `snapshot.json` | when `steps.json` has a query | The expected snapshot of each query, below. When there is no `classifications.json`, the entry's `expected` names this file and its `outcome` is `MATCH`. | 15.2, 15.3 |
| `acks.json` | no | The expected response to each ingestion, below. | 7.5, 13.2 |

#### config.json

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `now` | integer | yes | | The reference time, Unix seconds; the default time of every step. | 7.5 |
| `clock_skew_seconds` | integer | yes | | The allowed clock skew. | 7.5 |
| `reputation_service` | object | yes | | `service_id` (the audience of every report and the `iss` of every snapshot), `tenant_id`, `environment_id`, and `key`, the public JWK file the snapshots must verify under. `key` defaults to `keys/reputation-service.jwk.json`. | 13.2, 15.2 |
| `data_policy` | `DataPolicy` (A.3) | yes | | The data policy, such as that of B.9: `qualification_policy_id`, `ingestion_window_seconds`, `positive_weight_cap_per_task`, `maximum_failure_weight`, `task_attribution_source` and `reporter_independence_policy_id`. | 14.3, 14.6, 15.3 |
| `scoring` | object | no | `scoring_artifact_digest` `Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0`, `scoring_policy_revision` `finance-scoring-1` (B.6) | The scorer the snapshots pin. | 15.2, 15.3 |
| `visibility` | string | yes | | `execution` or `none`: whether the gateway profile declares execution visibility. | 14.1, 14.5 |
| `trust` | array | yes | | The trusted registration of each signer: `iss`, `role` `reporter`, `reporter_role` (an `OutcomeReport.reporter_role` value) and `keys`, paths of public JWK files under `keys/`. A signer registered for more than one `reporter_role`, such as the executor of a task that also evaluates it (rule 5), has one record per role. | 14.2, A.2 |
| `executor_classes` | array | no | `[]` | The installed execution-identity mapping: `principal_id`, `task_id`, `operation_id`, `class`, and, optionally, `executor_id` (default `null`: only the class is compared). | 14.2, 17.5 |
| `affiliations` | array | no | `[]` | The configured affiliation registry: `{evaluator_iss, operator_id}` pairs. | 14.6 rule 6 |
| `evaluator_agents` | array | no | `[]` | The agent an evaluator operates: `{evaluator_iss, agent_id, operator_id}`. Rule 7 reads it to find evaluator E's own agent and the evaluators an operator runs. It does not make an evaluator affiliated under rule 6; only `affiliations` does. | 14.6 rule 7 |
| `hold_clearance_authorities` | array of URI strings | no | `[]` | The `hold_clearance_authorities` of the active learning policy (B.9): `iss` values of `trust` records whose `REMEDIATION` report may clear a hold. | 15.4, 16.5 |

No case declares a severity rule (Section 15.3): a qualified attributable failure has weight 1, and `data_policy.maximum_failure_weight` bounds what such a rule could assign.

#### native_context.json

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `tasks` | array | yes | | The authoritative task records: `task_id`, `agent_id`, `operator_id`, `principal_id`, `independence_group` and `holder_jkt`, the holder key the task's admission bound (the receipt's `holder_jkt`); `holder_jkt` defaults to the holder test key's `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M`. A task's reports accrue to its agent and holder key; no case records a verified rotation, so a query under another holder key gets the cold-start values. | 6.4, 10.1, 12.1, 14.6 rules 1 to 3 |
| `records` | object | yes | | From a native record reference, the value an `evidence_refs` entry cites, to the record: `kind`, `state`, `returned`, `task_id`, `operation_id`, `executor` and `observed_at`. The kinds and states are below; `returned` is `data` or `empty` for a completed execution and `null` otherwise; `executor` may be `null` for every kind but `execution` and `authorization`. | 14.2, 14.5, 17.5 |

| `kind` | `state` | Cited by | Draft |
|---|---|---|---|
| `execution` | `accepted`, `completed`, `failed` | `EXECUTION` reports | 14.2, 14.5 |
| `authorization` | `allowed`, `denied` | `AUTHORIZATION` reports | 14.2, 14.5 |
| `assessment` | `completed` | `QUALITY` reports, and `FEEDBACK` reports from an evaluator or the task owner: the evaluator's assessment of an observed task, on its quality or its policy adherence, which verified feedback conveys | 14.2, 14.5 |
| `incident` | `confirmed` | `SECURITY` reports of a security authority, and corrections of them: the confirmed incident of the report's task and operation | 14.2, 14.5, 15.4 |
| `violation` | `recorded` | Gateway `SECURITY` reports: the gateway's immutable record of the violating request (a refusal record or the receipt it was recorded against) | 14.2, 14.5 |
| `remediation` | `completed` | `REMEDIATION` reports, beside the `event_id` of the hold they clear | 15.4, 16.5 |

A `CORRECTION` cites the record a report of the kind it corrects would cite (Section 14.6 rule 10): a `FAILURE` correction of an `EXECUTION` event the failed execution, an `UNKNOWN` one any execution record of its task and operation that names the executor, a correction of a `QUALITY` event, or of an evaluator's or task owner's `FEEDBACK` event, a completed assessment, a correction of a violation report the `violation` record, a correction of a confirmed incident the `incident` record.

#### steps.json

An array. Each step has exactly one of the members `ingest` and `query`. The harness runs the steps in order against one reputation service state.

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `ingest` | string | one of | | An `event_id`: the harness submits `signed/<event_id>.jws` to the outcomes endpoint. Submitting the same file again is an identical retry. | 7.5, 13.2, 14.3 |
| `received_at` | integer | no | `config.json`'s `now` | The service clock at ingestion. | 7.5, 14.3 |
| `query` | `ReputationQuery` (A.3) | one of | | The query the harness submits to the reputation query endpoint: `agent_id`, `holder_jkt`, `context` and `audience`. | 13.2, 15.1 |
| `now` | integer | no | `config.json`'s `now` | The service clock at the query, the time `t` of Section 15.3. | 15.3 |

#### classifications.json

The shape of the v1 mapping file `qualification.json` ([outcomes/mapping/README.md](outcomes/mapping/README.md)): `case`, `adversarial_claim`, `subject_event_id`, `events` and `dimension_deltas`. Each entry of `events` has `event_id`, `report`, `signed`, `qualification`, `reason`, `contribution` and `rationale`. v2 allows `qualification` `null` for a report whose qualification the draft does not fix; the harness then does not judge it. `subject_event_id` names a report whose `qualification` is not `null`: a case about a duplicate names the original report, or has no `classifications.json` and is judged by `snapshot.json` and `acks.json`. The qualification is the one in force at the end of the case: a reciprocal endorsement turns an earlier positive report `DISPUTED`. A harness judges `qualification` and the snapshots; `reason`, `contribution` and `rationale` are the case's account of the draft rules for readers.

| `reason` | `qualification` | Meaning | Draft |
|---|---|---|---|
| `mapped` | `QUALIFIED` | The report follows a row of the Section 14.5 table and passes the checks of Section 14.2. | 14.2, 14.5 |
| `invalid-report` | `UNQUALIFIED` | The report breaks a dimension rule of A.2. | A.2 |
| `no-executor-record` | `UNQUALIFIED` | An `EXECUTION` or `AUTHORIZATION` report, other than a report of absent execution visibility (Section 14.5), cites no immutable native record that identifies the actual executor. | 14.2, 14.5, A.2 |
| `no-completion-record` | `UNQUALIFIED` | An `EXECUTION` `SUCCESS` or `FAILURE` report cites only a record of an accepted request. | 14.2, 14.5 |
| `executor-class-mismatch` | `UNQUALIFIED` | The cited record's executor class differs from the class `executor_classes` declares. | 14.2, 17.5, A.2 |
| `reporter-not-authorized` | `UNQUALIFIED` | The signer is not registered for the report's `reporter_role`, or the role may not report this observation, such as a `SECURITY` report from a reporter that is neither a security authority nor a gateway reporting a policy violation, or a gateway `SECURITY` report that is not a `FAILURE` on `policy_adherence`, or a security authority's `SECURITY` report that is not a `FAILURE` on `none`. | 14.2, 14.5, 14.6 rule 12, A.2 |
| `task-unreconciled` | `UNQUALIFIED` | The report's `task_id` does not reconcile with the authoritative task records. | 14.6 rule 2 |
| `duplicate` | `null` | A report with the tuple of an earlier report: it gets a `DUPLICATE` acknowledgment and casts no second vote. | 7.5, 14.6 rule 4 |
| `self-praise` | `UNQUALIFIED` | An evaluator report by the signer registered as executor for the same task. | 14.6 rule 5 |
| `affiliated-evaluator` | `UNQUALIFIED` | A positive `QUALITY` or `FEEDBACK` report by an evaluator or task owner affiliated with the agent's operator. | 14.6 rule 6 |
| `reciprocal-endorsement` | `DISPUTED` | One of two positive reports of a reciprocal endorsement. | 14.4, 14.6 rule 7 |
| `causal-zero-weight` | `QUALIFIED` | A report whose `causal_assessment` is `ENVIRONMENT`, `UNKNOWN` or `MIXED`: no negative weight. | 14.6 rules 8 and 9 |
| `correction` | `QUALIFIED` | A correction of qualified or disputed events of the same task, operation, kind and dimension, from the same reporter or a security authority; with `result` `UNKNOWN` it retracts them. | 14.4, 14.6 rule 10, A.2 |
| `correction-mismatch` | `UNQUALIFIED` | A correction that names an event of another task, operation, kind or dimension, a later event, a duplicate, an event that is not `QUALIFIED` or `DISPUTED`, or that another reporter signed. | 14.6 rule 10 |
| `record-mismatch` | `UNQUALIFIED` | The cited record is not of the kind or state the row requires: an `AUTHORIZATION` report whose result is not the record's decision, a `SECURITY` report on `policy_adherence` that cites no `violation` record of its task and operation, or a `SECURITY` report on `none` that cites no confirmed `incident` record of its task and operation. | 14.2, 14.5, 15.4 |
| `no-assessment-record` | `UNQUALIFIED` | A `QUALITY` report, or a `FEEDBACK` report from an evaluator or the task owner, that cites no completed assessment of its task. | 14.2, 14.5 |

#### snapshot.json

An array, one entry per query step, in order.

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `step` | integer | yes | | The index of the query step in `steps.json`, from 0. | 13.2 |
| `value` | object | yes | | Members the snapshot's `value` must carry, at any depth: a subset of `ReputationValue`. `score_bps` and `confidence_bps` match within one basis point; every other member matches exactly. | 15.2, 15.3, 15.4 |
| `provenance` | object | yes | | `qualified_event_ids` and `superseded_event_ids`, each a sorted array of `[iss, jti]` pairs, which the printed `ProvenanceManifest` must carry exactly. The harness also checks that the snapshot's `provenance_digest` is the `object_digest` of the printed manifest and that the manifest's `scoring_policy_revision` and `evidence_cutoff` are the value's. | 15.2, A.2 |
| `claims` | object | no | `{}` | Members the snapshot payload must carry with exactly these values, such as `sub`, `aud` and `holder_jkt`. | 7.3, 15.2 |
| `exp_max` | integer | no | the query's `now` plus 300 | The latest permitted `exp`. | 15.2 |

#### acks.json

An array, one entry per ingest step, in order.

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `step` | integer | yes | | The index of the ingest step. | 13.2 |
| `status` | string or `null` | yes | | `ACCEPTED` or `DUPLICATE`, the `Acknowledgment.status`; `null` when the report is refused. | 7.5, 13.2, 14.6 rule 4 |
| `transport_code` | string or `null` | yes | | The Section 13.4 code of the refusal; `null` when there is an acknowledgment. | 13.4, 14.3 |

#### Outcomes output

The outcomes command prints one JSON object: `steps`, one entry per step in order, and `classifications`. An ingest step's entry is `{"ack": <Acknowledgment>}` or `{"problem": <Problem>}`. A query step's entry is `{"snapshot": "<compact pact-reputation+jwt>", "provenance": <ProvenanceManifest>}`; Section 15.2 requires the service to produce the manifest to an authorized auditor, and the harness is one. `classifications` is optional: an object from `event_id` to the report's qualification at the end of the case, or `null` for a refused report. The draft defines no endpoint that discloses a qualification, so a command may omit it; the harness then reports the qualification sub-check `SKIP` and still judges the acknowledgments and snapshots.

#### Example: outcomes/qualification/correction-recompute

The reserved case of row `R15`: a correction supersedes a qualified success, and the next snapshot reflects it. The executor reports with its own key; the jti values are illustrative.

`config.json`, beside the members of the mapping cases:

```json
{"data_policy":{"qualification_policy_id":"pact-qualification-v1","ingestion_window_seconds":604800,"positive_weight_cap_per_task":1,"maximum_failure_weight":5,"task_attribution_source":"native-task-registry","reporter_independence_policy_id":"pact-reporter-independence-v1"},
 "trust":[{"iss":"https://executor.example/finance","role":"reporter","reporter_role":"executor","keys":["keys/executor.jwk.json"]}]}
```

The reports: `execution-event-0001`, `EXECUTION` `SUCCESS` on `reliability`, observed at 1792079980, citing the completed record; and `correction-event-0002`, `CORRECTION` `FAILURE` on `reliability`, with `supersedes` `["execution-event-0001"]`, the same task, operation and reporter, and `observed_at` 1792079980, the time of the observation it corrects, citing the failed record. The correction is issued at 1792080010, so its `signing.json` entry states `"iat":1792080010,"exp":1792080310`.

`steps.json`:

```json
[{"ingest":"execution-event-0001","received_at":1792080000},
 {"query":{"agent_id":"https://identity.example/agents/invoice-assistant","holder_jkt":"xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M","context":{"tenant_id":"acme","environment_id":"https://gateway.example/environments/finance","agent_id":"https://identity.example/agents/invoice-assistant","purpose_id":"https://policies.example/purposes/invoice-summary/v1","action_class":"invoice-summary.export","resource_class":"department-finance-summary-job","runtime_class":"managed-v1"},"audience":"https://gateway.example/finance"},"now":1792080000},
 {"ingest":"correction-event-0002","received_at":1792080010},
 {"query":{"agent_id":"https://identity.example/agents/invoice-assistant","holder_jkt":"xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M","context":{"tenant_id":"acme","environment_id":"https://gateway.example/environments/finance","agent_id":"https://identity.example/agents/invoice-assistant","purpose_id":"https://policies.example/purposes/invoice-summary/v1","action_class":"invoice-summary.export","resource_class":"department-finance-summary-job","runtime_class":"managed-v1"},"audience":"https://gateway.example/finance"},"now":1792080010}]
```

`expected/outcomes/qualification/correction-recompute/snapshot.json`. Before the correction, one qualified success 20 seconds old: alpha 1.99999, beta 1, so `score_bps` 6666 and `confidence_bps` 476 (Section 15.3). After it, the correction is scored as one failure in place of the success: alpha 1, beta 1.99999, so 3333 and 476, and the success moves to `superseded_event_ids` (Sections 14.6 rule 10 and 15.2).

```json
[{"step":1,"value":{"dimensions":{"reliability":{"score_bps":6666,"confidence_bps":476,"independent_tasks":1,"qualified_events":1}}},
  "provenance":{"qualified_event_ids":[["https://executor.example/finance","w46P9OrhZ5qRRPcgp_ErpA"]],"superseded_event_ids":[]}},
 {"step":3,"value":{"dimensions":{"reliability":{"score_bps":3333,"confidence_bps":476,"independent_tasks":1,"qualified_events":1}}},
  "provenance":{"qualified_event_ids":[["https://executor.example/finance","suzoq2sCaO6k4E5tLzZpyA"]],"superseded_event_ids":[["https://executor.example/finance","w46P9OrhZ5qRRPcgp_ErpA"]]}}]
```

`classifications.json` has `subject_event_id` `correction-event-0002`, with both reports `QUALIFIED`: the success `mapped`, the correction `correction`. The manifest entry has `expected` `expected/outcomes/qualification/correction-recompute/classifications.json` and `outcome` `QUALIFIED`.

### Learning cases

A learning case (kind `learning`) tests the learning service: registration of signed artifacts, lifecycle events, and the effect of outcome reports and assessments on the registry. A case is the directory `learning/<case>/`:

| File | Required | Content | Draft |
|---|---|---|---|
| `config.json` | yes | Trusted configuration of the learning service, below. | 4.2, 16.2 |
| `policies/<name>.json` | yes | Each `LearningPolicy`, decoded, signed into `signed/policies/<name>.jws` (`pact-learning-policy+jwt`). | 16.2, A.2 |
| `artifacts/<name>.json` | no | Each `LearningArtifact` manifest, decoded, signed into `signed/artifacts/<name>.jws` (`pact-learning-artifact+jwt`). | 16.3 |
| `events/<event_id>.json` | no | Each `LearningEvent`, decoded, signed into `signed/events/<event_id>.jws` (`pact-learning-event+jwt`). Its digest members are filled through `digests` in `signing.json`. | 16.4, 16.5 |
| `reports/<event_id>.json` | no | Each `OutcomeReport`, decoded, signed into `signed/reports/<event_id>.jws`. | 14.4, 15.4 |
| `native_context.json` | when there is a report | The task and native records of the outcomes format, against which the reports qualify. | 14.2 |
| `assessments/<name>.json` | no | Each LLM assessment record, below; unsigned. | 16.6 |
| `signing.json` | yes | The generator contract above. | 7.5 |
| `steps.json` | yes | The inputs, in order, below. | 13.2 |

The expected result is `expected/<id>/registry.json`; the entry's `outcome` is `ACCEPTED` or `REJECTED`, the result of the step that `subject` names, or `MATCH` when `registry.json` has no `subject`.

Appendix A.3 requires every release gate of A.2 in `evaluation_policy`, so a policy without one is rejected at its `policy` step (`INVALID_MESSAGE`) and never installed; that is the case `learning/missing-gate`. A gate that is present and not satisfied is `GATE_NOT_MET`, as in the example below.

#### config.json

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `now` | integer | yes | | The reference time; the default time of every step. | 7.5 |
| `clock_skew_seconds` | integer | yes | | The allowed clock skew. | 7.5 |
| `learning_service` | object | yes | | `service_id`, the `aud` of policies, artifacts and events, `tenant_id` and `environment_id`. | 13.2, A.2 |
| `trust` | array | yes | | The trusted registration of each signer: `iss`, `role` (`policy-authority`, `learning-controller` or `reporter`, with `reporter_role` for a reporter) and `keys`. | 7.3, 14.2, 16.2 |
| `evaluations` | object from evaluation reference to `{evaluator_id}` | no | `{}` | The evaluator behind each `LearningEvent.evaluation_refs` value. Evaluation evidence that resolves only to the candidate's own controller is self-evaluation. | 16.3, 16.4 |
| `source_data_manifests` | object from digest to array of `event_id` | no | `{}` | The outcome events behind each `source_data_manifest_digest`. A correction that supersedes one of them requires re-evaluation of every `ACTIVE` or `SHADOW` artifact that cites the digest. | 14.4, 16.5 |
| `gates` | array | no | `[]` | What the service observes for each artifact: `artifact_id`, `version`, `independent_tasks`, `observation_seconds`, `test_suites_passed` (digests of the immutable test suites the artifact passed) and `metrics` (object from metric id to number). The shadow duration is not listed: it is the time between the accepted `SHADOW` event and a later event. | 16.3, 16.4, A.2 |

A case with reports also carries the outcomes-case members `reputation_service`, whose `service_id` is the reports' `aud`, `visibility` and, when its reports need it, `executor_classes` (section Outcomes cases); the reports qualify under the installed learning policy's `data_policy`. An event that a `CORRECTION` step supersedes is ingested by an earlier `outcome` step, so that rule 10 can compare its task, operation, dimension and reporter.

#### steps.json

An array of steps, applied in order against one learning service state that starts with no artifact and the conservative set in every context.

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `file` | path | yes | | The signed file of the input, or the decoded file of an assessment. | 13.2 |
| `kind` | string | yes | | `policy`: the authority installs the policy, which replaces the previous one. A policy that fails signature verification or the `LearningPolicy` schema of Appendix A.3, such as one without a release gate of A.2, is not installed, and the step gets a rejection with empty `reason_codes` and the Section 13.4 code: `INVALID_PROOF` for a signature that does not verify, `INVALID_MESSAGE` for a malformed JWS, a `typ` other than the endpoint's, or a payload that fails the schema. `artifact`: registration at the learning artifacts endpoint. `event`: submission at the learning events endpoint. `outcome`: an outcome report at the outcomes endpoint, such as a `SECURITY`, `REMEDIATION` or `CORRECTION` report. `assessment`: an LLM assessment handed to the learning service as data. | 13.2, 16.2 to 16.6 |
| `received_at` | integer | no | `config.json`'s `now` | The service clock at the step. | 7.5, 16.5 |

An assessment record carries what Section 16.6 requires to be attributable: `prompt_digest`, `model` (`{id, version}`), `rubric_id`, `input_digest`, `output` (any JSON; untrusted data) and `uncertainty`.

#### registry.json

| Member | Type | Required | Default | Meaning | Draft |
|---|---|---|---|---|---|
| `artifacts` | object from path to state | yes | | The state of each registered artifact at the end of the case, keyed by its signed manifest: `CANDIDATE`, `EVALUATED`, `SHADOW`, `ACTIVE`, `FROZEN`, `ROLLED_BACK` or `RETIRED`. | 16.3, 16.5 |
| `active` | array | yes | | One entry per context named in the `intended_contexts` of a registered artifact: `context`, a `ReputationContext`, and `artifact`, the path of the active artifact's signed manifest, or `null` when the conservative set is in force. | 16.4, 16.5, A.2 |
| `acknowledgments` | array | yes | | `{step, status}` for each step the service acknowledges: `ACCEPTED` or `DUPLICATE`. | 7.5, 13.2, 16.3 |
| `rejections` | array | yes | | `{step, code, reason_codes}` for each step the service rejects: the Section 13.4 code, such as `LEARNING_REJECTED` or `ID_CONFLICT`, and the Section 16.5 reason codes the Problem's `extensions.reason_codes` carries (empty for a code without them). | 13.4, 16.3, 16.5 |
| `holds` | array of `event_id` | no | `[]` | The confirmed `SECURITY` reports whose hold is active. | 15.4, 16.5 |
| `reevaluation_required` | array of paths | no | `[]` | The artifacts whose re-evaluation a correction requires: each was `ACTIVE` or `SHADOW` when the correction arrived, and none has since had an accepted `EVALUATED` event or been `RETIRED`. | 14.4, 16.5 |
| `subject` | string | no | absent | An RFC 6901 pointer to the entry of `acknowledgments` or `rejections` that the manifest `outcome` summarizes. Absent: the case is judged by the registry state alone, as an assessment-only case is. | 16.5, 16.6 |

Steps of kind `policy` and `assessment` get no acknowledgment; only a policy step that is not installed gets a rejection.

#### Learning output

Standard output is one strict JSON object (duplicate or unknown members, including `subject`, are errors) with the members of `registry.json` except `subject`. `artifacts` is keyed by the `artifact_digest` of the signed manifest, and `active[].artifact` and `reevaluation_required` hold the same digests. `holds` hold `event_id` values. Each `acknowledgments` entry is `{step, status, ack}`, where `ack` is the Acknowledgment object (A.3) with the same `status`. Each `rejections` entry is `{step, code, reason_codes, problem}`, where `problem` is the RFC 9457 Problem whose `code` is the entry's and whose `extensions.reason_codes` equals `reason_codes`. Order of entries and of reason codes is not significant. The exit status is informational.

#### Example: a shadow phase that is too short

The case `learning/gate-not-met` ([learning/README.md](learning/README.md)), on the B.9 to B.11 objects. The policy is that of B.9 with its own `jti` and an `exp` 30 days after issuance, so that it outlives the shadow phase (Section 16.5); the artifact is that of B.10 with the same change. The evaluation reference resolves to the independent evaluator of the policy's `required_evaluator_ids`.

`config.json`, the members that matter here:

```json
{"evaluations":{"configured-evaluation-store:independent-0001":{"evaluator_id":"https://learning.example/evaluators/independent"}},
 "gates":[{"artifact_id":"https://learning.example/artifacts/baseline-v1","version":"1","independent_tasks":120,"observation_seconds":691200,"test_suites_passed":["I7Z5M225iXt94t2aNsPS_YEN07CyAkcn_SuW7d057Sg"],"metrics":{"native-denial-override-count":0,"admission-regression-rate":0.004}}]}
```

`steps.json`:

```json
[{"file":"signed/policies/finance.jws","kind":"policy","received_at":1792080000},
 {"file":"signed/artifacts/baseline-v1.jws","kind":"artifact","received_at":1792080000},
 {"file":"signed/events/learning-evaluated-event-0001.jws","kind":"event","received_at":1792080060},
 {"file":"signed/events/learning-shadow-event-0001.jws","kind":"event","received_at":1792080120},
 {"file":"signed/events/learning-active-event-0001.jws","kind":"event","received_at":1792083720},
 {"file":"signed/events/learning-active-event-0002.jws","kind":"event","received_at":1792166580}]
```

Each event is issued at its step's time, so its `signing.json` entry states that `iat` and an `exp` 300 seconds later, and fills its digests. The first `ACTIVE` event, for example:

```json
{"decoded":"events/learning-active-event-0001.json","signed":"signed/events/learning-active-event-0001.jws","typ":"pact-learning-event+jwt","signer":"learning-controller","jti":"MLkZJm1NFAtQcUiYR0oKvQ","iat":1792083720,"exp":1792084020,
 "digests":{"/artifact_digest":"signed/artifacts/baseline-v1.jws","/activate_artifact_digest":"signed/artifacts/baseline-v1.jws","/policy_digest":"signed/policies/finance.jws"}}
```

`expected/learning/<case>/registry.json`. The first `ACTIVE` event arrives one hour after the shadow phase began, short of `minimum_shadow_seconds` 86400, and is rejected; the second arrives after it and is accepted. The second arrives 86460 seconds after the shadow phase began, clear of the 86400-second bound:

```json
{"artifacts":{"signed/artifacts/baseline-v1.jws":"ACTIVE"},
 "active":[{"context":{"tenant_id":"acme","environment_id":"https://gateway.example/environments/finance","agent_id":"https://identity.example/agents/invoice-assistant","purpose_id":"https://policies.example/purposes/invoice-summary/v1","action_class":"invoice.read","resource_class":"department-finance-invoice","runtime_class":"managed-v1"},"artifact":"signed/artifacts/baseline-v1.jws"}],
 "acknowledgments":[{"step":1,"status":"ACCEPTED"},{"step":2,"status":"ACCEPTED"},{"step":3,"status":"ACCEPTED"},{"step":5,"status":"ACCEPTED"}],
 "rejections":[{"step":4,"code":"LEARNING_REJECTED","reason_codes":["GATE_NOT_MET"]}],
 "holds":[],"reevaluation_required":[],
 "subject":"/rejections/0"}
```

The manifest entry has `outcome` `REJECTED`.

### Migration of committed cases

The generator v2 change performed these changes; each is mechanical and leaves every signed file in place, since its header and payload do not change:

1. Every committed case of `admission/`, `approval/` and `outcomes/mapping/` gained a `signing.json` that states what the generator's former built-in list stated for it: the artifact entries with their `decoded`, `signed`, `typ`, `signer` and `jti`, and the presentation entry with its `signer` and `jti`. No `iat`, `nbf` or `exp` is stated, so the defaults apply, and the built-in list was removed.
2. The `outcomes/mapping/` cases move `qualification_policy_id`, `reporter_independence_policy_id` and `ingestion_window_seconds` from the top level of `config.json` into `data_policy`, beside `positive_weight_cap_per_task` 1, `maximum_failure_weight` 5 and `task_attribution_source` `native-task-registry`, the B.9 values.
3. Their expected file `qualification.json` is renamed `classifications.json`, unchanged, and the manifest `expected` follows.
4. Each of them gains a `steps.json` that ingests its reports in file-name order at `config.json`'s `now` and then queries the task's context at `now`, and an expected `snapshot.json` for that query. The snapshot values come from Sections 14.5 and 15.3, computed from the draft, not from an implementation; this item is the one that is not mechanical.
