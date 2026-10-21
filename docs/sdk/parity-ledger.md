# API parity ledger

This ledger maps every exported symbol of the Go library packages in scope to its name in the TypeScript and Python ports, with a status, and records the names of the core-only Rust port (section [Rust](#rust)). The parity mechanism it belongs to is described in [tools/parity/README.md](../../tools/parity/README.md#api-ledger). The ports follow it; a port that names a symbol differently changes its row in the same change.

`tools/parity/api_ledger.py` checks it. The script lists the packages with `go list`, reads each one with `go doc -all`, and fails on an exported symbol without a row, on a row whose symbol the package no longer exports, on a duplicate row, and on a malformed row. It runs in `ci-go`:

```sh
python3 -I tools/parity/api_ledger.py             # check the ledger
python3 -I tools/parity/api_ledger.py --list      # print the symbols in scope, one per line
python3 -I tools/parity/api_ledger.py --selftest  # check the parser and the rules (no Go needed)
```

A change that adds, removes or renames an exported symbol of a package in scope updates this file in the same change.

The rows of `adapter`, `adapter/enroll`, `adapter/enroll/memory`, `adapter/freshness` and the `adapter/adaptertest` case model are frozen for the ports ([tools/parity/README.md](../../tools/parity/README.md#adapter-contract), Adapter contract): a change to one of those symbols follows the change rule there.

## Scope

The packages that `go list ./core/... ./adapter/... ./adapters/memory ./contract ./gateway ./holder ./runner/manifest ./validator` names in the library module `go/`. A new package under `core/` or `adapter/` enters the scope, and the check, as soon as it exists. The native adapters (`adapters/basic`, `adapters/mtls`, `adapters/aws` and later ones) and `adapters/internal/broken` are outside it: whether a port implements one is decided per adapter ([tools/parity/README.md](../../tools/parity/README.md#native-adapters-and-sources), Native adapters and sources).

A symbol is what `go doc -all` prints:

- every exported constant, variable, function and type: `Name`;
- every exported method of an exported type, and every method of an exported interface: `Type.Method`;
- every exported field of an exported struct type, an embedded exported type included: `Type.Field`. The fields of an anonymous struct type are covered by the row of the field that holds it.

## Modules

Each package section gives names relative to the port module of the same path.

| Go package | TypeScript export | Python module |
|---|---|---|
| `core` | `@hop-top/pact` (`.`) | `hop_top_pact.core` |
| `core/binding` | `./core/binding` | `hop_top_pact.core.binding` |
| `core/clock` | `./core/clock` | `hop_top_pact.core.clock` |
| `core/digest` | `./core/digest` | `hop_top_pact.core.digest` |
| `core/jcs` | `./core/jcs` | `hop_top_pact.core.jcs` |
| `core/jws` | `./core/jws` | `hop_top_pact.core.jws` |
| `core/strictjson` | `./core/strictjson` | `hop_top_pact.core.strictjson` |
| `adapter` | `./adapter` | `hop_top_pact.adapter` |
| `adapter/adaptertest` | `./adapter/adaptertest` | `hop_top_pact.adapter.adaptertest` |
| `adapter/enroll` | `./adapter/enroll` | `hop_top_pact.adapter.enroll` |
| `adapter/enroll/memory` | `./adapter/enroll/memory` | `hop_top_pact.adapter.enroll_memory` |
| `adapter/freshness` | `./adapter/freshness` | `hop_top_pact.adapter.freshness` |
| `adapter/installed` | `./adapter/installed` | `hop_top_pact.adapter.installed` |
| `adapter/source` | `./adapter/source` | `hop_top_pact.adapter.source` |
| `adapter/source/googledir` | `./adapter/source/googledir` | `hop_top_pact.adapter.source_googledir` |
| `adapter/source/scim` | `./adapter/source/scim` | `hop_top_pact.adapter.source_scim` |
| `adapter/source/ssf` | `./adapter/source/ssf` | `hop_top_pact.adapter.source_ssf` |
| `adapter/sourcetest` | `./adapter/sourcetest` | `hop_top_pact.adapter.sourcetest` |
| `adapter/task` | `./adapter/task` | `hop_top_pact.adapter.task` |
| `adapters/memory` | `./adapters/memory` | `hop_top_pact.adapters.memory` |
| `contract` | `./contract` | `hop_top_pact.contract` |
| `gateway` | `./gateway` | `hop_top_pact.gateway` |
| `holder` | `./holder` | `hop_top_pact.holder` |
| `runner/manifest` | `./runner/manifest` | `hop_top_pact.runner.manifest` |
| `validator` | `./validator` | `hop_top_pact.validator` |

The PHP namespaces are in section [PHP](#php).

Every package follows the same path rule: the TypeScript export and the Python module mirror the Go import path. `contract` is requirement contract issuance and verification (draft Sections 9.1 to 9.4); `holder` is the agent side: profile disclosure, contract verification and signed presentations (draft Sections 8, 10, 11.2 and 22.1); `validator` is the admission validator (draft Sections 11.3 to 12.2); `gateway` is the in-gateway admission middleware (draft Sections 4.4, 9.1, 10.2, 13.2 and 13.4).

## Columns and statuses

| Column | Content |
|---|---|
| Go symbol | the symbol, as above; one code span |
| TypeScript | the name in the TypeScript port |
| Python | the name in the Python port |
| Status | `planned`: the port does not have it yet; `done`: both ports have it under these names and its tests are ported; `deviation`: the ports differ from Go in a documented way (section [Deviations](#deviations)); `SDK extra`: a port module or name with no Go symbol, only in section [SDK extras](#sdk-extras) |
| Note | the reason for a deviation or for a name that does not follow the rules below |

A row moves from `planned` to `done` when both ports land it. A `deviation` row stays `deviation`.

## Naming rules

The names below follow these rules, except where a row's note says otherwise. Go initialisms stay one word: upper case inside a TypeScript name (`parseJWK`, `fromJSON`), lower case in a Python name (`parse_jwk`, `from_json`). One exception in TypeScript: `ID` inside a lowerCamel name (function, method, field, option) is written `Id` (`sourceId`, `withSourceId`, `newId`). Type names keep the Go spelling (`AgentID`, `TLSPeer`) and `UPPER_SNAKE` names are unchanged (`DEFAULT_SOURCE_ID`).

TypeScript casing follows what the existing TypeScript code already does:

- The TypeScript port writes every `ID` of a lowerCamel name as `Id` (`sourceId`, `principalId`, `checkId`, the `sourceId` option of `MemoryRegistry`) and every other initialism in upper case (`parseJWK`, `publicJWK`, `presentationJSON`, `fromJSON`, `JWSError`, `StrictJSONError`, `TLSPeer`, `subjectCN`). `rawRequestURI` of `RawRequest`, which names no Go symbol, follows the same rule.
- The TypeScript code of the hop-top kit (hop-top/poly-kit: `sdk/ts`, published as `@hop-top/kit`, `engine/sdk/ts-kit-engine` and `examples/spaced/ts`; non-test sources) agrees on `ID` by majority: 10 lowerCamel names use `Id` (`getInstallId` in `sdk/ts/src/telemetry/installId.ts`, `newId`, `nextId`, `installationId`, `validModernRequestId`) against 4 with `ID` (`handlerID` in `sdk/ts/src/uri.ts`, which wraps a dependency's function of that name, and three private constants of `installId.ts`, `installIDSize` among them). Its other initialisms are split: 27 names keep them upper case (`baseURL`, `parseURI`, `isValidJSON`, `APIClient`, `createCLI`, `LLMError`) and 35 capitalize them (`baseUrl`, `JsonRpcRequest`), 23 of those the `Mcp*` names of its `mcp/` module (`McpBridge`); `URL` alone is 4 to 4. The kit does not decide them, so upper case stands.
- No lint configuration sets a naming rule: the kit lints with `typescript-eslint` `recommended` (`sdk/ts/eslint.config.mjs`), which has no `naming-convention` rule, and the Biome rules of `ts/biome.json` name none.

| Go | TypeScript | Python |
|---|---|---|
| type, interface | same name | same name |
| function | `lowerCamel` | `snake_case` |
| method, interface method | `Type.lowerCamel` | `Type.snake_case` |
| field with a `json` tag | `Type.<json name>` (the generated types keep the JSON member names) | `Type.<json name>` |
| other field | `Type.lowerCamel` | `Type.snake_case` |
| constant of an exported type of the package (`go doc` lists it under the type) | `Type.MEMBER`: the name without the words its group shares, in `UPPER_SNAKE` | `Type.MEMBER`, a member of the `StrEnum` or `IntEnum` |
| other constant | `UPPER_SNAKE` | `UPPER_SNAKE` |
| sentinel error `ErrX` | a kind or code of the package's error class | a kind or code of the package's error class, or a subclass where its row names one |
| `Valid()` | guard `isType(x)` | `Type.is_valid(s)` |
| `Error()`, `Unwrap()`, `String()`, `Is()` | `message`, `cause`, `toString`, `instanceof` | `__str__`, `__cause__`, `__str__`, `isinstance` |
| `New*` constructor | `new Type(...)`, or the factory its row names | `Type(...)`, or the factory its row names |

## Deviations

The documented deviations ([tools/parity/README.md](../../tools/parity/README.md#deviations)). Every row they touch has status `deviation` and names the deviation in its note.

| Deviation | Go | TypeScript | Python | Rows |
|---|---|---|---|---|
| time precision | nanoseconds (`time.Time`, `time.Duration`) | milliseconds | microseconds | every function, method and field whose declaration has a `time.Time` or `time.Duration` |
| raw member values | `core.Object` holds `json.RawMessage` | raw text kept by the in-house tokenizer | parsed immutable values; JCS over the parsed tree equals JCS over the text because the strict parse admits only losslessly parsed values | `core` `Object` |
| adapter calls | synchronous, `context.Context` first | `Promise`, `AbortSignal` | synchronous `Protocol`, no context argument | every function and method that takes a `context.Context` |
| schema validation module | none in the library | SDK extra | SDK extra | section [SDK extras](#sdk-extras) |

## SDK extras

Port modules and names with no Go symbol.

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| none | `./core/schema` | `hop_top_pact.core.schema` | SDK extra | schema validation module over the vendored `pact.schema.json`; the Go library has none |
| none | none: a free-form member is `RawJSON` text, `null` when absent | `hop_top_pact.adapter.adaptertest.ABSENT` | SDK extra | `adapter/adaptertest` case model: the value of a free-form member (Go `json.RawMessage`) that the case file leaves out, told apart from a JSON `null` (`None`); Go keeps the raw bytes, nil when absent, and has no symbol for it |

## Rust

The Rust SDK (`rs/`, crate `hop-top-pact`, library `hop_top_pact`) is core-only ([tools/parity/README.md](../../tools/parity/README.md#what-parity-means)): it ports the `core` packages below and no other package in scope. Its names are recorded here, per package, instead of in a column of the package sections; `tools/parity/api_ledger.py` does not read this section. A Go symbol of a ported package that is not listed below has the Rust name the rules give.

### Modules

| Go package | Rust module | Status | Note |
|---|---|---|---|
| `core` | `hop_top_pact::core` | done | wire types, enums, `Digest`, `Limits` |
| `core/strictjson` | `hop_top_pact::core::strictjson` | done |  |
| `core/jcs` | `hop_top_pact::core::jcs` | done |  |
| `core/digest` | `hop_top_pact::core::digest` | done |  |
| `core/jws` | `hop_top_pact::core::jws` | deviation | ES256 only, see below |
| `core/clock` | `hop_top_pact::core::clock` | done |  |
| `core/binding` | none | n/a | outside the core-only scope; gate `adapter/vector/vectors/binding` is `n/a` for `rs` |
| every other package in scope | none | n/a | adapter contract, adapters, `contract`, `gateway`, `holder`, `runner/manifest`, `validator` |
| none | `hop_top_pact::core::schema` | SDK extra | as in TypeScript and Python |

### Naming rules

| Go | Rust |
|---|---|
| type, interface | same name; an interface is a trait (`KeyResolver`, `Clock`) |
| function | `snake_case` (`object_digest`, `check_window`, `parse_jwk`) |
| method | `Type::snake_case` |
| field with a `json` tag | the JSON member name (`iss`, `holder_jkt`, `r#type` for `type`) |
| other field | `snake_case` (`max_bytes`, `expected_holder_jkt`) |
| constant of a string enum of `core` | an associated constant `Type::MEMBER` of the open newtype (`Mode::OBSERVE`), with `Type::VALUES` and `Type::is_valid` for `Valid()` |
| other constant | `UPPER_SNAKE` (`MAX_SAFE_INTEGER`, `TYP_EVIDENCE`, `KEY_MAX_JSON_DEPTH`) |
| sentinel error `ErrX` | a variant of the module's kind enum: `strictjson::Kind::X`, `clock::Kind::X`, `jws::Reason::X` (the `Reason` names are the vector strings, `Reason::as_str`), `digest::Error::NotObject` |
| `Error()`, `Unwrap()`, `String()` | `Display`, `std::error::Error::source`, `Display` |
| `New*` constructor | `Type::new` |

### Symbols that do not follow the rules

| Go symbol | Rust | Status | Note |
|---|---|---|---|
| `core/strictjson` `Unmarshal` | `strictjson::unmarshal` | done | any `serde::de::DeserializeOwned` target; the unknown-field rule needs `#[serde(deny_unknown_fields)]`, which every `core` type has |
| `core/strictjson` `Decode` | `strictjson::decode` | done | returns `DecodeError`, a read error or a `strictjson::Error` |
| `core/strictjson` `ErrTarget` | none | deviation | the type system rules out a target that is not a pointer |
| none | `strictjson::parse` | SDK extra | decode into `serde_json::Value`, as Go decodes into `any` |
| `core/jcs` `Canonicalize` | `jcs::canonicalize`, `jcs::canonicalize_value` | done | `canonicalize_value` takes a `serde_json::Value`, as Python's |
| `core/digest` `ObjectDigest` | `digest::object_digest`, `digest::object_digest_json` | done | `object_digest_json` digests received JSON text |
| `core/clock` `NewFake` | `clock::Fake::new` | done |  |
| `core/clock` `MaxLifetime` | `clock::max_lifetime` | deviation | returns a `Duration`; the closed `Artifact` enum has no unknown value, so there is no `ErrUnknownArtifact` |
| `core/clock` `ErrUnknownArtifact` | none | deviation | see `MaxLifetime` |
| `core/jws` `Verify` | `jws::verify` | done |  |
| `core/jws` `Verifier` | `jws::Verifier` | done | borrows its resolver (`keys: Option<&dyn KeyResolver>`) and its algorithms |
| `core/jws` `Sign` | `jws::sign` | done | random nonces from the operating system's generator, S normalized to the low value, as in Go |
| `core/jws` `SignEd25519`, `PublicEd25519JWK`, `JWK.Ed25519PublicKey` | none | deviation | Ed25519 is not implemented |
| `core/jws` `AlgEd25519` | `jws::ALG_ED25519` | deviation | `Algorithms::accepts` never accepts it, so an Ed25519 header or key is rejected even where it is listed |
| `core/jws` `Thumbprint` | `jws::thumbprint` | deviation | an OKP key fails with `Reason::JWKCurve` |
| `core/jws` `KeyResolver.TrustedKeys` | `KeyResolver::trusted_keys` | done | returns `Option<&KeySet>` borrowed from the resolver |
| `core/jws` `Role` constants | `jws::Role` enum variants (`Role::RequirementPublisher`) | done | `Role::as_str` gives the draft name, `Role::parse` reads it |
| `core` `Object` | `core::Object` | deviation | `BTreeMap<String, serde_json::Value>`: parsed values, as in Python; the strict parse admits only losslessly parsed values, so JCS over the parsed tree equals JCS over the text |
| `core` `Limits.Validate*` | `Limits::validate_*` | done | take a reference; a nil object cannot occur, so there is no `ErrNilObject` |

### Deviations

| Area | Go | Rust |
|---|---|---|
| time precision | nanoseconds (`time.Time`, `time.Duration`) | nanoseconds (`SystemTime`, `Duration`); a skew is a `Duration`, so a negative skew cannot be passed |
| raw member values | `json.RawMessage` | `serde_json::Value`, as in Python |
| error order of a document with two faults | the first fault in document order | document faults (syntax, duplicate names, depth, numbers, trailing data) before type faults (unknown fields, `null`, integer targets), and an unpaired surrogate last |
| non-finite numbers in `ObjectDigest` | an encode error | a non-finite `f64` of a caller's own type encodes as `null` (`serde_json`); the `core` types hold no `f64` outside `MetricBound.value` |
| optional capability `jws-ed25519` | declared | not declared: the harness prints `skipped:capability` for an entry that needs it |

## PHP

The PHP SDK (`php/`, Packagist `hop-top/pact`, namespace `HopTop\Pact`) is core-only ([tools/parity/README.md](../../tools/parity/README.md#what-parity-means)). This section maps the Go packages in scope to its namespaces; the symbol rows below carry the TypeScript and Python names only. A Go symbol of a core package has a PHP name under the rules here; a package marked `n/a` has none, by scope.

| Go package | PHP namespace | Status | Note |
|---|---|---|---|
| `core` | `HopTop\Pact\Core` | done | generated wire classes with a `MEMBERS` table each, backed enums, `Digest`, `Limits`, `LimitError`; package constants on `Core` (`Core::VERSION`, `Core::DIGEST_LEN`, `Core::KEY_MAX_*`) |
| `core/strictjson` | `Core\StrictJson` | done | `StrictJson::parse`, `decode`, `parseStream`; `StrictJsonError` with the 13 Go kinds |
| `core/jcs` | `Core\Jcs` | done | `Jcs::canonicalize`, `Jcs::canonicalizeValue` |
| `core/digest` | `Core\Digest` | done | `Digests::objectDigest`, `artifactDigest`, `bytesDigest`; `NotObjectError` |
| `core/jws` | `Core\Jws` | done | `Jws::sign`, `verify`, `parseJwk`, `publicJwk`, `thumbprint`, `typRole`, `typs`, `reasonOf`; `Verifier`, `ParsedJws`, `Header`, `Jwk`, `KeySet`, `KeyResolver`, `KeyRequest`, `StaticResolver`, `Reason` (29 values), `Role`, `JwsError`; ES256 only |
| `core/clock` | `Core\Clock` | done | `Clock`, `SystemClock`, `FakeClock`; the functions on `Clocks`; `ClockError` with the 8 Go kinds |
| `runner/manifest` | none | n/a | the vectors harness reads the manifest with its own plain reader, as the Rust harness does |
| `core/binding` | none | n/a | the binding vectors have scope `adapter` |
| `adapter`, `adapter/...`, `adapters/memory` | none | n/a | no adapter contract in a core-only SDK |
| `contract`, `gateway`, `holder`, `validator` | none | n/a | outside the core scope |

Naming: Go type names unchanged; functions and methods `lowerCamel`; constants `UPPER_SNAKE`; a Go string enum is a PHP backed enum whose cases follow the Python member names, with `Valid()` as `Enum::isValid(string)`; a sentinel error is a kind, reason or code of the package's error class, which extends `HopTop\Pact\PactError`; package-level functions are static methods of a final class, since Composer autoloads classes only.

PHP deviations, beside those of section [Deviations](#deviations):

| Deviation | Go | PHP |
|---|---|---|
| time precision | nanoseconds | microseconds (`DateTimeImmutable`); durations are integer microseconds |
| raw member values (`core.Object`) | `json.RawMessage` | parsed immutable values, objects as `JsonObject`; JCS over the parsed tree equals JCS over the text because the strict parse admits only losslessly parsed values |
| enum-typed members | typed string | `string` properties, the enum class named in `MEMBERS`, so an unknown value decodes as in Go and is left to the schema |
| private keys | `*ecdsa.PrivateKey` | `OpenSSLAsymmetricKey`, with `Jws::privateKey` and `Jws::parsePrivateJwk` |

SDK extra of the PHP SDK: `Core\Schema` (validation with `opis/json-schema` and the in-house `uri` format). The vectors harness (`scripts/vectors.php`, namespace `HopTop\Pact\Vectors`, the schema-case verdict included) is a harness entry point, not SDK API.

## `adapter`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `ErrInvalidMessage` | `AdapterError` code `INVALID_MESSAGE` | `InvalidMessage(AdapterError)` | done |  |
| `ErrInvalidProof` | `AdapterError` code `INVALID_PROOF` | `InvalidProof(AdapterError)` | done |  |
| `ErrContextMismatch` | `AdapterError` code `CONTEXT_MISMATCH` | `ContextMismatch(AdapterError)` | done |  |
| `ErrDependencyUnavailable` | `AdapterError` code `DEPENDENCY_UNAVAILABLE` | `DependencyUnavailable(AdapterError)` | done |  |
| `ErrUnsupportedRequirement` | `AdapterError` code `UNSUPPORTED_REQUIREMENT` | `UnsupportedRequirement(AdapterError)` | done |  |
| `ErrUnsupportedPurpose` | `AdapterError` code `UNSUPPORTED_PURPOSE` | `UnsupportedPurpose(AdapterError)` | done |  |
| `ErrMissingField` | `AdapterError` code `MISSING_FIELD` | `MissingField(AdapterError)` | done |  |
| `Adapter` | `Adapter` | `Adapter` | done |  |
| `Adapter.Describe` | `Adapter.describe` | `Adapter.describe` | done |  |
| `AgentBinding` | `AgentBinding` | `AgentBinding` | done |  |
| `AgentBinding.AgentID` | `AgentBinding.agentId` | `AgentBinding.agent_id` | done |  |
| `AgentBinding.OperatorID` | `AgentBinding.operatorId` | `AgentBinding.operator_id` | done |  |
| `AgentBinding.HolderJKT` | `AgentBinding.holderJKT` | `AgentBinding.holder_jkt` | done |  |
| `AgentBinding.Status` | `AgentBinding.status` | `AgentBinding.status` | done |  |
| `AgentBinding.ObservedAt` | `AgentBinding.observedAt` | `AgentBinding.observed_at` | deviation | deviation: time precision |
| `AgentBinding.StatusCheckedAt` | `AgentBinding.statusCheckedAt` | `AgentBinding.status_checked_at` | deviation | deviation: time precision |
| `AgentBinding.SourceID` | `AgentBinding.sourceId` | `AgentBinding.source_id` | done |  |
| `AgentBinding.SourceRef` | `AgentBinding.sourceRef` | `AgentBinding.source_ref` | done |  |
| `AgentBinding.EnrolledElsewhere` | `AgentBinding.enrolledElsewhere` | `AgentBinding.enrolled_elsewhere` | done |  |
| `AgentID` | `AgentID` | `AgentID` | done |  |
| `BindingResolver` | `BindingResolver` | `BindingResolver` | done |  |
| `BindingResolver.ResolveAgentBinding` | `BindingResolver.resolveAgentBinding` | `BindingResolver.resolve_agent_binding` | deviation | deviation: adapter calls |
| `BindingStatus` | `BindingStatus` | `BindingStatus` | done |  |
| `BindingActive` | `BindingStatus.ACTIVE` | `BindingStatus.ACTIVE` | done |  |
| `BindingRevoked` | `BindingStatus.REVOKED` | `BindingStatus.REVOKED` | done |  |
| `BindingCompromised` | `BindingStatus.COMPROMISED` | `BindingStatus.COMPROMISED` | done |  |
| `BindingUnknown` | `BindingStatus.UNKNOWN` | `BindingStatus.UNKNOWN` | done |  |
| `BindingStatus.Valid` | `isBindingStatus(x)` | `BindingStatus.is_valid(s)` | done | guard |
| `CheckInput` | `CheckInput` | `CheckInput` | done |  |
| `CheckInput.Principal` | `CheckInput.principal` | `CheckInput.principal` | done |  |
| `CheckInput.Binding` | `CheckInput.binding` | `CheckInput.binding` | done |  |
| `CheckInput.Intent` | `CheckInput.intent` | `CheckInput.intent` | done |  |
| `CheckInput.Operation` | `CheckInput.operation` | `CheckInput.operation` | done |  |
| `CheckInput.EvidenceRefs` | `CheckInput.evidenceRefs` | `CheckInput.evidence_refs` | done |  |
| `CheckOutcome` | `CheckOutcome` | `CheckOutcome` | done |  |
| `CheckOutcome.Result` | `CheckOutcome.result` | `CheckOutcome.result` | done |  |
| `CheckOutcome.ReasonCode` | `CheckOutcome.reasonCode` | `CheckOutcome.reason_code` | done |  |
| `CheckOutcome.SourceID` | `CheckOutcome.sourceId` | `CheckOutcome.source_id` | done |  |
| `CheckOutcome.SourceRef` | `CheckOutcome.sourceRef` | `CheckOutcome.source_ref` | done |  |
| `CheckOutcome.ObservedAt` | `CheckOutcome.observedAt` | `CheckOutcome.observed_at` | deviation | deviation: time precision |
| `ClaimContext` | `ClaimContext` | `ClaimContext` | done |  |
| `ClaimContext.Principal` | `ClaimContext.principal` | `ClaimContext.principal` | done |  |
| `ClaimContext.Intent` | `ClaimContext.intent` | `ClaimContext.intent` | done |  |
| `ClaimContext.Operation` | `ClaimContext.operation` | `ClaimContext.operation` | done |  |
| `ClaimReader` | `ClaimReader` | `ClaimReader` | done |  |
| `ClaimReader.ReadNativeClaim` | `ClaimReader.readNativeClaim` | `ClaimReader.read_native_claim` | deviation | deviation: adapter calls |
| `Code` | `Code` | `Code` | done |  |
| `CodeInvalidMessage` | `Code.INVALID_MESSAGE` | `Code.INVALID_MESSAGE` | done |  |
| `CodeInvalidProof` | `Code.INVALID_PROOF` | `Code.INVALID_PROOF` | done |  |
| `CodeContextMismatch` | `Code.CONTEXT_MISMATCH` | `Code.CONTEXT_MISMATCH` | done |  |
| `CodeDependencyUnavailable` | `Code.DEPENDENCY_UNAVAILABLE` | `Code.DEPENDENCY_UNAVAILABLE` | done |  |
| `CodeUnsupportedRequirement` | `Code.UNSUPPORTED_REQUIREMENT` | `Code.UNSUPPORTED_REQUIREMENT` | done |  |
| `CodeUnsupportedPurpose` | `Code.UNSUPPORTED_PURPOSE` | `Code.UNSUPPORTED_PURPOSE` | done |  |
| `CodeMissingField` | `Code.MISSING_FIELD` | `Code.MISSING_FIELD` | done |  |
| `CodeOf` | `codeOf` | `code_of` | done | walks `cause` (TS) and `__cause__` (Python) |
| `ContextChecker` | `ContextChecker` | `ContextChecker` | done |  |
| `ContextChecker.CheckContext` | `ContextChecker.checkContext` | `ContextChecker.check_context` | deviation | deviation: adapter calls |
| `Decision` | `Decision` | `Decision` | done |  |
| `Decision.Effect` | `Decision.effect` | `Decision.effect` | done |  |
| `Decision.Obligations` | `Decision.obligations` | `Decision.obligations` | done |  |
| `Decision.Reason` | `Decision.reason` | `Decision.reason` | done |  |
| `Decision.SourceID` | `Decision.sourceId` | `Decision.source_id` | done |  |
| `Decision.SourceRef` | `Decision.sourceRef` | `Decision.source_ref` | done |  |
| `Decision.DecidedAt` | `Decision.decidedAt` | `Decision.decided_at` | deviation | deviation: time precision |
| `Decision.PolicyRevision` | `Decision.policyRevision` | `Decision.policy_revision` | done |  |
| `Decision.Permits` | `Decision.permits` | `Decision.permits` | done |  |
| `DenialReason` | `DenialReason` | `DenialReason` | done |  |
| `DenialNoCredential` | `DenialReason.NO_CREDENTIAL` | `DenialReason.NO_CREDENTIAL` | done |  |
| `DenialCredentialRejected` | `DenialReason.CREDENTIAL_REJECTED` | `DenialReason.CREDENTIAL_REJECTED` | done |  |
| `DenialReason.Valid` | `isDenialReason(x)` | `DenialReason.is_valid(s)` | done | guard |
| `Descriptor` | `Descriptor` | `Descriptor` | done |  |
| `Descriptor.Protocol` | `Descriptor.protocol` | `Descriptor.protocol` | done |  |
| `Descriptor.Version` | `Descriptor.version` | `Descriptor.version` | done |  |
| `Descriptor.MappingRevision` | `Descriptor.mappingRevision` | `Descriptor.mapping_revision` | done |  |
| `Descriptor.NativeAdapter` | `Descriptor.nativeAdapter` | `Descriptor.native_adapter` | done |  |
| `DescriptorsOf` | `descriptorsOf` | `descriptors_of` | done |  |
| `MultiDescriber` | `MultiDescriber` | `MultiDescriber` | done |  |
| `MultiDescriber.Descriptors` | `MultiDescriber.descriptors` | `MultiDescriber.descriptors` | done |  |
| `Effect` | `Effect` | `Effect` | done |  |
| `EffectAllow` | `Effect.ALLOW` | `Effect.ALLOW` | done |  |
| `EffectDeny` | `Effect.DENY` | `Effect.DENY` | done |  |
| `EffectUnknown` | `Effect.UNKNOWN` | `Effect.UNKNOWN` | done |  |
| `Effect.Valid` | `isEffect(x)` | `Effect.is_valid(s)` | done | guard |
| `Mechanism` | `Mechanism` | `Mechanism` | done |  |
| `NativeAuthenticator` | `NativeAuthenticator` | `NativeAuthenticator` | done |  |
| `NativeAuthenticator.AuthenticateNative` | `NativeAuthenticator.authenticateNative` | `NativeAuthenticator.authenticate_native` | deviation | deviation: adapter calls |
| `NativeAuthorizer` | `NativeAuthorizer` | `NativeAuthorizer` | done |  |
| `NativeAuthorizer.AuthorizeNative` | `NativeAuthorizer.authorizeNative` | `NativeAuthorizer.authorize_native` | deviation | deviation: adapter calls |
| `NativeClaim` | `NativeClaim` | `NativeClaim` | done |  |
| `NativeClaim.Value` | `NativeClaim.value` | `NativeClaim.value` | done |  |
| `NativeClaim.ObservedAt` | `NativeClaim.observedAt` | `NativeClaim.observed_at` | deviation | deviation: time precision |
| `NativeClaim.StatusCheckedAt` | `NativeClaim.statusCheckedAt` | `NativeClaim.status_checked_at` | deviation | deviation: time precision |
| `NativeClaim.SourceID` | `NativeClaim.sourceId` | `NativeClaim.source_id` | done |  |
| `NativeClaim.SourceRef` | `NativeClaim.sourceRef` | `NativeClaim.source_ref` | done |  |
| `NativeDenial` | `NativeDenial` | `NativeDenial` | done |  |
| `NativeDenial.Reason` | `NativeDenial.reason` | `NativeDenial.reason` | done |  |
| `NativeDenial.Code` | `NativeDenial.code` | `NativeDenial.code` | done |  |
| `NativeDenial.Error` | `NativeDenial.message` | `NativeDenial.__str__` | done | Go `error` interface |
| `NativeDenial.Is` | `instanceof` | `isinstance` | done | Go `errors.Is` target |
| `NativeDenial.PublicReason` | `NativeDenial.publicReason` | `NativeDenial.public_reason` | done |  |
| `NoVisibility` | `NoVisibility` | `NoVisibility` | done |  |
| `NoVisibility.Reason` | `NoVisibility.reason` | `NoVisibility.reason` | done |  |
| `NoVisibility.Validate` | `NoVisibility.validate` | `NoVisibility.validate` | done |  |
| `Obligation` | `Obligation` | `Obligation` | done |  |
| `Obligation.ID` | `Obligation.id` | `Obligation.id` | done |  |
| `Obligation.Attributes` | `Obligation.attributes` | `Obligation.attributes` | done |  |
| `Observation` | `Observation` | `Observation` | done |  |
| `Observation.EventID` | `Observation.eventId` | `Observation.event_id` | done |  |
| `Observation.EventKind` | `Observation.eventKind` | `Observation.event_kind` | done |  |
| `Observation.Context` | `Observation.context` | `Observation.context` | done |  |
| `Observation.TaskID` | `Observation.taskId` | `Observation.task_id` | done |  |
| `Observation.OperationID` | `Observation.operationId` | `Observation.operation_id` | done |  |
| `Observation.AdmissionReceiptID` | `Observation.admissionReceiptId` | `Observation.admission_receipt_id` | done |  |
| `Observation.ObservedAt` | `Observation.observedAt` | `Observation.observed_at` | deviation | deviation: time precision |
| `Observation.Result` | `Observation.result` | `Observation.result` | done |  |
| `Observation.Dimension` | `Observation.dimension` | `Observation.dimension` | done |  |
| `Observation.Severity` | `Observation.severity` | `Observation.severity` | done |  |
| `Observation.EvidenceRefs` | `Observation.evidenceRefs` | `Observation.evidence_refs` | done |  |
| `Observation.Attribution` | `Observation.attribution` | `Observation.attribution` | done |  |
| `Observation.Supersedes` | `Observation.supersedes` | `Observation.supersedes` | done |  |
| `Observation.Details` | `Observation.details` | `Observation.details` | done |  |
| `OperationMapper` | `OperationMapper` | `OperationMapper` | done |  |
| `OperationMapper.MapOperation` | `OperationMapper.mapOperation` | `OperationMapper.map_operation` | deviation | deviation: adapter calls |
| `OutcomeRecorder` | `OutcomeRecorder` | `OutcomeRecorder` | done |  |
| `OutcomeRecorder.RecordOutcome` | `OutcomeRecorder.recordOutcome` | `OutcomeRecorder.record_outcome` | deviation | deviation: adapter calls |
| `Principal` | `Principal` | `Principal` | done |  |
| `Principal.ID` | `Principal.id` | `Principal.id` | done |  |
| `Principal.Realm` | `Principal.realm` | `Principal.realm` | done |  |
| `Principal.Workload` | `Principal.workload` | `Principal.workload` | done |  |
| `Principal.Mechanism` | `Principal.mechanism` | `Principal.mechanism` | done |  |
| `Principal.AuthenticatedAt` | `Principal.authenticatedAt` | `Principal.authenticated_at` | deviation | deviation: time precision |
| `Principal.Attributes` | `Principal.attributes` | `Principal.attributes` | done |  |
| `Realm` | `Realm` | `Realm` | done |  |
| `Realm.TenantID` | `Realm.tenantId` | `Realm.tenant_id` | done |  |
| `Realm.EnvironmentID` | `Realm.environmentId` | `Realm.environment_id` | done |  |
| `Recorded` | `Recorded` | `Recorded` | done |  |
| `Recorded.Validate` | `Recorded.validate` | `Recorded.validate` | done |  |
| `Signed` | `Signed` | `Signed` | done |  |
| `Signed.JWS` | `Signed.jws` | `Signed.jws` | done |  |
| `Signed.Validate` | `Signed.validate` | `Signed.validate` | done |  |
| `Verdict` | `Verdict` | `Verdict` | done |  |
| `VerdictPass` | `Verdict.PASS` | `Verdict.PASS` | done |  |
| `VerdictFail` | `Verdict.FAIL` | `Verdict.FAIL` | done |  |
| `VerdictUnknown` | `Verdict.UNKNOWN` | `Verdict.UNKNOWN` | done |  |
| `Verdict.CheckStatus` | `Verdict.checkStatus` | `Verdict.check_status` | done |  |
| `Verdict.Valid` | `isVerdict(x)` | `Verdict.is_valid(s)` | done | guard |
| `Workload` | `Workload` | `Workload` | done |  |

## `adapter/adaptertest`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `DefaultFixtures` | `defaultFixtures` | `default_fixtures` | done | `FixtureTree = {read(path), list(dir)}` over a root directory |
| `Run` | `runConformance` | `run_case`, `conformance_cases` | done | TS takes a `TestContext` (type-only import); Python returns cases for `pytest.mark.parametrize` |
| `BindingJSON` | `BindingJSON` | `BindingJSON` | done |  |
| `BindingJSON.AgentID` | `BindingJSON.agent_id` | `BindingJSON.agent_id` | done | JSON member name |
| `BindingJSON.OperatorID` | `BindingJSON.operator_id` | `BindingJSON.operator_id` | done | JSON member name |
| `BindingJSON.HolderJKT` | `BindingJSON.holder_jkt` | `BindingJSON.holder_jkt` | done | JSON member name |
| `BindingJSON.Status` | `BindingJSON.status` | `BindingJSON.status` | done | JSON member name |
| `Call` | `Call` | `Call` | done |  |
| `Call.Realm` | `Call.realm` | `Call.realm` | done | JSON member name |
| `Call.Workload` | `Call.workload` | `Call.workload` | done | JSON member name |
| `Call.AgentID` | `Call.agent_id` | `Call.agent_id` | done | JSON member name |
| `Call.MappingVersion` | `Call.mapping_version` | `Call.mapping_version` | done | JSON member name |
| `Call.Principal` | `Call.principal` | `Call.principal` | done | JSON member name |
| `Call.Binding` | `Call.binding` | `Call.binding` | done | JSON member name |
| `Call.NativePath` | `Call.native_path` | `Call.native_path` | done | JSON member name |
| `Call.CheckID` | `Call.check_id` | `Call.check_id` | done | JSON member name |
| `Call.Intent` | `Call.intent` | `Call.intent` | done | JSON member name |
| `Call.Operation` | `Call.operation` | `Call.operation` | done | JSON member name |
| `Call.EvidenceRefs` | `Call.evidence_refs` | `Call.evidence_refs` | done | JSON member name |
| `Call.Observation` | `Call.observation` | `Call.observation` | done | JSON member name |
| `Case` | `Case` | `Case` | done |  |
| `Case.CaseVersion` | `Case.case_version` | `Case.case_version` | done | JSON member name |
| `Case.ID` | `Case.id` | `Case.id` | done | JSON member name |
| `Case.Title` | `Case.title` | `Case.title` | done | JSON member name |
| `Case.Draft` | `Case.draft` | `Case.draft` | done | JSON member name |
| `Case.Workloads` | `Case.workloads` | `Case.workloads` | done | JSON member name |
| `Case.Now` | `Case.now` | `Case.now` | done | JSON member name |
| `Case.NativeState` | `Case.native_state` | `Case.native_state` | done | JSON member name |
| `Case.Request` | `Case.request` | `Case.request` | done | JSON member name |
| `Case.Call` | `Case.call` | `Case.call` | done | JSON member name |
| `Case.Expect` | `Case.expect` | `Case.expect` | done | JSON member name |
| `Load` | `loadCases` | `load_cases` | done |  |
| `Env` | `Env` | `Env` | done |  |
| `Env.State` | `Env.state` | `Env.state` | done |  |
| `Env.Clock` | `Env.clock` | `Env.clock` | done |  |
| `Env.Hooks` | `Env.hooks` | `Env.hooks` | done |  |
| `Expect` | `Expect` | `Expect` | done |  |
| `Expect.Function` | `Expect.function` | `Expect.function` | done | JSON member name |
| `Expect.Outcome` | `Expect.outcome` | `Expect.outcome` | done | JSON member name |
| `Expect.ReasonCode` | `Expect.reason_code` | `Expect.reason_code` | done | JSON member name |
| `Expect.MustNotCall` | `Expect.must_not_call` | `Expect.must_not_call` | done | JSON member name |
| `Expect.LeakScan` | `Expect.leak_scan` | `Expect.leak_scan` | done | JSON member name |
| `Expect.Principal` | `Expect.principal` | `Expect.principal` | done | JSON member name |
| `Expect.Binding` | `Expect.binding` | `Expect.binding` | done | JSON member name |
| `Expect.Operation` | `Expect.operation` | `Expect.operation` | done | JSON member name |
| `Expect.Claim` | `Expect.claim` | `Expect.claim` | done | JSON member name |
| `Expect.Decision` | `Expect.decision` | `Expect.decision` | done | JSON member name |
| `ExpectBinding` | `ExpectBinding` | `ExpectBinding` | done |  |
| `ExpectBinding.AgentID` | `ExpectBinding.agent_id` | `ExpectBinding.agent_id` | done | JSON member name |
| `ExpectBinding.OperatorID` | `ExpectBinding.operator_id` | `ExpectBinding.operator_id` | done | JSON member name |
| `ExpectBinding.HolderJKT` | `ExpectBinding.holder_jkt` | `ExpectBinding.holder_jkt` | done | JSON member name |
| `ExpectBinding.Status` | `ExpectBinding.status` | `ExpectBinding.status` | done | JSON member name |
| `ExpectBinding.EnrolledElsewhere` | `ExpectBinding.enrolled_elsewhere` | `ExpectBinding.enrolled_elsewhere` | done | JSON member name |
| `ExpectClaim` | `ExpectClaim` | `ExpectClaim` | done |  |
| `ExpectClaim.Value` | `ExpectClaim.value` | `ExpectClaim.value` | done | JSON member name |
| `ExpectClaim.ObservedAt` | `ExpectClaim.observed_at` | `ExpectClaim.observed_at` | done | JSON member name |
| `ExpectClaim.StatusCheckedAt` | `ExpectClaim.status_checked_at` | `ExpectClaim.status_checked_at` | done | JSON member name |
| `ExpectClaim.SourceID` | `ExpectClaim.source_id` | `ExpectClaim.source_id` | done | JSON member name |
| `ExpectClaim.SourceRef` | `ExpectClaim.source_ref` | `ExpectClaim.source_ref` | done | JSON member name |
| `ExpectDecision` | `ExpectDecision` | `ExpectDecision` | done |  |
| `ExpectDecision.Obligations` | `ExpectDecision.obligations` | `ExpectDecision.obligations` | done | JSON member name |
| `ExpectDecision.SourceID` | `ExpectDecision.source_id` | `ExpectDecision.source_id` | done | JSON member name |
| `ExpectDecision.SourceRef` | `ExpectDecision.source_ref` | `ExpectDecision.source_ref` | done | JSON member name |
| `ExpectDecision.DecidedAt` | `ExpectDecision.decided_at` | `ExpectDecision.decided_at` | done | JSON member name |
| `ExpectDecision.PolicyRevision` | `ExpectDecision.policy_revision` | `ExpectDecision.policy_revision` | done | JSON member name |
| `ExpectOperation` | `ExpectOperation` | `ExpectOperation` | done |  |
| `ExpectOperation.EnvironmentID` | `ExpectOperation.environment_id` | `ExpectOperation.environment_id` | done | JSON member name |
| `ExpectOperation.PrincipalID` | `ExpectOperation.principal_id` | `ExpectOperation.principal_id` | done | JSON member name |
| `ExpectOperation.Action` | `ExpectOperation.action` | `ExpectOperation.action` | done | JSON member name |
| `ExpectOperation.Resources` | `ExpectOperation.resources` | `ExpectOperation.resources` | done | JSON member name |
| `ExpectOperation.Method` | `ExpectOperation.method` | `ExpectOperation.method` | done | JSON member name |
| `ExpectOperation.TargetURI` | `ExpectOperation.target_uri` | `ExpectOperation.target_uri` | done | JSON member name |
| `ExpectOperation.BodyDigest` | `ExpectOperation.body_digest` | `ExpectOperation.body_digest` | done | JSON member name |
| `ExpectOperation.Headers` | `ExpectOperation.headers` | `ExpectOperation.headers` | done | JSON member name |
| `ExpectPrincipal` | `ExpectPrincipal` | `ExpectPrincipal` | done |  |
| `ExpectPrincipal.ID` | `ExpectPrincipal.id` | `ExpectPrincipal.id` | done | JSON member name |
| `ExpectPrincipal.Realm` | `ExpectPrincipal.realm` | `ExpectPrincipal.realm` | done | JSON member name |
| `ExpectPrincipal.Workload` | `ExpectPrincipal.workload` | `ExpectPrincipal.workload` | done | JSON member name |
| `ExpectPrincipal.Mechanism` | `ExpectPrincipal.mechanism` | `ExpectPrincipal.mechanism` | done | JSON member name |
| `ExpectPrincipal.Attributes` | `ExpectPrincipal.attributes` | `ExpectPrincipal.attributes` | done | JSON member name |
| `Factory` | `Factory` | `Factory` | done |  |
| `Hooks` | `Hooks` | `Hooks` | done |  |
| `Hooks.Fire` | `Hooks.fire` | `Hooks.fire` | done |  |
| `Hooks.Fired` | `Hooks.fired` | `Hooks.fired` | done |  |
| `LeakScan` | `LeakScan` | `LeakScan` | done |  |
| `LeakScan.Secrets` | `LeakScan.secrets` | `LeakScan.secrets` | done | JSON member name |
| `ObligationJSON` | `ObligationJSON` | `ObligationJSON` | done |  |
| `ObligationJSON.ID` | `ObligationJSON.id` | `ObligationJSON.id` | done | JSON member name |
| `ObligationJSON.Attributes` | `ObligationJSON.attributes` | `ObligationJSON.attributes` | done | JSON member name |
| `ObservationJSON` | `ObservationJSON` | `ObservationJSON` | done |  |
| `ObservationJSON.EventID` | `ObservationJSON.event_id` | `ObservationJSON.event_id` | done | JSON member name |
| `ObservationJSON.EventKind` | `ObservationJSON.event_kind` | `ObservationJSON.event_kind` | done | JSON member name |
| `ObservationJSON.Context` | `ObservationJSON.context` | `ObservationJSON.context` | done | JSON member name |
| `ObservationJSON.TaskID` | `ObservationJSON.task_id` | `ObservationJSON.task_id` | done | JSON member name |
| `ObservationJSON.OperationID` | `ObservationJSON.operation_id` | `ObservationJSON.operation_id` | done | JSON member name |
| `ObservationJSON.AdmissionReceiptID` | `ObservationJSON.admission_receipt_id` | `ObservationJSON.admission_receipt_id` | done | JSON member name |
| `ObservationJSON.ObservedAt` | `ObservationJSON.observed_at` | `ObservationJSON.observed_at` | done | JSON member name |
| `ObservationJSON.Result` | `ObservationJSON.result` | `ObservationJSON.result` | done | JSON member name |
| `ObservationJSON.Dimension` | `ObservationJSON.dimension` | `ObservationJSON.dimension` | done | JSON member name |
| `ObservationJSON.Severity` | `ObservationJSON.severity` | `ObservationJSON.severity` | done | JSON member name |
| `ObservationJSON.EvidenceRefs` | `ObservationJSON.evidence_refs` | `ObservationJSON.evidence_refs` | done | JSON member name |
| `ObservationJSON.Attribution` | `ObservationJSON.attribution` | `ObservationJSON.attribution` | done | JSON member name |
| `ObservationJSON.Supersedes` | `ObservationJSON.supersedes` | `ObservationJSON.supersedes` | done | JSON member name |
| `ObservationJSON.Details` | `ObservationJSON.details` | `ObservationJSON.details` | done | JSON member name |
| `Options` | `Options` | `Options` | done |  |
| `Options.Fixtures` | `Options.fixtures` | `Options.fixtures` | done |  |
| `Options.Adapter` | `Options.adapter` | `Options.adapter` | done |  |
| `Options.SharedWorkloads` | `Options.sharedWorkloads` | `Options.shared_workloads` | done |  |
| `Options.Replaced` | `Options.replaced` | `Options.replaced` | done |  |
| `PrincipalJSON` | `PrincipalJSON` | `PrincipalJSON` | done |  |
| `PrincipalJSON.ID` | `PrincipalJSON.id` | `PrincipalJSON.id` | done | JSON member name |
| `PrincipalJSON.Realm` | `PrincipalJSON.realm` | `PrincipalJSON.realm` | done | JSON member name |
| `PrincipalJSON.Workload` | `PrincipalJSON.workload` | `PrincipalJSON.workload` | done | JSON member name |
| `PrincipalJSON.Mechanism` | `PrincipalJSON.mechanism` | `PrincipalJSON.mechanism` | done | JSON member name |
| `PrincipalJSON.AuthenticatedAt` | `PrincipalJSON.authenticated_at` | `PrincipalJSON.authenticated_at` | done | JSON member name |
| `PrincipalJSON.Attributes` | `PrincipalJSON.attributes` | `PrincipalJSON.attributes` | done | JSON member name |
| `RealmJSON` | `RealmJSON` | `RealmJSON` | done |  |
| `RealmJSON.TenantID` | `RealmJSON.tenant_id` | `RealmJSON.tenant_id` | done | JSON member name |
| `RealmJSON.EnvironmentID` | `RealmJSON.environment_id` | `RealmJSON.environment_id` | done | JSON member name |
| `Replacement` | `Replacement` | `Replacement` | done |  |
| `Replacement.By` | `Replacement.by` | `Replacement.by` | done |  |
| `Replacement.Reason` | `Replacement.reason` | `Replacement.reason` | done |  |
| `Request` | `Request` | `Request` | done |  |
| `Request.Method` | `Request.method` | `Request.method` | done | JSON member name |
| `Request.URL` | `Request.url` | `Request.url` | done | JSON member name |
| `Request.Headers` | `Request.headers` | `Request.headers` | done | JSON member name |
| `Request.BodyB64` | `Request.body_b64` | `Request.body_b64` | done | JSON member name |
| `Request.TLSPeer` | `Request.tlsPeer` | `Request.tls_peer` | done | API name; case-file member `tls_peer` |
| `Request.NativeStateRef` | `Request.native_state_ref` | `Request.native_state_ref` | done | JSON member name |
| `Request.Arrival` | `Request.arrival` | `Request.arrival` | done | JSON member name |
| `Result` | `Result` | `Result` | done |  |
| `Result.ID` | `Result.id` | `Result.id` | done |  |
| `Result.Failures` | `Result.failures` | `Result.failures` | done |  |
| `Evaluate` | `evaluateConformance` | `evaluate_conformance` | done | imports no test framework |
| `Result.Passed` | `Result.passed` | `Result.passed` | done |  |
| `Subject` | `Subject` | `Subject` | done |  |
| `Subject.Adapter` | `Subject.adapter` | `Subject.adapter` | done |  |
| `Subject.Arrive` | `Subject.arrive` | `Subject.arrive` | done |  |
| `Subject.Credential` | `Subject.credential` | `Subject.credential` | done |  |
| `Subject.VerifyOutcome` | `Subject.verifyOutcome` | `Subject.verify_outcome` | done |  |
| `TLSPeer` | `TLSPeer` | `TLSPeer` | done |  |
| `TLSPeer.SubjectCN` | `TLSPeer.subjectCN` | `TLSPeer.subject_cn` | done | TLS peer name of `RawRequest`; case-file member `subject_cn` |
| `TLSPeer.IssuerCN` | `TLSPeer.issuerCN` | `TLSPeer.issuer_cn` | done | TLS peer name of `RawRequest`; case-file member `issuer_cn` |
| `TLSPeer.DNSNames` | `TLSPeer.dnsNames` | `TLSPeer.dns_names` | done | TLS peer name of `RawRequest`; case-file member `dns_names` |
| `TLSPeer.URIs` | `TLSPeer.uris` | `TLSPeer.uris` | done | TLS peer name of `RawRequest`; case-file member `uris` |

## `adapter/enroll`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `ErrNotAuthorized` | `EnrollError` kind `NOT_AUTHORIZED` | `EnrollError` kind `NOT_AUTHORIZED` | done | sentinel error |
| `ErrNotFound` | `EnrollError` kind `NOT_FOUND` | `EnrollError` kind `NOT_FOUND` | done | sentinel error |
| `ErrAlreadyEnrolled` | `EnrollError` kind `ALREADY_ENROLLED` | `EnrollError` kind `ALREADY_ENROLLED` | done | sentinel error |
| `ErrCompromised` | `EnrollError` kind `COMPROMISED` | `EnrollError` kind `COMPROMISED` | done | sentinel error |
| `ErrRevoked` | `EnrollError` kind `REVOKED` | `EnrollError` kind `REVOKED` | done | sentinel error |
| `ErrKeyReuse` | `EnrollError` kind `KEY_REUSE` | `EnrollError` kind `KEY_REUSE` | done | sentinel error |
| `ErrInvalid` | `EnrollError` kind `INVALID` | `EnrollError` kind `INVALID` | done | sentinel error |
| `ErrWorkloadInUse` | `EnrollError` kind `WORKLOAD_IN_USE` | `EnrollError` kind `WORKLOAD_IN_USE` | done | sentinel error |
| `Actor` | `Actor` | `Actor` | done |  |
| `Actor.Kind` | `Actor.kind` | `Actor.kind` | done |  |
| `Actor.ID` | `Actor.id` | `Actor.id` | done |  |
| `Actor.Realm` | `Actor.realm` | `Actor.realm` | done |  |
| `Actor.CheckAuthority` | `Actor.checkAuthority` | `Actor.check_authority` | done |  |
| `ActorKind` | `ActorKind` | `ActorKind` | done |  |
| `Admin` | `ActorKind.ADMIN` | `ActorKind.ADMIN` | done |  |
| `AuthorizedIssuer` | `ActorKind.AUTHORIZED_ISSUER` | `ActorKind.AUTHORIZED_ISSUER` | done |  |
| `Agent` | `ActorKind.AGENT` | `ActorKind.AGENT` | done |  |
| `ActorKind.Valid` | `isActorKind(x)` | `ActorKind.is_valid(s)` | done | guard |
| `AuditAction` | `AuditAction` | `AuditAction` | done |  |
| `ActionEnroll` | `AuditAction.ENROLL` | `AuditAction.ENROLL` | done |  |
| `ActionRotate` | `AuditAction.ROTATE` | `AuditAction.ROTATE` | done |  |
| `ActionRevoke` | `AuditAction.REVOKE` | `AuditAction.REVOKE` | done |  |
| `ActionMarkCompromised` | `AuditAction.MARK_COMPROMISED` | `AuditAction.MARK_COMPROMISED` | done |  |
| `AuditEntry` | `AuditEntry` | `AuditEntry` | done |  |
| `AuditEntry.Seq` | `AuditEntry.seq` | `AuditEntry.seq` | done |  |
| `AuditEntry.At` | `AuditEntry.at` | `AuditEntry.at` | deviation | deviation: time precision |
| `AuditEntry.Action` | `AuditEntry.action` | `AuditEntry.action` | done |  |
| `AuditEntry.Actor` | `AuditEntry.actor` | `AuditEntry.actor` | done |  |
| `AuditEntry.AgentID` | `AuditEntry.agentId` | `AuditEntry.agent_id` | done |  |
| `AuditEntry.Workload` | `AuditEntry.workload` | `AuditEntry.workload` | done |  |
| `AuditEntry.OldJKT` | `AuditEntry.oldJKT` | `AuditEntry.old_jkt` | done |  |
| `AuditEntry.NewJKT` | `AuditEntry.newJKT` | `AuditEntry.new_jkt` | done |  |
| `AuditEntry.Result` | `AuditEntry.result` | `AuditEntry.result` | done |  |
| `AuditEntry.Reason` | `AuditEntry.reason` | `AuditEntry.reason` | done |  |
| `AuditResult` | `AuditResult` | `AuditResult` | done |  |
| `ResultApplied` | `AuditResult.APPLIED` | `AuditResult.APPLIED` | done |  |
| `ResultUnchanged` | `AuditResult.UNCHANGED` | `AuditResult.UNCHANGED` | done |  |
| `ResultDenied` | `AuditResult.DENIED` | `AuditResult.DENIED` | done |  |
| `ResultRejected` | `AuditResult.REJECTED` | `AuditResult.REJECTED` | done |  |
| `Registry` | `Registry` | `Registry` | done |  |
| `Registry.Lookup` | `Registry.lookup` | `Registry.lookup` | deviation | deviation: adapter calls |
| `Registry.Rotate` | `Registry.rotate` | `Registry.rotate` | deviation | deviation: adapter calls |
| `Registry.MarkCompromised` | `Registry.markCompromised` | `Registry.mark_compromised` | deviation | deviation: adapter calls |
| `Resolver` | `Resolver` | `Resolver` | done |  |
| `Resolver.Registry` | `Resolver.registry` | `Resolver.registry` | done |  |
| `Resolver.ResolveAgentBinding` | `Resolver.resolveAgentBinding` | `Resolver.resolve_agent_binding` | deviation | deviation: adapter calls |

## `adapter/enroll/memory`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `DefaultSourceID` | `DEFAULT_SOURCE_ID` | `DEFAULT_SOURCE_ID` | done |  |
| `Enrollment` | `Enrollment` | `Enrollment` | done |  |
| `Enrollment.AgentID` | `Enrollment.agentId` | `Enrollment.agent_id` | done |  |
| `Enrollment.OperatorID` | `Enrollment.operatorId` | `Enrollment.operator_id` | done |  |
| `Enrollment.Workload` | `Enrollment.workload` | `Enrollment.workload` | done |  |
| `Enrollment.HolderJKT` | `Enrollment.holderJKT` | `Enrollment.holder_jkt` | done |  |
| `Option` | `Option` | `Option` | done |  |
| `WithClock` | `withClock` | `with_clock` | done |  |
| `WithSharedWorkloads` | `withSharedWorkloads` | `with_shared_workloads` | done |  |
| `WithSourceID` | `withSourceId` | `with_source_id` | done |  |
| `Registry` | `MemoryRegistry` | `MemoryRegistry` | done |  |
| `New` | `new MemoryRegistry` | `MemoryRegistry(...)` | done | options become keyword arguments (Python) and an options object (TS) |
| `Registry.Audit` | `MemoryRegistry.audit` | `MemoryRegistry.audit` | done |  |
| `Registry.Enroll` | `MemoryRegistry.enroll` | `MemoryRegistry.enroll` | deviation | deviation: adapter calls |
| `Registry.Lookup` | `MemoryRegistry.lookup` | `MemoryRegistry.lookup` | deviation | deviation: adapter calls |
| `Registry.MarkCompromised` | `MemoryRegistry.markCompromised` | `MemoryRegistry.mark_compromised` | deviation | deviation: adapter calls |
| `Registry.Revoke` | `MemoryRegistry.revoke` | `MemoryRegistry.revoke` | deviation | deviation: adapter calls |
| `Registry.Rotate` | `MemoryRegistry.rotate` | `MemoryRegistry.rotate` | deviation | deviation: adapter calls |

## `adapter/freshness`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `Evaluate` | `evaluate` | `evaluate` | deviation | deviation: time precision |
| `Evaluator` | `Evaluator` | `Evaluator` | done |  |
| `Evaluator.Skew` | `Evaluator.skew` | `Evaluator.skew` | deviation | deviation: time precision |
| `Evaluator.Start` | `Evaluator.start` | `Evaluator.start` | deviation | deviation: time precision |
| `Evaluator.Guard` | `Evaluator.guard` | `Evaluator.guard` | done |  |
| `Evaluator.Evaluate` | `Evaluator.evaluate` | `Evaluator.evaluate` | deviation | deviation: time precision |
| `Monotonic` | `Monotonic` | `Monotonic` | done |  |
| `NewMonotonic` | `new Monotonic` | `Monotonic(...)` | done |  |
| `Monotonic.Check` | `Monotonic.check` | `Monotonic.check` | done |  |
| `Monotonic.Forget` | `Monotonic.forget` | `Monotonic.forget` | done |  |
| `Monotonic.Len` | `Monotonic.len` | `Monotonic.len` | done |  |
| `ReasonCode` | `ReasonCode` | `ReasonCode` | done |  |
| `Satisfied` | `ReasonCode.SATISFIED` | `ReasonCode.SATISFIED` | done |  |
| `StaleEvidence` | `ReasonCode.STALE_EVIDENCE` | `ReasonCode.STALE_EVIDENCE` | done |  |
| `ClockAhead` | `ReasonCode.CLOCK_AHEAD` | `ReasonCode.CLOCK_AHEAD` | done |  |
| `Restamped` | `ReasonCode.RESTAMPED` | `ReasonCode.RESTAMPED` | done |  |
| `UnsupportedRequirement` | `ReasonCode.UNSUPPORTED_REQUIREMENT` | `ReasonCode.UNSUPPORTED_REQUIREMENT` | done |  |
| `DependencyUnavailable` | `ReasonCode.DEPENDENCY_UNAVAILABLE` | `ReasonCode.DEPENDENCY_UNAVAILABLE` | done |  |
| `ReasonCode.TreatedAs` | `ReasonCode.treatedAs` | `ReasonCode.treated_as` | done |  |
| `Result` | `Result` | `Result` | done |  |

## `adapter/installed`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `CodeRequirementSatisfied` | `CODE_REQUIREMENT_SATISFIED` | `CODE_REQUIREMENT_SATISFIED` | planned |  |
| `CodeRequirementsChanged` | `CODE_REQUIREMENTS_CHANGED` | `CODE_REQUIREMENTS_CHANGED` | planned |  |
| `Authorize` | `authorize` | `authorize` | deviation | deviation: time precision, adapter calls |
| `Dependency` | `dependency` | `dependency` | planned |  |
| `Live` | `live` | `live` | deviation | deviation: adapter calls |
| `MapRequest` | `mapRequest` | `map_request` | planned |  |
| `ReadClaim` | `readClaim` | `read_claim` | deviation | deviation: time precision, adapter calls |
| `Record` | `record` | `record` | deviation | deviation: time precision |
| `Redact` | `redact` | `redact` | planned |  |
| `RunCheck` | `runCheck` | `run_check` | deviation | deviation: adapter calls |
| `SourceTimes` | `sourceTimes` | `source_times` | deviation | deviation: time precision |
| `ValidateChecks` | `validateChecks` | `validate_checks` | planned |  |
| `Check` | `Check` | `Check` | planned |  |
| `Check.Consult` | `Check.consult` | `Check.consult` | deviation | deviation: adapter calls |
| `CheckRecord` | `CheckRecord` | `CheckRecord` | planned |  |
| `CheckRecord.Result` | `CheckRecord.result` | `CheckRecord.result` | planned |  |
| `CheckRecord.ReasonCode` | `CheckRecord.reasonCode` | `CheckRecord.reason_code` | planned |  |
| `CheckRecord.SourceID` | `CheckRecord.sourceId` | `CheckRecord.source_id` | planned |  |
| `CheckRecord.SourceRef` | `CheckRecord.sourceRef` | `CheckRecord.source_ref` | planned |  |
| `CheckRecord.ObservedAt` | `CheckRecord.observedAt` | `CheckRecord.observed_at` | deviation | deviation: time precision |
| `CheckRecord.StatusCheckedAt` | `CheckRecord.statusCheckedAt` | `CheckRecord.status_checked_at` | deviation | deviation: time precision |
| `CheckRecord.Revision` | `CheckRecord.revision` | `CheckRecord.revision` | planned |  |
| `ClaimRecord` | `ClaimRecord` | `ClaimRecord` | planned |  |
| `ClaimRecord.Value` | `ClaimRecord.value` | `ClaimRecord.value` | planned |  |
| `ClaimRecord.Resource` | `ClaimRecord.resource` | `ClaimRecord.resource` | planned |  |
| `ClaimRecord.TaskID` | `ClaimRecord.taskId` | `ClaimRecord.task_id` | planned |  |
| `ClaimRecord.ObservedAt` | `ClaimRecord.observedAt` | `ClaimRecord.observed_at` | deviation | deviation: time precision |
| `ClaimRecord.StatusCheckedAt` | `ClaimRecord.statusCheckedAt` | `ClaimRecord.status_checked_at` | deviation | deviation: time precision |
| `ClaimRecord.SourceID` | `ClaimRecord.sourceId` | `ClaimRecord.source_id` | planned |  |
| `ClaimRecord.SourceRef` | `ClaimRecord.sourceRef` | `ClaimRecord.source_ref` | planned |  |
| `ClaimRecord.Applies` | `ClaimRecord.applies` | `ClaimRecord.applies` | planned |  |
| `ClaimSource` | `ClaimSource` | `ClaimSource` | planned |  |
| `ClaimSource.Claims` | `ClaimSource.claims` | `ClaimSource.claims` | deviation | deviation: adapter calls |
| `Freshness` | `Freshness` | `Freshness` | planned |  |
| `Freshness.MaxAgeSeconds` | `Freshness.maxAgeSeconds` | `Freshness.max_age_seconds` | planned |  |
| `Freshness.StatusMaxAgeSeconds` | `Freshness.statusMaxAgeSeconds` | `Freshness.status_max_age_seconds` | planned |  |
| `InstalledCheck` | `InstalledCheck` | `InstalledCheck` | planned |  |
| `InstalledCheck.Check` | `InstalledCheck.check` | `InstalledCheck.check` | planned |  |
| `InstalledCheck.Freshness` | `InstalledCheck.freshness` | `InstalledCheck.freshness` | planned |  |
| `InstalledCheck.PinnedRevision` | `InstalledCheck.pinnedRevision` | `InstalledCheck.pinned_revision` | planned |  |
| `PermissionLookup` | `PermissionLookup` | `PermissionLookup` | planned |  |
| `PermissionLookup.Decide` | `PermissionLookup.decide` | `PermissionLookup.decide` | deviation | deviation: adapter calls |
| `Reporting` | `Reporting` | `Reporting` | planned |  |
| `Reporting.Issuer` | `Reporting.issuer` | `Reporting.issuer` | planned |  |
| `Reporting.Audience` | `Reporting.audience` | `Reporting.audience` | planned |  |
| `Reporting.KID` | `Reporting.kid` | `Reporting.kid` | planned |  |
| `Reporting.Key` | `Reporting.key` | `Reporting.key` | planned |  |
| `Reporting.Validate` | `Reporting.validate` | `Reporting.validate` | planned |  |
| `Route` | `Route` | `Route` | planned |  |
| `Route.Method` | `Route.method` | `Route.method` | planned |  |
| `Route.Path` | `Route.path` | `Route.path` | planned |  |
| `Route.Action` | `Route.action` | `Route.action` | planned |  |
| `Route.Resource` | `Route.resource` | `Route.resource` | planned |  |
| `Route.Validate` | `Route.validate` | `Route.validate` | planned |  |

## `adapter/source`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `ErrInvalidFact` | `SourceError` kind `INVALID_FACT` | `SourceError` kind `INVALID_FACT` | planned | sentinel error |
| `ErrNoJoin` | `SourceError` kind `NO_JOIN` | `SourceError` kind `NO_JOIN` | planned | sentinel error |
| `Config` | `Config` | `Config` | planned |  |
| `Config.Store` | `Config.store` | `Config.store` | planned |  |
| `Config.SourceID` | `Config.sourceId` | `Config.source_id` | planned |  |
| `Config.Paths` | `Config.paths` | `Config.paths` | planned |  |
| `Config.Lag` | `Config.lag` | `Config.lag` | deviation | deviation: time precision |
| `Config.Clock` | `Config.clock` | `Config.clock` | planned |  |
| `Fact` | `Fact` | `Fact` | planned |  |
| `Fact.Value` | `Fact.value` | `Fact.value` | planned |  |
| `Fact.ObservedAt` | `Fact.observedAt` | `Fact.observed_at` | deviation | deviation: time precision |
| `Fact.StatusCheckedAt` | `Fact.statusCheckedAt` | `Fact.status_checked_at` | deviation | deviation: time precision |
| `Fact.SourceRef` | `Fact.sourceRef` | `Fact.source_ref` | planned |  |
| `Join` | `Join` | `Join` | planned |  |
| `Join.Attribute` | `Join.attribute` | `Join.attribute` | planned |  |
| `Join.Prefix` | `Join.prefix` | `Join.prefix` | planned |  |
| `Join.Principal` | `Join.principal` | `Join.principal` | planned |  |
| `Memory` | `Memory` | `Memory` | planned |  |
| `NewMemory` | `new Memory` | `Memory(...)` | planned |  |
| `Memory.Delete` | `Memory.delete` | `Memory.delete` | deviation | deviation: adapter calls |
| `Memory.Get` | `Memory.get` | `Memory.get` | deviation | deviation: adapter calls |
| `Memory.Put` | `Memory.put` | `Memory.put` | deviation | deviation: adapter calls |
| `Reader` | `Reader` | `Reader` | planned |  |
| `NewReader` | `new Reader` | `Reader(...)` | planned |  |
| `Reader.ReadNativeClaim` | `Reader.readNativeClaim` | `Reader.read_native_claim` | deviation | deviation: adapter calls |
| `Store` | `Store` | `Store` | planned |  |
| `Store.Put` | `Store.put` | `Store.put` | deviation | deviation: adapter calls |
| `Store.Get` | `Store.get` | `Store.get` | deviation | deviation: adapter calls |
| `Store.Delete` | `Store.delete` | `Store.delete` | deviation | deviation: adapter calls |

## `adapter/source/googledir`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `DefaultDirectoryURL` | `DEFAULT_DIRECTORY_URL` | `DEFAULT_DIRECTORY_URL` | planned |  |
| `DefaultIdentityURL` | `DEFAULT_IDENTITY_URL` | `DEFAULT_IDENTITY_URL` | planned |  |
| `DefaultStopURL` | `DEFAULT_STOP_URL` | `DEFAULT_STOP_URL` | planned |  |
| `PathAccountState` | `PATH_ACCOUNT_STATE` | `PATH_ACCOUNT_STATE` | planned |  |
| `DefaultTokenURL` | `DEFAULT_TOKEN_URL` | `DEFAULT_TOKEN_URL` | planned |  |
| `ErrNotFound` | `GoogleDirError` kind `NOT_FOUND` | `GoogleDirError` kind `NOT_FOUND` | planned | sentinel error |
| `MemberPath` | `memberPath` | `member_path` | planned |  |
| `TransitiveMemberPath` | `transitiveMemberPath` | `transitive_member_path` | planned |  |
| `APIError` | `APIError` | `APIError` | planned |  |
| `APIError.Status` | `APIError.status` | `APIError.status` | planned |  |
| `APIError.Reason` | `APIError.reason` | `APIError.reason` | planned |  |
| `APIError.Error` | `APIError.message` | `APIError.__str__` | planned |  |
| `APIError.Is` | `APIError.instanceof` | `APIError.isinstance` | planned |  |
| `Channel` | `Channel` | `Channel` | planned |  |
| `Channel.ID` | `Channel.id` | `Channel.id` | planned |  |
| `Channel.ResourceID` | `Channel.resourceId` | `Channel.resource_id` | planned |  |
| `Channel.Address` | `Channel.address` | `Channel.address` | planned |  |
| `Channel.Token` | `Channel.token` | `Channel.token` | planned |  |
| `Channel.Expiration` | `Channel.expiration` | `Channel.expiration` | deviation | deviation: time precision |
| `Client` | `Client` | `Client` | planned |  |
| `NewClient` | `new Client` | `Client(...)` | planned |  |
| `Client.HasMember` | `Client.hasMember` | `Client.has_member` | deviation | deviation: adapter calls |
| `Client.StopChannel` | `Client.stopChannel` | `Client.stop_channel` | deviation | deviation: adapter calls |
| `Client.TransitiveMember` | `Client.transitiveMember` | `Client.transitive_member` | deviation | deviation: adapter calls |
| `Client.User` | `Client.user` | `Client.user` | deviation | deviation: adapter calls |
| `Client.Users` | `Client.users` | `Client.users` | deviation | deviation: time precision, adapter calls |
| `Client.WatchUsers` | `Client.watchUsers` | `Client.watch_users` | deviation | deviation: time precision, adapter calls |
| `ClientConfig` | `ClientConfig` | `ClientConfig` | planned |  |
| `ClientConfig.DirectoryURL` | `ClientConfig.directoryURL` | `ClientConfig.directory_url` | planned |  |
| `ClientConfig.IdentityURL` | `ClientConfig.identityURL` | `ClientConfig.identity_url` | planned |  |
| `ClientConfig.ChannelsStopURL` | `ClientConfig.channelsStopURL` | `ClientConfig.channels_stop_url` | planned |  |
| `ClientConfig.HTTP` | `ClientConfig.http` | `ClientConfig.http` | planned |  |
| `ClientConfig.DirectoryTokens` | `ClientConfig.directoryTokens` | `ClientConfig.directory_tokens` | planned |  |
| `ClientConfig.IdentityTokens` | `ClientConfig.identityTokens` | `ClientConfig.identity_tokens` | planned |  |
| `ClientConfig.Clock` | `ClientConfig.clock` | `ClientConfig.clock` | planned |  |
| `Config` | `Config` | `Config` | planned |  |
| `Config.SourceID` | `Config.sourceId` | `Config.source_id` | planned |  |
| `Config.PrincipalPrefix` | `Config.principalPrefix` | `Config.principal_prefix` | planned |  |
| `Config.Client` | `Config.client` | `Config.client` | planned |  |
| `Config.Clock` | `Config.clock` | `Config.clock` | planned |  |
| `Config.Groups` | `Config.groups` | `Config.groups` | planned |  |
| `Config.TransitiveGroups` | `Config.transitiveGroups` | `Config.transitive_groups` | planned |  |
| `Config.Cache` | `Config.cache` | `Config.cache` | planned |  |
| `Config.MaxAge` | `Config.maxAge` | `Config.max_age` | deviation | deviation: time precision |
| `Feed` | `Feed` | `Feed` | planned |  |
| `NewFeed` | `new Feed` | `Feed(...)` | planned |  |
| `Feed.Handler` | `Feed.handler` | `Feed.handler` | planned | the port binds the handler to its own HTTP server API |
| `Feed.Status` | `Feed.status` | `Feed.status` | planned |  |
| `Feed.Tick` | `Feed.tick` | `Feed.tick` | deviation | deviation: adapter calls |
| `FeedConfig` | `FeedConfig` | `FeedConfig` | planned |  |
| `FeedConfig.Client` | `FeedConfig.client` | `FeedConfig.client` | planned |  |
| `FeedConfig.Store` | `FeedConfig.store` | `FeedConfig.store` | planned |  |
| `FeedConfig.Clock` | `FeedConfig.clock` | `FeedConfig.clock` | planned |  |
| `FeedConfig.PrincipalPrefix` | `FeedConfig.principalPrefix` | `FeedConfig.principal_prefix` | planned |  |
| `FeedConfig.Customer` | `FeedConfig.customer` | `FeedConfig.customer` | planned |  |
| `FeedConfig.Address` | `FeedConfig.address` | `FeedConfig.address` | planned |  |
| `FeedConfig.Token` | `FeedConfig.token` | `FeedConfig.token` | planned |  |
| `FeedConfig.PollInterval` | `FeedConfig.pollInterval` | `FeedConfig.poll_interval` | deviation | deviation: time precision |
| `FeedConfig.ChannelTTL` | `FeedConfig.channelTTL` | `FeedConfig.channel_ttl` | deviation | deviation: time precision |
| `FeedConfig.RenewBefore` | `FeedConfig.renewBefore` | `FeedConfig.renew_before` | deviation | deviation: time precision |
| `FeedConfig.PageSize` | `FeedConfig.pageSize` | `FeedConfig.page_size` | planned |  |
| `FeedConfig.NewID` | `FeedConfig.newId` | `FeedConfig.new_id` | planned |  |
| `Mode` | `Mode` | `Mode` | planned |  |
| `ModePush` | `Mode.PUSH` | `Mode.PUSH` | planned |  |
| `ModePoll` | `Mode.POLL` | `Mode.POLL` | planned |  |
| `Reader` | `Reader` | `Reader` | planned |  |
| `NewReader` | `new Reader` | `Reader(...)` | planned |  |
| `Reader.ReadNativeClaim` | `Reader.readNativeClaim` | `Reader.read_native_claim` | deviation | deviation: adapter calls |
| `ServiceAccount` | `ServiceAccount` | `ServiceAccount` | planned |  |
| `NewServiceAccount` | `new ServiceAccount` | `ServiceAccount(...)` | planned |  |
| `ServiceAccount.Token` | `ServiceAccount.token` | `ServiceAccount.token` | deviation | deviation: adapter calls |
| `ServiceAccountConfig` | `ServiceAccountConfig` | `ServiceAccountConfig` | planned |  |
| `ServiceAccountConfig.Key` | `ServiceAccountConfig.key` | `ServiceAccountConfig.key` | planned |  |
| `ServiceAccountConfig.Subject` | `ServiceAccountConfig.subject` | `ServiceAccountConfig.subject` | planned |  |
| `ServiceAccountConfig.Scopes` | `ServiceAccountConfig.scopes` | `ServiceAccountConfig.scopes` | planned |  |
| `ServiceAccountConfig.TokenURL` | `ServiceAccountConfig.tokenURL` | `ServiceAccountConfig.token_url` | planned |  |
| `ServiceAccountConfig.HTTP` | `ServiceAccountConfig.http` | `ServiceAccountConfig.http` | planned |  |
| `ServiceAccountConfig.Clock` | `ServiceAccountConfig.clock` | `ServiceAccountConfig.clock` | planned |  |
| `Status` | `Status` | `Status` | planned |  |
| `Status.Mode` | `Status.mode` | `Status.mode` | planned |  |
| `Status.ChannelID` | `Status.channelId` | `Status.channel_id` | planned |  |
| `Status.ChannelExpires` | `Status.channelExpires` | `Status.channel_expires` | deviation | deviation: time precision |
| `Status.LastSweep` | `Status.lastSweep` | `Status.last_sweep` | deviation | deviation: time precision |
| `Status.Sweeps` | `Status.sweeps` | `Status.sweeps` | planned |  |
| `TokenSource` | `TokenSource` | `TokenSource` | planned |  |
| `TokenSource.Token` | `TokenSource.token` | `TokenSource.token` | deviation | deviation: adapter calls |
| `User` | `User` | `User` | planned |  |
| `User.ID` | `User.id` | `User.id` | planned |  |
| `User.PrimaryEmail` | `User.primaryEmail` | `User.primary_email` | planned |  |
| `User.Suspended` | `User.suspended` | `User.suspended` | planned |  |
| `User.Archived` | `User.archived` | `User.archived` | planned |  |

## `adapter/source/scim`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `PathAccountState` | `PATH_ACCOUNT_STATE` | `PATH_ACCOUNT_STATE` | planned |  |
| `PathGroupIDs` | `PATH_GROUP_IDS` | `PATH_GROUP_IDS` | planned |  |
| `Config` | `Config` | `Config` | planned |  |
| `Config.Store` | `Config.store` | `Config.store` | planned |  |
| `Config.SourceID` | `Config.sourceId` | `Config.source_id` | planned |  |
| `Config.BasePath` | `Config.basePath` | `Config.base_path` | planned |  |
| `Config.Join` | `Config.join` | `Config.join` | planned |  |
| `Config.Credentials` | `Config.credentials` | `Config.credentials` | planned |  |
| `Config.Lag` | `Config.lag` | `Config.lag` | deviation | deviation: time precision |
| `Config.Clock` | `Config.clock` | `Config.clock` | planned |  |
| `Config.ErrorLog` | `Config.errorLog` | `Config.error_log` | planned | a logger callback in the ports |
| `Credential` | `Credential` | `Credential` | planned |  |
| `Credential.Token` | `Credential.token` | `Credential.token` | planned |  |
| `Credential.Provisioning` | `Credential.provisioning` | `Credential.provisioning` | planned |  |
| `Server` | `Server` | `Server` | planned |  |
| `New` | `new Server` | `Server(...)` | planned |  |
| `Server.Reader` | `Server.reader` | `Server.reader` | planned |  |
| `Server.ServeHTTP` | `Server.handle` | `Server.handle` | planned | the port binds the handler to its own HTTP server API |

## `adapter/source/ssf`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `CodeInvalidRequest` | `CODE_INVALID_REQUEST` | `CODE_INVALID_REQUEST` | planned |  |
| `CodeInvalidKey` | `CODE_INVALID_KEY` | `CODE_INVALID_KEY` | planned |  |
| `CodeInvalidIssuer` | `CODE_INVALID_ISSUER` | `CODE_INVALID_ISSUER` | planned |  |
| `CodeInvalidAudience` | `CODE_INVALID_AUDIENCE` | `CODE_INVALID_AUDIENCE` | planned |  |
| `CodeAuthenticationFailed` | `CODE_AUTHENTICATION_FAILED` | `CODE_AUTHENTICATION_FAILED` | planned |  |
| `CodeAccessDenied` | `CODE_ACCESS_DENIED` | `CODE_ACCESS_DENIED` | planned |  |
| `EventSessionRevoked` | `EVENT_SESSION_REVOKED` | `EVENT_SESSION_REVOKED` | planned |  |
| `EventCredentialChange` | `EVENT_CREDENTIAL_CHANGE` | `EVENT_CREDENTIAL_CHANGE` | planned |  |
| `EventAssuranceLevelChange` | `EVENT_ASSURANCE_LEVEL_CHANGE` | `EVENT_ASSURANCE_LEVEL_CHANGE` | planned |  |
| `EventAccountDisabled` | `EVENT_ACCOUNT_DISABLED` | `EVENT_ACCOUNT_DISABLED` | planned |  |
| `EventAccountEnabled` | `EVENT_ACCOUNT_ENABLED` | `EVENT_ACCOUNT_ENABLED` | planned |  |
| `EventAccountPurged` | `EVENT_ACCOUNT_PURGED` | `EVENT_ACCOUNT_PURGED` | planned |  |
| `EventAccountCredentialChangeRequired` | `EVENT_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED` | `EVENT_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED` | planned |  |
| `EventCredentialCompromise` | `EVENT_CREDENTIAL_COMPROMISE` | `EVENT_CREDENTIAL_COMPROMISE` | planned |  |
| `EventSessionsRevoked` | `EVENT_SESSIONS_REVOKED` | `EVENT_SESSIONS_REVOKED` | planned |  |
| `EventVerification` | `EVENT_VERIFICATION` | `EVENT_VERIFICATION` | planned |  |
| `EventStreamUpdated` | `EVENT_STREAM_UPDATED` | `EVENT_STREAM_UPDATED` | planned |  |
| `StateActive` | `STATE_ACTIVE` | `STATE_ACTIVE` | planned |  |
| `StateDisabled` | `STATE_DISABLED` | `STATE_DISABLED` | planned |  |
| `StateAbsent` | `STATE_ABSENT` | `STATE_ABSENT` | planned |  |
| `StatePasswordChangeRequired` | `STATE_PASSWORD_CHANGE_REQUIRED` | `STATE_PASSWORD_CHANGE_REQUIRED` | planned |  |
| `StateSessionRevoked` | `STATE_SESSION_REVOKED` | `STATE_SESSION_REVOKED` | planned |  |
| `StateCredentialChanged` | `STATE_CREDENTIAL_CHANGED` | `STATE_CREDENTIAL_CHANGED` | planned |  |
| `StateAssuranceChanged` | `STATE_ASSURANCE_CHANGED` | `STATE_ASSURANCE_CHANGED` | planned |  |
| `StateCredentialCompromised` | `STATE_CREDENTIAL_COMPROMISED` | `STATE_CREDENTIAL_COMPROMISED` | planned |  |
| `DeliveryPush` | `DELIVERY_PUSH` | `DELIVERY_PUSH` | planned |  |
| `DeliveryPoll` | `DELIVERY_POLL` | `DELIVERY_POLL` | planned |  |
| `StatusEnabled` | `STATUS_ENABLED` | `STATUS_ENABLED` | planned |  |
| `StatusPaused` | `STATUS_PAUSED` | `STATUS_PAUSED` | planned |  |
| `StatusDisabled` | `STATUS_DISABLED` | `STATUS_DISABLED` | planned |  |
| `FormatIssSub` | `FORMAT_ISS_SUB` | `FORMAT_ISS_SUB` | planned |  |
| `FormatOpaque` | `FORMAT_OPAQUE` | `FORMAT_OPAQUE` | planned |  |
| `FormatEmail` | `FORMAT_EMAIL` | `FORMAT_EMAIL` | planned |  |
| `KindApplied` | `KIND_APPLIED` | `KIND_APPLIED` | planned |  |
| `KindStaleEvent` | `KIND_STALE_EVENT` | `KIND_STALE_EVENT` | planned |  |
| `KindNoEffect` | `KIND_NO_EFFECT` | `KIND_NO_EFFECT` | planned |  |
| `KindUnknownSubject` | `KIND_UNKNOWN_SUBJECT` | `KIND_UNKNOWN_SUBJECT` | planned |  |
| `KindUnsupportedEvent` | `KIND_UNSUPPORTED_EVENT` | `KIND_UNSUPPORTED_EVENT` | planned |  |
| `KindDiscarded` | `KIND_DISCARDED` | `KIND_DISCARDED` | planned |  |
| `KindReplay` | `KIND_REPLAY` | `KIND_REPLAY` | planned |  |
| `KindRejected` | `KIND_REJECTED` | `KIND_REJECTED` | planned |  |
| `KindHoldCandidate` | `KIND_HOLD_CANDIDATE` | `KIND_HOLD_CANDIDATE` | planned |  |
| `KindVerification` | `KIND_VERIFICATION` | `KIND_VERIFICATION` | planned |  |
| `KindStreamUpdated` | `KIND_STREAM_UPDATED` | `KIND_STREAM_UPDATED` | planned |  |
| `AccountStatePath` | `ACCOUNT_STATE_PATH` | `ACCOUNT_STATE_PATH` | planned |  |
| `AlgES256` | `ALG_ES256` | `ALG_ES256` | planned |  |
| `AlgRS256` | `ALG_RS256` | `ALG_RS256` | planned |  |
| `MinRSABits` | `MIN_RSA_BITS` | `MIN_RSA_BITS` | planned |  |
| `ErrUnknownKey` | `SSFError` kind `UNKNOWN_KEY` | `SSFError` kind `UNKNOWN_KEY` | planned |  |
| `Config` | `Config` | `Config` | planned |  |
| `Config.SourceID` | `Config.sourceId` | `Config.source_id` | planned |  |
| `Config.Store` | `Config.store` | `Config.store` | planned |  |
| `Config.Clock` | `Config.clock` | `Config.clock` | planned |  |
| `Config.Issuers` | `Config.issuers` | `Config.issuers` | planned |  |
| `Config.PrincipalPrefix` | `Config.principalPrefix` | `Config.principal_prefix` | planned |  |
| `Config.Mappings` | `Config.mappings` | `Config.mappings` | planned |  |
| `Config.MaxAge` | `Config.maxAge` | `Config.max_age` | deviation | deviation: time precision |
| `Config.MaxBytes` | `Config.maxBytes` | `Config.max_bytes` | planned |  |
| `Config.CriticalSubjectMembers` | `Config.criticalSubjectMembers` | `Config.critical_subject_members` | planned |  |
| `Config.Authorization` | `Config.authorization` | `Config.authorization` | planned |  |
| `Config.Replay` | `Config.replay` | `Config.replay` | planned |  |
| `Config.HoldOn` | `Config.holdOn` | `Config.hold_on` | planned |  |
| `Config.Holds` | `Config.holds` | `Config.holds` | planned |  |
| `Config.Telemetry` | `Config.telemetry` | `Config.telemetry` | planned |  |
| `Delivery` | `Delivery` | `Delivery` | planned |  |
| `Delivery.Method` | `Delivery.method` | `Delivery.method` | planned |  |
| `Delivery.EndpointURL` | `Delivery.endpoint_url` | `Delivery.endpoint_url` | planned |  |
| `Delivery.AuthorizationHeader` | `Delivery.authorization_header` | `Delivery.authorization_header` | planned |  |
| `Error` | `Error` | `Error` | planned | the name collides with the language's Error: import it under an alias |
| `Error.Code` | `Error.code` | `Error.code` | planned |  |
| `Error.Description` | `Error.description` | `Error.description` | planned |  |
| `Error.Error` | `Error.message` | `Error.__str__` | planned |  |
| `HoldCandidate` | `HoldCandidate` | `HoldCandidate` | planned |  |
| `HoldCandidate.Principal` | `HoldCandidate.principal` | `HoldCandidate.principal` | planned |  |
| `HoldCandidate.Issuer` | `HoldCandidate.issuer` | `HoldCandidate.issuer` | planned |  |
| `HoldCandidate.JTI` | `HoldCandidate.jti` | `HoldCandidate.jti` | planned |  |
| `HoldCandidate.EventType` | `HoldCandidate.eventType` | `HoldCandidate.event_type` | planned |  |
| `HoldCandidate.EventTime` | `HoldCandidate.eventTime` | `HoldCandidate.event_time` | deviation | deviation: time precision |
| `HoldSink` | `HoldSink` | `HoldSink` | planned |  |
| `HoldSink.Candidate` | `HoldSink.candidate` | `HoldSink.candidate` | deviation | deviation: adapter calls |
| `Issuer` | `Issuer` | `Issuer` | planned |  |
| `Issuer.Issuer` | `Issuer.issuer` | `Issuer.issuer` | planned |  |
| `Issuer.Audience` | `Issuer.audience` | `Issuer.audience` | planned |  |
| `Issuer.Keys` | `Issuer.keys` | `Issuer.keys` | planned |  |
| `Issuer.Algorithms` | `Issuer.algorithms` | `Issuer.algorithms` | planned |  |
| `JWKS` | `JWKS` | `JWKS` | planned |  |
| `NewJWKS` | `new JWKS` | `JWKS(...)` | deviation | deviation: time precision |
| `JWKS.Key` | `JWKS.key` | `JWKS.key` | deviation | deviation: adapter calls |
| `JWKS.RSAKey` | `JWKS.rsaKey` | `JWKS.rsa_key` | deviation | deviation: adapter calls |
| `KeySource` | `KeySource` | `KeySource` | planned |  |
| `KeySource.Key` | `KeySource.key` | `KeySource.key` | deviation | deviation: adapter calls |
| `Mapping` | `Mapping` | `Mapping` | planned |  |
| `Mapping.Issuer` | `Mapping.issuer` | `Mapping.issuer` | planned |  |
| `Mapping.Format` | `Mapping.format` | `Mapping.format` | planned |  |
| `Mapping.SubjectIss` | `Mapping.subjectIss` | `Mapping.subject_iss` | planned |  |
| `Mapping.Value` | `Mapping.value` | `Mapping.value` | planned |  |
| `Mapping.Local` | `Mapping.local` | `Mapping.local` | planned |  |
| `PollConfig` | `PollConfig` | `PollConfig` | planned |  |
| `PollConfig.URL` | `PollConfig.url` | `PollConfig.url` | planned |  |
| `PollConfig.Authorization` | `PollConfig.authorization` | `PollConfig.authorization` | planned |  |
| `PollConfig.Client` | `PollConfig.client` | `PollConfig.client` | planned |  |
| `PollConfig.Receiver` | `PollConfig.receiver` | `PollConfig.receiver` | planned |  |
| `PollConfig.MaxEvents` | `PollConfig.maxEvents` | `PollConfig.max_events` | planned |  |
| `PollConfig.ReturnImmediately` | `PollConfig.returnImmediately` | `PollConfig.return_immediately` | planned |  |
| `PollResult` | `PollResult` | `PollResult` | planned |  |
| `PollResult.Received` | `PollResult.received` | `PollResult.received` | planned |  |
| `PollResult.Acknowledged` | `PollResult.acknowledged` | `PollResult.acknowledged` | planned |  |
| `PollResult.Rejected` | `PollResult.rejected` | `PollResult.rejected` | planned |  |
| `PollResult.MoreAvailable` | `PollResult.moreAvailable` | `PollResult.more_available` | planned |  |
| `Poller` | `Poller` | `Poller` | planned |  |
| `NewPoller` | `new Poller` | `Poller(...)` | planned |  |
| `Poller.Poll` | `Poller.poll` | `Poller.poll` | deviation | deviation: adapter calls |
| `Receiver` | `Receiver` | `Receiver` | planned |  |
| `NewReceiver` | `new Receiver` | `Receiver(...)` | planned |  |
| `Receiver.Accept` | `Receiver.accept` | `Receiver.accept` | deviation | deviation: adapter calls |
| `Receiver.PushHandler` | `Receiver.pushHandler` | `Receiver.push_handler` | planned |  |
| `Receiver.Reader` | `Receiver.reader` | `Receiver.reader` | planned |  |
| `Receiver.Verified` | `Receiver.verified` | `Receiver.verified` | planned |  |
| `Record` | `Record` | `Record` | planned |  |
| `Record.Kind` | `Record.kind` | `Record.kind` | planned |  |
| `Record.At` | `Record.at` | `Record.at` | deviation | deviation: time precision |
| `Record.Issuer` | `Record.issuer` | `Record.issuer` | planned |  |
| `Record.JTI` | `Record.jti` | `Record.jti` | planned |  |
| `Record.EventType` | `Record.eventType` | `Record.event_type` | planned |  |
| `Record.Principal` | `Record.principal` | `Record.principal` | planned |  |
| `Record.SubjectFormat` | `Record.subjectFormat` | `Record.subject_format` | planned |  |
| `Record.Reason` | `Record.reason` | `Record.reason` | planned |  |
| `ReplayMemory` | `ReplayMemory` | `ReplayMemory` | planned |  |
| `NewReplayMemory` | `new ReplayMemory` | `ReplayMemory(...)` | planned |  |
| `ReplayMemory.Lookup` | `ReplayMemory.lookup` | `ReplayMemory.lookup` | deviation | deviation: adapter calls |
| `ReplayMemory.Record` | `ReplayMemory.record` | `ReplayMemory.record` | deviation | deviation: time precision, adapter calls |
| `ReplayStore` | `ReplayStore` | `ReplayStore` | planned |  |
| `ReplayStore.Lookup` | `ReplayStore.lookup` | `ReplayStore.lookup` | deviation | deviation: adapter calls |
| `ReplayStore.Record` | `ReplayStore.record` | `ReplayStore.record` | deviation | deviation: time precision, adapter calls |
| `Result` | `Result` | `Result` | planned |  |
| `Result.JTI` | `Result.jti` | `Result.jti` | planned |  |
| `Result.Replay` | `Result.replay` | `Result.replay` | planned |  |
| `StaticKeys` | `StaticKeys` | `StaticKeys` | planned |  |
| `StaticKeys.Key` | `StaticKeys.key` | `StaticKeys.key` | deviation | deviation: adapter calls |
| `StaticKeySet` | `StaticKeySet` | `StaticKeySet` | planned |  |
| `StaticKeySet.EC` | `StaticKeySet.ec` | `StaticKeySet.ec` | planned |  |
| `StaticKeySet.RSA` | `StaticKeySet.rsa` | `StaticKeySet.rsa` | planned |  |
| `StaticKeySet.Key` | `StaticKeySet.key` | `StaticKeySet.key` | deviation | deviation: adapter calls |
| `StaticKeySet.RSAKey` | `StaticKeySet.rsaKey` | `StaticKeySet.rsa_key` | deviation | deviation: adapter calls |
| `RSAKey` | `RSAKey` | `RSAKey` | planned |  |
| `RSAKey.Kty` | `RSAKey.kty` | `RSAKey.kty` | planned | JSON member name |
| `RSAKey.N` | `RSAKey.n` | `RSAKey.n` | planned | JSON member name |
| `RSAKey.E` | `RSAKey.e` | `RSAKey.e` | planned | JSON member name |
| `RSAKey.Kid` | `RSAKey.kid` | `RSAKey.kid` | planned | JSON member name |
| `RSAKey.Alg` | `RSAKey.alg` | `RSAKey.alg` | planned | JSON member name |
| `RSAKey.Use` | `RSAKey.use` | `RSAKey.use` | planned | JSON member name |
| `RSAKey.KeyOps` | `RSAKey.key_ops` | `RSAKey.key_ops` | planned | JSON member name |
| `ParseRSAKey` | `parseRSAKey` | `parse_rsa_key` | planned |  |
| `RSAKey.PublicKey` | `publicKeyOfRSA(key)` | `public_key_of_rsa(key)` | planned | free function |
| `RSAKeySource` | `RSAKeySource` | `RSAKeySource` | planned |  |
| `RSAKeySource.RSAKey` | `RSAKeySource.rsaKey` | `RSAKeySource.rsa_key` | deviation | deviation: adapter calls |
| `Stream` | `Stream` | `Stream` | planned |  |
| `Stream.StreamID` | `Stream.streamId` | `Stream.stream_id` | planned |  |
| `Stream.Issuer` | `Stream.issuer` | `Stream.issuer` | planned |  |
| `Stream.Audience` | `Stream.audience` | `Stream.audience` | planned |  |
| `Stream.Delivery` | `Stream.delivery` | `Stream.delivery` | planned |  |
| `Stream.EventsSupported` | `Stream.eventsSupported` | `Stream.events_supported` | planned |  |
| `Stream.EventsRequested` | `Stream.eventsRequested` | `Stream.events_requested` | planned |  |
| `Stream.EventsDelivered` | `Stream.eventsDelivered` | `Stream.events_delivered` | planned |  |
| `Stream.MinVerificationInterval` | `Stream.minVerificationInterval` | `Stream.min_verification_interval` | planned |  |
| `StreamRequest` | `StreamRequest` | `StreamRequest` | planned |  |
| `StreamRequest.Delivery` | `StreamRequest.delivery` | `StreamRequest.delivery` | planned |  |
| `StreamRequest.EventsRequested` | `StreamRequest.eventsRequested` | `StreamRequest.events_requested` | planned |  |
| `StreamRequest.Description` | `StreamRequest.description` | `StreamRequest.description` | planned |  |
| `Telemetry` | `Telemetry` | `Telemetry` | planned |  |
| `Telemetry.Observe` | `Telemetry.observe` | `Telemetry.observe` | planned |  |
| `Transmitter` | `Transmitter` | `Transmitter` | planned |  |
| `NewTransmitter` | `new Transmitter` | `Transmitter(...)` | planned |  |
| `Transmitter.CreateStream` | `Transmitter.createStream` | `Transmitter.create_stream` | deviation | deviation: adapter calls |
| `Transmitter.RequestVerification` | `Transmitter.requestVerification` | `Transmitter.request_verification` | deviation | deviation: adapter calls |
| `Transmitter.SetStatus` | `Transmitter.setStatus` | `Transmitter.set_status` | deviation | deviation: adapter calls |
| `Transmitter.Status` | `Transmitter.status` | `Transmitter.status` | deviation | deviation: adapter calls |
| `Transmitter.Stream` | `Transmitter.stream` | `Transmitter.stream` | deviation | deviation: adapter calls |
| `TransmitterConfig` | `TransmitterConfig` | `TransmitterConfig` | planned |  |
| `TransmitterConfig.Issuer` | `TransmitterConfig.issuer` | `TransmitterConfig.issuer` | planned |  |
| `TransmitterConfig.ConfigurationEndpoint` | `TransmitterConfig.configurationEndpoint` | `TransmitterConfig.configuration_endpoint` | planned |  |
| `TransmitterConfig.StatusEndpoint` | `TransmitterConfig.statusEndpoint` | `TransmitterConfig.status_endpoint` | planned |  |
| `TransmitterConfig.VerificationEndpoint` | `TransmitterConfig.verificationEndpoint` | `TransmitterConfig.verification_endpoint` | planned |  |
| `TransmitterConfig.Authorization` | `TransmitterConfig.authorization` | `TransmitterConfig.authorization` | planned |  |
| `TransmitterConfig.Client` | `TransmitterConfig.client` | `TransmitterConfig.client` | planned |  |

## `adapter/sourcetest`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `Run` | `runSourceCases` | `run_source_case`, `source_cases` | planned | TS takes a `TestContext` (type-only import); Python returns cases for `pytest.mark.parametrize` |
| `Driver` | `Driver` | `Driver` | planned |  |
| `Driver.Model` | `Driver.model` | `Driver.model` | planned |  |
| `Driver.Open` | `Driver.open` | `Driver.open` | planned |  |
| `Env` | `Env` | `Env` | planned |  |
| `Env.Source` | `Env.source` | `Env.source` | planned |  |
| `Env.Clock` | `Env.clock` | `Env.clock` | planned |  |
| `Env.Hooks` | `Env.hooks` | `Env.hooks` | planned |  |
| `Options` | `Options` | `Options` | planned |  |
| `Options.Fixtures` | `Options.fixtures` | `Options.fixtures` | planned |  |
| `Options.Source` | `Options.source` | `Options.source` | planned |  |
| `Result` | `Result` | `Result` | planned |  |
| `Result.ID` | `Result.id` | `Result.id` | planned |  |
| `Result.Failures` | `Result.failures` | `Result.failures` | planned |  |
| `Evaluate` | `evaluateSourceCases` | `evaluate_source_cases` | planned | imports no test framework |
| `Result.Passed` | `Result.passed` | `Result.passed` | planned |  |
| `Subject` | `Subject` | `Subject` | planned |  |
| `Subject.Reader` | `Subject.reader` | `Subject.reader` | planned |  |
| `Subject.Apply` | `Subject.apply` | `Subject.apply` | deviation | deviation: adapter calls |

## `adapter/task`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `CodeTaskLimit` | `CODE_TASK_LIMIT` | `CODE_TASK_LIMIT` | planned |  |
| `ErrTaskLimit` | `TaskError` code `TASK_LIMIT` | `TaskLimit(TaskError)` | planned |  |
| `ErrNoRecord` | `TaskError` kind `NO_RECORD` | `TaskError` kind `NO_RECORD` | planned | sentinel error |
| `ErrNoEntry` | `TaskError` kind `NO_ENTRY` | `TaskError` kind `NO_ENTRY` | planned | sentinel error |
| `CheckApprovalTask` | `checkApprovalTask` | `check_approval_task` | deviation | deviation: adapter calls |
| `Approval` | `Approval` | `Approval` | planned |  |
| `Approval.Task` | `Approval.task` | `Approval.task` | planned |  |
| `Approval.Pending` | `Approval.pending` | `Approval.pending` | planned |  |
| `AsyncTracker` | `AsyncTracker` | `AsyncTracker` | planned |  |
| `AsyncTracker.Ledger` | `AsyncTracker.ledger` | `AsyncTracker.ledger` | planned |  |
| `AsyncTracker.Source` | `AsyncTracker.source` | `AsyncTracker.source` | planned |  |
| `AsyncTracker.MaxReads` | `AsyncTracker.maxReads` | `AsyncTracker.max_reads` | planned |  |
| `AsyncTracker.MinInterval` | `AsyncTracker.minInterval` | `AsyncTracker.min_interval` | deviation | deviation: time precision |
| `AsyncTracker.CheckHandle` | `AsyncTracker.checkHandle` | `AsyncTracker.check_handle` | planned |  |
| `AsyncTracker.Sleep` | `AsyncTracker.sleep` | `AsyncTracker.sleep` | deviation | deviation: time precision, adapter calls |
| `AsyncTracker.Track` | `AsyncTracker.track` | `AsyncTracker.track` | deviation | deviation: adapter calls |
| `Binding` | `Binding` | `Binding` | planned |  |
| `Binding.PrincipalID` | `Binding.principalId` | `Binding.principal_id` | planned |  |
| `Binding.AgentID` | `Binding.agentId` | `Binding.agent_id` | planned |  |
| `Binding.Workload` | `Binding.workload` | `Binding.workload` | planned |  |
| `Budget` | `Budget` | `Budget` | planned |  |
| `Budget.Limits` | `Budget.limits` | `Budget.limits` | planned |  |
| `Budget.Operations` | `Budget.operations` | `Budget.operations` | planned |  |
| `Budget.Pages` | `Budget.pages` | `Budget.pages` | planned |  |
| `Budget.Bytes` | `Budget.bytes` | `Budget.bytes` | planned |  |
| `Class` | `Class` | `Class` | planned |  |
| `ClassRead` | `Class.READ` | `Class.READ` | planned |  |
| `ClassKeyedWrite` | `Class.KEYED_WRITE` | `Class.KEYED_WRITE` | planned |  |
| `ClassLedgerWrite` | `Class.LEDGER_WRITE` | `Class.LEDGER_WRITE` | planned |  |
| `Config` | `Config` | `Config` | planned |  |
| `Config.Registry` | `Config.registry` | `Config.registry` | planned |  |
| `Config.Clock` | `Config.clock` | `Config.clock` | planned |  |
| `Config.Pager` | `Config.pager` | `Config.pager` | planned |  |
| `Config.Keys` | `Config.keys` | `Config.keys` | planned |  |
| `Effect` | `Effect` | `Effect` | planned |  |
| `EffectApplied` | `Effect.APPLIED` | `Effect.APPLIED` | planned |  |
| `EffectNone` | `Effect.NONE` | `Effect.NONE` | planned |  |
| `EffectCancelled` | `Effect.CANCELLED` | `Effect.CANCELLED` | planned |  |
| `EffectRunning` | `Effect.RUNNING` | `Effect.RUNNING` | planned |  |
| `EffectIndeterminate` | `Effect.INDETERMINATE` | `Effect.INDETERMINATE` | planned |  |
| `Entry` | `Entry` | `Entry` | planned |  |
| `Entry.Key` | `Entry.key` | `Entry.key` | planned |  |
| `Entry.State` | `Entry.state` | `Entry.state` | planned |  |
| `Entry.Binding` | `Entry.binding` | `Entry.binding` | planned |  |
| `Entry.Budget` | `Entry.budget` | `Entry.budget` | planned |  |
| `Entry.Operations` | `Entry.operations` | `Entry.operations` | planned |  |
| `IdempotencyStore` | `IdempotencyStore` | `IdempotencyStore` | planned |  |
| `IdempotencyStore.Bind` | `IdempotencyStore.bind` | `IdempotencyStore.bind` | deviation | deviation: adapter calls |
| `NewMemoryIdempotencyStore` | `newMemoryIdempotencyStore` | `new_memory_idempotency_store` | planned |  |
| `Key` | `Key` | `Key` | planned |  |
| `Key.Realm` | `Key.realm` | `Key.realm` | planned |  |
| `Key.Task` | `Key.task` | `Key.task` | planned |  |
| `Label` | `Label` | `Label` | planned |  |
| `LabelTaskUnknown` | `Label.TASK_UNKNOWN` | `Label.TASK_UNKNOWN` | planned |  |
| `LabelTaskMismatch` | `Label.TASK_MISMATCH` | `Label.TASK_MISMATCH` | planned |  |
| `LabelTaskCompleted` | `Label.TASK_COMPLETED` | `Label.TASK_COMPLETED` | planned |  |
| `LabelTaskCancelled` | `Label.TASK_CANCELLED` | `Label.TASK_CANCELLED` | planned |  |
| `LabelDeadlineElapsed` | `Label.DEADLINE_ELAPSED` | `Label.DEADLINE_ELAPSED` | planned |  |
| `LabelBudgetExhausted` | `Label.BUDGET_EXHAUSTED` | `Label.BUDGET_EXHAUSTED` | planned |  |
| `LabelOperationInFlight` | `Label.OPERATION_IN_FLIGHT` | `Label.OPERATION_IN_FLIGHT` | planned |  |
| `LabelOutcomeUnknown` | `Label.OUTCOME_UNKNOWN` | `Label.OUTCOME_UNKNOWN` | planned |  |
| `LabelIdempotencyConflict` | `Label.IDEMPOTENCY_CONFLICT` | `Label.IDEMPOTENCY_CONFLICT` | planned |  |
| `Label.TaskLimit` | `Label.taskLimit` | `Label.task_limit` | planned |  |
| `Limit` | `Limit` | `Limit` | planned |  |
| `Bounded` | `bounded` | `bounded` | planned |  |
| `Unbounded` | `unbounded` | `unbounded` | planned |  |
| `Limit.Value` | `Limit.value` | `Limit.value` | planned |  |
| `Limits` | `Limits` | `Limits` | planned |  |
| `Limits.MaxOperations` | `Limits.maxOperations` | `Limits.max_operations` | planned |  |
| `Limits.MaxPages` | `Limits.maxPages` | `Limits.max_pages` | planned |  |
| `Limits.MaxBytes` | `Limits.maxBytes` | `Limits.max_bytes` | planned |  |
| `Limits.Deadline` | `Limits.deadline` | `Limits.deadline` | deviation | deviation: time precision |
| `Memory` | `Memory` | `Memory` | planned |  |
| `NewMemory` | `new Memory` | `Memory(...)` | planned |  |
| `Memory.Entry` | `Memory.entry` | `Memory.entry` | deviation | deviation: adapter calls |
| `Memory.Observe` | `Memory.observe` | `Memory.observe` | deviation | deviation: adapter calls |
| `Memory.Record` | `Memory.record` | `Memory.record` | deviation | deviation: adapter calls |
| `Memory.Reserve` | `Memory.reserve` | `Memory.reserve` | deviation | deviation: adapter calls |
| `Memory.Resolve` | `Memory.resolve` | `Memory.resolve` | deviation | deviation: adapter calls |
| `OpState` | `OpState` | `OpState` | planned |  |
| `OpReserved` | `OpState.RESERVED` | `OpState.RESERVED` | planned |  |
| `OpAccepted` | `OpState.ACCEPTED` | `OpState.ACCEPTED` | planned |  |
| `OpSucceeded` | `OpState.SUCCEEDED` | `OpState.SUCCEEDED` | planned |  |
| `OpFailed` | `OpState.FAILED` | `OpState.FAILED` | planned |  |
| `OpUnknown` | `OpState.UNKNOWN` | `OpState.UNKNOWN` | planned |  |
| `OpReleased` | `OpState.RELEASED` | `OpState.RELEASED` | planned |  |
| `Operation` | `Operation` | `Operation` | planned |  |
| `Operation.ID` | `Operation.id` | `Operation.id` | planned |  |
| `Operation.OperationID` | `Operation.operationId` | `Operation.operation_id` | planned |  |
| `Operation.Fingerprint` | `Operation.fingerprint` | `Operation.fingerprint` | planned |  |
| `Operation.IdempotencyKey` | `Operation.idempotencyKey` | `Operation.idempotency_key` | planned |  |
| `Operation.State` | `Operation.state` | `Operation.state` | planned |  |
| `Operation.Attempts` | `Operation.attempts` | `Operation.attempts` | planned |  |
| `Operation.NativeRef` | `Operation.nativeRef` | `Operation.native_ref` | planned |  |
| `Operation.Handle` | `Operation.handle` | `Operation.handle` | planned |  |
| `Operation.RetryAfter` | `Operation.retryAfter` | `Operation.retry_after` | deviation | deviation: time precision |
| `Pager` | `Pager` | `Pager` | planned |  |
| `Pager.CheckNext` | `Pager.checkNext` | `Pager.check_next` | planned |  |
| `Record` | `Record` | `Record` | planned |  |
| `Record.Ref` | `Record.ref` | `Record.ref` | planned |  |
| `Record.State` | `Record.state` | `Record.state` | planned |  |
| `Record.Limits` | `Record.limits` | `Record.limits` | planned |  |
| `Record.AuthorityExpires` | `Record.authorityExpires` | `Record.authority_expires` | deviation | deviation: time precision |
| `Ref` | `Ref` | `Ref` | planned |  |
| `Refusal` | `Refusal` | `Refusal` | planned |  |
| `Refusal.Label` | `Refusal.label` | `Refusal.label` | planned |  |
| `Refusal.Operation` | `Refusal.operation` | `Refusal.operation` | planned |  |
| `Refusal.Error` | `Refusal.message` | `Refusal.__str__` | planned |  |
| `Refusal.Unwrap` | `Refusal.cause` | `Refusal.__cause__` | planned |  |
| `Registry` | `Registry` | `Registry` | planned |  |
| `Registry.Resolve` | `Registry.resolve` | `Registry.resolve` | deviation | deviation: adapter calls |
| `Registry.Lookup` | `Registry.lookup` | `Registry.lookup` | deviation | deviation: adapter calls |
| `Request` | `Request` | `Request` | planned |  |
| `Request.Principal` | `Request.principal` | `Request.principal` | planned |  |
| `Request.AgentID` | `Request.agentId` | `Request.agent_id` | planned |  |
| `Request.TaskID` | `Request.taskId` | `Request.task_id` | planned |  |
| `Request.Operation` | `Request.operation` | `Request.operation` | planned |  |
| `Request.Route` | `Request.route` | `Request.route` | planned |  |
| `Request.Continuation` | `Request.continuation` | `Request.continuation` | planned |  |
| `Request.BodyLength` | `Request.bodyLength` | `Request.body_length` | planned |  |
| `Reservation` | `Reservation` | `Reservation` | planned |  |
| `Reservation.Key` | `Reservation.key` | `Reservation.key` | planned |  |
| `Reservation.Operation` | `Reservation.operation` | `Reservation.operation` | planned |  |
| `Reservation.Send` | `Reservation.send` | `Reservation.send` | planned |  |
| `Reservation.BytesLeft` | `Reservation.bytesLeft` | `Reservation.bytes_left` | planned |  |
| `Result` | `Result` | `Result` | planned |  |
| `Result.Sent` | `Result.sent` | `Result.sent` | planned |  |
| `Result.Status` | `Result.status` | `Result.status` | planned |  |
| `Result.Handle` | `Result.handle` | `Result.handle` | planned |  |
| `Result.RetryAfter` | `Result.retryAfter` | `Result.retry_after` | deviation | deviation: time precision |
| `Result.NativeRef` | `Result.nativeRef` | `Result.native_ref` | planned |  |
| `Result.Bytes` | `Result.bytes` | `Result.bytes` | planned |  |
| `Result.NextLink` | `Result.nextLink` | `Result.next_link` | planned |  |
| `Route` | `Route` | `Route` | planned |  |
| `Route.ID` | `Route.id` | `Route.id` | planned |  |
| `Route.Version` | `Route.version` | `Route.version` | planned |  |
| `Route.Class` | `Route.class` | `Route.class` | planned |  |
| `Route.Page` | `Route.page` | `Route.page` | planned |  |
| `Route.Definitive` | `Route.definitive` | `Route.definitive` | planned |  |
| `Settled` | `Settled` | `Settled` | planned |  |
| `Settled.Operation` | `Settled.operation` | `Settled.operation` | planned |  |
| `Settled.PageToken` | `Settled.pageToken` | `Settled.page_token` | planned |  |
| `Settled.Report` | `Settled.report` | `Settled.report` | planned |  |
| `State` | `State` | `State` | planned |  |
| `StateActive` | `State.ACTIVE` | `State.ACTIVE` | planned |  |
| `StateCompleted` | `State.COMPLETED` | `State.COMPLETED` | planned |  |
| `StateCancelled` | `State.CANCELLED` | `State.CANCELLED` | planned |  |
| `StateExpired` | `State.EXPIRED` | `State.EXPIRED` | planned |  |
| `Status` | `Status` | `Status` | planned |  |
| `Status.Effect` | `Status.effect` | `Status.effect` | planned |  |
| `Status.Authoritative` | `Status.authoritative` | `Status.authoritative` | planned |  |
| `Status.Handle` | `Status.handle` | `Status.handle` | planned |  |
| `Status.RetryAfter` | `Status.retryAfter` | `Status.retry_after` | deviation | deviation: time precision |
| `StatusSource` | `StatusSource` | `StatusSource` | planned |  |
| `StatusSource.ReadStatus` | `StatusSource.readStatus` | `StatusSource.read_status` | deviation | deviation: adapter calls |
| `TaskLedger` | `TaskLedger` | `TaskLedger` | planned |  |
| `TaskLedger.Resolve` | `TaskLedger.resolve` | `TaskLedger.resolve` | deviation | deviation: adapter calls |
| `TaskLedger.Reserve` | `TaskLedger.reserve` | `TaskLedger.reserve` | deviation | deviation: adapter calls |
| `TaskLedger.Record` | `TaskLedger.record` | `TaskLedger.record` | deviation | deviation: adapter calls |
| `TaskLedger.Observe` | `TaskLedger.observe` | `TaskLedger.observe` | deviation | deviation: adapter calls |
| `TaskLedger.Entry` | `TaskLedger.entry` | `TaskLedger.entry` | deviation | deviation: adapter calls |

## `adapters/memory`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `CodeApprovalScopeMismatch` | `CODE_APPROVAL_SCOPE_MISMATCH` | `CODE_APPROVAL_SCOPE_MISMATCH` | done |  |
| `CodeRequirementsChanged` | `CODE_REQUIREMENTS_CHANGED` | `CODE_REQUIREMENTS_CHANGED` | done |  |
| `Model` | `MODEL` | `MODEL` | done |  |
| `PolicySourceID` | `POLICY_SOURCE_ID` | `POLICY_SOURCE_ID` | done |  |
| `Arrive` | `arrive` | `arrive` | done |  |
| `Arrived` | `arrived` | `arrived` | done |  |
| `Factory` | `factory` | `factory` | done |  |
| `FactoryWith` | `factoryWith` | `factory_with` | done |  |
| `NormalizeOrigin` | `normalizeOrigin` | `normalize_origin` | done |  |
| `SubjectOf` | `subjectOf` | `subject_of` | done |  |
| `Adapter` | `MemoryAdapter` | `MemoryAdapter` | done |  |
| `FromJSON` | `fromJSON` | `from_json` | done |  |
| `New` | `newMemoryAdapter` | `new_adapter` | done |  |
| `Adapter.AuthenticateNative` | `MemoryAdapter.authenticateNative` | `MemoryAdapter.authenticate_native` | deviation | deviation: adapter calls |
| `Adapter.AuthorizeNative` | `MemoryAdapter.authorizeNative` | `MemoryAdapter.authorize_native` | deviation | deviation: adapter calls |
| `Adapter.CheckContext` | `MemoryAdapter.checkContext` | `MemoryAdapter.check_context` | deviation | deviation: adapter calls |
| `Adapter.Credential` | `MemoryAdapter.credential` | `MemoryAdapter.credential` | done |  |
| `Adapter.Describe` | `MemoryAdapter.describe` | `MemoryAdapter.describe` | done |  |
| `Adapter.MapOperation` | `MemoryAdapter.mapOperation` | `MemoryAdapter.map_operation` | deviation | deviation: adapter calls |
| `Adapter.ReadNativeClaim` | `MemoryAdapter.readNativeClaim` | `MemoryAdapter.read_native_claim` | deviation | deviation: adapter calls |
| `Adapter.RecordOutcome` | `MemoryAdapter.recordOutcome` | `MemoryAdapter.record_outcome` | deviation | deviation: adapter calls |
| `Adapter.ResolveAgentBinding` | `MemoryAdapter.resolveAgentBinding` | `MemoryAdapter.resolve_agent_binding` | deviation | deviation: adapter calls |
| `Adapter.State` | `MemoryAdapter.state` | `MemoryAdapter.state` | done |  |
| `Adapter.VerifyOutcome` | `MemoryAdapter.verifyOutcome` | `MemoryAdapter.verify_outcome` | done |  |
| `CheckFreshness` | `CheckFreshness` | `CheckFreshness` | done |  |
| `CheckFreshness.MaxAgeSeconds` | `CheckFreshness.max_age_seconds` | `CheckFreshness.max_age_seconds` | done | JSON member name |
| `CheckFreshness.StatusMaxAgeSeconds` | `CheckFreshness.status_max_age_seconds` | `CheckFreshness.status_max_age_seconds` | done | JSON member name |
| `CheckRecord` | `CheckRecord` | `CheckRecord` | planned | TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.ID` | `CheckRecord.id` | `CheckRecord.id` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.Principal` | `CheckRecord.principal` | `CheckRecord.principal` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.AgentID` | `CheckRecord.agent_id` | `CheckRecord.agent_id` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.Result` | `CheckRecord.result` | `CheckRecord.result` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.ReasonCode` | `CheckRecord.reason_code` | `CheckRecord.reason_code` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.SourceID` | `CheckRecord.source_id` | `CheckRecord.source_id` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.SourceRef` | `CheckRecord.source_ref` | `CheckRecord.source_ref` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.ObservedAt` | `CheckRecord.observed_at` | `CheckRecord.observed_at` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.StatusCheckedAt` | `CheckRecord.status_checked_at` | `CheckRecord.status_checked_at` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.Freshness` | `CheckRecord.freshness` | `CheckRecord.freshness` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.PinnedRevision` | `CheckRecord.pinned_revision` | `CheckRecord.pinned_revision` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.Revision` | `CheckRecord.revision` | `CheckRecord.revision` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `CheckRecord.Applies` | `CheckRecord.applies` | `CheckRecord.applies` | done |  |
| `ClaimRecord` | `ClaimRecord` | `ClaimRecord` | planned | TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.Realm` | `ClaimRecord.realm` | `ClaimRecord.realm` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.Principal` | `ClaimRecord.principal` | `ClaimRecord.principal` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.Path` | `ClaimRecord.path` | `ClaimRecord.path` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.Resource` | `ClaimRecord.resource` | `ClaimRecord.resource` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.TaskID` | `ClaimRecord.task_id` | `ClaimRecord.task_id` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.Value` | `ClaimRecord.value` | `ClaimRecord.value` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.ObservedAt` | `ClaimRecord.observed_at` | `ClaimRecord.observed_at` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.StatusCheckedAt` | `ClaimRecord.status_checked_at` | `ClaimRecord.status_checked_at` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.SourceID` | `ClaimRecord.source_id` | `ClaimRecord.source_id` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.SourceRef` | `ClaimRecord.source_ref` | `ClaimRecord.source_ref` | planned | JSON member name; TypeScript: the record interface is not exported; the export of this name is the object of its `applies` operation |
| `ClaimRecord.Applies` | `ClaimRecord.applies` | `ClaimRecord.applies` | done |  |
| `Enrollment` | `Enrollment` | `Enrollment` | done |  |
| `Enrollment.Realm` | `Enrollment.realm` | `Enrollment.realm` | done | JSON member name |
| `Enrollment.Workload` | `Enrollment.workload` | `Enrollment.workload` | done | JSON member name |
| `Enrollment.AgentID` | `Enrollment.agent_id` | `Enrollment.agent_id` | done | JSON member name |
| `Enrollment.OperatorID` | `Enrollment.operator_id` | `Enrollment.operator_id` | done | JSON member name |
| `Enrollment.HolderJKT` | `Enrollment.holder_jkt` | `Enrollment.holder_jkt` | done | JSON member name |
| `Enrollment.Status` | `Enrollment.status` | `Enrollment.status` | done | JSON member name |
| `Enrollment.ObservedAt` | `Enrollment.observed_at` | `Enrollment.observed_at` | done | JSON member name |
| `Enrollment.StatusCheckedAt` | `Enrollment.status_checked_at` | `Enrollment.status_checked_at` | done | JSON member name |
| `Enrollment.SourceID` | `Enrollment.source_id` | `Enrollment.source_id` | done | JSON member name |
| `Enrollment.SourceRef` | `Enrollment.source_ref` | `Enrollment.source_ref` | done | JSON member name |
| `Gateway` | `Gateway` | `Gateway` | done |  |
| `Gateway.TenantID` | `Gateway.tenant_id` | `Gateway.tenant_id` | done | JSON member name |
| `Gateway.EnvironmentID` | `Gateway.environment_id` | `Gateway.environment_id` | done | JSON member name |
| `Gateway.Origin` | `Gateway.origin` | `Gateway.origin` | done | JSON member name |
| `Gateway.HeaderAllowlist` | `Gateway.header_allowlist` | `Gateway.header_allowlist` | done | JSON member name |
| `Identity` | `Identity` | `Identity` | done |  |
| `Identity.Ref` | `Identity.ref` | `Identity.ref` | done | JSON member name |
| `Identity.ID` | `Identity.id` | `Identity.id` | done | JSON member name |
| `Identity.Realm` | `Identity.realm` | `Identity.realm` | done | JSON member name |
| `Identity.Workload` | `Identity.workload` | `Identity.workload` | done | JSON member name |
| `Identity.Secret` | `Identity.secret` | `Identity.secret` | done | JSON member name |
| `Identity.Attributes` | `Identity.attributes` | `Identity.attributes` | done | JSON member name |
| `Mapping` | `Mapping` | `Mapping` | done |  |
| `Mapping.Version` | `Mapping.version` | `Mapping.version` | done | JSON member name |
| `Mapping.Routes` | `Mapping.routes` | `Mapping.routes` | done | JSON member name |
| `Obligation` | `Obligation` | `Obligation` | done |  |
| `Obligation.ID` | `Obligation.id` | `Obligation.id` | done | JSON member name |
| `Obligation.Attributes` | `Obligation.attributes` | `Obligation.attributes` | done | JSON member name |
| `Option` | `Option` | `Option` | done |  |
| `WithSharedWorkloads` | `withSharedWorkloads` | `with_shared_workloads` | done |  |
| `PolicyRule` | `PolicyRule` | `PolicyRule` | done |  |
| `PolicyRule.Realm` | `PolicyRule.realm` | `PolicyRule.realm` | done | JSON member name |
| `PolicyRule.Principal` | `PolicyRule.principal` | `PolicyRule.principal` | done | JSON member name |
| `PolicyRule.Action` | `PolicyRule.action` | `PolicyRule.action` | done | JSON member name |
| `PolicyRule.Resource` | `PolicyRule.resource` | `PolicyRule.resource` | done | JSON member name |
| `PolicyRule.Effect` | `PolicyRule.effect` | `PolicyRule.effect` | done | JSON member name |
| `PolicyRule.Obligations` | `PolicyRule.obligations` | `PolicyRule.obligations` | done | JSON member name |
| `PolicyRule.Reason` | `PolicyRule.reason` | `PolicyRule.reason` | done | JSON member name |
| `PolicyRule.SourceID` | `PolicyRule.source_id` | `PolicyRule.source_id` | done | JSON member name |
| `PolicyRule.SourceRef` | `PolicyRule.source_ref` | `PolicyRule.source_ref` | done | JSON member name |
| `PolicyRule.DecidedAt` | `PolicyRule.decided_at` | `PolicyRule.decided_at` | done | JSON member name |
| `PolicyRule.PolicyRevision` | `PolicyRule.policy_revision` | `PolicyRule.policy_revision` | done | JSON member name |
| `Realm` | `Realm` | `Realm` | done |  |
| `Realm.TenantID` | `Realm.tenant_id` | `Realm.tenant_id` | done | JSON member name |
| `Realm.EnvironmentID` | `Realm.environment_id` | `Realm.environment_id` | done | JSON member name |
| `Reporting` | `Reporting` | `Reporting` | done |  |
| `Reporting.Issuer` | `Reporting.issuer` | `Reporting.issuer` | done | JSON member name |
| `Reporting.Audience` | `Reporting.audience` | `Reporting.audience` | done | JSON member name |
| `Reporting.KID` | `Reporting.kid` | `Reporting.kid` | done | JSON member name |
| `Route` | `Route` | `Route` | done |  |
| `Route.Method` | `Route.method` | `Route.method` | done | JSON member name |
| `Route.Path` | `Route.path` | `Route.path` | done | JSON member name |
| `Route.Action` | `Route.action` | `Route.action` | done | JSON member name |
| `Route.Resource` | `Route.resource` | `Route.resource` | done | JSON member name |
| `Sighting` | `Sighting` | `Sighting` | done |  |
| `Sighting.SourceID` | `Sighting.source_id` | `Sighting.source_id` | done | JSON member name |
| `Sighting.SourceRef` | `Sighting.source_ref` | `Sighting.source_ref` | done | JSON member name |
| `Sighting.ObservedAt` | `Sighting.observed_at` | `Sighting.observed_at` | done | JSON member name |
| `State` | `State` | `State` | done |  |
| `State.Model` | `State.model` | `State.model` | done | JSON member name |
| `State.Gateway` | `State.gateway` | `State.gateway` | done | JSON member name |
| `State.Mappings` | `State.mappings` | `State.mappings` | done | JSON member name |
| `State.Identities` | `State.identities` | `State.identities` | done | JSON member name |
| `State.Enrollments` | `State.enrollments` | `State.enrollments` | done | JSON member name |
| `State.ApprovedPaths` | `State.approved_paths` | `State.approved_paths` | done | JSON member name |
| `State.Claims` | `State.claims` | `State.claims` | done | JSON member name |
| `State.Checks` | `State.checks` | `State.checks` | done | JSON member name |
| `State.Policy` | `State.policy` | `State.policy` | done | JSON member name |
| `State.Visibility` | `State.visibility` | `State.visibility` | done | JSON member name |
| `State.Reporting` | `State.reporting` | `State.reporting` | done | JSON member name |
| `State.Sightings` | `State.sightings` | `State.sightings` | done | JSON member name |
| `State.UnavailableSources` | `State.unavailable_sources` | `State.unavailable_sources` | done | JSON member name |
| `ParseState` | `parseState` | `parse_state` | done |  |
| `State.Validate` | `State.validate` | `State.validate` | done |  |

## `contract`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `CodeReplay` | `CODE_REPLAY` | `CODE_REPLAY` | planned |  |
| `CodeRequirementsChanged` | `CODE_REQUIREMENTS_CHANGED` | `CODE_REQUIREMENTS_CHANGED` | planned |  |
| `CodeExpired` | `CODE_EXPIRED` | `CODE_EXPIRED` | planned |  |
| `CodeSecurityHold` | `CODE_SECURITY_HOLD` | `CODE_SECURITY_HOLD` | planned |  |
| `SelectionConsistencyCheck` | `SELECTION_CONSISTENCY_CHECK` | `SELECTION_CONSISTENCY_CHECK` | planned |  |
| `ExtensionTransportProfile` | `EXTENSION_TRANSPORT_PROFILE` | `EXTENSION_TRANSPORT_PROFILE` | planned |  |
| `TransportHTTPS` | `TRANSPORT_HTTPS` | `TRANSPORT_HTTPS` | planned |  |
| `TransportStdioIPC` | `TRANSPORT_STDIO_IPC` | `TRANSPORT_STDIO_IPC` | planned |  |
| `ErrInvalidMessage` | `ContractError` code `INVALID_MESSAGE` | `ContractError` code `INVALID_MESSAGE` | planned | sentinel error |
| `ErrInvalidProof` | `ContractError` code `INVALID_PROOF` | `ContractError` code `INVALID_PROOF` | planned | sentinel error |
| `ErrContextMismatch` | `ContractError` code `CONTEXT_MISMATCH` | `ContractError` code `CONTEXT_MISMATCH` | planned | sentinel error |
| `ErrUnsupportedRequirement` | `ContractError` code `UNSUPPORTED_REQUIREMENT` | `ContractError` code `UNSUPPORTED_REQUIREMENT` | planned | sentinel error |
| `ErrRequirementsChanged` | `ContractError` code `REQUIREMENTS_CHANGED` | `ContractError` code `REQUIREMENTS_CHANGED` | planned | sentinel error |
| `ErrExpired` | `ContractError` code `EXPIRED` | `ContractError` code `EXPIRED` | planned | sentinel error |
| `ErrReplay` | `ContractError` code `REPLAY` | `ContractError` code `REPLAY` | planned | sentinel error |
| `ErrDependencyUnavailable` | `ContractError` code `DEPENDENCY_UNAVAILABLE` | `ContractError` code `DEPENDENCY_UNAVAILABLE` | planned | sentinel error |
| `ErrSecurityHold` | `ContractError` code `SECURITY_HOLD` | `ContractError` code `SECURITY_HOLD` | planned | sentinel error |
| `ErrUnsupportedPurpose` | `ContractError` code `UNSUPPORTED_PURPOSE` | `ContractError` code `UNSUPPORTED_PURPOSE` | planned | sentinel error |
| `Authenticated` | `Authenticated` | `Authenticated` | planned |  |
| `Authenticated.Principal` | `Authenticated.principal` | `Authenticated.principal` | planned |  |
| `Authenticated.Binding` | `Authenticated.binding` | `Authenticated.binding` | planned |  |
| `Contract` | `Contract` | `Contract` | planned |  |
| `Contract.Compact` | `Contract.compact` | `Contract.compact` | planned |  |
| `Contract.Claims` | `Contract.claims` | `Contract.claims` | planned |  |
| `Contract.Digest` | `Contract.digest` | `Contract.digest` | planned |  |
| `Contract.Check` | `Contract.check` | `Contract.check` | planned |  |
| `Contract.CheckActive` | `Contract.checkActive` | `Contract.check_active` | planned |  |
| `Contract.NonceRecord` | `Contract.nonceRecord` | `Contract.nonce_record` | planned |  |
| `Contract.Transport` | `Contract.transport` | `Contract.transport` | planned |  |
| `ES256Signer` | `ES256Signer` | `ES256Signer` | planned |  |
| `ES256Signer.Kid` | `ES256Signer.kid` | `ES256Signer.kid` | planned |  |
| `ES256Signer.Key` | `ES256Signer.key` | `ES256Signer.key` | planned |  |
| `ES256Signer.SignContract` | `ES256Signer.signContract` | `ES256Signer.sign_contract` | planned |  |
| `Expect` | `Expect` | `Expect` | planned |  |
| `Expect.AgentID` | `Expect.agentId` | `Expect.agent_id` | planned |  |
| `Expect.Audience` | `Expect.audience` | `Expect.audience` | planned |  |
| `Expect.Realm` | `Expect.realm` | `Expect.realm` | planned |  |
| `Expect.SupportedExtensions` | `Expect.supportedExtensions` | `Expect.supported_extensions` | planned |  |
| `MemoryReplay` | `MemoryReplay` | `MemoryReplay` | planned |  |
| `NewMemoryReplay` | `new MemoryReplay` | `MemoryReplay` | planned |  |
| `MemoryReplay.Consume` | `MemoryReplay.consume` | `MemoryReplay.consume` | deviation | deviation: time precision, adapter calls |
| `MemoryReplay.Register` | `MemoryReplay.register` | `MemoryReplay.register` | deviation | deviation: time precision, adapter calls |
| `NonceRecord` | `NonceRecord` | `NonceRecord` | planned |  |
| `NonceRecord.Nonce` | `NonceRecord.nonce` | `NonceRecord.nonce` | planned |  |
| `NonceRecord.AgentID` | `NonceRecord.agentId` | `NonceRecord.agent_id` | planned |  |
| `NonceRecord.HolderJKT` | `NonceRecord.holderJKT` | `NonceRecord.holder_jkt` | planned |  |
| `NonceRecord.Realm` | `NonceRecord.realm` | `NonceRecord.realm` | planned |  |
| `NonceRecord.OperationDigest` | `NonceRecord.operationDigest` | `NonceRecord.operation_digest` | planned |  |
| `NonceRecord.RequirementsDigest` | `NonceRecord.requirementsDigest` | `NonceRecord.requirements_digest` | planned |  |
| `Policy` | `Policy` | `Policy` | planned |  |
| `Policy.BaseRevision` | `Policy.baseRevision` | `Policy.base_revision` | planned |  |
| `Policy.LearningPolicyDigest` | `Policy.learningPolicyDigest` | `Policy.learning_policy_digest` | planned |  |
| `Policy.LearningArtifactDigest` | `Policy.learningArtifactDigest` | `Policy.learning_artifact_digest` | planned |  |
| `Publisher` | `Publisher` | `Publisher` | planned |  |
| `Publisher.Issuer` | `Publisher.issuer` | `Publisher.issuer` | planned |  |
| `Publisher.Audience` | `Publisher.audience` | `Publisher.audience` | planned |  |
| `Publisher.Realm` | `Publisher.realm` | `Publisher.realm` | planned |  |
| `Publisher.Signer` | `Publisher.signer` | `Publisher.signer` | planned |  |
| `Publisher.Replay` | `Publisher.replay` | `Publisher.replay` | planned |  |
| `Publisher.Lifetime` | `Publisher.lifetime` | `Publisher.lifetime` | deviation | deviation: time precision |
| `Publisher.Purposes` | `Publisher.purposes` | `Publisher.purposes` | planned |  |
| `Publisher.ProtectedPaths` | `Publisher.protectedPaths` | `Publisher.protected_paths` | planned |  |
| `Publisher.Issue` | `Publisher.issue` | `Publisher.issue` | deviation | deviation: time precision, adapter calls |
| `ReplayStore` | `ReplayStore` | `ReplayStore` | planned |  |
| `ReplayStore.Register` | `ReplayStore.register` | `ReplayStore.register` | deviation | deviation: time precision, adapter calls |
| `ReplayStore.Consume` | `ReplayStore.consume` | `ReplayStore.consume` | deviation | deviation: time precision, adapter calls |
| `Requirements` | `Requirements` | `Requirements` | planned |  |
| `Requirements.Policy` | `Requirements.policy` | `Requirements.policy` | planned |  |
| `Requirements.SelectedSet` | `Requirements.selectedSet` | `Requirements.selected_set` | planned |  |
| `Requirements.ConservativeSet` | `Requirements.conservativeSet` | `Requirements.conservative_set` | planned |  |
| `Requirements.FieldRules` | `Requirements.fieldRules` | `Requirements.field_rules` | planned |  |
| `Requirements.ContextChecks` | `Requirements.contextChecks` | `Requirements.context_checks` | planned |  |
| `Requirements.Mode` | `Requirements.mode` | `Requirements.mode` | planned |  |
| `Requirements.Extensions` | `Requirements.extensions` | `Requirements.extensions` | planned |  |
| `Requirements.Thresholds` | `Requirements.thresholds` | `Requirements.thresholds` | planned |  |
| `Requirements.Transport` | `Requirements.transport` | `Requirements.transport` | planned |  |
| `Signer` | `Signer` | `Signer` | planned |  |
| `Signer.SignContract` | `Signer.signContract` | `Signer.sign_contract` | planned |  |
| `ThresholdRule` | `ThresholdRule` | `ThresholdRule` | planned |  |
| `ThresholdRule.Dimension` | `ThresholdRule.dimension` | `ThresholdRule.dimension` | planned |  |
| `ThresholdRule.Statistic` | `ThresholdRule.statistic` | `ThresholdRule.statistic` | planned |  |
| `ThresholdRule.Minimum` | `ThresholdRule.minimum` | `ThresholdRule.minimum` | planned |  |
| `ThresholdRule.SecurityStatus` | `ThresholdRule.securityStatus` | `ThresholdRule.security_status` | planned |  |
| `Verifier` | `Verifier` | `Verifier` | planned |  |
| `Verifier.Publishers` | `Verifier.publishers` | `Verifier.publishers` | planned |  |
| `Verifier.Algorithms` | `Verifier.algorithms` | `Verifier.algorithms` | planned |  |
| `Verifier.Skew` | `Verifier.skew` | `Verifier.skew` | deviation | deviation: time precision |
| `Verifier.Verify` | `Verifier.verify` | `Verifier.verify` | deviation | deviation: time precision |

## `core`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `KeyMaxPresentationBytes` | `KEY_MAX_PRESENTATION_BYTES` | `KEY_MAX_PRESENTATION_BYTES` | done |  |
| `KeyMaxArtifactPayloadBytes` | `KEY_MAX_ARTIFACT_PAYLOAD_BYTES` | `KEY_MAX_ARTIFACT_PAYLOAD_BYTES` | done |  |
| `KeyMaxProfileBytes` | `KEY_MAX_PROFILE_BYTES` | `KEY_MAX_PROFILE_BYTES` | done |  |
| `KeyMaxEvidenceArtifacts` | `KEY_MAX_EVIDENCE_ARTIFACTS` | `KEY_MAX_EVIDENCE_ARTIFACTS` | done |  |
| `KeyMaxFieldRules` | `KEY_MAX_FIELD_RULES` | `KEY_MAX_FIELD_RULES` | done |  |
| `KeyMaxJSONDepth` | `KEY_MAX_JSON_DEPTH` | `KEY_MAX_JSON_DEPTH` | done |  |
| `KeyMaxResources` | `KEY_MAX_RESOURCES` | `KEY_MAX_RESOURCES` | done |  |
| `KeyMaxDescriptionBytes` | `KEY_MAX_DESCRIPTION_BYTES` | `KEY_MAX_DESCRIPTION_BYTES` | done |  |
| `DigestLen` | `DIGEST_LEN` | `DIGEST_LEN` | done |  |
| `Version` | `VERSION` | `VERSION` | done |  |
| `ErrLimitExceeded` | `LimitError` kind `LIMIT_EXCEEDED` | `LimitError` kind `LIMIT_EXCEEDED` | done | sentinel error |
| `ErrLimitsInvalid` | `LimitError` kind `LIMITS_INVALID` | `LimitError` kind `LIMITS_INVALID` | done | sentinel error |
| `ErrNilObject` | `LimitError` kind `NIL_OBJECT` | `LimitError` kind `NIL_OBJECT` | done | sentinel error |
| `AckStatus` | `AckStatus` | `AckStatus` | done |  |
| `AckAccepted` | `AckStatus.ACCEPTED` | `AckStatus.ACCEPTED` | done |  |
| `AckDuplicate` | `AckStatus.DUPLICATE` | `AckStatus.DUPLICATE` | done |  |
| `AckStatus.Valid` | `isAckStatus(x)` | `AckStatus.is_valid(s)` | done | guard |
| `Acknowledgment` | `Acknowledgment` | `Acknowledgment` | done |  |
| `Acknowledgment.RequestID` | `Acknowledgment.request_id` | `Acknowledgment.request_id` | done | JSON member name |
| `Acknowledgment.Status` | `Acknowledgment.status` | `Acknowledgment.status` | done | JSON member name |
| `Acknowledgment.ArtifactID` | `Acknowledgment.artifact_id` | `Acknowledgment.artifact_id` | done | JSON member name |
| `Acknowledgment.ReceivedAt` | `Acknowledgment.received_at` | `Acknowledgment.received_at` | done | JSON member name |
| `Acknowledgment.Extensions` | `Acknowledgment.extensions` | `Acknowledgment.extensions` | done | JSON member name |
| `AdaptiveControl` | `AdaptiveControl` | `AdaptiveControl` | done |  |
| `AdaptiveControl.ControlID` | `AdaptiveControl.control_id` | `AdaptiveControl.control_id` | done | JSON member name |
| `AdaptiveControl.ValueSchema` | `AdaptiveControl.value_schema` | `AdaptiveControl.value_schema` | done | JSON member name |
| `AdaptiveControl.AllowRelaxation` | `AdaptiveControl.allow_relaxation` | `AdaptiveControl.allow_relaxation` | done | JSON member name |
| `AdaptiveControl.Extensions` | `AdaptiveControl.extensions` | `AdaptiveControl.extensions` | done | JSON member name |
| `AdmissionAttestation` | `AdmissionAttestation` | `AdmissionAttestation` | done |  |
| `AdmissionAttestation.PactVersion` | `AdmissionAttestation.pact_version` | `AdmissionAttestation.pact_version` | done | JSON member name |
| `AdmissionAttestation.Issuer` | `AdmissionAttestation.iss` | `AdmissionAttestation.iss` | done | JSON member name |
| `AdmissionAttestation.Subject` | `AdmissionAttestation.sub` | `AdmissionAttestation.sub` | done | JSON member name |
| `AdmissionAttestation.Audience` | `AdmissionAttestation.aud` | `AdmissionAttestation.aud` | done | JSON member name |
| `AdmissionAttestation.JTI` | `AdmissionAttestation.jti` | `AdmissionAttestation.jti` | done | JSON member name |
| `AdmissionAttestation.IssuedAt` | `AdmissionAttestation.iat` | `AdmissionAttestation.iat` | done | JSON member name |
| `AdmissionAttestation.NotBefore` | `AdmissionAttestation.nbf` | `AdmissionAttestation.nbf` | done | JSON member name |
| `AdmissionAttestation.Expiry` | `AdmissionAttestation.exp` | `AdmissionAttestation.exp` | done | JSON member name |
| `AdmissionAttestation.TenantID` | `AdmissionAttestation.tenant_id` | `AdmissionAttestation.tenant_id` | done | JSON member name |
| `AdmissionAttestation.PresentationID` | `AdmissionAttestation.presentation_id` | `AdmissionAttestation.presentation_id` | done | JSON member name |
| `AdmissionAttestation.OperationID` | `AdmissionAttestation.operation_id` | `AdmissionAttestation.operation_id` | done | JSON member name |
| `AdmissionAttestation.PrincipalID` | `AdmissionAttestation.principal_id` | `AdmissionAttestation.principal_id` | done | JSON member name |
| `AdmissionAttestation.EnvironmentID` | `AdmissionAttestation.environment_id` | `AdmissionAttestation.environment_id` | done | JSON member name |
| `AdmissionAttestation.HolderJKT` | `AdmissionAttestation.holder_jkt` | `AdmissionAttestation.holder_jkt` | done | JSON member name |
| `AdmissionAttestation.ProfileDigest` | `AdmissionAttestation.profile_digest` | `AdmissionAttestation.profile_digest` | done | JSON member name |
| `AdmissionAttestation.IntentDigest` | `AdmissionAttestation.intent_digest` | `AdmissionAttestation.intent_digest` | done | JSON member name |
| `AdmissionAttestation.OperationDigest` | `AdmissionAttestation.operation_digest` | `AdmissionAttestation.operation_digest` | done | JSON member name |
| `AdmissionAttestation.RequirementsDigest` | `AdmissionAttestation.requirements_digest` | `AdmissionAttestation.requirements_digest` | done | JSON member name |
| `AdmissionAttestation.LearningPolicyDigest` | `AdmissionAttestation.learning_policy_digest` | `AdmissionAttestation.learning_policy_digest` | done | JSON member name |
| `AdmissionAttestation.LearningArtifactDigest` | `AdmissionAttestation.learning_artifact_digest` | `AdmissionAttestation.learning_artifact_digest` | done | JSON member name |
| `AdmissionAttestation.Decision` | `AdmissionAttestation.decision` | `AdmissionAttestation.decision` | done | JSON member name |
| `AdmissionAttestation.TerminalReason` | `AdmissionAttestation.terminal_reason` | `AdmissionAttestation.terminal_reason` | done | JSON member name |
| `AdmissionAttestation.Mode` | `AdmissionAttestation.mode` | `AdmissionAttestation.mode` | done | JSON member name |
| `AdmissionAttestation.Checks` | `AdmissionAttestation.checks` | `AdmissionAttestation.checks` | done | JSON member name |
| `AdmissionAttestation.Extensions` | `AdmissionAttestation.extensions` | `AdmissionAttestation.extensions` | done | JSON member name |
| `AgentProfile` | `AgentProfile` | `AgentProfile` | done |  |
| `AgentProfile.ProfileID` | `AgentProfile.profile_id` | `AgentProfile.profile_id` | done | JSON member name |
| `AgentProfile.Revision` | `AgentProfile.revision` | `AgentProfile.revision` | done | JSON member name |
| `AgentProfile.AgentID` | `AgentProfile.agent_id` | `AgentProfile.agent_id` | done | JSON member name |
| `AgentProfile.OperatorID` | `AgentProfile.operator_id` | `AgentProfile.operator_id` | done | JSON member name |
| `AgentProfile.TenantID` | `AgentProfile.tenant_id` | `AgentProfile.tenant_id` | done | JSON member name |
| `AgentProfile.HolderJKT` | `AgentProfile.holder_jkt` | `AgentProfile.holder_jkt` | done | JSON member name |
| `AgentProfile.CreatedAt` | `AgentProfile.created_at` | `AgentProfile.created_at` | done | JSON member name |
| `AgentProfile.ExpiresAt` | `AgentProfile.expires_at` | `AgentProfile.expires_at` | done | JSON member name |
| `AgentProfile.Attributes` | `AgentProfile.attributes` | `AgentProfile.attributes` | done | JSON member name |
| `AgentProfile.Extensions` | `AgentProfile.extensions` | `AgentProfile.extensions` | done | JSON member name |
| `ArtifactType` | `ArtifactType` | `ArtifactType` | done |  |
| `ArtifactBaseline` | `ArtifactType.BASELINE` | `ArtifactType.BASELINE` | done |  |
| `ArtifactScore` | `ArtifactType.SCORE` | `ArtifactType.SCORE` | done |  |
| `ArtifactRequirementSelector` | `ArtifactType.REQUIREMENT_SELECTOR` | `ArtifactType.REQUIREMENT_SELECTOR` | done |  |
| `ArtifactCalibrator` | `ArtifactType.CALIBRATOR` | `ArtifactType.CALIBRATOR` | done |  |
| `ArtifactAssessment` | `ArtifactType.ASSESSMENT` | `ArtifactType.ASSESSMENT` | done |  |
| `ArtifactType.Valid` | `isArtifactType(x)` | `ArtifactType.is_valid(s)` | done | guard |
| `Attribution` | `Attribution` | `Attribution` | done |  |
| `Attribution.NativeTaskRef` | `Attribution.native_task_ref` | `Attribution.native_task_ref` | done | JSON member name |
| `Attribution.IndependenceGroup` | `Attribution.independence_group` | `Attribution.independence_group` | done | JSON member name |
| `Attribution.CausalAssessment` | `Attribution.causal_assessment` | `Attribution.causal_assessment` | done | JSON member name |
| `Attribution.AssessmentRef` | `Attribution.assessment_ref` | `Attribution.assessment_ref` | done | JSON member name |
| `Attribution.Extensions` | `Attribution.extensions` | `Attribution.extensions` | done | JSON member name |
| `BoundDirection` | `BoundDirection` | `BoundDirection` | done |  |
| `BoundLower` | `BoundDirection.LOWER` | `BoundDirection.LOWER` | done |  |
| `BoundUpper` | `BoundDirection.UPPER` | `BoundDirection.UPPER` | done |  |
| `BoundDirection.Valid` | `isBoundDirection(x)` | `BoundDirection.is_valid(s)` | done | guard |
| `CausalAssessment` | `CausalAssessment` | `CausalAssessment` | done |  |
| `CausalAgent` | `CausalAssessment.AGENT` | `CausalAssessment.AGENT` | done |  |
| `CausalEnvironment` | `CausalAssessment.ENVIRONMENT` | `CausalAssessment.ENVIRONMENT` | done |  |
| `CausalMixed` | `CausalAssessment.MIXED` | `CausalAssessment.MIXED` | done |  |
| `CausalUnknown` | `CausalAssessment.UNKNOWN` | `CausalAssessment.UNKNOWN` | done |  |
| `CausalAssessment.Valid` | `isCausalAssessment(x)` | `CausalAssessment.is_valid(s)` | done | guard |
| `CheckResult` | `CheckResult` | `CheckResult` | done |  |
| `CheckResult.CheckID` | `CheckResult.check_id` | `CheckResult.check_id` | done | JSON member name |
| `CheckResult.Result` | `CheckResult.result` | `CheckResult.result` | done | JSON member name |
| `CheckResult.ReasonCode` | `CheckResult.reason_code` | `CheckResult.reason_code` | done | JSON member name |
| `CheckResult.CheckedAt` | `CheckResult.checked_at` | `CheckResult.checked_at` | done | JSON member name |
| `CheckResult.SourceObservedAt` | `CheckResult.source_observed_at` | `CheckResult.source_observed_at` | done | JSON member name |
| `CheckResult.StatusCheckedAt` | `CheckResult.status_checked_at` | `CheckResult.status_checked_at` | done | JSON member name |
| `CheckResult.EvidenceIDs` | `CheckResult.evidence_ids` | `CheckResult.evidence_ids` | done | JSON member name |
| `CheckResult.SourceID` | `CheckResult.source_id` | `CheckResult.source_id` | done | JSON member name |
| `CheckResult.SourceRef` | `CheckResult.source_ref` | `CheckResult.source_ref` | done | JSON member name |
| `CheckResult.Extensions` | `CheckResult.extensions` | `CheckResult.extensions` | done | JSON member name |
| `CheckStatus` | `CheckStatus` | `CheckStatus` | done |  |
| `CheckPass` | `CheckStatus.PASS` | `CheckStatus.PASS` | done |  |
| `CheckFail` | `CheckStatus.FAIL` | `CheckStatus.FAIL` | done |  |
| `CheckUnknown` | `CheckStatus.UNKNOWN` | `CheckStatus.UNKNOWN` | done |  |
| `CheckNotApplicable` | `CheckStatus.NOT_APPLICABLE` | `CheckStatus.NOT_APPLICABLE` | done |  |
| `CheckStatus.Valid` | `isCheckStatus(x)` | `CheckStatus.is_valid(s)` | done | guard |
| `Claim` | `Claim` | `Claim` | done |  |
| `Claim.Path` | `Claim.path` | `Claim.path` | done | JSON member name |
| `Claim.Value` | `Claim.value` | `Claim.value` | done | JSON member name |
| `Comparison` | `Comparison` | `Comparison` | done |  |
| `ComparisonEqual` | `Comparison.EQUAL` | `Comparison.EQUAL` | done |  |
| `ComparisonSubset` | `Comparison.SUBSET` | `Comparison.SUBSET` | done |  |
| `Comparison.Valid` | `isComparison(x)` | `Comparison.is_valid(s)` | done | guard |
| `ContractRequest` | `ContractRequest` | `ContractRequest` | done |  |
| `ContractRequest.AgentID` | `ContractRequest.agent_id` | `ContractRequest.agent_id` | done | JSON member name |
| `ContractRequest.HolderJKT` | `ContractRequest.holder_jkt` | `ContractRequest.holder_jkt` | done | JSON member name |
| `ContractRequest.Intent` | `ContractRequest.intent` | `ContractRequest.intent` | done | JSON member name |
| `ContractRequest.Operation` | `ContractRequest.operation` | `ContractRequest.operation` | done | JSON member name |
| `ContractRequest.Extensions` | `ContractRequest.extensions` | `ContractRequest.extensions` | done | JSON member name |
| `DataPolicy` | `DataPolicy` | `DataPolicy` | done |  |
| `DataPolicy.QualificationPolicyID` | `DataPolicy.qualification_policy_id` | `DataPolicy.qualification_policy_id` | done | JSON member name |
| `DataPolicy.IngestionWindowSeconds` | `DataPolicy.ingestion_window_seconds` | `DataPolicy.ingestion_window_seconds` | done | JSON member name |
| `DataPolicy.PositiveWeightCapPerTask` | `DataPolicy.positive_weight_cap_per_task` | `DataPolicy.positive_weight_cap_per_task` | done | JSON member name |
| `DataPolicy.MaximumFailureWeight` | `DataPolicy.maximum_failure_weight` | `DataPolicy.maximum_failure_weight` | done | JSON member name |
| `DataPolicy.TaskAttributionSource` | `DataPolicy.task_attribution_source` | `DataPolicy.task_attribution_source` | done | JSON member name |
| `DataPolicy.ReporterIndependencePolicyID` | `DataPolicy.reporter_independence_policy_id` | `DataPolicy.reporter_independence_policy_id` | done | JSON member name |
| `DataPolicy.Extensions` | `DataPolicy.extensions` | `DataPolicy.extensions` | done | JSON member name |
| `Decision` | `Decision` | `Decision` | done |  |
| `DecisionAdmissible` | `Decision.ADMISSIBLE` | `Decision.ADMISSIBLE` | done |  |
| `DecisionInadmissible` | `Decision.INADMISSIBLE` | `Decision.INADMISSIBLE` | done |  |
| `DecisionDeferred` | `Decision.DEFERRED` | `Decision.DEFERRED` | done |  |
| `Decision.Valid` | `isDecision(x)` | `Decision.is_valid(s)` | done | guard |
| `Digest` | `Digest` | `Digest` | done |  |
| `Digest.Validate` | `Digest.validate` | `Digest.validate` | done |  |
| `Dimension` | `Dimension` | `Dimension` | done |  |
| `DimensionReliability` | `Dimension.RELIABILITY` | `Dimension.RELIABILITY` | done |  |
| `DimensionTaskQuality` | `Dimension.TASK_QUALITY` | `Dimension.TASK_QUALITY` | done |  |
| `DimensionPolicyAdherence` | `Dimension.POLICY_ADHERENCE` | `Dimension.POLICY_ADHERENCE` | done |  |
| `DimensionNone` | `Dimension.NONE` | `Dimension.NONE` | done |  |
| `Dimension.Valid` | `isDimension(x)` | `Dimension.is_valid(s)` | done | guard |
| `DimensionStats` | `DimensionStats` | `DimensionStats` | done |  |
| `DimensionStats.ScoreBPS` | `DimensionStats.score_bps` | `DimensionStats.score_bps` | done | JSON member name |
| `DimensionStats.ConfidenceBPS` | `DimensionStats.confidence_bps` | `DimensionStats.confidence_bps` | done | JSON member name |
| `DimensionStats.IndependentTasks` | `DimensionStats.independent_tasks` | `DimensionStats.independent_tasks` | done | JSON member name |
| `DimensionStats.QualifiedEvents` | `DimensionStats.qualified_events` | `DimensionStats.qualified_events` | done | JSON member name |
| `DimensionStats.NewestEventAt` | `DimensionStats.newest_event_at` | `DimensionStats.newest_event_at` | done | JSON member name |
| `DimensionStats.Extensions` | `DimensionStats.extensions` | `DimensionStats.extensions` | done | JSON member name |
| `EvaluationPolicy` | `EvaluationPolicy` | `EvaluationPolicy` | done |  |
| `EvaluationPolicy.MinimumIndependentTasks` | `EvaluationPolicy.minimum_independent_tasks` | `EvaluationPolicy.minimum_independent_tasks` | done | JSON member name |
| `EvaluationPolicy.MinimumObservationSeconds` | `EvaluationPolicy.minimum_observation_seconds` | `EvaluationPolicy.minimum_observation_seconds` | done | JSON member name |
| `EvaluationPolicy.MinimumShadowSeconds` | `EvaluationPolicy.minimum_shadow_seconds` | `EvaluationPolicy.minimum_shadow_seconds` | done | JSON member name |
| `EvaluationPolicy.HoldoutPolicyID` | `EvaluationPolicy.holdout_policy_id` | `EvaluationPolicy.holdout_policy_id` | done | JSON member name |
| `EvaluationPolicy.ImmutableTestSuiteDigests` | `EvaluationPolicy.immutable_test_suite_digests` | `EvaluationPolicy.immutable_test_suite_digests` | done | JSON member name |
| `EvaluationPolicy.MetricBounds` | `EvaluationPolicy.metric_bounds` | `EvaluationPolicy.metric_bounds` | done | JSON member name |
| `EvaluationPolicy.MaximumRolloutPercent` | `EvaluationPolicy.maximum_rollout_percent` | `EvaluationPolicy.maximum_rollout_percent` | done | JSON member name |
| `EvaluationPolicy.RequiredEvaluatorIDs` | `EvaluationPolicy.required_evaluator_ids` | `EvaluationPolicy.required_evaluator_ids` | done | JSON member name |
| `EvaluationPolicy.RollbackConditionIDs` | `EvaluationPolicy.rollback_condition_ids` | `EvaluationPolicy.rollback_condition_ids` | done | JSON member name |
| `EvaluationPolicy.Extensions` | `EvaluationPolicy.extensions` | `EvaluationPolicy.extensions` | done | JSON member name |
| `EvaluationRequest` | `EvaluationRequest` | `EvaluationRequest` | done |  |
| `EvaluationRequest.Presentation` | `EvaluationRequest.presentation` | `EvaluationRequest.presentation` | done | JSON member name |
| `EvaluationRequest.ActualOperation` | `EvaluationRequest.actual_operation` | `EvaluationRequest.actual_operation` | done | JSON member name |
| `EvaluationRequest.Extensions` | `EvaluationRequest.extensions` | `EvaluationRequest.extensions` | done | JSON member name |
| `EventKind` | `EventKind` | `EventKind` | done |  |
| `EventAdmission` | `EventKind.ADMISSION` | `EventKind.ADMISSION` | done |  |
| `EventAuthorization` | `EventKind.AUTHORIZATION` | `EventKind.AUTHORIZATION` | done |  |
| `EventExecution` | `EventKind.EXECUTION` | `EventKind.EXECUTION` | done |  |
| `EventQuality` | `EventKind.QUALITY` | `EventKind.QUALITY` | done |  |
| `EventSecurity` | `EventKind.SECURITY` | `EventKind.SECURITY` | done |  |
| `EventFeedback` | `EventKind.FEEDBACK` | `EventKind.FEEDBACK` | done |  |
| `EventCorrection` | `EventKind.CORRECTION` | `EventKind.CORRECTION` | done |  |
| `EventRemediation` | `EventKind.REMEDIATION` | `EventKind.REMEDIATION` | done |  |
| `EventKind.Valid` | `isEventKind(x)` | `EventKind.is_valid(s)` | done | guard |
| `Evidence` | `Evidence` | `Evidence` | done |  |
| `Evidence.PactVersion` | `Evidence.pact_version` | `Evidence.pact_version` | done | JSON member name |
| `Evidence.Issuer` | `Evidence.iss` | `Evidence.iss` | done | JSON member name |
| `Evidence.Subject` | `Evidence.sub` | `Evidence.sub` | done | JSON member name |
| `Evidence.Audience` | `Evidence.aud` | `Evidence.aud` | done | JSON member name |
| `Evidence.JTI` | `Evidence.jti` | `Evidence.jti` | done | JSON member name |
| `Evidence.IssuedAt` | `Evidence.iat` | `Evidence.iat` | done | JSON member name |
| `Evidence.NotBefore` | `Evidence.nbf` | `Evidence.nbf` | done | JSON member name |
| `Evidence.Expiry` | `Evidence.exp` | `Evidence.exp` | done | JSON member name |
| `Evidence.TenantID` | `Evidence.tenant_id` | `Evidence.tenant_id` | done | JSON member name |
| `Evidence.EnvironmentID` | `Evidence.environment_id` | `Evidence.environment_id` | done | JSON member name |
| `Evidence.HolderJKT` | `Evidence.holder_jkt` | `Evidence.holder_jkt` | done | JSON member name |
| `Evidence.Kind` | `Evidence.kind` | `Evidence.kind` | done | JSON member name |
| `Evidence.Claims` | `Evidence.claims` | `Evidence.claims` | done | JSON member name |
| `Evidence.StatusRef` | `Evidence.status_ref` | `Evidence.status_ref` | done | JSON member name |
| `Evidence.Extensions` | `Evidence.extensions` | `Evidence.extensions` | done | JSON member name |
| `EvidenceKind` | `EvidenceKind` | `EvidenceKind` | done |  |
| `EvidenceKindIdentity` | `EvidenceKind.IDENTITY` | `EvidenceKind.IDENTITY` | done |  |
| `EvidenceKindMembership` | `EvidenceKind.MEMBERSHIP` | `EvidenceKind.MEMBERSHIP` | done |  |
| `EvidenceKindDelegation` | `EvidenceKind.DELEGATION` | `EvidenceKind.DELEGATION` | done |  |
| `EvidenceKindRuntime` | `EvidenceKind.RUNTIME` | `EvidenceKind.RUNTIME` | done |  |
| `EvidenceKindCapability` | `EvidenceKind.CAPABILITY` | `EvidenceKind.CAPABILITY` | done |  |
| `EvidenceKindApproval` | `EvidenceKind.APPROVAL` | `EvidenceKind.APPROVAL` | done |  |
| `EvidenceKind.Valid` | `isEvidenceKind(x)` | `EvidenceKind.is_valid(s)` | done | guard |
| `FieldRule` | `FieldRule` | `FieldRule` | done |  |
| `FieldRule.RuleID` | `FieldRule.rule_id` | `FieldRule.rule_id` | done | JSON member name |
| `FieldRule.Path` | `FieldRule.path` | `FieldRule.path` | done | JSON member name |
| `FieldRule.Schema` | `FieldRule.schema` | `FieldRule.schema` | done | JSON member name |
| `FieldRule.Source` | `FieldRule.source` | `FieldRule.source` | done | JSON member name |
| `FieldRule.Comparison` | `FieldRule.comparison` | `FieldRule.comparison` | done | JSON member name |
| `FieldRule.AllowedIssuers` | `FieldRule.allowed_issuers` | `FieldRule.allowed_issuers` | done | JSON member name |
| `FieldRule.NativePath` | `FieldRule.native_path` | `FieldRule.native_path` | done | JSON member name |
| `FieldRule.MaxAgeSeconds` | `FieldRule.max_age_seconds` | `FieldRule.max_age_seconds` | done | JSON member name |
| `FieldRule.StatusMaxAgeSeconds` | `FieldRule.status_max_age_seconds` | `FieldRule.status_max_age_seconds` | done | JSON member name |
| `FieldRule.Extensions` | `FieldRule.extensions` | `FieldRule.extensions` | done | JSON member name |
| `GatewayEndpoints` | `GatewayEndpoints` | `GatewayEndpoints` | done |  |
| `GatewayEndpoints.Requirements` | `GatewayEndpoints.requirements` | `GatewayEndpoints.requirements` | done | JSON member name |
| `GatewayEndpoints.Evaluate` | `GatewayEndpoints.evaluate` | `GatewayEndpoints.evaluate` | done | JSON member name |
| `GatewayEndpoints.Outcomes` | `GatewayEndpoints.outcomes` | `GatewayEndpoints.outcomes` | done | JSON member name |
| `GatewayEndpoints.ReputationQuery` | `GatewayEndpoints.reputation_query` | `GatewayEndpoints.reputation_query` | done | JSON member name |
| `GatewayEndpoints.LearningArtifacts` | `GatewayEndpoints.learning_artifacts` | `GatewayEndpoints.learning_artifacts` | done | JSON member name |
| `GatewayEndpoints.LearningEvents` | `GatewayEndpoints.learning_events` | `GatewayEndpoints.learning_events` | done | JSON member name |
| `GatewayEndpoints.ReceiptsQuery` | `GatewayEndpoints.receipts_query` | `GatewayEndpoints.receipts_query` | done | JSON member name |
| `GatewayMetadata` | `GatewayMetadata` | `GatewayMetadata` | done |  |
| `GatewayMetadata.GatewayID` | `GatewayMetadata.gateway_id` | `GatewayMetadata.gateway_id` | done | JSON member name |
| `GatewayMetadata.EnvironmentID` | `GatewayMetadata.environment_id` | `GatewayMetadata.environment_id` | done | JSON member name |
| `GatewayMetadata.WireVersions` | `GatewayMetadata.wire_versions` | `GatewayMetadata.wire_versions` | done | JSON member name |
| `GatewayMetadata.JWSAlgorithms` | `GatewayMetadata.jws_algorithms` | `GatewayMetadata.jws_algorithms` | done | JSON member name |
| `GatewayMetadata.Endpoints` | `GatewayMetadata.endpoints` | `GatewayMetadata.endpoints` | done | JSON member name |
| `GatewayMetadata.JWKSURI` | `GatewayMetadata.jwks_uri` | `GatewayMetadata.jwks_uri` | done | JSON member name |
| `GatewayMetadata.OperationMappingVersion` | `GatewayMetadata.operation_mapping_version` | `GatewayMetadata.operation_mapping_version` | done | JSON member name |
| `GatewayMetadata.ExtensionsSupported` | `GatewayMetadata.extensions_supported` | `GatewayMetadata.extensions_supported` | done | JSON member name |
| `GatewayMetadata.Modes` | `GatewayMetadata.modes` | `GatewayMetadata.modes` | done | JSON member name |
| `GatewayMetadata.PresentationTransports` | `GatewayMetadata.presentation_transports` | `GatewayMetadata.presentation_transports` | done | JSON member name |
| `GatewayMetadata.Limits` | `GatewayMetadata.limits` | `GatewayMetadata.limits` | done | JSON member name |
| `GatewayMetadata.ProtectedHeaderNames` | `GatewayMetadata.protected_header_names` | `GatewayMetadata.protected_header_names` | done | JSON member name |
| `GatewayMetadata.HeaderNormalizationID` | `GatewayMetadata.header_normalization_id` | `GatewayMetadata.header_normalization_id` | done | JSON member name |
| `GatewayMetadata.Adapters` | `GatewayMetadata.adapters` | `GatewayMetadata.adapters` | done | JSON member name |
| `GatewayMetadata.Extensions` | `GatewayMetadata.extensions` | `GatewayMetadata.extensions` | done | JSON member name |
| `Intent` | `Intent` | `Intent` | done |  |
| `Intent.IntentID` | `Intent.intent_id` | `Intent.intent_id` | done | JSON member name |
| `Intent.PurposeID` | `Intent.purpose_id` | `Intent.purpose_id` | done | JSON member name |
| `Intent.Description` | `Intent.description` | `Intent.description` | done | JSON member name |
| `Intent.TaskID` | `Intent.task_id` | `Intent.task_id` | done | JSON member name |
| `Intent.Extensions` | `Intent.extensions` | `Intent.extensions` | done | JSON member name |
| `JWSAlgorithm` | `JWSAlgorithm` | `JWSAlgorithm` | done |  |
| `AlgES256` | `JWSAlgorithm.ES256` | `JWSAlgorithm.ES256` | done |  |
| `AlgEd25519` | `JWSAlgorithm.ED25519` | `JWSAlgorithm.ED25519` | done |  |
| `JWSAlgorithm.Valid` | `isJWSAlgorithm(x)` | `JWSAlgorithm.is_valid(s)` | done | guard |
| `LearningArtifact` | `LearningArtifact` | `LearningArtifact` | done |  |
| `LearningArtifact.PactVersion` | `LearningArtifact.pact_version` | `LearningArtifact.pact_version` | done | JSON member name |
| `LearningArtifact.Issuer` | `LearningArtifact.iss` | `LearningArtifact.iss` | done | JSON member name |
| `LearningArtifact.Subject` | `LearningArtifact.sub` | `LearningArtifact.sub` | done | JSON member name |
| `LearningArtifact.Audience` | `LearningArtifact.aud` | `LearningArtifact.aud` | done | JSON member name |
| `LearningArtifact.JTI` | `LearningArtifact.jti` | `LearningArtifact.jti` | done | JSON member name |
| `LearningArtifact.IssuedAt` | `LearningArtifact.iat` | `LearningArtifact.iat` | done | JSON member name |
| `LearningArtifact.NotBefore` | `LearningArtifact.nbf` | `LearningArtifact.nbf` | done | JSON member name |
| `LearningArtifact.Expiry` | `LearningArtifact.exp` | `LearningArtifact.exp` | done | JSON member name |
| `LearningArtifact.TenantID` | `LearningArtifact.tenant_id` | `LearningArtifact.tenant_id` | done | JSON member name |
| `LearningArtifact.ArtifactID` | `LearningArtifact.artifact_id` | `LearningArtifact.artifact_id` | done | JSON member name |
| `LearningArtifact.Version` | `LearningArtifact.version` | `LearningArtifact.version` | done | JSON member name |
| `LearningArtifact.ModelType` | `LearningArtifact.model_type` | `LearningArtifact.model_type` | done | JSON member name |
| `LearningArtifact.ImplementationID` | `LearningArtifact.implementation_id` | `LearningArtifact.implementation_id` | done | JSON member name |
| `LearningArtifact.ContentDigest` | `LearningArtifact.content_digest` | `LearningArtifact.content_digest` | done | JSON member name |
| `LearningArtifact.SourceDataManifestDigest` | `LearningArtifact.source_data_manifest_digest` | `LearningArtifact.source_data_manifest_digest` | done | JSON member name |
| `LearningArtifact.FeatureSchemaDigest` | `LearningArtifact.feature_schema_digest` | `LearningArtifact.feature_schema_digest` | done | JSON member name |
| `LearningArtifact.TrainingConfigurationDigest` | `LearningArtifact.training_configuration_digest` | `LearningArtifact.training_configuration_digest` | done | JSON member name |
| `LearningArtifact.EvaluationReportDigest` | `LearningArtifact.evaluation_report_digest` | `LearningArtifact.evaluation_report_digest` | done | JSON member name |
| `LearningArtifact.IntendedContexts` | `LearningArtifact.intended_contexts` | `LearningArtifact.intended_contexts` | done | JSON member name |
| `LearningArtifact.BaseRevision` | `LearningArtifact.base_revision` | `LearningArtifact.base_revision` | done | JSON member name |
| `LearningArtifact.ParentArtifactDigest` | `LearningArtifact.parent_artifact_digest` | `LearningArtifact.parent_artifact_digest` | done | JSON member name |
| `LearningArtifact.OutputControls` | `LearningArtifact.output_controls` | `LearningArtifact.output_controls` | done | JSON member name |
| `LearningArtifact.ArtifactStoreRef` | `LearningArtifact.artifact_store_ref` | `LearningArtifact.artifact_store_ref` | done | JSON member name |
| `LearningArtifact.Extensions` | `LearningArtifact.extensions` | `LearningArtifact.extensions` | done | JSON member name |
| `LearningEvent` | `LearningEvent` | `LearningEvent` | done |  |
| `LearningEvent.PactVersion` | `LearningEvent.pact_version` | `LearningEvent.pact_version` | done | JSON member name |
| `LearningEvent.Issuer` | `LearningEvent.iss` | `LearningEvent.iss` | done | JSON member name |
| `LearningEvent.Subject` | `LearningEvent.sub` | `LearningEvent.sub` | done | JSON member name |
| `LearningEvent.Audience` | `LearningEvent.aud` | `LearningEvent.aud` | done | JSON member name |
| `LearningEvent.JTI` | `LearningEvent.jti` | `LearningEvent.jti` | done | JSON member name |
| `LearningEvent.IssuedAt` | `LearningEvent.iat` | `LearningEvent.iat` | done | JSON member name |
| `LearningEvent.NotBefore` | `LearningEvent.nbf` | `LearningEvent.nbf` | done | JSON member name |
| `LearningEvent.Expiry` | `LearningEvent.exp` | `LearningEvent.exp` | done | JSON member name |
| `LearningEvent.TenantID` | `LearningEvent.tenant_id` | `LearningEvent.tenant_id` | done | JSON member name |
| `LearningEvent.EventID` | `LearningEvent.event_id` | `LearningEvent.event_id` | done | JSON member name |
| `LearningEvent.EnvironmentID` | `LearningEvent.environment_id` | `LearningEvent.environment_id` | done | JSON member name |
| `LearningEvent.ArtifactDigest` | `LearningEvent.artifact_digest` | `LearningEvent.artifact_digest` | done | JSON member name |
| `LearningEvent.PreviousArtifactDigest` | `LearningEvent.previous_artifact_digest` | `LearningEvent.previous_artifact_digest` | done | JSON member name |
| `LearningEvent.PolicyDigest` | `LearningEvent.policy_digest` | `LearningEvent.policy_digest` | done | JSON member name |
| `LearningEvent.Transition` | `LearningEvent.transition` | `LearningEvent.transition` | done | JSON member name |
| `LearningEvent.ExpectedState` | `LearningEvent.expected_state` | `LearningEvent.expected_state` | done | JSON member name |
| `LearningEvent.ExpectedActiveDigest` | `LearningEvent.expected_active_digest` | `LearningEvent.expected_active_digest` | done | JSON member name |
| `LearningEvent.ActivateArtifactDigest` | `LearningEvent.activate_artifact_digest` | `LearningEvent.activate_artifact_digest` | done | JSON member name |
| `LearningEvent.EffectiveAt` | `LearningEvent.effective_at` | `LearningEvent.effective_at` | done | JSON member name |
| `LearningEvent.ScopeContexts` | `LearningEvent.scope_contexts` | `LearningEvent.scope_contexts` | done | JSON member name |
| `LearningEvent.EvaluationRefs` | `LearningEvent.evaluation_refs` | `LearningEvent.evaluation_refs` | done | JSON member name |
| `LearningEvent.ReasonCodes` | `LearningEvent.reason_codes` | `LearningEvent.reason_codes` | done | JSON member name |
| `LearningEvent.Extensions` | `LearningEvent.extensions` | `LearningEvent.extensions` | done | JSON member name |
| `LearningMode` | `LearningMode` | `LearningMode` | done |  |
| `LearningObserve` | `LearningMode.OBSERVE` | `LearningMode.OBSERVE` | done |  |
| `LearningBoundedAutonomous` | `LearningMode.BOUNDED_AUTONOMOUS` | `LearningMode.BOUNDED_AUTONOMOUS` | done |  |
| `LearningMode.Valid` | `isLearningMode(x)` | `LearningMode.is_valid(s)` | done | guard |
| `LearningPolicy` | `LearningPolicy` | `LearningPolicy` | done |  |
| `LearningPolicy.PactVersion` | `LearningPolicy.pact_version` | `LearningPolicy.pact_version` | done | JSON member name |
| `LearningPolicy.Issuer` | `LearningPolicy.iss` | `LearningPolicy.iss` | done | JSON member name |
| `LearningPolicy.Subject` | `LearningPolicy.sub` | `LearningPolicy.sub` | done | JSON member name |
| `LearningPolicy.Audience` | `LearningPolicy.aud` | `LearningPolicy.aud` | done | JSON member name |
| `LearningPolicy.JTI` | `LearningPolicy.jti` | `LearningPolicy.jti` | done | JSON member name |
| `LearningPolicy.IssuedAt` | `LearningPolicy.iat` | `LearningPolicy.iat` | done | JSON member name |
| `LearningPolicy.NotBefore` | `LearningPolicy.nbf` | `LearningPolicy.nbf` | done | JSON member name |
| `LearningPolicy.Expiry` | `LearningPolicy.exp` | `LearningPolicy.exp` | done | JSON member name |
| `LearningPolicy.TenantID` | `LearningPolicy.tenant_id` | `LearningPolicy.tenant_id` | done | JSON member name |
| `LearningPolicy.PolicyID` | `LearningPolicy.policy_id` | `LearningPolicy.policy_id` | done | JSON member name |
| `LearningPolicy.EnvironmentID` | `LearningPolicy.environment_id` | `LearningPolicy.environment_id` | done | JSON member name |
| `LearningPolicy.Mode` | `LearningPolicy.mode` | `LearningPolicy.mode` | done | JSON member name |
| `LearningPolicy.ControllerIDs` | `LearningPolicy.controller_ids` | `LearningPolicy.controller_ids` | done | JSON member name |
| `LearningPolicy.BaseRevision` | `LearningPolicy.base_revision` | `LearningPolicy.base_revision` | done | JSON member name |
| `LearningPolicy.ConservativeSet` | `LearningPolicy.conservative_set` | `LearningPolicy.conservative_set` | done | JSON member name |
| `LearningPolicy.AllowedRequirementSets` | `LearningPolicy.allowed_requirement_sets` | `LearningPolicy.allowed_requirement_sets` | done | JSON member name |
| `LearningPolicy.AdaptiveFields` | `LearningPolicy.adaptive_fields` | `LearningPolicy.adaptive_fields` | done | JSON member name |
| `LearningPolicy.PermittedArtifactTypes` | `LearningPolicy.permitted_artifact_types` | `LearningPolicy.permitted_artifact_types` | done | JSON member name |
| `LearningPolicy.PermittedImplementationIDs` | `LearningPolicy.permitted_implementation_ids` | `LearningPolicy.permitted_implementation_ids` | done | JSON member name |
| `LearningPolicy.DataPolicy` | `LearningPolicy.data_policy` | `LearningPolicy.data_policy` | done | JSON member name |
| `LearningPolicy.EvaluationPolicy` | `LearningPolicy.evaluation_policy` | `LearningPolicy.evaluation_policy` | done | JSON member name |
| `LearningPolicy.HoldClearanceAuthorities` | `LearningPolicy.hold_clearance_authorities` | `LearningPolicy.hold_clearance_authorities` | done | JSON member name |
| `LearningPolicy.Extensions` | `LearningPolicy.extensions` | `LearningPolicy.extensions` | done | JSON member name |
| `LifecycleState` | `LifecycleState` | `LifecycleState` | done |  |
| `StateCandidate` | `LifecycleState.CANDIDATE` | `LifecycleState.CANDIDATE` | done |  |
| `StateEvaluated` | `LifecycleState.EVALUATED` | `LifecycleState.EVALUATED` | done |  |
| `StateShadow` | `LifecycleState.SHADOW` | `LifecycleState.SHADOW` | done |  |
| `StateActive` | `LifecycleState.ACTIVE` | `LifecycleState.ACTIVE` | done |  |
| `StateFrozen` | `LifecycleState.FROZEN` | `LifecycleState.FROZEN` | done |  |
| `StateRolledBack` | `LifecycleState.ROLLED_BACK` | `LifecycleState.ROLLED_BACK` | done |  |
| `StateRetired` | `LifecycleState.RETIRED` | `LifecycleState.RETIRED` | done |  |
| `LifecycleState.Valid` | `isLifecycleState(x)` | `LifecycleState.is_valid(s)` | done | guard |
| `LimitError` | `LimitError` | `LimitError` | done |  |
| `LimitError.Kind` | `LimitError.kind` | `LimitError.kind` | done |  |
| `LimitError.Key` | `LimitError.key` | `LimitError.key` | done |  |
| `LimitError.Max` | `LimitError.max` | `LimitError.max` | done |  |
| `LimitError.Got` | `LimitError.got` | `LimitError.got` | done |  |
| `LimitError.Error` | `LimitError.message` | `LimitError.__str__` | done | Go `error` interface |
| `LimitError.Unwrap` | `LimitError.cause` | `LimitError.__cause__` | done | Go error chain |
| `Limits` | `Limits` | `Limits` | done |  |
| `Limits.PresentationBytes` | `Limits.presentationBytes` | `Limits.presentation_bytes` | done |  |
| `Limits.ArtifactPayloadBytes` | `Limits.artifactPayloadBytes` | `Limits.artifact_payload_bytes` | done |  |
| `Limits.ProfileBytes` | `Limits.profileBytes` | `Limits.profile_bytes` | done |  |
| `Limits.EvidenceArtifacts` | `Limits.evidenceArtifacts` | `Limits.evidence_artifacts` | done |  |
| `Limits.FieldRules` | `Limits.fieldRules` | `Limits.field_rules` | done |  |
| `Limits.Depth` | `Limits.depth` | `Limits.depth` | done |  |
| `Limits.Resources` | `Limits.resources` | `Limits.resources` | done |  |
| `Limits.DescriptionBytes` | `Limits.descriptionBytes` | `Limits.description_bytes` | done |  |
| `Defaults` | `defaultLimits()` | `defaults()` | done |  |
| `Limits.ArtifactJSON` | `artifactJSON(l, ...)` | `artifact_json(limits, ...)` | done | free function taking the limits first |
| `Limits.Check` | `checkLimits(l)` | `check(limits)` | done | free function |
| `Limits.PresentationJSON` | `presentationJSON(l, ...)` | `presentation_json(limits, ...)` | done | free function taking the limits first |
| `Limits.ProfileJSON` | `profileJSON(l, ...)` | `profile_json(limits, ...)` | done | free function taking the limits first |
| `Limits.ValidateArtifactSize` | `validateArtifactSize(l, ...)` | `validate_artifact_size(limits, ...)` | done | free function taking the limits first |
| `Limits.ValidateContract` | `validateContract(l, ...)` | `validate_contract(limits, ...)` | done | free function taking the limits first |
| `Limits.ValidateIntent` | `validateIntent(l, ...)` | `validate_intent(limits, ...)` | done | free function taking the limits first |
| `Limits.ValidateOperation` | `validateOperation(l, ...)` | `validate_operation(limits, ...)` | done | free function taking the limits first |
| `Limits.ValidatePresentation` | `validatePresentation(l, ...)` | `validate_presentation(limits, ...)` | done | free function taking the limits first |
| `Limits.ValidateProfileSize` | `validateProfileSize(l, ...)` | `validate_profile_size(limits, ...)` | done | free function taking the limits first |
| `MetricBound` | `MetricBound` | `MetricBound` | done |  |
| `MetricBound.Direction` | `MetricBound.direction` | `MetricBound.direction` | done | JSON member name |
| `MetricBound.Value` | `MetricBound.value` | `MetricBound.value` | done | JSON member name |
| `Mode` | `Mode` | `Mode` | done |  |
| `ModeEnforced` | `Mode.ENFORCED` | `Mode.ENFORCED` | done |  |
| `ModeObserve` | `Mode.OBSERVE` | `Mode.OBSERVE` | done |  |
| `Mode.Valid` | `isMode(x)` | `Mode.is_valid(s)` | done | guard |
| `NativeAdapter` | `NativeAdapter` | `NativeAdapter` | done |  |
| `NativeAdapter.Protocol` | `NativeAdapter.protocol` | `NativeAdapter.protocol` | done | JSON member name |
| `NativeAdapter.Version` | `NativeAdapter.version` | `NativeAdapter.version` | done | JSON member name |
| `NativeAdapter.MappingRevision` | `NativeAdapter.mapping_revision` | `NativeAdapter.mapping_revision` | done | JSON member name |
| `NativeAdapter.Extensions` | `NativeAdapter.extensions` | `NativeAdapter.extensions` | done | JSON member name |
| `Object` | `PactObject` | `PactObject` | deviation | deviation: raw member values |
| `OperationContext` | `OperationContext` | `OperationContext` | done |  |
| `OperationContext.OperationID` | `OperationContext.operation_id` | `OperationContext.operation_id` | done | JSON member name |
| `OperationContext.EnvironmentID` | `OperationContext.environment_id` | `OperationContext.environment_id` | done | JSON member name |
| `OperationContext.PrincipalID` | `OperationContext.principal_id` | `OperationContext.principal_id` | done | JSON member name |
| `OperationContext.Action` | `OperationContext.action` | `OperationContext.action` | done | JSON member name |
| `OperationContext.Resources` | `OperationContext.resources` | `OperationContext.resources` | done | JSON member name |
| `OperationContext.Method` | `OperationContext.method` | `OperationContext.method` | done | JSON member name |
| `OperationContext.TargetURI` | `OperationContext.target_uri` | `OperationContext.target_uri` | done | JSON member name |
| `OperationContext.BodyDigest` | `OperationContext.body_digest` | `OperationContext.body_digest` | done | JSON member name |
| `OperationContext.Headers` | `OperationContext.headers` | `OperationContext.headers` | done | JSON member name |
| `OperationContext.Extensions` | `OperationContext.extensions` | `OperationContext.extensions` | done | JSON member name |
| `OutcomeReport` | `OutcomeReport` | `OutcomeReport` | done |  |
| `OutcomeReport.PactVersion` | `OutcomeReport.pact_version` | `OutcomeReport.pact_version` | done | JSON member name |
| `OutcomeReport.Issuer` | `OutcomeReport.iss` | `OutcomeReport.iss` | done | JSON member name |
| `OutcomeReport.Subject` | `OutcomeReport.sub` | `OutcomeReport.sub` | done | JSON member name |
| `OutcomeReport.Audience` | `OutcomeReport.aud` | `OutcomeReport.aud` | done | JSON member name |
| `OutcomeReport.JTI` | `OutcomeReport.jti` | `OutcomeReport.jti` | done | JSON member name |
| `OutcomeReport.IssuedAt` | `OutcomeReport.iat` | `OutcomeReport.iat` | done | JSON member name |
| `OutcomeReport.NotBefore` | `OutcomeReport.nbf` | `OutcomeReport.nbf` | done | JSON member name |
| `OutcomeReport.Expiry` | `OutcomeReport.exp` | `OutcomeReport.exp` | done | JSON member name |
| `OutcomeReport.TenantID` | `OutcomeReport.tenant_id` | `OutcomeReport.tenant_id` | done | JSON member name |
| `OutcomeReport.EventID` | `OutcomeReport.event_id` | `OutcomeReport.event_id` | done | JSON member name |
| `OutcomeReport.EnvironmentID` | `OutcomeReport.environment_id` | `OutcomeReport.environment_id` | done | JSON member name |
| `OutcomeReport.TaskID` | `OutcomeReport.task_id` | `OutcomeReport.task_id` | done | JSON member name |
| `OutcomeReport.OperationID` | `OutcomeReport.operation_id` | `OutcomeReport.operation_id` | done | JSON member name |
| `OutcomeReport.AdmissionReceiptID` | `OutcomeReport.admission_receipt_id` | `OutcomeReport.admission_receipt_id` | done | JSON member name |
| `OutcomeReport.ObservedAt` | `OutcomeReport.observed_at` | `OutcomeReport.observed_at` | done | JSON member name |
| `OutcomeReport.ReporterRole` | `OutcomeReport.reporter_role` | `OutcomeReport.reporter_role` | done | JSON member name |
| `OutcomeReport.Context` | `OutcomeReport.context` | `OutcomeReport.context` | done | JSON member name |
| `OutcomeReport.EventKind` | `OutcomeReport.event_kind` | `OutcomeReport.event_kind` | done | JSON member name |
| `OutcomeReport.Result` | `OutcomeReport.result` | `OutcomeReport.result` | done | JSON member name |
| `OutcomeReport.Dimension` | `OutcomeReport.dimension` | `OutcomeReport.dimension` | done | JSON member name |
| `OutcomeReport.Severity` | `OutcomeReport.severity` | `OutcomeReport.severity` | done | JSON member name |
| `OutcomeReport.EvidenceRefs` | `OutcomeReport.evidence_refs` | `OutcomeReport.evidence_refs` | done | JSON member name |
| `OutcomeReport.Attribution` | `OutcomeReport.attribution` | `OutcomeReport.attribution` | done | JSON member name |
| `OutcomeReport.Supersedes` | `OutcomeReport.supersedes` | `OutcomeReport.supersedes` | done | JSON member name |
| `OutcomeReport.Details` | `OutcomeReport.details` | `OutcomeReport.details` | done | JSON member name |
| `OutcomeReport.Extensions` | `OutcomeReport.extensions` | `OutcomeReport.extensions` | done | JSON member name |
| `OutcomeResult` | `OutcomeResult` | `OutcomeResult` | done |  |
| `OutcomeSuccess` | `OutcomeResult.SUCCESS` | `OutcomeResult.SUCCESS` | done |  |
| `OutcomeFailure` | `OutcomeResult.FAILURE` | `OutcomeResult.FAILURE` | done |  |
| `OutcomeUnknown` | `OutcomeResult.UNKNOWN` | `OutcomeResult.UNKNOWN` | done |  |
| `OutcomeNotApplicable` | `OutcomeResult.NOT_APPLICABLE` | `OutcomeResult.NOT_APPLICABLE` | done |  |
| `OutcomeResult.Valid` | `isOutcomeResult(x)` | `OutcomeResult.is_valid(s)` | done | guard |
| `Presentation` | `Presentation` | `Presentation` | done |  |
| `Presentation.PactVersion` | `Presentation.pact_version` | `Presentation.pact_version` | done | JSON member name |
| `Presentation.Issuer` | `Presentation.iss` | `Presentation.iss` | done | JSON member name |
| `Presentation.Subject` | `Presentation.sub` | `Presentation.sub` | done | JSON member name |
| `Presentation.Audience` | `Presentation.aud` | `Presentation.aud` | done | JSON member name |
| `Presentation.JTI` | `Presentation.jti` | `Presentation.jti` | done | JSON member name |
| `Presentation.IssuedAt` | `Presentation.iat` | `Presentation.iat` | done | JSON member name |
| `Presentation.NotBefore` | `Presentation.nbf` | `Presentation.nbf` | done | JSON member name |
| `Presentation.Expiry` | `Presentation.exp` | `Presentation.exp` | done | JSON member name |
| `Presentation.TenantID` | `Presentation.tenant_id` | `Presentation.tenant_id` | done | JSON member name |
| `Presentation.Contract` | `Presentation.contract` | `Presentation.contract` | done | JSON member name |
| `Presentation.Profile` | `Presentation.profile` | `Presentation.profile` | done | JSON member name |
| `Presentation.Intent` | `Presentation.intent` | `Presentation.intent` | done | JSON member name |
| `Presentation.Operation` | `Presentation.operation` | `Presentation.operation` | done | JSON member name |
| `Presentation.Evidence` | `Presentation.evidence` | `Presentation.evidence` | done | JSON member name |
| `Presentation.Reputation` | `Presentation.reputation` | `Presentation.reputation` | done | JSON member name |
| `Presentation.Nonce` | `Presentation.nonce` | `Presentation.nonce` | done | JSON member name |
| `Presentation.Extensions` | `Presentation.extensions` | `Presentation.extensions` | done | JSON member name |
| `PresentationTransport` | `PresentationTransport` | `PresentationTransport` | done |  |
| `TransportHeader` | `PresentationTransport.HEADER` | `PresentationTransport.HEADER` | done |  |
| `TransportGatewayEvaluate` | `PresentationTransport.GATEWAY_EVALUATE` | `PresentationTransport.GATEWAY_EVALUATE` | done |  |
| `TransportAdapterEnvelope` | `PresentationTransport.ADAPTER_ENVELOPE` | `PresentationTransport.ADAPTER_ENVELOPE` | done |  |
| `PresentationTransport.Valid` | `isPresentationTransport(x)` | `PresentationTransport.is_valid(s)` | done | guard |
| `Problem` | `Problem` | `Problem` | done |  |
| `Problem.Type` | `Problem.type` | `Problem.type` | done | JSON member name |
| `Problem.Title` | `Problem.title` | `Problem.title` | done | JSON member name |
| `Problem.Status` | `Problem.status` | `Problem.status` | done | JSON member name |
| `Problem.Code` | `Problem.code` | `Problem.code` | done | JSON member name |
| `Problem.RequestID` | `Problem.request_id` | `Problem.request_id` | done | JSON member name |
| `Problem.Extensions` | `Problem.extensions` | `Problem.extensions` | done | JSON member name |
| `ReceiptQuery` | `ReceiptQuery` | `ReceiptQuery` | done |  |
| `ReceiptQuery.ReceiptID` | `ReceiptQuery.receipt_id` | `ReceiptQuery.receipt_id` | done | JSON member name |
| `ReceiptQuery.Extensions` | `ReceiptQuery.extensions` | `ReceiptQuery.extensions` | done | JSON member name |
| `ReporterRole` | `ReporterRole` | `ReporterRole` | done |  |
| `ReporterGateway` | `ReporterRole.GATEWAY` | `ReporterRole.GATEWAY` | done |  |
| `ReporterExecutor` | `ReporterRole.EXECUTOR` | `ReporterRole.EXECUTOR` | done |  |
| `ReporterEvaluator` | `ReporterRole.EVALUATOR` | `ReporterRole.EVALUATOR` | done |  |
| `ReporterTaskOwner` | `ReporterRole.TASK_OWNER` | `ReporterRole.TASK_OWNER` | done |  |
| `ReporterSecurityAuthority` | `ReporterRole.SECURITY_AUTHORITY` | `ReporterRole.SECURITY_AUTHORITY` | done |  |
| `ReporterAgent` | `ReporterRole.AGENT` | `ReporterRole.AGENT` | done |  |
| `ReporterRole.Valid` | `isReporterRole(x)` | `ReporterRole.is_valid(s)` | done | guard |
| `ReputationContext` | `ReputationContext` | `ReputationContext` | done |  |
| `ReputationContext.TenantID` | `ReputationContext.tenant_id` | `ReputationContext.tenant_id` | done | JSON member name |
| `ReputationContext.EnvironmentID` | `ReputationContext.environment_id` | `ReputationContext.environment_id` | done | JSON member name |
| `ReputationContext.AgentID` | `ReputationContext.agent_id` | `ReputationContext.agent_id` | done | JSON member name |
| `ReputationContext.PurposeID` | `ReputationContext.purpose_id` | `ReputationContext.purpose_id` | done | JSON member name |
| `ReputationContext.ActionClass` | `ReputationContext.action_class` | `ReputationContext.action_class` | done | JSON member name |
| `ReputationContext.ResourceClass` | `ReputationContext.resource_class` | `ReputationContext.resource_class` | done | JSON member name |
| `ReputationContext.RuntimeClass` | `ReputationContext.runtime_class` | `ReputationContext.runtime_class` | done | JSON member name |
| `ReputationContext.Extensions` | `ReputationContext.extensions` | `ReputationContext.extensions` | done | JSON member name |
| `ReputationDimensions` | `ReputationDimensions` | `ReputationDimensions` | done |  |
| `ReputationDimensions.Reliability` | `ReputationDimensions.reliability` | `ReputationDimensions.reliability` | done | JSON member name |
| `ReputationDimensions.TaskQuality` | `ReputationDimensions.task_quality` | `ReputationDimensions.task_quality` | done | JSON member name |
| `ReputationDimensions.PolicyAdherence` | `ReputationDimensions.policy_adherence` | `ReputationDimensions.policy_adherence` | done | JSON member name |
| `ReputationQuery` | `ReputationQuery` | `ReputationQuery` | done |  |
| `ReputationQuery.AgentID` | `ReputationQuery.agent_id` | `ReputationQuery.agent_id` | done | JSON member name |
| `ReputationQuery.HolderJKT` | `ReputationQuery.holder_jkt` | `ReputationQuery.holder_jkt` | done | JSON member name |
| `ReputationQuery.Context` | `ReputationQuery.context` | `ReputationQuery.context` | done | JSON member name |
| `ReputationQuery.Audience` | `ReputationQuery.audience` | `ReputationQuery.audience` | done | JSON member name |
| `ReputationQuery.Extensions` | `ReputationQuery.extensions` | `ReputationQuery.extensions` | done | JSON member name |
| `ReputationSnapshot` | `ReputationSnapshot` | `ReputationSnapshot` | done |  |
| `ReputationSnapshot.PactVersion` | `ReputationSnapshot.pact_version` | `ReputationSnapshot.pact_version` | done | JSON member name |
| `ReputationSnapshot.Issuer` | `ReputationSnapshot.iss` | `ReputationSnapshot.iss` | done | JSON member name |
| `ReputationSnapshot.Subject` | `ReputationSnapshot.sub` | `ReputationSnapshot.sub` | done | JSON member name |
| `ReputationSnapshot.Audience` | `ReputationSnapshot.aud` | `ReputationSnapshot.aud` | done | JSON member name |
| `ReputationSnapshot.JTI` | `ReputationSnapshot.jti` | `ReputationSnapshot.jti` | done | JSON member name |
| `ReputationSnapshot.IssuedAt` | `ReputationSnapshot.iat` | `ReputationSnapshot.iat` | done | JSON member name |
| `ReputationSnapshot.NotBefore` | `ReputationSnapshot.nbf` | `ReputationSnapshot.nbf` | done | JSON member name |
| `ReputationSnapshot.Expiry` | `ReputationSnapshot.exp` | `ReputationSnapshot.exp` | done | JSON member name |
| `ReputationSnapshot.TenantID` | `ReputationSnapshot.tenant_id` | `ReputationSnapshot.tenant_id` | done | JSON member name |
| `ReputationSnapshot.EnvironmentID` | `ReputationSnapshot.environment_id` | `ReputationSnapshot.environment_id` | done | JSON member name |
| `ReputationSnapshot.HolderJKT` | `ReputationSnapshot.holder_jkt` | `ReputationSnapshot.holder_jkt` | done | JSON member name |
| `ReputationSnapshot.Value` | `ReputationSnapshot.value` | `ReputationSnapshot.value` | done | JSON member name |
| `ReputationSnapshot.Extensions` | `ReputationSnapshot.extensions` | `ReputationSnapshot.extensions` | done | JSON member name |
| `ReputationValue` | `ReputationValue` | `ReputationValue` | done |  |
| `ReputationValue.Context` | `ReputationValue.context` | `ReputationValue.context` | done | JSON member name |
| `ReputationValue.Dimensions` | `ReputationValue.dimensions` | `ReputationValue.dimensions` | done | JSON member name |
| `ReputationValue.EvidenceCutoff` | `ReputationValue.evidence_cutoff` | `ReputationValue.evidence_cutoff` | done | JSON member name |
| `ReputationValue.ProvenanceDigest` | `ReputationValue.provenance_digest` | `ReputationValue.provenance_digest` | done | JSON member name |
| `ReputationValue.ScoringArtifactDigest` | `ReputationValue.scoring_artifact_digest` | `ReputationValue.scoring_artifact_digest` | done | JSON member name |
| `ReputationValue.ScoringPolicyRevision` | `ReputationValue.scoring_policy_revision` | `ReputationValue.scoring_policy_revision` | done | JSON member name |
| `ReputationValue.SecurityStatus` | `ReputationValue.security_status` | `ReputationValue.security_status` | done | JSON member name |
| `ReputationValue.HoldRefs` | `ReputationValue.hold_refs` | `ReputationValue.hold_refs` | done | JSON member name |
| `ReputationValue.Extensions` | `ReputationValue.extensions` | `ReputationValue.extensions` | done | JSON member name |
| `RequirementContract` | `RequirementContract` | `RequirementContract` | done |  |
| `RequirementContract.PactVersion` | `RequirementContract.pact_version` | `RequirementContract.pact_version` | done | JSON member name |
| `RequirementContract.Issuer` | `RequirementContract.iss` | `RequirementContract.iss` | done | JSON member name |
| `RequirementContract.Subject` | `RequirementContract.sub` | `RequirementContract.sub` | done | JSON member name |
| `RequirementContract.Audience` | `RequirementContract.aud` | `RequirementContract.aud` | done | JSON member name |
| `RequirementContract.JTI` | `RequirementContract.jti` | `RequirementContract.jti` | done | JSON member name |
| `RequirementContract.IssuedAt` | `RequirementContract.iat` | `RequirementContract.iat` | done | JSON member name |
| `RequirementContract.NotBefore` | `RequirementContract.nbf` | `RequirementContract.nbf` | done | JSON member name |
| `RequirementContract.Expiry` | `RequirementContract.exp` | `RequirementContract.exp` | done | JSON member name |
| `RequirementContract.TenantID` | `RequirementContract.tenant_id` | `RequirementContract.tenant_id` | done | JSON member name |
| `RequirementContract.ContractID` | `RequirementContract.contract_id` | `RequirementContract.contract_id` | done | JSON member name |
| `RequirementContract.EnvironmentID` | `RequirementContract.environment_id` | `RequirementContract.environment_id` | done | JSON member name |
| `RequirementContract.HolderJKT` | `RequirementContract.holder_jkt` | `RequirementContract.holder_jkt` | done | JSON member name |
| `RequirementContract.OperationDigest` | `RequirementContract.operation_digest` | `RequirementContract.operation_digest` | done | JSON member name |
| `RequirementContract.IntentDigest` | `RequirementContract.intent_digest` | `RequirementContract.intent_digest` | done | JSON member name |
| `RequirementContract.BaseRevision` | `RequirementContract.base_revision` | `RequirementContract.base_revision` | done | JSON member name |
| `RequirementContract.SelectedSet` | `RequirementContract.selected_set` | `RequirementContract.selected_set` | done | JSON member name |
| `RequirementContract.FieldRules` | `RequirementContract.field_rules` | `RequirementContract.field_rules` | done | JSON member name |
| `RequirementContract.ContextChecks` | `RequirementContract.context_checks` | `RequirementContract.context_checks` | done | JSON member name |
| `RequirementContract.LearningPolicyDigest` | `RequirementContract.learning_policy_digest` | `RequirementContract.learning_policy_digest` | done | JSON member name |
| `RequirementContract.LearningArtifactDigest` | `RequirementContract.learning_artifact_digest` | `RequirementContract.learning_artifact_digest` | done | JSON member name |
| `RequirementContract.Nonce` | `RequirementContract.nonce` | `RequirementContract.nonce` | done | JSON member name |
| `RequirementContract.Mode` | `RequirementContract.mode` | `RequirementContract.mode` | done | JSON member name |
| `RequirementContract.Extensions` | `RequirementContract.extensions` | `RequirementContract.extensions` | done | JSON member name |
| `RuleSource` | `RuleSource` | `RuleSource` | done |  |
| `RuleSourceSelf` | `RuleSource.SELF` | `RuleSource.SELF` | done |  |
| `RuleSourceEvidence` | `RuleSource.EVIDENCE` | `RuleSource.EVIDENCE` | done |  |
| `RuleSourceNative` | `RuleSource.NATIVE` | `RuleSource.NATIVE` | done |  |
| `RuleSource.Valid` | `isRuleSource(x)` | `RuleSource.is_valid(s)` | done | guard |
| `SecurityStatus` | `SecurityStatus` | `SecurityStatus` | done |  |
| `SecurityClear` | `SecurityStatus.CLEAR` | `SecurityStatus.CLEAR` | done |  |
| `SecurityCaution` | `SecurityStatus.CAUTION` | `SecurityStatus.CAUTION` | done |  |
| `SecurityHold` | `SecurityStatus.HOLD` | `SecurityStatus.HOLD` | done |  |
| `SecurityUnknown` | `SecurityStatus.UNKNOWN` | `SecurityStatus.UNKNOWN` | done |  |
| `SecurityStatus.Valid` | `isSecurityStatus(x)` | `SecurityStatus.is_valid(s)` | done | guard |
| `Severity` | `Severity` | `Severity` | done |  |
| `SeverityInfo` | `Severity.INFO` | `Severity.INFO` | done |  |
| `SeverityLow` | `Severity.LOW` | `Severity.LOW` | done |  |
| `SeverityMedium` | `Severity.MEDIUM` | `Severity.MEDIUM` | done |  |
| `SeverityHigh` | `Severity.HIGH` | `Severity.HIGH` | done |  |
| `SeverityCritical` | `Severity.CRITICAL` | `Severity.CRITICAL` | done |  |
| `Severity.Valid` | `isSeverity(x)` | `Severity.is_valid(s)` | done | guard |
| `TerminalReason` | `TerminalReason` | `TerminalReason` | done |  |
| `TerminalCompleted` | `TerminalReason.COMPLETED` | `TerminalReason.COMPLETED` | done |  |
| `TerminalCancelled` | `TerminalReason.CANCELLED` | `TerminalReason.CANCELLED` | done |  |
| `TerminalExpired` | `TerminalReason.EXPIRED` | `TerminalReason.EXPIRED` | done |  |
| `TerminalReason.Valid` | `isTerminalReason(x)` | `TerminalReason.is_valid(s)` | done | guard |
| `Transition` | `Transition` | `Transition` | done |  |
| `TransitionEvaluated` | `Transition.EVALUATED` | `Transition.EVALUATED` | done |  |
| `TransitionShadow` | `Transition.SHADOW` | `Transition.SHADOW` | done |  |
| `TransitionActive` | `Transition.ACTIVE` | `Transition.ACTIVE` | done |  |
| `TransitionFrozen` | `Transition.FROZEN` | `Transition.FROZEN` | done |  |
| `TransitionRolledBack` | `Transition.ROLLED_BACK` | `Transition.ROLLED_BACK` | done |  |
| `TransitionRetired` | `Transition.RETIRED` | `Transition.RETIRED` | done |  |
| `Transition.Valid` | `isTransition(x)` | `Transition.is_valid(s)` | done | guard |

## `core/binding`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `ErrInvalidConfig` | `RequestError` kind `INVALID_CONFIG` | `RequestError` kind `INVALID_CONFIG` | done | sentinel error |
| `ErrInvalidRequest` | `RequestError` kind `INVALID_REQUEST` | `RequestError` kind `INVALID_REQUEST` | done | sentinel error |
| `ErrBodyRead` | `RequestError` kind `BODY_READ` | `RequestError` kind `BODY_READ` | done | sentinel error |
| `FromRequest` | `fromRequest` | `from_request` | done |  |
| `Config` | `Config` | `Config` | done |  |
| `Config.Origin` | `Config.origin` | `Config.origin` | done |  |
| `Config.HeaderAllowlist` | `Config.headerAllowlist` | `Config.header_allowlist` | done |  |
| `Config.HeaderNormalizationID` | `Config.headerNormalizationId` | `Config.header_normalization_id` | done |  |
| `Config.MappingVersion` | `Config.mappingVersion` | `Config.mapping_version` | done |  |
| `Config.MaxBody` | `Config.maxBody` | `Config.max_body` | done |  |
| `Config.Validate` | `Config.validate` | `Config.validate` | done |  |
| `RequestError` | `RequestError` | `RequestError` | done |  |
| `RequestError.Rule` | `RequestError.rule` | `RequestError.rule` | done |  |
| `RequestError.Detail` | `RequestError.detail` | `RequestError.detail` | done |  |
| `RequestError.Error` | `RequestError.message` | `RequestError.__str__` | done | Go `error` interface |
| `RequestError.Unwrap` | `RequestError.cause` | `RequestError.__cause__` | done | Go error chain |
| `Rule` | `Rule` | `Rule` | done |  |
| `RuleNoRequest` | `Rule.NO_REQUEST` | `Rule.NO_REQUEST` | done |  |
| `RuleMethod` | `Rule.METHOD` | `Rule.METHOD` | done |  |
| `RuleTargetForm` | `Rule.TARGET_FORM` | `Rule.TARGET_FORM` | done |  |
| `RuleFragment` | `Rule.FRAGMENT` | `Rule.FRAGMENT` | done |  |
| `RuleUserinfo` | `Rule.USERINFO` | `Rule.USERINFO` | done |  |
| `RuleNonASCIIHost` | `Rule.NON_ASCII_HOST` | `Rule.NON_ASCII_HOST` | done |  |
| `RuleInvalidCharacter` | `Rule.INVALID_CHARACTER` | `Rule.INVALID_CHARACTER` | done |  |
| `RuleMalformedEscape` | `Rule.MALFORMED_ESCAPE` | `Rule.MALFORMED_ESCAPE` | done |  |
| `RuleEncodedUnreserved` | `Rule.ENCODED_UNRESERVED` | `Rule.ENCODED_UNRESERVED` | done |  |
| `RuleLowercaseHex` | `Rule.LOWERCASE_HEX` | `Rule.LOWERCASE_HEX` | done |  |
| `RuleInvalidUTF8` | `Rule.INVALID_UTF8` | `Rule.INVALID_UTF8` | done |  |
| `RuleEncodedSlash` | `Rule.ENCODED_SLASH` | `Rule.ENCODED_SLASH` | done |  |
| `RuleDotSegment` | `Rule.DOT_SEGMENT` | `Rule.DOT_SEGMENT` | done |  |
| `RuleTargetTooLong` | `Rule.TARGET_TOO_LONG` | `Rule.TARGET_TOO_LONG` | done |  |
| `RuleContentEncoding` | `Rule.CONTENT_ENCODING` | `Rule.CONTENT_ENCODING` | done |  |
| `RuleTransferCoding` | `Rule.TRANSFER_CODING` | `Rule.TRANSFER_CODING` | done |  |
| `RuleBodyTooLarge` | `Rule.BODY_TOO_LARGE` | `Rule.BODY_TOO_LARGE` | done |  |
| `RuleHeaderValue` | `Rule.HEADER_VALUE` | `Rule.HEADER_VALUE` | done |  |
| `RuleHeaderTooLong` | `Rule.HEADER_TOO_LONG` | `Rule.HEADER_TOO_LONG` | done |  |
| `RuleHeaderKeyCollision` | `Rule.HEADER_KEY_COLLISION` | `Rule.HEADER_KEY_COLLISION` | done | rule kept for parity; unreachable over an ordered `RawRequest`, which keeps every field line in order |
| `RuleDuplicateHost` | `Rule.DUPLICATE_HOST` | `Rule.DUPLICATE_HOST` | planned |  |
| `RuleMissingHost` | `Rule.MISSING_HOST` | `Rule.MISSING_HOST` | planned |  |
| `RuleInvalidHost` | `Rule.INVALID_HOST` | `Rule.INVALID_HOST` | planned |  |

## `core/clock`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `BaselineSkew` | `BASELINE_SKEW_MS` | `BASELINE_SKEW` | done |  |
| `ErrSkew` | `ClockError` kind `SKEW` | `ClockError` kind `SKEW` | done | sentinel error |
| `ErrTimestamp` | `ClockError` kind `TIMESTAMP` | `ClockError` kind `TIMESTAMP` | done | sentinel error |
| `ErrNotYetValid` | `ClockError` kind `NOT_YET_VALID` | `ClockError` kind `NOT_YET_VALID` | done | sentinel error |
| `ErrIssuedInFuture` | `ClockError` kind `ISSUED_IN_FUTURE` | `ClockError` kind `ISSUED_IN_FUTURE` | done | sentinel error |
| `ErrExpired` | `ClockError` kind `EXPIRED` | `ClockError` kind `EXPIRED` | done | sentinel error |
| `ErrLifetime` | `ClockError` kind `LIFETIME` | `ClockError` kind `LIFETIME` | done | sentinel error |
| `ErrTooOld` | `ClockError` kind `TOO_OLD` | `ClockError` kind `TOO_OLD` | done | sentinel error |
| `ErrUnknownArtifact` | `ClockError` kind `UNKNOWN_ARTIFACT` | `ClockError` kind `UNKNOWN_ARTIFACT` | done | sentinel error |
| `CheckLifetime` | `checkLifetime` | `check_lifetime` | done |  |
| `CheckPresentation` | `checkPresentation` | `check_presentation` | deviation | deviation: time precision |
| `CheckPresentationAge` | `checkPresentationAge` | `check_presentation_age` | deviation | deviation: time precision |
| `CheckWindow` | `checkWindow` | `check_window` | deviation | deviation: time precision |
| `MaxLifetime` | `maxLifetime` | `max_lifetime` | deviation | deviation: time precision |
| `ReplayRetention` | `replayRetention` | `replay_retention` | deviation | deviation: time precision; a retention past the language maximum means no expiry: Python the language maximum (`datetime.max`, UTC), TypeScript `Infinity` |
| `Artifact` | `Artifact` | `Artifact` | done |  |
| `Presentation` | `Artifact.PRESENTATION` | `Artifact.PRESENTATION` | done |  |
| `Contract` | `Artifact.CONTRACT` | `Artifact.CONTRACT` | done |  |
| `Evidence` | `Artifact.EVIDENCE` | `Artifact.EVIDENCE` | done |  |
| `Snapshot` | `Artifact.SNAPSHOT` | `Artifact.SNAPSHOT` | done |  |
| `Outcome` | `Artifact.OUTCOME` | `Artifact.OUTCOME` | done |  |
| `Profile` | `Artifact.PROFILE` | `Artifact.PROFILE` | done |  |
| `Artifact.String` | `Artifact.toString` | `Artifact.__str__` | done | Go `fmt.Stringer` |
| `Clock` | `Clock` | `Clock` | done |  |
| `Clock.Now` | `Clock.now` | `Clock.now` | deviation | deviation: time precision |
| `Fake` | `FakeClock` | `FakeClock` | done |  |
| `NewFake` | `new FakeClock` | `FakeClock(...)` | deviation | deviation: time precision |
| `Fake.Advance` | `FakeClock.advance` | `FakeClock.advance` | deviation | deviation: time precision |
| `Fake.Now` | `FakeClock.now` | `FakeClock.now` | deviation | deviation: time precision |
| `Fake.Set` | `FakeClock.set` | `FakeClock.set` | deviation | deviation: time precision |
| `SystemClock` | `SystemClock` | `SystemClock` | done |  |
| `SystemClock.Now` | `SystemClock.now` | `SystemClock.now` | deviation | deviation: time precision |

## `core/digest`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `ErrNotObject` | `NotObjectError` | `NotObjectError` | done |  |
| `ArtifactDigest` | `artifactDigest` | `artifact_digest` | done |  |
| `BytesDigest` | `bytesDigest` | `bytes_digest` | done |  |
| `ObjectDigest` | `objectDigest` | `object_digest` | done |  |

## `core/jcs`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `Canonicalize` | `canonicalize` | `canonicalize`, `canonicalize_value` | done |  |

## `core/jws`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `AlgES256` | `ALG_ES256` | `ALG_ES256` | done |  |
| `AlgEd25519` | `ALG_ED25519` | `ALG_ED25519` | done |  |
| `TypRequirements` | `TYP_REQUIREMENTS` | `TYP_REQUIREMENTS` | done |  |
| `TypEvidence` | `TYP_EVIDENCE` | `TYP_EVIDENCE` | done |  |
| `TypPresentation` | `TYP_PRESENTATION` | `TYP_PRESENTATION` | done |  |
| `TypAdmission` | `TYP_ADMISSION` | `TYP_ADMISSION` | done |  |
| `TypOutcome` | `TYP_OUTCOME` | `TYP_OUTCOME` | done |  |
| `TypReputation` | `TYP_REPUTATION` | `TYP_REPUTATION` | done |  |
| `TypLearningPolicy` | `TYP_LEARNING_POLICY` | `TYP_LEARNING_POLICY` | done |  |
| `TypLearningArtifact` | `TYP_LEARNING_ARTIFACT` | `TYP_LEARNING_ARTIFACT` | done |  |
| `TypLearningEvent` | `TYP_LEARNING_EVENT` | `TYP_LEARNING_EVENT` | done |  |
| `DefaultMaxCompactBytes` | `DEFAULT_MAX_COMPACT_BYTES` | `DEFAULT_MAX_COMPACT_BYTES` | done |  |
| `Sign` | `sign` | `sign` | done |  |
| `SignEd25519` | `signEd25519` | `sign_ed25519` | planned | Ed25519 is ported in neither language |
| `Thumbprint` | `thumbprint` | `thumbprint` | done |  |
| `Typs` | `typs` | `typs` | done |  |
| `Algorithms` | `Algorithms` | `Algorithms` | planned | Python: no `Algorithms` type (ES256 only) |
| `Algorithms.Accepts` | `Algorithms.accepts` | `Algorithms.accepts` | planned | Python: no `Algorithms` type (ES256 only) |
| `Algorithms.NewKeySet` | `Algorithms.newKeySet` | `Algorithms.new_key_set` | planned | Python: no `Algorithms` type (ES256 only) |
| `Algorithms.ParseJWK` | `Algorithms.parseJWK` | `Algorithms.parse_jwk` | planned | Python: no `Algorithms` type (ES256 only) |
| `Error` | `JWSError` | `JWSError` | done |  |
| `Error.Reason` | `JWSError.reason` | `JWSError.reason` | done |  |
| `Error.Detail` | `JWSError.detail` | `JWSError.detail` | done |  |
| `Error.Err` | `JWSError.cause` | `JWSError.err` | done | TypeScript: the `cause` of `Error` |
| `Error.Error` | `JWSError.message` | `JWSError.__str__` | done | Go `error` interface |
| `Error.Unwrap` | `JWSError.cause` | `JWSError.__cause__` | done | Go error chain |
| `Header` | `Header` | `Header` | done |  |
| `Header.Alg` | `Header.alg` | `Header.alg` | done |  |
| `Header.Typ` | `Header.typ` | `Header.typ` | done |  |
| `Header.Kid` | `Header.kid` | `Header.kid` | done |  |
| `Header.JWK` | `Header.jwk` | `Header.jwk` | done |  |
| `JWK` | `JWK` | `JWK` | done |  |
| `JWK.Kty` | `JWK.kty` | `JWK.kty` | done | JSON member name |
| `JWK.Crv` | `JWK.crv` | `JWK.crv` | done | JSON member name |
| `JWK.X` | `JWK.x` | `JWK.x` | done | JSON member name |
| `JWK.Y` | `JWK.y` | `JWK.y` | done | JSON member name |
| `JWK.Kid` | `JWK.kid` | `JWK.kid` | done | JSON member name |
| `JWK.Alg` | `JWK.alg` | `JWK.alg` | done | JSON member name |
| `JWK.Use` | `JWK.use` | `JWK.use` | done | JSON member name |
| `ParseJWK` | `parseJWK` | `parse_jwk` | done |  |
| `PublicEd25519JWK` | `publicEd25519JWK` | `public_ed25519_jwk` | planned | Ed25519 is ported in neither language |
| `PublicJWK` | `publicJWK` | `public_jwk` | done |  |
| `JWK.Algorithm` | `algorithmOf(jwk)` | `JWK.algorithm` | done | TypeScript: free function, `JWK` is an interface |
| `JWK.Ed25519PublicKey` | `ed25519PublicKeyOf(jwk)` | `JWK.ed25519_public_key` | planned | TypeScript: free function, `JWK` is an interface; Ed25519 is ported in neither language |
| `JWK.PublicKey` | `publicKeyOf(jwk)` | `public_key_of(jwk)` | done | free function |
| `KeyRequest` | `KeyRequest` | `KeyRequest` | done |  |
| `KeyRequest.Typ` | `KeyRequest.typ` | `KeyRequest.typ` | done |  |
| `KeyRequest.Role` | `KeyRequest.role` | `KeyRequest.role` | done |  |
| `KeyRequest.Kid` | `KeyRequest.kid` | `KeyRequest.kid` | done |  |
| `KeyRequest.Header` | `KeyRequest.header` | `KeyRequest.header` | done |  |
| `KeyRequest.Payload` | `KeyRequest.payload` | `KeyRequest.payload` | done |  |
| `KeyResolver` | `KeyResolver` | `KeyResolver` | done |  |
| `KeyResolver.TrustedKeys` | `KeyResolver.trustedKeys` | `KeyResolver.trusted_keys` | done |  |
| `KeyResolver.HolderJKT` | `KeyResolver.holderJKT` | `KeyResolver.holder_jkt` | done |  |
| `KeySet` | `KeySet` | `KeySet` | done |  |
| `NewKeySet` | `new KeySet` | `new_key_set` | done |  |
| `KeySet.Lookup` | `KeySet.lookup` | `KeySet.lookup` | done |  |
| `ParsedJWS` | `ParsedJWS` | `ParsedJWS` | done |  |
| `ParsedJWS.Compact` | `ParsedJWS.compact` | `ParsedJWS.compact` | done |  |
| `ParsedJWS.Header` | `ParsedJWS.header` | `ParsedJWS.header` | done |  |
| `ParsedJWS.Role` | `ParsedJWS.role` | `ParsedJWS.role` | done |  |
| `ParsedJWS.RawHeader` | `ParsedJWS.rawHeader` | `ParsedJWS.raw_header` | done |  |
| `ParsedJWS.Payload` | `ParsedJWS.payload` | `ParsedJWS.payload` | done |  |
| `ParsedJWS.SigningInput` | `ParsedJWS.signingInput` | `ParsedJWS.signing_input` | done |  |
| `ParsedJWS.Signature` | `ParsedJWS.signature` | `ParsedJWS.signature` | done |  |
| `ParsedJWS.Key` | `ParsedJWS.key` | `ParsedJWS.key` | done |  |
| `ParsedJWS.KeyThumbprint` | `ParsedJWS.keyThumbprint` | `ParsedJWS.key_thumbprint` | done |  |
| `Verify` | `verify` | `verify` | done |  |
| `Reason` | `Reason` | `Reason` | done |  |
| `ErrCompactSize` | `Reason.COMPACT_SIZE` | `Reason.COMPACT_SIZE` | done |  |
| `ErrCompactForm` | `Reason.COMPACT_FORM` | `Reason.COMPACT_FORM` | done |  |
| `ErrBase64URL` | `Reason.BASE64_URL` | `Reason.BASE64_URL` | done |  |
| `ErrHeaderJSON` | `Reason.HEADER_JSON` | `Reason.HEADER_JSON` | done |  |
| `ErrHeaderCrit` | `Reason.HEADER_CRIT` | `Reason.HEADER_CRIT` | done |  |
| `ErrHeaderB64` | `Reason.HEADER_B64` | `Reason.HEADER_B64` | done |  |
| `ErrHeaderJKU` | `Reason.HEADER_JKU` | `Reason.HEADER_JKU` | done |  |
| `ErrHeaderX5U` | `Reason.HEADER_X5U` | `Reason.HEADER_X5U` | done |  |
| `ErrHeaderX5C` | `Reason.HEADER_X5C` | `Reason.HEADER_X5C` | done |  |
| `ErrAlgUnsupported` | `Reason.ALG_UNSUPPORTED` | `Reason.ALG_UNSUPPORTED` | done |  |
| `ErrTypUnsupported` | `Reason.TYP_UNSUPPORTED` | `Reason.TYP_UNSUPPORTED` | done |  |
| `ErrTypMismatch` | `Reason.TYP_MISMATCH` | `Reason.TYP_MISMATCH` | done |  |
| `ErrKidMissing` | `Reason.KID_MISSING` | `Reason.KID_MISSING` | done |  |
| `ErrKidUnknown` | `Reason.KID_UNKNOWN` | `Reason.KID_UNKNOWN` | done |  |
| `ErrKidDuplicate` | `Reason.KID_DUPLICATE` | `Reason.KID_DUPLICATE` | done |  |
| `ErrJWKMissing` | `Reason.JWK_MISSING` | `Reason.JWK_MISSING` | done |  |
| `ErrJWKUnexpected` | `Reason.JWK_UNEXPECTED` | `Reason.JWK_UNEXPECTED` | done |  |
| `ErrJWKPrivate` | `Reason.JWK_PRIVATE` | `Reason.JWK_PRIVATE` | done |  |
| `ErrJWKInvalid` | `Reason.JWK_INVALID` | `Reason.JWK_INVALID` | done |  |
| `ErrJWKCurve` | `Reason.JWK_CURVE` | `Reason.JWK_CURVE` | done |  |
| `ErrJWKOffCurve` | `Reason.JWK_OFF_CURVE` | `Reason.JWK_OFF_CURVE` | done |  |
| `ErrJWKUsage` | `Reason.JWK_USAGE` | `Reason.JWK_USAGE` | done |  |
| `ErrHolderJKTMismatch` | `Reason.HOLDER_JKT_MISMATCH` | `Reason.HOLDER_JKT_MISMATCH` | done |  |
| `ErrKeyUnavailable` | `Reason.KEY_UNAVAILABLE` | `Reason.KEY_UNAVAILABLE` | done |  |
| `ErrPayloadDetached` | `Reason.PAYLOAD_DETACHED` | `Reason.PAYLOAD_DETACHED` | done |  |
| `ErrPayloadJSON` | `Reason.PAYLOAD_JSON` | `Reason.PAYLOAD_JSON` | done |  |
| `ErrSignatureLength` | `Reason.SIGNATURE_LENGTH` | `Reason.SIGNATURE_LENGTH` | done |  |
| `ErrSignatureInvalid` | `Reason.SIGNATURE_INVALID` | `Reason.SIGNATURE_INVALID` | done |  |
| `ErrSigningKey` | `Reason.SIGNING_KEY` | `Reason.SIGNING_KEY` | done |  |
| `ReasonOf` | `reasonOf` | `reason_of` | done |  |
| `Reason.Error` | `Reason.message` | `Reason.__str__` | planned | Go `error` interface; TypeScript: a `Reason` is a string with no `message` (the text is `JWSError.message`) |
| `Role` | `Role` | `Role` | done |  |
| `RoleRequirementPublisher` | `Role.REQUIREMENT_PUBLISHER` | `Role.REQUIREMENT_PUBLISHER` | done |  |
| `RoleIssuer` | `Role.ISSUER` | `Role.ISSUER` | done |  |
| `RoleHolder` | `Role.HOLDER` | `Role.HOLDER` | done |  |
| `RoleValidator` | `Role.VALIDATOR` | `Role.VALIDATOR` | done |  |
| `RoleReporter` | `Role.REPORTER` | `Role.REPORTER` | done |  |
| `RoleReputationService` | `Role.REPUTATION_SERVICE` | `Role.REPUTATION_SERVICE` | done |  |
| `RolePolicyAuthority` | `Role.POLICY_AUTHORITY` | `Role.POLICY_AUTHORITY` | done |  |
| `RoleLearningController` | `Role.LEARNING_CONTROLLER` | `Role.LEARNING_CONTROLLER` | done |  |
| `TypRole` | `typRole` | `typ_role` | done |  |
| `StaticResolver` | `StaticResolver` | `StaticResolver` | done |  |
| `StaticResolver.KeySets` | `StaticResolver.keySets` | `StaticResolver.key_sets` | done |  |
| `StaticResolver.ExpectedHolderJKT` | `StaticResolver.expectedHolderJKT` | `StaticResolver.expected_holder_jkt` | done |  |
| `StaticResolver.HolderJKT` | `StaticResolver.holderJKT` | `StaticResolver.holder_jkt` | done | Python: raises `LookupError` when `expected_holder_jkt` is empty |
| `StaticResolver.TrustedKeys` | `StaticResolver.trustedKeys` | `StaticResolver.trusted_keys` | done |  |
| `Verifier` | `Verifier` | `Verifier` | done |  |
| `Verifier.Keys` | `Verifier.keys` | `Verifier.keys` | done |  |
| `Verifier.Typ` | `Verifier.typ` | `Verifier.typ` | done |  |
| `Verifier.MaxCompactBytes` | `Verifier.maxCompactBytes` | `Verifier.max_compact_bytes` | done |  |
| `Verifier.Limits` | `Verifier.limits` | `Verifier.limits` | done |  |
| `Verifier.Algorithms` | `Verifier.algorithms` | `Verifier.algorithms` | planned | Python: no `Algorithms` type (ES256 only) |
| `Verifier.Verify` | `Verifier.verify` | `Verifier.verify` | done |  |

## `core/strictjson`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `MaxSafeInteger` | `MAX_SAFE_INTEGER` | `MAX_SAFE_INTEGER` | done |  |
| `DefaultMaxBytes` | `DEFAULT_MAX_BYTES` | `DEFAULT_MAX_BYTES` | done |  |
| `DefaultMaxDepth` | `DEFAULT_MAX_DEPTH` | `DEFAULT_MAX_DEPTH` | done |  |
| `ErrTarget` | `StrictJSONError` kind `TARGET` | `StrictJSONError` kind `TARGET` | done | sentinel error |
| `ErrSize` | `StrictJSONError` kind `SIZE` | `StrictJSONError` kind `SIZE` | done | sentinel error |
| `ErrSyntax` | `StrictJSONError` kind `SYNTAX` | `StrictJSONError` kind `SYNTAX` | done | sentinel error |
| `ErrInvalidUTF8` | `StrictJSONError` kind `INVALID_UTF8` | `StrictJSONError` kind `INVALID_UTF8` | done | sentinel error |
| `ErrLoneSurrogate` | `StrictJSONError` kind `LONE_SURROGATE` | `StrictJSONError` kind `LONE_SURROGATE` | done | sentinel error |
| `ErrDepth` | `StrictJSONError` kind `DEPTH` | `StrictJSONError` kind `DEPTH` | done | sentinel error |
| `ErrDuplicateKey` | `StrictJSONError` kind `DUPLICATE_KEY` | `StrictJSONError` kind `DUPLICATE_KEY` | done | sentinel error |
| `ErrUnknownField` | `StrictJSONError` kind `UNKNOWN_FIELD` | `StrictJSONError` kind `UNKNOWN_FIELD` | done | sentinel error |
| `ErrNonFinite` | `StrictJSONError` kind `NON_FINITE` | `StrictJSONError` kind `NON_FINITE` | done | sentinel error |
| `ErrInteger` | `StrictJSONError` kind `INTEGER` | `StrictJSONError` kind `INTEGER` | done | sentinel error |
| `ErrNull` | `StrictJSONError` kind `NULL` | `StrictJSONError` kind `NULL` | done | sentinel error |
| `ErrTrailingData` | `StrictJSONError` kind `TRAILING_DATA` | `StrictJSONError` kind `TRAILING_DATA` | done | sentinel error |
| `ErrType` | `StrictJSONError` kind `TYPE` | `StrictJSONError` kind `TYPE` | done | sentinel error |
| `Decode` | `parse` | `parse`, `parse_stream` | done |  |
| `Unmarshal` | `decode` | `decode` | done |  |
| `Error` | `StrictJSONError` | `StrictJSONError` | done |  |
| `Error.Kind` | `StrictJSONError.kind` | `StrictJSONError.kind` | done |  |
| `Error.Path` | `StrictJSONError.path` | `StrictJSONError.path` | done |  |
| `Error.Offset` | `StrictJSONError.offset` | `StrictJSONError.offset` | done |  |
| `Error.Detail` | `StrictJSONError.detail` | `StrictJSONError.detail` | done |  |
| `Error.Error` | `StrictJSONError.message` | `StrictJSONError.__str__` | done | Go `error` interface |
| `Error.Unwrap` | `StrictJSONError.cause` | `StrictJSONError.__cause__` | done | Go error chain |
| `Limits` | `Limits` | `Limits` | done |  |
| `Limits.MaxBytes` | `Limits.maxBytes` | `Limits.max_bytes` | done |  |
| `Limits.MaxDepth` | `Limits.maxDepth` | `Limits.max_depth` | done |  |

## `gateway`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `HeaderPresentation` | `HEADER_PRESENTATION` | `HEADER_PRESENTATION` | planned |  |
| `HeaderAdmission` | `HEADER_ADMISSION` | `HEADER_ADMISSION` | planned |  |
| `RequirementsPath` | `REQUIREMENTS_PATH` | `REQUIREMENTS_PATH` | planned |  |
| `DefaultAdmissionHeaderBytes` | `DEFAULT_ADMISSION_HEADER_BYTES` | `DEFAULT_ADMISSION_HEADER_BYTES` | planned |  |
| `ErrNotRecorded` | `GatewayError` kind `not-recorded` | `GatewayError` kind `not-recorded` | planned | sentinel error |
| `New` | `newGateway` | `new_gateway` | planned | middleware and handler types of the port's HTTP server |
| `Admission` | `Admission` | `Admission` | planned |  |
| `Admission.Principal` | `Admission.principal` | `Admission.principal` | planned |  |
| `Admission.Operation` | `Admission.operation` | `Admission.operation` | planned |  |
| `Admission.Receipt` | `Admission.receipt` | `Admission.receipt` | planned |  |
| `Admission.Native` | `Admission.native` | `Admission.native` | planned |  |
| `FromContext` | `fromContext` | `from_context` | planned | request context of the port's HTTP server |
| `Class` | `Class` | `Class` | planned |  |
| `ClassOff` | `Class.OFF` | `Class.OFF` | planned |  |
| `ClassObserve` | `Class.OBSERVE` | `Class.OBSERVE` | planned |  |
| `ClassEnforce` | `Class.ENFORCE` | `Class.ENFORCE` | planned |  |
| `Config` | `Config` | `Config` | planned |  |
| `Config.Adapter` | `Config.adapter` | `Config.adapter` | planned |  |
| `Config.Validator` | `Config.validator` | `Config.validator` | planned |  |
| `Config.Publisher` | `Config.publisher` | `Config.publisher` | planned |  |
| `Config.Requirements` | `Config.requirements` | `Config.requirements` | planned |  |
| `Config.Records` | `Config.records` | `Config.records` | planned |  |
| `Config.MappingVersion` | `Config.mappingVersion` | `Config.mapping_version` | planned |  |
| `Config.Routes` | `Config.routes` | `Config.routes` | planned | route patterns of the port's HTTP router |
| `Config.Default` | `Config.default` | `Config.default` | planned |  |
| `Config.AdmissionHeaderBytes` | `Config.admissionHeaderBytes` | `Config.admission_header_bytes` | planned |  |
| `Config.NativeDenial` | `Config.nativeDenial` | `Config.native_denial` | planned | handler type of the port's HTTP server |
| `ContractRecord` | `ContractRecord` | `ContractRecord` | planned |  |
| `ContractRecord.MappingVersion` | `ContractRecord.mappingVersion` | `ContractRecord.mapping_version` | planned |  |
| `ContractRecord.OperationID` | `ContractRecord.operationId` | `ContractRecord.operation_id` | planned |  |
| `ContractRecords` | `ContractRecords` | `ContractRecords` | planned |  |
| `ContractRecords.Record` | `ContractRecords.record` | `ContractRecords.record` | deviation | deviation: adapter calls |
| `ContractRecords.Lookup` | `ContractRecords.lookup` | `ContractRecords.lookup` | deviation | deviation: adapter calls |
| `MemoryHolds` | `MemoryHolds` | `MemoryHolds` | planned |  |
| `NewMemoryHolds` | `new MemoryHolds` | `MemoryHolds(...)` | planned |  |
| `MemoryHolds.Holds` | `MemoryHolds.holds` | `MemoryHolds.holds` | deviation | deviation: adapter calls |
| `MemoryHolds.Set` | `MemoryHolds.set` | `MemoryHolds.set` | planned |  |
| `MemoryHolds.SetUnavailable` | `MemoryHolds.setUnavailable` | `MemoryHolds.set_unavailable` | planned |  |
| `MemoryRecords` | `MemoryRecords` | `MemoryRecords` | planned |  |
| `NewMemoryRecords` | `new MemoryRecords` | `MemoryRecords(...)` | planned |  |
| `MemoryRecords.Lookup` | `MemoryRecords.lookup` | `MemoryRecords.lookup` | deviation | deviation: adapter calls |
| `MemoryRecords.Record` | `MemoryRecords.record` | `MemoryRecords.record` | deviation | deviation: adapter calls |
| `MemoryStatus` | `MemoryStatus` | `MemoryStatus` | planned |  |
| `NewMemoryStatus` | `new MemoryStatus` | `MemoryStatus(...)` | planned |  |
| `MemoryStatus.EvidenceStatus` | `MemoryStatus.evidenceStatus` | `MemoryStatus.evidence_status` | deviation | deviation: adapter calls |
| `MemoryStatus.Set` | `MemoryStatus.set` | `MemoryStatus.set` | planned |  |
| `RequirementSource` | `RequirementSource` | `RequirementSource` | planned |  |
| `RequirementSource.Requirements` | `RequirementSource.requirements` | `RequirementSource.requirements` | deviation | deviation: adapter calls |
| `RequirementsFunc` | `RequirementsFunc` | `RequirementsFunc` | planned | a function type: a plain function in both ports |
| `RequirementsFunc.Requirements` | `RequirementsFunc.requirements` | `RequirementsFunc.requirements` | deviation | deviation: adapter calls |
| `StaticPolicy` | `StaticPolicy` | `StaticPolicy` | planned |  |
| `StaticPolicy.ActivePolicy` | `StaticPolicy.activePolicy` | `StaticPolicy.active_policy` | planned |  |
| `StaticPolicy.Selected` | `StaticPolicy.selected` | `StaticPolicy.selected` | planned |  |
| `StaticPolicy.Active` | `StaticPolicy.active` | `StaticPolicy.active` | deviation | deviation: adapter calls |
| `StaticPolicy.Selection` | `StaticPolicy.selection` | `StaticPolicy.selection` | deviation | deviation: adapter calls |

## `holder`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `CodeConflictingEvidence` | `CODE_CONFLICTING_EVIDENCE` | `CODE_CONFLICTING_EVIDENCE` | planned |  |
| `CodeExpired` | `CODE_EXPIRED` | `CODE_EXPIRED` | planned |  |
| `ErrInvalidMessage` | `HolderError` code `INVALID_MESSAGE` | `HolderError` code `INVALID_MESSAGE` | planned | sentinel error |
| `ErrUnsupportedVersion` | `HolderError` code `INVALID_MESSAGE`, kind `unsupported-version` | `HolderError` code `INVALID_MESSAGE`, kind `unsupported-version` | planned | sentinel error; shares its code with `ErrInvalidMessage` |
| `ErrInvalidProof` | `HolderError` code `INVALID_PROOF` | `HolderError` code `INVALID_PROOF` | planned | sentinel error |
| `ErrContextMismatch` | `HolderError` code `CONTEXT_MISMATCH` | `HolderError` code `CONTEXT_MISMATCH` | planned | sentinel error |
| `ErrUnsupportedRequirement` | `HolderError` code `UNSUPPORTED_REQUIREMENT` | `HolderError` code `UNSUPPORTED_REQUIREMENT` | planned | sentinel error |
| `ErrMissingField` | `HolderError` code `MISSING_FIELD` | `HolderError` code `MISSING_FIELD` | planned | sentinel error |
| `ErrConflictingEvidence` | `HolderError` code `CONFLICTING_EVIDENCE` | `HolderError` code `CONFLICTING_EVIDENCE` | planned | sentinel error |
| `ErrExpired` | `HolderError` code `EXPIRED` | `HolderError` code `EXPIRED` | planned | sentinel error |
| `ErrDependencyUnavailable` | `HolderError` code `DEPENDENCY_UNAVAILABLE` | `HolderError` code `DEPENDENCY_UNAVAILABLE` | planned | sentinel error |
| `NewMemoryKeyES256` | `MemoryKey.es256` | `MemoryKey.es256` | planned |  |
| `NewMemoryKeyEd25519` | `MemoryKey.ed25519` | `MemoryKey.ed25519` | planned |  |
| `OperationFromRequest` | `operationFromRequest` | `operation_from_request` | planned | request type of the port's HTTP client |
| `Holder` | `Holder` | `Holder` | planned |  |
| `Holder.AgentID` | `Holder.agentId` | `Holder.agent_id` | planned |  |
| `Holder.Keys` | `Holder.keys` | `Holder.keys` | planned |  |
| `Holder.Gateway` | `Holder.gateway` | `Holder.gateway` | planned |  |
| `Holder.Realm` | `Holder.realm` | `Holder.realm` | planned |  |
| `Holder.Publishers` | `Holder.publishers` | `Holder.publishers` | planned |  |
| `Holder.Algorithms` | `Holder.algorithms` | `Holder.algorithms` | planned |  |
| `Holder.Extensions` | `Holder.extensions` | `Holder.extensions` | planned |  |
| `Holder.Skew` | `Holder.skew` | `Holder.skew` | deviation | deviation: time precision |
| `Holder.Lifetime` | `Holder.lifetime` | `Holder.lifetime` | deviation | deviation: time precision |
| `Holder.Random` | `Holder.random` | `Holder.random` | planned | random byte source |
| `Holder.Transport` | `Holder.transport` | `Holder.transport` | planned |  |
| `Holder.Negotiate` | `Holder.negotiate` | `Holder.negotiate` | deviation | deviation: adapter calls |
| `Holder.Present` | `Holder.present` | `Holder.present` | deviation | deviation: time precision, adapter calls |
| `Holder.VerifyContract` | `Holder.verifyContract` | `Holder.verify_contract` | deviation | deviation: time precision, adapter calls |
| `Input` | `Input` | `Input` | planned |  |
| `Input.Contract` | `Input.contract` | `Input.contract` | planned |  |
| `Input.Intent` | `Input.intent` | `Input.intent` | planned |  |
| `Input.Operation` | `Input.operation` | `Input.operation` | planned |  |
| `Input.Profile` | `Input.profile` | `Input.profile` | planned |  |
| `Input.Evidence` | `Input.evidence` | `Input.evidence` | planned |  |
| `Input.Reputation` | `Input.reputation` | `Input.reputation` | planned |  |
| `KeySource` | `KeySource` | `KeySource` | planned |  |
| `KeySource.PublicJWK` | `KeySource.publicJWK` | `KeySource.public_jwk` | deviation | deviation: adapter calls |
| `KeySource.Sign` | `KeySource.sign` | `KeySource.sign` | deviation | deviation: adapter calls |
| `MemoryKey` | `MemoryKey` | `MemoryKey` | planned | in-memory key source for tests |
| `MemoryKey.PublicJWK` | `MemoryKey.publicJWK` | `MemoryKey.public_jwk` | deviation | deviation: adapter calls |
| `MemoryKey.Sign` | `MemoryKey.sign` | `MemoryKey.sign` | deviation | deviation: adapter calls |
| `Presentation` | `Presentation` | `Presentation` | planned |  |
| `Presentation.Compact` | `Presentation.compact` | `Presentation.compact` | planned |  |
| `Presentation.Claims` | `Presentation.claims` | `Presentation.claims` | planned |  |
| `Presentation.Contract` | `Presentation.contract` | `Presentation.contract` | planned |  |
| `Presentation.Digest` | `Presentation.digest` | `Presentation.digest` | planned |  |
| `Presentation.ProfileDigest` | `Presentation.profileDigest` | `Presentation.profile_digest` | planned |  |

## `runner/manifest`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `FileName` | `FILE_NAME` | `FILE_NAME` | done |  |
| `SchemaFileName` | `SCHEMA_FILE_NAME` | `SCHEMA_FILE_NAME` | done |  |
| `Version` | `VERSION` | `VERSION` | done |  |
| `RuleJSON` | `RULE_JSON` | `RULE_JSON` | done |  |
| `RuleShape` | `RULE_SHAPE` | `RULE_SHAPE` | done |  |
| `RuleID` | `RULE_ID` | `RULE_ID` | done |  |
| `RuleIDDuplicate` | `RULE_ID_DUPLICATE` | `RULE_ID_DUPLICATE` | done |  |
| `RuleOrder` | `RULE_ORDER` | `RULE_ORDER` | done |  |
| `RuleKind` | `RULE_KIND` | `RULE_KIND` | done |  |
| `RuleScope` | `RULE_SCOPE` | `RULE_SCOPE` | done |  |
| `RulePath` | `RULE_PATH` | `RULE_PATH` | done |  |
| `RuleExpected` | `RULE_EXPECTED` | `RULE_EXPECTED` | done |  |
| `RuleOutcome` | `RULE_OUTCOME` | `RULE_OUTCOME` | done |  |
| `RuleSpecMapRow` | `RULE_SPEC_MAP_ROW` | `RULE_SPEC_MAP_ROW` | done |  |
| `RuleDraftSection` | `RULE_DRAFT_SECTION` | `RULE_DRAFT_SECTION` | done |  |
| `RuleCapabilities` | `RULE_CAPABILITIES` | `RULE_CAPABILITIES` | done |  |
| `RuleConformanceProfile` | `RULE_CONFORMANCE_PROFILE` | `RULE_CONFORMANCE_PROFILE` | done |  |
| `RuleTransport` | `RULE_TRANSPORT` | `RULE_TRANSPORT` | done |  |
| `RuleLayer` | `RULE_LAYER` | `RULE_LAYER` | done |  |
| `RuleAdapterCasePath` | `RULE_ADAPTER_CASE_PATH` | `RULE_ADAPTER_CASE_PATH` | done |  |
| `RuleSourceCasePath` | `RULE_SOURCE_CASE_PATH` | `RULE_SOURCE_CASE_PATH` | done |  |
| `RulePathMissing` | `RULE_PATH_MISSING` | `RULE_PATH_MISSING` | done |  |
| `RuleExpectedMissing` | `RULE_EXPECTED_MISSING` | `RULE_EXPECTED_MISSING` | done |  |
| `RuleUncovered` | `RULE_UNCOVERED` | `RULE_UNCOVERED` | done |  |
| `RuleExtension` | `RULE_EXTENSION` | `RULE_EXTENSION` | done |  |
| `RuleRowUnknown` | `RULE_ROW_UNKNOWN` | `RULE_ROW_UNKNOWN` | done |  |
| `RuleFixtureMissing` | `RULE_FIXTURE_MISSING` | `RULE_FIXTURE_MISSING` | done |  |
| `RuleGroupPlanned` | `RULE_GROUP_PLANNED` | `RULE_GROUP_PLANNED` | done |  |
| `RuleGroupPartialEmpty` | `RULE_GROUP_PARTIAL_EMPTY` | `RULE_GROUP_PARTIAL_EMPTY` | done |  |
| `RuleGroupPartialComplete` | `RULE_GROUP_PARTIAL_COMPLETE` | `RULE_GROUP_PARTIAL_COMPLETE` | done |  |
| `RuleGroupLanded` | `RULE_GROUP_LANDED` | `RULE_GROUP_LANDED` | done |  |
| `RuleGroupUnlisted` | `RULE_GROUP_UNLISTED` | `RULE_GROUP_UNLISTED` | done |  |
| `RuleSpecMap` | `RULE_SPEC_MAP` | `RULE_SPEC_MAP` | done |  |
| `IDPattern` | `ID_PATTERN` | `ID_PATTERN` | done |  |
| `AdapterCaseIDPattern` | `ADAPTER_CASE_ID_PATTERN` | `ADAPTER_CASE_ID_PATTERN` | done |  |
| `SourceCaseIDPattern` | `SOURCE_CASE_ID_PATTERN` | `SOURCE_CASE_ID_PATTERN` | done |  |
| `PathPattern` | `PATH_PATTERN` | `PATH_PATTERN` | done |  |
| `SpecMapRowPattern` | `SPEC_MAP_ROW_PATTERN` | `SPEC_MAP_ROW_PATTERN` | done |  |
| `DraftSectionPattern` | `DRAFT_SECTION_PATTERN` | `DRAFT_SECTION_PATTERN` | done |  |
| `ConformanceProfileFull` | `CONFORMANCE_PROFILE_FULL` | `CONFORMANCE_PROFILE_FULL` | done |  |
| `ConformanceProfileSingleOwner` | `CONFORMANCE_PROFILE_SINGLE_OWNER` | `CONFORMANCE_PROFILE_SINGLE_OWNER` | done |  |
| `DefaultConformanceProfile` | `DEFAULT_CONFORMANCE_PROFILE` | `DEFAULT_CONFORMANCE_PROFILE` | done |  |
| `TransportHTTPS` | `TRANSPORT_HTTPS` | `TRANSPORT_HTTPS` | done |  |
| `TransportStdioIPC` | `TRANSPORT_STDIO_IPC` | `TRANSPORT_STDIO_IPC` | done |  |
| `DefaultTransport` | `DEFAULT_TRANSPORT` | `DEFAULT_TRANSPORT` | done |  |
| `LayerTranscript` | `LAYER_TRANSCRIPT` | `LAYER_TRANSCRIPT` | done |  |
| `LayerOS` | `LAYER_OS` | `LAYER_OS` | done |  |
| `StatusPlanned` | `STATUS_PLANNED` | `STATUS_PLANNED` | done |  |
| `StatusPartial` | `STATUS_PARTIAL` | `STATUS_PARTIAL` | done |  |
| `StatusLanded` | `STATUS_LANDED` | `STATUS_LANDED` | done |  |
| `CapabilityJWSEd25519` | `CAPABILITY_JWS_ED25519` | `CAPABILITY_JWS_ED25519` | done |  |
| `TestdataDir` | `TESTDATA_DIR` | `TESTDATA_DIR` | done |  |
| `Capabilities` | `capabilities` | `capabilities` | done |  |
| `ConformanceProfiles` | `conformanceProfiles` | `conformance_profiles` | done |  |
| `FixtureExists` | `fixtureExists` | `fixture_exists` | done |  |
| `Kinds` | `kinds` | `kinds` | done |  |
| `Layers` | `layers` | `layers` | done |  |
| `Outcomes` | `outcomes` | `outcomes` | done |  |
| `ParseSpecMap` | `parseSpecMap` | `parse_spec_map` | done |  |
| `Scopes` | `scopes` | `scopes` | done |  |
| `Transports` | `transports` | `transports` | done |  |
| `Entry` | `Entry` | `Entry` | done |  |
| `Entry.ID` | `Entry.id` | `Entry.id` | done |  |
| `Entry.Kind` | `Entry.kind` | `Entry.kind` | done |  |
| `Entry.Scope` | `Entry.scope` | `Entry.scope` | done |  |
| `Entry.Path` | `Entry.path` | `Entry.path` | done |  |
| `Entry.Expected` | `Entry.expected` | `Entry.expected` | done |  |
| `Entry.Outcome` | `Entry.outcome` | `Entry.outcome` | done |  |
| `Entry.SpecMapRow` | `Entry.specMapRow` | `Entry.spec_map_row` | done |  |
| `Entry.DraftSection` | `Entry.draftSection` | `Entry.draft_section` | done |  |
| `Entry.Capabilities` | `Entry.capabilities` | `Entry.capabilities` | done |  |
| `Entry.ConformanceProfile` | `Entry.conformanceProfile` | `Entry.conformance_profile` | done |  |
| `Entry.Transport` | `Entry.transport` | `Entry.transport` | done |  |
| `Entry.Layer` | `Entry.layer` | `Entry.layer` | done |  |
| `Entry.ConformanceProfiles` | `Entry.conformanceProfiles` | `Entry.conformance_profiles` | done |  |
| `Entry.Transports` | `Entry.transports` | `Entry.transports` | done |  |
| `Kind` | `Kind` | `Kind` | done |  |
| `KindKey` | `Kind.KEY` | `Kind.KEY` | done |  |
| `KindVector` | `Kind.VECTOR` | `Kind.VECTOR` | done |  |
| `KindSchema` | `Kind.SCHEMA` | `Kind.SCHEMA` | done |  |
| `KindEvaluate` | `Kind.EVALUATE` | `Kind.EVALUATE` | done |  |
| `KindOutcomes` | `Kind.OUTCOMES` | `Kind.OUTCOMES` | done |  |
| `KindLearning` | `Kind.LEARNING` | `Kind.LEARNING` | done |  |
| `KindAdapterCase` | `Kind.ADAPTER_CASE` | `Kind.ADAPTER_CASE` | done |  |
| `KindAdapterAsset` | `Kind.ADAPTER_ASSET` | `Kind.ADAPTER_ASSET` | done |  |
| `KindSourceCase` | `Kind.SOURCE_CASE` | `Kind.SOURCE_CASE` | done |  |
| `KindProfileInvalid` | `Kind.PROFILE_INVALID` | `Kind.PROFILE_INVALID` | done |  |
| `KindTransport` | `Kind.TRANSPORT` | `Kind.TRANSPORT` | done |  |
| `KindMCP` | `Kind.MCP` | `Kind.MCP` | done |  |
| `KindProfile` | `Kind.PROFILE` | `Kind.PROFILE` | done |  |
| `Kind.HasExpected` | `Kind.hasExpected` | `Kind.has_expected` | done |  |
| `Kind.Known` | `Kind.known` | `Kind.known` | done |  |
| `Kind.RequiredScope` | `Kind.requiredScope` | `Kind.required_scope` | done |  |
| `Manifest` | `Manifest` | `Manifest` | done |  |
| `Manifest.Version` | `Manifest.version` | `Manifest.version` | done |  |
| `Manifest.Entries` | `Manifest.entries` | `Manifest.entries` | done |  |
| `Load` | `load` | `load` | done |  |
| `Parse` | `parse` | `parse` | done |  |
| `Manifest.Lookup` | `Manifest.lookup` | `Manifest.lookup` | done |  |
| `Manifest.Validate` | `Manifest.validate` | `Manifest.validate` | done |  |
| `Problem` | `Problem` | `Problem` | done |  |
| `Problem.Rule` | `Problem.rule` | `Problem.rule` | done |  |
| `Problem.Where` | `Problem.where` | `Problem.where` | done |  |
| `Problem.Msg` | `Problem.msg` | `Problem.msg` | done |  |
| `Problem.Err` | `Problem.err` | `Problem.err` | done |  |
| `Problem.String` | `Problem.toString` | `Problem.__str__` | done | Go `fmt.Stringer` |
| `Problems` | `Problems` | `Problems` | done |  |
| `Check` | `check` | `check` | done |  |
| `CheckSpecMap` | `checkSpecMap` | `check_spec_map` | done |  |
| `Completeness` | `completeness` | `completeness` | done |  |
| `Problems.Err` | `Problems.err` | `Problems.err` | done |  |
| `Problems.Error` | `Problems.message` | `Problems.__str__` | done | Go `error` interface |
| `Problems.Unwrap` | `Problems.cause` | `Problems.__cause__` | done | Go error chain |
| `Row` | `Row` | `Row` | done |  |
| `Row.ID` | `Row.id` | `Row.id` | done |  |
| `Row.Fixtures` | `Row.fixtures` | `Row.fixtures` | done |  |
| `Scope` | `Scope` | `Scope` | done |  |
| `ScopeCore` | `Scope.CORE` | `Scope.CORE` | done |  |
| `ScopeRunner` | `Scope.RUNNER` | `Scope.RUNNER` | done |  |
| `ScopeAdapter` | `Scope.ADAPTER` | `Scope.ADAPTER` | done |  |
| `Scope.Known` | `Scope.known` | `Scope.known` | done |  |
| `SpecMap` | `SpecMap` | `SpecMap` | done |  |
| `SpecMap.Rows` | `SpecMap.rows` | `SpecMap.rows` | done |  |
| `SpecMap.Groups` | `SpecMap.groups` | `SpecMap.groups` | done |  |

## `validator`

| Go symbol | TypeScript | Python | Status | Note |
|---|---|---|---|---|
| `CheckNativeAuthentication` | `CHECK_NATIVE_AUTHENTICATION` | `CHECK_NATIVE_AUTHENTICATION` | planned |  |
| `CheckAgentHolderBinding` | `CHECK_AGENT_HOLDER_BINDING` | `CHECK_AGENT_HOLDER_BINDING` | planned |  |
| `CheckContractValidity` | `CHECK_CONTRACT_VALIDITY` | `CHECK_CONTRACT_VALIDITY` | planned |  |
| `CheckNonce` | `CHECK_NONCE` | `CHECK_NONCE` | planned |  |
| `CheckOperationBinding` | `CHECK_OPERATION_BINDING` | `CHECK_OPERATION_BINDING` | planned |  |
| `CheckIntentBinding` | `CHECK_INTENT_BINDING` | `CHECK_INTENT_BINDING` | planned |  |
| `CheckProfileValidity` | `CHECK_PROFILE_VALIDITY` | `CHECK_PROFILE_VALIDITY` | planned |  |
| `CheckEvidenceValidity` | `CHECK_EVIDENCE_VALIDITY` | `CHECK_EVIDENCE_VALIDITY` | planned |  |
| `CheckReputationContext` | `CHECK_REPUTATION_CONTEXT` | `CHECK_REPUTATION_CONTEXT` | planned |  |
| `CheckSecurityHold` | `CHECK_SECURITY_HOLD` | `CHECK_SECURITY_HOLD` | planned |  |
| `CheckActivePolicy` | `CHECK_ACTIVE_POLICY` | `CHECK_ACTIVE_POLICY` | planned |  |
| `CheckReceiptStore` | `CHECK_RECEIPT_STORE` | `CHECK_RECEIPT_STORE` | planned |  |
| `CheckNativePrincipalBinding` | `CHECK_NATIVE_PRINCIPAL_BINDING` | `CHECK_NATIVE_PRINCIPAL_BINDING` | planned |  |
| `CheckSelectionConsistency` | `CHECK_SELECTION_CONSISTENCY` | `CHECK_SELECTION_CONSISTENCY` | planned |  |
| `ErrNotFound` | `ValidatorError` kind `NOT_FOUND` | `ValidatorError` kind `NOT_FOUND` | planned | sentinel error |
| `ErrTransition` | `ValidatorError` kind `TRANSITION` | `ValidatorError` kind `TRANSITION` | planned | sentinel error |
| `Decide` | `decide` | `decide` | planned |  |
| `ProblemOf` | `problemOf` | `problem_of` | planned |  |
| `ActivePolicy` | `ActivePolicy` | `ActivePolicy` | planned |  |
| `ActivePolicy.Policy` | `ActivePolicy.policy` | `ActivePolicy.policy` | planned |  |
| `ActivePolicy.ConservativeSet` | `ActivePolicy.conservativeSet` | `ActivePolicy.conservative_set` | planned |  |
| `ActivePolicy.ScoringPolicyRevisions` | `ActivePolicy.scoringPolicyRevisions` | `ActivePolicy.scoring_policy_revisions` | planned |  |
| `AttestationStore` | `AttestationStore` | `AttestationStore` | planned |  |
| `AttestationStore.Consume` | `AttestationStore.consume` | `AttestationStore.consume` | deviation | deviation: time precision, adapter calls |
| `Config` | `Config` | `Config` | planned |  |
| `Config.Audience` | `Config.audience` | `Config.audience` | planned |  |
| `Config.Realm` | `Config.realm` | `Config.realm` | planned |  |
| `Config.Issuer` | `Config.issuer` | `Config.issuer` | planned |  |
| `Config.SourceID` | `Config.sourceId` | `Config.source_id` | planned |  |
| `Config.Publishers` | `Config.publishers` | `Config.publishers` | planned |  |
| `Config.Issuers` | `Config.issuers` | `Config.issuers` | planned |  |
| `Config.ReputationServices` | `Config.reputationServices` | `Config.reputation_services` | planned |  |
| `Config.Algorithms` | `Config.algorithms` | `Config.algorithms` | planned |  |
| `Config.Skew` | `Config.skew` | `Config.skew` | deviation | deviation: time precision |
| `Config.Limits` | `Config.limits` | `Config.limits` | planned |  |
| `Config.EvaluationTime` | `Config.evaluationTime` | `Config.evaluation_time` | deviation | deviation: time precision |
| `Config.NativeMappings` | `Config.nativeMappings` | `Config.native_mappings` | planned |  |
| `Config.InstalledChecks` | `Config.installedChecks` | `Config.installed_checks` | planned |  |
| `Config.SupportedExtensions` | `Config.supportedExtensions` | `Config.supported_extensions` | planned |  |
| `ContextMapper` | `ContextMapper` | `ContextMapper` | planned |  |
| `ContextMapper.ReputationContext` | `ContextMapper.reputationContext` | `ContextMapper.reputation_context` | deviation | deviation: adapter calls |
| `ES256Signer` | `ES256Signer` | `ES256Signer` | planned |  |
| `ES256Signer.Kid` | `ES256Signer.kid` | `ES256Signer.kid` | planned |  |
| `ES256Signer.Key` | `ES256Signer.key` | `ES256Signer.key` | planned |  |
| `ES256Signer.SignAttestation` | `ES256Signer.signAttestation` | `ES256Signer.sign_attestation` | planned |  |
| `Ed25519Signer` | `Ed25519Signer` | `Ed25519Signer` | planned |  |
| `Ed25519Signer.Kid` | `Ed25519Signer.kid` | `Ed25519Signer.kid` | planned |  |
| `Ed25519Signer.Key` | `Ed25519Signer.key` | `Ed25519Signer.key` | planned |  |
| `Ed25519Signer.SignAttestation` | `Ed25519Signer.signAttestation` | `Ed25519Signer.sign_attestation` | planned |  |
| `Event` | `Event` | `Event` | planned |  |
| `EventPresented` | `Event.PRESENTED` | `Event.PRESENTED` | planned |  |
| `EventContractExp` | `Event.CONTRACT_EXP` | `Event.CONTRACT_EXP` | planned |  |
| `EventPassed` | `Event.PASSED` | `Event.PASSED` | planned |  |
| `EventFailed` | `Event.FAILED` | `Event.FAILED` | planned |  |
| `EventUnavailable` | `Event.UNAVAILABLE` | `Event.UNAVAILABLE` | planned |  |
| `EventCancelled` | `Event.CANCELLED` | `Event.CANCELLED` | planned |  |
| `EventDeadline` | `Event.DEADLINE` | `Event.DEADLINE` | planned |  |
| `EvidenceStatus` | `EvidenceStatus` | `EvidenceStatus` | planned |  |
| `EvidenceStatus.Revoked` | `EvidenceStatus.revoked` | `EvidenceStatus.revoked` | planned |  |
| `EvidenceStatus.CheckedAt` | `EvidenceStatus.checkedAt` | `EvidenceStatus.checked_at` | deviation | deviation: time precision |
| `EvidenceStatus.SourceID` | `EvidenceStatus.sourceId` | `EvidenceStatus.source_id` | planned |  |
| `Handoff` | `Handoff` | `Handoff` | planned |  |
| `Handoff.Validators` | `Handoff.validators` | `Handoff.validators` | planned |  |
| `Handoff.Audience` | `Handoff.audience` | `Handoff.audience` | planned |  |
| `Handoff.Realm` | `Handoff.realm` | `Handoff.realm` | planned |  |
| `Handoff.Algorithms` | `Handoff.algorithms` | `Handoff.algorithms` | planned |  |
| `Handoff.Skew` | `Handoff.skew` | `Handoff.skew` | deviation | deviation: time precision |
| `Handoff.Consumed` | `Handoff.consumed` | `Handoff.consumed` | planned |  |
| `Handoff.Holds` | `Handoff.holds` | `Handoff.holds` | planned |  |
| `Handoff.Accept` | `Handoff.accept` | `Handoff.accept` | deviation | deviation: time precision, adapter calls |
| `HoldStore` | `HoldStore` | `HoldStore` | planned |  |
| `HoldStore.Holds` | `HoldStore.holds` | `HoldStore.holds` | deviation | deviation: adapter calls |
| `Issuer` | `Issuer` | `Issuer` | planned |  |
| `Issuer.ID` | `Issuer.id` | `Issuer.id` | planned |  |
| `Issuer.Keys` | `Issuer.keys` | `Issuer.keys` | planned |  |
| `Issuer.ClaimPaths` | `Issuer.claimPaths` | `Issuer.claim_paths` | planned |  |
| `MemoryAttestations` | `MemoryAttestations` | `MemoryAttestations` | planned |  |
| `NewMemoryAttestations` | `new MemoryAttestations` | `MemoryAttestations(...)` | planned |  |
| `MemoryAttestations.Consume` | `MemoryAttestations.consume` | `MemoryAttestations.consume` | deviation | deviation: time precision, adapter calls |
| `MemoryReceipts` | `MemoryReceipts` | `MemoryReceipts` | planned |  |
| `NewMemoryReceipts` | `new MemoryReceipts` | `MemoryReceipts(...)` | planned |  |
| `MemoryReceipts.All` | `MemoryReceipts.all` | `MemoryReceipts.all` | planned |  |
| `MemoryReceipts.ByContract` | `MemoryReceipts.byContract` | `MemoryReceipts.by_contract` | deviation | deviation: adapter calls |
| `MemoryReceipts.Get` | `MemoryReceipts.get` | `MemoryReceipts.get` | deviation | deviation: adapter calls |
| `MemoryReceipts.Put` | `MemoryReceipts.put` | `MemoryReceipts.put` | deviation | deviation: adapter calls |
| `Native` | `Native` | `Native` | planned |  |
| `NativeMapping` | `NativeMapping` | `NativeMapping` | planned |  |
| `NativeMapping.Path` | `NativeMapping.path` | `NativeMapping.path` | planned |  |
| `NativeMapping.NativePath` | `NativeMapping.nativePath` | `NativeMapping.native_path` | planned |  |
| `NativeMapping.Source` | `NativeMapping.source` | `NativeMapping.source` | planned |  |
| `PolicyRegistry` | `PolicyRegistry` | `PolicyRegistry` | planned |  |
| `PolicyRegistry.Active` | `PolicyRegistry.active` | `PolicyRegistry.active` | deviation | deviation: adapter calls |
| `PolicyRegistry.Selection` | `PolicyRegistry.selection` | `PolicyRegistry.selection` | deviation | deviation: adapter calls |
| `ReceiptStore` | `ReceiptStore` | `ReceiptStore` | planned |  |
| `ReceiptStore.Put` | `ReceiptStore.put` | `ReceiptStore.put` | deviation | deviation: adapter calls |
| `ReceiptStore.Get` | `ReceiptStore.get` | `ReceiptStore.get` | deviation | deviation: adapter calls |
| `ReceiptStore.ByContract` | `ReceiptStore.byContract` | `ReceiptStore.by_contract` | deviation | deviation: adapter calls |
| `Request` | `Request` | `Request` | planned |  |
| `Request.Presentation` | `Request.presentation` | `Request.presentation` | planned |  |
| `Request.Operation` | `Request.operation` | `Request.operation` | planned |  |
| `Request.Principal` | `Request.principal` | `Request.principal` | planned |  |
| `Request.Transport` | `Request.transport` | `Request.transport` | planned |  |
| `Result` | `Result` | `Result` | planned |  |
| `Result.Receipt` | `Result.receipt` | `Result.receipt` | planned |  |
| `Result.Attestation` | `Result.attestation` | `Result.attestation` | planned |  |
| `Selection` | `Selection` | `Selection` | planned |  |
| `Selection.RecordRef` | `Selection.recordRef` | `Selection.record_ref` | planned |  |
| `Selection.Selector` | `Selection.selector` | `Selection.selector` | planned |  |
| `Selection.Current` | `Selection.current` | `Selection.current` | planned |  |
| `SelectionInput` | `SelectionInput` | `SelectionInput` | planned |  |
| `SelectionInput.Snapshot` | `SelectionInput.snapshot` | `SelectionInput.snapshot` | planned |  |
| `SelectionInput.Holds` | `SelectionInput.holds` | `SelectionInput.holds` | planned |  |
| `Selector` | `Selector` | `Selector` | planned |  |
| `Selector.Order` | `Selector.order` | `Selector.order` | planned |  |
| `Selector.Select` | `Selector.select` | `Selector.select` | planned |  |
| `Selector.Rules` | `Selector.rules` | `Selector.rules` | planned |  |
| `Selector.Checks` | `Selector.checks` | `Selector.checks` | planned |  |
| `Signer` | `Signer` | `Signer` | planned |  |
| `Signer.SignAttestation` | `Signer.signAttestation` | `Signer.sign_attestation` | planned |  |
| `SourceCapability` | `SourceCapability` | `SourceCapability` | planned |  |
| `SourceCapability.SourceID` | `SourceCapability.sourceId` | `SourceCapability.source_id` | planned |  |
| `SourceCapability.BestMaxAgeSeconds` | `SourceCapability.bestMaxAgeSeconds` | `SourceCapability.best_max_age_seconds` | planned |  |
| `SourceCapability.BestStatusMaxAgeSeconds` | `SourceCapability.bestStatusMaxAgeSeconds` | `SourceCapability.best_status_max_age_seconds` | planned |  |
| `SourceCapability.LiveCheck` | `SourceCapability.liveCheck` | `SourceCapability.live_check` | planned |  |
| `State` | `State` | `State` | planned |  |
| `StateContractIssued` | `State.CONTRACT_ISSUED` | `State.CONTRACT_ISSUED` | planned |  |
| `StateEvaluating` | `State.EVALUATING` | `State.EVALUATING` | planned |  |
| `StateSealedAdmissible` | `State.SEALED_ADMISSIBLE` | `State.SEALED_ADMISSIBLE` | planned |  |
| `StateSealedInadmissible` | `State.SEALED_INADMISSIBLE` | `State.SEALED_INADMISSIBLE` | planned |  |
| `StateSealedDeferred` | `State.SEALED_DEFERRED` | `State.SEALED_DEFERRED` | planned |  |
| `StateCancelled` | `State.CANCELLED` | `State.CANCELLED` | planned |  |
| `StateExpired` | `State.EXPIRED` | `State.EXPIRED` | planned |  |
| `Next` | `next` | `next` | planned |  |
| `State.Terminal` | `State.terminal` | `State.terminal` | planned |  |
| `StatusChecker` | `StatusChecker` | `StatusChecker` | planned |  |
| `StatusChecker.EvidenceStatus` | `StatusChecker.evidenceStatus` | `StatusChecker.evidence_status` | deviation | deviation: adapter calls |
| `Validator` | `Validator` | `Validator` | planned |  |
| `Validator.Config` | `Validator.config` | `Validator.config` | planned |  |
| `Validator.Native` | `Validator.native` | `Validator.native` | planned |  |
| `Validator.Replay` | `Validator.replay` | `Validator.replay` | planned |  |
| `Validator.Receipts` | `Validator.receipts` | `Validator.receipts` | planned |  |
| `Validator.Holds` | `Validator.holds` | `Validator.holds` | planned |  |
| `Validator.Policies` | `Validator.policies` | `Validator.policies` | planned |  |
| `Validator.Status` | `Validator.status` | `Validator.status` | planned |  |
| `Validator.Contexts` | `Validator.contexts` | `Validator.contexts` | planned |  |
| `Validator.Signer` | `Validator.signer` | `Validator.signer` | planned |  |
| `Validator.Clock` | `Validator.clock` | `Validator.clock` | planned |  |
| `Validator.Evaluate` | `Validator.evaluate` | `Validator.evaluate` | deviation | deviation: adapter calls |
