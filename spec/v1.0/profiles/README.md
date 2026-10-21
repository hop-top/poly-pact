# PACT integration profiles

This directory holds integration profiles. An integration profile states, for one native gateway or product, the exact PACT conformance claim and the evidence behind it: protected routes and actions, enforcement points, native dependencies, alternative paths, unsupported forms, identity mapping, source freshness, membership and status sources, attribute sources, residual limits, and negative fixtures. Profiles exist because the draft requires enforced gateways and adapters, and each claim needs to be scoped and shown path by path. The open finding G01 of the specification review asks for this: demonstrate that every claimed path is controlled and that bypass paths are closed, equivalently enforced, or explicitly outside the claim.

## Four meanings of profile

Four different things in this repository are called "profile". Use the names below. The sections after this one are about integration profiles; where they say "profile" without a qualifier, they mean an integration profile.

| Name | Meaning | Example path |
|---|---|---|
| AgentProfile | The data object of draft §8.1, always written "AgentProfile". | `spec/v1.0/draft.md`, Appendix B.1 |
| integration profile | The G01 template instance per native mechanism, `spec/v1.0/profiles/<mechanism>/profile.{md,json}`. The MCP adapter profile is an integration profile. | `spec/v1.0/profiles/mcp/profile.md` |
| transport profile | Draft §13.3: how PACT messages ride a channel other than the HTTPS baseline, `spec/v1.0/profiles/transport/<id>/`. | `spec/v1.0/profiles/transport/stdio-ipc/` |
| conformance profile | Draft §22.1: a named subset of roles and §22.2 rows, `spec/v1.0/profiles/conformance/<id>/`. The ids are `full` and `single-owner`. | `spec/v1.0/profiles/conformance/single-owner/` |

### Naming rule

The bare word "profile" is never a JSON key, directory name, or flag value for these concepts. The JSON keys are `agent_profile`, `conformance_profile`, `transport_profile`, and `integration_profile`. One documented exception: the runner flags `--profile` and `--transport` take a conformance profile id and a transport name respectively. The `profile` member of a `Presentation` (draft §11.2) already carries an AgentProfile on the wire; this rule does not rename it.

### Registry

[`registry.json`](registry.json) lists the conformance, transport, and integration profiles, and the source documents. It is an array of entries with the fields `kind` (`conformance`, `transport`, `integration`, or `source`, a membership or status source document that an integration profile's 8.1 row embeds through `source_document`), `id`, `version` (`"0.1"`), `doc` (the repo-relative path of the profile document), and `status` (`draft`). An adapter entry also records its `mapping_revision`; the MCP entry records `pact-mcp-1`. The file holds the entries `conformance/full`, `conformance/single-owner` and `transport/stdio-ipc`, and one `integration` entry for each integration profile of the index below, with the `mapping_revision` of its adapters: `abac`, `aws`, `basic`, `db`, `files`, `k8s`, `ldap`, `mcp`, `mtls`, `oauth`, `rebac` and `saml`. The `doc` path of the transport entry is the [`stdio-ipc` transport profile](transport/stdio-ipc/profile.md). The `doc` paths of the conformance entries point to documents that later changes add, so this README writes them as inline code, not links. Each later integration profile appends its own entry in the change that adds it. Parse the file with a strict JSON parser that rejects duplicate keys.

### Identifiers

A profile has no URI. It is identified by (kind, id, version), for example `conformance/single-owner` 0.1. The extension identifiers used in `extensions` objects (draft §21) are the first-party tokens `pact-conformance-profile-v1` and `pact-transport-profile-v1`, for the conformance-profile and transport-profile extensions respectively. They are named in the style of the draft's other baseline parts (`beta-decay-v1`, `pact-qualification-v1`, `execution-control-v1`). Identifiers beginning `pact-` are reserved for the specification. Every other extension identifier must be an HTTPS URI under the publisher's control. The normative sentence lands in draft §21 in a later change.

## Writing a profile

1. Copy [`TEMPLATE.md`](TEMPLATE.md) and name the copy after the gateway or product.
2. Fill all ten sections, including subsections 8.1 and 8.2 of section 8; each starts with a one-line "How to fill" note and the template ends with a filled mini-example for a fictional gateway.
3. Keep the profile language-neutral so adapter SDKs in other languages can reuse it and its fixtures.
4. Write paths to files that do not exist yet as inline code, not as links.
5. Add a row for the profile to the index below in the same change.
6. In the shared-account row of section 7, state the default of [`identity-mapping.md`](identity-mapping.md) §5 (not supported), or the reason for supporting shared accounts that IM-19 requires, with its primary source. A profile that authenticates no request itself states that it inherits the choice of the profile that does.

## Completeness

A profile is complete only when every one of the ten sections is filled. An incomplete profile cannot support an enforced-support claim (draft §4.4 and §22.1). An admission-only implementation describes itself as a partial role implementation, and observation-mode deployments disclose that native access is not conditioned on PACT admission.

## Machine-readable form

[`integration-profile.schema.json`](integration-profile.schema.json) is a JSON Schema (Draft 2020-12, no remote references) for the content of a profile. Its eleven top-level keys are all required and map to template sections 1 to 6 and 8 to 10, with section 8 split into three keys: `claim`, `protected_routes`, `enforcement_points`, `native_dependencies`, `bypass_paths`, `unsupported_forms`, `freshness`, `membership_sources`, `attribute_sources`, `residual_limits`, and `fixtures`. Every object is closed, so an unknown key is an error. Role names are the draft §22.1 names, function names are the draft §17.1 names, and components are `C01` to `C16`. A fixture `path` is relative to `spec/`. Three template spellings differ in the schema: the dispositions `equivalently-enforced` and `out-of-claim` are `equivalent` and `out_of_claim`, and an outage that ends in `DEFERRED` is `defer`. The profile header and section 7 (identity mapping) have no field yet and stay in the Markdown profile.

`membership_sources` is the machine-readable form of template subsection 8.1. Each entry names one native source of membership, role, or account-status facts and declares the `facts` it offers (`identity`, `groups`, `roles`, `account_state`), the `live_check` (`available`, and an `endpoint_class` when it is `true`), the `change_feed` (`mode` of `none`, `poll_delta`, or `push`, and a `mechanism` unless it is `none`), the `best_status_max_age_seconds` the integration can achieve, and the `value_semantics` (`authoritative_current` or `cached_snapshot`, draft §17.2). An entry with no live check is a cached snapshot with a bound of at least 1 second. An empty array is valid for an integration that reads no such fact; every profile that reads them fills the block. The template tables of 8.1 use the same snake_case spelling as the schema.

`attribute_sources` is the machine-readable form of template subsection 8.2. Each entry names one native source of subject, resource, or environment attributes that are not membership or account-status facts, and declares its `category` (`subject`, `resource`, or `environment`), the `attributes` it answers, and its `freshness`. `action` is not a category, because `OperationContext.action` carries the action. `attributes` lists one or more approved native paths of the installed mapping, each once; a path is a `/` followed by segments of letters, digits, `_`, `.`, and `-`, separated by `/`, such as `/subject/clearance`. `freshness` is the `source` of the `freshness` entry that bounds the source, spelled exactly as there. The array is required, and an empty array is valid for an integration that reads no such attribute. JSON Schema cannot check that `freshness` names an existing entry: the profile-validate lint, `pactconf profile validate`, enforces it. [`testdata/index.json`](testdata/index.json) also indexes one valid and five invalid attribute source blocks, which are validated against `$defs/attributeSource`.

In a profile's `profile.json`, `fixtures` lists only fixtures that exist on disk and are registered in [`spec/v1.0/fixtures/manifest.json`](../fixtures/manifest.json): the `id` of each entry is a manifest entry id and its `path` a file under `spec/`. A planned case is listed only in section 10 of the profile's Markdown file, under a "Planned" heading, and never in `fixtures`. The change that lands a profile's cases adds them to `fixtures` in the same change. The profile-validate lint enforces existence and registration strictly, with no exemption for planned cases.

The `claim` object has six required keys. Two of them name profiles, `conformance_profile` and `transport`, and both are arrays with at least one entry, even when the claim names a single profile. `conformance_profile` lists conformance profile ids (draft §22.1), which are the entries of kind `conformance` in [`registry.json`](registry.json): `full` and `single-owner`. `transport` lists the transport profiles the claim uses, each as an object such as `{"transport_profile": "https", "version": "0.1"}`. `transport_profile` is `https` (the baseline HTTPS binding, which has no registry entry) or `stdio-ipc` (draft §13.3), and `version` is `0.1`. A profile has no URI: it is identified by its kind, id, and version. `transport` is not `presentation_transports`, which lists `header`, `gateway-evaluate`, and `adapter-envelope`. [`testdata/index.json`](testdata/index.json) indexes one valid and six invalid claim blocks, with the failing keyword and location of each invalid one, for a validator to check against.

[`example.profile.json`](example.profile.json) fills the schema for the fictional gateway of the template's mini-example. Its `fixtures` array is empty: no registered fixture exercises the fictional gateway, so the eight fixture ids of the mini-example stay in section 10 of the template, under "Planned".

### Validating a profile

`pactconf profile validate`, the Go tool in `cli/pactconf` of the source repository, checks each file in three steps, and a step runs only when the one before it passed: a strict JSON parse, because a schema validator cannot see duplicate object keys; validation against the schema; and the profile-validate lint, which checks what the schema cannot express. Each failure is printed with the RFC 6901 JSON Pointer of its location, and the tool exits 1 when a file fails. After `make go-build`, from the repository root:

```sh
go/bin/pactconf profile validate spec/v1.0/profiles/example.profile.json spec/v1.0/profiles/*/profile.json
```

The lint applies these rules, by name, to a schema-valid profile. Text that is only white space counts as empty.

- `route-enforcement`: when `protected_routes` is not empty, `enforcement_points` has an entry for each of `authenticate_native`, `map_operation`, and `authorize_native`.
- `bypass-control` and `bypass-evidence`: every `bypass_paths` entry has a `control` and non-empty `evidence`.
- `adapters` and `mapping-revision`: `claim.adapters` is not empty, and each entry has a non-empty `mapping_revision`.
- `unsupported-forms`: `unsupported_forms` is not empty, and neither is any entry.
- `fixture-path` and `fixture-id`: every `fixtures` entry has a `path` that names an existing file or directory inside `spec/`, and an `id` that is an entry id of the manifest.
- `freshness-coverage`: when `native_dependencies` lists `C02` or `C05`, `freshness` has at least one row. A freshness row names no component, so the lint cannot tie a row to a component.
- `attribute-freshness`: every `attribute_sources` entry's `freshness` is the `source` of a `freshness` entry, spelled exactly as there.

[`../fixtures/profiles/index.json`](../fixtures/profiles/index.json) indexes invalid profiles, each registered in the manifest with kind `profile-invalid`, and the errors each must fail with.

Any Draft 2020-12 validator can run the schema step alone, for example `check-jsonschema --schemafile spec/v1.0/profiles/integration-profile.schema.json spec/v1.0/profiles/example.profile.json`, which prints `ok -- validation done` for a valid file. `check-jsonschema --check-metaschema spec/v1.0/profiles/integration-profile.schema.json` checks the schema itself.

## Index

The table lists every integration profile in this directory, with the claim its section 1 states.

| Profile | Gateway or product | Deployment form (draft §4.4) | Roles claimed | Mode | Status |
|---|---|---|---|---|---|
| [abac](abac/profile.md) | Document gateway whose policy decisions come from Open Policy Agent through its REST Data API (sample I11) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [aws](aws/profile.md) | Custom API on Amazon API Gateway (HTTP API) with AWS IAM authorization, whose Lambda integration hosts the adapter and validator; the execution role acts downstream as a distinct actor (sample I09) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [basic](basic/profile.md) | HTTP Basic authentication adapter in front of a legacy invoice API (sample I01) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [db](db/profile.md) | Database broker that runs fixed, parameterized queries on PostgreSQL 16 under a dedicated login role per principal, with the database's privileges and row-level security deciding the rows (sample I13) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [files](files/profile.md) | File broker on a Windows file server, opening local NTFS files under the requesting user's impersonated context (sample I04) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [files, Unix](files/unix.md) | File broker on Unix | none | none | none | stub; makes no claim |
| [files, SMB](files/smb.md) | File broker over SMB | none | none | none | stub; makes no claim |
| [k8s](k8s/profile.md) | Operations gateway that authenticates agents by Kubernetes service-account tokens and executes admitted operations under the agent's registered service account (sample I10) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [ldap](ldap/profile.md) | LDAP-backed authentication, group membership, and account state (sample I06) | in-gateway | `PACT Gateway 0.1`, for the adapter capabilities of draft §17.1 only | `enforced` | draft; negative cases planned |
| [mcp](mcp/profile.md) | MCP adapter | not yet stated | not yet stated | not yet stated | draft; work in progress: pinned references and method classification only |
| [mtls](mtls/profile.md) | Gateway that authenticates machine clients with X.509 client certificates over mutual TLS (sample I07) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [oauth](oauth/profile.md) | Gateway that authenticates agent requests with OAuth 2.0 bearer access tokens: opaque tokens by RFC 7662 introspection (sample I03) and Microsoft Entra ID v2.0 access tokens (samples I02, I14), and Google ID tokens of one pinned hosted domain | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [rebac](rebac/profile.md) | Gateway whose native decision is a Check against an OpenFGA relationship store (sample I12) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; negative cases planned |
| [saml](saml/profile.md) | SAML 2.0 service provider session to agent broker (sample I05) | in-gateway | `PACT Gateway 0.1`, `PACT Validator 0.1` | `enforced` | draft; work in progress, negative cases planned |

Four cross-cutting profile documents state rules that the integration profiles cite: [freshness.md](freshness.md) (source freshness and rechecks), [identity-mapping.md](identity-mapping.md) (native identity to enrolled agent and key), [request-binding.md](request-binding.md) (request binding and native translation), and [multi-operation.md](multi-operation.md) (task ledger, budgets, retries, and side effects).
