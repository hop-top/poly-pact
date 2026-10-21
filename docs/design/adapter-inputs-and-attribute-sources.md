# Adapter inputs, decision provenance, attribute sources, and planned fixtures

Status: approved on 2026-10-16.

## 1. Problem

The seven adapter profiles on main (basic, saml, mtls, files, abac, rebac, ldap) each worked around the same gaps:

1. `adapter.Decision` carries no provenance (no source, decision record, time, or policy revision), and the ABAC profile believed `Obligation` cannot carry a type and parameters.
2. `ReadNativeClaim` receives only the principal, so resource-scoped facts (classification, owning department) and task-scoped facts (the SAML `TaskGrant`) cannot be read. The ABAC profile also asked for a principal in `CheckContext` and the contract in `AuthorizeNative`.
3. The integration-profile schema can describe membership and account-status sources only; it has no place for clearance, device posture, classification, network zone, or time.
4. `profile.json` `fixtures[]` is used two ways: five profiles leave it empty, files and ldap list planned paths that do not exist.

Constraints: stay faithful to draft 17.1 (behavioral contracts; native authorization is final and independent of PACT; PACT never interprets native policy). Pre-release: breaking Go changes are acceptable while the only consumers are in this repo (`adaptertest`, `adapters/memory`, `adapters/internal/broken`). The language-neutral case files and the seven profile files must stay valid.

Success: the interface-gap notes in the abac, saml and basic profiles are replaced by the real mechanism; suite, memory and broken are updated with mutation proof; every profile validates; `fixtures[]` means one thing everywhere.

## 2. Decisions

### D1. Decision provenance; Obligation unchanged

`adapter.Decision` gains four fields, mirroring `NativeClaim` and `CheckOutcome` and draft A.2 ("`source_ref` identifies its immutable decision/observation record"):

| Field | Type | Meaning |
|---|---|---|
| `SourceID` | string | The configured native policy source that decided. Required (non-empty) on every returned Decision. |
| `SourceRef` | string | Immutable native decision record (for OPA, the `decision_id`); empty when the source gives none. |
| `DecidedAt` | time.Time | When the source decided; zero when it gives none. Never later than now plus the baseline skew. |
| `PolicyRevision` | string | Revision of the native policy that produced the decision; empty when the source reports none. |

`Obligation{ID, Attributes}` keeps its shape. Its doc comment is clarified: `ID` is the obligation type as the native policy names it, `Attributes` its parameters; PACT defines no obligation types and never interprets them; the gateway enforces them (draft 17.3 assigns row and field restrictions to the gateway). A profile that relies on particular obligation types names them (ABAC: `filter_fields`, `redact`, `watermark`). No draft change.

### D2. Function inputs

- `ReadNativeClaim(ctx, nativePath string, c ClaimContext) (NativeClaim, error)` replaces the `Principal` parameter with:

  ```go
  // ClaimContext is the evaluation context a native claim is read in (draft 17.1:
  // "approved native path and context").
  type ClaimContext struct {
      Principal Principal             // the authenticated principal
      Intent    core.Intent           // the declared intent; Intent.TaskID scopes task facts
      Operation core.OperationContext // the actual operation; Operation.Resources scopes resource facts
  }
  ```

  The approved mapping decides which part a path uses (subject paths use `Principal`, resource paths use `Operation.Resources`, task paths use `Intent.TaskID`). An adapter reads nothing else from the request. No draft change: 17.1 already names "context".
- `CheckContext` takes an `adapter.CheckInput`: the authenticated `Principal` with its attributes, the `AgentBinding` the validator verified, the intent, the operation and the evidence references (draft 17.1 as amended, decided 2026-10-18). Decided after the ABAC check needed `device_id` and `peer_address` and the SAML delegation check needed the grantee: the scope comparison of 17.3.1 on agent and principal was not evaluable from the earlier inputs. A check compares against these inputs and never against the operation's text, the presentation or the profile.
- `AuthorizeNative` is unchanged. Draft 17.1 gives it the original principal and the actual operation; native authorization never sees the PACT contract. The ABAC policy-version binding moves to the caller: the gateway compares `Decision.PolicyRevision` with the contract's installed check version and, on mismatch, does not use the decision and answers `REQUIREMENTS_CHANGED` (obtain a new contract). This is profile text in `abac/profile.md`, not draft text.

Case-file contract (language-neutral, additive):

- `call` for `read_native_claim` gains optional `intent` and `operation` objects (same shapes as in the draft; `operation` already exists for `authorize_native` cases).
- `native_state.claims[]` entries gain optional `resource` and `task_id` keys; an entry with either key matches only a call whose operation lists that resource or whose intent carries that task.
- `native_state.policy[]` entries gain optional `source_id`, `source_ref`, `decided_at`, `policy_revision`; `expect.decision` may assert them.
- Existing cases stay valid unchanged except where a new required check (Decision.SourceID) needs a `source_id` in their `policy[]` entries.

### D3. `attribute_sources`

A new top-level array in `spec/v1.0/profiles/integration-profile.schema.json`, REQUIRED (an empty array is valid), matching how `membership_sources` is required. `membership_sources` is unchanged and stays about membership and account status.

```json
"attributeSource": {
  "type": "object", "additionalProperties": false,
  "required": ["source", "category", "attributes", "freshness"],
  "properties": {
    "source":     {"$ref": "#/$defs/text"},
    "category":   {"enum": ["subject", "resource", "environment"]},
    "attributes": {"type": "array", "minItems": 1, "uniqueItems": true,
                   "items": {"description": "approved native path", "type": "string", "pattern": "^/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$"}},
    "freshness":  {"description": "the `source` of the matching freshness entry", "$ref": "#/$defs/text"}
  }
}
```

- Categories follow the OPA input shape; `action` is excluded because `OperationContext.action` carries it.
- ABAC mapping: clearance and department are `subject`; classification and owning department are `resource`; device posture, network zone and time are `environment`. Time and gateway-observed network zone use a freshness entry for the gateway itself (`observation: authoritative`, `max_age_seconds: 0`, `status_max_age_seconds: 0`, `outage: defer`).
- JSON Schema cannot check that `freshness` names an existing entry; the profile-validate lint (`pactconf profile validate`) does.
- `TEMPLATE.md` section 8 gains an "Attribute sources" subsection; `README.md` documents the field; `example.profile.json` and the six non-ABAC profiles gain `"attribute_sources": []`; ABAC gets its real entries.

### D4. Planned fixtures convention

`fixtures[]` in `profile.json` lists only fixtures that exist on disk and are registered in `spec/v1.0/fixtures/manifest.json`, which is what the schema's `fixtureRef` already says. Planned cases are listed only in `profile.md` section 10 under a "Planned" heading. The conformance task that lands a profile's cases adds them to `fixtures[]` in the same change. `files` and `ldap` move their planned entries out of `profile.json` (their section 10 already lists them). The profile-validate lint enforces existence strictly, with no planned exemption.

Rejected alternative: a `status: planned` marker on `fixtureRef`. It admits dangling ids into a machine-readable claim and needs exemption logic in every consumer.

## 3. Plan

Two tasks, run in parallel; then the held suite tasks resume.

**Task A — adapter inputs and decision provenance (go).** Branch `feat/adapter-inputs`.
- `go/adapter`: `ClaimContext`; `ReadNativeClaim` signature; `Decision` fields; doc comments for `Obligation`, `CheckContext`, `AuthorizeNative`; `CheckInput`, the `ContextChecker` signature and `installed.Check.Consult` (2026-10-18); tests that pin the new shapes.
- `go/adapter/adaptertest`: claim calls pass `ClaimContext`; case loader reads the optional `call.intent`/`call.operation`, `claims[].resource`/`task_id`, `policy[]` provenance; a check that every returned Decision has a non-empty `SourceID` and a `DecidedAt` not later than now plus skew.
- `go/adapters/memory`: resource- and task-scoped claims; Decision provenance from `policy[]`.
- `go/adapters/internal/broken`: new defects, each failing the cases it targets: claim ignores the resource scope, claim ignores the task scope, Decision without `SourceID`, Decision `DecidedAt` in the future. Every existing invariant holds (each defect fails its cases; all defects fail every case; a case no defect targets fails its own test).
- New `_common` cases only where needed to pin the new behaviour (resource-scoped claim, task-scoped claim, decision provenance); manifest updated, sorted, unique.
- Profile docs: replace the interface-gap notes in `abac`, `saml` and `basic` `profile.md` with the real mechanism; in `abac`, describe the caller-side `PolicyRevision` comparison. Do not touch their `profile.json` (task B owns those).
- Commit this spec to `docs/design/adapter-inputs-and-attribute-sources.md`.
- Acceptance: `go -C go test -count=1 -race ./...` green; gofmt, vet (also GOOS=windows), golangci-lint clean; mutation check (each new rule broken in a targeted way makes a test fail); `make spec-manifest spec-links` green.

**Task B — attribute sources and the fixtures convention (schema).** Branch `docs/attribute-sources`.
- Schema: `attributeSource` and the required top-level `attribute_sources`.
- `spec/v1.0/profiles/testdata`: valid and invalid blocks (missing category, unknown category, empty attributes, non-path attribute, unknown key) with `index.json` entries.
- `TEMPLATE.md` section 8 subsection; `README.md` field documentation, plus the D4 convention stated next to `fixtures`.
- All eight profile files (`example.profile.json` and the seven profiles): add `attribute_sources` (`[]` except ABAC); ABAC moves clearance, department, device, classification, network zone and time into `attribute_sources` and updates its `profile.md` sections 4 and 8 to match; `files` and `ldap` empty `fixtures[]` and keep the cases under section 10 "Planned".
- Acceptance: every profile validates with python3 jsonschema (duplicate-key strict); each invalid testdata block fails for its named reason; schema mutation check (drop `required`, the category enum, `minItems`, `additionalProperties: false`: each makes testdata fail); `make spec-validate spec-links` green; `go -C go test -count=1 ./...` green.

Conflict boundary: task A edits `abac/profile.md` only in its interface-gap passages; task B edits `abac/profile.md` only in sections 4 and 8 and owns every `profile.json`.

After A merges, the held work on the identity fixtures and the freshness fixtures resumes on top of it. After B merges, the profile-validate lint can start, with D4's strict rule.
