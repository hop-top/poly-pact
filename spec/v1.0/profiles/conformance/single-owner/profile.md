# Conformance profile single-owner 0.1

This document defines the conformance profile `conformance/single-owner`, version `0.1`, of draft Section 22.1 ([`../../../draft.md`](../../../draft.md)). A deployment under this profile has one owner, one environment and one realm, and runs the Holder, Gateway and Validator roles without the Reputation and Learning roles. The profile is listed in [`../../registry.json`](../../registry.json) as the entry of kind `conformance` and id `single-owner`. Its machine-readable form is [`profile.json`](profile.json).

The name is single-owner, not "lite". The profile weakens no security invariant of draft Section 5 and no requirement of the roles it keeps. What it removes is the reputation, learning and multi-party trust machinery, and for each removed requirement it names what replaces it and the test that shows the replacement is no weaker (section 7). A conformance profile narrows scope; it is not permission to weaken a normative requirement (draft Section 23).

Where this document and the draft differ, the draft governs. Requirement ids of the form `SO-<AREA>-<n>` label each MUST of this document; the Fixture index at the end maps each one to the fixtures that test it.

Sections that later changes add to this document: the static policy constants, owner-managed holds, receipts and audit-only outcomes (referred to below as "section Static policy and audit"), and the applicability matrix of draft Section 22.2 (`applicability.json` in this directory, referred to below as "the applicability matrix").

## 1. Definition

A deployment is a single-owner deployment exactly when all five conditions below hold. They are conjunctive. Each is checked by the conformance runner against the trusted configuration of the case, `config.json` (draft Section 4.2; [`../../../fixtures/README.md`](../../../fixtures/README.md), sections config.json and config.json additions), over three of its members: `owner`, `trust` and `validator.iss`. A case run under this profile whose `config.json` has no `owner` member, or whose `owner` breaks a condition, does not hold a single-owner claim, and the run fails.

| Id | Condition | Predicate over `config.json` |
|---|---|---|
| C1 | Exactly one owner trust root. | `owner.owner_issuers` is not empty. The `iss` of every `trust` record whose `role` is `requirement-publisher`, `validator`, `enrollment-authority` or `hold-authority` is listed in `owner.owner_issuers`, and so is `validator.iss`. The `iss` of every `trust` record of role `issuer` is listed in `owner.owner_issuers`, or that record is listed, by `iss`, in `owner.evidence_issuers` with `owner_trusted` `true` and with every one of its `claim_paths`. |
| C2 | Exactly one environment. | `owner.environment_ids` has exactly one entry, and it equals `gateway.environment_id`. |
| C3 | Exactly one realm. | `owner.realms` has exactly one entry, and its `tenant_id` and `environment_id` equal `gateway.tenant_id` and `gateway.environment_id`. |
| C4 | Every agent enrollment was made by the owner. | `owner.self_registration` is `false`, and the `enrolled_by` of every entry of `owner.enrollments` is listed in `owner.owner_issuers` and is the `iss` of a `trust` record of role `enrollment-authority`. |
| C5 | Approval issuers are owner issuers. | Every issuer that may issue evidence of `kind` `approval` (draft Section 8.3) is listed in `owner.owner_issuers`. The configuration carries no evidence kinds, so the runner also checks the condition at evaluation: evidence of kind `approval` whose `iss` is not listed in `owner.owner_issuers` is rejected, whatever `owner.evidence_issuers` lists. |

SO-DEF-1. A deployment that describes itself as single-owner MUST satisfy C1 to C5.

SO-DEF-2. Evidence issuers other than the owner MUST be listed one by one in `owner.evidence_issuers`, each with the claim paths it may assert and `owner_trusted` `true`. Evidence from any other issuer, or for a claim path its entry does not list, is rejected, as draft Section 22.2 row 2 requires (valid evidence from an issuer unauthorized for the claim path).

SO-DEF-3. Evidence of kind `approval` MUST be issued by an issuer listed in `owner.owner_issuers` (C5).

SO-DEF-4. The enrollment of every agent MUST have been made by the owner, through the native administrative enrollment of draft Section 6.1. Self-registration is off (C4).

The runner names the members above with the shapes that the fixtures README defines for `config.json` (`owner` and its members) and that [`../../../fixtures/vectors/jws/README.md`](../../../fixtures/vectors/jws/README.md) defines for the signer roles, including `enrollment-authority` and `hold-authority`.

## 2. Role map

| Role (draft Section 22.1) | Under single-owner |
|---|---|
| PACT Holder 0.1 | Mandatory. |
| PACT Gateway 0.1 | Mandatory. |
| PACT Validator 0.1 | Mandatory. |
| PACT Reputation 0.1 | Absent. |
| PACT Learning 0.1 | Absent. |

Holder, Gateway and Validator MAY be colocated in one process (draft Section 4.1); role separation and authority restrictions still apply when they are. The roles a single-owner deployment claims are the five roles of draft Section 22.1 minus the `omitted_roles` of its declaration (section 3): Holder, Gateway and Validator.

SO-ROLE-1. Absent means absent. A single-owner deployment MUST NOT run any part of the Reputation or Learning role, in `enforced` or in `observe` mode: no reputation observation mode, no scoring, no reputation snapshot, no learning policy, no learning artifact and no learning event. Reputation does not start in observation under this profile. An outcome the gateway records is audit data only (section Static policy and audit) and is never a reputation input.

SO-ROLE-2. The trusted configuration MUST NOT name a reputation service, a learning controller or a learning policy authority: no `trust` record of `config.json` has the `role` `reputation-service`, `learning-controller` or `policy-authority`.

Deployment form and conformance profile are independent (draft Section 4.4): an in-gateway or sidecar deployment may be single-owner. Observation is a mode, not a profile.

SO-ROLE-3. In `observe` mode, every record of a single-owner deployment MUST declare observation mode (draft Section 4.4), and an observed admission is never counted as an enforced one.

## 3. Disclosure

A single-owner deployment declares itself with the first-party extension `pact-conformance-profile-v1` (draft Section 21). Its value is a `ConformanceDeclaration`, the payload definition `$defs/ConformanceDeclaration` of [`../../../schemas/pact.schema.json`](../../../schemas/pact.schema.json) (draft Appendix A.3):

```json
{
  "conformance_profile": "single-owner",
  "version": "0.1",
  "omitted_roles": ["reputation", "learning"],
  "owner": "https://owner.example/issuer"
}
```

`owner` is the issuer URI of the owner trust root, and it is listed in `owner.owner_issuers` of the trusted configuration. `omitted_roles` is exactly `reputation` and `learning`; the schema rejects any other role in it, and a declaration of `full` omits none (draft Appendix A.2).

SO-DISC-1. The declaration MUST appear in the gateway metadata, both as the key `pact-conformance-profile-v1` of `extensions` and as an entry of `extensions_supported`; in the `extensions` of every `RequirementContract` the gateway issues; and in the `extensions` of every `AdmissionAttestation` (draft Section 21). Its value MUST validate against `ConformanceDeclaration`, with `conformance_profile` `single-owner`, `version` `0.1`, `omitted_roles` `reputation` and `learning`, and `owner` listed in `owner.owner_issuers`.

SO-DISC-2. A gateway configured as single-owner MUST NOT issue a requirement contract without the declaration. A contract without it, presented to a single-owner gateway, fails `contract-validity` with reason code `CONTEXT_MISMATCH` (draft Sections 11.3, step 3 and 12.1).

SO-DISC-3. The three copies MUST be equal as JSON data. A contract whose declaration differs from the gateway metadata's fails `contract-validity` with `CONTEXT_MISMATCH`; an attestation whose declaration differs from the contract's is rejected at handoff with `CONTEXT_MISMATCH` (draft Section 11.5).

SO-DISC-4. A holder whose policy requires another conformance profile MUST refuse a contract that declares single-owner, and present nothing under it. A holder that does not support the extension defers, as draft Section 21 states.

SO-DISC-5. A single-owner deployment MUST describe itself as single-owner and MUST NOT describe itself as a full PACT deployment (draft Section 22.1).

### 3.1 Endpoints of the omitted roles

The gateway metadata schema requires the `reputation_query`, `learning_artifacts` and `learning_events` endpoints of draft Section 13.2 in the HTTPS binding. A single-owner deployment over `https` still lists them, and each answers as below. No schema change is made for this profile.

SO-END-1. Every request to the reputation query, learning artifacts or learning events endpoint MUST be answered with an RFC 9457 problem whose `code` is `UNSUPPORTED_REQUIREMENT` and whose `status` is 422 (draft Section 13.4), whether the request is authenticated, signed or valid, and MUST change no state: no snapshot is issued, and no artifact, event or policy is recorded.

SO-END-2. A signed `LearningPolicy`, `LearningArtifact` or `LearningEvent` offered to a single-owner deployment on any operation MUST be rejected with `UNSUPPORTED_REQUIREMENT` and MUST change no state.

Over a transport profile (draft Section 13.3.1), the same rules apply to the transport-neutral operation that profile maps each of those rows to.

## 4. Application of the draft

| Draft section | Under single-owner |
|---|---|
| 9.4 Base and adaptive requirements | Exactly one requirement set, `static`. It is the conservative set and the only permitted set, so it includes the base requirements, as every permitted set must. `selected_set` is `static` in every contract. No set is selected from reputation or learning input, so `selection-consistency-v1` is never required. The contract still carries `learning_policy_digest` and `learning_artifact_digest`; their values are profile constants (section Static policy and audit). |
| 11.3 step 9 Reputation snapshot | Replaced: a presentation that carries a reputation snapshot is rejected (SO-PROH-5). No `reputation-context` check is recorded, since no snapshot is presented (draft Section 12.1). The `security-hold` check stays mandatory. |
| 13.2 Baseline endpoints | Unchanged except for the endpoints of the omitted roles (section 3.1). |
| 14 Outcome evidence and feedback | Outcomes are audit-only: the gateway records admission and authorization outcomes (draft Section 14.1) in an audit log that has no qualification state and feeds no score (section Static policy and audit). |
| 15 Contextual reputation; 16 Continuous and autonomous learning | Not required (draft Sections 15.1 and 16.1, as revised; draft Section 22.1). This profile defines their replacements (section 7). |
| 17.1 Required adapter capabilities | `record_outcome` records audit data only. `read_native_claim` has no approved mapping for `/attributes/reputation` or a descendant, so it returns no value for such a path. |
| Appendix A, `GatewayMetadata` | The declaration in `extensions` and `extensions_supported`; all seven endpoints listed over `https`. No schema change. |

SO-APP-1. A requirement publisher under this profile MUST NOT issue a contract whose `selected_set` is not `static`, or that contains a field rule on `/attributes/reputation` or a descendant. A validator that receives such a contract does not admit it: its rules are not the authorized rules of the static set (draft Section 11.3, step 3), and the decision follows from draft Section 11.4.

## 5. Prohibitions

SO-PROH-1. No third-party authority. A single-owner deployment MUST NOT accept evidence from an issuer outside `owner.owner_issuers` unless that issuer is owner-trusted for that claim path (SO-DEF-2).

SO-PROH-2. No federation. A single-owner deployment MUST NOT accept native authority from another environment; draft Section 21 already defines no federation, and C2 and C3 leave a single-owner deployment no second environment or realm.

SO-PROH-3. No cross-tenant evidence. Evidence whose `tenant_id` or `environment_id` is not the realm of `owner.realms` MUST be rejected (`CONTEXT_MISMATCH`, draft Section 22.2 row 4).

SO-PROH-4. No acting as an issuer for others. The gateway MUST NOT issue evidence, a contract or an attestation whose audience is not itself, or whose environment is not its own; such a request is refused with `CONTEXT_MISMATCH` and nothing is signed.

SO-PROH-5. No reputation or learning input. A reputation snapshot in a presentation MUST be rejected with `INVALID_MESSAGE`, and a learning policy, learning artifact or learning event MUST NOT be accepted (SO-END-1, SO-END-2).

SO-PROH-6. No self-asserted trust upgrade. An agent profile, a presentation, an evidence artifact, a discovery response or any other message MUST NOT change the conformance profile, the owner trust root or the trust records of a single-owner deployment (draft Section 4.2). Only the owner changes them, through the native administrative controls, as section 6 describes.

SO-PROH-7. No trust from new keys. An unknown agent MUST NOT obtain a contract, an enrollment or a trusted status by creating keys (draft Section 6.1): its contract request is refused with `INVALID_PROOF` (draft Section 9.1).

## 6. Upgrade and downgrade

A single-owner deployment can become a full deployment without enrolling its agents again.

SO-UPG-1. An upgrade to `full` MUST preserve each agent's `agent_id`, `holder_jkt` and operator binding, the enrollment registry and the stored receipts. An agent enrolled before the upgrade is admitted after it under a `full` contract with no new enrollment.

The upgrade steps, in order:

1. Publish a signed learning policy in `observe` mode whose `conservative_set` is `static`, the static set id.
2. Stand up the Reputation role.
3. Replace the declaration with one of `conformance_profile` `full`, which omits no role, in the gateway metadata, and issue only contracts that carry it.
4. Import the audit log, if at all, only through the historical-import process of draft Section 14.3.

SO-UPG-2. Audit entries recorded under single-owner MUST enter reputation only through the historical-import process of draft Section 14.3, with separate provenance. They give no automatic reputation credit.

SO-UPG-3. A downgrade from `full` to single-owner MUST: make the single-owner declaration present in every copy of section 3; make the endpoints of the omitted roles answer as section 3.1 states; and reject every outstanding reputation snapshot (SO-PROH-5).

## 7. Replacement table

Each requirement this profile replaces or narrows, the equivalent that stands in for it, and the negative test that shows the equivalent is no weaker. The row-by-row classification of draft Section 22.2 is the applicability matrix.

| Requirement (draft) | Replaced or narrowed by | Negative test |
|---|---|---|
| 4.2 Trusted reputation services, outcome reporters and learning controllers | None configured (SO-ROLE-2); one owner trust root (C1). | `profiles/single-owner/so-third-party-issuer`, `profiles/single-owner/so-two-environments-config` |
| 6.4 Reputation history across rotation | No reputation history exists; a rotated key inherits nothing. | `profiles/single-owner/so-reputation-query` |
| 9.4 Set selection from learning policy and reputation | One static set; no reputation rule in a contract (SO-APP-1). | `profiles/single-owner/so-reputation-rule-in-contract`, `profiles/single-owner/so-no-reputation-after-7000` |
| 11.3 step 9 Snapshot verification | Every snapshot rejected (SO-PROH-5). | `profiles/single-owner/so-presentation-with-snapshot` |
| 13.2 Reputation query endpoint | Answers 422 `UNSUPPORTED_REQUIREMENT`, no state change (SO-END-1). | `profiles/single-owner/so-reputation-query` |
| 13.2 Learning artifacts and events endpoints | Answer 422 `UNSUPPORTED_REQUIREMENT`, no state change (SO-END-1). | `profiles/single-owner/so-learning-artifact-submit`, `profiles/single-owner/so-learning-event-submit` |
| 14.3 Qualification and scoring of outcomes | Audit-only outcomes; 7000 admissions leave no snapshot and an identical contract. | `profiles/single-owner/so-no-reputation-after-7000` |
| 15.4 Security holds from the reputation service | Owner-managed persistent holds; only the owner sets or clears one. | `profiles/single-owner/so-hold-persist`, `profiles/single-owner/so-hold-clear-owner-only` |
| 16.2 Learning policy | No learning policy accepted (SO-END-2). | `profiles/single-owner/so-learning-policy-submit` |
| 16.5 Rollback invalidates contracts | A change of the owner's static policy revision invalidates outstanding contracts (`REQUIREMENTS_CHANGED`); holds persist. | `profiles/single-owner/so-policy-revision-change` |
| 17.1 `record_outcome`, `read_native_claim` on reputation | Audit only; no reputation mapping (section 4). | `profiles/single-owner/so-reputation-rule-in-contract` |
| 22.1 Declared omission | Declaration in all three copies, equal, never described as full (SO-DISC-1 to SO-DISC-5). | `profiles/single-owner/so-missing-disclosure`, `profiles/single-owner/so-disclosure-mismatch`, `profiles/single-owner/so-full-claim-with-omitted-roles` |

## 8. profile.json

[`profile.json`](profile.json) is the machine-readable form of sections 1 to 3. No JSON Schema for a conformance profile file exists yet: it is checked by a strict JSON parse (draft Section 7.1) and by comparing its `kind`, `id`, `version` and `doc` with the entry of [`../../registry.json`](../../registry.json) of the same kind and id. Its members:

| Member | Content |
|---|---|
| `kind`, `id`, `version`, `doc` | The registry entry: `conformance`, `single-owner`, `0.1`, and the path of this document. |
| `roles` | `mandatory` and `absent`, by the role tokens of `ConformanceDeclaration.omitted_roles` and their counterparts `holder`, `gateway`, `validator`; and `colocation_allowed`. |
| `constraints` | C1 to C5 and SO-ROLE-2 as predicates over `config.json`, below. |
| `extension` | The extension identifier, the reference of its payload definition, the fixed members of the declaration value (`owner_member_of` points to the `config.json` array that lists its `owner`), where it appears, and the error when copies differ or the contract lacks the declaration. |
| `endpoints` | The behaviour of each endpoint of draft Section 13.2 under the profile. |
| `applicability` | The path of the applicability matrix, relative to this directory. |

A predicate is an object with an `op` and JSON Pointers (RFC 6901) into `config.json`; inside `each`, `where` and `require`, pointers are relative to the array element. The ops:

| `op` | Holds when |
|---|---|
| `non_empty` | The array at `path` has at least one entry. |
| `count` | The array at `path` has exactly `equals` entries. |
| `equal` | The value at `path` equals the value at `to` (a pointer into `config.json`), as JSON data. |
| `const` | The value at `path` equals `value`. |
| `member_of` | The value at `path` is an entry of the array at `set` (a pointer into `config.json`). |
| `in` | The value at `path` is an entry of `values`. |
| `not` | The predicate `predicate` does not hold. |
| `any` | At least one predicate of `predicates` holds. |
| `each` | For every entry of the array at `path` for which the predicate `where` holds (every entry when `where` is absent), every predicate of `require` holds. |
| `listed` | The array at `set` has an entry whose member at `key` equals the element's value at `self_key` (`key` when `self_key` is absent), and every predicate of `require` holds for that entry: there, a pointer written `self:<pointer>` points into the element, and every other pointer into the entry. |
| `subset` | Every entry of the array at `path` is an entry of the array at `of`. |

Each constraint also names the `requirement` it encodes and its `scope`.

A constraint with `scope` `evidence` is checked at evaluation, on each evidence artifact used, instead of on `config.json`; its pointers starting with `/evidence` point into the decoded `Evidence` payload.

## Fixture index

Landed fixtures exist in `spec/v1.0/fixtures` and are registered in [`../../../fixtures/manifest.json`](../../../fixtures/manifest.json).

| Fixture id | Status | Requirements |
|---|---|---|
| `schema/profiles/valid-conformance-declaration` | landed | SO-DISC-1 |
| `schema/profiles/cd-omitted-role-not-optional` | landed | SO-DISC-1 |
| `schema/profiles/cd-unknown-profile` | landed | SO-DISC-1 |
| `schema/profiles/cd-unknown-member` | landed | SO-DISC-1 |
| `schema/profiles/valid-https-single-owner-metadata` | landed | SO-DISC-1, SO-END-1 |
| `schema/profiles/gm-endpoints-missing-reputation` | landed | SO-END-1 |
| `schema/profiles/valid-contract-both-extensions` | landed | SO-DISC-1 |
| `schema/profiles/valid-attestation-conformance-ext` | landed | SO-DISC-1 |

### Planned

These cases are planned under `spec/v1.0/fixtures/profiles/single-owner/`, each registered with `conformance_profile` `["single-owner"]` (or `["full", "single-owner"]` where noted) and `transport` `["https"]`. None is registered yet.

| Fixture id | Requirements |
|---|---|
| `profiles/single-owner/so-valid-static` (full and single-owner) | SO-DEF-1, SO-DISC-1, SO-APP-1 |
| `profiles/single-owner/so-upgrade-no-reenroll` | SO-UPG-1 |
| `profiles/single-owner/so-upgrade-audit-import` | SO-UPG-2 |
| `profiles/single-owner/so-full-claim-with-omitted-roles` | SO-DISC-5, SO-END-1 |
| `profiles/single-owner/so-reputation-rule-in-contract` | SO-APP-1 |
| `profiles/single-owner/so-presentation-with-snapshot` | SO-PROH-5, SO-UPG-3 |
| `profiles/single-owner/so-missing-disclosure` | SO-DISC-1, SO-DISC-2, SO-UPG-3 |
| `profiles/single-owner/so-disclosure-mismatch` | SO-DISC-3, SO-PROH-6 |
| `profiles/single-owner/so-holder-requires-other-profile` | SO-DISC-4 |
| `profiles/single-owner/so-third-party-issuer` | SO-DEF-1 (C1), SO-DEF-2, SO-PROH-1 |
| `profiles/single-owner/so-act-as-issuer` | SO-PROH-4 |
| `profiles/single-owner/so-approval-non-owner` | SO-DEF-1 (C5), SO-DEF-3 |
| `profiles/single-owner/so-cross-tenant-evidence` | SO-DEF-1 (C3), SO-PROH-2, SO-PROH-3 |
| `profiles/single-owner/so-self-registration` | SO-DEF-1 (C4), SO-DEF-4, SO-PROH-7 |
| `profiles/single-owner/so-two-environments-config` | SO-DEF-1 (C2), SO-PROH-2 |
| `profiles/single-owner/so-reputation-service-config` | SO-ROLE-2 |
| `profiles/single-owner/so-learning-policy-submit` | SO-ROLE-1, SO-END-2, SO-PROH-5 |
| `profiles/single-owner/so-learning-artifact-submit` | SO-ROLE-1, SO-END-1, SO-END-2, SO-PROH-5 |
| `profiles/single-owner/so-learning-event-submit` | SO-ROLE-1, SO-END-1, SO-END-2, SO-PROH-5 |
| `profiles/single-owner/so-reputation-query` | SO-ROLE-1, SO-END-1, SO-UPG-3 |
| `profiles/single-owner/so-no-reputation-after-7000` | SO-ROLE-1, SO-APP-1 |
| `profiles/single-owner/so-hold-persist` | SO-DEF-1 (C1) |
| `profiles/single-owner/so-hold-clear-owner-only` | SO-DEF-1 (C1) |
| `profiles/single-owner/so-policy-revision-change` | SO-APP-1 |
| `profiles/single-owner/so-observe-mode-labeled` | SO-ROLE-3 |
