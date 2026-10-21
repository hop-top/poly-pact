---
title: "PACT Protocol Specification"
subtitle: "Agent Profiles, Intent, Reputation, and Adaptive Admission"
expansion: "Purpose-bound Access Control & Trust"
spec_version: "1.0.0-alpha.0" # x-release-please-version
wire_version: "0.1"
status: "Draft" # Draft | In Review | Approved | Implemented | Deprecated
authors:
  - name: "Jad"
    email: "me@jadb.io"
pact_core_components:
  agent_profiles:
    identity: "agent_id URI + holder key (RFC 7638 JWK thumbprint), bound through native enrollment"
    profile_type: "Requirement-driven AgentProfile disclosure view"
  intent:
    schema_format: "JSON Schema Draft 2020-12"
    binding: "Signed presentation binds purpose to one operation and challenge nonce"
  reputation:
    outcome_evidence: "pact-outcome+jwt"
    scoring_model: "beta-decay-v1"
    security_hold: "Independent of statistical decay"
  adaptive_admission:
    enforcement_point: "In-gateway or trusted validator; native authorization remains final"
    decisions: ["ADMISSIBLE", "INADMISSIBLE", "DEFERRED"]
    learning_modes: ["observe", "bounded_autonomous"]
transport:
  signatures: "JWS Compact (RFC 7515), ES256 / P-256 baseline"
  channel: "HTTPS"
last_updated: 2026-10-15
---

# PACT Protocol Specification

* **Authors:** Jad (me@jadb.io)
* **Status:** Draft | **Spec version:** 1.0.0-alpha.0 | **Wire version:** `0.1` <!-- x-release-please-version -->
* **Last Updated:** 2026-10-15
* **Name:** PACT — Purpose-bound Access Control & Trust
* **Agent Profiles:** Requirement-driven disclosure views; holder-key proof of possession
* **Intent:** Signed presentation binding purpose to operation and challenge nonce
* **Reputation:** Contextual, outcome-based (`beta-decay-v1`); security holds persist independent of decay
* **Adaptive Admission:** Gateway-published requirements; bounded, rollback-able learning; never grants native access

This document defines a protocol proposal and its conformance criteria. It does not claim that an implementation, interoperability suite, or independent security assessment has been completed.

## 1. Abstract

PACT defines how an AI agent presents its profile, declared intent, and verifiable evidence to an existing access-controlled gateway. A gateway publishes the profile requirements that apply to a requested operation. PACT evaluates whether the agent meets those requirements, records the result, and supplies attributable outcomes to a continuous reputation and learning loop.

Existing environments retain ownership of authentication, roles, groups, resource permissions, delegation authority, and final authorization. PACT standardizes the agent information and evidence those environments can consume. A successful PACT admission result never independently grants resource access.

Reputation is a first-class, contextual protocol input. Continuous learning updates reputation and can autonomously select or adjust admission requirements within an explicitly authorized learning policy. Neither reputation nor learning can invent membership, override a native denial, or expand an agent's underlying authority.

The baseline uses HTTPS, asymmetric JSON Web Signatures, proof of possession of a registered agent key, bounded freshness, single-use challenges, explicit audience and operation binding, and signed admission receipts. A reference scoring model, outcome records, learning lifecycle, schema definitions, and conformance tests are included.

## 2. Scope and non-goals

### 2.1 What PACT standardizes

1. A common agent profile and the provenance of its claims.
2. Gateway-published, machine-readable requirements for those profiles.
3. A signed presentation binding a profile to an intent and an actual request.
4. Admission checks and a precise, auditable result.
5. Contextual reputation based on attributable outcomes.
6. Continuous learning, controlled autonomous adaptation, and rollback.
7. Integration contracts that preserve existing authorization boundaries.

### 2.2 What remains with the environment

The environment defines its users, service accounts, roles, groups, permissions, resource identifiers, policy evaluation, native tokens, approval processes, delegation semantics, and enforcement mechanisms. It also defines whether a particular purpose is permitted and what operations that purpose justifies.

PACT does not define a replacement IAM system, universal role taxonomy, access-token service, or cross-organization permission hierarchy. It does not require gateways to adopt a new resource permission model. A gateway MAY implement its own requirement checks directly or use a trusted PACT validator.

The core does not issue bearer access tokens, grant capabilities, execute business actions, or guarantee an agent's internal motivation. It can bind a declaration to a request and validate evidence about the request. Preventing later misuse of information requires controls in the execution environment.

### 2.3 Admission and authorization

For an operation protected by PACT:

`execute = native_authentication_valid AND pact_admission_admissible AND native_authorization_allows AND native_execution_conditions_satisfied`

An unknown, unavailable, expired, or indeterminate term does not authorize execution. A native denial always wins. A PACT rejection can make access more restrictive, subject to the gateway's published policy, but a PACT pass cannot make native permissions more permissive.

PACT can be deployed in observation mode during integration. Observation mode MUST be labeled in records and MUST NOT be represented as enforced protection. Enforced mode MUST apply the expression above on every protected operation.

## 3. Conventions and terminology

The uppercase requirement words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY have the meanings in BCP 14, RFC 2119 and RFC 8174. Sections 1–23 and Appendix A are normative unless explicitly marked informative. Examples and Appendices B–D are informative.

| Term | Meaning |
|---|---|
| Agent | A software actor with a stable identity within a defined trust realm. |
| Principal | The user or workload whose native authority is relevant to a request. |
| Operator | The accountable organization or person operating an agent. |
| Gateway | The existing enforcement boundary that accepts or denies resource requests. |
| Validator | A gateway component or trusted service that evaluates PACT requirements. |
| Profile | An agent's structured, presented claims; field presence alone does not establish truth. |
| Requirement contract | A signed, versioned specification of the fields, evidence, and contextual checks required for one presentation. |
| Evidence issuer | An authority trusted for specified claim types and scopes. |
| Admission | Whether the presented agent context meets the gateway's PACT requirements. |
| Admission attestation | A signed record of admission checks, bound to one presentation and operation. It is not an access token. |
| Outcome | An attributable observation about an admission, native authorization decision, execution, or task result. |
| Reputation | A contextual estimate derived from qualified outcome evidence, with explicit uncertainty and provenance. |
| Learning policy | The administrator-authorized boundaries within which adaptation may occur. |
| Learning artifact | A versioned scoring, selection, calibration, or assessment model and its configuration. |
| Security hold | An explicit restriction requiring a defined remediation process; independent of statistical score decay. |
| Realm | An administrative trust domain identified by `tenant_id` and `environment_id`. |

Identifiers are opaque unless a field explicitly specifies otherwise. Identity, confidence, capability, reputation, admission, and authorization MUST remain distinguishable concepts and record types.

## 4. Architecture and trust boundaries

### 4.1 Participants

| Participant | Responsibility |
|---|---|
| Agent holder | Maintains its profile, obtains evidence, and proves possession of its enrolled signing key. |
| Native identity system | Authenticates principals and workloads and supplies authoritative identity or membership context. |
| Existing gateway | Maps the actual request to native action/resource semantics; evaluates native authorization and enforces the result. |
| Requirement publisher | Publishes the base requirements and permitted adaptive requirement sets. |
| PACT validator | Checks presentation integrity, provenance, freshness, binding, and requirement satisfaction. |
| Evidence issuers | Assert identity binding, membership, delegation, runtime state, capability assessment, or approvals within explicitly trusted scopes. |
| Reputation service | Qualifies outcomes, maintains contextual history, and signs reputation snapshots. |
| Learning controller | Trains or updates models, evaluates candidates, and promotes or rolls back versions within an authorized learning policy. |

These are logical roles. They MAY be colocated. Role separation and authority restrictions still apply when components share a process. An informative diagram of the control and data boundaries is in [`diagrams/architecture.mmd`](diagrams/architecture.mmd).

### 4.2 Trusted configuration

Each gateway MUST configure, through its existing administrative controls:

- Trusted requirement publishers and validators, including their key sources.
- Agent-to-native-identity and key-binding rules.
- Evidence issuers, allowed claim paths, claim kinds, audiences, tenants, and environments.
- Native context mappings and the authoritative source for each mapping.
- Reputation services, outcome reporter roles, and learning controllers.
- Base requirements, adaptive boundaries, revocation mechanisms, and fail-closed behavior.

An agent profile, discovery response, or signed claim MUST NOT install or broaden these trust anchors. A valid signature proves control of a key; issuer authority is a separate check.

### 4.3 Integration boundary

The integration surface is deliberately small: the gateway obtains a requirement contract, validates the supplied profile and evidence, and uses the admission result as an additional condition in its existing access decision.

PACT MUST NOT create a native role, add group membership, change an ACL, or exchange a declaration for a more privileged service identity. A connector using a service account MUST preserve the requesting principal's native restrictions. Its technical credential is not evidence that the requesting agent is authorized.

### 4.4 Supported deployment forms

| Form | Required behavior |
|---|---|
| In-gateway | The gateway evaluates PACT and native policy in its own request path. |
| Trusted sidecar/service | A separate validator returns an operation-bound attestation; the gateway independently checks its issuer, binding, freshness, and single-use status before native authorization. |
| Observation | Outcomes are collected without enforcing PACT admission; every record declares observation mode. |

Deployment form and conformance profile (Section 22.1) are independent: any form MAY be combined with a declared conformance profile, and observation is a mode, not a conformance profile.

An opaque legacy gateway that cannot authenticate the principal, expose a usable request mapping, or enforce an additional condition cannot claim enforced PACT support merely because an agent profile has the right fields.

## 5. Security and behavioral invariants

1. **Native authority is preserved.** Admission and reputation cannot override native authentication or authorization.
2. **Required fields have required provenance.** Security-relevant claims require a trusted source with authority over those claims.
3. **The presenter is bound to the subject.** An agent cannot reuse another agent's identity or evidence without a valid native delegation and an explicit binding recognized by the gateway.
4. **A result is request-specific.** Profile, intent, native principal, gateway, requirement version, and actual operation are cryptographically bound together.
5. **No positive result from uncertainty.** Missing evidence, stale state, unsupported requirements, and unavailable required dependencies do not produce `ADMISSIBLE`.
6. **Learning stays within policy.** Autonomous changes cannot remove immutable requirements or expand native authority.
7. **Reputation follows evidence.** Repeated admission checks alone do not improve reputation.
8. **Incidents survive decay.** Time decay cannot clear a security hold.
9. **Every completed authenticated evaluation has a receipt.** Pass, fail, defer, cancel, and timeout are distinguishable.
10. **Private keys remain private.** Public validation does not distribute a signing secret to verifiers.

## 6. Identity, enrollment, and key lifecycle

### 6.1 Stable identity

`agent_id` is an absolute URI identifying an agent within its trust realm. A native workload identifier, a gateway-assigned URI, or a suitably governed DID MAY be used. A gateway MUST bind the identifier to an authenticated workload/principal and an enrolled public key through its existing enrollment process or a trusted identity-binding issuer.

Enrollment, operator verification, role assignment, and approval authority remain native administrative operations. Self-registration proves neither organizational identity nor entitlement. Unknown agents MUST NOT obtain trusted status solely by creating keys.

### 6.2 Holder key

`holder_jkt` is the RFC 7638 SHA-256 JWK thumbprint of the agent's public signing key. The gateway MUST verify that the presentation key matches this thumbprint and the current enrolled binding for `agent_id` in the relevant realm.

PACT requires proof of possession in each presentation. Transport authentication alone does not replace this proof. Conversely, a valid presentation signature does not replace the gateway's native authentication requirements.

### 6.3 Optional DID binding

`did:key` MAY be carried as an additional key identifier. It MUST NOT be treated as proof of operator identity, membership, or permission. Because a `did:key` identifier changes when its key changes, stable agent identity and reputation continuity MUST be managed separately when this method is used.

Implementations supporting `did:key` MUST follow the actual method specification, including multicodec and multibase processing, exact key lengths, and allowed key types. DID Core alone does not define the method.

### 6.4 Rotation and compromise

Routine key rotation MUST use a native authenticated administrative workflow or an authorized rotation issuer. Proof by the old key alone MUST NOT recover an identity marked compromised. New profiles and fresh key-bound evidence are required after rotation; old key bindings become invalid according to the configured propagation bound.

The reputation service MAY preserve history across a verified routine rotation. It MUST retain the rotation event and MUST NOT silently transfer a trusted score to an unrelated identity. A compromise event triggers the configured security hold and reevaluation of affected evidence and outcomes.

Private keys SHOULD be held in a protected key store or workload signing service. Production systems MUST NOT use shared demo keys. This specification does not require private keys in environment variables or plaintext files.

## 7. Encoding, signatures, and freshness

### 7.1 JSON data

PACT objects use UTF-8 JSON. Duplicate property names, non-finite numbers, invalid Unicode, and unknown core fields MUST be rejected. Explicit `extensions` objects are the only locations for additional protocol fields. An extension affecting validation MUST be advertised and supported; otherwise admission is deferred with `UNSUPPORTED_REQUIREMENT`.

Protocol timestamps are integer Unix epoch seconds. Identifiers, monetary quantities requiring exact decimals, and large counters outside the interoperable integer range MUST be strings with an application-defined format. Core integer fields are limited to the exact range `0..9007199254740991`.

### 7.2 Signed artifacts

Security-relevant artifacts use JWS Compact Serialization, RFC 7515, with an attached JSON payload. All header fields are protected. Implementations MUST verify the received signing input directly; they MUST NOT parse and reserialize the payload to reconstruct the signature input.

The baseline MUST implement JOSE `ES256` with P-256 keys. `Ed25519` from RFC 9864 MAY be negotiated explicitly, using the corresponding RFC 8037 key representation. The older ambiguous `EdDSA` identifier is not accepted in this profile. HMAC algorithms, `none`, detached payloads, unencoded payloads, and unrecognized critical headers are prohibited in the baseline.

Issuers MUST set and validators MUST check the artifact-specific `typ`. Service-signed artifacts use `kid` resolved only within the configured trusted issuer's key set. An agent presentation includes its public `jwk`; that key is accepted only after matching the enrolled `holder_jkt`. Private JWK parameters MUST be rejected. `jku`, `x5u`, and arbitrary network key discovery from an untrusted artifact are prohibited.

### 7.3 Artifact types and claims

| Artifact | JWS `typ` | Required signer |
|---|---|---|
| Requirement contract | `pact-requirements+jwt` | Gateway-authorized requirement publisher |
| Evidence | `pact-evidence+jwt` | Issuer authorized for its claim paths and scope |
| Presentation | `pact-presentation+jwt` | Enrolled agent holder key |
| Admission attestation | `pact-admission+jwt` | Gateway-authorized validator |
| Outcome report | `pact-outcome+jwt` | Authorized reporter for the observation type |
| Reputation snapshot | `pact-reputation+jwt` | Authorized reputation service |
| Learning policy | `pact-learning-policy+jwt` | Native administrator or delegated policy authority |
| Learning artifact manifest | `pact-learning-artifact+jwt` | Authorized learning controller |
| Learning lifecycle event | `pact-learning-event+jwt` | Controller authorized for that transition |

These `typ` values and PACT-specific fields are private experimental identifiers in this draft, not claims of IANA registration. They MUST NOT be accepted as OAuth access tokens or identity-provider login tokens.

All signed payloads use the common claims in Appendix A: `pact_version`, `iss`, `sub`, `aud`, `jti`, `iat`, `nbf`, `exp`, and `tenant_id`, plus the fields of the artifact type. `aud` is one exact URI, never a generic string meaning every PACT gateway. Each type defines whether that URI identifies a gateway or a bounded control service. `sub` identifies the subject specified for the artifact. `iss` selects a configured trust record; its text does not establish trust by itself.

### 7.4 Digests

`object_digest(x)` means base64url without padding of SHA-256 over the RFC 8785 canonical UTF-8 representation of JSON object `x`. Full RFC 8785 behavior is required, including number serialization, UTF-16 property ordering, and I-JSON restrictions.

`artifact_digest(s)` means base64url without padding of SHA-256 over the ASCII bytes of the exact compact JWS string `s`. `bytes_digest(b)` applies the same hash and encoding to raw bytes.

JCS is used for reproducible object digests, not as a substitute for JWS signing rules. Evidence profiles claiming a W3C Verifiable Credential proof suite MUST implement that suite fully; the core does not label a custom JWS as `Ed25519Signature2020`.

### 7.5 Time and replay rules

Validators MUST check `nbf <= now + clock_skew`, `iat <= now + clock_skew`, and `now < exp`. The baseline maximum clock skew is 5 seconds; there is no expiry grace period. For presentations, `exp - iat` MUST be at most 60 seconds and `now - iat` MUST be at most 60 seconds. Deployments MAY tighten these bounds.

A presentation MUST carry the single-use nonce from its requirement contract. Consumption is an atomic operation shared across replicas. The nonce is bound to the agent, holder key, realm, operation digest, and requirement contract digest. Replay records MUST remain until at least the later of the artifact expiry and `iat + 60 + clock_skew`; records MUST NOT be evicted earlier under load. A full or unavailable replay store causes deferral, not fail-open admission. A nonce for which the replay store holds no record, because it was never registered or its record was evicted after its retention bound, is treated as consumed: the transport error is `REPLAY` (Section 13.4).

For signed control artifacts such as outcomes and learning events, the receiving service MUST implement durable deduplication by `(iss, jti)` and reject a different payload with the same key. An identical authenticated retry returns the original acknowledgment, or an `Acknowledgment` with status `DUPLICATE`, and creates no additional evidence or state transition. Deduplication lasts at least as long as the associated evidence or lifecycle record is retained.

## 8. Agent profile and evidence model

### 8.1 Core profile

An `AgentProfile` is a versioned disclosure view, not a universal public directory entry. Each view has a unique `profile_id`; changes increment `revision`. The signed presentation protects the exact disclosed view. Distinct gateway-specific views MAY reveal different optional attributes without publishing a global dossier.

Core fields are `profile_id`, `revision`, `agent_id`, `operator_id`, `tenant_id`, `holder_jkt`, `created_at`, `expires_at`, and `attributes`. Exact types are in Appendix A. Profiles expire within 24 hours of creation in the baseline; evidence and request validity can be substantially shorter.

`attributes` contains gateway-understood namespaces, such as `identity`, `environment`, `delegation`, `runtime`, `capabilities`, and `reputation`. These are structured data, not executable expressions. Gateway requirements determine which paths are mandatory, their types, their allowed values, and their required source.

### 8.2 Three sources of claim truth

| Rule source | Meaning | Appropriate use |
|---|---|---|
| `self` | The agent asserts the value, and its presentation protects integrity only. | Display name, stated capability, descriptive runtime information. |
| `evidence` | A configured issuer attests the value, subject, holder binding, audience, and scope. | Operator identity, qualified capability, delegated authority reference, runtime attestation. |
| `native` | The gateway compares the profile value with current context obtained through its existing authenticated systems. | Principal identity, tenant, role membership, native delegation, resource entitlement context. |

Reputation fields use `evidence` with a trusted `ReputationSnapshot`, with context matching under Section 15. A profile MUST NOT claim that a self-asserted role, capability, reputation, or runtime statement has authoritative provenance.

### 8.3 Evidence assertions

An `Evidence` artifact carries `environment_id`, `holder_jkt`, `kind`, a list of `{path, value}` claims, and `status_ref`. Paths are JSON Pointers into the presented profile. `kind` is one of `identity`, `membership`, `delegation`, `runtime`, `capability`, or `approval`.

Evidence `sub` MUST equal `profile.agent_id`; its realm, audience, and holder binding MUST match. Every accepted claim MUST be within the issuer's configured claim-path and claim-kind authority. A generic issuer allowlist is insufficient. The evidence MUST be current, not issued in the future, and not revoked. Its original `iat` MUST represent the source assertion time; an adapter MUST NOT refresh stale upstream facts by re-signing them with a new timestamp.

`status_ref` is an opaque issuer-scoped identifier, not a caller-controlled fetch URL. The configured issuer adapter defines how status is checked and how freshness is established. Unknown status is not evidence of validity.

### 8.4 Claim comparison

An evidence claim satisfies a field rule only if the path, subject, context, and allowed issuer match. For `comparison: equal`, the profile value and authoritative value MUST be equal as JSON data; object member order is ignored, array order is significant. For `comparison: subset`, both values MUST be arrays of unique scalars, and every presented value MUST occur in the authoritative array.

All applicable rules are conjunctive. Multiple conflicting authoritative values produce `CONFLICTING_EVIDENCE`; the validator MUST NOT select whichever value permits access. A field rule's schema applies to the presented value in addition to source comparison.

### 8.5 Native context and delegation

Native values MUST come from the gateway's authenticated context or a configured authoritative lookup. Client-supplied headers, profile text, URL parameters, and model output are not native context. Mappings MUST preserve issuer, tenant, and identity namespaces so similarly named users or roles are not conflated.

Delegation profile fields MAY identify a principal, a native delegation reference, expiry, or permitted audience. PACT validates that required fields and evidence are present and correspond to native context. The native system still decides whether the delegation authorizes this operation. PACT does not mint a delegation or weaken its restrictions.

The baseline attribute paths for these delegation fields are `/attributes/delegation/authority_ref`, `/attributes/delegation/principal_id`, `/attributes/delegation/expires_at`, and `/attributes/delegation/audience`. The prefix `/attributes/delegation` is reserved for delegation fields (Section 9.2 and Appendix A.2); the member names are informative. Whether a gateway requires any of them is defined by its requirement contract.

### 8.6 Evidence renewal and agent self-maintenance

Agents SHOULD automatically refresh expiring profiles and evidence through authorized issuer workflows. An agent MAY update self-descriptive fields without additional approval. It MUST NOT convert a missing authoritative value into a self-asserted replacement. If requirements change, it obtains a new contract and presents a new profile view.

## 9. Gateway requirement contracts

### 9.1 Purpose

A `RequirementContract` answers: **For this agent and this operation, which fields must be defined, what must their values satisfy, and who must establish their truth?**

The contract binds a base policy revision and a selected adaptive requirement set to a single operation and challenge nonce. Its `sub` is the agent, `aud` is the target gateway, and `iss` is an authorized requirement publisher. It expires within 60 seconds. It contains the enrolled `holder_jkt`, `environment_id`, `operation_digest`, `intent_digest`, `base_revision`, `selected_set`, `field_rules`, `context_checks`, `learning_policy_digest`, `learning_artifact_digest`, `nonce`, and `mode`.

The gateway MUST obtain native authentication and a trustworthy agent/key binding before issuing a personalized contract. Public discovery does not enroll an agent or disclose protected requirements.

A contract request is refused with the transport error `INVALID_PROOF` when the request is not natively authenticated, when the realm holds no binding of the named agent to the authenticated workload, or when that binding is revoked or names another key; with `CONTEXT_MISMATCH` when the agent is enrolled for another workload of the realm (Section 17.1), or when the proposed operation names another principal or environment than the authenticated ones; and with `SECURITY_HOLD` when the binding is marked compromised (Section 6.4). A refused request issues no contract and registers no nonce.

### 9.2 Field rules

Each `FieldRule` contains a unique `rule_id`, profile `path`, JSON `schema`, `source`, `comparison`, `allowed_issuers`, `native_path`, `max_age_seconds`, and `status_max_age_seconds`. Unused source-specific values are represented exactly as specified in Appendix A; their presence does not enable another source.

- Every listed path is required. Absent, null when not allowed, malformed, or nonconforming values fail the rule.
- `self` is prohibited for identity binding, principal authority, tenant membership, role membership, delegation, approval, and reputation decisions.
- `evidence` requires at least one configured allowed issuer; an empty list does not mean any issuer.
- `native` requires an approved `native_path` mapping. The gateway compares the supplied value against the mapped native value.
- `max_age_seconds` applies to the original source observation, not an intermediary's receipt time.
- `status_max_age_seconds` bounds cached revocation or membership-status checks. Zero requires a fresh authoritative check for this evaluation.
- For a rule on `/attributes/reputation` or a descendant, both ages apply as Appendix A.2 states: the snapshot's issuance is the observation, and the status check is the gateway's own hold check.

Schemas use JSON Schema Draft 2020-12. The baseline accepts the validation keywords listed in Appendix A. Remote references, executable extensions, and unbounded user-supplied regular expressions are prohibited. Publishers compile and validate schemas before activation.

### 9.3 Context checks

Field rules are accompanied by the mandatory protocol checks of Section 12.1, which cover holder binding, native identity binding, intent/operation mapping, freshness, revocation, and security holds. `context_checks` declares named gateway checks required by the policy, such as native delegation validation or an existing approval reference. Check identifiers MUST resolve to installed, versioned gateway logic. Unknown checks result in deferral.

This mechanism does not create a general remote policy programming language. A contract cannot download arbitrary code or broaden the installed check's authority.

The baseline check `execution-identity-v1` is defined in Section 17.5.

`selection-consistency-v1` is a baseline check identifier, alongside the mandatory protocol checks (Sections 9.4 and 11.3). A gateway that has not installed it treats it as an unknown check, which results in deferral.

### 9.4 Base and adaptive requirements

The base policy contains immutable requirements for a learning-policy epoch. Adaptive requirement sets can add controls or vary controls explicitly designated adaptive, such as requiring a supervisor's approval attestation, verified runtime isolation, or more recent capability evidence.

Every permitted set MUST include the base requirements. The gateway selects the effective set using the active learning policy, verified reputation, and request context. The agent cannot select a weaker set. Unknown agents or insufficient evidence use the policy's conservative set.

The "selection inputs" are the active `learning_policy_digest`, the selector's `learning_artifact_digest`, the `ReputationSnapshot` used (identified by its `jti`), the current hold status, and `base_revision`. The gateway's record of the selection inputs used to select a contract's set is its "selection record". A selection that yields the conservative set, including one made for an unknown agent or on insufficient evidence, is recorded like any other. When the contract's `selected_set` differs from the policy's `conservative_set`, the contract MUST (a) list `selection-consistency-v1` in `context_checks` and (b) express every reputation threshold the selector relied on as a field rule with source `evidence` under `/attributes/reputation`: for a minimum on a dimension statistic, `path` `/attributes/reputation/dimensions/<dimension>/<statistic>` and a `schema` whose `minimum` is the threshold; for a required security status, `path` `/attributes/reputation/security_status` and a `schema` whose `const` is that status. The policy's authorized rules for a set other than the conservative set MUST contain these rules, so that a validator comparing the contract with that table (Section 11.3, step 3) also establishes (b); a publisher MUST NOT issue a contract whose selected set lacks one of them (`INVALID_MESSAGE`, Section 13.4). Section 11.3, step 9 defines how the validator evaluates the check.

The signed contract contains the complete effective requirements, not only their names. Changing the active base policy, relevant hold, or required model version invalidates outstanding contracts unless the native administrator explicitly authorized a bounded compatibility window that preserves all current mandatory controls.

### 9.5 Example integration

For a finance gateway, required profile fields might include `environment.principal_id`, `environment.roles`, `delegation.authority_ref`, and `runtime.isolation`.

The role field is compared with native directory context or an authorized membership issuer. The delegation reference is checked by the existing delegation service. The runtime field needs trusted runtime evidence only when the selected requirement set requires it. Even after those fields pass PACT, the gateway still checks whether that principal can read the particular invoice.

## 10. Intent and operation binding

### 10.1 Declared intent

An `Intent` contains `intent_id`, `purpose_id`, `description`, and `task_id`. The `purpose_id` is an environment-recognized identifier with versioned semantics. `description` is explanatory text and MUST NOT be treated as an executable policy or proof of authority. `task_id` groups work belonging to the same native task or approval; a client-generated value MUST be reconciled with the authoritative task context before it affects reputation deduplication. A gateway that counts operations, pages, or bytes against a task, or records an idempotency key for one, does so by the authoritative task reference, never by the client value.

The gateway MUST define how its purpose identifiers map to allowed task categories and request context. An unrecognized purpose yields `UNSUPPORTED_PURPOSE`: as a transport error when the gateway refuses the contract request, and as the `UNKNOWN` result, with that reason code, of the installed purpose/operation check (Section 11.3, step 8) when it is found during an evaluation, which defers. If the environment cannot evaluate whether an operation is consistent with the declared purpose, it MUST NOT claim that PACT enforces that relationship. It can operate in observation mode until that check exists.

### 10.2 Actual operation

An `OperationContext` contains `operation_id`, `environment_id`, `principal_id`, `action`, `resources`, `method`, `target_uri`, `body_digest`, and `headers`. It is a description used for binding; it is not a permission grant.

The gateway adapter MUST derive the action, resources, and principal from the actual authenticated request and installed mapping rules. It MUST compare that context with the signed presentation. It MUST NOT trust a client-supplied resource list when the request body, path, query, or headers cause a different resource to be accessed.

The actual operation context carries the `operation_id` of the contract the presentation was issued under: the `operation_id` the `ContractRequest` proposed, which the gateway records with the contract when it issues it and does not derive from the actual request.

For the baseline HTTP mapping:

- `method` is the uppercase HTTP method.
- `target_uri` is the externally configured HTTPS origin plus the exact request path and query. Scheme and host are lowercase; a default port is omitted. Path and query octets, percent encoding, and query order are preserved: the gateway never rewrites them. Fragments and userinfo are forbidden. Ambiguous encodings are rejected, never normalized. An encoding is ambiguous when RFC 3986 syntax-based normalization (Section 6.2.2) would change it, or when it hides structure: a percent-encoded unreserved character (RFC 3986 Section 2.3, for example `%7E`), lowercase hexadecimal digits in a percent-encoding (Section 2.1), an encoded slash (`%2F`) in the path, or percent-encoded octets that are not well-formed UTF-8 (RFC 3629).
- The public origin comes from trusted gateway configuration. Untrusted forwarding headers cannot select it.
- `body_digest` hashes the exact request-body bytes after HTTP transfer decoding. The baseline forbids HTTP content encodings on protected requests. An empty body hashes the empty byte string.
- `headers` contains the normalized, lowercase names and exact gateway-normalized values of all application headers that can alter action semantics, plus `content-type` when a body is present. The gateway publishes its header allowlist and normalization rules. Authorization credentials, PACT presentation headers, hop-by-hop headers, and signatures are excluded; identity is bound through `principal_id` and native authentication.
- The same mapping version MUST be used when issuing the requirement contract and validating the actual operation.

A protected request that violates a rule of this mapping is rejected with `INVALID_MESSAGE` (Section 13.4).

For JSON-native MCP/A2A adapters, a versioned mapping MAY use a canonical message object instead of HTTP body bytes. It is not automatically interoperable with the baseline HTTP mapping. A mapping that uses a canonical message object MUST:

- serialize the object with RFC 8785 and set `body_digest` to `object_digest` (Section 7.4) of that object;
- include in the object the native method, the native protocol version, the mapping revision, every parameter (strict-parsed, with no duplicate property names and I-JSON numbers), the resource targets, the credentials context as identifiers only (principal and audience, never credential values; actor binding is in Section 17.5), and every field that influences execution, including definition digests, continuation state, input responses, and the task reference;
- set `OperationContext.method` to the mapping's uppercase token, `target_uri` to a gateway-configured logical HTTPS URI that names the target and is not a network location, and `resources` to the mapping's normalized target identifiers;
- be declared in `GatewayMetadata.adapters` with its `mapping_revision` (Section 13.3); and
- make no claim of interoperability with the HTTP mapping.

### 10.3 Scope changes and retries

Any material change to intent, principal, action, resources, body, or consequential headers requires a new contract and presentation. A passing result cannot authorize a later action in a multi-step task by implication.

Native systems retain transaction, budget, and idempotency enforcement. `operation_id` is a correlation identifier, not a guarantee of exactly-once execution. Gateways MUST use their native idempotency mechanisms for side effects and MUST NOT automatically repeat an ambiguous non-idempotent action. A repeat of an ambiguous action is not automatic. It is permitted only when the native system's idempotency mechanism is documented to suppress a duplicate and a native status check has shown that the action did not take effect. PACT evidence deduplication cannot repair duplicated business execution.

## 11. Admission exchange

### 11.1 Sequence

| Step | Message or action | Required result |
|---|---|---|
| 1 | Native authentication and request mapping | Establish principal, realm, enrolled agent/key, and proposed operation context. |
| 2 | `ContractRequest` | Ask for requirements for the proposed operation and intent. |
| 3 | Signed `RequirementContract` | Return effective rules, bound context, active learning versions, and a one-use nonce. |
| 4 | Profile preparation | Agent fills required fields and obtains valid evidence and, when required, a reputation snapshot. |
| 5 | Signed `Presentation` with the actual request | Bind profile, evidence, intent, operation, contract, and nonce to the enrolled key. |
| 6 | PACT evaluation | Produce `ADMISSIBLE`, `INADMISSIBLE`, or `DEFERRED`. |
| 7 | Native authorization and execution conditions | Gateway independently decides whether this exact operation may execute. |
| 8 | Signed receipt and outcome records | Record admission and, where observable, native authorization and execution results. |

### 11.2 Presentation contents

A `Presentation` embeds the exact compact requirement contract, profile, intent, operation, an array of compact evidence artifacts, an optional compact reputation snapshot, and the nonce. Its `iss` and `sub` MUST both equal the profile's `agent_id`, its audience MUST be the gateway, and its realm MUST match the contract and native context.

The JWS is mandatory. The presentation's public key MUST match both the profile and contract `holder_jkt` and the current enrollment. Evidence is checked under its own issuer authority; the agent's signature over evidence does not make that evidence authoritative.

A presentation's `exp` is bounded by Section 7.5 only; it is not required to be capped by the contract's `exp` or the profile's `expires_at`, because the evaluation deadline (Section 12.2) and the receipt expiry (Section 12.1) take the earliest of them. A holder SHOULD NOT set a presentation's `exp` later than its contract's `exp`, and SHOULD NOT present a profile whose `expires_at` is earlier than the presentation's `exp`; a validator does not reject a presentation for either.

### 11.3 Validator algorithm

The validator MUST execute the following logical checks. It MAY optimize independent checks without changing their semantics or the decision. In particular, it MAY leave a check unevaluated once the results already established fix the decision whatever the remaining results would be (Section 11.4); the receipt still records every check the contract's `context_checks` names (Section 12.1):

1. Enforce transport authentication, size limits, supported version, strict JSON parsing, and artifact types.
2. Verify the agent signature and current native identity/key binding. Do not allocate reputation-bearing identity based solely on an unverified claim.
3. Verify the requirement publisher, contract signature, subject, audience, realm, validity, and active policy/model version. Ensure its rules are exactly the authorized effective requirements: the publisher's signature excludes client-edited rules, and a validator that holds the policy's table of authorized requirements (an in-gateway validator always does, Section 4.4) MUST compare the contract's `field_rules` and `context_checks` with the table's entry for `selected_set` under the pinned `base_revision`, `learning_policy_digest`, and `learning_artifact_digest`, as JSON data with array order significant; a difference is `contract-validity` `FAIL` with reason code `CONTEXT_MISMATCH`. A validator that does not hold the table, such as a sidecar validator of a separately published policy, relies on the signature and the pinned versions and says so in its integration profile.
4. Check the presentation's time bounds and nonce association. Atomically consume the nonce after identity/signature validation and before a positive result can be issued.
5. Reconstruct the actual operation using the installed adapter. Compare its digest with the contract and presentation. Bind the intent through the contract's `intent_digest` and the presentation.
6. Validate profile age, holder, subject, tenant, operator evidence where required, and all required field schemas.
7. Validate each used evidence artifact's signature, issuer scope, subject, holder, audience, realm, original observation age, expiry, and revocation state. Compare values according to each field rule.
8. Resolve required native facts and compare them with profile fields. Evaluate installed native context checks, including the purpose/operation relation and any delegation or approval checks.
9. Verify any reputation snapshot's context, provenance, freshness, active hold state, and scoring-policy revision: the revision MUST be one the gateway currently accepts (Section 15.2, Appendix A.2). The snapshot's `scoring_artifact_digest` identifies its scorer (Section 16.5) and is not compared with the contract's `learning_artifact_digest`, which pins the selector; a rolled-back or frozen selector invalidates the contract (Section 16.5), not the snapshot. Apply the effective rules; the validator MUST NOT replace the published rules with a free-form LLM judgment. For `selection-consistency-v1` (Sections 9.3 and 9.4), the validator re-derives the effective set with the contract's pinned selector, using (i) the presented snapshot and (ii) the gateway's own current trusted selection input. If either yields a set stricter than the contract's `selected_set`, the check result is `FAIL` with reason code `SELECTION_INPUT_CHANGED`, the decision is `DEFERRED`, and the retry guidance is "obtain a new contract"; on reuse of the contract, the transport error is `REQUIREMENTS_CHANGED` (Section 13.4). If both yield a set equal to or weaker than `selected_set`, the check result is `PASS` and the contract's set stands; it is never changed to a weaker set mid-exchange. The re-derivation is deterministic: the same inputs yield the same result.
10. Persist the decision and checks, then issue the signed admission attestation. Positive admission also requires a final check that the contract is still active and no known security hold or binding revocation became effective during evaluation.

### 11.4 Decisions

| Decision | Meaning | Gateway behavior |
|---|---|---|
| `ADMISSIBLE` | All required PACT checks passed for this exact request. | Continue with native authorization and execution checks. |
| `INADMISSIBLE` | A required claim or condition is demonstrably missing, false, disallowed, or mismatched, including a rejected, expired, revoked, or inapplicable approval. | Do not execute through the protected path. |
| `DEFERRED` | A required check cannot currently be established: unavailable source, unsupported check, uncertain evidence, or pending approval with an established request. | Do not execute; return a reason and bounded retry guidance. |

The protocol does not use a generic `VERIFIED` verdict that conflates identity, skill, authorization, and trustworthiness. Failure to satisfy an admission requirement is not automatically a negative reputation event.

When the required checks of one evaluation include both `FAIL` and `UNKNOWN` results, the decision is `INADMISSIBLE`: a demonstrable failure is not cured by establishing the uncertain checks. The exceptions are the `FAIL` results that this specification maps to `DEFERRED` because the contract, not the agent, is stale: `SELECTION_INPUT_CHANGED` (Section 11.3, step 9) and `REQUIREMENTS_CHANGED` (Section 12.2). When no required check is `FAIL` and at least one is `UNKNOWN`, the decision is `DEFERRED`. Every check that was evaluated, and every check the contract's `context_checks` names, is recorded whatever the decision (Section 12.1).

### 11.5 Sidecar handoff

In a sidecar deployment, the gateway MUST verify the attestation signature, expected validator, audience, subject, holder binding, native principal, environment, operation and intent digests, profile and requirement digests, decision, and expiry. The gateway MUST atomically mark an `ADMISSIBLE` attestation's `jti` consumed before accepting it for its associated operation. A receipt is never reusable for a different request. An attestation that fails these comparisons, or whose decision is not `ADMISSIBLE` or whose mode is not `enforced`, is rejected with `CONTEXT_MISMATCH`; one whose expiry has passed with `EXPIRED`; one whose `jti` was already consumed with `REPLAY`; one under a current security hold with `SECURITY_HOLD`; and one the hold or attestation store cannot answer for with `DEPENDENCY_UNAVAILABLE`.

The gateway MUST enforce current local security holds, active requirement revisions, native identity validity, and native authorization at handoff. It MUST reject a stale positive attestation even if its signature remains mathematically valid. Native downstream APIs MUST NOT accept the attestation as their ordinary access credential.

## 12. Admission receipts and state machine

### 12.1 Receipt contents

An `AdmissionAttestation` contains the decision, terminal reason, operation and presentation IDs, native principal, holder binding, environment, profile/intent/operation/requirements digests, learning-policy and artifact digests, and an ordered list of `CheckResult` objects. The signed payload is a receipt of the validator's assertion, not proof that a task was performed correctly.

The attestation's `operation_digest` is the `object_digest` (Section 7.4) of the actual `OperationContext` the validator evaluated (Section 11.3, step 5), and its `operation_id` and `principal_id` are that context's: `principal_id` is the native principal that `authenticate_native` established for the actual request (Section 17.1), never a principal taken from the presentation. When that digest differs from the contract's `operation_digest`, the operation-binding comparison of Section 11.3, step 5, fails, so an `ADMISSIBLE` receipt carries the contract's digest and the operation and principal IDs of the operation the contract was issued for. The contract's own `operation_digest` stays bound through `requirements_digest`, which hashes the exact signed contract (Appendix A.2).

Every check result identifies its check or rule, outcome (`PASS`, `FAIL`, `UNKNOWN`, or `NOT_APPLICABLE`), stable reason code, evaluation time, source observation and status-check times where applicable, and supporting evidence IDs or an immutable native source reference. A check that was not performed MUST NOT be recorded as passed. The receipt records exactly one result for every check the contract's `context_checks` names (Section 9.3). Such a check that the validator did not evaluate, because the results already established fixed the decision (Section 11.3) or because the evaluation was cancelled or expired (Section 12.2), is recorded with result `UNKNOWN` and reason code `NOT_EVALUATED`, an approval-class check included (Section 17.3.1). It is never recorded as `NOT_APPLICABLE`: that result counts toward `ADMISSIBLE` (Appendix A.2) and is reserved for a check that policy explicitly makes inapplicable to the operation. A native read is an invocation of `read_native_claim` or `check_context` (Section 17.1) on which a field rule or context check depends; `native-principal-binding-v1` needs none (Section 17.5). A field rule or check whose native read had not completed when the evaluation ended, by cancellation or at the evaluation deadline (Section 12.2), was not performed: it is not recorded as passed, and when the contract's `context_checks` names it, it is recorded `UNKNOWN` with reason code `NOT_EVALUATED` as above. Receipts SHOULD minimize raw sensitive values; evidence identifiers and digests usually suffice.

The protocol checks of Section 11.3 are recorded under the following identifiers, in this order, each at most once. A receipt lists them first, then one result per field rule under its `rule_id` in contract order, then one result per entry of `context_checks` in contract order.

| `check_id` | What it records | Section |
|---|---|---|
| `native-authentication` | The native authentication and realm of the actual request. | 11.3 step 1, 17.1 |
| `agent-holder-binding` | The enrolled binding of the agent to the authenticated workload and the presentation key. | 6.2, 11.3 step 2 |
| `contract-validity` | Publisher, subject, audience, realm, extensions, and the authorized rules of the selected set. | 11.3 step 3 |
| `nonce` | The single-use nonce and its atomic consumption. | 7.5, 11.3 step 4 |
| `operation-binding` | The actual and presented operations against the contract's `operation_digest`. | 11.3 step 5 |
| `intent-binding` | The presented intent against the contract's `intent_digest`. | 11.3 step 5 |
| `profile-validity` | Profile subject, tenant, operator, age, and lifetime. | 8.1, 11.3 step 6 |
| `evidence-validity` | Every embedded evidence artifact's signature, issuer scope, binding, timing, and status. | 11.3 step 7 |
| `reputation-context` | The presented snapshot's provenance, binding, freshness, scoring revision, context, and hold state; recorded only when a snapshot is presented. | 11.3 step 9, 15.2 |
| `security-hold` | The current applicable security holds of the agent. | 11.3 steps 9 and 10, 15.4 |
| `active-policy` | That the contract's pinned base revision and learning digests are still active. | 11.3 steps 3 and 10, 12.2 |
| `receipt-store` | That the receipt could be durably recorded; recorded only when it could not (Section 12.2). | 11.3 step 10, 18 |

A gateway MAY record further protocol checks under identifiers that do not collide with these, with a field rule's `rule_id`, or with an installed check identifier.

Receipt expiry MUST be at most 60 seconds after issuance, whatever the decision. For `ADMISSIBLE`, it MUST also be no later than the earliest applicable presentation, contract, profile, and evidence expiry. For failed, cancelled, or timed-out evaluations, the window is not shortened by the expiry of the evaluated input; such a receipt conveys no positive admission.

### 12.2 State transitions

| Current state | Event | Next state |
|---|---|---|
| `CONTRACT_ISSUED` | Authenticated, valid holder presentation arrives | `EVALUATING` |
| `CONTRACT_ISSUED` | Contract expires before a presentation | `EXPIRED` |
| `EVALUATING` | All required checks pass | `SEALED_ADMISSIBLE` |
| `EVALUATING` | A required condition demonstrably fails | `SEALED_INADMISSIBLE` |
| `EVALUATING` | A required dependency or approval is unavailable | `SEALED_DEFERRED` |
| `EVALUATING` | Requestor cancels through native authenticated session control | `CANCELLED` |
| `EVALUATING` | Evaluation deadline or input validity expires | `EXPIRED` |

The evaluation deadline is the earliest of the contract expiry, presentation expiry, or 30 seconds after evaluation starts. Terminal transitions are atomic and immutable. Cancelled or expired authenticated evaluations receive `DEFERRED` receipts with specific terminal reasons. A presentation whose time bounds (Section 7.5) have already elapsed when it arrives, or whose contract has already expired, is rejected with the transport error `EXPIRED` (Section 13.4) and receives no receipt; only an evaluation whose input expires after it starts receives the `DEFERRED` receipt above. A contract never presented may be recorded as expired without creating an agent reputation event or unsolicited delivery.

Waiting for an external approval does not keep a PACT evaluation open. When a required approval is pending, the evaluation seals as `SEALED_DEFERRED` within the deadline above. The approval can arrive later and support a fresh evaluation: the agent starts a new exchange under Section 11 with a new presentation that references the approval. A sealed receipt is never reopened, amended, or converted to another decision; the earlier `DEFERRED` receipt remains in the record, and the fresh evaluation produces its own receipt. See Appendix B.12 and the informative sequence in [`diagrams/admission-approval.mmd`](diagrams/admission-approval.mmd). Section 17.3.1 maps the native state of an approval-class check to its check result, admission decision, and reason code.

Invalid signatures, invalid native authentication, a presentation received over a transport other than the one its contract names (Section 13.3.1), and oversized requests are rejected before an authenticated evaluation is accepted. They receive a safe transport error, not a fabricated agent admission receipt. Security telemetry MAY record them separately without attributing unverified claims to a victim.

A presentation under a contract that has been invalidated (Sections 9.4 and 16.5) is evaluated: the `active-policy` check is `FAIL` with reason code `REQUIREMENTS_CHANGED`, the decision is `DEFERRED`, and the retry guidance is "obtain a new contract". The transport error `REQUIREMENTS_CHANGED` (Section 13.4) is returned when a sealed contract is presented again (Section 11.3, step 9) or when the native gateway rejects a protected request under an inactive contract before an authenticated evaluation.

If a required receipt cannot be durably recorded, the gateway MUST NOT produce a positive enforced admission: an evaluation whose result would be `ADMISSIBLE` seals `DEFERRED` instead, with the protocol check `receipt-store` (Section 12.1) appended to its results as `UNKNOWN` with reason code `DEPENDENCY_UNAVAILABLE`; the receipt is returned to the caller whether or not the retried record succeeds, and conveys no positive admission. A receipt of another decision is returned as sealed; the gateway records that it could not be stored. Signed receipts are retained for the native audit-retention period; expiry prevents current use, not historical signature inspection.

## 13. HTTP binding and integration interfaces

### 13.1 Discovery

The gateway publishes HTTPS metadata at `/.well-known/pact-configuration`. Discovery is bound to a configured gateway origin and MUST NOT itself establish trust in an unrelated issuer. Metadata includes `gateway_id`, `environment_id`, supported wire versions, JOSE algorithms, endpoint URLs, key-set reference, operation mapping version, accepted extensions, modes, and applicable size limits.

The metadata `limits` object carries the baseline limits keys defined in Section 20.1, including one presentation size key for each transport listed in `presentation_transports`.

Production TLS certificate and hostname validation is mandatory. Redirects across origins require explicit administrative configuration. No credentials or evidence artifacts may be carried in URL query parameters.

### 13.2 Baseline endpoints

| Method and endpoint | Request | Response |
|---|---|---|
| `GET /.well-known/pact-configuration` | No PACT body; native access controls MAY restrict metadata | `GatewayMetadata` JSON |
| `POST /pact/v0.1/requirements` | Native-authenticated `ContractRequest` JSON | Signed `RequirementContract` (`application/jose`) |
| Native protected operation | Existing native credentials plus `PACT-Presentation` header, or the negotiated adapter envelope | Native result plus receipt reference or `PACT-Admission` compact receipt when size permits |
| `POST /pact/v0.1/evaluate` | Signed presentation and authenticated gateway-supplied actual operation context | Signed admission attestation; available only to authorized gateway callers |
| `POST /pact/v0.1/outcomes` | Signed `OutcomeReport` | `Acknowledgment` JSON |
| `POST /pact/v0.1/reputation/query` | Native-authenticated `ReputationQuery` JSON | Signed `ReputationSnapshot` |
| `POST /pact/v0.1/learning/artifacts` | Signed `LearningArtifact` | `Acknowledgment` JSON |
| `POST /pact/v0.1/learning/events` | Signed `LearningEvent` | `Acknowledgment` JSON |
| `POST /pact/v0.1/receipts/query` | Native-authenticated `ReceiptQuery` JSON | Signed stored receipt, or a non-disclosing not-found response |

The HTTP paths in this table are normative for the HTTP binding only; a transport profile (Section 13.3.1) maps each row to a transport-neutral operation name.

The evaluate endpoint is a gateway-to-validator interface, not a public route by which an agent can claim that a fictitious operation occurred. Its wrapper contains `{presentation, actual_operation}`. The authenticated calling gateway MUST be authorized for the attestation audience and environment. A colocated implementation MAY use an internal call with equivalent authentication and integrity.

Native operation requests with presentations exceeding configured header limits MUST use a negotiated envelope adapter or trusted gateway-to-validator transfer. Truncation and dropping evidence are prohibited. A deployment MUST publish an actually usable presentation transport; merely adding a header that its proxy rejects does not satisfy conformance.

In enforced mode, a protected request that carries no presentation, neither in the `PACT-Presentation` header nor in the negotiated adapter envelope, is refused with the transport error `INVALID_PROOF` (HTTP 401) before an authenticated evaluation: it carries no holder proof, and it receives no receipt (Section 12.2).

The gateway sends the compact receipt in the `PACT-Admission` response header only when the receipt is no longer than a deployment-configured limit, 8192 bytes (8 KiB) by default. A longer receipt is omitted, never truncated, and is available through `POST /pact/v0.1/receipts/query`.

Artifact and event ingestion is authorized separately for each issuer role and realm. Reputation queries and receipt queries enforce privacy-aware native authorization. There is no public reputation lookup requirement, no unauthenticated profile-registration endpoint, and no generic session-view token in the core.

### 13.3 Native protocols

An MCP or A2A adapter MUST declare the exact protocol versions it implements, its authentication mapping, and how it binds native method names and parameters to PACT operation context. It MUST retain those protocols' authentication and authorization requirements. The PACT presentation is additional to, never a replacement for, the native protocol's authentication and authorization. One `GatewayMetadata.adapters` entry is required per pinned protocol revision, and an adapter entry without an exact `version` or `mapping_revision` is invalid. Custom `/a2a/*` routes alone do not establish A2A compatibility.

For local IPC or stdio, an adapter MUST bind to a trusted local workload identity and preserve equivalent message integrity and origin attribution. This is a separately declared transport profile; the baseline's HTTPS requirements are not silently waived.

### 13.3.1 Transport profiles

A transport profile is declared, never inferred. It states how PACT messages ride a channel other than the HTTPS baseline.

A transport profile MUST define:

- the channel set and the channels it excludes;
- peer identity binding for each channel, with an assurance level;
- framing and frame limits, aligned to Section 20.1;
- a discovery method that replaces Section 13.1;
- a transport-neutral name for each operation in the Section 13.2 table;
- error carriage for Section 13.4;
- a replay-store scope that is independent of connection lifetime; and
- an explicit list of what the channel does not protect.

A transport profile MUST NOT waive Section 6.2 proof of possession; Section 7 (JWS `typ` and `alg` checks, freshness, and atomic nonce consumption); Section 18 fail-closed behavior; Section 20.2 quotas; or the Section 19 requirement for TLS on network paths. A channel reachable over a network, such as loopback TCP or a forwarded or tunnelled socket, is not eligible for a local-channel profile and stays under the HTTPS baseline.

Gateway metadata returned by the profile's discovery method carries the extension `pact-transport-profile-v1`, and the effective `RequirementContract` carries the same value, so that `requirements_digest` binds it. Section 21 governs where a declaration appears. The transport a contract names is the `transport_profile` of the `TransportDeclaration` that its `extensions` carry under `pact-transport-profile-v1` (Appendix A.2), or the HTTPS baseline when it carries none. The gateway establishes the transport of each received message from the channel it arrived on, as part of `authenticate_native` (Section 17.1), never from the message, and passes it to the validator with the actual operation. An enforced-mode holder MUST NOT send a presentation over a transport other than the one its contract names, and an enforced-mode gateway MUST reject a presentation, and a contract request's response MUST NOT be returned, over another transport: the transport error is `CONTEXT_MISMATCH`, returned before an authenticated evaluation (Section 12.2), so no receipt is issued (the downgrade rule). In `observe` mode the mismatch is recorded.

### 13.4 Errors

Transport errors use RFC 9457 problem details with `type`, `title`, `status`, `code`, and a non-sensitive `request_id`. Authenticated native failures MAY include per-rule reasons; public errors MUST avoid disclosing private membership, existence of resources, or internal issuer details.

| Code | Typical HTTP status | Meaning |
|---|---:|---|
| `INVALID_MESSAGE` | 400 | Invalid JSON, schema, signature format, or unsupported structure, including a protected request that violates the operation mapping (Section 10.2) and a signed artifact whose `typ` is not the one the receiving endpoint consumes (Section 7.3), and a message whose `pact_version` is not one the receiver implements (Section 21). |
| `INVALID_PROOF` | 401 | Signature, holder binding, or native authentication failed. |
| `REPLAY` | 409 | Nonce, presentation, or positive attestation already consumed, or a nonce the replay store holds no record of (Section 7.5). |
| `CONTEXT_MISMATCH` | 403 | Principal, audience, realm, intent, actual operation, or transport (Section 13.3.1) differs; a contract whose rules are not the authorized effective requirements of its selected set (Section 11.3, step 3); or an attestation presented at handoff whose decision is not `ADMISSIBLE` or whose mode is not `enforced` (Section 11.5). |
| `REQUIREMENTS_CHANGED` | 409 | Contract is no longer active; obtain a new contract. |
| `UNSUPPORTED_REQUIREMENT` | 422 | Required field rule, extension, mapping, or context check is unsupported. |
| `UNSUPPORTED_PURPOSE` | 422 | Purpose identifier has no installed meaning. |
| `MISSING_FIELD` / `INVALID_CLAIM` | 403 | An admission field is absent or fails its rule. |
| `CONFLICTING_EVIDENCE` | 403 | Required authoritative assertions conflict. |
| `STALE_EVIDENCE` / `REVOKED_EVIDENCE` | 403 | Evidence is too old or explicitly invalidated. |
| `DEPENDENCY_UNAVAILABLE` | 503 | Required verification cannot currently be completed. |
| `SECURITY_HOLD` | 403 | An applicable hold blocks admission. |
| `EXPIRED` | 410 | Contract, presentation, signed control artifact, or evaluation deadline expired. |
| `RATE_LIMITED` | 429 | Request is throttled; bounded retry information MAY be included. |
| `ID_CONFLICT` | 409 | A durable identifier was reused with different content. |
| `LEARNING_REJECTED` | 409 | A learning artifact registration or lifecycle transition was rejected; `extensions.reason_codes` lists the Section 16.5 reason codes. |
| `TASK_LIMIT` | 403 | The native task of the operation has no budget left, is cancelled or completed, or is past its deadline. The request was refused by a native limit, not by an admission requirement. |

An evaluation endpoint normally returns its signed decision with HTTP 200 after a completed authenticated evaluation. The table governs transport failures and the native gateway's rejection of a protected request. An HTTP success code is never a substitute for checking the signed admission decision.

When the native gateway refuses a protected request after an authenticated evaluation, the code follows from the sealed receipt, except at a sidecar handoff, whose rejection codes Section 11.5 gives. When the receipt's terminal reason is `EXPIRED` (Section 12.2), it is `EXPIRED`. Otherwise, for `INADMISSIBLE`, it is the reason code of the first `FAIL` result, in receipt order, whose reason code is a code of the table above, other than a `FAIL` result that Section 11.4 maps to `DEFERRED`; when no result qualifies, it is `INVALID_CLAIM` (HTTP 403). For `DEFERRED`, it is `REQUIREMENTS_CHANGED` when a `FAIL` result is one that Section 11.4 maps to `DEFERRED`; otherwise the reason code of the first `UNKNOWN` result, in receipt order, whose reason code is a code of the table above; and when no result qualifies, `DEPENDENCY_UNAVAILABLE` (HTTP 503). A reason code outside the table, such as `APPROVAL_REJECTED` or `APPROVAL_PENDING` (Section 17.3.1), is never the problem's `code`.

The table does not govern a native authorization denial after admission (Section 11.1, step 7): such a request receives the native system's own denial, HTTP 403 by default; a deployment MAY configure another denial response. An admission does not change the denial (Section 2.3).

Every signed artifact a service receives as a message, a requirement contract, a presentation, or a signed control artifact such as an outcome report or a learning policy, manifest, or event, is checked against the time rules of Section 7.5 and the maximum validity of its type before it is processed. One whose `exp` has passed when it arrives is rejected with `EXPIRED`; one whose `iat` or `nbf` is later than now plus the clock skew, or whose validity exceeds the maximum of its type, is rejected with `INVALID_MESSAGE`; and a signed control artifact whose `aud`, `tenant_id`, or `environment_id` does not name the receiving service, its tenant, or its environment is rejected with `CONTEXT_MISMATCH`; the audience, tenant, and environment of a requirement contract or a presentation are evaluated by the `contract-validity` check instead (Section 11.3, step 3), not rejected before an authenticated evaluation (Section 12.2). An outcome report whose `observed_at` is later than now plus the clock skew, or older than the ingestion window of Section 14.3, is likewise rejected with `INVALID_MESSAGE`; an older observation enters only through the historical-import process of that section. An evidence artifact or reputation snapshot embedded in a presentation is not a message: one that breaks these rules fails the `evidence-validity` or `reputation-context` check, with reason code `STALE_EVIDENCE` when it has expired and `INVALID_CLAIM` when its `iat` or `nbf` is in the future or its validity exceeds the maximum of its type (Section 20.1), and the field rules that rely on it fail with the same code.

For carriage over a transport other than HTTP, the RFC 9457 problem object is carried unchanged in the error `data` member. Its `status` field keeps the HTTP-class number as the failure class, and the code column of the table above is unchanged.

## 14. Outcome evidence and feedback

### 14.1 Purpose and event kinds

All conforming gateways MUST support recording admission outcomes and native authorization results. Where execution is observable, an authorized adapter SHOULD report execution results and independent quality assessments. Missing execution visibility MUST be declared; it MUST NOT be filled with assumed success.

`OutcomeReport.event_kind` is one of `ADMISSION`, `AUTHORIZATION`, `EXECUTION`, `QUALITY`, `SECURITY`, `FEEDBACK`, `CORRECTION`, or `REMEDIATION`. A report binds an `event_id`, agent, realm, task and operation, admission receipt if one exists, observation time, reporter role, and reputation context.

`result` is `SUCCESS`, `FAILURE`, `UNKNOWN`, or `NOT_APPLICABLE`. `dimension` is `reliability`, `task_quality`, `policy_adherence`, or `none`. `severity` is `info`, `low`, `medium`, `high`, or `critical`. Every report includes `evidence_refs`, an attribution statement, and `supersedes` references for corrections. Free text is untrusted data and cannot direct the learning service.

### 14.2 Who may report what

| Reporter | Normally eligible observations |
|---|---|
| Gateway | Admission and native authorization decisions; detected policy violations. |
| Resource service / trusted executor | Whether the operation actually executed, failed, or has unknown outcome. |
| Authorized evaluator / task owner | Task quality or verified feedback, tied to an observed task, including an assessment of the task's policy adherence (Section 14.5). |
| Security authority | Confirmed incidents, compromise, holds, and remediation. |
| Agent itself | Self-reported diagnostics; no positive reputation weight by default. |

The receiver MUST verify reporter authority, subject binding through the original task, audience, realm, event timing, and evidence references. A signature proves who reported an observation; it does not prove that the observation is true. Reporter independence and reliability are part of evidence qualification.

A detected policy violation is a request the agent signed that the gateway refused, or recorded after admission, for breaking a rule the gateway enforces on the agent: an operation outside the declared intent (Section 10.3), reuse of a positive attestation (Sections 11.5 and 12.1), a prohibited credential header (Section 19), or a data-flow limitation (Section 17.4). A native denial, an unmet requirement, a rate limit, an outage, or a transport failure is not one (Section 14.3). The gateway reports it under the row of that name in Section 14.5, citing its immutable record of the violating request; it is a `policy_adherence` failure and never a hold (Section 15.4).

An `EXECUTION` or `AUTHORIZATION` `OutcomeReport` MUST reference, in `evidence_refs`, an immutable native record identifying the actual executor identity (Section 17.5), except a report of absent execution visibility (Section 14.5), whose `evidence_refs` is empty. The receiver classifies a report whose executor class differs from the mapping's declared class as `UNQUALIFIED`.

### 14.3 Qualification and deduplication

The reputation service MUST classify each report as `QUALIFIED`, `UNQUALIFIED`, or `DISPUTED`. It records the reason, source provenance, and scoring-policy version. Only qualified observations may contribute to positive or negative statistics.

Admission passes, repeated challenges, token possession, self-declared confidence, and heartbeats MUST NOT generate positive task-performance reputation. Native denials, unmet profile requirements, outages, and ambiguous evaluation results MUST NOT count as agent misconduct without additional attributable evidence.

Deduplication uses both the signed report identifier and the authoritative `(task_id, operation_id, event_kind, dimension, reporter)` tuple. Positive contributions are additionally capped per independent task group under Section 15. An agent-controlled change of task ID cannot create an independent task. Corrections supersede prior qualified contributions; they do not add a second vote.

Evidence ingestion accepts observations no older than the configured ingestion window (`ingestion_window_seconds` of the data policy, Appendix B.9; baseline 7 days), and no later than `now + clock_skew`. Signed report validity is at most 300 seconds. Durable deduplication indexes MUST cover the entire ingestion window and any longer period required to recompute retained reputation. Reports outside the window require an authorized historical-import process with separate provenance and cannot be backdated into current confidence silently.

### 14.4 Disputes and correction

Disputed observations remain visible in provenance but are excluded from new positive reputation and autonomous promotion until resolved. Their negative contribution is policy-defined; a security hold uses a separate, attributable security decision. Corrections trigger recomputation of affected snapshots and evaluation of whether an active model must be rolled back.

The protocol MUST preserve enough lineage to identify which snapshots, training sets, and model releases used an observation. Deleting evidence under retention or privacy policy MUST have a defined effect on derived data; retained claims cannot pretend that deleted source material remains independently inspectable.

### 14.5 Baseline native outcome mapping

The mapping below is normative. It assigns native observations to existing `OutcomeReport` fields and values (Section 14.1) and adds no field. Reputation effects remain subject to qualification and deduplication under Section 14.3 and scoring under Section 15.3. A hyphen means the row does not fix that value.

A report whose `dimension` is not one this table gives its `event_kind` is invalid (Appendix A.2): `reliability` is observed only by an `EXECUTION` report, and `task_quality` and `policy_adherence` never by one.

| Native observation | `event_kind` | `result` | `dimension` | Reputation effect and conditions |
|---|---|---|---|---|
| PACT admission decision | `ADMISSION` | `SUCCESS` or `FAILURE` | `none` | Zero weight. |
| Native authorization allow | `AUTHORIZATION` | `SUCCESS` | `none` | Zero weight. |
| Native denial | `AUTHORIZATION` | `FAILURE` | `none` | Zero weight; not misconduct (Section 14.3). |
| Pre-authentication or transport failure | No `OutcomeReport` (Section 12.2) | - | - | - |
| Execution completed with data returned | `EXECUTION` | `SUCCESS` | `reliability` | Counts toward `reliability`. |
| Execution completed, zero rows or filtered result | `EXECUTION` | `SUCCESS` | `reliability` | Counts toward `reliability`; `details` is `"empty"`; `task_quality` requires an evaluator; the report never implies that a hidden row was read. |
| Asynchronous request accepted | `EXECUTION` | `UNKNOWN` | `none` | Zero weight; new `event_id`. |
| Asynchronous completion observed | `EXECUTION` | `SUCCESS` or `FAILURE` | `reliability` | Counts toward `reliability`; separate `event_id`; the deduplication tuple differs by dimension. |
| Asynchronous completion observed with status cancelled | `EXECUTION` | `FAILURE` | `reliability` | Counts toward `reliability`; `details` is `"cancelled"`; `causal_assessment` is `UNKNOWN` unless the executor establishes who cancelled (Section 14.6 rule 8). |
| Ambiguous timeout | `EXECUTION` | `UNKNOWN` | `none` | Zero weight; reconcile natively, never retry blindly (Section 10.3). |
| Execution visibility unavailable | `EXECUTION` | `UNKNOWN` | `none` | Zero weight; `evidence_refs` is empty and the gateway profile declares absent visibility. |
| Independent assessment | `QUALITY`, reported by an evaluator or the task owner (Section 14.2) | `SUCCESS` or `FAILURE` | `task_quality` | Counts toward `task_quality`; `evidence_refs` cites the completed assessment of the task. |
| Verified feedback | `FEEDBACK`, reported by an evaluator or the task owner, or by the agent itself as a diagnostic (Section 14.2) | `SUCCESS` or `FAILURE` | `task_quality` | Counts toward `task_quality` as an assessment does, under Section 14.2 and Section 14.6 rules 5 to 9; from an evaluator or the task owner it cites the completed assessment it conveys; from the agent itself a success has zero weight (rule 11) and a failure counts as an attributable failure. |
| Independent assessment of policy adherence | `QUALITY` or `FEEDBACK`, reported by an evaluator or the task owner, or `FEEDBACK` by the agent itself as a diagnostic (Section 14.2) | `SUCCESS` or `FAILURE` | `policy_adherence` | Counts toward `policy_adherence`, a success positively and a failure negatively, under the eligibility of Section 14.2 and Section 14.6 rules 5 to 9, as an assessment counts toward `task_quality` and with the same evidence; from the agent itself never positively (rule 11). |
| Detected policy violation (Section 14.2) | `SECURITY`, reported by `gateway` only | `FAILURE` | `policy_adherence` | Counts toward `policy_adherence` as one failure when `causal_assessment` is `AGENT` (Section 14.6, rules 8 and 9); `evidence_refs` cites the gateway's immutable record of the violating request; places no hold (Section 15.4). A gateway `SECURITY` report with another `result` or `dimension` is `UNQUALIFIED`. |
| Confirmed incident | `SECURITY`, reported by `security_authority` only | `FAILURE` | `none` | Zero weight in every dimension; places a hold (Section 15.4); `evidence_refs` cites the confirmed incident record of its task and operation. A security authority's `SECURITY` report with another `result` or `dimension`, or that cites no such record, is `UNQUALIFIED` and places no hold. |
| Remediation completed | `REMEDIATION`, reported by `security_authority` only | `SUCCESS` | `none` | Zero weight; clears the hold it names in `evidence_refs` when its signer is a hold clearance authority (Section 15.4). |

### 14.6 Baseline qualification policy `pact-qualification-v1` and reporter independence policy `pact-reporter-independence-v1`

`pact-qualification-v1` is the baseline qualification policy and `pact-reporter-independence-v1` is the baseline reporter independence policy. They are usable as the values of `DataPolicy.qualification_policy_id` and `DataPolicy.reporter_independence_policy_id` respectively. The baseline consists of the rules below.

1. `independence_group` MUST come from `task_attribution_source`.
2. A client-supplied `task_id` that does not reconcile with the authoritative task context is `UNQUALIFIED` (Section 10.1).
3. Subdivided or repeated operations within one native task collapse to one independence group, so the per-group cap of Section 15.3 applies to them as one group.
4. A duplicate of the tuple (`task_id`, `operation_id`, `event_kind`, `dimension`, reporter) receives an `Acknowledgment` with status `DUPLICATE` and casts no second vote.
5. A signer registered as executor for a task MUST NOT be accepted as evaluator for the same task (self-praise). A signer is registered as executor for a task when a trust record registers it for `reporter_role` `executor` and it reported, in that role, an `EXECUTION` event of that task; its `QUALITY` and `FEEDBACK` reports on that task are `UNQUALIFIED`, whichever report was received first.
6. An evaluator or task owner affiliated with the agent's `operator_id`, according to a configured affiliation registry, has its positive `QUALITY` and `FEEDBACK` reports classified `UNQUALIFIED`; its negative reports are unaffected.
7. Reciprocal endorsement: when evaluator E's own agent has been evaluated by the agent's operator within the ingestion window, both positive reports, `QUALITY` or `FEEDBACK`, are classified `DISPUTED` pending review.
8. A `causal_assessment` of `ENVIRONMENT` or `UNKNOWN` carries zero negative weight.
9. A `causal_assessment` of `MIXED` has a policy-defined weight; the baseline weight is zero.
10. A `CORRECTION` supersedes the events it names in `supersedes` and triggers recomputation of every snapshot whose provenance includes a superseded event (Section 14.4). The correction MUST name events of the same `task_id`, `operation_id`, `event_kind` and `dimension`, each received before it and `QUALIFIED` or `DISPUTED`, from the same reporter or from a security authority; otherwise it is `UNQUALIFIED`. For this rule the `event_kind` of a superseded correction is that of the events it superseded. The correction carries the `dimension` of the events it supersedes whatever its `result`; it is exempt from the Appendix A.2 rule that gives a report with `result` `UNKNOWN` dimension `none`. Section 14.2 and rules 5 to 9 and 11 apply to a correction as to a report of that `event_kind` from its signer, so a correction cannot add what its signer could not report; a security authority may correct any reporter's events. A qualified correction is scored as one event with its own `result`, `dimension` and `observed_at` in place of the superseded events; a correction with `result` `UNKNOWN` retracts them and, having zero weight, is listed in neither array of the provenance manifest. The superseded events are listed in `superseded_event_ids` and not in `qualified_event_ids` (Section 15.2).
11. Events reported by the agent itself are never positive (Section 14.2).
12. A `SECURITY` report carries statistical weight only as the detected policy violation of Section 14.5: from a gateway, with `result` `FAILURE` and dimension `policy_adherence`. A `SECURITY` report from a security authority is the confirmed incident of Section 14.5, `FAILURE` on `none` citing the confirmed incident record of its task and operation; it has zero weight in every dimension and its effect is the hold of Section 15.4; with another `result` or `dimension`, or without that record, it is `UNQUALIFIED` and places no hold. A `SECURITY` report from any other reporter, or from a gateway with another `result` or `dimension`, is `UNQUALIFIED`. Under rule 10 a correction of `SECURITY` events is qualified and weighed as a `SECURITY` report from its signer, except that one with `result` `UNKNOWN` retracts them; like every correction, it places and clears no hold (Section 15.4).

## 15. Contextual reputation

### 15.1 Context and dimensions

A role omitted under a declared conformance profile (Section 22.1) is not required of that deployment, and the profile defines what replaces it; this section stays normative for every other deployment.

Reputation is scoped by `ReputationContext`: `tenant_id`, `environment_id`, `agent_id`, `purpose_id`, `action_class`, `resource_class`, and `runtime_class`. A context is defined by an administrator-approved mapping, not by arbitrary labels supplied by the agent.

The mandatory dimensions are `reliability`, `task_quality`, and `policy_adherence`. They MUST remain separate. A gateway MAY use a published composite for ranking, but MUST retain dimension values and MUST NOT use a composite to conceal a security hold or missing evidence.

A successful invoice-reader history does not automatically become a payroll-writer history. Cross-context transfer is allowed only through a versioned, evaluated transfer policy that discloses source contexts and discounts confidence. The baseline does not transfer positive evidence between contexts.

### 15.2 Snapshot

A `ReputationSnapshot` is a signed, audience-specific artifact with subject and holder binding, context, values, evidence cutoff, provenance digest, scoring artifact digest, and security status. The baseline expiry is at most 300 seconds. A snapshot is mapped to the profile at `/attributes/reputation`; the complete value or any required subfield MUST match the signed snapshot value.

`ReputationValue.provenance_digest` is `object_digest` (Section 7.4) of a `ProvenanceManifest` with these members:

| Member | Content |
|---|---|
| `qualified_event_ids` | Sorted array of `[iss, jti]` string pairs, one for each qualified `OutcomeReport` that contributes to the snapshot's values (Section 14.3). |
| `superseded_event_ids` | Sorted array of `[iss, jti]` string pairs, one for each report superseded by a correction (Section 14.4). |
| `qualification_policy_id` | Identifier of the qualification policy applied; the baseline is `pact-qualification-v1` (Section 14.6). |
| `scoring_policy_revision` | The value's `scoring_policy_revision`. |
| `evidence_cutoff` | The value's `evidence_cutoff`. |

Each array sorts ascending by `iss`, then by `jti`, comparing strings by UTF-16 code units as RFC 8785 does for property names. A qualified report whose weight is zero (a zero-weight row of Section 14.5, a retracting correction of Section 14.6 rule 10, or Section 14.6 rules 8 and 9) contributes no value and is not listed. For each dimension, `qualified_events` is the number of listed reports with that `dimension` and `independent_tasks` is the number of distinct independence groups among them; the per-group cap of Section 15.3 limits the weight a group contributes, not the reports listed. The manifest is not a wire object: it is not signed, is not carried in the snapshot, and has no schema definition. The reputation service MUST be able to produce it to an authorized auditor.

`score_bps` and `confidence_bps` are integers in `0..10000`. A score describes the specified dimension, not a universal probability of trustworthiness. Confidence describes the scoring model's stated evidence strength; a model claiming probabilistic calibration MUST supply calibration evidence. Appendix E (informative) describes the content of that evidence. `independent_tasks` and `qualified_events` MUST be disclosed with each dimension.

The validator MUST reject a snapshot from the wrong realm, context, holder, audience, active scoring-policy epoch, or subject. It checks the current applicable security hold separately even when the snapshot is fresh.

### 15.3 Baseline scoring: `beta-decay-v1`

The baseline continuously updates three independent weighted success/failure models. It is a transparent starting model, not a claim of empirical calibration. Appendix E (informative) describes how to evaluate the thresholds and evidence ages that rely on its output.

For each dimension at evaluation time `t`:

`alpha = 1 + sum(w_i * 2 ** (-(t - observed_at_i) / 2592000))` over qualified successes.

`beta = 1 + sum(w_i * 2 ** (-(t - observed_at_i) / 2592000))` over qualified failures.

`score_bps = floor(10000 * alpha / (alpha + beta))`.

`effective_weight = alpha + beta - 2`.

`confidence_bps = floor(10000 * effective_weight / (effective_weight + 20))`.

The half-life is 30 days. Empty history produces score 5000 and confidence 0. `UNKNOWN` and `NOT_APPLICABLE` contribute zero weight. At most one positive weight unit per independent native task group per dimension is permitted. The cap applies to the decayed sum: in each dimension the successes of one group add to `alpha` the lesser of 1 and the sum of their `w_i * 2 ** (-(t - observed_at_i) / 2592000)`, not one undecayed unit and not the first success alone. Normal attributable failure has weight 1; weight up to 5 requires an explicitly approved severity rule. Repeated reports of the same failure are not independent failures.

An identity or credential check is not a task group. Artificially subdividing a task, cycling keys, or repeated fast-path admission cannot accumulate positive weight. The authoritative task/group attribution and reporter independence rules MUST be configured before the baseline can produce nonzero confidence.

Numeric calculations MUST use at least IEEE 754 binary64 precision and the stated floor operation. The signed reputation service output is authoritative for admission; verifiers do not substitute independently rounded values. Implementations testing recomputation SHOULD allow one basis point of numerical tolerance. Promotion policies MUST use an explicit margin and MUST NOT rely on a rounding-boundary equality.

### 15.4 Security status and cold starts

Security status is `CLEAR`, `CAUTION`, `HOLD`, or `UNKNOWN`. `CLEAR` means no applicable known hold under current authoritative checks; it does not certify benign behavior. A `HOLD` is independent of statistical score and cannot decay away. A hold is the agent's: a snapshot of that agent reports it in every context and under every holder key, including a key enrolled after the hold (Section 6.4). `hold_refs` lists the `event_id` of each confirmed `SECURITY` report whose hold is active. A `SECURITY` report confirms an incident, and so places a hold, only when it is `QUALIFIED` under the confirmed-incident row of Section 14.5: `result` `FAILURE`, dimension `none`, signed by a registered security authority (Section 14.2) and citing the confirmed incident record of its task and operation; any other `SECURITY` report places no hold. A detected policy violation that a gateway reports (Section 14.5) is a `policy_adherence` failure, not a hold: a gateway escalates a suspected incident to its security authority through its native process, and only that authority's confirmed incident holds. A `REMEDIATION` report names the hold it clears by that `event_id` in `evidence_refs`, beside its completion evidence, and clears it only when its signer is one of the learning policy's `hold_clearance_authorities` (Section 16.5). An authority reports each incident and each remediation under the `task_id` and `operation_id` it concerns: a second `SECURITY` or `REMEDIATION` report from the same authority on the same task and operation repeats the deduplication tuple of Section 14.6 rule 4, is acknowledged `DUPLICATE`, and neither places nor clears a hold. A correction of a confirmed `SECURITY` report (Section 14.6, rules 10 and 12) supersedes it in provenance and leaves its hold in place, whoever signs it and whatever its `result`: `hold_refs` keeps the superseded report's `event_id`, and a `REMEDIATION` names that `event_id`. A hold placed on an observation its authority later withdraws is cleared as any hold is, by a hold clearance authority whose remediation's completion evidence records the withdrawal. A correction is never a clearance.

New identities and unfamiliar contexts use the conservative requirement set, even if their nominal score is neutral. Operators, native workload enrollment, and task provenance provide accountability. Rate limits are abuse controls and MUST NOT be marketed as proof of Sybil resistance. A new DID cannot inherit positive reputation without verified identity continuity.

### 15.5 What reputation may change

Within an authorized learning policy, reputation MAY change required evidence freshness, approval-attestation requirements, runtime-attestation requirements, capability-assessment frequency, routing preference, or eligibility for an already authorized autonomy tier.

It MUST NOT create a native permission, remove an immutable requirement, waive a known security hold, or convert absence of evidence into evidence of safety. Cached checks can be reused only within explicit freshness bounds; the existence of a high score does not waive identity, signature, revocation, context, or native authorization checks.

## 16. Continuous and autonomous learning

### 16.1 Required learning loop

A role omitted under a declared conformance profile (Section 22.1) is not required of that deployment, and the profile defines what replaces it; this section stays normative for every other deployment.

PACT includes continuous evidence ingestion and reputation updating as part of the protocol. Every full implementation MUST support the lifecycle records in this section. An environment may activate `observe` mode or `bounded_autonomous` mode through a signed learning policy; it is not required to permit autonomous relaxation of requirements.

The learning loop is: collect attributable outcomes, qualify and deduplicate them, update contextual reputation, propose a candidate artifact, evaluate it, observe it in shadow mode, promote it within policy, monitor behavior, and roll back when required. An informative diagram of this loop is in [`diagrams/learning-loop.mmd`](diagrams/learning-loop.mmd).

A deterministic scoring update is a valid learning mechanism. Learned statistical models and LLM-assisted assessments MAY be added without changing the requirement that the admission decision executes typed, bounded rules.

### 16.2 Learning policy

A `LearningPolicy` identifies its realm, authorized controller and evaluators, mode, immutable base revision, conservative set, allowed requirement-set IDs, adaptive fields, data qualification policy, training and evaluation rules, release gates, hold-clearance authority, and rollback conditions.

`adaptive_fields` MUST be an explicit allowlist of configurable controls and their bounds. It MUST NOT include native roles, resource ACLs, trusted issuer enrollment, key recovery authority, base identity rules, or native denial handling.

Examples of permitted autonomy include removing a supervisor-approval requirement after sustained independently evaluated performance, requiring fresher runtime evidence after anomalies, or routing a task to a better-qualified agent that already has native access. Such changes are allowed only where the signed policy already authorizes them and all release gates pass.

### 16.3 Candidate artifacts and evaluation

A `LearningArtifact` records its ID and version, model type, content digest, source-data manifest digest, feature schema digest, training configuration digest, evaluation report digest, intended contexts, base revision, parent artifact, and declared output controls.

Artifacts are data/configuration evaluated by installed implementations. An artifact MUST NOT cause unreviewed executable code, arbitrary URLs, or tools to be installed. Model files loaded by the learning system must use an explicitly permitted safe format and authenticated artifact storage.

Private staging of a candidate before registration is outside PACT. Registration is a `POST /pact/v0.1/learning/artifacts` of a signed manifest. The manifest is immutable, and the artifact enters `CANDIDATE` on acknowledgment. `evaluation_report_digest` is the `bytes_digest` of the controller's pre-registration candidate report, which covers training and validation on the controller's own data. That report MUST NOT contain the manifest (no self-reference) and MUST NOT be the sole promotion evidence. Independent evaluator results are referenced by the `evaluation_refs` of the `EVALUATED` `LearningEvent` and by the policy's `immutable_test_suite_digests`. The identity that is evaluated, shadowed, and activated is `artifact_digest` of the manifest's compact JWS, which is the value of `LearningEvent.artifact_digest`.

Any change to model bytes, feature schema, training configuration, intended contexts, or the candidate report requires a new manifest with an incremented `version` and `parent_artifact_digest` equal to the prior manifest's digest; the prior candidate is `RETIRED` by a `LearningEvent`. Re-registration of an identical manifest returns an `Acknowledgment` with status `DUPLICATE`. Registration of the same `artifact_id` and `version` with different content returns `ID_CONFLICT`. Registration of a manifest whose `output_controls` names a control that is not a `control_id` of the policy's `adaptive_fields` is rejected with `LEARNING_REJECTED` (Section 13.4) and the reason code `CONTROL_NOT_ADAPTIVE` (Section 16.5). Registration of a manifest whose `model_type` is not in the policy's `permitted_artifact_types` or whose `implementation_id` is not in its `permitted_implementation_ids` (Section 16.5) is rejected with `LEARNING_REJECTED` and the reason code `IMPLEMENTATION_NOT_PERMITTED`; a manifest that fails both rules lists both codes.

Before promotion, the controller MUST demonstrate:

1. A disjoint or time-separated evaluation set whose provenance and independence are recorded.
2. Tests for native-denial preservation, required-field provenance, cross-tenant confusion, prompt injection in feedback, reputation farming, and security-hold preservation.
3. Performance and calibration metrics appropriate to the claimed output; uncertainty and subgroup/context coverage are disclosed. Appendix E (informative) describes how these metrics are evaluated for reputation thresholds and evidence ages.
4. Minimum independent task coverage and observation duration specified in the learning policy.
5. Shadow comparison against the current artifact, with regression limits and a bounded rollout plan.
6. A known compatible rollback artifact and a conservative fallback when that artifact is unavailable.

The artifact that proposes a change MUST NOT be its sole source of promotion evidence. Evaluation MAY run autonomously, but evaluation criteria, trusted evaluator roles, and immutable tests originate from authorized policy, not from the candidate.

The learning service checks this evidence at two events. An `EVALUATED` event is accepted only when one of its `evaluation_refs` resolves to a result of an evaluator in the policy's `required_evaluator_ids` other than the candidate's controller (the manifest's `iss`) and the event's signer; otherwise it is rejected, with `SELF_EVALUATED` when its references resolve only to results of that controller or signer, and with `GATE_NOT_MET` in every other case. The release gates of the policy (Appendix A.2) are checked when an `ACTIVE` event arrives, and an `ACTIVE` event that fails one is rejected with `GATE_NOT_MET`; an `EVALUATED` event is not rejected for a release gate. A minimum, a shadow duration, and a metric bound are met when the observed value equals them: an `upper` bound when the value is at most the bound, a `lower` bound when it is at least the bound. The shadow duration runs from the service's acceptance of the artifact's `SHADOW` event to its receipt of the `ACTIVE` event, both on the service's clock.

### 16.4 Autonomous promotion

In `observe` mode, candidates and suggested changes are recorded; no active requirement selection changes without a native authorized approval.

In `bounded_autonomous` mode, an authorized controller MAY promote a candidate without per-release human approval when every preauthorized gate passes. The controller emits a signed `LearningEvent` binding policy, candidate, evaluation evidence, previous artifact, rollout scope, effective time, and reason codes.

Requirement relaxation MUST remain within the policy's least restrictive allowed set. Automatic tightening MAY happen more quickly under defined incident or drift triggers, but still uses allowed controls and produces an audit event. Unknown or unsupported model output triggers the conservative set or deferral, never a guessed permissive action.

### 16.5 Consistency, monitoring, and rollback

Each requirement contract pins the learning-policy and artifact digests used to select its requirements. Promotion is an atomic version transition within a realm and policy scope. Concurrent controllers use a compare-and-swap on the expected previous artifact; conflicting transitions are rejected.

Artifacts move through the states `CANDIDATE`, `EVALUATED`, `SHADOW`, `ACTIVE`, `FROZEN`, `ROLLED_BACK`, and `RETIRED`. The permitted transitions are:

| From | To | Path |
|---|---|---|
| `CANDIDATE` | `EVALUATED` | Normal activation |
| `EVALUATED` | `SHADOW` | Normal activation |
| `SHADOW` | `ACTIVE` | Normal activation |
| `ACTIVE` | `FROZEN` | Freeze |
| `ACTIVE` | `ROLLED_BACK` | Rollback |
| `ACTIVE` | `RETIRED` | Retirement |
| `FROZEN` | `EVALUATED` | Reactivation after freeze |
| `SHADOW` | `EVALUATED` | Re-evaluation |
| `CANDIDATE` | `RETIRED` | Retirement |
| `EVALUATED` | `RETIRED` | Retirement |
| `SHADOW` | `RETIRED` | Retirement |
| `FROZEN` | `RETIRED` | Retirement |
| `ROLLED_BACK` | `RETIRED` | Retirement |

The `LearningEvent.transition` enum already covers every target state in this table.

A promotion replaces only the conservative set. An `ACTIVE` event is accepted only while the conservative set is in force in every context of its `scope_contexts`, so its `expected_active_digest` is null (Appendix A.2); an artifact in force in one of those contexts first leaves `ACTIVE` by its own `FROZEN`, `ROLLED_BACK`, or `RETIRED` event. Every state change of an artifact is thus recorded by an event whose `artifact_digest` names it, except the activation of a fallback, which the rollback event names in `activate_artifact_digest`. An artifact is promoted only in contexts it was registered for: an `ACTIVE` event whose `scope_contexts` include a context outside the artifact's `intended_contexts` is rejected with `CONTEXT_NOT_INTENDED`.

The learning service accepts a manifest or lifecycle event only from a signer listed in the `controller_ids` of the installed learning policy; with no policy installed it accepts none, and it rejects the others with `CONTROLLER_NOT_AUTHORIZED`. The compare-and-swap of an event from an authorized signer fails, and the event is rejected with `VERSION_CONFLICT`, when its `policy_digest` is not the digest of the installed policy, when its `artifact_digest` names no registered artifact or one that is not in its `expected_state`, or when the contexts of its `scope_contexts` do not all have its `expected_active_digest` in force, null meaning the conservative set, or, for an event whose `expected_state` is `ACTIVE`, when the artifact is in force in a context its `scope_contexts` omit: an event that leaves `ACTIVE` names every context the artifact is in force in. An artifact in force in several contexts thus leaves `ACTIVE` in all of them at once; an adaptive set returns to one of them only through the fallback the event activates or a later shadow phase and promotion. A rejection with either code lists no other reason code. An event whose `expected_state` and `transition` are not a row of the table above is invalid (Appendix A.2).

A compatible rollback artifact is an artifact that meets all of the following conditions:

1. It has the same `base_revision` and `model_type` as the outgoing artifact.
2. Its `implementation_id` is in the `permitted_implementation_ids` of the `LearningPolicy`.
3. Its state is `EVALUATED` or later, and it has a completed `SHADOW` phase under the current policy digest.
4. Its `intended_contexts` cover the `scope_contexts` of the rollback event.

When no artifact meets all four conditions, the `conservative_set` is used and the `reason_codes` of the rollback event include `FALLBACK_INCOMPATIBLE`. A rollback event whose `activate_artifact_digest` names an artifact that does not meet them is rejected with `FALLBACK_INCOMPATIBLE`; the rollback event that records the conservative fallback carries `activate_artifact_digest` null.

Contract invalidation has two triggers:

- A `ROLLED_BACK` or `FROZEN` event whose `artifact_digest` is D invalidates every outstanding contract whose `learning_artifact_digest` is D, with the code `REQUIREMENTS_CHANGED` (Section 13.4).
- A changed `policy_digest` invalidates every outstanding contract whose `learning_policy_digest` pins the old digest.

After the `exp` of the `LearningPolicy`, `ACTIVE` remains in effect for admission only under a separately current native base policy. No transition except to `FROZEN`, `ROLLED_BACK`, or `RETIRED` is accepted, and a rejected transition carries the reason `POLICY_EXPIRED`.

The baseline reason codes for the `reason_codes` of a `LearningEvent` are:

| Code | Meaning |
|---|---|
| `DRIFT_THRESHOLD` | A drift threshold of the learning policy failed. |
| `REGRESSION_LIMIT` | A regression limit of the learning policy was exceeded. |
| `NATIVE_DENIAL_OVERRIDE` | An artifact output overrode a native denial. |
| `DATA_CORRECTION` | Source data was corrected (`CORRECTION`, Section 14.4). |
| `VERSION_CONFLICT` | The transition was rejected by the compare-and-swap on the expected state, the expected previous artifact, or the policy digest (above). |
| `EVALUATION_GATES_PASSED` | The release gates of the learning policy passed, as in Appendix B.11. |
| `POLICY_EXPIRED` | The transition was rejected because the `LearningPolicy` has expired (above). |
| `FALLBACK_INCOMPATIBLE` | No compatible rollback artifact exists, or the named fallback is not compatible (above). |
| `GATE_NOT_MET` | A release gate of the learning policy is not satisfied: a bound, a minimum duration, or a shadow phase not completed. |
| `SELF_EVALUATED` | The only evaluation evidence comes from the candidate's own controller (Section 16.3). |
| `OBSERVE_MODE` | The policy's `mode` is `observe`, so no activation is accepted without a native authorized approval (Section 16.4). |
| `CONTROL_NOT_ADAPTIVE` | An artifact's `output_controls` names a control outside `adaptive_fields` (Sections 16.2 and 16.3). |
| `CONTROLLER_NOT_AUTHORIZED` | The signer of a manifest or lifecycle event is not one of the `controller_ids` of the installed learning policy, or no learning policy is installed (above). |
| `CONTEXT_NOT_INTENDED` | An `ACTIVE` event names a context outside the artifact's `intended_contexts` (above). |
| `IMPLEMENTATION_NOT_PERMITTED` | A manifest's `model_type` or `implementation_id` is outside the learning policy's `permitted_artifact_types` or `permitted_implementation_ids` (Section 16.3). |

A registration or lifecycle event rejected for a reason of this table returns the transport error `LEARNING_REJECTED` (Section 13.4), whose `extensions.reason_codes` lists the applicable codes of this table, at least one. A message that fails a rule of Section 13.4 or Appendix A.2 before these rules apply, such as an expired, malformed, or duplicate-identifier message, carries that rule's code instead: `EXPIRED`, `CONTEXT_MISMATCH`, `INVALID_MESSAGE`, `INVALID_PROOF`, or `ID_CONFLICT`.

A `CORRECTION` that removes a qualified event from a training manifest MUST trigger re-evaluation of every `ACTIVE` or `SHADOW` artifact whose `source_data_manifest_digest` includes it. Re-evaluation is recorded by an accepted `EVALUATED` event of the artifact with new independent evaluation evidence (Section 16.3): a `SHADOW` artifact takes the `SHADOW` to `EVALUATED` row of the table above, and an `ACTIVE` artifact reaches `EVALUATED` through `FROZEN`. The requirement also ends when the artifact is `RETIRED`. Until it ends, the artifact's earlier evaluation does not count: an `ACTIVE` event for it is rejected with `GATE_NOT_MET`, and it does not meet condition 3 of a compatible rollback artifact.

Rollback records a transition on the outgoing artifact and activation of a previously evaluated compatible artifact in one atomic release event. A frozen artifact requires a new successful evaluation and shadow phase before reactivation. An initial conservative baseline requires recorded administrative activation and conformance evidence; it cannot be bootstrapped by the proposing agent.

Separate artifacts MAY implement reputation scoring and requirement selection. A snapshot pins its scorer; a contract pins its selector. The learning policy specifies the permitted artifact types and installed implementation identifiers. Model manifests and policy artifacts have a maximum validity of 30 days in the baseline; they require authenticated renewal. Lifecycle events have a maximum validity of 300 seconds. Expired policy authority freezes autonomous changes and permits only a separately current native base policy or deferral.

Active controllers MUST monitor the policy's drift, error, security, and data-quality thresholds. A failed threshold triggers the configured freeze, tightening, or rollback. Rollback restores a known compatible artifact or the conservative set, invalidates affected outstanding contracts, and records its reason and affected contexts.

Neither rollback nor data decay may erase a security hold. Clearing a hold requires its configured native authority or a separately preauthorized remediation workflow with independently verifiable completion evidence.

### 16.6 LLM-assisted assessment

An LLM MAY generate capability exercises, summarize evidence, classify suspected issues, or propose requirement changes. Its output is untrusted until validated against the typed schema and authorized policy. An agent's correct answer demonstrates at most performance on that assessment; it does not establish identity or authorization.

Assessment prompts, model/version, rubric, input digest, output, and uncertainty MUST be attributable where they affect reputation. Assessment frequency and weight are capped. `AMBIGUOUS` assessment results do not automatically penalize reputation. Prompt text cannot override issuer authority, immutable rules, or native access decisions.

## 17. Native gateway integration contract

### 17.1 Required adapter capabilities

An enforced adapter MUST expose or implement the following logical functions through the environment's existing interfaces:

| Function | Input | Output / requirement |
|---|---|---|
| `authenticate_native` | Actual request | Authenticated principal and workload context, or native denial. |
| `resolve_agent_binding` | Realm, authenticated workload, and the agent ID the request names | The enrolled binding of that agent ID to that workload in that realm: operator binding, holder key, and current binding status; `UNKNOWN` when no such enrollment exists, together with whether that agent ID is enrolled for another workload of the realm. |
| `map_operation` | Actual request and mapping version | Authoritative `OperationContext`; all consequential request data is covered. |
| `read_native_claim` | Approved native path and context | Authoritative value, original observation time, status time, and source ID. |
| `check_context` | Installed check ID; the authenticated principal and workload context that `authenticate_native` returned, with its authenticated attributes; the agent binding that `resolve_agent_binding` returned; intent; operation; evidence references | `PASS`, `FAIL`, or `UNKNOWN`, with a reason. |
| `authorize_native` | Original principal and actual operation | Existing policy decision; PACT cannot rewrite a denial. |
| `record_outcome` | Attributable decision/execution observation | Signed outcome or declared absence of execution visibility. |

These are behavioral contracts, not required new REST APIs. Existing gateway plugins, policy hooks, middleware, directory lookups, or native claims can satisfy them.

The agent ID only selects among the enrollments of the authenticated workload; it never selects an enrollment of another workload, and a workload alone never names an agent. The holder-key proof then binds the request to the selected enrollment (Section 6.2). When the profile in use does not support workloads shared by several agents, a workload with more than one enrollment in force is a configuration error: the function returns no binding and reports `UNSUPPORTED_REQUIREMENT`.

The principal and the binding that `check_context` receives are the ones this evaluation established: the principal of Section 12.1, as `authenticate_native` returned it with its authenticated attributes, and the binding verified in Section 11.3, step 2. A check that compares the agent or the principal (Sections 17.3.1 and 17.5) compares against these inputs, never against a value the presentation, the profile, or an evidence artifact carries, and it does not re-judge the binding's status, which Section 11.3, step 2 decided. A check that needs neither ignores them. `native-principal-binding-v1` is evaluated by the validator (Section 17.5) and is not run through `check_context`.

### 17.2 Role and field mapping

Mappings MUST be explicitly configured and versioned. For example, the profile path `/attributes/environment/roles` may map to the gateway's authenticated `groups` claim through an administrator-approved translation. A role name from one issuer or tenant MUST NOT match a same-spelled role from another by accident.

The adapter MUST document whether values are current authoritative state or cached credential snapshots. Requirement freshness must be achievable by the configured source. If a source cannot establish the demanded freshness, the result is deferred or the requirement is changed by an authorized policy publisher; the adapter cannot claim a check it did not perform.

### 17.3 Approvals and execution controls

A required approval is an existing native approval reference or trusted attestation bound to agent, principal, purpose, operation or bounded native task, and validity. A conversational statement or model-generated confirmation is not approval evidence.

Human approval and exception workflows are external to PACT. PACT does not define how approvals are requested, routed, granted, or revoked, or what an exception means. It accepts evidence of an approval and verifies its issuer authority, scope, validity, and current status. An authorized exception is considered only through the environment's current native authorization policy. PACT evidence of an exception neither grants nor implies it.

The gateway remains responsible for resource enforcement, row/field permissions, transaction limits, native revocation, and prevention of a broadly privileged connector from becoming an unintended deputy. PACT's integration guarantee is that it supplies verified required context and preserves those checks. It does not implement those controls in the profile itself.

### 17.3.1 Approval, exception, and activation check results

An approval-class check is an installed check, named in `context_checks` (Section 9.3), that establishes the native state of an approval, exception, or activation. Its `check_context` result (Section 17.1) is recorded as a `CheckResult`. The following table is normative. The agent and the principal of the scope comparison are the inputs of `check_context` (Section 17.1). It maps the native state established by the check to the `CheckResult.result`, the admission decision, and the stable `reason_code`.

| Native state established by the check | `CheckResult.result` | Admission decision | `reason_code` |
|---|---|---|---|
| Valid and applicable | `PASS` | Contributes to `ADMISSIBLE` | `REQUIREMENT_SATISFIED` |
| Pending: a legitimate request exists for this exact scope and is undecided | `UNKNOWN` | `DEFERRED` | `APPROVAL_PENDING` |
| Required reference absent | `FAIL` | `INADMISSIBLE` | `MISSING_FIELD` |
| Rejected | `FAIL` | `INADMISSIBLE` | `APPROVAL_REJECTED` |
| Expired | `FAIL` | `INADMISSIBLE` | `APPROVAL_EXPIRED` |
| Revoked | `FAIL` | `INADMISSIBLE` | `APPROVAL_REVOKED` |
| Approver lacks authority | `FAIL` | `INADMISSIBLE` | `APPROVAL_AUTHORITY_MISMATCH` |
| Scope mismatch: agent, principal, purpose, operation, task, amount, or resource | `FAIL` | `INADMISSIBLE` | `APPROVAL_SCOPE_MISMATCH` |
| Status source unavailable | `UNKNOWN` | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` |
| None: the check was not evaluated (Section 12.1) | `UNKNOWN` | As the other results fix it (Section 11.4), or `DEFERRED` for a cancelled or expired evaluation (Section 12.2) | `NOT_EVALUATED` |

These rules apply to approval-class checks:

- `UNKNOWN` for a pending approval is permitted only when the adapter has established that a legitimate request exists for this exact scope; anything else is a demonstrated `FAIL`.
- An `INADMISSIBLE` decision caused by a rejected, expired, or revoked approval is not agent misconduct (Section 14.3).
- An approval requirement that is part of `base_revision` MUST NOT appear in `LearningPolicy.adaptive_fields`. Only a control listed in `adaptive_fields` with `allow_relaxation` true may be relaxed; otherwise reputation cannot change it (Sections 15.5 and 16.2).
- A native exception changes only the `authorize_native` result. Evidence of kind `approval` satisfies only the field rule or check that names it. See Section 17.3.

### 17.4 Data-flow limitations

A requirement such as `runtime.isolation = managed` may demand a trusted runtime attestation. It does not itself enforce egress restrictions or erase data after use. Gateways MUST distinguish verified runtime facts from actual guarantees provided by that runtime. If a claimed purpose restriction depends on sandboxing or output controls, the environment must supply and verify those controls before representing the restriction as enforced.

The baseline defines two check classes for data-use controls:

- Runtime-evidence checks: field rules on `/attributes/runtime` with source evidence. They establish a verified fact only.
- `execution-control-v1`: an installed check that returns `PASS` only when the native containment control named by the mapping, such as an egress allowlist, an output filter, or a sandbox policy, is verified installed and current for this exact operation. It returns `UNKNOWN` otherwise.

A deployment MUST NOT describe a purpose or data-use restriction as "enforced" unless `execution-control-v1` is in the effective contract's `context_checks` and its result for the operation is `PASS`. Absent that, the deployment's integration profile labels the restriction "attested-only" and records post-read residual limits. Receipts MUST NOT name a runtime-evidence check as a containment control.

### 17.5 Actor binding and execution identity

The table lists each actor in an operation, how it is bound, and the source that establishes the binding. It adds no field.

| Actor | Binding | Source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id` | `authenticate_native` (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source` (Sections 10.1 and 14.5) |
| Native delegation | `/attributes/delegation/authority_ref` | Source `native`, or `evidence` of kind `delegation`; check `native-delegation-v1` |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2) |
| Downstream executor | The identity under which `authorize_native` and the resource operation run | Check `execution-identity-v1` |

Every actor transition is native. PACT records and checks a transition and never mints it.

`native-principal-binding-v1` is a baseline installed check (Section 9.3) that the validator evaluates from inputs it already holds: it returns `PASS` with reason code `REQUIREMENT_SATISFIED` when the principal the presentation claims to act for, the profile value at `/attributes/environment/principal_id`, equals the `OperationContext.principal_id` that `authenticate_native` established for the actual request; `FAIL` with reason code `CONTEXT_MISMATCH` when they differ; and `FAIL` with reason code `MISSING_FIELD` when the profile carries no such value. It consults no native source and is not an input of `check_context` (Section 17.1). The principal at contract issuance needs no separate comparison: it is bound by the contract's `operation_digest` and compared in Section 11.3, step 5. A native credential renewed or refreshed between issuance and evaluation passes both comparisons when the identifier it yields is unchanged.

`execution-identity-v1` is a baseline installed check (Section 9.3). The installed mapping declares the executor identity class for each (principal, task, operation) as one of `delegated-user`, `registered-app-executor`, `dedicated-role`, or `impersonated-user`. The check returns `PASS` only when the executor that will run the operation equals the declared class and binding. Any fallback to a broader credential returns `FAIL` with reason code `EXECUTOR_MISMATCH`. An indeterminate executor returns `UNKNOWN` with reason code `DEPENDENCY_UNAVAILABLE`, which yields `DEFERRED`. `authorize_native` MUST be invoked with the original principal, never the executor's own authority.

These adversarial cases have the following results:

- Principal substitution: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- Changed task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- Stale or revoked delegation: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.

`EXECUTOR_MISMATCH` and `TASK_MISMATCH` are check reason codes recorded in the `CheckResult` (Section 12.1), like the approval codes of Section 17.3.1; they are not transport codes of Section 13.4.

Section 14.2 governs how outcome reports reference the actual executor identity.

## 18. Revocation, freshness, and availability

The gateway MUST track the current status of agent/key bindings, trusted issuers, requirement revisions, security holds, and accepted evidence according to its configured sources. Profile expiration and statistical decay do not substitute for revocation.

Each required source declares a maximum staleness in the contract. The baseline default is 30 seconds for cached evidence-status checks; sensitive native authority or hold checks SHOULD use zero. Native authorization follows its own, separately documented consistency guarantees. PACT MUST NOT promise instantaneous global revocation when the underlying identity or policy system is eventually consistent.

Revocation acknowledged by the gateway prevents subsequent admissions in that gateway's consistency domain. An already executed operation cannot be undone by revoking its receipt. In-flight native operations follow native cancellation and transaction semantics, which must be documented by the adapter.

If a required source, replay store, hold store, active policy registry, or receipt store is unavailable, enforced admission fails closed with `DEFERRED`. A reputation dependency may fall back to the explicitly configured conservative set only if the policy permits it and the resulting contract contains all corresponding requirements. It cannot reuse an expired favorable score.

## 19. Privacy and evidence protection

Gateways MUST request only fields and evidence needed for their declared admission requirements. Profiles, task descriptions, native memberships, and reputation history SHOULD be disclosed to the intended gateway only. A gateway MUST enforce native authorization on profile, outcome, receipt, and reputation queries.

Receipt and reputation queries from another tenant or an unauthorized principal MUST return the non-disclosing not-found response of Section 13.2.

PACT signatures provide integrity and attribution, not confidentiality. TLS is mandatory on network paths. Stored artifacts containing sensitive data require access controls and encryption appropriate to the environment. Logs MUST NOT contain native access credentials or private keys. Raw task contents SHOULD be kept out of reputation records; an authorized evidence reference and content digest are preferred.

Receipts, outcome reports, and logs MUST NOT contain any of the following credential material:

- the headers `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `pact-presentation`, and `pact-admission`;
- any header named in the gateway's `protected_header_names`;
- private JWK parameters `d`, `p`, `q`, `dp`, `dq`, `qi`, and `k`;
- native tokens and passwords.

`OutcomeReport.details` MUST NOT carry raw task content; use a content digest and an `evidence_refs` entry instead.

An evidence digest is not necessarily anonymous: predictable values may be guessable. Systems MUST protect the associated context and avoid exposing cross-tenant correlators. Retention, correction, deletion, and model-data lineage policies MUST be documented. Retention of signatures does not justify retaining all underlying user content indefinitely.

Section 14.4 requires deletion of evidence to have a defined effect on derived data. Deleting an observation under retention or privacy policy MUST:

1. remove it from all later recomputation;
2. leave a tombstone in the lineage that carries the event identifier and digest only;
3. produce a new snapshot whose `provenance_digest` differs from that of the snapshot computed before the deletion; and
4. flag every artifact whose `source_data_manifest_digest` included it (Section 16.5).

## 20. Abuse resistance and resource limits

### 20.1 Baseline limits

| Item | Baseline limit |
|---|---:|
| Decoded presentation, including embedded artifacts | 256 KiB |
| Individual signed evidence or reputation artifact | 32 KiB decoded payload |
| Profile JSON | 32 KiB |
| Evidence artifacts in a presentation | 32 |
| Field rules in a contract | 128 |
| JSON nesting depth | 16 |
| Resources in an operation | 256 |
| Human-readable description | 4096 UTF-8 bytes |
| Contract validity | At most 60 seconds |
| Presentation validity | At most 60 seconds |
| Admission receipt validity | At most 60 seconds after issuance |
| Evaluation time | At most 30 seconds and no later than input expiry |
| Profile lifetime | At most 24 hours |
| Evidence artifact lifetime | At most 1 hour; individual rules can require fresher facts |
| Reputation snapshot lifetime | At most 300 seconds |
| Outcome report validity | At most 300 seconds |
| Clock skew | At most 5 seconds; no expiry grace |
| Transport frame (profile-defined) | The declared frame limit MUST be at least 360448 bytes (352 KiB) and at most 1048576 bytes (1 MiB). The minimum is `ceil(262144 x 4/3)` = 349526 bytes for the encoded payload plus 10922 bytes for the JOSE header, signature, and envelope: 349526 + 10922 = 360448 = 352 x 1024. The transport profile declaration advertises the declared limit as `max_frame_bytes` of its `TransportDeclaration` (Appendix A.3). `max_envelope_presentation_bytes` in the limits map still bounds the decoded presentation the envelope carries and stays at most 262144. |

Metadata MAY advertise tighter limits. Larger limits require a negotiated profile and explicit resource-budget review. Validators check size, depth, and allowed algorithms before expensive cryptographic, registry, or model operations. The envelope transport MUST support the advertised limits even if ordinary HTTP headers do not.

A gateway advertises its limits in the `limits` object of its `GatewayMetadata` (Section 13.1). It MUST advertise every key in the first table below and, for each transport listed in `presentation_transports`, the matching key in the second table. Each advertised value MUST be no larger than the baseline value shown, except `replay_retention_seconds`, whose baseline value is a minimum.

| Key | Baseline value | Corresponding limit |
|---|---:|---|
| `max_presentation_bytes` | 262144 | Decoded presentation, including embedded artifacts |
| `max_artifact_payload_bytes` | 32768 | Individual signed evidence or reputation artifact |
| `max_profile_bytes` | 32768 | Profile JSON |
| `max_evidence_artifacts` | 32 | Evidence artifacts in a presentation |
| `max_field_rules` | 128 | Field rules in a contract |
| `max_json_depth` | 16 | JSON nesting depth |
| `max_resources` | 256 | Resources in an operation |
| `max_description_bytes` | 4096 | Human-readable description |
| `contract_validity_seconds` | 60 | Contract validity |
| `presentation_validity_seconds` | 60 | Presentation validity |
| `evaluation_seconds` | 30 | Evaluation time |
| `clock_skew_seconds` | 5 | Clock skew |
| `replay_retention_seconds` | At least 65 | Replay record retention (Section 7.5) |

| Presentation transport | Key | Baseline value |
|---|---|---:|
| `header` | `max_header_presentation_bytes` | 262144 |
| `adapter-envelope` | `max_envelope_presentation_bytes` | 262144 |
| `gateway-evaluate` | `max_evaluate_presentation_bytes` | 262144 |

A transport whose key is below the size of a valid maximal presentation (`max_presentation_bytes` as advertised) MUST NOT be the only advertised presentation transport. Appendix F gives an informative template for reporting the capacity and outage behavior measured against these limits.

### 20.2 Abuse controls

Deployments MUST enforce quotas per authenticated workload, operator/tenant, and IP as appropriate. Workload and tenant quotas prevent rotating a cheap identifier from bypassing all limits. The protocol does not prescribe a universal numerical request rate because legitimate workloads differ.

Untrusted URLs in profiles, evidence, feedback, or artifact manifests MUST NOT cause automatic network fetches. Evidence and model references resolve only through configured stores and issuer adapters. Callback delivery is outside the baseline. Model evaluation has independent budgets and timeouts so an attacker cannot turn admissions into unbounded inference work.

Security-relevant parsers MUST reject duplicate JSON keys and ambiguous encodings before interpreting values. Signature and audience checks precede trust in embedded claims. Protected endpoints must not depend on whether a caller labels its input a harmless capability exercise.

### 20.3 Threat coverage and residual limits

| Threat | Protocol control | Remaining dependency |
|---|---|---|
| Forged roles or operator claims | Claim-scoped issuer trust or comparison with native authoritative context | Integrity of the native identity system and issuer |
| Stolen profile/evidence | Holder binding and per-request signed presentation | Protection of the enrolled private key |
| Replayed presentation | Fresh, operation-bound nonce with atomic consumption | Shared store availability and correct clocks |
| Reused receipt at another gateway/action | Audience, principal, intent and operation binding; one-time consumption | Correct native request mapping |
| Reputation farming | Qualified task outcomes, independence grouping, caps and deduplication | Honest task attribution and trustworthy reporters |
| Sybil identities | Native enrollment, operator accountability, conservative cold start | Enrollment assurance; no universal Sybil-prevention claim |
| Compromised high-reputation agent | Security holds, revocation, current identity and native authorization checks | Incident detection and propagation latency |
| Feedback/model poisoning | Provenance, trusted evaluators, immutable tests, shadowing and rollback | Adequacy of evaluation and monitoring |
| Purpose laundering | Signed purpose, request binding, installed purpose/context checks | Native policy semantics and execution controls |
| Post-read misuse of data | `execution-control-v1` `PASS` required for "enforced" label; others labeled "attested-only"; runtime evidence establishes a verified fact only | Actual runtime isolation, egress and downstream controls; post-read residual limits recorded for every "attested-only" restriction |

## 21. Versioning and extensibility

Specification patch releases correct text without changing accepted wire behavior. `pact_version` identifies the wire major/minor; this draft uses `0.1`. Implementations MUST reject unsupported versions and MUST NOT silently downgrade to unsigned messages or Airlock 0.1 behavior.

Extensions use administrator-approved, collision-resistant identifiers: identifiers beginning `pact-` are reserved for this specification, and every other extension identifier MUST be an HTTPS URI under the publisher's control. The first-party extension identifiers are `pact-conformance-profile-v1` and `pact-transport-profile-v1`, and a conformance or transport profile declaration uses them. An extension affecting admission MUST be present in both gateway metadata and the effective contract. Unknown required extensions yield `DEFERRED`; they are never ignored.

A conformance profile or transport profile declaration is an extension affecting admission. It MUST appear in gateway metadata (`extensions` and `extensions_supported`), in the `extensions` of the effective `RequirementContract`, and in the `extensions` of the `AdmissionAttestation`. A profile has no URI: it is identified by its kind, id, and version. A holder that does not support the extension MUST defer (Section 7.1) and MAY refuse by local policy.

The initial profile has no federation of native authority. Cross-environment evidence is accepted only if the receiving gateway explicitly trusts the issuer for the relevant claim, scope, audience, and source freshness. Reusing a cryptographic identity across environments does not transfer roles or permissions. A future federation profile must define its own authority and context translation rules.

## 22. Conformance

### 22.1 Role claims

| Conformance role | Mandatory capabilities |
|---|---|
| PACT Holder 0.1 | Profile construction, contract verification, required evidence handling, key proof, request binding, strict version negotiation. |
| PACT Gateway 0.1 | Native-bound contract issuance or trusted publisher integration, enforced admission path, native authorization preservation, receipt validation, revocation/hold checks, outcome reporting. |
| PACT Validator 0.1 | All mandatory validation checks, strict cryptography and parsing, atomic replay controls, signed receipts for completed authenticated evaluations. |
| PACT Reputation 0.1 | Qualified outcome ingestion, contextual scoring, confidence/provenance, corrections, signed snapshots, security-status integration, anti-farming controls. |
| PACT Learning 0.1 | Signed learning policies/artifacts/events, evaluation and shadow lifecycle, bounded autonomous operation when enabled, monitoring and rollback. |

A full PACT deployment includes all roles, whether provided by one implementation or connected services. Reputation and learning are core protocol components. A deployment that omits the Reputation or Learning role MUST declare a conformance profile (Section 21) that permits exactly that omission and MUST describe itself as that profile; it MUST NOT describe itself as a full PACT deployment. Any other omission, or an omission without a declared profile (for example, an admission-only implementation that declares none), is a partial role implementation and MUST be described as such. The conformance profiles are the entries of kind `conformance` in `profiles/registry.json`. Activation of autonomous policy changes remains an explicit environment policy choice.

Transport adapters and transport profiles declare their exact native-protocol versions, mapping revisions, profile ids, and profile versions. Observation-mode deployments MUST disclose that native access is not conditioned on PACT admission.

### 22.2 Required negative and behavioral tests

Before claiming a role implementation conforms, it MUST pass all applicable cases:

| Test | Expected result |
|---|---|
| Validly signed profile containing a self-asserted privileged role | Does not satisfy an authoritative role requirement. |
| Valid evidence from an issuer unauthorized for the claim path | Reject the evidence. |
| Another agent's valid evidence or an old holder key | Reject subject/holder binding. |
| Correct signature but wrong tenant, environment, audience, principal, or operation | No admission. |
| Modified body, query, consequential header, action, or resource | Context mismatch. |
| Duplicate JSON keys, non-finite values, invalid Unicode, unsupported `typ` or algorithm | Reject before interpreting authority. |
| Unknown field-rule schema keyword or required extension | No permissive fallback. |
| Same nonce submitted concurrently to different replicas | At most one presentation is accepted for evaluation. |
| Old presentation after cache eviction | Reject by time/nonce bounds. |
| Reuse of a positive attestation for another request or a second handoff | Reject. |
| Valid PACT admission with native authorization denial | No execution. |
| Required source or replay store unavailable | Defer or use an explicitly allowed conservative contract; never fail open. |
| Seven or seven thousand successful admission-only checks | No positive task-performance reputation. |
| Agent changes task identifiers or rotates keys to multiply feedback | No automatic independent-task credit or inherited trust. |
| Duplicate or superseded task outcome | No double contribution; corrected snapshots reflect the change. |
| High-quality history in one resource/action context | No automatic transfer into an unrelated context. |
| Passage of time after a confirmed incident | Security hold remains until authorized remediation. |
| Missing evidence or environmental outage | No automatic misconduct penalty. |
| Learning model requests a new role or weaker immutable identity check | Reject the proposed change. |
| Candidate evaluates itself as safe without independent gates | Cannot promote. |
| Two controllers promote from the same previous version | One succeeds; the other records a version conflict. |
| Rollback after an adverse outcome or poisoned-data correction | Restore compatible policy/artifact, invalidate affected contracts, preserve holds. |
| LLM assessment answer contains instructions to ignore policy | Treat as assessment data; no authority change. |
| Expired or cancelled authenticated evaluation | Terminal deferred receipt; no positive admission. |

A conformance profile classifies every row of this table as `applies`, `replaced`, or `not applicable`. Each `replaced` or `not applicable` row MUST name a replacement test that is no weaker than the original intent. A profile claim without a complete classification is invalid.

Cross-language tests MUST cover RFC 8785 Unicode ordering and number serialization, JOSE signature encoding, JWK thumbprints, and every supported native operation mapping. A parser's happy-path schema validation alone does not establish conformance.

## 23. Design decisions and open standardization work

The draft makes the following deliberate choices: native authorization remains authoritative; profiles are requirement-driven disclosure views; positive admission is single-operation evidence; core artifacts use JWS rather than a custom VC proof; reputation is contextual and evidence-based; learning is continuous but policy-bounded; and the baseline requires online native enforcement.

Open standardization work includes registering identifiers if the protocol advances, publishing an interoperable test-vector suite, defining independently reviewed native adapter profiles, empirically validating scoring and release thresholds, and specifying federation only if deployment evidence justifies it. Appendix E gives an informative protocol for evaluating reputation thresholds and evidence ages. Appendix F gives an informative template for reporting measured capacity and outage behavior. These are release work items, not permission to weaken a normative requirement in the meantime.

No universal reputation threshold, guarantee of LLM correctness, or proof of internal intent is claimed. Environment-specific release thresholds MUST be explicit in the signed learning policy. A deployment cannot conceal missing policy choices behind a generic “trusted agent” label. A conformance profile narrows scope; it is not permission to weaken a normative requirement, and an undeclared profile is the generic “trusted agent” label this section prohibits.

## 24. References

The following standards are referenced for specific mechanisms. PACT does not claim their endorsement. Adapter implementations must pin the versions they implement.

| Reference | Use |
|---|---|
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) | Requirement language. |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) | JWS Compact Serialization. |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518), [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | Keys, algorithms, and JWT claims. |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK thumbprints. |
| [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) and [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) | Optional Ed25519 key representation and fully specified JOSE algorithm. |
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) | JWT validation practices and token-type separation. |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) | Canonical JSON for object digests. |
| [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) | JSON Pointer claim paths. |
| [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12) | Message structure and field-rule schemas. |
| [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) | HTTP problem details. |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) | Native OAuth integration security context. |
| [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) | Related structured authorization work; PACT does not replace it. |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | Related OAuth proof-of-possession mechanism. PACT presentation proof is separately specified and is not called DPoP. |
| [W3C DID Core](https://www.w3.org/TR/did-core/) and [did:key method](https://w3c-ccg.github.io/did-key-spec/) | Optional identifier/key-binding context. |
| [W3C Data Integrity EdDSA Cryptosuites](https://www.w3.org/TR/vc-di-eddsa/) | Actual proof-suite requirements for optional VC adapters. |
| [MCP authorization, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) | Existing MCP authorization model; pinned adapter reference (legacy era). |
| [MCP basic, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic) | Existing MCP base protocol; pinned adapter reference (modern era). |
| [MCP transports, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports): [stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio) and [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) | Existing MCP transports; pinned adapter reference (modern era). |
| [MCP authorization, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) and its [security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) | Existing MCP authorization model; pinned adapter reference (modern era). |
| [MCP tools, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Existing MCP tool methods; pinned adapter reference (modern era). |
| [MCP tasks extension](https://modelcontextprotocol.io/extensions/tasks/overview) | Existing MCP tasks extension, `io.modelcontextprotocol/tasks`; pinned adapter reference (modern era). |
| [A2A specification, 0.3.0](https://a2a-protocol.org/v0.3.0/specification/) | Existing A2A authentication/authorization model; illustrative pinned adapter reference. |
| [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) | Informative architecture context for identity, policy, and enforcement boundaries. |
| [NIST AI RMF 1.0](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf) | Informative context for model evaluation, governance, and monitoring. |

## Appendix A. Normative schemas and additional semantic validation

### A.1 Schema conventions

The schema in A.3 defines decoded signed payloads and unsigned transport wrapper objects. It does not validate a compact JWS string's cryptography. A receiver first uses the protected `typ` to select the corresponding definition and applies that definition after secure parsing and signature processing. It MUST also apply the semantic rules in this document.

All listed object properties are required unless omitted from that object's `required` array. `extensions` is optional and defaults to an empty object. Core objects reject additional fields. `AgentProfile.attributes` and explicitly declared configuration/metric maps are data namespaces whose keys are controlled by the effective requirement or learning policy. Their openness does not allow unknown protocol fields elsewhere.

The schema's URN identifies this draft schema and is not a network retrieval endpoint. The schema is a single standalone file. All `$ref` references are local.

Field-rule `schema` objects use this restricted Draft 2020-12 keyword set: `type`, `enum`, `const`, `properties`, `required`, `additionalProperties`, `items`, `minItems`, `maxItems`, `uniqueItems`, `contains`, `minContains`, `maxContains`, `minLength`, `maxLength`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `allOf`, `anyOf`, `oneOf`, and `not`. Nested schemas obey the same restriction. Boolean schemas are supported. Other keywords, including `$ref`, `pattern`, and unenforced `format` annotations, are rejected in field rules. Publishers MUST impose finite evaluation budgets and the document's depth limits.

### A.2 Source-specific and cross-object rules

- `self` field rules have empty `allowed_issuers`, `native_path = null`, `comparison = equal`, and both age limits zero. This does not satisfy a rule that requires authority.
- `evidence` rules have a nonempty `allowed_issuers` array and `native_path = null`.
- `native` rules have empty `allowed_issuers` and a nonempty `native_path` pointing to an installed mapping.
- A `self` rule is invalid, and the contract is rejected with `INVALID_MESSAGE` (Section 13.4), when its `path` is `/attributes/environment/principal_id`, or is `/attributes/delegation` or `/attributes/reputation` or a descendant of either (Section 9.2). A publisher MUST also refuse a `self` rule on any path that its installed mapping (Section 17.2) classifies as identity, tenant membership, role membership, delegation, or approval; the integration profile lists those paths.
- Common signed claims satisfy `iat < exp` and `nbf < exp`; artifact-specific lifetimes and subject/audience rules also apply. All `jti` and nonce values contain at least 128 bits of cryptographically secure randomness.
- Profile `created_at < expires_at`, `created_at <= now + clock_skew`, and `now < expires_at`; the holder, subject, realm, and all required observations must match the signed contract and current native context. No source observation or status-check time may be later than `now + clock_skew`. A profile that breaks `now < expires_at` fails the `profile-validity` check with `STALE_EVIDENCE`; one that breaks the other two bounds or the 24-hour lifetime of Section 8.1 fails it with `INVALID_CLAIM`; one whose `agent_id`, `tenant_id`, or `operator_id` is not the bound agent's, the realm's, or the enrolled operator's fails it with `CONTEXT_MISMATCH`.
- `RequirementContract.contract_id` is an opaque correlation identifier; `requirements_digest` always hashes the exact signed contract, including its nonce. `operation_digest`, `intent_digest`, and `profile_digest` use `object_digest` of the corresponding complete objects.
- Evidence claims may target exactly the configured paths or their explicitly allowed descendants. JSON Pointer escaping follows RFC 6901. `operator_id` is compared with the enrolled operator binding; it cannot be changed by self-assertion.
- Reputation `value.context` must match the installed mapping for the actual operation. Its `holder_jkt` and subject match the profile. The snapshot's value is the authoritative value for `/attributes/reputation` and descendants. Evidence issuers for reputation must specifically be configured reputation services.
- A reputation value's `evidence_cutoff` cannot be later than its issuance or the validator's current time plus allowed skew. The snapshot must carry a scoring-policy revision the gateway currently accepts; the gateway's trusted configuration lists the accepted revisions (Section 4.2), and a snapshot with another revision fails the `reputation-context` check with `CONTEXT_MISMATCH`. The snapshot's `scoring_artifact_digest` is not compared with any contract's `learning_artifact_digest`.
- A reputation snapshot carries no `status_ref`. For a field rule whose `path` is `/attributes/reputation` or a descendant, `max_age_seconds` bounds `now - iat` of the snapshot, its issuance being the observation of its value (`evidence_cutoff` is bounded separately, above), and `status_max_age_seconds` bounds the age of the validator's own security-hold check (Sections 15.4 and 18) at the time the rule is evaluated; the snapshot's `security_status` and `hold_refs` do not satisfy that check. The rule's `CheckResult` records `source_observed_at` as the snapshot's `iat` and `status_checked_at` as the time of that hold check.
- A reputation value's `provenance_digest` equals the `object_digest` of its `ProvenanceManifest` (Section 15.2), whose `scoring_policy_revision` and `evidence_cutoff` equal the value's own. The manifest is not a wire object, so the schema does not validate it.
- `CheckResult.evidence_ids` may be empty for local native checks; such a check's `source_id` identifies the installed authoritative adapter and `source_ref` identifies its immutable decision/observation record when an external fact was used. Unknown source IDs are invalid. `source_observed_at` and `status_checked_at` are required for source-age and status-age checks respectively; they are null only when that category does not apply. Nonce and local structural checks may have null source references and observation timestamps.
- The `reputation-context` and `selection-consistency-v1` `CheckResult` `evidence_ids` MUST include the presented snapshot `jti`; `source_ref` MUST identify the gateway's selection record.
- `ADMISSIBLE` requires all required checks to be `PASS` or explicitly `NOT_APPLICABLE` under policy. A required field is never not applicable merely because it is absent.
- Approval-class checks MUST use the reason codes in Section 17.3.1: `REQUIREMENT_SATISFIED`, `APPROVAL_PENDING`, `MISSING_FIELD`, `APPROVAL_REJECTED`, `APPROVAL_EXPIRED`, `APPROVAL_REVOKED`, `APPROVAL_AUTHORITY_MISMATCH`, `APPROVAL_SCOPE_MISMATCH`, `DEPENDENCY_UNAVAILABLE`, and `NOT_EVALUATED` (Section 12.1).
- `OutcomeReport.reporter_role` must match the receiver's trusted registration of the signer. A report that does not is acknowledged and classified `UNQUALIFIED` (Section 14.3): it places, clears, and corrects nothing. `sub` must match the attributable agent in the recorded task. `CORRECTION` requires nonempty `supersedes`; other events must use an empty array unless the installed evidence policy explicitly supports replacement semantics.
- `ADMISSION` and `AUTHORIZATION` events MUST use dimension `none`.
- An `OutcomeReport` with `result` `UNKNOWN` MUST use dimension `none`, except a `CORRECTION`, which carries the `dimension` of the events it supersedes whatever its `result` (Section 14.6, rule 10).
- An `OutcomeReport` uses a `dimension` that Section 14.5 gives its `event_kind`: `EXECUTION` uses `reliability` or `none`; `QUALITY` and `FEEDBACK` use `task_quality` or `policy_adherence`; `SECURITY` uses `policy_adherence` or `none`; `REMEDIATION` uses `none`; a `CORRECTION` carries the `dimension` of the events it supersedes (Section 14.6, rule 10). Any other pair is invalid: an `EXECUTION` report on `task_quality` or `policy_adherence` is not an assessment, and a `QUALITY` or `FEEDBACK` report on `reliability` is not an execution record.
- An `EXECUTION` or `AUTHORIZATION` `OutcomeReport` MUST reference, in `evidence_refs`, an immutable native record identifying the actual executor identity (Section 14.2), except a report of absent execution visibility (Section 14.5), whose `evidence_refs` is empty. A report whose executor class differs from the mapping's declared class is `UNQUALIFIED`.
- Learning policy `sub` is its environment URI. Learning artifact `sub` is its artifact URI. Learning event `sub` is the outgoing or transitioned artifact URI, not the controller. Their `aud` identifies the bounded learning service or deployment policy service that is authorized to consume them.
- Learning policy controls use installed control identifiers with typed bounds. Merely adding an entry to an open configuration map cannot authorize a new control. Release gates include minimum independent tasks, minimum observation duration, shadow duration, regression bounds, and immutable test-suite digests. Appendix A.3 requires each of them, so a learning policy without one is invalid (`INVALID_MESSAGE`, Section 13.4) and authorizes no promotion.
- Learning events carry `expected_state` and `expected_active_digest`. The receiver verifies both atomically. `previous_artifact_digest` is the artifact that was in force in the event's `scope_contexts` before the transition, the expected previous artifact of the compare-and-swap (Section 16.5), so it equals `expected_active_digest`; both are null for an `ACTIVE` event and when the conservative set is in force. `activate_artifact_digest` is required for activation and is otherwise null. For rollback it identifies the compatible fallback, or is null when no compatible artifact exists and `reason_codes` includes `FALLBACK_INCOMPATIBLE` (Section 16.5); `artifact_digest` identifies the outgoing artifact. For activation `expected_active_digest` is null, since a promotion replaces only the conservative set (Section 16.5). An event whose `activate_artifact_digest` or `expected_active_digest` breaks these rules, or whose `previous_artifact_digest` differs from its `expected_active_digest`, or whose `expected_state` and `transition` are not a row of the Section 16.5 table, is invalid (`INVALID_MESSAGE`, Section 13.4); a failed compare-and-swap is `VERSION_CONFLICT` (Section 16.5).
- A `LearningArtifact` is registered as a signed manifest that is immutable and enters `CANDIDATE` on acknowledgment (Section 16.3). Its `evaluation_report_digest` never changes after registration; any change listed in Section 16.3, including a different report, requires a new manifest with an incremented `version` and `parent_artifact_digest` equal to the prior manifest's digest.
- Metadata endpoint URLs and key-set URLs are accepted only within configured trusted origins or explicit administrative allowlists. Discovery does not authorize arbitrary fetching.
- `GatewayMetadata.endpoints` and `jwks_uri` may be omitted only from metadata whose `extensions` carries the transport profile declaration `pact-transport-profile-v1` (Section 13.3.1), whose discovery method replaces Section 13.1; metadata without that declaration carries both, and every endpoint or key-set URL that metadata publishes is an HTTPS URL. The schema checks that the declaration is present, not that the receiver supports the profile.
- The value of the extension `pact-conformance-profile-v1` validates against the A.3 definition `ConformanceDeclaration`, and the value of `pact-transport-profile-v1` against `TransportDeclaration`, wherever the extension appears (Section 21); the receiver applies them, since the `extensions` objects of the schema are open. A `ConformanceDeclaration` of the profile `full` omits no role. An `extensions_supported` entry is a URI or a `pact-` token; that a URI is HTTPS and under the publisher's control is a rule of Section 21 that the schema cannot check.
- The schema validates `GatewayMetadata.limits` only as a map of positive integers. The required keys, bounds, and transport-key rule in Section 20.1 apply in addition.
- A `Schema` structural match does not imply valid issuer authority, native authorization, trustworthy feedback, safe learning, or correct runtime enforcement.

### A.3 JSON Schema

The normative schema is published as [`schemas/pact.schema.json`](schemas/pact.schema.json). Its `$defs` also holds two payload-only definitions, `ConformanceDeclaration` and `TransportDeclaration`: the schemas of the profile declaration values of Section 21 (A.2). They are not wire objects, so the root `oneOf` does not list them and no `typ` selects them.

## Appendix B. Worked finance-gateway example (informative)

The following fictional example uses reserved `.example` hostnames. It demonstrates the separation between required profile fields, evidence, native authorization, and learning. Values are illustrative policy choices, not recommended universal thresholds. Signed artifacts are shown decoded unless explicitly labeled compact JWS. The sample timestamp is 2026-10-15T16:00:00Z; these records are not live credentials. The enrollment, native authorization, status adapters, and active-model registry are assumed fixtures, not independently established by the example.

The agent is already enrolled and natively authenticated. The gateway maps the real request to one invoice read. It selects the `supervised` requirements, including an existing native approval reference. A positive admission continues to the gateway's invoice permission check. If that check denies access, no read occurs and no execution success is reported. The illustrative reputation numbers assume zero elapsed decay at the evidence cutoff.

### B.1 Agent profile

```json
{
  "profile_id": "finance-profile-view-0001",
  "revision": 1,
  "agent_id": "https://identity.example/agents/invoice-assistant",
  "operator_id": "https://identity.example/operators/acme",
  "tenant_id": "acme",
  "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
  "created_at": 1792080000,
  "expires_at": 1792083600,
  "attributes": {
    "environment": {
      "principal_id": "https://identity.example/principals/alice",
      "roles": [
        "finance-reader"
      ]
    },
    "delegation": {
      "authority_ref": "native-approval:september-summary-007"
    },
    "runtime": {
      "isolation": "managed"
    },
    "reputation": {
      "context": {
        "tenant_id": "acme",
        "environment_id": "https://gateway.example/environments/finance",
        "agent_id": "https://identity.example/agents/invoice-assistant",
        "purpose_id": "https://policies.example/purposes/invoice-summary/v1",
        "action_class": "invoice.read",
        "resource_class": "department-finance-invoice",
        "runtime_class": "managed-v1"
      },
      "dimensions": {
        "reliability": {
          "score_bps": 9259,
          "confidence_bps": 5555,
          "independent_tasks": 25,
          "qualified_events": 25,
          "newest_event_at": 1792080000
        },
        "task_quality": {
          "score_bps": 9000,
          "confidence_bps": 4736,
          "independent_tasks": 18,
          "qualified_events": 18,
          "newest_event_at": 1792080000
        },
        "policy_adherence": {
          "score_bps": 8750,
          "confidence_bps": 2307,
          "independent_tasks": 6,
          "qualified_events": 6,
          "newest_event_at": 1792080000
        }
      },
      "evidence_cutoff": 1792080000,
      "provenance_digest": "te9wb7ClTY1tDWP7q_-ntYdCZnoXNwTH70GkmId2QBA",
      "scoring_artifact_digest": "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0",
      "scoring_policy_revision": "finance-scoring-1",
      "security_status": "CLEAR",
      "hold_refs": []
    }
  }
}
```

### B.2 Declared intent

```json
{
  "intent_id": "intent-september-invoices-007",
  "purpose_id": "https://policies.example/purposes/invoice-summary/v1",
  "description": "Read the approved September invoice to prepare the department summary.",
  "task_id": "native-task:september-summary-007"
}
```

### B.3 Actual operation context

```json
{
  "operation_id": "invoice-read-operation-0001",
  "environment_id": "https://gateway.example/environments/finance",
  "principal_id": "https://identity.example/principals/alice",
  "action": "invoice.read",
  "resources": [
    "https://invoices.example/invoices/INV-1042"
  ],
  "method": "GET",
  "target_uri": "https://gateway.example/invoices/INV-1042",
  "body_digest": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
  "headers": {}
}
```

### B.4 Effective requirement contract

```json
{
  "pact_version": "0.1",
  "iss": "https://trust.example/issuers/finance",
  "sub": "https://identity.example/agents/invoice-assistant",
  "aud": "https://gateway.example/finance",
  "jti": "zIMh1jdcSU0EP90CYPIbwA",
  "iat": 1792080000,
  "nbf": 1792080000,
  "exp": 1792080060,
  "tenant_id": "acme",
  "contract_id": "contract-finance-0001",
  "environment_id": "https://gateway.example/environments/finance",
  "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
  "operation_digest": "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0",
  "intent_digest": "t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M",
  "base_revision": "finance-base-3",
  "selected_set": "supervised",
  "field_rules": [
    {
      "rule_id": "principal",
      "path": "/attributes/environment/principal_id",
      "schema": {
        "type": "string"
      },
      "source": "native",
      "comparison": "equal",
      "allowed_issuers": [],
      "native_path": "/principal/id",
      "max_age_seconds": 30,
      "status_max_age_seconds": 0
    },
    {
      "rule_id": "roles",
      "path": "/attributes/environment/roles",
      "schema": {
        "type": "array",
        "items": {
          "type": "string"
        },
        "uniqueItems": true,
        "contains": {
          "const": "finance-reader"
        }
      },
      "source": "native",
      "comparison": "equal",
      "allowed_issuers": [],
      "native_path": "/principal/roles",
      "max_age_seconds": 30,
      "status_max_age_seconds": 0
    },
    {
      "rule_id": "supervisor-approval",
      "path": "/attributes/delegation/authority_ref",
      "schema": {
        "type": "string",
        "minLength": 1
      },
      "source": "native",
      "comparison": "equal",
      "allowed_issuers": [],
      "native_path": "/task/approval_ref",
      "max_age_seconds": 30,
      "status_max_age_seconds": 0
    },
    {
      "rule_id": "isolation",
      "path": "/attributes/runtime/isolation",
      "schema": {
        "const": "managed"
      },
      "source": "evidence",
      "comparison": "equal",
      "allowed_issuers": [
        "https://trust.example/issuers/finance"
      ],
      "native_path": null,
      "max_age_seconds": 30,
      "status_max_age_seconds": 0
    },
    {
      "rule_id": "reputation-status",
      "path": "/attributes/reputation/security_status",
      "schema": {
        "const": "CLEAR"
      },
      "source": "evidence",
      "comparison": "equal",
      "allowed_issuers": [
        "https://reputation.example/finance"
      ],
      "native_path": null,
      "max_age_seconds": 30,
      "status_max_age_seconds": 0
    }
  ],
  "context_checks": [
    "native-principal-binding-v1",
    "purpose-operation-v1",
    "native-delegation-v1",
    "security-hold-v1"
  ],
  "learning_policy_digest": "mIu2mtBMHPAf6CgJkuwuDsUWhs9bu-Wkenl4QlrcQAQ",
  "learning_artifact_digest": "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0",
  "nonce": "N8WrKpg8XNb9Wh_QuWlHbw",
  "mode": "enforced"
}
```

### B.5 Runtime evidence

```json
{
  "pact_version": "0.1",
  "iss": "https://trust.example/issuers/finance",
  "sub": "https://identity.example/agents/invoice-assistant",
  "aud": "https://gateway.example/finance",
  "jti": "7oJQ-3bglLNLRx8Tpz275Q",
  "iat": 1792080000,
  "nbf": 1792080000,
  "exp": 1792080300,
  "tenant_id": "acme",
  "environment_id": "https://gateway.example/environments/finance",
  "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
  "kind": "runtime",
  "claims": [
    {
      "path": "/attributes/runtime/isolation",
      "value": "managed"
    }
  ],
  "status_ref": "runtime-attestation:finance-agent-0001"
}
```

### B.6 Contextual reputation snapshot

```json
{
  "pact_version": "0.1",
  "iss": "https://reputation.example/finance",
  "sub": "https://identity.example/agents/invoice-assistant",
  "aud": "https://gateway.example/finance",
  "jti": "VW7HSF227CWWBU7wN09Q5A",
  "iat": 1792080000,
  "nbf": 1792080000,
  "exp": 1792080300,
  "tenant_id": "acme",
  "environment_id": "https://gateway.example/environments/finance",
  "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
  "value": {
    "context": {
      "tenant_id": "acme",
      "environment_id": "https://gateway.example/environments/finance",
      "agent_id": "https://identity.example/agents/invoice-assistant",
      "purpose_id": "https://policies.example/purposes/invoice-summary/v1",
      "action_class": "invoice.read",
      "resource_class": "department-finance-invoice",
      "runtime_class": "managed-v1"
    },
    "dimensions": {
      "reliability": {
        "score_bps": 9259,
        "confidence_bps": 5555,
        "independent_tasks": 25,
        "qualified_events": 25,
        "newest_event_at": 1792080000
      },
      "task_quality": {
        "score_bps": 9000,
        "confidence_bps": 4736,
        "independent_tasks": 18,
        "qualified_events": 18,
        "newest_event_at": 1792080000
      },
      "policy_adherence": {
        "score_bps": 8750,
        "confidence_bps": 2307,
        "independent_tasks": 6,
        "qualified_events": 6,
        "newest_event_at": 1792080000
      }
    },
    "evidence_cutoff": 1792080000,
    "provenance_digest": "te9wb7ClTY1tDWP7q_-ntYdCZnoXNwTH70GkmId2QBA",
    "scoring_artifact_digest": "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0",
    "scoring_policy_revision": "finance-scoring-1",
    "security_status": "CLEAR",
    "hold_refs": []
  }
}
```

In this example `provenance_digest` is computed as the `object_digest` of the snapshot's `ProvenanceManifest` (Section 15.2). The manifest is not a wire object and is not shown; the digest value above is illustrative.

### B.7 Admission receipt

```json
{
  "pact_version": "0.1",
  "iss": "https://trust.example/issuers/finance",
  "sub": "https://identity.example/agents/invoice-assistant",
  "aud": "https://gateway.example/finance",
  "jti": "bzKGCRDKD7KiDH_aFDZmsA",
  "iat": 1792080000,
  "nbf": 1792080000,
  "exp": 1792080060,
  "tenant_id": "acme",
  "presentation_id": "v6wxT-_cB0Ua8Xkqgcuu2g",
  "operation_id": "invoice-read-operation-0001",
  "principal_id": "https://identity.example/principals/alice",
  "environment_id": "https://gateway.example/environments/finance",
  "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
  "profile_digest": "b6pNI8i5pX5MtuxkaBw0M-4tmzdkGsHVS_Kyji7_uOU",
  "intent_digest": "t79YgXU70gzKitcuPJ_fUp4V_bM5MGooinyuyL8cE5M",
  "operation_digest": "R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0",
  "requirements_digest": "NBT3fg3NrXBiyMdcOvQaAXqX0ZmkSaO8daKT1HPZZ8A",
  "learning_policy_digest": "mIu2mtBMHPAf6CgJkuwuDsUWhs9bu-Wkenl4QlrcQAQ",
  "learning_artifact_digest": "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0",
  "decision": "ADMISSIBLE",
  "terminal_reason": "COMPLETED",
  "mode": "enforced",
  "checks": [
    {
      "check_id": "native-authentication",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-native-authentication"
    },
    {
      "check_id": "agent-holder-binding",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-agent-holder-binding"
    },
    {
      "check_id": "contract-validity",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-contract-validity"
    },
    {
      "check_id": "nonce",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": null,
      "status_checked_at": null,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": null
    },
    {
      "check_id": "operation-binding",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-operation-binding"
    },
    {
      "check_id": "intent-binding",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-intent-binding"
    },
    {
      "check_id": "profile-validity",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-profile-validity"
    },
    {
      "check_id": "evidence-validity",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-evidence-validity"
    },
    {
      "check_id": "reputation-context",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [
        "VW7HSF227CWWBU7wN09Q5A"
      ],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-selection-record:example-selection"
    },
    {
      "check_id": "security-hold",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-security-hold"
    },
    {
      "check_id": "active-policy",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-active-policy"
    },
    {
      "check_id": "principal",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-principal"
    },
    {
      "check_id": "roles",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-roles"
    },
    {
      "check_id": "supervisor-approval",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-supervisor-approval"
    },
    {
      "check_id": "isolation",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [
        "7oJQ-3bglLNLRx8Tpz275Q"
      ],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-isolation"
    },
    {
      "check_id": "reputation-status",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-reputation-status"
    },
    {
      "check_id": "native-principal-binding-v1",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-native-principal-binding-v1"
    },
    {
      "check_id": "purpose-operation-v1",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-purpose-operation-v1"
    },
    {
      "check_id": "native-delegation-v1",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-native-delegation-v1"
    },
    {
      "check_id": "security-hold-v1",
      "result": "PASS",
      "reason_code": "REQUIREMENT_SATISFIED",
      "checked_at": 1792080000,
      "source_observed_at": 1792080000,
      "status_checked_at": 1792080000,
      "evidence_ids": [],
      "source_id": "configured-finance-validator-v1",
      "source_ref": "configured-validation-record:example-security-hold-v1"
    }
  ]
}
```

B.4 selects the conservative set (`supervised`), so `selection-consistency-v1` is correctly absent from its `context_checks` and from this receipt. The gateway still records that selection, and the `reputation-context` check names that selection record in `source_ref` (Appendix A.2).

### B.8 Attributable execution outcome

```json
{
  "pact_version": "0.1",
  "iss": "https://trust.example/issuers/finance",
  "sub": "https://identity.example/agents/invoice-assistant",
  "aud": "https://reputation.example/finance",
  "jti": "JaY-UqmPb9qmGH2lWaCjpQ",
  "iat": 1792080000,
  "nbf": 1792080000,
  "exp": 1792080300,
  "tenant_id": "acme",
  "event_id": "execution-event-0001",
  "environment_id": "https://gateway.example/environments/finance",
  "task_id": "native-task:september-summary-007",
  "operation_id": "invoice-read-operation-0001",
  "admission_receipt_id": "bzKGCRDKD7KiDH_aFDZmsA",
  "observed_at": 1792080000,
  "reporter_role": "executor",
  "context": {
    "tenant_id": "acme",
    "environment_id": "https://gateway.example/environments/finance",
    "agent_id": "https://identity.example/agents/invoice-assistant",
    "purpose_id": "https://policies.example/purposes/invoice-summary/v1",
    "action_class": "invoice.read",
    "resource_class": "department-finance-invoice",
    "runtime_class": "managed-v1"
  },
  "event_kind": "EXECUTION",
  "result": "SUCCESS",
  "dimension": "reliability",
  "severity": "info",
  "evidence_refs": [
    "native-execution-log:finance-read-0001"
  ],
  "attribution": {
    "native_task_ref": "native-task:september-summary-007",
    "independence_group": "native-task-group:september-summary-007",
    "causal_assessment": "AGENT",
    "assessment_ref": null
  },
  "supersedes": [],
  "details": "Native authorization allowed the invoice read and the resource service confirmed completion."
}
```

### B.9 Bounded autonomous learning policy

```json
{
  "pact_version": "0.1",
  "iss": "https://trust.example/issuers/finance",
  "sub": "https://gateway.example/environments/finance",
  "aud": "https://learning.example/finance",
  "jti": "gjQS0erLZ5ViIOUylZ8BBA",
  "iat": 1792080000,
  "nbf": 1792080000,
  "exp": 1792166400,
  "tenant_id": "acme",
  "policy_id": "finance-admission-learning-v1",
  "environment_id": "https://gateway.example/environments/finance",
  "mode": "bounded_autonomous",
  "controller_ids": [
    "https://learning.example/controllers/finance"
  ],
  "base_revision": "finance-base-3",
  "conservative_set": "supervised",
  "allowed_requirement_sets": [
    "supervised",
    "established"
  ],
  "adaptive_fields": [
    {
      "control_id": "supervisor-approval-required",
      "value_schema": {
        "type": "boolean"
      },
      "allow_relaxation": true
    }
  ],
  "permitted_artifact_types": [
    "baseline",
    "score",
    "requirement_selector"
  ],
  "permitted_implementation_ids": [
    "beta-decay-v1",
    "finance-selector-v1"
  ],
  "data_policy": {
    "qualification_policy_id": "pact-qualification-v1",
    "ingestion_window_seconds": 604800,
    "positive_weight_cap_per_task": 1,
    "maximum_failure_weight": 5,
    "task_attribution_source": "native-task-registry",
    "reporter_independence_policy_id": "pact-reporter-independence-v1"
  },
  "evaluation_policy": {
    "minimum_independent_tasks": 100,
    "minimum_observation_seconds": 604800,
    "minimum_shadow_seconds": 86400,
    "holdout_policy_id": "time-separated-holdout-v1",
    "immutable_test_suite_digests": [
      "I7Z5M225iXt94t2aNsPS_YEN07CyAkcn_SuW7d057Sg"
    ],
    "metric_bounds": {
      "native-denial-override-count": {
        "direction": "upper",
        "value": 0
      },
      "admission-regression-rate": {
        "direction": "upper",
        "value": 0.01
      }
    },
    "maximum_rollout_percent": 10,
    "required_evaluator_ids": [
      "https://learning.example/evaluators/independent"
    ],
    "rollback_condition_ids": [
      "any-native-denial-override",
      "qualified-regression-limit"
    ]
  },
  "hold_clearance_authorities": [
    "https://security.example/finance"
  ]
}
```

In the `data_policy` object of the example above, `qualification_policy_id` and `reporter_independence_policy_id` use the baseline identifiers `pact-qualification-v1` and `pact-reporter-independence-v1` defined in Section 14.6. Deployments may define their own policy identifiers.

### B.10 Learning artifact manifest

```json
{
  "pact_version": "0.1",
  "iss": "https://learning.example/controllers/finance",
  "sub": "https://learning.example/artifacts/baseline-v1",
  "aud": "https://learning.example/finance",
  "jti": "x8XB1wxd7EQWq2FYr9CyIw",
  "iat": 1792080000,
  "nbf": 1792080000,
  "exp": 1792166400,
  "tenant_id": "acme",
  "artifact_id": "https://learning.example/artifacts/baseline-v1",
  "version": "1",
  "model_type": "baseline",
  "implementation_id": "beta-decay-v1",
  "content_digest": "pQQCoOLBo6OHIhzTsWX9ljJ8rvjczaRL36wCrVVU5_A",
  "source_data_manifest_digest": "Tb1bltn4m5rkxOVTBtmNx5ziPlW91bWe75DMsC-VDCc",
  "feature_schema_digest": "X_S1c0g3IwnKjerYmkCyRQLV2oJ3J348zXuj3Hv7o_o",
  "training_configuration_digest": "kZjEABtBB3GQX676atzKTT-7Y2JmiIl-Y8agfKpUYiI",
  "evaluation_report_digest": "MJCmRyAqRLSoUsyDHBrLsp4LlUufQyMxfyCsxdX7zVc",
  "intended_contexts": [
    {
      "tenant_id": "acme",
      "environment_id": "https://gateway.example/environments/finance",
      "agent_id": "https://identity.example/agents/invoice-assistant",
      "purpose_id": "https://policies.example/purposes/invoice-summary/v1",
      "action_class": "invoice.read",
      "resource_class": "department-finance-invoice",
      "runtime_class": "managed-v1"
    }
  ],
  "base_revision": "finance-base-3",
  "parent_artifact_digest": null,
  "output_controls": [
    "supervisor-approval-required"
  ],
  "artifact_store_ref": "configured-store:baseline-v1"
}
```

The manifest above is the registered candidate, and its `evaluation_report_digest` is the digest of the controller's pre-registration report (Section 16.3).

### B.11 Learning lifecycle event

```json
{
  "pact_version": "0.1",
  "iss": "https://learning.example/controllers/finance",
  "sub": "https://learning.example/artifacts/baseline-v1",
  "aud": "https://learning.example/finance",
  "jti": "c0-w6hRMSr11xeR5OIVitg",
  "iat": 1792080000,
  "nbf": 1792080000,
  "exp": 1792080300,
  "tenant_id": "acme",
  "event_id": "learning-shadow-event-0001",
  "environment_id": "https://gateway.example/environments/finance",
  "artifact_digest": "Is5hAn87tiTQEbsbEPbL7oeEZWa74Gxmr4Xrp0SQUQ0",
  "previous_artifact_digest": null,
  "policy_digest": "mIu2mtBMHPAf6CgJkuwuDsUWhs9bu-Wkenl4QlrcQAQ",
  "transition": "SHADOW",
  "expected_state": "EVALUATED",
  "expected_active_digest": null,
  "activate_artifact_digest": null,
  "effective_at": 1792080000,
  "scope_contexts": [
    {
      "tenant_id": "acme",
      "environment_id": "https://gateway.example/environments/finance",
      "agent_id": "https://identity.example/agents/invoice-assistant",
      "purpose_id": "https://policies.example/purposes/invoice-summary/v1",
      "action_class": "invoice.read",
      "resource_class": "department-finance-invoice",
      "runtime_class": "managed-v1"
    }
  ],
  "evaluation_refs": [
    "configured-evaluation-store:example-report"
  ],
  "reason_codes": [
    "EVALUATION_GATES_PASSED"
  ]
}
```

The artifact and lifecycle objects above illustrate their formats separately from the assumed active baseline. The `SHADOW` event does not activate a model. An actual deployment must supply its complete verified lifecycle and current active-version registry before using an artifact for enforced admission. The sample evaluation/report references are illustrative identifiers, not claims of completed evaluations.

### B.12 Deferred approval and fresh presentation

An agent requests an operation whose effective requirements include supervisor approval. No approval exists yet.

1. The gateway evaluates the presentation. The required approval is unavailable and an approval request for this exact scope is open, so the check returns `UNKNOWN` with reason code `APPROVAL_PENDING` (Section 17.3.1) and PACT seals the evaluation as `DEFERRED` with a reason and bounded retry guidance. Without an open request, the same case is `FAIL` with `MISSING_FIELD` and seals as `INADMISSIBLE`. The gateway does not execute the operation, and no evaluation stays open.
2. A supervisor approves through the organization's existing approval system. The approver's actual role is defined by that external environment, not by PACT. That system may also grant a permitted exception. PACT is not involved in the approval workflow.
3. The agent obtains a fresh requirement contract and submits a new presentation that references the approval.
4. The gateway verifies the approval's issuer authority, scope, validity, and current status, and then evaluates admission again. This evaluation produces its own receipt. The earlier `DEFERRED` receipt is unchanged.
5. If the result is `ADMISSIBLE`, the gateway applies native authorization under its current policy, including any exception the environment recognizes. A native denial still wins.
6. If the supervisor rejects, the fresh evaluation seals `INADMISSIBLE` with `APPROVAL_REJECTED`; it is not a reputation event.

### B.13 Gateway metadata with baseline limits

The finance gateway publishes the following at `/.well-known/pact-configuration`. It advertises every baseline limits key from Section 20.1. The `header` transport is advertised at 8192 bytes, below `max_presentation_bytes`, so it is not the only advertised transport: the `adapter-envelope` and `gateway-evaluate` transports each carry the full 262144 bytes. The adapter version, header names, and identifiers are illustrative.

```json
{
  "gateway_id": "https://gateway.example/finance",
  "environment_id": "https://gateway.example/environments/finance",
  "wire_versions": ["0.1"],
  "jws_algorithms": ["ES256"],
  "endpoints": {
    "requirements": "https://gateway.example/pact/v0.1/requirements",
    "evaluate": "https://gateway.example/pact/v0.1/evaluate",
    "outcomes": "https://gateway.example/pact/v0.1/outcomes",
    "reputation_query": "https://gateway.example/pact/v0.1/reputation/query",
    "learning_artifacts": "https://gateway.example/pact/v0.1/learning/artifacts",
    "learning_events": "https://gateway.example/pact/v0.1/learning/events",
    "receipts_query": "https://gateway.example/pact/v0.1/receipts/query"
  },
  "jwks_uri": "https://gateway.example/.well-known/jwks.json",
  "operation_mapping_version": "finance-http-1",
  "extensions_supported": [],
  "modes": ["enforced"],
  "presentation_transports": ["header", "adapter-envelope", "gateway-evaluate"],
  "limits": {
    "max_presentation_bytes": 262144,
    "max_artifact_payload_bytes": 32768,
    "max_profile_bytes": 32768,
    "max_evidence_artifacts": 32,
    "max_field_rules": 128,
    "max_json_depth": 16,
    "max_resources": 256,
    "max_description_bytes": 4096,
    "contract_validity_seconds": 60,
    "presentation_validity_seconds": 60,
    "evaluation_seconds": 30,
    "clock_skew_seconds": 5,
    "replay_retention_seconds": 65,
    "max_header_presentation_bytes": 8192,
    "max_envelope_presentation_bytes": 262144,
    "max_evaluate_presentation_bytes": 262144
  },
  "protected_header_names": ["if-match", "x-dry-run"],
  "header_normalization_id": "finance-header-normalization-1",
  "adapters": [
    {
      "protocol": "mcp",
      "version": "2025-11-25",
      "mapping_revision": "finance-mcp-1"
    }
  ]
}
```

## Appendix C. Cryptographic fixture (informative)

This fixture provides a valid ES256 JWS for the runtime evidence in Appendix B. It uses a deliberately public test key derived from P-256 private scalar `2`; the example holder key uses test scalar `1`. These scalars are test fixtures only and MUST NOT be used for production identities. The signature bytes may differ if the fixture is regenerated because ECDSA signing uses a fresh nonce. A conforming verifier validates the provided received signing input rather than regenerating a signature.

Issuer public JWK (configure this test issuer explicitly; the fixture is not a trust anchor):

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg",
  "y": "B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E",
  "kid": "test-issuer-key-1",
  "alg": "ES256",
  "use": "sig"
}
```

Holder public JWK and thumbprint:

```json
{
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
    "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
  },
  "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
}
```

Exact compact evidence JWS:

```text
eyJhbGciOiJFUzI1NiIsInR5cCI6InBhY3QtZXZpZGVuY2Urand0Iiwia2lkIjoidGVzdC1pc3N1ZXIta2V5LTEifQ.ewogICJwYWN0X3ZlcnNpb24iOiAiMC4xIiwKICAiaXNzIjogImh0dHBzOi8vdHJ1c3QuZXhhbXBsZS9pc3N1ZXJzL2ZpbmFuY2UiLAogICJzdWIiOiAiaHR0cHM6Ly9pZGVudGl0eS5leGFtcGxlL2FnZW50cy9pbnZvaWNlLWFzc2lzdGFudCIsCiAgImF1ZCI6ICJodHRwczovL2dhdGV3YXkuZXhhbXBsZS9maW5hbmNlIiwKICAianRpIjogIjdvSlEtM2JnbExOTFJ4OFRwejI3NVEiLAogICJpYXQiOiAxNzkyMDgwMDAwLAogICJuYmYiOiAxNzkyMDgwMDAwLAogICJleHAiOiAxNzkyMDgwMzAwLAogICJ0ZW5hbnRfaWQiOiAiYWNtZSIsCiAgImVudmlyb25tZW50X2lkIjogImh0dHBzOi8vZ2F0ZXdheS5leGFtcGxlL2Vudmlyb25tZW50cy9maW5hbmNlIiwKICAiaG9sZGVyX2prdCI6ICJ4eDBCY0Etd01vaHc4YXRZREpPZTZwZUdNb2RrbEcyd1JIQmxYSE12bDBNIiwKICAia2luZCI6ICJydW50aW1lIiwKICAiY2xhaW1zIjogWwogICAgewogICAgICAicGF0aCI6ICIvYXR0cmlidXRlcy9ydW50aW1lL2lzb2xhdGlvbiIsCiAgICAgICJ2YWx1ZSI6ICJtYW5hZ2VkIgogICAgfQogIF0sCiAgInN0YXR1c19yZWYiOiAicnVudGltZS1hdHRlc3RhdGlvbjpmaW5hbmNlLWFnZW50LTAwMDEiCn0.qiZpXOwu5RsEaJCAf5fXXlID8gFjHR_B4alE_jHMCa0Y6ZpW2tjNpzz3m47WCO65PiKiOsw6l3isryCAQZvQtw
```

Expected decoded payload: the base64url-decoded payload equals, byte for byte and without canonicalization, the UTF-8 text of the B.5 JSON block (member order and two-space indentation preserved, LF line breaks, no trailing newline), so its `pact_version` is `0.1`. Expected decoded type: `pact-evidence+jwt`. Expected subject: `https://identity.example/agents/invoice-assistant`. Expected claim: `/attributes/runtime/isolation` equals `managed`. Signature validation alone does not satisfy issuer scope, enrollment, status, age, or native authorization requirements.

## Appendix D. Coverage of the review and subsequent scope decisions (informative)

| Finding or direction | Where addressed |
|---|---|
| Intent was informational and not bound to execution | Sections 2, 10, 11 and 17 bind the actual request and require installed purpose checks while preserving native enforcement. |
| Controlled environments should define required agent-profile fields | Sections 8, 9 and 17 define field rules, trusted provenance and native claim mappings without introducing a replacement IAM layer. |
| Semantic challenges conflated skill with authority | Sections 5 and 16.6 confine them to qualified capability evidence. |
| Any issuer and optional subject binding | Sections 4, 6, 7 and 8 require claim-scoped trust, enrolled-key possession and exact context binding. |
| Reputation farming and global scores | Sections 14 and 15 require attributable outcomes, deduplication, independent task groups, dimensions and contextual confidence. |
| Continuous/autonomous learning must be first-class | Section 16 specifies the complete learning lifecycle and preauthorized autonomous adaptation. |
| Replay TTL and distributed races | Sections 7.5, 11 and 12 specify bounded acceptance, atomic nonce and receipt consumption, and terminal-state rules. |
| Incorrect signing/canonicalization and VC proof claims | Section 7 adopts exact JOSE and JCS mechanisms and removes the mislabeled core proof. |
| Generic HS256 trust token | Sections 2, 7 and 11 replace it with an asymmetric admission receipt that conveys no independent native access. |
| Missing revocation and recovery | Sections 6, 15.4 and 18 distinguish stable identity, key rotation, security holds, status freshness and recovery authority. |
| Incomplete schemas and failure behavior | Sections 11–13, Appendix A and the conformance matrix define complete message shapes and error paths. |
| Overstated MCP/A2A gap and interoperability | Sections 13.3, 21 and 24 preserve existing authorization and require versioned adapter mappings. |
| Implementation-specific engine requirements | Section 17 specifies behavioral interfaces without requiring LangGraph, Pydantic, Redis, a particular database or an LLM vendor. |
| Partial role claims without a defined small-deployment route (22.1) | Section 22.1 routes an omitted Reputation or Learning role through a declared conformance profile; the single-owner profile is defined in `profiles/conformance/single-owner/`. |
| Local IPC and stdio transport requirement (13.3 last paragraph) | Section 13.3.1 defines the requirements on a transport profile; Sections 13.2, 13.4, 20.1 and 22.1 carry the matching hooks; the stdio and IPC profile is defined in `profiles/transport/stdio-ipc/`. |
| Native MCP method and parameter binding (10.2, 13.3) | Section 10.2 states the canonical message object requirements; Section 13.3 requires one adapter declaration per pinned protocol revision; Section 24 pins the MCP references; the MCP adapter profile is defined in `profiles/mcp/`. |

## Appendix E. Evaluating reputation thresholds and evidence ages (informative)

This appendix describes how a deployment evaluates the reputation thresholds and evidence ages it selects. The result is the calibration evidence that Section 15.2 requires of a model claiming probabilistic calibration. The evidence is a report, not a wire object, and has no schema definition. The appendix sets no numeric thresholds, and Sections 15.2, 15.3 and 16.3 remain the normative sources. The baseline `beta-decay-v1` makes no claim of empirical calibration (Section 15.3).

The calibration evidence contains the following.

| Item | Content |
|---|---|
| Calibration | Per-dimension Brier score and expected calibration error on a time-separated holdout, for `reliability`, `task_quality` and `policy_adherence` separately (Section 15.1). |
| Coverage | Per-context coverage counts (Sections 15.1 and 16.3, item 3). |
| Cold start | Cold-start behavior with empty history (Section 15.3) and for new identities and unfamiliar contexts, which use the conservative requirement set (Section 15.4). |
| Decay sensitivity | Decay sensitivity at 7, 30 and 90 days. The baseline half-life is 30 days (Section 15.3). |
| Margins | Threshold-boundary margin analysis, including the explicit margin that Section 15.3 requires of promotion policies. |
| Failure cost | A failure-cost statement: the cost of failure where the thresholds and evidence ages apply. |
| Provenance | Evaluator identity, which originates from authorized policy and not from the candidate (Section 16.3), and a data provenance digest (Section 7.4) covering the provenance recorded for the evaluation data (Section 16.3, item 1). |

The keys of a `LearningPolicy`'s `evaluation_policy.metric_bounds` MUST name the metric definition version, so that a bound is not applied to a figure computed under a different definition of the metric. The schema does not constrain the key text.

The example numbers in Appendix B.9 and in the examples [U09](examples/example_U09.md) and [U13](examples/example_U13.md) (100 independent tasks, 7 days, assessment ages of 10 and 45 minutes, and a 10 percent rollout) are illustrative and are not safe defaults. A deployment evaluates its own choices as this appendix describes.

## Appendix F. Capacity and outage reporting template (informative)

A deployment that claims capacity or outage behavior for PACT admission produces one report per deployment. The template sets no numeric thresholds; Sections 18 and 20.1 remain the normative sources.

The report states the exact versions of every component measured: the PACT specification and wire versions, the validator and gateway builds, each native adapter's protocol version and mapping revision, and the replay store, hold store, and policy registry. It also states the protected scope: the gateway, the environment, and the operations and resources to which the figures apply.

| Measurement | Report |
|---|---|
| Contract issuance | Measured p50 and p99 latency |
| Signature verification | Measured p50 and p99 latency |
| `object_digest` | Measured p50 and p99 latency |
| Native lookups | Measured p50 and p99 latency |
| Evaluation, end to end | Measured p50 and p99 latency |
| Replay-store compare-and-swap (CAS) contention | Contention measured at the claimed load, with that load stated |
| Evidence size distribution | Distribution of evidence artifact sizes |

For each of the following conditions, the report states the expected `DEFERRED` count and records zero fail-open admissions:

- replay store full;
- hold store down;
- policy registry down.
