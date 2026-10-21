# PACT example review — handoff to the specification team

**Date:** 2026-10-15  
**Basis:** PACT Protocol v1.0 (retrieved draft version 1), six worked use cases, and fourteen integration samples.  
**Scope:** Clarifications, adapter profiles, required external components, deliberate limitations, and unperformed validation extracted from these twenty examples.  
**Status:** Ready for review. All 27 findings are OPEN; priorities and suggested owners are recommendations, not assignments or new protocol requirements.

## Message for the draft team

The twenty examples show conditional architectural compatibility. They require an enforced PACT gateway and correctly integrated native identity, delegation, authorization, and execution. They do not establish seamless product support, running interoperability, or end-to-end security. Several narratives assume infrastructure that has not been supplied; some deliberately narrow the route, identity model, or execution environment.

The core admission pattern accommodates the illustrated decisions while leaving native authority with the environment. The immediate work is to specify the integration claims and verifiable adapter profiles, clarify lifecycle boundaries, assign deployment components, and execute conformance and empirical learning tests. Unimplemented normative requirements are not automatically missing core features. This register is not a claim of an exhaustive security audit of the full protocol.

Three focused decisions need explicit disposition: external approval/exception/activation state handling (G06), selection evidence changing between contract issuance and use (G10), and candidate staging relative to a mandatory evaluation-report digest (G12). The team should decide whether existing fields, installed checks, or declared extensions suffice; no new core message type is presumed necessary.

## Classification and priority

- **Profile:** An existing rule needs a concrete platform binding, native mapping, field schema, or execution profile.
- **Clarification:** Wording or lifecycle needs an interoperable decision rule; this is not automatically a proven vulnerability.
- **Deployment:** A native/operational component must exist and be configured correctly; preserve its external ownership.
- **Validation:** A behavior or safety claim remains untested or uncalibrated.
- **Coverage:** The example deliberately demonstrates a narrower supported form.

**P0:** Resolve or explicitly constrain before claiming secure enforced support for the affected scenario. **P1:** Resolve before broad interoperability, operational-maturity, or adaptive-safety claims. These are readiness priorities, not confirmed vulnerability severities. All IDs in this document are editorial review IDs.

## Required components and ownership

The sixteen entries below are logical responsibilities, not sixteen mandatory new services. Existing systems can supply them and one component can perform several responsibilities.

| ID | Responsibility | What must exist | Suggested owner |
|---|---|---|---|
| C01 | PACT enforcement gateway/validator | Installed hook on claimed paths; proof/schema/rule evaluation and admission gating. | Gateway implementer |
| C02 | Native authentication and claim adapters | Trusted native identity and current authoritative lookups with namespaced mappings. | Native IAM and adapter owners |
| C03 | Enrollment, issuer trust, and key lifecycle | Agent/operator/native actor/holder bindings, scoped issuers, rotation, compromise, and recovery. | IAM/security owner |
| C04 | Native delegation and task authority | Recognized user/workload-to-agent task, scope, expiry, and actual executor relationship. | Application/IAM owner |
| C05 | Evidence and authoritative status sources | Scoped issuers/native facts with original observation times, expiry, revocation, and protected references. | Issuer/adapter owner |
| C06 | External approval, exception, or PIM workflow | Existing approver/authentication/activation process and trusted applicability/status checks. | Native privilege/approval owner |
| C07 | Purpose and exact operation mapper | Installed task semantics and versioned request/resource/downstream mappings. | Adapter/application owner |
| C08 | Native resource executor and authorization | Actual operation under the intended identity with native restrictions and obligations. | Resource owner |
| C09 | Durable atomic exchange state | Nonce/receipt consumption, terminal decisions, active policy/version checks, and stored receipts. | Gateway/platform owner |
| C10 | Task attribution and outcome qualification | Authorized independent reporters, task/group provenance, visibility, deduplication, correction/dispute handling. | Resource/evidence owner |
| C11 | Contextual reputation service | Qualified dimensions, confidence/provenance, fresh snapshots, cold starts, and holds. | Reputation owner |
| C12 | Policy/artifact registry and learning lifecycle | Current authorized baseline/selector/scorer; for adaptation, controller, independent gates, rollout monitoring and recovery. | Learning/platform owner |
| C13 | Revocation and security holds | Current binding/issuer/evidence/policy status, durable holds, and recovery authority. | Security/IAM owner |
| C14 | Protected evidence and audit storage | Access controls, credential exclusion, retention/deletion, immutable references, and derived-data lineage. | Security/data owner |
| C15 | Native transactions, budgets, and side-effect control | Idempotency, task limits, completion/timeout reconciliation, cancellation, and native transactions. | Application/resource owner |
| C16 | Runtime authority and containment | Required attestations and real sandbox, egress, and output controls where claimed. | Runtime/security owner |

The common baseline is C01–C03, C05, C07, C09–C10, C13–C14 plus C12’s current authorized policy/artifact registry. Add C04 for delegated/task execution, C06 for required external authorization, C08 for the actual resource operation, C15 for relevant business transactions/limits, and C16 for claimed runtime/data-use guarantees. C11 and the full C12 lifecycle support reputation and adaptation. This inventory does not assert those components have been built.

## Deduplicated open register

| ID | Open issue | Type | Priority | Affected examples |
|---|---|---|---|---|
| G01 | Enforced integration scope | Profile / coverage | P0 | All 20 |
| G02 | Native identity and enrolled agent/key mapping | Profile | P0 | All 20 |
| G03 | Delegation and actual downstream execution identity | Profile / clarification | P0 | U01, U05, U06, U07, I02, I03, I04, I05, I08, I11, I12, I13, I14 |
| G04 | Exact request binding and native translation profiles | Profile | P0 | All 20 |
| G05 | Achievable source freshness and execution-time rechecks | Profile / validation | P0 | All 20 |
| G06 | External approval, exception, and activation states | Clarification / profile | P0 | U06, U07, I14 |
| G07 | Native outcome and visibility mappings | Profile / clarification | P1 | All 20 |
| G08 | Task independence and reporter qualification | Deployment / validation | P0 | U01, U09, U13 |
| G09 | Empirical reputation thresholds and evidence ages | Validation | P1 | U09, U13 |
| G10 | Selection evidence changes before contract use | Clarification / validation | P0 | U09, U13 |
| G11 | Safe bounded learning, rollout, and recovery | Validation / deployment | P0 | U13 |
| G12 | Candidate manifest staging and immutability | Clarification | P1 | U13 |
| G13 | Executed end-to-end conformance evidence | Validation | P0 | All 20 |
| G14 | SAML session-to-agent broker | Profile / coverage | P0 | I05 |
| G15 | LDAP identity, groups, and account state | Profile | P1 | I06 |
| G16 | mTLS peer identity and certificate lifecycle | Profile | P0 | I07 |
| G17 | OAuth/OIDC token and client/subject mapping | Profile | P0 | I02, I03, I14 |
| G18 | Graph delegated and application execution profiles | Profile / deployment | P0 | I02, I08 |
| G19 | Native file identity, paths, and handles | Profile / coverage | P0 | I04 |
| G20 | Database identity, row security, and pooling | Profile / coverage | P0 | I13 |
| G21 | Cloud/Kubernetes caller and executor boundaries | Profile / coverage | P0 | I09, I10 |
| G22 | ABAC fact authority and policy obligations | Profile | P0 | I11 |
| G23 | ReBAC model/store consistency and sharing paths | Profile | P0 | I12 |
| G24 | Privacy, retention, correction, and lineage operations | Deployment / validation | P1 | All 20 |
| G25 | Runtime evidence versus actual data-use control | Deployment / coverage | P0 | U01, U09, I01, I04, I11 |
| G26 | Multi-operation tasks, budgets, retries, and side effects | Profile / deployment | P0 | U01, U06, U07, I02, I03, I08, I14 |
| G27 | Transport, latency, capacity, and outage budgets | Validation / profile | P1 | All 20 |

## Finding details and closure evidence

### G01 — Enforced integration scope

**Status:** OPEN · **Type:** Profile / coverage · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** All 20 examples  
**Draft anchors:** §§2.3, 4.4, 17, 22–23

**Already specified / observed:** Enforced gateways and adapters are already required; native PACT support in the named products has not been demonstrated.

**Requested disposition or work:** Define an integration-profile template identifying protected routes/actions, enforcement points, native dependencies, alternative paths, unsupported forms, and the exact conformance claim.

**Evidence needed to close:** Demonstrate that every claimed path is controlled and bypass paths are closed, equivalently enforced, or explicitly outside the claim.

### G02 — Native identity and enrolled agent/key mapping

**Status:** OPEN · **Type:** Profile · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** All 20 examples  
**Draft anchors:** §§4.2, 6, 8.5, 17.2

**Already specified / observed:** The draft already requires trusted enrollment, stable identities, issuer scope, rotation, recovery, and holder binding; platform registries are assumed in examples.

**Requested disposition or work:** Specify namespaced native user/client/workload identifiers, trusted enrollment actors, shared-account handling, certificate/token/role-session bindings, and lifecycle rules.

**Evidence needed to close:** Fixtures distinguish another user, tenant, client, certificate, account, role session, or holder key; compromised identities cannot recover by self-assertion.

### G03 — Delegation and actual downstream execution identity

**Status:** OPEN · **Type:** Profile / clarification · **Priority:** P0  
**Suggested owner:** Spec maintainers with adapter/native-workflow owners  
**Affected examples:** U01, U05, U06, U07, I02, I03, I04, I05, I08, I11, I12, I13, I14  
**Draft anchors:** §§2.2, 4.3, 8.5, 11.5, 17

**Already specified / observed:** Native delegation remains external and requesting-principal restrictions must be preserved. Several examples assume task registries, session brokers, or credential executors.

**Requested disposition or work:** Define how agent, user/workload principal, authorized task, native delegation, broker, and actual downstream actor are bound, checked, and audited. Decide whether existing fields/checks/extensions suffice.

**Evidence needed to close:** An execution trace proves authority for each actor transition and rejects principal substitution, broader-credential fallback, changed tasks, and stale delegation.

### G04 — Exact request binding and native translation profiles

**Status:** OPEN · **Type:** Profile · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** All 20 examples  
**Draft anchors:** §§10–11, 13.3, 17.1, 22

**Already specified / observed:** The HTTP baseline and versioned equivalent mappings are specified; concrete platform mappings and independent test vectors remain absent.

**Requested disposition or work:** Pin origin, method, path/query, body, principal, resource/action mapping, consequential headers, mapping version, paging, fixed queries, and downstream translations.

**Evidence needed to close:** Independent implementations produce the same binding and reject changed resources, body/query/header semantics, mappings, origins, or extra downstream operations.

### G05 — Achievable source freshness and execution-time rechecks

**Status:** OPEN · **Type:** Profile / validation · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** All 20 examples  
**Draft anchors:** §§7.5, 8.3, 9.2, 11.5, 17.2, 18

**Already specified / observed:** Original observation times, bounded caching, fail-closed operation, and native consistency limits already exist; tokens, directories, sessions, and handles differ.

**Requested disposition or work:** Document source observation/status semantics, cache/replication bounds, outages, expiry, and checks at issuance, evaluation, handoff, and execution.

**Evidence needed to close:** Exercise revocation, stale snapshots, source clocks, mid-exchange policy changes, and outages; re-signing never launders an old observation.

### G06 — External approval, exception, and activation states

**Status:** OPEN · **Type:** Clarification / profile · **Priority:** P0  
**Suggested owner:** Spec maintainers with adapter/native-workflow owners  
**Affected examples:** U06, U07, I14  
**Draft anchors:** §§2.3, 8.3, 9.3, 11.4, 12.2, 15.5, 16.2, 17.3

**Already specified / observed:** Approval evidence and DEFERRED already exist. The retrieved draft retains terse wording; the examples use the subsequently discussed external-workflow clarification.

**Requested disposition or work:** Clarify current native decisions after authorized exceptions, immutable terminal receipts, and fresh contracts/presentations. Map missing, pending, rejected, expired, revoked, and inapplicable approvals; distinguish mandatory native approvals from explicitly adaptive PACT scrutiny.

**Evidence needed to close:** Fixtures cover pending deferral, demonstrated failure, fresh evaluation, wrong approver/scope, and mandatory human checks surviving high reputation.

### G07 — Native outcome and visibility mappings

**Status:** OPEN · **Type:** Profile / clarification · **Priority:** P1  
**Suggested owner:** Spec maintainers with adapter/native-workflow owners  
**Affected examples:** All 20 examples  
**Draft anchors:** §§11.4, 12, 14; Appendix A OutcomeReport

**Already specified / observed:** Admission, authorization, execution, quality, UNKNOWN, and NOT_APPLICABLE are specified; platform response mappings are illustrative.

**Requested disposition or work:** Map native denial, pre-authentication failure, empty queries, async acceptance/completion, ambiguous timeouts, and unavailable execution visibility to events and reputation eligibility.

**Evidence needed to close:** Never record a hidden row as read, an accepted restart as completed, admission as task success, or an ordinary denial/outage as proven misconduct.

### G08 — Task independence and reporter qualification

**Status:** OPEN · **Type:** Deployment / validation · **Priority:** P0  
**Suggested owner:** Deployment/security/evidence owners and independent evaluators  
**Affected examples:** U01, U09, U13  
**Draft anchors:** §§10.1, 14–15

**Already specified / observed:** Qualified reporters, task-group caps, deduplication, correction, and provenance are already required; trustworthy task/evaluation infrastructure is assumed.

**Requested disposition or work:** Provide a reference qualification policy for native task groups, reporter authority, independence/collusion, causal attribution, evidence lineage, and corrections/disputes.

**Evidence needed to close:** Reject repeated admissions, subdivided tasks, duplicate reports, self-praise, reciprocal endorsements, and misattributed environmental failures; corrections recompute derived results.

### G09 — Empirical reputation thresholds and evidence ages

**Status:** OPEN · **Type:** Validation · **Priority:** P1  
**Suggested owner:** Independent conformance/evaluation owners with adapter maintainers  
**Affected examples:** U09, U13  
**Draft anchors:** §§15.2–15.5, 16.3, 23

**Already specified / observed:** The baseline is not empirically calibrated. Example counts, observation durations, thresholds, and assessment ages are local choices.

**Requested disposition or work:** Define and independently evaluate deployment metrics, thresholds, calibration, context coverage, cold starts, drift, uncertainty, and failure costs.

**Evidence needed to close:** Evidence justifies any reduced scrutiny; sparse history, wrong contexts, decay, and threshold boundaries remain conservative. Example numbers are not promoted as safe defaults.

### G10 — Selection evidence changes before contract use

**Status:** OPEN · **Type:** Clarification / validation · **Priority:** P0  
**Suggested owner:** Spec maintainers with adapter/native-workflow owners  
**Affected examples:** U09, U13  
**Draft anchors:** §§9.4, 11.3, 11.5, 15.2, 16.5

**Already specified / observed:** Contracts pin effective rules and learning versions; snapshots pin their scorer. The examples require consistency but do not settle every selection-input race.

**Requested disposition or work:** Define how selection evidence is recorded/referenced and what a changed snapshot, confidence, hold, or policy does before presentation/handoff. Decide if installed checks or extensions suffice.

**Evidence needed to close:** Tests establish deterministic acceptance, rejection, or new-contract behavior when eligibility changes; an unjustified weaker set is not silently retained.

### G11 — Safe bounded learning, rollout, and recovery

**Status:** OPEN · **Type:** Validation / deployment · **Priority:** P0  
**Suggested owner:** Learning/platform owners and independent evaluators  
**Affected examples:** U13  
**Draft anchors:** §16, §22

**Already specified / observed:** Independent gates, shadowing, atomic promotion, monitoring, fallback, and rollback are already normative requirements; no lifecycle was executed.

**Requested disposition or work:** Implement and exercise controllers, independent evaluators, artifact/version stores, metric gates, rollout scope, drift/poisoning monitoring, and compatible recovery.

**Evidence needed to close:** Demonstrate concurrent-release conflicts, corrected data, policy expiry, bounded rollout, incompatible fallback rejection, contract invalidation, and hold preservation.

### G12 — Candidate manifest staging and immutability

**Status:** OPEN · **Type:** Clarification · **Priority:** P1  
**Suggested owner:** Spec maintainers  
**Affected examples:** U13  
**Draft anchors:** §§16.3–16.5; Appendix A LearningArtifact

**Already specified / observed:** LearningArtifact requires evaluation_report_digest while the narrative stages a candidate before evaluation. The old example could imply adding that digest later.

**Requested disposition or work:** Distinguish private candidate staging from registered signed manifests; define report timing, the immutable identity evaluated, revised-manifest identity, and any lifecycle implications without introducing a self-referential digest.

**Evidence needed to close:** Produce a schema-valid signed lifecycle with stable references and no omitted required field or mutation of an accepted signed object.

### G13 — Executed end-to-end conformance evidence

**Status:** OPEN · **Type:** Validation · **Priority:** P0  
**Suggested owner:** Independent conformance/evaluation owners with adapter maintainers  
**Affected examples:** All 20 examples  
**Draft anchors:** §§7, 11–13, 20, 22–23; Appendices A–C

**Already specified / observed:** The draft specifies crypto and negative tests. These examples remain narratives and partial excerpts, not running interoperable integrations.

**Requested disposition or work:** Publish signed fixtures and run independent multi-component tests of issuer/type/holder checks, replay, request changes, tenant confusion, denial preservation, sidecar handoff, rotation, and outages.

**Evidence needed to close:** Independent implementations interoperate on the advertised profile and reject required adversarial cases; results identify exact versions and protected scope.

### G14 — SAML session-to-agent broker

**Status:** OPEN · **Type:** Profile / coverage · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I05  
**Draft anchors:** §§6, 8.5, 13, 17; I05

**Already specified / observed:** The example keeps SAML SSO at the SP and assumes an authorized server-side task broker; unattended agent login is not demonstrated.

**Requested disposition or work:** Specify SP-session task authorization, agent enrollment, broker authority, expiry/logout, and supported workflows while retaining actual SAML validation.

**Evidence needed to close:** Reject wrong-SP/replayed assertions, another session principal, expired user/broker authority, and unauthorized agent tasks.

### G15 — LDAP identity, groups, and account state

**Status:** OPEN · **Type:** Profile · **Priority:** P1  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I06  
**Draft anchors:** §§8.5, 9.2, 17.2, 18; I06

**Already specified / observed:** A dedicated directory account and configured schema/resolver are assumed; LDAP does not supply a universal application entitlement model.

**Requested disposition or work:** Pin directory realms, supported authentication, stable identifiers, group/nested-group resolution, disabled-account semantics, lookup authority, and replication bounds.

**Evidence needed to close:** Exercise unauthenticated/empty binds, disabled/missing accounts, duplicate names, unsupported groups, denied lookups, outages, and removed membership.

### G16 — mTLS peer identity and certificate lifecycle

**Status:** OPEN · **Type:** Profile · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I07  
**Draft anchors:** §§4, 6–8, 17–18; I07

**Already specified / observed:** The example separates native TLS identity from the PACT key and assumes trustworthy PKI mapping and TLS termination.

**Requested disposition or work:** Define certificate identity policy, status/renewal, connection reuse/resumption, and authenticated peer-identity forwarding from a trusted terminator. Distinguish OAuth certificate-bound tokens.

**Evidence needed to close:** Reject forged forwarded headers, proxy bypass, wrong certificate/workload/key combinations, and unacceptable certificate status on reused connections.

### G17 — OAuth/OIDC token and client/subject mapping

**Status:** OPEN · **Type:** Profile · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I02, I03, I14  
**Draft anchors:** §§4, 6, 8.5, 13, 17–18; I02, I03, I14

**Already specified / observed:** Native sign-in and API authorization remain distinct. Issuer-specific validation, consent, audiences, credential flows, and sender constraints are assumed.

**Requested disposition or work:** Pin issuer/tenant/audience/subject/client/scope, opaque versus JWT validation, required introspection facts, refresh, storage, and native sender proofs. Do not relabel ID tokens as core PACT evidence.

**Evidence needed to close:** Block wrong audience/client/tenant, inactive or insufficient-scope tokens, missing consent/sender proofs, and authority changes on refresh.

### G18 — Graph delegated and application execution profiles

**Status:** OPEN · **Type:** Profile / deployment · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I02, I08  
**Draft anchors:** §§4.3, 8.5, 10, 17; I02, I08

**Already specified / observed:** Delegated Graph uses a custom gateway/OBO flow; app-only Graph uses a registered executor and scoped application authorization.

**Requested disposition or work:** Specify original and downstream app actors, grants/consent, OBO versus app-only acquisition, mailbox/resource mapping, and parallel grants defeating scope.

**Evidence needed to close:** Test wrong mailbox/app, broad parallel grants, consent loss, interaction/OBO failure, app-only user-endpoint misuse, and privilege-expanding fallback.

### G19 — Native file identity, paths, and handles

**Status:** OPEN · **Type:** Profile / coverage · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I04  
**Draft anchors:** §§4.3, 10, 17–18; I04

**Already specified / observed:** The example demonstrates a local Windows broker/open under a usable user context; SMB and Unix variants remain unworked.

**Requested disposition or work:** Specify identity acquisition, effective user/group/inherited rights, actual least-access opens, path/reparse/object binding, handle isolation/lifetime, and native revocation limits; define separate remote/Unix profiles.

**Evidence needed to close:** Reject broader-account fallback, changed paths/objects, inaccessible ACLs, stale contexts, and cross-task handles; remote variants also test delegation and share denial.

### G20 — Database identity, row security, and pooling

**Status:** OPEN · **Type:** Profile / coverage · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I13  
**Draft anchors:** §§4.3, 10, 17–18; I13

**Already specified / observed:** The database sample uses a dedicated restricted login and fixed query; shared pools and arbitrary SQL are not established.

**Requested disposition or work:** Specify role acquisition/current-role verification, owner/superuser/BYPASSRLS exclusions, grants, row semantics, query binding, connection reset, and any pooled identity mechanism.

**Evidence needed to close:** Prevent cross-request tenant/role leakage, bypass/owner execution, SQL substitution/injection, and hidden-row disclosure; preserve empty-result semantics.

### G21 — Cloud/Kubernetes caller and executor boundaries

**Status:** OPEN · **Type:** Profile / coverage · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I09, I10  
**Draft anchors:** §§4.3, 10, 13, 17; I09, I10

**Already specified / observed:** AWS covers a custom IAM-authorized API; Kubernetes covers a registered service-account executor. Universal interception is not demonstrated.

**Requested disposition or work:** Pin authentic AWS caller/role-session context and transformation, Kubernetes cluster/namespace/account/token audience, broker privileges, actual downstream actor, and implemented scope.

**Evidence needed to close:** Reject forged identity headers, wrong cluster/role session, wrong token audience, broader fallback, hidden additive grants, and translated operations with different semantics.

### G22 — ABAC fact authority and policy obligations

**Status:** OPEN · **Type:** Profile · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I11  
**Draft anchors:** §§8–10, 17–18; I11

**Already specified / observed:** The native policy engine remains authoritative; trustworthy subject/resource/device/environment sources and obligation enforcement are assumed.

**Requested disposition or work:** Define source authority, comparisons, document classification, policy version, current condition checks, and actual enforcement of filtering or other obligations.

**Evidence needed to close:** Tampered or stale clearance/classification/device/network facts, outages, changed execution conditions, and unmet obligations cannot disclose data.

### G23 — ReBAC model/store consistency and sharing paths

**Status:** OPEN · **Type:** Profile · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** I12  
**Draft anchors:** §§8.5, 10, 17–18; I12

**Already specified / observed:** A configured store/model and principal mapping are assumed. Removing one relationship does not remove a separate legitimate sharing path.

**Requested disposition or work:** Pin tenant/store/model/relation/object mappings, trusted contextual facts, query/cache consistency, full alternative-path semantics, and authorized relationship writes.

**Evidence needed to close:** Test tenant/model substitution, injected tuples, stale membership, remaining direct shares, service outage, and view-to-edit escalation.

### G24 — Privacy, retention, correction, and lineage operations

**Status:** OPEN · **Type:** Deployment / validation · **Priority:** P1  
**Suggested owner:** Deployment/security/evidence owners and independent evaluators  
**Affected examples:** All 20 examples  
**Draft anchors:** §§12.1, 14.4, 19

**Already specified / observed:** The draft already requires protected evidence, minimization, retention/correction, and lineage; operational stores and access rules are assumed.

**Requested disposition or work:** Implement authorized lookups, credential exclusion, sensitive-value minimization, deletion effects on derived snapshots/models, disputes/corrections, and private audit/reputation access.

**Evidence needed to close:** Corrections/deletions identify affected derived artifacts; records exclude credentials and unnecessary business contents; unrelated tenants cannot inspect them.

### G25 — Runtime evidence versus actual data-use control

**Status:** OPEN · **Type:** Deployment / coverage · **Priority:** P0  
**Suggested owner:** Deployment/security/evidence owners and independent evaluators  
**Affected examples:** U01, U09, I01, I04, I11  
**Draft anchors:** §§2.2, 10.1, 17.4, 19

**Already specified / observed:** Trusted runtime facts do not themselves prevent export, later misuse, or inappropriate outputs; purpose enforcement depends on installed native controls.

**Requested disposition or work:** Identify actual purpose checks, sandbox/egress/output controls and attestation coverage/freshness for every claimed guarantee. Document post-read residual limits.

**Evidence needed to close:** Distinguish correct runtime/purpose labels from prohibited operations and downstream data misuse; do not advertise unsupported guarantees.

### G26 — Multi-operation tasks, budgets, retries, and side effects

**Status:** OPEN · **Type:** Profile / deployment · **Priority:** P0  
**Suggested owner:** Adapter maintainers with spec and native-resource owners  
**Affected examples:** U01, U06, U07, I02, I03, I08, I14  
**Draft anchors:** §§10.3, 12.2, 14, 17.3

**Already specified / observed:** Fresh operation binding is required; native transaction/budget/idempotency/cancellation and async semantics remain external.

**Requested disposition or work:** Define task/page correlation, approval scope, native idempotency keys, limits, ambiguous effects, completion tracking, and cancellation across new contracts.

**Evidence needed to close:** Fresh contracts cannot reset budgets or duplicate orders/restarts; paging stays task-bound; ambiguous effects are reconciled rather than blindly retried.

### G27 — Transport, latency, capacity, and outage budgets

**Status:** OPEN · **Type:** Validation / profile · **Priority:** P1  
**Suggested owner:** Independent conformance/evaluation owners with adapter maintainers  
**Affected examples:** All 20 examples  
**Draft anchors:** §§7.5, 12, 13.2, 18, 20.1

**Already specified / observed:** Artifact lifetimes, size/deadline limits, envelope transport, and fail-closed stores are specified; production capacity was not measured.

**Requested disposition or work:** Publish each transport and achievable limits; measure lookup/signing/evaluation latency, replay/version store contention, evidence sizes, and documented fallbacks.

**Evidence needed to close:** At claimed load, exchanges fit the supported transport and expiry windows without dropping evidence, evicting live replay records, fabricating freshness, or failing open.

## Deliberate design choices and unsupported wider claims

| Source | Choice or assumption | Wider claim not established |
|---|---|---|
| I01 Basic | Dedicated account and controlled gateway | Shared-password agent distinction or enforcement on an unchanged server |
| I02/I03 OAuth/M365 | Custom API hook or constrained connector | PACT enforcement by Graph/every SaaS or protection of bypass routes |
| I04 files | Broker-local Windows user-context NTFS open | Remote SMB delegation/share controls, Unix behavior, immediate handle revocation |
| I05 SAML | Existing SP session plus authorized task broker | Universal unattended SAML agent login or delegation supplied by SAML itself |
| I06 LDAP | Dedicated account and configured resolver | Employee delegation or universal schema/nested-group semantics |
| I07 mTLS | Native certificate plus separate enrolled PACT key | OAuth certificate-bound tokens, SPIFFE/SPIRE, or insecure peer-header forwarding |
| I08 app-only | Explicit scheduled workload and scoped executor | Borrowed user rights or mailbox narrowing through profile declaration |
| I09 AWS | Custom IAM-authorized API Gateway integration | Direct PACT enforcement across arbitrary AWS services or inherited caller authority for its execution role |
| I10 Kubernetes | Dedicated-account executor and declared namespace scope | Universal interception, arbitrary impersonation, or absence of other additive grants from one YAML snippet |
| I11/I12 ABAC/ReBAC | Native engines and configured facts/model | Universal policies/relationships or instantaneous propagation |
| I13 database | Dedicated restricted login and fixed query | Safe shared pooling, arbitrary SQL, or executed database verification |
| I14 PIM | Existing human-governed activation/delegated execution | Agent-operated MFA/elevation or accepted action equaling completed action |
| U09 reputation | Already active selector and local illustrative thresholds | Empirical safety, predictive calibration, or measured benefit of reduced scrutiny |
| U13 learning | Hypothetical evaluation, rollout, and recovery | A trained/promoted model, exercised rollback, safe gate calibration, or resolved manifest staging |

These choices are not permission to bypass native controls and are not all protocol defects. A wider support claim needs its own adapter and evidence.

## Complete source-to-finding inventory

Uxx identifies original worked use cases; Ixx identifies integration samples. Original numbering is preserved. Every source now contains readiness warnings, assumptions, components, gaps, deliberate limits, and pending validation.

| Review ID | Updated file | Specific findings in addition to shared work | Scenario-specific components |
|---|---|---|---|
| U01 | [example_U01.md](../spec/v1.0/examples/example_U01.md) | G03, G08, G25, G26 | C04, C08, C10, C16 |
| U05 | [example_U05.md](../spec/v1.0/examples/example_U05.md) | G03, G07 | C04, C08, C10 |
| U06 | [example_U06.md](../spec/v1.0/examples/example_U06.md) | G03, G06, G26 | C04, C06, C08, C15 |
| U07 | [example_U07.md](../spec/v1.0/examples/example_U07.md) | G03, G06, G26 | C04, C06, C08, C15 |
| U09 | [example_U09.md](../spec/v1.0/examples/example_U09.md) | G08, G09, G10, G25 | C10, C11, C12, C16 |
| U13 | [example_U13.md](../spec/v1.0/examples/example_U13.md) | G08, G09, G10, G11, G12 | C10, C11, C12, C14 |
| I01 | [example_I01.md](../spec/v1.0/examples/example_I01.md) | G01, G02, G25 | C02, C03, C08 |
| I02 | [example_I02.md](../spec/v1.0/examples/example_I02.md) | G03, G17, G18, G26 | C02, C04, C08, C15 |
| I03 | [example_I03.md](../spec/v1.0/examples/example_I03.md) | G03, G17, G26 | C02, C04, C08, C15 |
| I04 | [example_I04.md](../spec/v1.0/examples/example_I04.md) | G03, G19, G25 | C04, C08, C15, C16 |
| I05 | [example_I05.md](../spec/v1.0/examples/example_I05.md) | G03, G14 | C02, C04, C08 |
| I06 | [example_I06.md](../spec/v1.0/examples/example_I06.md) | G02, G15 | C02, C03, C08 |
| I07 | [example_I07.md](../spec/v1.0/examples/example_I07.md) | G02, G16 | C02, C03, C08, C13 |
| I08 | [example_I08.md](../spec/v1.0/examples/example_I08.md) | G03, G18, G26 | C04, C03, C08, C15 |
| I09 | [example_I09.md](../spec/v1.0/examples/example_I09.md) | G04, G21 | C02, C03, C07, C08 |
| I10 | [example_I10.md](../spec/v1.0/examples/example_I10.md) | G04, G21 | C03, C02, C07, C08 |
| I11 | [example_I11.md](../spec/v1.0/examples/example_I11.md) | G03, G22, G25 | C04, C05, C08, C16 |
| I12 | [example_I12.md](../spec/v1.0/examples/example_I12.md) | G03, G23 | C04, C07, C08 |
| I13 | [example_I13.md](../spec/v1.0/examples/example_I13.md) | G03, G20, G07 | C04, C07, C08, C14 |
| I14 | [example_I14.md](../spec/v1.0/examples/example_I14.md) | G03, G06, G17, G26 | C04, C06, C08, C15 |

Shared work attached to all examples: G01, G02, G04, G05, G07, G13, G24, G27. The shared component baseline is described above and in each example. Direct source mappings identify where an issue is specifically exposed, not every possible transitive dependency. Qualification, scoring, and release findings also apply wherever another example enables the corresponding shared reputation or learning service.

## Recommended decisions and implementation sequence

1. Agree on the integration claim/profile template (G01), then prioritize native identity, delegation, operation, source-status, and platform profiles (G02–G05, G14–G23).
2. Resolve external approval states (G06), selection-input changes (G10), and complete immutable candidate registration (G12). Keep native IAM/approval processes external.
3. Assign deployment responsibility for every applicable component; require explicit execution identity, bypass control, authoritative sources, and consistency limits before advertising enforced support.
4. Close outcome, conformance, and empirical reputation/learning work with evidence (G07–G13), then exercise privacy, containment, side-effect, and capacity behavior (G24–G27).

## Work completed and practical limits

- Updated all six original use cases and fourteen integration samples while preserving the native-authority boundary.
- Preserved existing source identities and unrelated narratives. Corrected U13’s candidate step so it no longer suggests appending a required digest to an accepted signed manifest.
- Extracted 27 deduplicated OPEN findings and 16 component responsibilities with source mappings, draft anchors, recommended priorities/owners, and closure evidence.
- Did not modify the protocol draft, implement adapters, run live native-system integrations, measure reputation/learning efficacy, or send this handoff to a team.

## Editorial validation

The document checks cover the twenty-file inventory, finding/component ID integrity, preservation of original narratives except the stated U13 clarification, Markdown code-fence balance, JSON/YAML excerpt syntax, and package contents. They establish document consistency only, not protocol conformance, cryptographic interoperability, executed SQL, or a security evaluation.

## Review provenance

Current inputs were materialized from their existing file identities before editing. Versions below identify reviewed inputs, not a new protocol release.

| Review ID | Input version | Input SHA-256 |
|---|---:|---|
| U01 | 0 | 79f25019bfd7b6a5f67b43ba5aac4b4d627f49b8ba3f6b8d483799ad88e22752 |
| U05 | 0 | 2258ac3beafb1ccee0a8f347d4d7177238dc72119d5f20cec494ebe14fddbded |
| U06 | 0 | 3f32a0b212a2deb863169753848d429cff2d4fb08df8450904aec7c39e05ff2f |
| U07 | 0 | d0435c2b527e82343974d9b0072fd27beae99e5abdd36ad529f4b14b42c6d0b9 |
| U09 | 0 | 3b849938b291d3b1963c20650e034a31ac02eec774deb2c4890e088db86baa5b |
| U13 | 0 | 02a3559dbe0c8c221c7f25fbbc1d698178e6d268aadecde79fa69cb4f6acf0e6 |
| I01 | 0 | c082f99425af88e704baeffd3b0f5bcaaefa11385d5d611c0b0ba2e5474317dc |
| I02 | 0 | 98516dc5a6583346318fca47e49134dcd0a62725f3e0ea3c8902ecd4bbe72de2 |
| I03 | 0 | 191a1318c4be1716f8df6d8fba86a0590b4ce60d12e906cdc8a5863b2cc3b41e |
| I04 | 0 | 89b60db234e44b6855083590b6931cef81dfaa4f14eee6d460964471faec7379 |
| I05 | 0 | 41f8ce6d60c9e0eb6b41dc30e46da1ed32e22d83ee3124eae3e36fabe7824e5f |
| I06 | 0 | 4e979f4ccdcd20e553c23762be149452c1e520d6592f940021d2cdba8e77b88e |
| I07 | 0 | e3f3b33349e43c277567638b37969c5032557cafd75554cacffc9901beb7faeb |
| I08 | 0 | 117c6f4c0fdf37aa8dcd5eda36ab6eef31ad6abb70920e5fe3e9695978181055 |
| I09 | 0 | f4feb8e44720e3d067d54bcb5bc8a126748bc9a5b593b52503c0898319259594 |
| I10 | 0 | 3ea86cc2bf725a28dd7b09a2b43d5a9645bcfb41ad5b305f36e5bebc0cc4f6f6 |
| I11 | 0 | b4320d83bbcf6a09987f774e507b45237eb7449e614aab685aaba56c494b9fa2 |
| I12 | 0 | 55dd434b72b6a2d526e4bac3a5f5bbcf26ec777ebee92fbf6cd4f80bdaa22111 |
| I13 | 0 | dba2477f6d32d89d23291756150a26b4a6d28e7bf4aabb57c835e06fb0969051 |
| I14 | 0 | c3b5fa91485e72fc1eea9b97edda6bd7a2dca31e324369ab4c23649b509b44ba |

Draft input SHA-256: 5d1ea23158a7ad3f3b87ec60217ee33f0780b78183529cad31451aa554e5bc46 (retrieved version 1).
