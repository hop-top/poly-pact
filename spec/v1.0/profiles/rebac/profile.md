# PACT ReBAC model/store consistency and sharing-path profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose and status

This is an integration profile, filled on the structure of [`TEMPLATE.md`](../TEMPLATE.md), for relationship-based access control (ReBAC) where the native decision is a Check against an OpenFGA relationship store. It is the profile deliverable for finding G23 of `docs/handoff.md` (source repository only, not part of the mirror) and fills the claim for the sample [I12](../../examples/example_I12.md). G23 asks to pin the tenant, store, model, relation, and object mappings, to say which contextual facts are trusted, to state the query and cache consistency, to state what a Check means when more than one sharing path exists, and to say who may write relationships. This profile answers each item (section 12) and states what stays unestablished (sections 6, 9, and 14).

The profile adds no wire field and no protocol requirement. Where it and [`draft.md`](../../draft.md) differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. The rules RB-1 to RB-19 (section 11) are normative for an adapter that claims this profile; the other sections state the claim, the evidence, and the limits.

The adapter conformance cases `REBAC-01` to `REBAC-12` (section 10) are in `spec/v1.0/fixtures/adapters/rebac/`. The statements about OpenFGA cite the upstream documentation (section 13); section 14.3 records the behaviors that were also observed on an OpenFGA server and the release they were observed on.

Conventions used below:

| Token | Meaning |
|---|---|
| `RB-n` | A normative rule of this profile (section 11). |
| `REBAC-nn` | A closure item of G23 and the negative case that demonstrates it (sections 10 and 12). |
| `[OF-n]` | A statement about OpenFGA taken from the upstream page listed as OF-n in section 13, read while writing this profile. Every statement about what OpenFGA does carries one, or is marked "to probe". |
| `P-n` | An item to probe against a real server before this profile supports an enforced claim (section 14). |
| `R`, `B`, `F` ids | Route, bypass path, and freshness source rows of sections 2, 5, and 8. |

The sample's names (Maya, Orion, Northstar) are fictional. This profile uses them only in worked examples.

## Profile header

| Field | Value |
|---|---|
| Profile name | `ReBAC with an OpenFGA relationship store` |
| Target product and version | OpenFGA server, release pinned per environment and recorded in the pin record (RB-1); the release is not established here (P-1). Upstream documentation places the per-request consistency preference in v1.6.0 and later without a flag, and in v1.5.7 only behind an experimental flag (RB-11, [OF-6], [OF-7]) |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `2`, `2026-10-18` |
| Maintainer | PACT specification maintainers |
| Reference documents | draft = `spec/v1.0/draft.md`; handoff = `docs/handoff.md` (source repository only; sections 6 and 12 draw on it); identity rules = `spec/v1.0/profiles/identity-mapping.md`; freshness rules = `spec/v1.0/profiles/freshness.md` |

## 1. Claim scope

**How to fill:** The claim is for an in-gateway deployment in `enforced` mode whose `authorize_native` is one OpenFGA Check per protected operation.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway. The trusted sidecar/service form is not claimed (section 6) |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed; connected services of the deployment supply them |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced` |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` |
|---|---|---|
| `openfga-http` | `1.x`: the OpenFGA HTTP API, whose OpenAPI document declares `info.version` `1.x` [OF-2]. The server release is pinned per environment and recorded by probe P-1 | `pact-rebac-1` |

The claim covers the relationship decision for two operations on a document, read and edit. It does not cover the authenticating mechanism (its own profile declares it), the document service's own enforcement beyond the conditions of draft §2.3, or any operation other than R1 and R2.

## 2. Protected routes and actions

**How to fill:** A mechanism profile fixes route classes; the deployment's installed mapping binds each concrete route to exactly one of R1 and R2, and a route that reduces to neither is not claimed.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/documents/{document_id}` | `GET` | `document.read`, relation `viewer` | `document:<object-id>`, where the registry (RB-6) maps the native document identifier taken from the path parameter, in the realm of the authenticated principal |
| R2 | `/documents/{document_id}` | `PATCH` | `document.write`, relation `editor` | `document:<object-id>` as for R1; the request body and consequential headers are part of the bound operation (draft §10.2) |

The patterns are reference patterns. A deployment that serves other paths states them in its installed mapping, at mapping revision `pact-rebac-1` or later. Document listing, search, deletion, sharing, and any relationship change are not claimed (section 6).

### 2.1 Relation table

The relation is chosen by the action of the mapped operation and by nothing else (RB-5). The table is versioned with the mapping revision, so the contract issuer and the validator use the same table (draft §10.2, §17.2).

| Table revision | Action | Relation | Object type |
|---|---|---|---|
| `pact-rebac-1` | `document.read` | `viewer` | `document` |
| `pact-rebac-1` | `document.write` | `editor` | `document` |

### 2.2 Reference model (informative)

The sample's model has three types and the permission `viewer` derived from project membership, with optional direct viewers. This table restates it and adds the relation `editor` that R2 needs; the sample's text does not define `editor`, so the reference model adds it as a direct assignment only. A deployment's pinned model defines its own derivation, and this profile pins the relation names, not their definitions.

| Type | Relation | Meaning in the reference model |
|---|---|---|
| `user` | none | A native collaboration principal, by its mapped subject id (RB-6) |
| `project` | `member` | Assigned to users |
| `document` | `parent` | The project the document belongs to |
| `document` | direct viewer | Optional direct share to an individual user |
| `document` | `viewer` | Direct viewer, or member of the parent project |
| `document` | `editor` | Direct assignment only (added by this profile) |

[OF-12] documents the pattern: a document's parent relation lets a relation derive from the parent, and "users that are directly assigned" remain another way to hold the relation.

## 3. Enforcement points

**How to fill:** The five required functions run in order inside the gateway's request path, and the other four adapter functions of draft §17.1 are listed as supporting rows.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Gateway login stage, before routing, through the deployment's existing identity mechanism | Gateway implementer and IAM owner | Produces the principal in that mechanism's namespace (identity-mapping §3.3, ReBAC row), never an OpenFGA label |
| 2 | `map_operation` | Gateway mapping stage, mapping revision `pact-rebac-1` | Adapter owner | Derives action, document, and principal from the actual request; selects the object per RB-6 and the relation per RB-5; covers path, query, body, and consequential headers (draft §10.2) |
| 3 | PACT evaluation | In-gateway validator in the same request path, after mapping and before native authorization | Gateway implementer | In-gateway form: no sidecar handoff |
| 4 | `authorize_native` | The gateway's Check call to the pinned OpenFGA store (RB-1 to RB-13) | Adapter owner for the call; resource owner for the store, model, and tuples | The original principal's mapped subject is the Check user (RB-19). A native denial is final (draft §2.3) |
| 5 | Execution | The document service performs the read or the edit for the delegating principal | Resource owner | Declared executor class `delegated-user` (draft §17.5); reached only after steps 1 to 4 pass |
| support | `resolve_agent_binding` | Enrollment registry lookup inside the gateway, by the realm, the authenticated workload, and the agent ID that the presentation names | Gateway implementer | Supplies the enrolled agent ID and holder key (identity-mapping §4). Whether a workload may carry more than one record is the choice of the authenticating profile (section 7) |
| support | `read_native_claim` | Lookup in the authenticated request context and the installed configuration | Adapter owner | Approved native paths: `/attributes/environment/principal_id`, `/attributes/environment/tenant_id`, `/attributes/delegation/authority_ref`. The relationship store is not read through this function (RB-14) |
| support | `check_context` | Installed gateway checks | Gateway implementer | `native-principal-binding-v1`, `native-delegation-v1`, `execution-identity-v1` (draft §17.5); their definitions belong to the delegation work of finding G03 (section 7) |
| support | `record_outcome` | Gateway outcome writer after the Check and after execution | Gateway implementer | A Check allow and a Check deny are `AUTHORIZATION` events with zero reputation weight; the executed read is `EXECUTION`; each references an immutable native record of the executor (draft §14.2, §14.5). An outage is not misconduct (draft §14.3) |

## 4. Native dependencies

**How to fill:** Twelve of the sixteen handoff components are used, and each of the other four carries the reason it does not apply.

The deployment supplies each system. Listing a component does not assert that it has been built; the reference implementation has an adapter for this profile (section 15).

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and filter chain | Gateway implementer | To be supplied by the deployment |
| C02 | Native authentication and claim adapters | baseline | The deployment's identity mechanism, and the adapter that implements `authorize_native` for this profile | IAM owner and adapter owner | The identity mechanism is to be supplied; the adapter is `go/adapters/rebac` in the reference implementation (section 15) |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry (identity-mapping §4) | IAM and security owner | To be supplied; a reference registry exists in `go/adapter/enroll` |
| C04 | Native delegation and task authority | delegated or task execution | The collaboration system's record of the principal-to-agent task authorization | Collaboration platform owner | Required: the sample assumes it; its binding rules are the delegation work of finding G03 (section 7) |
| C05 | Evidence and authoritative status sources | baseline | OpenFGA store (the Check), enrollment registry | Resource owner, adapter owner | To be supplied |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: read and edit of a document need no external approval in this claim |
| C07 | Purpose and exact operation mapper | baseline | Mapping registry holding the pin record, relation table, and subject and object mappings (RB-1 to RB-6) | Adapter owner | To be supplied; this profile specifies it |
| C08 | Native resource executor and authorization | the actual resource operation | OpenFGA store with the pinned model and tuples; the document service | Resource owner | To be supplied |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store | Platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Gateway outcome writer and document service audit log | Resource owner | To be supplied |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | Registry only; no adaptation lifecycle is claimed. Reputation and learning cannot change the relation table or the pin (RB-18) |
| C13 | Revocation and security holds | baseline | Revocation and hold store | Security and IAM owner | To be supplied |
| C14 | Protected evidence and audit storage | baseline | Access-controlled evidence and audit store | Security and data owner | To be supplied |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: no budget or transaction limit is claimed; the document service keeps its own idempotency control for the edit (draft §10.3) |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no runtime attestation or data-use guarantee is claimed (draft §17.4) |

## 5. Alternative and bypass paths

**How to fill:** Six other ways to reach a document or to influence the relationship decision are listed: two `equivalently-enforced`, two `closed`, and two `out-of-claim`.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Another legitimate sharing path in the native model: a remaining direct share, membership of another project, or a public grant, after one path is removed | `equivalently-enforced` | The Check evaluates the full pinned model, so every path the model grants meets the same `authorize_native` point and the same decision (RB-14); fixture `REBAC-05` |
| B2 | View-then-edit: using an allowed `viewer` decision, or a read-bound admission, to edit the same document | `equivalently-enforced` | The edit is a separate operation (R2) that meets steps 1 to 5 again with relation `editor` (RB-18); fixtures `REBAC-07`, `REBAC-08` |
| B3 | Relationship data supplied by the agent: a profile or evidence claim naming a membership, a `contextual_tuples` value, a store id, a model id, or a tenant in the request | `closed` | None of them is read as a tuple, a pin, or a mapping (RB-3, RB-8); fixtures `REBAC-01`, `REBAC-02`, `REBAC-03` |
| B4 | A document of another tenant presented through this tenant's mapping | `closed` | The registry entry of the document belongs to one realm and a mismatch sends no Check (RB-4); fixture `REBAC-09` |
| B5 | Direct request to the document service that skips the gateway | `out-of-claim` | Excluded in section 6: this profile does not establish network or credential separation between the agent and the document service. A deployment that closes it adds its own control and negative fixture |
| B6 | Direct calls from the agent to the OpenFGA API (Check, Read, Expand, ListObjects, or Write) | `out-of-claim` | Excluded in section 6: this profile does not establish that the agent has no route or credential to the store API (RB-16, P-5). A deployment that closes it adds its own control and negative fixture |

The alternative-path semantics of B1 are stated in RB-14: after a membership removal, a remaining direct share legitimately keeps the Check allowed. PACT does not remove that share and does not deny on its own account.

## 6. Unsupported forms

**How to fill:** The first row is seeded from the "I11/I12 ABAC/ReBAC" row of the handoff "Deliberate design choices" table, whose wider claim not established reads "Universal policies/relationships or instantaneous propagation". The other rows come from sections 2, 5, and 11.

| Unsupported form | Seed (handoff source row) | Why it is not established |
|---|---|---|
| Universal relationships: any relationship model or store, or one fixed graph semantics, treated as covered | I11/I12 ABAC/ReBAC: "Universal policies/relationships or instantaneous propagation" | Only a configured store and a pinned model are claimed; the model's meaning belongs to the native system (RB-1, RB-14) |
| Instantaneous propagation of a relationship change | I11/I12 ABAC/ReBAC: same row | A change reaches the gateway at the next Check, within the store's own consistency; the bound is stated in section 8 and section 9 and depends on probes P-1 and P-2 |
| Writing, changing, or deleting relationships through PACT, an agent, a profile claim, evidence, a receipt, or an outcome report | Section 5, B3 and B6 | Relationship writes are application-only (RB-16) |
| Contextual tuples supplied by the agent, or taken from a profile or evidence claim | Section 5, B3 | Only gateway-derived tuples are allowed (RB-7, RB-8) |
| Listing, searching, or filtering documents with ListObjects, Expand, or Read, and reading relationships as profile field values | Section 2 | Only the Check decides (RB-15); those queries answer different questions and have their own limits [OF-9], [OF-10] |
| An agent as a relationship subject, or an agent acting under relationships of its own | Section 7 | The subject is the delegating principal's mapped subject (RB-19) |
| `user` values that are usersets or wildcards, and cross-store Checks | Section 11, RB-6 | A userset is self-defining in a Check [OF-2]; the adapter sends only the mapped `user:<subject-id>` to the one pinned store |
| Models that use conditions: a Check `context` object or conditioned tuples | Section 2.2 | No gateway-derived `context` is specified; the adapter sends none |
| The trusted sidecar/service deployment form | Section 1 | Only the in-gateway form is claimed |
| Shared accounts as a way to tell agents apart | Section 7; identity-mapping §5 | The relationship decision is per delegating principal and cannot distinguish agents; each agent needs its own enrollment |
| Network or credential separation between the agent and the document service or the store API | Section 5, B5 and B6 | A deployment control with no negative fixture in this profile |
| Any route other than R1 and R2 | Section 2 | Not listed in section 2, so not claimed |

## 7. Identity mapping

**How to fill:** The shared rules are in [`identity-mapping.md`](../identity-mapping.md); the table records the choices this profile makes or narrows.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | The principal is the identifier of the authenticating mechanism, in that mechanism's namespace (identity-mapping §3.3, ReBAC row). The relationship subject `user:<subject-id>` and the object `document:<object-id>` are mapped facts (draft §17.2), not identifiers, and are produced by the registry of RB-6. No new namespace token is defined |
| Trusted enrollment actors | Both actors of identity-mapping §4.2. Changing the mapping registry is a gateway administrative act (draft §4.2); the application's sharing service, the agent, a profile, and a signed claim cannot change it |
| Shared-account handling | Inherited (identity-mapping §5, IM-19): the relationship engine authenticates nobody, so the shared-account choice and its consequence are those of the profile whose mechanism authenticated the request. Whatever that choice, a shared account is no way to tell agents apart here (section 6): two enrolled agents acting for one principal get the same relationship decisions, because the native model decides per principal, and each agent has its own enrollment |
| Certificate, token, or role-session bindings | None specific. The credential binding is the authenticating mechanism's (identity-mapping §6). The gateway's call to the store uses the gateway's own store credential, never the principal's or the agent's |
| Lifecycle rules (rotation, compromise, recovery) | Deferred to identity-mapping §7. Removing a principal from the registry withdraws every PACT-mediated access of that principal at the next evaluation. A subject id is never reassigned (RB-6) |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None. The profile is stricter in one place: the registry mapping is one to one per store, so no two principals share a subject id (RB-6) |

### 7.1 Dependency on the delegation work (finding G03)

The relationship `user` of a Check is bound to the delegating principal: the principal of the operation context, for whom the task was authorized, and never the agent and never a service or administrator identity (RB-19). Finding G03 of `docs/handoff.md` covers how the agent, the principal, the authorized task, the native delegation, the broker, and the downstream executor are bound and checked (draft §17.5). This profile depends on that work textually only. It names the values the checks bind (`principal_id`, `Intent.task_id`, `/attributes/delegation/authority_ref`, the executor class `delegated-user`) and the results the sample expects, and it defines no algorithm for `native-principal-binding-v1`, `native-delegation-v1`, or `execution-identity-v1`. Until that work lands, a claim under this profile cannot cite more than the draft's own §17.5 text for those checks.

## 8. Freshness

**How to fill:** Two sources are declared, the relationship store and the enrollment registry, each with a bound it can achieve and an outage rule.

The relationship decision is not read as a field value and is not compared with a field rule, so the age arithmetic of [`freshness.md`](../freshness.md) §3 does not apply to it. Row F1 and section 8.2 declare instead what draft §18 calls the separately documented consistency of native authorization. The freshness of the principal's source belongs to the profile of the authenticating mechanism (O-6).

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 OpenFGA Check decision (`authorize_native`) | Current authoritative state, read for each Check with `HIGHER_CONSISTENCY`: the documented caches are not used and the read goes to the datastore [OF-1], [OF-5]. The decision carries no observation time: the Check response has the field `allowed` and a field the documentation calls internal [OF-2], so a revision or consistency token is not available [OF-1]. The declared bound holds only if probes P-1 and P-2 pass | 0 | 0 | `DEFERRED` (RB-13) |
| F2 Enrollment registry (agent and key binding status) | Current authoritative state, read for each evaluation. The observation time of a binding is the time of its last change (identity-mapping IM-10), so no field rule compares it with `max_age`; the 0 follows the formula of `freshness.md` §4.2 for an authoritative source | 0 | 0 | `DEFERRED` |

If probing shows that the pinned deployment cannot meet F1, the deployment's instance of this profile declares the observed bound in place of 0. A requirement with a smaller limit is then `DEFERRED` or changed by its publisher (`freshness.md` §4.2, convention 2).

### 8.1 Membership and status sources

The relationship store supplies membership and role facts (project membership, document roles) as a decision. The schema's fact vocabulary has no `relationship` value, so the closest values `groups` and `roles` are used (section 14, O-4). The adapter asks the store for each decision, so it holds no cached membership and uses no change feed.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 OpenFGA Check decision (`authorize_native`) | `groups`, `roles` | `true` | Relationship store Check API | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

### 8.2 Consistency preference and cache bounds

The adapter sends `consistency` `HIGHER_CONSISTENCY` on every Check (RB-9). The parameter, its values, and its default are documented in [OF-1] and [OF-2]: `UNSPECIFIED` is the default and behaves as `MINIMIZE_LATENCY`, which "will serve queries from the cache when possible"; `HIGHER_CONSISTENCY` "will skip the cache and query the database directly". The documented consequence for this profile is that, for a Check with `HIGHER_CONSISTENCY`, the server's Check query cache and iterator cache are not used [OF-5], and that the same holds when caching is disabled, as it is by default [OF-1].

Each environment records the server's cache and replica settings in its pin record, so the bound behind F1 is checkable. The defaults below are the documented defaults of the current server documentation [OF-5]; whether they hold on the pinned release is probe P-3.

| Setting | Documented default | Used for a Check with `HIGHER_CONSISTENCY` | Recorded in the pin record |
|---|---|---|---|
| Check query cache (`check-query-cache-enabled`, `check-query-cache-ttl`) | disabled; TTL 10 s | No [OF-5] | Enabled flag and TTL |
| Check iterator cache (`check-iterator-cache-enabled`, `check-iterator-cache-ttl`) | disabled; TTL 10 s | No [OF-5] | Enabled flag and TTL |
| Cache controller (`cache-controller-enabled`, `cache-controller-ttl`) | disabled; TTL 10 s | Not relevant: it invalidates the two caches above [OF-5] | Enabled flag and TTL |
| Secondary (read replica) datastore | none | Reads that request `HIGHER_CONSISTENCY` go to the primary: documented for PostgreSQL [OF-6] and for MySQL from v1.22.0 [OF-7] | Present or absent, and the observed replication lag |
| Consistency preference sent by the adapter | n/a | `HIGHER_CONSISTENCY` on every Check (RB-9) | Fixed by this profile |

Two bounds follow from the documented behavior.

- With `HIGHER_CONSISTENCY`, no documented cache contributes to staleness, and the declared bound of F1 is 0 s against the primary datastore. The datastore's own commit semantics remain the consistency domain (section 9).
- If a deployment sent `MINIMIZE_LATENCY` and enabled the caches, the documented sources of staleness would be the three TTLs of the table, and the documentation says the query cache "turns Check and ListObjects into eventually consistent APIs" [OF-5]. This profile gives no bound for that mode, and the adapter never uses it.

The documentation gives a cost: "Always specifying `HIGHER_CONSISTENCY` will have a significant impact in performance" [OF-1]. This profile accepts that cost for protected operations; the capacity figures belong to the deployment (draft §20.1).

## 9. Residual limits

**How to fill:** The profile states what remains true after a successful admission and an allowed Check, and how a change reaches the gateway from each source.

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Document data already returned to the agent is not recalled by a later tuple removal or revocation; the edit already applied is not undone. No egress or data-use control is claimed (draft §17.4, §18) | Disclosed here; no bound |
| Revocation propagation: relationship store | A tuple deletion or addition reaches the gateway at the next Check. The consistency domain is the OpenFGA datastore that serves `HIGHER_CONSISTENCY` reads. Removing one tuple removes one path only; a remaining path keeps the decision allowed (RB-14) | 0 s after the datastore commit, if probes P-1 and P-2 pass; otherwise the observed replication lag. Instantaneous global propagation is not demonstrated |
| Revocation propagation: enrollment registry | A rotation, revocation, or compromise mark reaches the gateway at the next evaluation (identity-mapping §7.5) | 0 s within the registry's own consistency; the registry's replication delay, if it has replicas, is its declared bound |
| Revocation propagation: pin and mapping changes | A new pin record, relation table, or subject and object mapping takes effect in a gateway instance when that instance loads the configuration | The deployment's configuration rollout time, which this profile does not establish. An instance still on the old record keeps using the old store, model, and table |
| Check-to-execution gap | The Check and the document service's operation are not atomic. A relationship that changes between them is honored by the operation already allowed (draft §18) | The time between the Check and the execution; disclosed, no bound |
| Remaining sharing paths | A removal of membership, or of one share, leaves every other path in force (RB-14) | Disclosed; removing all paths is a native act of the sharing service |
| No observation reference | The Check returns no revision or consistency token [OF-1], so the decision has no `SourceRef` and no re-stamp can be detected for it (`freshness.md` §7). The integration rests on the store's committed state at the time of the read | Disclosed; no bound |
| Tuples outlive the principal | Tuples that name a subject id remain in the store until the application removes them. The registry never reassigns a subject id (RB-6), so a later principal does not inherit them | Disclosed; clean-up is a native act of the sharing service |
| Contextual tuples from token claims | A tuple derived from a token claim lasts until the token expires, even if the underlying claim changes [OF-4] | The token lifetime, declared by a deployment that uses such a tuple in its own section 8 row (RB-7) |
| Store credential scope | The documentation read does not describe a production-supported way to limit one store credential to Check (RB-16, [OF-14]) | Open: probe P-5 |

## 10. Fixture index

**How to fill:** the negative cases that demonstrate the claim and the expected result of each.

Nine cases carry the closure items of G23, and `REBAC-10` to `REBAC-12` replace three common cases. Each is a group of adapter cases of this profile in `spec/v1.0/fixtures/adapters/rebac/`, one file per variant, named by its lower-case ID and variant, such as `rebac-04.stale-membership.json`, with the manifest id `adapters/rebac/rebac-04.stale-membership`; a group of one case has no variant (`rebac-10.json`). The native state of the cases, the fake store a harness builds from it and the hooks it fires are described in the cases README (`spec/v1.0/fixtures/adapters/rebac/README.md`). The reference model of section 2.2 is the asset `assets/model.fga`, and `assets/model-next.fga` is a later model of the same store. Every case and both assets are registered in `spec/v1.0/fixtures/manifest.json` and listed in the `fixtures` array of `profile.json`.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `REBAC-01` | Tenant substitution: `authorize_native` for a principal of another tenant, for which the store holds tuples, or for an operation of another environment than the principal's realm | `CONTEXT_MISMATCH`; no Check is sent (hook `check` does not fire) | `adapters/rebac/rebac-01.other-tenant`, `rebac-01.other-environment` | R1, R2, B3, RB-3, RB-4 |
| `REBAC-02` | An `authorization_model_id` in the request query, with a later model in the store under which the principal would be a viewer | The value is not read: the Check names the pinned model, so the decision is a denial with `policy_revision` the pinned id, and hook `check-latest-model` does not fire; the control shows the pinned id with a later model present | `adapters/rebac/rebac-02.query-model-id`, with the control `rebac-02.pinned-model`; assets `model.fga`, `model-next.fga` | R1, R2, B3, RB-2, RB-3 |
| `REBAC-03` | Injected tuple: a membership of the project named in the request query or in an allowlisted header, with no stored path | Not a tuple: hook `contextual-tuples` does not fire, and the decision follows the stored relationships, a denial | `adapters/rebac/rebac-03.query-claim`, `rebac-03.header-claim` | R1, B3, RB-7, RB-8 |
| `REBAC-04` | Stale membership: a store cache that still holds a removed membership; and one that lags behind an added membership | Hook `check-cached` does not fire (every Check asks `HIGHER_CONSISTENCY`), and the decision follows the store: a denial after the removal, an allow after the addition | `adapters/rebac/rebac-04.stale-membership`, `rebac-04.added-membership` | R1, F1, RB-9 |
| `REBAC-05` | Remaining direct share: membership of the project removed, a direct share of the document kept; and no remaining path | The Check is allowed and the adapter does not deny on its own; with no path, the denial as the store gave it | `adapters/rebac/rebac-05.direct-share`, `rebac-05.no-remaining-path`; asset `model.fga` | R1, B1, RB-14 |
| `REBAC-06` | Store outage or fault: no connection, no answer in time, `500`, `422`, `409`, `403`, `401` for the gateway's key, a `200` answer whose `allowed` is not one boolean or is absent or is not JSON; `400` and `404` | No allow, no execution: `DEPENDENCY_UNAVAILABLE` (`DEFERRED`, draft §18, §22.2), and the key appears in no error; for `400` and `404` the configuration fault `UNSUPPORTED_REQUIREMENT`, never a decision | `adapters/rebac/rebac-06.unreachable`, `rebac-06.timeout`, `rebac-06.server-error`, `rebac-06.throttled`, `rebac-06.conflict`, `rebac-06.forbidden`, `rebac-06.unauthenticated`, `rebac-06.allowed-string`, `rebac-06.no-allowed`, `rebac-06.duplicate-allowed`, `rebac-06.not-json`, `rebac-06.bad-request`, `rebac-06.not-found` | R1, R2, F1, RB-13 |
| `REBAC-07` | An edit requested with a read-bound presentation; and an operation context bound to `document.read` for a `PATCH` of the document | `map_operation` maps the edit to `document.write`, so the read-bound presentation does not match it and the validator answers `CONTEXT_MISMATCH` (draft §10.2, §10.3); `authorize_native` refuses the read-bound context for an edit with `CONTEXT_MISMATCH` and sends no Check | `adapters/rebac/rebac-07.edit-maps-write`, `rebac-07.read-context-for-edit` | R2, B2, RB-18 |
| `REBAC-08` | A fresh edit operation, admitted for `document.write`, by an editor who is not a viewer and by a viewer who is not an editor; an action with no row in the relation table | The Check carries relation `editor`: an allow for the editor, a denial for the viewer; the unlisted action has no Check, `UNSUPPORTED_REQUIREMENT` | `adapters/rebac/rebac-08.editor`, `rebac-08.viewer-only`, `rebac-08.unlisted-action` | R2, B2, RB-5, RB-18 |
| `REBAC-09` | A document whose registry entry belongs to another tenant; a document with no registry entry | `CONTEXT_MISMATCH`; no Check is sent | `adapters/rebac/rebac-09.other-tenant-document`, `rebac-09.unregistered-document` | R1, R2, B4, RB-4, RB-6 |
| `REBAC-10` | A Check that answers `allowed` true | `authorize_native` returns `ALLOW` with no obligations; no execution hook fires. Replaces `COMMON-06.allow-no-execution` | `adapters/rebac/rebac-10` | R1, RB-13, RB-19 |
| `REBAC-11` | A Check that answers `allowed` false | `authorize_native` returns `DENY` with no obligations; no execution. Replaces `COMMON-06.deny-unchanged` | `adapters/rebac/rebac-11` | R1, RB-13, RB-14 |
| `REBAC-12` | A Check against the pinned store and model | `source_id` the pinned `store_id`, `policy_revision` the pinned `authorization_model_id`, `source_ref` null and `decided_at` null: a Check answer carries no decision record and no decision time. Replaces `COMMON-06.decision-provenance` | `adapters/rebac/rebac-12` | RB-1, RB-2 |

A stub that denies when the stored membership of the document's project is absent, ignoring direct shares, fails `REBAC-05.direct-share`; the Go repository keeps such a stub as the red baseline of every ReBAC case. The integration tier of the Go repository runs the cases an OpenFGA server can realize, `REBAC-04` and `REBAC-05` among them, against a server named by `PACT_TEST_OPENFGA_URL`.

Paths without a fixture: B5 and B6 are `out-of-claim`. Section 14 lists the rules that no case exercises (O-1, O-2).

### Replaced common cases

| Common case | Reason | Replacement |
|---|---|---|
| `COMMON-06.allow-no-execution` | A Check answer carries no obligation [OF-2] | `REBAC-10` |
| `COMMON-06.deny-unchanged` | As above | `REBAC-11` |
| `COMMON-06.decision-provenance` | A Check answer carries no decision record and no decision time [OF-2] | `REBAC-12` |

`COMMON-06.no-connector-substitution` and `COMMON-06.no-policy-not-allowed` run unchanged: the harness realizes `policy` as tuples on the relation of the action.

## 11. Normative rules

The rules are grouped by the item of G23 they answer. "Request" means the actual authenticated request and the presentation; "registry" means the mapping registry of component C07.

### 11.1 Pins and mappings

**RB-1. Pin record.** For each realm (`tenant_id`, `environment_id`) the gateway's trusted configuration (draft §4.2) holds one pin record: `store_id`, `authorization_model_id`, the relation table revision, the mapping revision, the OpenFGA server release (probe P-1), and the cache and replica settings of section 8.2. A change to any member is an administrative configuration change that creates a new revision of the record. OpenFGA models are immutable and each write creates a new model with a new id [OF-3], [OF-18], so a pin moves only when an administrator names a new id. OpenFGA's guidance is to pin the model id alongside the store id in configuration [OF-3].

**RB-2. Every Check names the pin.** Each Check is `POST /stores/{store_id}/check` with the pinned `store_id` and a body with the pinned `authorization_model_id` [OF-2]. The adapter never omits the model id. When it is omitted, OpenFGA uses the last created model of the store [OF-3], so a model written elsewhere would change the decision without any configuration change. OpenFGA recommends passing it in production [OF-3], [OF-16].

**RB-3. No request-selected pin or mapping.** The store, the model, the relation, the object type, and the tenant never come from a header, query parameter, request body, profile attribute, evidence claim, or model output (draft §8.5; identity-mapping IM-1). A value of that kind that names a store or a model is not read (REBAC-02). One that names a tenant different from the realm of the authenticated principal is `CONTEXT_MISMATCH` (REBAC-01); the realm comes from the authenticated context and the trusted configuration.

**RB-4. Tenant isolation.** The registry states, per realm, whether the realm has its own store or shares a store with other realms. OpenFGA documents a multi-tenant shape in which one store serves all tenants and the tenant boundary is enforced inside the authorization model [OF-15]. In a shared store every subject id and object id carries the realm namespace, so equal local ids of two tenants never coincide (draft §8.5; identity-mapping IM-4, IM-7). The registry entry of a document belongs to exactly one realm. An operation whose document entry belongs to another realm than the principal's is `CONTEXT_MISMATCH` and no Check is sent (REBAC-09).

**RB-5. Relation per action, in a versioned table.** The relation of a Check is the relation of the table row of section 2.1 for the action of the mapped operation. It is never taken from the request's text. An action with no row has no Check and no allow, and the adapter reports `UNSUPPORTED_REQUIREMENT`. The relation must exist in the pinned model: OpenFGA answers a Check on a relation not defined in the model with a `400 Bad Request` [OF-13], which is a configuration fault (RB-13), never a decision. The table revision and the mapping revision are one version, used both when the contract is issued and when the actual operation is validated (draft §10.2).

**RB-6. Subject and object mapping through the registry.** The registry maps the authenticated principal to the Check subject `user:<subject-id>` and the document of the actual operation to `document:<object-id>`. The mapping is explicit and versioned (draft §17.2) and one to one per store: no two principals share a subject id, and a subject id is never reassigned. A subject id is opaque and carries no name, e-mail address, or other personal data; OpenFGA advises against personal data in identifiers [OF-16]. A document maps by a registry lookup or by a deterministic, versioned rule that adds the realm namespace (RB-4); a deployment states which. Each id uses only ASCII letters, digits, `-`, `_`, and `.`, so the `user` string contains one type separator and no `#` and no `*`. A principal or a document with no registry entry in the realm of the request gets no Check and no allow (`CONTEXT_MISMATCH`). The Check `user` is always the mapped string and never a userset or a wildcard: OpenFGA documents that the `user` field may be a userset such as `group:marketing#member` or the public form `user:*`, and that a userset is self-defining in a Check, so some usersets always return `allowed` true [OF-2]. The lengths stay within the documented limits: `user` at most 512, `object` at most 256, `relation` at most 50 characters [OF-2]. Whether the pinned server accepts every id of this form is probe P-4.

### 11.2 Contextual facts

**RB-7. Gateway-derived contextual tuples only.** By default a Check carries no `contextual_tuples`. A deployment may allow named tuple templates in its registry. Each is filled only from the authenticated native context or from a configured authoritative lookup (draft §8.5), its `user` is the subject of RB-6, and at most 100 tuples are sent in one request, the documented limit [OF-2], [OF-4]. A contextual tuple is ephemeral and exists only for the request [OF-4], so the freshness of such a fact is the freshness of the source the gateway took it from, not that of the store. A tuple derived from a token claim lasts until the token expires even if the claim changes [OF-4], and the deployment declares that lifetime in its own section 8 row. The documentation says contextual tuples are treated as if they were stored tuples during the request, and that one with the same user, relation, and object as a stored tuple takes precedence over it [OF-4]. A template therefore supplies only facts of the kind draft §8.5 describes, such as the group memberships of the authenticated token or the organization the principal is logged into, and never a tuple on a relation of the relation table (`viewer`, `editor`) for a document: such a tuple would be the grant being checked, and a PACT pass cannot make native permissions more permissive (draft §2.3, §4.3).

**RB-8. Never agent-supplied; a claim is not a tuple.** A profile attribute, evidence claim, assertion, or request field that names a relationship is untrusted data. It is compared with native context where a field rule says so and it is never a stored or contextual tuple (draft §8.2, §9.2: a self-asserted claim cannot establish role membership). A correctly signed claim does not make its issuer an author of the relationship graph (draft §4.2). The adapter sends `contextual_tuples` only as RB-7 allows (REBAC-03).

### 11.3 Consistency, cache, and outage

**RB-9. `HIGHER_CONSISTENCY` on every Check.** The adapter sets `consistency` to `HIGHER_CONSISTENCY` on every Check of `authorize_native`. It never sends `MINIMIZE_LATENCY` or `UNSPECIFIED`, and it never omits the field: the default `UNSPECIFIED` behaves as `MINIMIZE_LATENCY` [OF-2] (REBAC-04). With caching disabled the documentation says all queries have strong consistency regardless of the mode [OF-1], so sending the preference is not redundant: it keeps the decision strong when an operator later enables a cache.

**RB-10. No adapter cache; one Check per operation.** The adapter keeps no cache of Check results and reuses no decision for another operation or a later one (`freshness.md` §6: a native allow is not cached by PACT). Each protected operation makes its own Check at the `authorize_native` step, after PACT admission.

**RB-11. Version gate.** RB-9 holds only on a server release on which the consistency parameter is available and effective. The upstream documentation does not give a version on its consistency page [OF-1]. The release notes say per-request consistency was added in v1.5.7 for Check, Expand, ListObjects, ListUsers, and Read behind the experimental flag `enable-consistency-params`, and that the flag was removed in v1.6.0, after which the option is enabled by default [OF-7]. The configuration documentation lists the flag for releases from 1.5.6 up to but excluding 1.6.0 [OF-6], one release earlier than the release notes (P-3). A deployment therefore pins v1.6.0 or later, records the release in the pin record, and passes probe P-1 on it. A release that fails P-1 does not carry this profile's claim.

**RB-12. Declared cache and replica settings.** The pin record holds the settings of section 8.2. The declared bound of F1 is 0 s when RB-9 holds and probes P-1 and P-2 pass. A deployment that observes a larger bound declares it, and the consequences of `freshness.md` §4.2 follow.

**RB-13. Outage and faults never allow.** Any outcome other than a well-formed answer yields no allow and no execution (draft §2.3, §18). The adapter does not retry with a weaker consistency, does not fall back to a cached decision, and does not try another store or model (REBAC-06).

| Outcome of the Check call | Adapter result | PACT result |
|---|---|---|
| `200` with `allowed` true | Allow | The operation continues to its execution conditions |
| `200` with `allowed` false | Deny | Native denial: no execution; `AUTHORIZATION` event with result `FAILURE` and no reputation weight (draft §14.5) |
| `200` without a boolean `allowed` | No answer | `DEFERRED`, `DEPENDENCY_UNAVAILABLE` |
| No connection, timeout, `5xx`, `409`, `422`, `401`, or `403` | No answer | `DEFERRED`, `DEPENDENCY_UNAVAILABLE` |
| `400` or `404` (relation, model, or path not matching the pin) | Configuration fault, no decision | `DEFERRED`, `UNSUPPORTED_REQUIREMENT` |

The OpenFGA status meanings are those of the Check reference: `400` invalid input, `401` not authenticated, `403` forbidden, `404` incorrect path, `409` aborted by a transaction conflict, `422` timed out under excessive throttling, `500` internal error [OF-2]. The mapping of those statuses to PACT codes is this profile's choice.

### 11.4 Alternative paths

**RB-14. The Check evaluates the full model.** The decision is exactly the `allowed` of the Check at the pinned model. OpenFGA documents that the answer uses the authorization model, the stored tuples, the contextual tuples of the request, and the implicit tuples that follow from the model [OF-2], and that a document relation may derive from a parent while direct assignment remains another way to hold it [OF-12]. It follows, and this profile states it explicitly, that when a principal loses one path, such as project membership, a remaining direct share legitimately keeps the Check allowed. The adapter does not deny on its own account because a particular path is absent, does not require the agent to prove a particular path, and does not look for paths with Expand or Read. The adapter also does not allow when the Check answers false. A native denial wins over a PACT pass, and a PACT pass adds no permission (draft §2.3, §4.3).

The worked states below use the reference model and the Check of `viewer` on the briefing document for the subject of Maya. The table is informative.

| Stored state | Check answer | Adapter result |
|---|---|---|
| Maya is a member of Orion; the document's parent is Orion | allowed | Allow |
| Membership removed; no direct share | not allowed | Deny |
| Membership removed; a direct share of the document remains | allowed | Allow, legitimately (REBAC-05) |
| Direct share removed; membership remains | allowed | Allow |

**RB-15. Only the Check decides.** `authorize_native` uses Check. ListObjects, Expand, Read, and ListUsers are not used to decide an operation. Check is documented as the call that answers whether a user has a relationship with an object, and Expand as a tool for debugging that returns a tree of users and usersets [OF-9], [OF-11]. ListObjects is bounded by a time limit and a maximum result count and returns unsorted objects, and the documentation says Check and ListObjects agree in general but "some exceptions apply" [OF-2], [OF-10].

### 11.5 Relationship writes

**RB-16. Application-only writes.** Relationships are written only by the application's own sharing service, under its own native authorization (a project owner shares a document through the existing application), with the store credential of that service. OpenFGA documents applications that keep sharing data only in the store [OF-19], and Write as a transactional update of tuples [OF-8]. The adapter's store credential is used for Check only: the adapter has no Write, the gateway's PACT components expose no path to it, and no contract, profile, evidence, receipt, or outcome report creates or changes a tuple (draft §4.3: PACT does not create a native role, add group membership, or change an ACL). The agent holds no store credential. After the sharing service writes a relationship, a fresh PACT exchange and a fresh Check reflect it. OpenFGA supports the authentication methods `none`, `preshared`, and `oidc` [OF-5] and advises configuring authentication and transport security in production [OF-17]. Its built-in per-store roles (`reader`, `writer`, `model_writer`) are an experimental feature since v1.7.0 that the documentation does not recommend for production [OF-14]. The documentation read does not establish how one credential is limited to Check, so the deployment states its own control and the profile lists the point as open (P-5, section 9). The profile does not claim that B6 is closed.

**RB-17. Model and store administration is not the adapter's.** Creating a store, writing a model, and changing a pin are administrative acts of the deployment [OF-3], [OF-18]. A new model is rolled out by a new pin record. When a change renames a relation, the tuples are migrated and the relation table takes a new revision before the pin moves [OF-3]. An agent, a profile, a learned artifact, and the adapter cannot do any of these.

### 11.6 View to edit, and subject binding

**RB-18. Edit is a new operation.** A change of action requires a new contract and presentation (draft §10.3). An admission, a contract, or an allowed `viewer` Check for `document.read` never authorizes `document.write`: the edit meets steps 1 to 5 again, its relation is `editor` (RB-5), and a read-bound presentation presented for an edit is `CONTEXT_MISMATCH` (REBAC-07, REBAC-08). A `viewer` answer never answers an `editor` question, and the adapter never substitutes one relation for the other. Reputation and learning cannot change the relation table, the pin, or the mapping (draft §15.5, §16.2: they cannot create a native permission or touch native roles and resource ACLs).

**RB-19. The relationship subject is the delegating principal.** `authorize_native` is invoked with the original principal (draft §17.5), and the Check `user` is that principal's subject from RB-6. It is not the agent's `agent_id`, the executor's own authority, the gateway's connector identity, or an administrator identity (draft §4.3). If the read or the Check would run under a broader subject, `execution-identity-v1` returns `FAIL` with `EXECUTOR_MISMATCH` (draft §17.5). Section 7.1 states the dependency on the delegation work.

The Check request for the sample's read, with the model id of the pin and no contextual tuples, is:

```json
{
  "tuple_key": {
    "user": "user:u-0042",
    "relation": "viewer",
    "object": "document:northstar.orion-brief"
  },
  "authorization_model_id": "<pinned model id>",
  "consistency": "HIGHER_CONSISTENCY"
}
```

The subject id `u-0042` and the object id `northstar.orion-brief` are registry outputs for Maya and for the briefing document in the realm of the example (RB-4, RB-6).

## 12. G23 closure map

Each item G23 requests, and each piece of evidence it needs to close, maps to rules and to cases. The first table maps the work G23 requests, the second the evidence it needs, both as worded in `docs/handoff.md`.

| G23 requested work | Rules | Cases |
|---|---|---|
| Pin tenant, store, model, relation, and object mappings | RB-1 to RB-6, RB-17 | REBAC-01, REBAC-02, REBAC-08, REBAC-09 |
| Trusted contextual facts | RB-7, RB-8 | REBAC-03 |
| Query and cache consistency | RB-9 to RB-13 | REBAC-04, REBAC-06 |
| Full alternative-path semantics | RB-14, RB-15 | REBAC-05 |
| Authorized relationship writes | RB-16, RB-17 | REBAC-03 for the claim that names a tuple; no case exercises the write path itself (O-1) |

| G23 evidence needed to close | Case | Result |
|---|---|---|
| Tenant and model substitution | REBAC-01, REBAC-02, REBAC-09 | Mismatch or ignored; the configured store and model decide |
| Injected tuples | REBAC-03 | Not a tuple; `contextual_tuples` empty |
| Stale membership | REBAC-04 | `HIGHER_CONSISTENCY` sent; the decision follows the store |
| Remaining direct shares | REBAC-05 | Allow; the adapter does not deny on its own |
| Service outage | REBAC-06 | No allow; `DEFERRED` |
| View-to-edit escalation | REBAC-07, REBAC-08 | `CONTEXT_MISMATCH` for the read-bound presentation; relation `editor` for a fresh edit |

The decision table of the sample maps to this profile as follows.

| Sample condition | Profile behavior |
|---|---|
| Verified agent and delegation, `viewer` relation established | Admit; Check allowed; execute (RB-9, RB-14) |
| Valid organizational role, no relationship path | Check not allowed: native denial (RB-14) |
| Membership removed, no alternative share | Check not allowed (RB-14) |
| Membership removed, direct share remains | Check allowed (RB-14, REBAC-05) |
| Agent names a relationship of another tenant | Mapping prevents substitution (RB-3, RB-4, REBAC-01, REBAC-09) |
| Relationship service unavailable | No allow, no execution, `DEFERRED` (RB-13, REBAC-06) |
| Agent offers a new `member` tuple in its profile | Untrusted data, not a tuple (RB-8, REBAC-03) |
| View permission exists, task asks for editing | Separate operation and relation `editor` (RB-18, REBAC-07, REBAC-08) |

## 13. Upstream sources

Every OpenFGA statement above cites one of these pages, all read while writing this profile. The release notes are the project's own `CHANGELOG.md`.

| ID | Source | Used for |
|---|---|---|
| OF-1 | https://openfga.dev/docs/interacting/consistency | Consistency values, default, cache behavior, no version stated, no consistency token |
| OF-2 | https://openfga.dev/docs/api/service/relationship-queries/check-user-authorization | Check request and response, `consistency` enum, `authorization_model_id`, contextual tuple limit, usersets and `user:*`, status codes, identifier length limits |
| OF-3 | https://openfga.dev/docs/getting-started/immutable-models | Immutable models, pinning the model id, behavior when it is omitted |
| OF-4 | https://openfga.dev/docs/interacting/contextual-tuples | Contextual tuples: ephemeral, limit, precedence, token claims |
| OF-5 | https://openfga.dev/docs/getting-started/setup-openfga/configuration | Cache and controller defaults, authentication methods |
| OF-6 | https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga | Experimental flag table, read replicas and `HIGHER_CONSISTENCY` |
| OF-7 | https://raw.githubusercontent.com/openfga/openfga/main/CHANGELOG.md | Releases 1.5.7, 1.6.0, and 1.22.0 |
| OF-8 | https://openfga.dev/docs/api/service/relationship-tuples/add-or-delete-tuples | Write is a transactional update |
| OF-9 | https://openfga.dev/docs/interacting/relationship-queries | What Check, Expand, ListObjects, and ListUsers are for |
| OF-10 | https://openfga.dev/docs/api/service/relationship-queries/list-objects-a-user-is-related-to | ListObjects bounds and ordering |
| OF-11 | https://openfga.dev/docs/api/service/relationship-queries/expand-relationships-in-userset-tree-format | Expand returns a userset tree |
| OF-12 | https://openfga.dev/docs/modeling/parent-child | Parent-child inheritance and direct assignment |
| OF-13 | https://openfga.dev/docs/getting-started/perform-check | `allowed` result; undefined relation is a `400` |
| OF-14 | https://openfga.dev/docs/getting-started/setup-openfga/access-control | Built-in access control: experimental, store roles |
| OF-15 | https://openfga.dev/docs/use-cases/multi-tenant-saas | Single store for all tenants, tenant boundary in the model |
| OF-16 | https://openfga.dev/docs/getting-started/tuples-api-best-practices | No personal data in identifiers; always pass the model id |
| OF-17 | https://openfga.dev/docs/best-practices/running-in-production | Authentication and transport security in production |
| OF-18 | https://openfga.dev/docs/api/service/authorization-models/create-a-new-authorization-model | Writing a model returns a new id |
| OF-19 | https://openfga.dev/docs/best-practices/source-of-truth | Sharing data kept only in the store |

Upstream facts this profile relies on that the sources state differently or not at all are listed in section 14.

## 14. Items to probe and open items

### 14.1 To probe

These items are not established by documentation. Each is probed against a real server at the pinned release before an enforced claim cites this profile. No OpenFGA server was available while this profile was written, so none has been run.

| ID | Item | What the documentation says | Probe |
|---|---|---|---|
| P-1 | The consistency preference is accepted and effective on the pinned release, and the release is recorded | [OF-1] gives no version. [OF-7]: added in v1.5.7 behind `enable-consistency-params`; the flag removed and the option enabled by default in v1.6.0. [OF-6]: flag listed for `1.5.6 <= v < 1.6.0` | Record the server release. With a Check query cache enabled, delete a tuple and Check with `MINIMIZE_LATENCY` and then `HIGHER_CONSISTENCY`: the second answer reflects the deletion and the first may not. Repeat with the cache disabled. Record both answers and the release |
| P-2 | With a secondary datastore, `HIGHER_CONSISTENCY` reaches the primary on the pinned release and datastore, and the replication lag is known | [OF-6]: routed to the primary for PostgreSQL. [OF-7]: for MySQL from v1.22.0. [OF-5] describes the secondary option "for postgres only", which differs from [OF-7] for MySQL | Delete a tuple on the primary, Check with `HIGHER_CONSISTENCY` while the replica lags, and record the answer and the lag |
| P-3 | Documentation conflicts on the pinned release | [OF-2] says the Check API "caches results for a short time" by default; [OF-1] and [OF-5] say caching is disabled by default. [OF-6] and [OF-7] differ by one release on the flag range | Read the effective settings of the pinned release and record the cache defaults actually in force |
| P-4 | The identifier form of RB-6 is accepted | [OF-2] gives length limits only; the identifier pattern is not stated on the pages read | Write and Check subject and object ids of the RB-6 form, including the realm namespace separator, on the pinned release |
| P-5 | One credential can be restricted to Check | [OF-5] lists the authentication methods; [OF-14] describes experimental per-store roles not recommended for production | State the deployment's control (a gateway-only network path, a Check-only proxy, or experimental access control) and show a write attempt with the adapter credential fails |

### 14.2 Open items

| ID | Item |
|---|---|
| O-1 | No case exercises the rule that the adapter has no write path to the store (RB-16), or that the agent has no store route (B6). Add a case, or keep the rule as documentation |
| O-2 | No case sends a mapped `user` that is a userset or a wildcard, or presents a principal with no registry entry (RB-6). A document with no registry entry and an action without a table row are `REBAC-09.unregistered-document` and `REBAC-08.unlisted-action` |
| O-3 | Closed: the file names, the manifest ids and the case ids are those of section 10 |
| O-4 | The schema's fact vocabulary (`identity`, `groups`, `roles`, `account_state`) has no value for a relationship; `groups` and `roles` stand in for it in 8.1 |
| O-5 | The sample's reference model has no `editor` relation; the reference model of 2.2 adds one |
| O-6 | The freshness of the authenticating mechanism's identity source is declared by that mechanism's own profile, which the template has no field to cite |

### 14.3 Probe record

The behaviors below were observed on 2026-10-18 on OpenFGA `v1.10.0` (container image `openfga/openfga:v1.10.0`, in-memory datastore, pre-shared key authentication), through the HTTP API on the loopback interface. The release and datastore are those of the observation, not of any deployment, so they do not close P-1 to P-5 for a pinned environment; they confirm the documented behavior the cases rely on.

| Item | Request | Observed answer |
|---|---|---|
| P-1 (in part) | Check query cache and iterator cache enabled with a 60 s TTL. A Check with `MINIMIZE_LATENCY` that is allowed through project membership; the membership tuple deleted; the same Check with `MINIMIZE_LATENCY`, with no `consistency`, and with `HIGHER_CONSISTENCY` | `allowed` true, true, true, then false: the first two answers after the deletion came from the cache, the `HIGHER_CONSISTENCY` answer did not. With the caches disabled, the Check after the deletion answered false |
| P-1 (in part) | `consistency` `"STRONG"`, a string that is not a value of the enum, after the same deletion with the caches enabled | `200` with `allowed` true, the cached answer: an unknown string is not refused. A number in `consistency` is `400` `validation_error` |
| P-4 | Subject `user:u-0042`, objects `document:northstar.orion-brief` and `project:northstar.orion` written and Checked | Accepted |
| RB-2 | A Check naming a model id the store does not hold | `400` `authorization_model_not_found` |
| RB-5 | A Check on a relation the model does not define | `400` `validation_error` |
| RB-13 | A Check on a store id that does not exist, without a model id; with a model id; a store id that is not 26 characters of the ULID alphabet; an undefined path | `400` `latest_authorization_model_not_found`; `400` `authorization_model_not_found`; `400` `validation_error`; `404` `undefined_endpoint` |
| RB-13 | A Check without `Authorization`; with another key | `401` `bearer_token_missing`; `401` `unauthenticated` |
| RB-7 | A Check whose contextual tuple makes the user a member of the parent project | `allowed` true: the contextual tuple counted as stored for the request ([OF-4]) |
| RB-6 | A Check whose `user` is the userset `document:northstar.orion-brief#viewer` of the object and relation checked | `allowed` true: a userset is self-defining ([OF-2]) |
| [OF-2] | A Check body with an unknown member | Accepted; the member was ignored |
| [OF-2] | A well-formed Check | `200` `{"allowed":true,"resolution":""}` |

The second row is why RB-9 is enforced by the adapter's own request and not by the server: a misspelled preference is answered as the default.

## 15. Reference implementation (informative)

The reference code is Go. It is not part of the claim, and this section is the only one that names it.

| Draft function | Package and type | Behavior this profile relies on |
|---|---|---|
| All seven functions | `go/adapter` (`Adapter` and one interface per function) | The interfaces and errors the validator and the conformance harness compile against; `Descriptor` carries `Protocol`, `Version`, and `MappingRevision` for the metadata entry of section 1 |
| `authorize_native` | `go/adapter` `NativeAuthorizer.AuthorizeNative` | Returns a `Decision` whose `Effect` is `EffectAllow`, `EffectDeny`, or `EffectUnknown`; only `EffectAllow` permits (`Decision.Permits`), so a denial is final by construction. The `Decision` carries `SourceID` the pinned `store_id` and `PolicyRevision` the pinned `authorization_model_id`; `SourceRef` is empty and `DecidedAt` the zero time, since the Check response gives neither a decision record nor a time [OF-2], and `Obligations` is empty, since a Check carries none. Outage maps to an error wrapping `ErrDependencyUnavailable` (`DEPENDENCY_UNAVAILABLE`, RB-13); a tenant mismatch to `ErrContextMismatch` (`CONTEXT_MISMATCH`, RB-3, RB-4); an action with no table row to `ErrUnsupportedRequirement` (`UNSUPPORTED_REQUIREMENT`, RB-5) |
| `authenticate_native` | `go/adapter` `Principal`, `Realm`, `Workload` | `Principal.ID` is namespaced by issuer and tenant; `Principal.Realm` carries `TenantID` and `EnvironmentID`, the realm of RB-3 and RB-4 |
| `resolve_agent_binding` | `go/adapter/enroll` `Registry`, `Resolver` | The enrollment registry of F2: `Lookup` takes the realm, the workload and the presented agent ID, and returns that agent's binding on the workload, `ACTIVE`, `REVOKED`, or `COMPROMISED`, or `UNKNOWN` when it has no record there; `Rotate` and `MarkCompromised` need an `Admin` or `AuthorizedIssuer` actor |
| `read_native_claim` | `go/adapter` `ClaimReader`, `NativeClaim` | Reads the approved paths of section 3 with the times the source gives |
| Freshness of a read claim | `go/adapter/freshness` `Evaluate`, `Evaluator`, `Monotonic` | Evaluates `max_age_seconds` and `status_max_age_seconds` of a claim read through `read_native_claim`; it is not applied to the Check decision (section 8) |

The reference adapter for this profile is `go/adapters/rebac`. Its `Config` holds the pin record (`Pin`), the relation tables (`DocumentRelations` is the table of section 2.1), the route tables (`DocumentRoutes` gives R1 and R2), the mapping registry (`Registry`, with `StaticRegistry` over fixed entries), the OpenFGA server (`Store`: the base URL, https or loopback http, the pre-shared key, the client and the time limit of a Check), and the deployment's identity mechanism (`Authenticator`), which `authenticate_native` calls. Before a Check, `authorize_native` also requires that the operation context be one the pinned mapping revision produces for its own method and target, so a context bound to `document.read` for an edit is `CONTEXT_MISMATCH` (RB-18, `REBAC-07.read-context-for-edit`). It passes the common cases of the conformance suite, with the three replacements of section 10, and the cases of section 10, in a unit tier over a fake of the Check API and in an integration tier against an OpenFGA server (section 14.3).
