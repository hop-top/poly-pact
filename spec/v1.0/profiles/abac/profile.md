# PACT ABAC fact-authority and policy-obligation profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose and status

This is the integration profile (the structure of [`TEMPLATE.md`](../TEMPLATE.md)) for attribute-based access control through an installed policy decision point, Open Policy Agent (OPA), reached through its REST Data API. It answers the open finding G22 of `docs/handoff.md` (source repository only, not part of the mirror): where each policy input fact comes from and how fresh it must be, how clearance is compared, what a policy decision document contains and how it is pinned to a policy version, which conditions are read again before execution, and how the obligations of a decision are enforced before any data is disclosed. [Example I11](../../examples/example_I11.md) is the informative narrative; its organizations, routes, and thresholds are fictional and this profile does not make them real.

The native policy engine stays authoritative. A PACT rejection can make access more restrictive; a PACT pass never makes a native permission more permissive, and a native denial always wins (draft §2.3, §4.3). This profile defines no PACT policy language. It fixes the fact inputs, the comparison of clearance levels, the decision document, the execution-time rechecks, and the obligation handling, and nothing about what a policy decides.

Sections 1 to 10 fill the ten sections of the template. Sections 11 to 15 hold the rules that sections 1 to 10 cite, each with an id from ABAC-1 to ABAC-30 so that fixtures and reviews can cite it; they are normative for a claim under this profile. Sections 16 to 18 are informative: the closure map for G22, the reference implementation, and the sources and open items. The uppercase requirement words have the meanings of draft §3, and where this document and [`draft.md`](../../draft.md) differ, the draft governs. Each rule ends with its basis: a draft section, an OPA source tag from section 18, or `profile` for a convention this document adds. A convention applies to every claim under this profile.

The machine-readable form is [`profile.json`](profile.json), which validates against [`integration-profile.schema.json`](../integration-profile.schema.json). It holds sections 1 to 6 and 8 to 10 only; the profile header, the identity-mapping section, and the rules stay here.

## Profile header

| Field | Value |
|---|---|
| Profile name | ABAC fact-authority and policy-obligation profile (OPA) |
| Target product and version | Open Policy Agent as policy decision point (PDP), REST Data API `v1`, the version segment of the `/v1/data` path of [OPA-REST]; the exact OPA release is not pinned (open item O1) |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `r1`, 2026-10-16; the ABAC check runs through `check_context` on the principal it receives (draft §17.1); cases `abac-04.check`, `abac-11.check`, `abac-13.check`, `abac-14.check`, `abac-28.check`, `abac-38.*` |
| Maintainer | PACT adapter maintainers; a named maintainer is open item O9 |
| Reference documents | draft = `spec/v1.0/draft.md`; handoff = `docs/handoff.md` (source repository only; finding G22); example = `spec/v1.0/examples/example_I11.md`; shared rules = [`identity-mapping.md`](../identity-mapping.md) and [`freshness.md`](../freshness.md) |

## 1. Claim scope

The document gateway evaluates PACT and the native ABAC decision in its own request path (draft §4.4). It claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over the `header` presentation transport, and is a partial role implementation (draft §22.1) because it claims neither Holder, Reputation, nor Learning. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1; the roles it does not claim are supplied by connected services of the deployment, as in the template's mini-example. Its contracts use the conservative requirement set only, so no reputation or adaptation is needed to claim this profile.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Holder 0.1`, `PACT Reputation 0.1`, and `PACT Learning 0.1` are not claimed |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced`. No claim is made for observation mode, where obligations would not be enforced |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` |
|---|---|---|
| `opa-data-api` | `v1` | `pact-abac-1` |

The adapter entry names the binding to the PDP. The protected route uses the baseline HTTP mapping of draft §10.2, whose version the gateway publishes as `operation_mapping_version`; the deployment fills that value, and `pact-abac-1` also names the revision of the mapping from the operation and the facts to the policy input (section 11).

## 2. Protected routes and actions

One route is claimed. It is a reference route for the I11 operation, a document read; a deployment that claims more routes adds its own rows, and any route not listed is not claimed.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/api/documents/{document_id}` | `GET` | `document.read` | `document:{document_id}`, resolved by `map_operation` from the path parameter against the document catalog; the one member of `OperationContext.resources`. Query parameters and headers that can change what is returned are part of the bound operation (draft §10.2). The response is one JSON document |

## 3. Enforcement points

The document gateway is the enforcement point, OPA is the decision point, and the document service is the executor that performs the read for the principal. The effective contract for R1 names in `context_checks` the installed ABAC check (ABAC-16), `native-principal-binding-v1`, `native-delegation-v1`, and `execution-identity-v1`, and carries field rules for `/attributes/environment/department` and `/attributes/environment/clearance` (ABAC-12).

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Gateway authentication stage, before routing | Gateway implementer | Produces the principal in the namespace of the authenticating mechanism (ABAC-4) and, as the `Principal` attributes `device_id` and `peer_address`, the authenticated device identifier and the connection's peer address (ABAC-6, ABAC-7) |
| 2 | `map_operation` | Gateway mapping stage, mapping revision `pact-abac-1` | Adapter owner | Builds the `OperationContext` for R1: action `document.read`, one resource |
| 3 | PACT evaluation | In-gateway validator in the same request path | Gateway implementer | Field rules for department and clearance, and the four installed checks above; the ABAC check establishes the policy-version pin (ABAC-16) |
| 4 | `authorize_native` | The adapter's decision client, calling the PDP (ABAC-13 to ABAC-20) | PDP owner and adapter owner | The native ABAC decision for the original principal; a native denial is final (draft §2.3) |
| 5 | Execution | Document service, as executor | Resource owner | Rereads device, zone, and time (ABAC-21 to ABAC-24), applies the obligations, and releases (ABAC-25 to ABAC-30), under executor class `delegated-user` |
| support | `resolve_agent_binding` | Enrollment registry lookup inside the gateway, by the realm, the authenticated workload, and the agent ID that the presentation names | Gateway implementer | Enrolled agent ID and holder key (identity-mapping section 4). Whether a workload may carry more than one record is the choice of the authenticating profile (section 7) |
| support | `read_native_claim` | Fact adapters for F1 to F8 over approved native paths (section 8) | Adapter owner | Value, original observation time, status time, and source ID, as the source gives them (ABAC-9) |
| support | `check_context` | Installed gateway checks | Gateway implementer | The four checks named above; the ABAC check runs on the `Principal` that `check_context` receives, reading `device_id` and `peer_address` from its attributes (draft §17.1, ABAC-6, ABAC-7) |
| support | `record_outcome` | Gateway outcome writer, and the executor's native record (ABAC-30) | Gateway implementer and resource owner | Outcome attributed to the admission decision and to the executor identity |

Actor binding (draft §17.5) applies unchanged and adds no field. Every actor transition is native; PACT records and checks it and never mints it.

| Actor | Binding field or check | Source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the agent, resolved by the gateway (draft §6.1, §6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: the authenticated user, with department from the identity and HR mapping |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the task in the delegation registry |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Existing delegation registry: agent, user, and task authority |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (draft §4.2) |
| Downstream executor | Check `execution-identity-v1`, declared class `delegated-user` | The document service, which reads for the principal after the ABAC decision |

The adversarial results are those of draft §17.5: principal substitution gives `FAIL` with `CONTEXT_MISMATCH`; a changed task gives `FAIL` with `TASK_MISMATCH`; a stale or revoked delegation gives `FAIL` with `STALE_EVIDENCE` or `REVOKED_EVIDENCE`; a broader executor credential gives `FAIL` with `EXECUTOR_MISMATCH`; an executor that cannot be determined gives `UNKNOWN`, which yields `DEFERRED`. This profile adds one rule: the policy input names the original principal and never the executor (ABAC-1), so the executor's own authority never reaches the PDP.

## 4. Native dependencies

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and filter chain of the document gateway | Gateway implementer | To be supplied by the deployment |
| C02 | Native authentication and claim adapters | baseline | Identity adapter (`authenticate_native`, principal and department lookups) and the fact adapters behind `read_native_claim`; the decision client of this profile | IAM owner and adapter owner | Identity adapter exists; the decision client is the adapter this profile specifies, built as the reference implementation of section 17 |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry, administrator-run enrollment | IAM and security owner | To be supplied by the deployment |
| C04 | Native delegation and task authority | delegated or task execution | Delegation registry holding user, agent, and task authority, behind `native-delegation-v1` | Application and IAM owner | Exists |
| C05 | Evidence and authoritative status sources | baseline | HR/identity adapter, security-attribute service, device-management adapter, document catalog, the gateway itself (network zone and time), enrollment registry, hold store | Owner of each source | Exists as the sources of section 8, of its membership source (8.1), and of its attribute sources (8.2) |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the sample policy needs no external approval; a policy that does adds this component and an approval-class check (draft §17.3.1) |
| C07 | Purpose and exact operation mapper | baseline | Mapper at revision `pact-abac-1` for the operation and the policy input | Adapter owner | To be supplied |
| C08 | Native resource executor and authorization | the actual resource operation | OPA with the installed policy as the native decision; the document service as executor, applying obligations | Policy owner and resource owner | Policy engine exists; the obligation executor is assumed and is specified by ABAC-25 to ABAC-30 |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store; the shared store of the monotonic guard (freshness profile section 7) | Gateway and platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Gateway outcome writer and the executor's native record | Resource and evidence owner | To be supplied |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Registry of base requirements and the installed-check registry that holds the pinned policy version (ABAC-16) | Platform owner | Registry only, no adaptation lifecycle. The OPA policy source is a native store owned by the policy owner, not this registry |
| C13 | Revocation and security holds | baseline | Revocation and hold store | Security and IAM owner | To be supplied |
| C14 | Protected evidence and audit storage | baseline | Access-controlled evidence and audit store, including the OPA decision log (ABAC-18) | Security and data owner | To be supplied |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: R1 is a read with no transaction or budget |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no runtime or data-use guarantee is claimed. Obligation enforcement is resource enforcement by C08 before disclosure (draft §17.3); use after disclosure is attested-only (section 9) |

## 5. Alternative and bypass paths

The negative cases are named in section 10, with the fixtures and Go tests that carry them.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Direct request to the document service from any host other than the gateway | `closed` | Network policy admits only the gateway as a source, and the executor refuses a request that lacks the envelope of ABAC-29; case ABAC-21 |
| B2 | Direct request to the PDP's Data, Policy, or other API by any process other than the adapter, including a write of policy or data | `closed` | The PDP authenticates its clients, and the adapter identity is authorized only for POST on the decision path (ABAC-19); case ABAC-22 |
| B3 | Other actions on the same documents: export, download, search, list | `out-of-claim` | Only R1 is listed in section 2; excluded in section 6 |
| B4 | Other applications or routes that read the document store or the catalog directly | `out-of-claim` | The claim covers R1 only; excluded in section 6 |
| B5 | A shared HTTP response cache between the executor and the agent | `out-of-claim` | A cached copy of a disclosed response would be served without a new decision; excluded in section 6, and the deployment disables caching for R1 |

## 6. Unsupported forms

The first two rows are seeded from the I11/I12 row of the "Deliberate design choices" table of the handoff; the others come from the rules below and from sections 2 and 5.

| Unsupported form | Seed (handoff source row) | Why it is not established |
|---|---|---|
| Universal policies, or a PACT policy language | I11/I12 ABAC/ReBAC: "Universal policies/relationships or instantaneous propagation" | Only the native OPA policy and its decision document (ABAC-15) are claimed. PACT defines no policy language, no other engine, and no policy; the clearance chain and the sample rule are illustrative |
| Instantaneous propagation of a fact change | I11/I12 ABAC/ReBAC: same row | A change reaches a decision within the status bound of its source (section 8) and, for device, zone, and time, again at execution within 30 seconds; nothing faster is promised (draft §18) |
| Policy input taken from the agent, including a signed evidence artifact | Section 11, ABAC-1 | Evidence the agent carries is compared and discarded; the input carries the authoritative value. I11 also names scoped trusted evidence for clearance as an option; this profile does not use it |
| Clearance with compartments or any order that is not one chain | Section 12, ABAC-11 | Only a configured finite chain of levels is claimed (open item O6) |
| Obligation types other than `filter_fields`, `redact`, and `watermark`; deny-list filtering; parameters beyond section 15 | Section 15, ABAC-25 | The draft defines no obligation; this profile defines three and treats any other as unmet |
| Obligations on content that is not a JSON document, other than a watermark whose means the mapping declares; disclosure that streams bytes before every obligation is applied | Section 15, ABAC-27 | The executor must hold the content until every obligation is applied and verified |
| Policy rules specific to an agent, a task, or a purpose | Section 11, ABAC-2 | The input has no agent identifier, task, or purpose; the task relation is established by `native-delegation-v1` and the purpose and operation check, not by the policy |
| Any action other than `document.read` on R1, including export | Section 2 | Not listed, so not claimed; an export needs its own operation binding (draft §10.3) |
| Execution-time recheck of principal, department, clearance, classification, or owning department | Section 14, ABAC-21 | Only device, zone, and time are read again; the others rely on their admission-time bounds (section 9) |
| Reuse of a decision across requests; an embedded or non-REST OPA interface | Section 13, ABAC-17 | Every decision is a new query through the REST Data API |
| Verification of policy content from `policy_version` or from a bundle revision | Section 13, ABAC-16 | Both are labels the policy publisher sets; the profile pins and compares them |
| Observation mode | Section 1 | Obligations are not enforced there |
| Enforcement of data use after disclosure | Handoff G25, draft §17.4 | `execution-control-v1` is not in the contract; use after disclosure is attested-only |

## 7. Identity mapping

The identity rules are those of [`identity-mapping.md`](../identity-mapping.md). The profile records only its own choices.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | The principal and the workload are written in the namespace of the mechanism that authenticated the request (identity-mapping section 3.3, ABAC and ReBAC row: the engine authenticates nobody, and its own subject label is a mapped fact, not the identifier). Department identifiers use the `x-dept` namespace of ABAC-4 |
| Trusted enrollment actors | The native administrative workflow of the gateway (identity-mapping section 4.2); no identity-binding issuer is configured by this profile |
| Shared-account handling | Inherited (identity-mapping §5, IM-19): the decision engine authenticates nobody, so the shared-account choice and its consequence are those of the profile whose mechanism authenticated the request. Whatever that choice, the input carries the principal and never the workload or the agent, so two agents acting for one principal receive one decision (section 6) |
| Certificate, token, or role-session bindings | None is bound by this profile; IM-21 to IM-24 apply to the authenticating mechanism. The device identifier (ABAC-6) is an authenticated attribute and binds no holder key |
| Lifecycle rules (rotation, compromise, recovery) | Deferred to identity-mapping section 7 (IM-25 to IM-29); the propagation bound of the enrollment source is in section 9 |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None |

## 8. Freshness

Nine rows are listed: the sources of the eight policy input facts F1 to F8, where one row holds F7 and F8 because the gateway itself observes both, and the two baseline sources every enforced profile reads (S1, S2). Each fact has one authority and nothing else supplies it (ABAC-1, ABAC-3). The limits are this profile's required bounds (ABAC-9), not measurements. A deployment may tighten them and may not loosen them. A source that cannot meet a limit is not claimed for that fact, and the exchange is `DEFERRED` (freshness profile section 4.2). Every outage ends in `DEFERRED`, which fails closed (draft §18). The PDP is also a required source: its outage is `DEFERRED` with `DEPENDENCY_UNAVAILABLE` (ABAC-10).

How the numbers were chosen: a `status_max_age` of 0 for the principal, clearance, classification, and owning department, because they are sensitive native authority (draft §18); 30 for device, the baseline default for cached status checks (draft §18); 60 for department, the declared lag of the HR replica (freshness profile section 4.2). A `max_age` of 30 for a fact read live from its own authority is the evaluation deadline (draft §12.2, §20.1); 90 for department is the 60 second lag plus that deadline; 300 for device compliance is the management service's compliance evaluation interval, a deployment-declared default that is an assumption (open item O7). Both limits are 0 for zone and time: the gateway is their source and observes them for the request (ABAC-7), and a limit of zero means the observation was made in the evaluation that uses it (freshness profile section 3.1, rule 5).

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Principal identifier (HR/identity adapter; `subject.principal_id`) | Current authoritative state: the identifier and account state the identity adapter resolves for this request's authentication. The observation time is that resolution, never the receipt time of a token (draft §8.3) | 30 | 0 | `DEFERRED` |
| F2 Department (HR/identity adapter; `subject.department`) | Current authoritative state at the answering replica. The observation time is the replication watermark, or the read time minus the declared 60 second lag (freshness profile section 4.1) | 90 | 60 | `DEFERRED` |
| F3 Clearance (security-attribute service; `subject.clearance`) | Current authoritative state read from the service's own store with no cache; the observation time is the service's as-of time | 30 | 0 | `DEFERRED` |
| F4 Device compliance (device-management adapter; `environment.device.compliant`) | Current authoritative record of the management service. The observation time is when the service last evaluated the device; the status time is the read of the record, with at most 30 seconds of cache in the adapter | 300 | 30 | `DEFERRED` |
| F5 Document classification (document catalog; `resource.classification`) | Current authoritative state of the catalog record of the mapped document, read from the catalog's own store | 30 | 0 | `DEFERRED` |
| F6 Owning department (document catalog; `resource.owning_department`) | As F5 | 30 | 0 | `DEFERRED` |
| F7, F8 Network zone and time (the gateway itself; `environment.network_zone`, `environment.time`) | The gateway is the source of both: F7 is the zone derived for this request from the connection's peer address and the configured zone map, and F8 is the gateway's clock reading for this request. The observation and status times are the derivation or reading instant, which falls within the evaluation | 0 | 0 | `DEFERRED` |
| S1 Enrollment registry (agent and key binding status) | Current authoritative state, read for each evaluation (identity-mapping section 7.5) | 30 | 0 | `DEFERRED` |
| S2 Security hold store | Current authoritative state, read for each evaluation (draft §18) | 30 | 0 | `DEFERRED` |

### 8.1 Membership and status sources

F1 supplies the identity fact, so it is listed again here. The other policy input facts, F2 to F8, are subject, resource, and environment attributes outside the vocabulary of `facts` (`identity`, `groups`, `roles`, `account_state`): the department is one identifier the policy reads as an attribute, not a group membership. They are listed in 8.2. F1 has no change feed that the adapter uses: it is read on demand.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 Principal identifier (HR/identity adapter; `subject.principal_id`) | `identity` | `true` | Identity adapter lookup | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

### 8.2 Attribute sources

F2 to F8 are read through `read_native_claim` over approved native paths of the mapping `pact-abac-1` (ABAC-1). Each path is the policy input member of section 11 written with `/` in place of `.`, and its category is the top-level input member that holds it. The input members that are not listed here have no attribute source: `subject.principal_id` is F1 (8.1), and `resource.id` and `action.id` come from `map_operation`. The `freshness` column names the row of the table above that bounds the source; in `profile.json` it is that row's `source` text. The document catalog has two entries because F5 and F6 have a row each.

| Source | `category` | `attributes` | `freshness` |
|---|---|---|---|
| HR/identity adapter | `subject` | `/subject/department` | F2 |
| Security-attribute service | `subject` | `/subject/clearance` | F3 |
| Device-management adapter | `environment` | `/environment/device/compliant` | F4 |
| Document catalog | `resource` | `/resource/classification` | F5 |
| Document catalog | `resource` | `/resource/owning_department` | F6 |
| The gateway itself | `environment` | `/environment/network_zone`, `/environment/time` | F7, F8 |

## 9. Residual limits

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Content disclosed after the obligations were applied is outside the executor's control: the agent can copy, forward, or export it. A watermark marks a copy and does not prevent copying. Purpose and data-use restrictions are labeled "attested-only" (draft §17.4) because `execution-control-v1` is not in the contract. An executed read is not undone by revoking its receipt (draft §18) | Disclosed here; no bound |
| Revocation propagation | A change at F1, F3, F5, or F6 is seen at the next read, whose status bound is 0, within each source's own consistency. A change at F2 is seen within 60 s. A change at F4, F7, or F8 is seen within 30 s at admission and again at execution (ABAC-21). Enrollment and hold status are read with status bound 0 (S1, S2), so the propagation bound of the enrollment source is its own consistency, with no PACT cache (identity-mapping section 7.5) | 0 s for F1, F3, F5, F6, S1, S2; 60 s for F2; 30 s for F4, F7, F8 |
| Decision-to-release window | The principal, department, clearance, classification, and owning department are not read again at execution. A change between the decision and the release is not seen. The window is bounded by the executor's own request deadline, not by PACT (open item O8) | Disclosed here; no PACT bound |
| Policy label | `policy_version` and the bundle revision are labels. A policy change that keeps the label is invisible to the pin (ABAC-16) | Disclosed here; change control belongs to the policy owner |
| Source integrity | The fact sources are authoritative by assumption (I11). A corrupted HR, clearance, catalog, or device record yields a decision that looks correct. PACT detects stale facts and disagreement with the agent's claim, not a wrong source | Disclosed here |
| Decision log content | OPA's log event carries the full input and result, so clearance, department, and device state are stored with it. Logs are protected evidence (ABAC-18). A mask rule reduces what a replay can reproduce, and OPA's log delivery requeues, backs off, and drops events above a rate limit [OPA-LOG] | Disclosed here; any mask rule is listed by the deployment |
| Obligation granularity | `filter_fields` and `redact` act on JSON Pointers of one JSON document. Response size, timing, error text, and the vacuous satisfaction of a pointer that resolves to nothing are side channels this profile does not close | Disclosed here |
| Time rules | A policy rule conditioned on `environment.time` can be 30 s out of date at execution (F8) | 30 s |

## 10. Fixture index

Thirty-seven negative cases and the positive control ABAC-38 cover the route, the closed bypass paths, every source row of section 8, the decision protocol, the execution-time rechecks and the obligations. The ids are those of the earlier revision without the letters `NEG`, the form the adapters README gives a case id; a case id names its rules here and nowhere else, so `ABAC-05` is a case and `ABAC-5` a rule. Twenty-three of them are adapter cases of this profile and live in `spec/v1.0/fixtures/adapters/abac/`, each file named after its case id in lower case, such as `abac-02.control.json`, with the manifest id `adapters/abac/abac-02.control`; `profile.json` lists the case files and the policy asset in `fixtures`. The [cases README](../../fixtures/adapters/abac/README.md) defines their native state, `abac/1`: the PDP, its policy or its literal answer, the zone map and the fact sources of a case. The policy of the cases, [`assets/policy.rego`](../../fixtures/adapters/abac/assets/policy.rego), is the I11 rule in Rego; the integration tier loads it into OPA. Behaviour that a single call of an adapter function cannot show (the gateway's comparison of the version and of the obligation types, the execution-time recheck, the executor's enforcement of the obligations, the absence of a decision cache) is covered by Go tests of the adapter package. The ABAC check itself is an adapter function, `check_context` with the entry's identifier (draft §17.1), and its results are cases.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `ABAC-01` | The profile discloses a clearance stronger than the authoritative value | The field rule fails with `INVALID_CLAIM`; the PDP input never contains the claimed value (draft §22.2, self-asserted privileged claim) | `abac-01.claim`, `abac-01.decision`; the field rule with `INVALID_CLAIM` is the validator's (draft §9.2), not an adapter function | R1; ABAC-1, ABAC-12 |
| `ABAC-02` | Department, classification, zone, or device supplied in a header, query, body, profile, or signed evidence artifact | The value is not in the input; the input equals the one built without it | `abac-02.classification`, `abac-02.control`, `abac-02.department`, `abac-02.device`. The adapter's functions receive no presentation, profile, evidence artifact, query or body, so a value there has no path to the input; the cases cover the headers, the operation's extensions and the principal attributes that do reach `authorize_native` | R1; ABAC-1, ABAC-5, ABAC-6 |
| `ABAC-03` | A forwarding header names a trusted zone while the peer address is outside it | The zone in the input comes from the peer address | `abac-03.claim`, `abac-03.forwarded-zone` | ABAC-7 |
| `ABAC-04` | No authenticated device identifier, and a device identifier in a header | No input and no PDP query; `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`, `DEFERRED` | `abac-04.claim`, `abac-04.no-device`, `abac-04.check` (the check with a principal that carries no `device_id`: `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`, no PDP query) | ABAC-6, ABAC-8 |
| `ABAC-05` | An observation older than `max_age`, or a status check older than `status_max_age`, one case for each of F1 to F8, S1, S2 | Not `ADMISSIBLE`: `STALE_EVIDENCE`; no PDP query | `abac-05.at-limits`, `abac-05.classification-status`, `abac-05.clearance-observed`, `abac-05.department-observed`, `abac-05.department-status`, `abac-05.device-observed`, `abac-05.device-status`, `abac-05.owning-department-observed`, `abac-05.principal-id-status`. F7 and F8 are observed by the gateway in the call that uses them and cannot be stale at admission; S1 is `_common/fresh-01.revoked-after-issuance` and S2 the gateway's hold store, neither an adapter function of this profile | F1 to F8, S1, S2; ABAC-9 |
| `ABAC-06` | A source clock ahead of the validator, or a re-stamped observation | `CLOCK_AHEAD` or `RESTAMPED`; no PDP query | `abac-06.at-skew`, `abac-06.clock-ahead`, `abac-06.restamped` | ABAC-9 |
| `ABAC-07` | A required source unavailable at evaluation, one case for each of F1 to F8, S1, S2 | `DEFERRED` with `DEPENDENCY_UNAVAILABLE`; no PDP query (draft §18, §22.2) | `abac-07.catalog`, `abac-07.clearance`, `abac-07.device`, `abac-07.hr`, `abac-07.outage-before-stale`. S1 is `_common/fresh-05.binding-source-down`; F7 and F8 have no source outside the gateway; S2 is the gateway's | F1 to F8, S1, S2; ABAC-8, ABAC-10 |
| `ABAC-08` | The catalog has no classification or owning department for the mapped document; a department with no `x-dept` mapping | `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`, `DEFERRED` | `abac-08.device-not-boolean`, `abac-08.missing-before-stale`, `abac-08.no-classification`, `abac-08.no-owning-department`, `abac-08.no-source-time`, `abac-08.unmapped-department`, `abac-08.unmapped-zone` | ABAC-4, ABAC-5, ABAC-8 |
| `ABAC-09` | A clearance or classification name outside the configured chain | The policy yields `allow` false; no execution | `abac-09.classification`, `abac-09.clearance`, against the policy of `assets/policy.rego` | ABAC-11 |
| `ABAC-10` | Clearance `internal` against classification `confidential` in the chain `public`, `internal`, `confidential`, `restricted`, where string order and chain order differ | The comparison follows chain rank, so the result is a denial | `abac-10.rank-denies`, `abac-10.rank-permits`, against the same policy | ABAC-11 |
| `ABAC-11` | A PDP answer with no `result` member | No execution; an `unknown` decision; `DEPENDENCY_UNAVAILABLE` | `abac-11.empty-object`, `abac-11.no-result`, `abac-11.check` (`UNKNOWN` with `DEPENDENCY_UNAVAILABLE`) | ABAC-14 |
| `ABAC-12` | A PDP `result` that is a bare boolean, lacks `allow` or `obligations`, has a wrong type, an extra member, a repeated obligation type, or duplicate JSON keys | No execution; `UNSUPPORTED_REQUIREMENT` | `abac-12.allow-string`, `abac-12.array-body`, `abac-12.array-result`, `abac-12.bare-boolean`, `abac-12.duplicate-member`, `abac-12.empty-type`, `abac-12.extra-member`, `abac-12.no-allow`, `abac-12.no-obligations`, `abac-12.not-json`, `abac-12.null-result`, `abac-12.obligation-extra-member`, `abac-12.obligation-no-params`, `abac-12.obligations-object`, `abac-12.params-not-object`, `abac-12.repeated-type`, `abac-12.trailing-text` | ABAC-14, ABAC-15, ABAC-26 |
| `ABAC-13` | A decision whose `policy_version` is absent, empty, or not a string | `REQUIREMENTS_CHANGED` at the check; `UNSUPPORTED_REQUIREMENT` from `authorize_native` (ABAC-14 row 6) | `abac-13.absent`, `abac-13.empty`, `abac-13.not-string`, `abac-13.check` (`FAIL` with `REQUIREMENTS_CHANGED`) | ABAC-16 |
| `ABAC-14` | A decision whose `policy_version` differs from the pinned one after the policy was updated | `REQUIREMENTS_CHANGED`; obtain a new contract | `abac-14.other-version`: the adapter returns the version it got; `abac-14.check`: the check is `FAIL` with `REQUIREMENTS_CHANGED`; the gateway's comparison with the pin on the `authorize_native` path is a Go test | ABAC-16 |
| `ABAC-15` | The PDP answers with a status other than 200, times out, or refuses the connection | `DEFERRED` with `DEPENDENCY_UNAVAILABLE` | `abac-15.redirect`, `abac-15.refused`, `abac-15.status-204`, `abac-15.status-400`, `abac-15.status-404`, `abac-15.status-500`, `abac-15.timeout` | ABAC-10, ABAC-14 |
| `ABAC-16` | A 200 answer with no `decision_id`, an empty one, or one that is not a string (ABAC-14 row 4) | No execution; `DEPENDENCY_UNAVAILABLE` | `abac-16.empty-decision-id`, `abac-16.no-decision-id`, `abac-16.numeric-decision-id` | ABAC-18 |
| `ABAC-17` | `allow` false with obligations | No execution; `authorize_native` returns the denial with its obligations, and no executor is involved | `abac-17.deny-with-obligations` | ABAC-17 |
| `ABAC-18` | A policy built-in error under strict evaluation | No decision and no execution; no `allow` without its obligation | `abac-18.builtin-error`. Probed on OPA 1.21.2: with `strict-builtin-errors=true` a built-in error is status 500 with code `internal_error`; without it the document is undefined (open item O2) | ABAC-13 |
| `ABAC-19` | Valid admission and a native denial | No execution (draft §22.2) | `abac-19.native-deny` | ABAC-17 |
| `ABAC-20` | A second request after an allowed first one | A new PDP query; no reuse of the first decision | Go test of the adapter package: two calls make two queries; nothing is cached | ABAC-17 |
| `ABAC-21` | A request to the document service from a host other than the gateway | Refused; no content returned | No fixture: a deployment control of the document service | B1; ABAC-29 |
| `ABAC-22` | A request to the OPA API by an identity other than the adapter's, and a policy or data write | Refused | Go test of the adapter package: the adapter sends only `POST` to the decision path, with its own credential. The PDP's refusal of other clients and of writes is deployment configuration (ABAC-19) | B2; ABAC-19 |
| `ABAC-23` | The device becomes non-compliant after admission and its `status_max_age` has elapsed | Rereading yields a denial; no disclosure | Go test of the adapter package (`Recheck`) | ABAC-21, ABAC-22 |
| `ABAC-24` | The network zone changes after admission and its `status_max_age` has elapsed | Rereading yields a denial; no disclosure | Go test of the adapter package (`Recheck`) | ABAC-21, ABAC-22 |
| `ABAC-25` | The device source is unavailable at the recheck | No disclosure | Go test of the adapter package (`Recheck`) | ABAC-23 |
| `ABAC-26` | The release happens within `status_max_age` of the admission reading | The decision in force stands; disclosure proceeds (a control case) | Go test of the adapter package (`Recheck`) | ABAC-21 |
| `ABAC-27` | The new decision at the recheck carries other obligations, or another version | The new set governs; a version mismatch gives `REQUIREMENTS_CHANGED` | Go test of the adapter package (`Recheck`) | ABAC-22 |
| `ABAC-28` | An obligation of an unknown type | `authorize_native` returns the allow with the obligation unchanged; the gateway does not use it; no disclosure | `abac-28.unknown-type`, `abac-28.check` (`UNKNOWN` with `UNSUPPORTED_REQUIREMENT`, ABAC-14 row 9); the gateway's refusal and the executor's are Go tests (`Gate`, `Enforcer`) | ABAC-14 row 9, ABAC-25, ABAC-28 |
| `ABAC-29` | An obligation with missing, unknown, or malformed parameters, or a malformed pointer | No disclosure | Go test of the adapter package (`Enforcer`) | ABAC-25, ABAC-28 |
| `ABAC-30` | A `filter_fields` obligation | No member outside `keep` appears anywhere in the response, error paths included | Go test of the adapter package (`Enforcer`) | ABAC-25, ABAC-27 |
| `ABAC-31` | A `redact` obligation | The original value appears nowhere in the response; the marker is present | Go test of the adapter package (`Enforcer`) | ABAC-25, ABAC-27 |
| `ABAC-32` | A `watermark` obligation the executor cannot apply to the content type | No disclosure | Go test of the adapter package (`Enforcer`) | ABAC-28 |
| `ABAC-33` | The executor fails while applying obligations | No byte of content is released | Go test of the adapter package (`Enforcer`) | ABAC-27 |
| `ABAC-34` | The executor receives a read without the envelope, or with `obligations` absent | No disclosure | Go test of the adapter package (`Enforcer.Release`) | ABAC-29 |
| `ABAC-35` | Principal substitution, changed task, stale or revoked delegation, broader executor credential, undeterminable executor | The results of draft §17.5 | No ABAC fixture: the checks of draft §17.5 are the gateway's; the adapter half is `_common/common-06.no-connector-substitution` | Section 3 |
| `ABAC-36` | An export action presented under a read admission | Context mismatch (draft §22.2) | `abac-36.export`, `abac-36.read`; the context mismatch at admission is the validator's | R1; section 6 |
| `ABAC-37` | A 200 answer with `decision_id` and a valid document | `authorize_native` returns the decision with `source_id` the PDP's configured identifier, `source_ref` the `decision_id`, `policy_revision` the `policy_version` and `decided_at` null; no execution. Replaces `COMMON-06.decision-provenance` | `abac-37.provenance` | ABAC-15, ABAC-18 |
| `ABAC-38` | A well-formed, version-pinned, attributable decision through the installed check, with `allow` true and with `allow` false | `check_context` returns `PASS` with `REQUIREMENT_SATISFIED` in both: the check does not report `allow` (section 13) | `abac-38.check-allow`, `abac-38.check-deny`, against the policy of `assets/policy.rego` | ABAC-14 rows 8 and 10, ABAC-16 |

### Replaced common cases

| Common case | Reason | Replacement |
|---|---|---|
| `COMMON-06.decision-provenance` | The Data API answer carries no decision time (ABAC-15, section 17), so `decided_at` 1792079998 cannot be realized | `ABAC-37.provenance` |

Every other common case runs unchanged. The common-06 cases carry `device_id` and `peer_address` on the principal (ABAC-6, ABAC-7); the harness supplies the facts F2, F3, F5 and F6 for the case's principal and resource, since the common policy reads none of them.

## 11. Policy input, fact authority, and freshness

The adapter queries the PDP with an input of exactly four members, `subject`, `resource`, `action`, and `environment`. The table fixes every member and its form.

| Member | Fact | Form |
|---|---|---|
| `subject.principal_id` | F1 | The `Principal` identifier from `authenticate_native`, in the namespace of the authenticating mechanism (ABAC-4); equal to `OperationContext.principal_id` |
| `subject.department` | F2 | A department identifier in the `x-dept` namespace (ABAC-4) |
| `subject.clearance` | F3 | A level name of the configured chain (ABAC-11) |
| `resource.id` | map_operation | The one resource of the `OperationContext` (ABAC-5) |
| `resource.classification` | F5 | A level name of the configured chain |
| `resource.owning_department` | F6 | A department identifier in the `x-dept` namespace |
| `action.id` | map_operation | `OperationContext.action`, here `document.read` |
| `environment.device.compliant` | F4 | A JSON boolean; `true` only when the management service reports the device compliant |
| `environment.network_zone` | F7 | A zone identifier from the gateway's configured zone map |
| `environment.time` | F8 | Integer Unix seconds of the gateway clock reading (draft §7.1) |

An example input, with the PDP path `pact/abac/decision` and fictional values:

```json
{
  "input": {
    "subject": {
      "principal_id": "ldap:corp-directory:4f6c2a1e-9b3d-4c85-a2f0-1d7e6b5a4c39",
      "department": "x-dept:northstar-hr:procurement",
      "clearance": "confidential"
    },
    "resource": {
      "id": "document:c-2041",
      "classification": "confidential",
      "owning_department": "x-dept:northstar-hr:procurement"
    },
    "action": {"id": "document.read"},
    "environment": {
      "device": {"compliant": true},
      "network_zone": "corporate",
      "time": 1792080000
    }
  }
}
```

**ABAC-1. Native sources only.** The input comes from three places: the authenticated native context of `authenticate_native`, `read_native_claim` over paths approved in the versioned mapping, and the `OperationContext` of `map_operation`. A value from the presentation, the AgentProfile, an evidence artifact, the declared intent, a header, the query string, the body, or a model output never enters the input, even when its signature verifies or it satisfies a field rule. Where the profile carries a value for the same fact (ABAC-12), that value is compared and discarded, and the input carries the authoritative one. The subject is the original principal, never the executor's own authority. *Basis: draft §8.2, §8.5, §17.1, §17.5.*

**ABAC-2. Fixed input shape.** The input has the four members and the members of the table, and no others. A policy that needs another fact needs a new mapping revision and a new installed check (ABAC-16). The input has no agent identifier, task, or purpose (section 6). *Basis: profile.*

**ABAC-3. One authority per fact.** The facts are inputs, never policy data. The policy's `data` documents hold policy parameters only: the clearance chain (ABAC-11), action tables, and obligation templates. No subject, resource, device, or network fact is loaded as policy data. The policy does not fetch a fact itself, for example through an outbound HTTP call, and does not read a clock; the only time it sees is `environment.time`. A second copy of a fact would be a second authority with no freshness declaration (draft §17.2). OPA's decision log records the results of non-deterministic built-ins, `http.send` among them, in `nd_builtin_cache` [OPA-LOG]. *Basis: draft §17.2; profile.*

**ABAC-4. Identifiers.** `subject.principal_id` is the identifier the authenticating mechanism produced, compared by exact octets (identity-mapping section 3.3, ABAC and ReBAC row, IM-1 to IM-5). `subject.department` and `resource.owning_department` are written `x-dept:{hr-source-id}:{department-id}` in the grammar of identity-mapping section 3.1, where `hr-source-id` is the configured identifier of the HR directory and `department-id` is the immutable department key in it. The mapping from the HR source and from the catalog to this form is configured and versioned. A catalog value with no mapping is not a department (ABAC-8). Departments of different HR sources never compare equal. *Basis: draft §8.5, §17.2; identity-mapping.*

**ABAC-5. Resource facts come from the mapped resource.** `resource.id` is the identifier `map_operation` produced from the actual request, never a client-supplied list (draft §10.2). The catalog path for the classification and the owning department is the approved path template instantiated with that identifier. A document absent from the catalog, or with a missing classification or owning department, has no established fact (ABAC-8). The adapter does not accept a classification the agent states or a lower one the agent proposes (I11). *Basis: draft §10.2, §17.2; profile.*

**ABAC-6. Device identity from authenticated context.** The device is identified by an authenticated attribute of the request, such as a device certificate validated by native authentication, carried by `authenticate_native` as the `Principal` attribute `device_id`. The ABAC check and `authorize_native` read it from the `Principal` they receive (draft §17.1). An identifier from a header, the profile, or the body is never used. A request with no authenticated device identifier has no device fact (ABAC-8). Whether the device is the agent's host or the user's device is open item O5. *Basis: draft §8.5; profile.*

**ABAC-7. Connection facts.** The zone is derived by the gateway from the transport-level peer address of the connection that carries this request, with the zone map of trusted gateway configuration (draft §4.2). A forwarding header, such as `X-Forwarded-For`, never selects it. `authenticate_native` records that peer address as the `Principal` attribute `peer_address`, and the zone is derived from it. The time is the gateway clock reading for this request. Both are derived again for each request and never cached per connection, because a connection class has no revocation after it is opened (freshness profile section 4.1). *Basis: draft §4.2, §10.2; freshness profile; profile.*

**ABAC-8. An unestablished fact yields no input.** The adapter builds the input only when every fact of the table has a `PASS` freshness verdict (freshness profile section 3) and a value of the required form. Otherwise it makes no PDP query, and the result follows this table, in which the first matching row applies.

| Condition | Verdict and reason code | ABAC check result and admission decision | `authorize_native` returns |
|---|---|---|---|
| A required source cannot answer | `UNKNOWN`, `DEPENDENCY_UNAVAILABLE` | `UNKNOWN`; `DEFERRED` | An error of kind `DEPENDENCY_UNAVAILABLE` |
| The source gives no usable time, the value is missing or outside its form (no authenticated device, a department with no mapping, a non-boolean), or a limit is invalid | `UNKNOWN`, `UNSUPPORTED_REQUIREMENT` | `UNKNOWN`; `DEFERRED` | An error of kind `UNSUPPORTED_REQUIREMENT` |
| An age is above its limit, a source clock is ahead, or an observation was re-stamped | `FAIL`, `STALE_EVIDENCE`, `CLOCK_AHEAD`, or `RESTAMPED` | `FAIL`; `INADMISSIBLE` | An `unknown` decision: the PDP was not consulted |

The reason codes and their results are those of freshness profile section 3.2. The mapping of a value outside its form to `UNSUPPORTED_REQUIREMENT` is a profile convention: draft §13.4 has no code for it, and the code means that a required mapping has no installed meaning. *Basis: draft §13.4, §17.2, §18; freshness profile; profile.*

**ABAC-9. Limits and arithmetic.** Each fact is read with the limits of section 8 and evaluated at every use under the rules of freshness profile section 3, with `ObservedAt` and `StatusCheckedAt` as the source gives them and never the read time (draft §8.3). The limits live in the installed check entry (ABAC-16), because a fact the agent does not disclose has no field rule to carry them; for F2 and F3 the contract's field rules (ABAC-12) carry limits equal to or tighter than the entry's. A cache never extends a limit, and the guard against re-stamping applies to every fact that has a source reference. *Basis: draft §9.2, §17.2, §18; freshness profile.*

**ABAC-10. Outage.** A required source or the PDP that cannot answer gives `DEFERRED` with `DEPENDENCY_UNAVAILABLE`. There is no last-known-good value and no fallback policy: no integration serves a stale fact or a decision of an earlier request because a source is down, and no outage widens a limit. *Basis: draft §18; freshness profile section 5.*

## 12. Comparisons

**ABAC-11. Clearance is a configured chain.** The clearance order is one finite, totally ordered list of level names, lowest first, for example `public`, `internal`, `confidential`, `restricted` (illustrative). A chain is a lattice whose meet and join are the lesser and the greater level, so this is the ordinal lattice the profile supports. The chain is policy data and is covered by the pinned `policy_version` (ABAC-16): renaming or reordering a level is a new version. `subject.clearance` and `resource.classification` are names from this chain. A policy that compares levels compares chain ranks: a clearance permits a classification when both names are in the chain and the rank of the clearance is at least the rank of the classification, which is the sample rule of I11. It never compares names as strings or numbers. A name outside the chain has no rank: any comparison with it is false and the policy yields `allow` false, and it is never ranked lowest or highest. *Basis: profile; I11.*

**ABAC-12. Disclosed claims are compared for equality.** Where the contract requires the agent to disclose `/attributes/environment/department` and `/attributes/environment/clearance`, each field rule has source `native`, a `native_path` mapped to F2 or F3, and comparison `equal` (draft §8.4, §9.2). The draft's comparisons are `equal` and `subset` only; there is no ordinal field-rule comparison, so ordering exists only in the policy (ABAC-11). A disclosed value that differs from the authoritative one, higher or lower, fails the rule with `INVALID_CLAIM`. The clearance is never taken from an evidence artifact (section 6). *Basis: draft §8.4, §9.2; profile.*

## 13. Decision protocol and policy version

The installed ABAC check (ABAC-16), run through `check_context` on the authenticated principal and the actual operation it receives (draft §17.1), and `authorize_native` run the same procedure: build the input (section 11), query the PDP (ABAC-13), and classify the answer (ABAC-14). `authorize_native` returns the decision, which is `allow`, `deny`, or `unknown`, with every obligation of the document and its provenance as the PDP gave them, or an error of a draft §13.4 kind; it never edits, drops, or adds an obligation and never converts an allow into a denial (draft §17.1: the existing decision). The gateway, not the adapter, refuses an allow it cannot enforce (ABAC-28). The check reports whether the procedure produced a well-formed, version-pinned, attributable decision whose obligations are supported. It never reports `allow`, so that admission and authorization stay distinguishable (draft §3, I11).

**ABAC-13. Request.** The adapter sends `POST {pdp}/v1/data/{decision path}?strict-builtin-errors=true` with `Content-Type: application/json` and a body whose only top-level member is `input` [OPA-REST, Get a Document (with Input)]. Any other top-level member of the body is treated as request metadata, which OPA makes available to custom built-ins and records in its decision log [OPA-REST, Request/Response Metadata], so the adapter sends none. `{decision path}` is the slash-separated path of the one decision document of the installed check entry; the reference value is `pact/abac/decision`. The query parameter `strict-builtin-errors` is required. Without it, a built-in call that raises a runtime error evaluates to undefined and evaluation continues [OPA-LANG, Errors]; a rule whose body does not match produces no value [OPA-LANG, the note after the negation example]; so, by this profile's analysis and not an OPA statement, a rule that contributes an obligation could silently contribute nothing while `allow` stays true. With the parameter, built-in errors are fatal and OPA returns an error immediately [OPA-REST, query parameters]. OPA 1.21.2 answers it with status 500 and the code `internal_error` (open item O2); ABAC-14 treats every status other than 200 alike. The adapter MAY add `provenance=true` to the query (ABAC-18). *Basis: OPA; profile.*

**ABAC-14. Classifying the answer.** OPA answers a decision query with a JSON object. `result` holds the document the path names and is omitted when the document is undefined; the server answers 200 for an undefined document, 400 for an invalid input document, and 500 for a server error; `decision_id` is present when decision logging is enabled [OPA-REST, Get a Document (with Input)]. The adapter applies the rows below in order, and the first that matches decides. The columns give what the ABAC check and `authorize_native` return, and the code of the gateway's rejection of the protected request (draft §13.4).

| # | Observed | ABAC check result and admission decision | `authorize_native` returns | Gateway rejection |
|---|---|---|---|---|
| 1 | No answer, a timeout, a transport failure, or a status other than 200 | `UNKNOWN`, `DEPENDENCY_UNAVAILABLE`; `DEFERRED` | An error of kind `DEPENDENCY_UNAVAILABLE` | `DEPENDENCY_UNAVAILABLE` |
| 2 | Status 200 and a body that is not one JSON object under strict parsing (duplicate member names, non-finite numbers, invalid Unicode: draft §7.1) | `UNKNOWN`, `UNSUPPORTED_REQUIREMENT`; `DEFERRED` | An error of kind `UNSUPPORTED_REQUIREMENT` | `UNSUPPORTED_REQUIREMENT` |
| 3 | The object has no `result` member: an undefined document | `UNKNOWN`, `DEPENDENCY_UNAVAILABLE`; `DEFERRED` | An `unknown` decision with no obligations | `DEPENDENCY_UNAVAILABLE` |
| 4 | No `decision_id`, or one that is not a non-empty string | `UNKNOWN`, `DEPENDENCY_UNAVAILABLE`; `DEFERRED` | An error of kind `DEPENDENCY_UNAVAILABLE` | `DEPENDENCY_UNAVAILABLE` |
| 5 | `result` is not a JSON object: a boolean, null, number, string, or array | `UNKNOWN`, `UNSUPPORTED_REQUIREMENT`; `DEFERRED` | An error of kind `UNSUPPORTED_REQUIREMENT` | `UNSUPPORTED_REQUIREMENT` |
| 6 | The `policy_version` member is absent, is not a string, is empty, or differs from the pinned version (ABAC-16) | `FAIL`, `REQUIREMENTS_CHANGED`; `DEFERRED`, retry guidance "obtain a new contract" | For an absent, empty, or non-string member, an error of kind `UNSUPPORTED_REQUIREMENT` (the document fails ABAC-15); otherwise the decision as the document gives it, with `policy_version` as `PolicyRevision`: the comparison with the pinned version is the gateway's (section 17), and a decision of another version is never used | `REQUIREMENTS_CHANGED` |
| 7 | `result` fails the decision schema of ABAC-15 | `UNKNOWN`, `UNSUPPORTED_REQUIREMENT`; `DEFERRED` | An error of kind `UNSUPPORTED_REQUIREMENT` | `UNSUPPORTED_REQUIREMENT` |
| 8 | A valid document with `allow` false | `PASS`, `REQUIREMENT_SATISFIED` (the check does not report `allow`) | A `deny` decision with the obligations the document carries (ABAC-17) | The gateway's native denial |
| 9 | A valid document with `allow` true and an obligation type outside the installed set (ABAC-25) | `UNKNOWN`, `UNSUPPORTED_REQUIREMENT`; `DEFERRED` | An `allow` decision with the obligations as the document carries them | The gateway's generic denial: the allow is not used and nothing is disclosed (ABAC-28) |
| 10 | A valid document with `allow` true and every obligation type in the installed set | `PASS`, `REQUIREMENT_SATISFIED` | An `allow` decision with the obligations | None |

A malformed, undefined, or unattributable answer never becomes an allow, and never becomes `PASS` for any check. An undefined document is not read as a denial: it means the PDP gave no decision, and the profile reports what happened instead of inventing a native denial. The mapping of rows 2, 5, and 7 to `UNSUPPORTED_REQUIREMENT` is a profile convention, like row 4's use of `DEPENDENCY_UNAVAILABLE` for a decision that cannot be attributed (draft §12.2: a required record that cannot be written gives no positive admission). *Basis: OPA; draft §13.4, §17.3.1, §18; profile.*

**ABAC-15. The decision document.** The value of the decision path is a JSON object with exactly three members.

| Member | Type | Rule |
|---|---|---|
| `allow` | boolean | Required. `true` permits the operation, `false` denies it. No other value is a decision |
| `obligations` | array | Required, and an empty array means none. Each element is an object with exactly `type` (a non-empty string) and `params` (a JSON object, which may be empty). At most one element has a given `type` (ABAC-26). An absent member is malformed, never "no obligations" |
| `policy_version` | string | Required and non-empty. Compared by exact octets with the pinned version (ABAC-16) |

Any other member of the document or of an obligation is malformed (ABAC-14, row 7). The document has no member for a reason or an explanation. The adapter reads `result` and `decision_id` from the answer, and `provenance` only to record a bundle revision (ABAC-18); it ignores the other members OPA may add, such as metrics. *Basis: profile.*

An example answer:

```json
{
  "decision_id": "8f0d6a3e-5c1b-4a7e-9d2f-3b6c1e4a7d90",
  "result": {
    "allow": true,
    "obligations": [
      {"type": "filter_fields", "params": {"keep": ["/title", "/supplier", "/terms"]}},
      {"type": "watermark", "params": {"label": "supplier-review"}}
    ],
    "policy_version": "abac-2026-10-01"
  }
}
```

**ABAC-16. The policy version is pinned.** The effective contract names the installed ABAC check in `context_checks` (draft §9.3). The installed check entry records its identifier, the PDP endpoint and decision path, the pinned `policy_version`, the mapping revision, the limits of section 8 (ABAC-9), the installed obligation set (ABAC-25), and the executor class. An entry never changes: a change to any member is a new entry under a new identifier, which new contracts name. The identifier is chosen by the gateway's administrators, and the pinned `policy_version` is the installed check version of this profile (open item O4). A decision whose `policy_version` is absent, not a string, empty, or not equal to the pinned version means that the policy now installed is not the one the contract was issued for, and the result is `REQUIREMENTS_CHANGED` ("Contract is no longer active; obtain a new contract", draft §13.4). The same rule applies in the ABAC check and in `authorize_native` (row 6 of ABAC-14). For the check, the `FAIL` result, the `DEFERRED` decision, the retry guidance, and the transport error on reuse of the contract follow draft §11.3 step 9 for `selection-consistency-v1`; the draft does not define them for this check. At evaluation the validator checks that the contract's entry is the one active for the route (draft §11.3 steps 3 and 10). The pinned version is a label the policy publisher sets, and neither it nor the bundle revision proves the policy's content (section 9). *Basis: draft §9.3, §9.4, §11.3, §13.4; profile.*

**ABAC-17. Allow and deny.** Only `allow` true permits. A denial, an unknown decision, an error, or an absent decision does not. The adapter never turns a denial into an allow, never edits an obligation, and never repeats a query with an altered input to find an allow. The obligations of a denial are returned with it and never applied: no executor is involved in a denial, and the native record of the refusal lists them (ABAC-30). A decision is not cached: each `authorize_native` call and each recheck is a new query, and a decision of one request is never reused for another (freshness profile section 6: a native allow is not cached by PACT). A PACT pass cannot make a native decision more permissive, and a native denial wins (draft §2.3). *Basis: draft §2.3, §17.1; freshness profile; profile.*

**ABAC-18. Attribution and decision logging.** Decision logging must be enabled at the PDP: `decision_id` is present only then, and the event it identifies carries the policy path, the input, the result, and the revision of each bundle used [OPA-REST, Response Message; OPA-LOG]. The adapter records the `decision_id`, the pinned `policy_version`, and when available the bundle revision (reported through the `provenance` parameter of the Data API [OPA-REST, Provenance] or the log event) in the native record of ABAC-30, and as the `source_ref` of its `CheckResult` (draft Appendix A.2). The log event holds the full input, so the facts of section 11 are stored in it: the log is protected evidence storage (C14, draft §19). OPA re-queues a log chunk that the service rejects and drops events when a configured rate limit is exceeded [OPA-LOG], so its log is an audit aid and does not replace the gateway's own durable receipt (draft §12.2). *Basis: OPA; draft §12.2, §19, Appendix A.2; profile.*

**ABAC-19. The PDP channel and its API.** The adapter reaches the PDP over TLS and verifies the PDP's certificate (draft §19: TLS is mandatory on network paths, and draft §13.3.1 treats loopback TCP as a network path). OPA's authentication and authorization are off by default [OPA-SEC, Authentication and Authorization], so the PDP is configured to authenticate its clients, by client certificate or bearer token, and to authorize the adapter's identity for POST on the decision path only. The same API can create or replace policy and data [OPA-REST, Create or Update a Policy; Create or Overwrite a Document], so no credential held by the adapter or by the agent's host can write either, and policy reaches the PDP through its owner's publication process. A PDP with authentication and authorization off is not a PDP under this profile. Binding OPA to the loopback interface, its default [OPA-SEC, Interface Binding], reduces exposure and is not authorization. *Basis: OPA; draft §13.3.1, §19; profile.*

**ABAC-20. The policy answers on every input.** The policy emits a complete decision document for every input, including a denial: a default decision whose `allow` is false, whose `obligations` is empty, and whose `policy_version` is the version string the policy carries. OPA's `default` keyword supplies a value when every rule of the document is undefined, and accepts a composite term without variables or references [OPA-LANG, Default Keyword]. A policy that omits the default is not wrong for the adapter, which treats an undefined document as row 3 of ABAC-14, but it turns each unmatched input into a deferral instead of a denial. *Basis: OPA; profile.*

## 14. Execution-time rechecks

An admission and an execution are different instants. Between them a device can become non-compliant or a request can move to another network zone, and an allow that rests on the old state is stale (I11).

**ABAC-21. Set and trigger.** Before it releases content, the executor side rereads F4 (device compliance), F7 (network zone), and F8 (time). For each, let `s` be the status check time of the reading in force and `L` its `status_max_age` from section 8. When the execution instant minus `s` is greater than `L`, the fact is read again through `read_native_claim`; an age equal to `L` passes (freshness profile section 3.1, rule 4). The age is counted from `s`, which is not later than the admission decision, so the rule is never more lenient than counting from admission. The facts F1 to F3, F5, and F6 are not read again at execution and keep their admission-time verdicts (section 9). A deployment may add facts to this set and may not remove one. *Basis: draft §2.3, §9.2, §18; freshness profile; profile.*

**ABAC-22. Re-decision.** When any fact was read again, the adapter evaluates the new readings under the rules of section 3 of the freshness profile, with the start of the recheck as the evaluation start, builds a new input from the new readings and the unchanged ones, and queries the PDP again. The new decision replaces the decision in force: a denial, an unknown, an error, or a version mismatch (ABAC-16) means no disclosure, and the new decision's obligations, not the old ones, are applied (ABAC-27). When no fact needed a new reading, the decision in force stands. *Basis: draft §2.3, §17.1; profile.*

**ABAC-23. A failed recheck.** A reread that cannot complete, a reread fact that fails freshness, or a new decision other than an allow with supported obligations makes the execution condition of draft §2.3 (`native_execution_conditions_satisfied`) false: nothing is disclosed. The gateway's rejection carries the code of the matching row of ABAC-8 or ABAC-14. A source outage is never a pass, and no last-known-good value stands in (ABAC-10). *Basis: draft §2.3, §18.*

**ABAC-24. Placement.** The recheck runs after the executor holds the content and before the first byte is released, so that a slow read does not lengthen the window. The obligations are applied after the recheck settles. *Basis: profile.*

## 15. Obligations

The draft does not define an obligation: the word appears in the handoff and in I11, and draft §17.3 only states that the gateway remains responsible for resource enforcement and field permissions. This profile defines the term for itself. An obligation is a typed condition in a policy decision that the executor must carry out before it discloses data. PACT carries it to the executor and does not interpret it: the obligation of the reference adapter contract holds the obligation type and its parameters, and PACT defines no obligation type (section 17). The executor interprets it, as follows.

**ABAC-25. The three obligation types.** The installed obligation set of an entry (ABAC-16) is `filter_fields`, `redact`, and `watermark`. Their `params` are closed objects: a missing member, an unknown member, or a wrong type makes the obligation unmet (ABAC-28).

| `type` | `params` | Meaning |
|---|---|---|
| `filter_fields` | `keep`: an array of JSON Pointers | The disclosed document contains only the values at the listed pointers, with the containers needed to hold them. Every other member is removed |
| `redact` | `paths`: an array of JSON Pointers | The value at each listed pointer is replaced by the redaction marker of the executor's mapping. The member stays, and the original value is not disclosed |
| `watermark` | `label`: a non-empty string | The disclosed representation carries the label, by the means that the mapping revision declares for its content type |

A pointer follows the syntax of RFC 6901 section 3, which makes a non-conforming pointer an error condition [RFC 6901]. A pointer that contains the token `-` makes the parameters malformed, because RFC 6901 section 4 makes that token an error condition for an application that does not define it. A well-formed pointer that resolves to no value is satisfied: nothing the obligation names is disclosed. *Basis: RFC 6901 sections 3 and 4; profile.*

**ABAC-26. Order and repetition.** A decision holds at most one obligation of each type; a repeated type makes the document malformed (ABAC-14, row 7), and the policy merges. The executor applies the obligations in the order `filter_fields`, `redact`, `watermark`, whatever the order of the array. A `redact` pointer is resolved against the document after filtering. *Basis: profile.*

**ABAC-27. The executor enforces before disclosure.** The executor is the enforcement point. It holds the content, applies the obligations of the decision that governs the release (ABAC-22), verifies the postcondition of each on the result (no member outside `keep`; every resolved `redact` pointer holds the marker; the label is present), and only then releases. Disclosure is the release of the first byte of content, or of any value derived from it, toward the gateway or the agent, including an error body. No byte of unfiltered content is released before every obligation is applied and verified, and a streamed response releases nothing until then. An executor that cannot hold the content until then cannot claim this profile for that route. Recording an obligation in a profile or a receipt is not enforcement (I11). *Basis: draft §17.3; I11; profile.*

**ABAC-28. Unknown or unmet means no disclosure.** An obligation is unknown when its type is not in the installed set or its parameters do not fit ABAC-25. It is unmet when the executor cannot apply or verify it: the content is not a JSON document for `filter_fields` or `redact`, the mapping declares no watermark means for the content type, a pointer is malformed, or an error, timeout, or resource limit occurs while it is applied. In every such case nothing is disclosed. The response is the gateway's generic denial, which does not name the obligation or the policy (draft §13.4: public errors avoid disclosing private detail), and the refusal is recorded (ABAC-30). The gateway compares the type of each obligation of an allow with the installed set of the contract's entry (ABAC-16) before the executor is involved: an allow with a type outside the set is not used, the response is the generic denial above, and the refusal is recorded (ABAC-30); the executor repeats the check itself. `authorize_native` reports the obligation and does not judge it (ABAC-14, row 9). *Basis: draft §13.4, §17.3; profile.*

**ABAC-29. The envelope.** The gateway gives the executor, over the authenticated channel that closes B1, an envelope with the `operation_id`, the `decision_id`, the `policy_version`, and the `obligations` array, which may be empty. The executor refuses a request that arrives without the envelope or with `obligations` absent or not an array. Absence is never "no obligations". The executor does not honor an allow that did not come through the gateway. *Basis: draft §2.3, §17.3; profile.*

**ABAC-30. The native record and the outcomes.** For each release and each refusal the executor writes one immutable native record with the `operation_id`, the `decision_id`, the `policy_version`, the obligation types applied, the executor identity (draft §17.5), and the result. The `AUTHORIZATION` and `EXECUTION` outcome reports reference that record in `evidence_refs` (draft §14.2, Appendix A.2), and a report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`. A release is reported as in draft §14.5: a filtered or complete read is `EXECUTION`, `SUCCESS`, `reliability`. Draft §14.5 has no row for a read that the native policy allowed and the executor refused for an obligation, so this profile reports it as `EXECUTION`, `FAILURE`, dimension `none`, which carries no reputation weight and is not agent misconduct (draft §14.3, §14.5). *Basis: draft §14.2, §14.3, §14.5, §17.5; profile.*

## 16. Closure map for G22 (informative)

The handoff states the requested work and the evidence needed to close G22. This table maps each item to the rules that answer it and to the negative cases of section 10. Closure rests on those cases passing; this document maps items to rules and closes nothing by itself.

| G22 item | Where it is answered | Rules | Cases |
|---|---|---|---|
| Work: source authority | Section 8 table; section 11 | ABAC-1 to ABAC-7 | ABAC-01 to ABAC-04 |
| Work: comparisons | Section 12 | ABAC-11, ABAC-12 | ABAC-01, ABAC-09, ABAC-10 |
| Work: document classification | F5 and F6; section 11 | ABAC-5, ABAC-8, ABAC-11 | ABAC-02, ABAC-08, ABAC-09 |
| Work: policy version | Section 13 | ABAC-15, ABAC-16, ABAC-18, ABAC-20 | ABAC-12 to ABAC-14, ABAC-16, ABAC-38 |
| Work: current condition checks | Section 14 | ABAC-9, ABAC-21 to ABAC-24 | ABAC-23 to ABAC-27 |
| Work: actual enforcement of filtering or other obligations | Section 15 | ABAC-25 to ABAC-30 | ABAC-28 to ABAC-34 |
| Evidence: tampered clearance, classification, device, or network facts | Sections 11 and 12 | ABAC-1, ABAC-3, ABAC-5 to ABAC-7, ABAC-12 | ABAC-01 to ABAC-04 |
| Evidence: stale facts | Sections 8 and 11 | ABAC-8, ABAC-9 | ABAC-05, ABAC-06 |
| Evidence: outages | Sections 11 to 14 | ABAC-8, ABAC-10, ABAC-14, ABAC-23 | ABAC-07, ABAC-15, ABAC-25 |
| Evidence: changed execution conditions | Section 14 | ABAC-21 to ABAC-24 | ABAC-23 to ABAC-27 |
| Evidence: unmet obligations cannot disclose data | Section 15 | ABAC-25 to ABAC-30 | ABAC-28 to ABAC-34 |

## 17. Reference implementation (informative)

The reference implementation is the Go module `hop.top/pact-go` under `go/`. The rules above are language-neutral; this table names the Go packages that carry them. The adapter that queries the PDP is the package `go/adapters/abac`, which uses the standard library only.

| Profile concept | Go name | Behavior |
|---|---|---|
| The seven functions of draft §17.1 | `go/adapter`: `Adapter` and its seven interfaces, `NativeAuthenticator`, `BindingResolver`, `OperationMapper`, `ClaimReader`, `ContextChecker`, `NativeAuthorizer`, `OutcomeRecorder` | Each takes a `context.Context` first |
| Adapter entry of section 1 | `adapter.Descriptor` with `Protocol`, `Version`, `MappingRevision` | `opa-data-api`, `v1`, `pact-abac-1` |
| An `allow`, `deny`, or `unknown` decision | `adapter.Decision` with `Effect` set to `EffectAllow`, `EffectDeny`, or `EffectUnknown` | `Permits` is true only for `EffectAllow`; the zero value and an undefined effect do not permit. `Reason` is untrusted text, and this profile sets it to a fixed text and never copies policy text into it |
| The attribution (ABAC-18) and the policy version (ABAC-16) of a decision | `adapter.Decision` with `SourceID`, `SourceRef`, `DecidedAt`, `PolicyRevision` | `SourceID` is the configured identifier of the PDP of the installed check entry. `SourceRef` is the `decision_id`. `PolicyRevision` is the `policy_version` member of `result` as the PDP gave it, and is empty when that member is absent or not a string. `DecidedAt` is the zero time, because the Data API gives no decision time (ABAC-15); `COMMON-06.decision-provenance` is therefore replaced (section 10) |
| A wire obligation `{type, params}` | `adapter.Obligation` with `ID` and `Attributes` | `ID` is the obligation type as the native policy names it, so it carries `type`, and `Attributes` holds its parameters, so it carries `params`. PACT defines no obligation type and never interprets one; the executor enforces the three of ABAC-25 (section 15, draft §17.3) |
| An error of kind `DEPENDENCY_UNAVAILABLE` or `UNSUPPORTED_REQUIREMENT` | `adapter.ErrDependencyUnavailable`, `adapter.ErrUnsupportedRequirement`, and `adapter.CodeOf` | An implementation returns an error that wraps the sentinel |
| A fact read (F1 to F8) | `ClaimReader.ReadNativeClaim` with an `adapter.ClaimContext` of `Principal`, `Intent`, and `Operation`, returning `adapter.NativeClaim` with `Value`, `ObservedAt`, `StatusCheckedAt`, `SourceID`, `SourceRef` | The approved path decides which part of the context a read uses. F1 to F3 are facts of `ClaimContext.Principal`, and the device identifier of F4 is one of its authenticated attributes (ABAC-6). F5 and F6 are facts of the resource identifier in `ClaimContext.Operation.Resources`, which `map_operation` produced (ABAC-5). No fact is read from `ClaimContext.Intent` (ABAC-1). A zero time means the source gives none (ABAC-8) |
| The freshness verdict of ABAC-8, ABAC-9, ABAC-21, ABAC-22 | `go/adapter/freshness`: `Evaluate`, `Evaluator` with `Skew`, `Start`, and `Guard`, and `Monotonic` | `Start` is the recheck start in ABAC-22. The reason codes are `Satisfied`, `StaleEvidence`, `ClockAhead`, `Restamped`, `UnsupportedRequirement`, and `DependencyUnavailable`. The limits come from a `core.FieldRule`, of which only the two age limits are read |
| The ABAC check result | `adapter.CheckOutcome` with `Result`, `ReasonCode`, `SourceID`, `SourceRef`, `ObservedAt` | `ReasonCode` is a string, so it carries `REQUIREMENTS_CHANGED` |
| Binding status (S1) | `go/adapter/enroll`: `Registry` and `Resolver`, which exposes a registry as the `BindingResolver` | Statuses `ACTIVE`, `REVOKED`, `COMPROMISED`, `UNKNOWN` |
| The adapter of this profile | `go/adapters/abac`: `New` over a `Config` | The inherited `authenticate_native` and `resolve_agent_binding` are the configuration's (section 7); `map_operation` with `DocumentRoutes` of `pact-abac-1`; `read_native_claim` of the fact paths; `record_outcome` with no visibility of execution |
| The fact sources of section 8 and their limits | `SubjectSource`, `ResourceSource`, `DeviceSource`, `EnvironmentSource`; `Gateway` (zone map and clock, F7 and F8); `ProfileLimits`; `ErrNoFact` | A limit looser than the profile's is refused by `New`. A fact the source does not hold is `ErrNoFact`, reported as `UNSUPPORTED_REQUIREMENT` (ABAC-8) |
| The decision protocol of section 13 | `Adapter.AuthorizeNative`, `Adapter.Decide`, `PDP` | `PDP.URL` must be an `https` origin; a redirect is never followed; the answer is read strictly and classified by ABAC-14 |
| The installed ABAC check (ABAC-16) | `Entry`, `Adapter.CheckContext` | `CheckContext` runs the ABAC check when the check ID is the entry's, on the `Principal` and `Operation` of the `adapter.CheckInput` it receives (draft §17.1), reading `device_id` and `peer_address` from the principal's attributes; any other ID runs the other installed checks |
| The gateway's use of a decision (section 17, ABAC-28) | `Gate` | `ErrNotPermitted`, `ErrRequirementsChanged` (code `REQUIREMENTS_CHANGED`), `ErrObligationUnsupported` |
| The execution-time recheck (section 14) | `Adapter.Recheck` over an `Admission` | F4, F7, F8 read again when their status age exceeds the limit; a new decision replaces the one in force |
| The executor's obligations (section 15) | `Enforcer`, `Envelope`, `ParseEnvelope`, `EnvelopeFor`, `Watermark`, `JSONMemberWatermark`, `ParsePointer` | Nothing is released unless every obligation is installed, well-formed, applied in the order of ABAC-26 and verified |

How the contract carries the version pin and the inputs of the check:

- The policy version is compared by the gateway, the caller of `AuthorizeNative`. `AuthorizeNative` takes the original principal and the actual operation and no contract (draft §17.1), and returns the `policy_version` the PDP gave as `Decision.PolicyRevision`. Before the gateway uses a decision, it compares `PolicyRevision` by exact octets with the installed check version that the contract names, which is the pinned `policy_version` of the contract's installed check entry (ABAC-16, open item O4). On a mismatch, including an empty `PolicyRevision`, the gateway does not use the decision and answers `REQUIREMENTS_CHANGED`: obtain a new contract (draft §13.4). This is how row 6 of ABAC-14 names its code on the `authorize_native` path, as the check path does through `ReasonCode`. The decision that row has the adapter return carries the `PolicyRevision` the PDP gave, so the comparison names the code, and a decision of another version is never used. `REQUIREMENTS_CHANGED` is the gateway's answer, not an error kind of package `adapter`.
- `ReadNativeClaim` reads in an `adapter.ClaimContext`, so the adapter instantiates the path template of F5 and F6 with the resource identifier in `ClaimContext.Operation.Resources` (ABAC-5).
- `CheckContext` takes the installed check ID and an `adapter.CheckInput`: the authenticated `Principal`, the agent binding, the intent, the operation, and the evidence references, as draft §17.1 lists its inputs. The ABAC check reads the principal, whose `ID` is `OperationContext.principal_id` namespaced by issuer and tenant (draft §8.5, ABAC-4), and the operation; it reads no agent, task, or purpose (ABAC-2) and ignores the binding and the intent. The device identifier of ABAC-6 and the peer address of ABAC-7 are the `Principal` attributes `device_id` and `peer_address`, set by `authenticate_native`; `CheckContext`, `AuthorizeNative` and `ReadNativeClaim` read them from the `Principal` they receive and keep no request state of their own.
- The draft has no definition of an obligation (section 15).

## 18. Sources and open items

The facts about OPA and RFC 6901 in this profile come from these pages, read on 2026-10-16. The OPA pages were read as the project's documentation sources on its default branch, and the REST API page was also read on the published site, where its Data API passages agree. The latest OPA release on that date was v1.21.2, and the release these pages describe is not pinned (O1).

| Tag | Source | Used for |
|---|---|---|
| `OPA-REST` | [REST API Reference](https://www.openpolicyagent.org/docs/rest-api) | Data API "Get a Document (with Input)": the `input` member of the request body, extra top-level members as request metadata, `result` omitted for an undefined document, status 200, 400, and 500, `decision_id` when decision logging is enabled, `strict-builtin-errors`; Provenance; the policy and data write endpoints |
| `OPA-LOG` | [Decision Logs](https://www.openpolicyagent.org/docs/management-decision-logs) | The fields of a log event, `nd_builtin_cache`, masking, requeue on a failed upload, and dropped events above the rate limit |
| `OPA-LANG` | [Policy Language](https://www.openpolicyagent.org/docs/policy-language) | The `default` keyword; built-in errors evaluating to undefined unless strict; a rule body that does not match produces no value |
| `OPA-SEC` | [Security](https://www.openpolicyagent.org/docs/security) | Authentication and authorization off by default, TLS, and interface binding |
| `RFC 6901` | [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901) | Sections 3 and 4: syntax, evaluation, and the error conditions |

Open items. Each is an explicit gap and none is a rule.

| ID | Open item |
|---|---|
| O1 | The OPA release is not pinned. To probe: send the request of ABAC-13 and one input for each row of ABAC-14 to the release the deployment pins, and confirm the status and body of each |
| O2 | The status and body of the error that `strict-builtin-errors` produces are not stated by the REST page, which says only that evaluation returns an error immediately. Probed on OPA 1.21.2 with a policy whose built-in fails: with the parameter, status 500 with code `internal_error` and an `errors` entry of code `eval_builtin_error`; without it, a 200 answer with no `result`. Other releases remain to probe. ABAC-14 treats every status other than 200 alike, so no rule depends on the answer |
| O3 | Decision-log delivery under a log-service outage or overload is described only as requeue, backoff, and dropping above a rate limit. To probe in the deployment's configuration before relying on the log for audit |
| O4 | The draft names no spelling for the identifier of an installed check, and no namespace for one that a profile defines. This profile takes the pinned `policy_version` of the installed entry as the installed check version and leaves the identifier to the administrators |
| O5 | Whether `environment.device` describes the agent's host or the user's device (ABAC-6) |
| O6 | A clearance order with compartments, a partial order, needs a revision of ABAC-11 |
| O7 | The numeric bounds of section 8 are proposed defaults, unmeasured. The 300 second bound for device compliance rests on an assumed management-service interval |
| O8 | Whether a decision older than some bound at release must be taken again, which would close the decision-to-release window for F1 to F3, F5, and F6 (section 9) |
| O9 | A named maintainer, the registry entry for this profile (kind `integration`, id `abac`, version `0.1`, mapping revision `pact-abac-1`), and the row of the index in the profiles README are not added by this change. The `fixtures` array of `profile.json` lists the adapter cases of section 10 |
| O10 | The parameter conventions of the three obligation types (the allow-list `keep`, the redaction marker, the watermark means) and the outcome row of ABAC-30 are this profile's definitions, because the draft defines none. The owner confirms them |
