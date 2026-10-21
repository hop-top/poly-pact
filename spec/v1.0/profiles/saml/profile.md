# PACT integration profile: SAML service provider session to agent broker

This profile targets spec version 1.0 and wire version 0.1 and is a draft. It is work in progress: some negative cases of section 10 have case files and others are planned, so the profile must not be cited as support for an enforced claim until every case exists and passes (see "Completeness" in [`TEMPLATE.md`](../TEMPLATE.md)).

## Profile header

| Field | Value |
|---|---|
| Profile name | SAML SP session to agent broker |
| Target product and version | A SAML 2.0 service provider with an application task broker, using the SAML 2.0 Web Browser SSO profile and, where it supports logout, the Single Logout profile, both through the SP's own SAML implementation. SAML Core and SAML Profiles, OASIS Standards of 15 March 2005 (Annex D). No product is named; a deployment that claims this profile names its SP product and exact version (open item OI-9) |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `2`, 2026-10-18: SB-11 renumbered, SB-16 refuses a grant for another agent, OI-2 codes fixed, `native-principal-binding-v1` removed from the adapter's checks; condition 5 of SB-11 compares the grantee with the binding `check_context` receives |
| Maintainer | PACT adapter profile maintainers |
| Reference documents | draft = [`draft.md`](../../draft.md); handoff = `docs/handoff.md` (source repository only); identity mapping = [`identity-mapping.md`](../identity-mapping.md); freshness = [`freshness.md`](../freshness.md); informative example = [`example_I05.md`](../../examples/example_I05.md); SAML Core and SAML Profiles (Annex D) |

## Scope and boundary

The profile covers one arrangement, the one of [`example_I05.md`](../../examples/example_I05.md). A SAML 2.0 service provider (SP) signs its users in through its own SAML implementation and keeps its own session for each user. An application task broker in the SP performs delegated tasks for an enrolled agent inside that user's session, on the SP's own resources. The adapter consumes two native records, an `SPSession` and a `TaskGrant` (Annex A). It consumes no SAML message.

The profile specifies the work items that finding G14 of `docs/handoff.md` asks for: SP-session task authorization, agent enrollment, broker authority, expiry and logout, and the supported workflows, while the actual SAML validation is retained by the SP. It does not close G14. Closure needs executed negative cases (Annex C), which are separate work.

**Boundary.** SAML assertion processing stays in the SP's SAML implementation. The table lists the checks that implementation makes, with the source text of each, to say what the adapter does not do. This profile adds no requirement to these checks and restates none of them; it assumes them. A deployment whose SAML implementation does not make them cannot claim this profile.

| Check made by the SP's SAML implementation | Where SAML states it | What the adapter sees |
|---|---|---|
| The issuer is a configured trusted identity provider, and its keys verify the signatures | SAML Profiles §4.1.4.2 (the `Issuer` carries the identity provider's identifier); §4.1.6 (metadata MAY document signing keys). The trust configuration itself is local to the SP | Nothing |
| Signatures on the `Response` and the assertion | SAML Profiles §4.1.4.3 (verify any signatures present); §4.1.4.5 (with the POST binding the assertions MUST be signed) | Nothing |
| Audience | SAML Profiles §4.1.4.2 (a bearer assertion MUST carry an `AudienceRestriction` naming the SP); SAML Core §2.5.1.4 (valid if and only if the relying party is in the audiences) | Nothing |
| Recipient | SAML Profiles §4.1.4.3 | Nothing |
| Validity window | SAML Profiles §4.1.4.3 (`NotOnOrAfter` of the bearer confirmation, with allowable clock skew); SAML Core §2.5.1.1 (an assertion with invalid or indeterminate conditions MUST be rejected) | Nothing |
| `InResponseTo` | SAML Profiles §4.1.4.3 (equals the ID of the original `AuthnRequest`, unless the response is unsolicited); §4.1.5 (an unsolicited response MUST NOT carry it) | Nothing |
| Replay | SAML Profiles §4.1.4.5 (keep the set of used assertion IDs for the `NotOnOrAfter` window) | Nothing |
| Authentication and application of logout messages | SAML Core §3.7.3.1 (the session participant MUST authenticate the message and invalidate the sessions it names, also when a matching assertion arrives later); SAML Profiles §4.4.4.1 | `logged_out` of the `SPSession` |
| Mapping of the accepted assertion to a principal | SAML Core §8.3 (name identifier formats) and identity-mapping §3.3 | `principal` of the `SPSession` |

An assertion that the SAML implementation rejects leaves no `SPSession` and so no principal, and it yields no `OutcomeReport` (draft §14.5, pre-authentication failure). The JSON signatures of PACT do not replace XML signature processing.

**Dependency on the delegation binding model.** The final semantics of `/attributes/delegation/authority_ref` wait for the delegation binding model of finding G03. SB-12 fixes only what it states, and open item OI-1 records the rest.

## 1. Claim scope

The adapter runs in the SP's portal request path (draft §4.4, in-gateway form) and claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over the `header` presentation transport. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1. The roles it does not claim are supplied by the enrolled agent's holder software and by connected services of the deployment, as in the template's mini-example. Whether a deployment that omits Reputation or Learning should instead declare `single-owner` is open (OI-8), because that profile's document has not landed.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway: the PACT validator runs in the SP's protected request path |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Holder 0.1`, `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced`. The paths outside the claim (section 5) are not conditioned on PACT admission |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` |
|---|---|---|
| `saml` | `2.0` | `pact-saml-1` |

The mapping revision `pact-saml-1` covers the operation mapping of section 2 (the baseline HTTP mapping of draft §10.2) and the principal mapping of SB-4.

## 2. Protected routes and actions

The claim covers two route classes of the broker's agent-facing API. Both are reads on the SP's own resources. A deployment publishes its concrete route patterns in its gateway metadata, and each one is an instance of a class below; a route that is not an instance is not claimed. Operations with side effects are not claimed (SB-20).

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/broker/v1/tasks/{task_id}/records/{record_id}` | `GET` | `record.read` | `record:{record_id}`, from the path parameter. `task_id` from the path is the `Intent.task_id` that SB-11 checks against the grant. The principal is the session principal (SB-16), never a request parameter |
| R2 | `/broker/v1/tasks/{task_id}/records` | `GET` | `record.list` | `record-collection`, the collection the session principal's native authority covers. Query parameters, such as a filter and a page token, are part of the bound operation (draft §10.2) |

## 3. Enforcement points

The five required functions run in request order inside the SP's request path. No SAML message is processed in this path: SAML processing happened earlier, when the session was created (SB-1).

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Broker request stage, before routing to the resource layer | Broker owner | Verifies the agent's own broker credential (SB-15), resolves the grant named by the request's task reference, checks that the grant's `agent_id` holds an enrollment in force on the agent's workload (SB-16), reads the grant's `SPSession` live, and returns the session principal with the agent's workload. No live session, or a grant for another agent: native denial |
| 2 | `map_operation` | Broker mapping stage, mapping revision `pact-saml-1` | Adapter owner | Baseline HTTP mapping (draft §10.2) for R1 and R2; `principal_id` is the session principal |
| 3 | PACT evaluation | In-gateway validator in the same request path | Gateway implementer | Runs after mapping and before native authorization; installed checks are listed in the `check_context` row |
| 4 | `authorize_native` | The SP's existing access policy for the requested records | Resource owner | Invoked with the session principal and the actual operation, never with the broker's identity (draft §17.5). A native denial is final (draft §2.3) |
| 5 | Execution | The broker performs the read in the SP's resource layer under the user's session and the recorded grant | Broker owner | Executor class `delegated-user` (SB-19). Session and grant are read again immediately before it starts (SB-11) |
| support | `resolve_agent_binding` | Enrollment registry lookup by the realm, the agent's broker workload, and the agent ID that the presentation names | IAM and security owner | Supplies the enrolled agent ID, operator and holder key; independent of the SAML sign-in (SB-14). The workload alone never names an agent, and a workload with more than one enrollment in force is a configuration error (section 7) |
| support | `read_native_claim` | Live read of the `SPSession` record for the approved paths `/attributes/environment/principal_id` and `/attributes/environment/idp_realm`; a directory adapter for membership facts when a contract requires them (SB-22) | Adapter owner | Returns value, observation time, status time and source ID (SB-23) |
| support | `check_context` | Installed checks `native-delegation-v1` and `execution-identity-v1`, with the mandatory protocol checks | Gateway implementer | `native-delegation-v1` evaluates the grant (SB-11) on the authenticated principal and the agent's binding it receives (draft §17.1); `execution-identity-v1` follows draft §17.5. `native-principal-binding-v1` is not a `check_context` check: the validator evaluates it from inputs it already holds (draft §17.5), in row 3 of this table |
| support | `record_outcome` | Broker outcome writer, after execution | Resource owner | Reports `ADMISSION`, `AUTHORIZATION` and `EXECUTION` observations, each referencing an immutable native record of the actual executor identity (draft §14.2, §14.5). A rejected assertion yields no report |

## 4. Native dependencies

Twelve of the sixteen components are used and four carry the reason they are not. Listing a component does not assert that it has been built; the broker and its stores are assumed by the example and not every SP has them.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator in the SP's request path | Gateway implementer | To be supplied |
| C02 | Native authentication and claim adapters | baseline | The SP's SAML implementation and session store; the broker's agent authentication; the adapter's claim and check functions | SP and IAM owners, adapter owner | SAML implementation and session store assumed to exist; broker authentication and adapter functions to be supplied |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry (identity-mapping §4), administrator-run enrollment | IAM and security owner | A reference registry exists (Annex F); a production store is to be supplied |
| C04 | Native delegation and task authority | delegated or task execution | The task broker and its `TaskGrant` store | Application and IAM owner | Assumed by the example and to be supplied by the SP; final `authority_ref` semantics wait for G03 (OI-1) |
| C05 | Evidence and authoritative status sources | baseline | `SPSession` store, `TaskGrant` store, enrollment registry, hold store; membership from a directory adapter under its own profile | SP, IAM and adapter owners | Stores to be supplied; the directory adapter profile has not landed (OI-7) |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: no approval workflow is part of this profile. Reauthentication or approval the environment requires is handled by its own workflow, after which the agent obtains a fresh contract and presentation |
| C07 | Purpose and exact operation mapper | baseline | Broker mapper at revision `pact-saml-1` | Adapter owner | To be supplied |
| C08 | Native resource executor and authorization | the actual resource operation | The SP's resource layer and access policy | Resource owner | Exists (assumed): the SP's own |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store | Gateway and platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Broker task record (the `task_attribution_source`) and the SP audit log of executor identity | Resource and evidence owner | To be supplied |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed here |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | To be supplied as a registry only; no adaptation lifecycle is claimed |
| C13 | Revocation and security holds | baseline | Hold store and enrollment status | Security and IAM owner | To be supplied |
| C14 | Protected evidence and audit storage | baseline | Access-controlled evidence and audit store | Security and data owner | To be supplied. Records that hold a principal identifier carry the controls of SAML Core §8.3.7 (SB-3) |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: only reads are claimed (SB-20) |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no runtime or data-use guarantee is claimed. A required runtime fact is attested-only (draft §17.4) and post-read limits are in section 9 |

## 5. Alternative and bypass paths

Six other ways to reach the SP's resources or its sessions are listed: two `closed`, and four `out-of-claim`. No path is `equivalently-enforced`, because the user's own browser access does not go through the broker.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Grant creation and management routes of the portal, reached with an agent credential and no user session | `closed` | These routes accept only a live `SPSession` as authentication and reject an agent credential (SB-8); planned case SAML-10 |
| B2 | Broker routes and methods outside R1 and R2, including every operation with side effects, reached with a valid agent credential, an enrolled agent and a live grant | `closed` | The broker's agent-facing route table serves only R1 and R2 (SB-20); planned case SAML-11 |
| B3 | The same portal resources reached directly by the user's own browser session, with no agent involved | `out-of-claim` | Native user access under native authorization; not an agent request path; excluded in section 6 (the user's own access, row U3) |
| B4 | An agent using a copy of the user's session credential or of a SAML assertion against portal routes | `out-of-claim` | SB-3 forbids the SP to hand either to the agent, but a user-side copy cannot be controlled; excluded in section 6 (row U3) |
| B5 | SAML sign-in (assertion consumer) and single logout endpoints of the SP | `out-of-claim` | Assertion validation stays in the SP's SAML implementation (SB-1). What the adapter does with the resulting sessions is covered by the cases SAML-01, SAML-02, SAML-04 and SAML-05 |
| B6 | Native administrative paths that create, change or revoke enrollments, grants or sessions | `out-of-claim` | Governed by the environment's own administrative controls (draft §4.2, identity-mapping §4.2); not an agent request path |

## 6. Unsupported forms

The first two rows are seeded from the I05 row of the handoff "Deliberate design choices" table. The others come from the example, from the sections above, and from the SAML texts.

| ID | Unsupported form | Seed (handoff source row) | Why it is not established |
|---|---|---|---|
| U1 | Universal unattended SAML agent login | I05: "Universal unattended SAML agent login or delegation supplied by SAML itself" | A request with no live `SPSession` has no principal (SB-16, case SAML-09). Browser SSO is the flow in which the principal reaches the SP through a user agent, and the scenario assumes a standard commercial browser (SAML Profiles §4.1, §4.1.2 step 1). The Enhanced Client or Proxy profile (SAML Profiles §4.2) and any other SAML profile or binding used by an agent as a SAML party are not claimed |
| U2 | Delegation supplied by SAML itself | I05: "Universal unattended SAML agent login or delegation supplied by SAML itself" | The only delegation this profile reads is the `TaskGrant`, created by a portal action (SB-8). No delegation, proxying or act-as meaning is read from any SAML message or extension |
| U3 | Assertion export to the agent, export of the SP session credential to the agent, and the user's own direct access | Example I05, Assumptions: "without exporting assertions as general agent credentials" | The SP hands the agent neither (SB-3). The asserting party makes no representation to a relying party outside the assertion's audience (SAML Core §2.5.1.4), and an assertion with `OneTimeUse` MUST NOT be retained for future use (SAML Core §2.5.1.5). A copy that a user makes is outside the claim (B4), as is the user's own access (B3) |
| U4 | IdP-initiated agent sessions | Section 5, B5 | An unsolicited `Response` (SAML Profiles §4.1.5) can at most establish the user's SP session, if the SP accepts such responses. It never creates a grant and never starts an agent task: a grant exists only through a portal action in a live session (SB-8). Whether such sessions are excluded altogether is open (OI-6) |
| U5 | Agents that share one broker credential | Section 7 | Each agent has its own broker credential, the default of identity-mapping §5 (SB-15, IM-19); a workload with more than one enrollment in force is a configuration error (section 7) |
| U6 | Operations with side effects, and every route other than R1 and R2 | Section 2 | Transactions, budgets and idempotency need C15, which is not used (draft §10.3). A route not listed in section 2 is not claimed |
| U7 | Membership, role and account-state facts taken from the assertion, the `SPSession` or `authn_instant` | Example I05, Required profile and evidence: "the configured native source must establish the demanded freshness" | Such facts come only from a directory adapter with its own observation time (SB-22). No directory adapter profile has landed (OI-7) |
| U8 | A requirement on how recently the user authenticated | Section 8 | `authn_instant` is not a freshness time (SB-7). A deployment that needs authentication recency installs a named check; none is defined here (OI-10) |
| U9 | An SP that has no task broker | Example I05, Deliberate simplifications: "An application task broker is assumed; not every SP provides one" | There is no `TaskGrant` and no authenticated portal action to create one |
| U10 | The final semantics of `authority_ref` | Section 1 | They wait for the delegation binding model of G03 (OI-1) |

## 7. Identity mapping

Agent enrollment is separate from the user's session. The user is identified by the `saml` namespace of identity-mapping §3.3, and the agent is identified by its enrollment record on the agent's own broker workload, selected by the agent ID that the presentation names (SB-14, SB-15). All other rules are deferred to [`identity-mapping.md`](../identity-mapping.md).

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | User: `saml:{sp-id}:{idp-entity-id}:{subject}` (SB-4), for example `saml:https%3A%2F%2Fsp.example%2Fmetadata:https%3A%2F%2Fidp.example%2Fsaml:8f3e1c5a2b`. Client: the SAML relying party is the SP, carried as `sp-id`. Workload: the agent's own broker credential, written in the namespace of the mechanism that authenticates it (identity-mapping §3.3) or in an `x-` namespace the deployment defines; never in the `saml` namespace and never derived from an `SPSession` (SB-15) |
| Trusted enrollment actors | Both kinds of identity-mapping §4.2: the native administrative workflow, and an authorized identity-binding issuer configured for the realm. The user is not one: a portal action creates a `TaskGrant` for an already enrolled agent and nothing more (SB-8, SB-14) |
| Shared-account handling | Not supported, the default of identity-mapping §5 (section 6, U5; IM-19). Each agent has its own broker credential (SB-15), and no reason for supporting shared credentials is stated. A workload with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states |
| Certificate, token, or role-session bindings | None. Neither the SAML assertion, nor the `SPSession`, nor the `TaskGrant` is bound to the holder key (IM-21); the holder key is bound only by enrollment. The grant names an `agent_id`, not a key |
| Lifecycle rules (rotation, compromise, recovery) | Deferred to identity-mapping §7. Rotation keeps the `agent_id`, so existing grants stay usable; revocation or a compromise mark makes every grant of that agent unusable at the next evaluation, because the binding status is read each time (section 8, F3). A recovered agent is enrolled under a new `agent_id` (IM-28) and needs new grants |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule. Narrowings: the `saml` `subject` is a persistent NameID value or a local account identifier, with the local account preferred, and a NameID whose `NameQualifier` names another entity than the configured issuer is not mapped (SB-4, OI-3); shared accounts are unsupported (IM-19 allows supporting them only with a stated reason) |

## 8. Freshness

Four sources are listed with `max_age` and `status_max_age` in seconds, and every outage ends in `DEFERRED`, which fails closed (draft §18). The sources are read live, so each bound is zero; following freshness §4.2, the best `max_age` of an authoritative source is its best status bound. A deployment whose stores replicate or cache cannot claim these bounds: it declares its replication lag and cache time as the bounds of that source, and a requirement below them is `UNSUPPORTED_REQUIREMENT` (freshness §4.2, convention 2).

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 SP session store (`SPSession` lookup) | Current authoritative state of the session record, read live for each evaluation and again before execution. The observation and status times of the two session claims (SB-23) are the instant of that read | 0 | 0 | `DEFERRED` |
| F2 Task grant store (`TaskGrant` lookup) | Current authoritative state of the grant, read live in the same way; revocation and expiry are visible at the next read | 0 | 0 | `DEFERRED` |
| F3 Enrollment registry (agent and key binding status) | Current authoritative state, read for each evaluation. The observation time is the last change to the record and the status time is the read (identity-mapping IM-10). No field rule applies a `max_age` to the binding; its status gates admission (IM §7.5) | 0 | 0 | `DEFERRED` |
| F4 Security hold store | Current authoritative state, read for each evaluation (gateway baseline, C13) | 0 | 0 | `DEFERRED` |

**Departure from freshness §4.1, session row.** That row names the assertion's issue time as the observation time of session attributes. The `SPSession` carries `authn_instant`, the time the identity provider gives for the authentication event (SAML Core §2.7.2), and no issue time. This profile does not use `authn_instant` as an observation time of any fact (SB-7). It treats `principal_id` and `idp_realm` as properties of the SP's own session record that the session store answers from its current state (SB-23). The identity provider is not asked again, so a change at the identity provider reaches the SP only through logout propagation or re-authentication (section 9).

**Membership facts.** The adapter reads no membership, role or account-state fact itself. When a contract requires one, it comes from a directory adapter: a configured native source with its own observation time and status time (SB-22). That adapter's own integration profile declares the source, its bounds and its outage behavior, so this table has no row for it. Until such a profile is cited, a contract that requires such a fact cannot be claimed as enforced under this profile (OI-7). The directory is a source of class "directory, replicated" in freshness §4.1: its observation time is the replication watermark, or the read time minus the declared lag, and never the read time of a replica, and never `authn_instant`.

### 8.1 Membership and status sources

The `SPSession` store supplies the `identity` fact, the authenticated principal. The `TaskGrant` store and the enrollment registry supply no membership, role or account-state fact. No other source of this profile supplies one (SB-22).

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 SP session store (`SPSession` lookup) | `identity` | `true` | Local lookup of the SP's session record, on the authoritative copy | `none` | Not applicable: no change feed. A logout or expiry is applied to the store directly and is seen at the next read | 0 | `authoritative_current` |

## 9. Residual limits

The profile states what remains true after a successful admission and how each end of authority reaches the adapter.

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Data already returned to the agent is not recalled by a later logout, expiry, or revocation of a grant, and an executed operation is not undone by revoking its receipt (draft §18). No egress, output or data-use control is claimed (C16 is not used). A runtime fact a contract requires, such as isolation, is attested-only (draft §17.4) | Disclosed here; no bound |
| Revocation propagation: SP session | A logout, a termination by the SP, and expiry are seen at the next read of the session record, and every grant of that session is then unusable (SB-10, SB-11) | Zero within the SP's consistency domain (F1, F2) |
| Revocation propagation: identity provider | A session that ends at the identity provider reaches this profile only as a logout request at the SP or as a new authentication by the user; otherwise the SP session continues until its own end. The session authority SHOULD send logout requests to the participants (SAML Core §3.7.3.2), and a participant it cannot reach leaves the session in place there (the `PartialLogout` status, SAML Core §3.7.3.2). This profile uses no other mechanism; the authentication query of SAML Core §3.3.2.2 asks for statements about past authentication acts and is neither used nor assessed here | Bounded by `expires_at` of the session (SB-5) and by the grant's `expires_at`; not otherwise |
| Revocation propagation: grants and enrollment | A grant revoked by the user, or a binding revoked or marked compromised, prevents later admissions in the gateway's consistency domain (draft §18). The binding is read for each evaluation (identity-mapping §7.5) | Zero within each store's own consistency (F2, F3) |
| In-flight operations | A read that has begun when the session ends is not cancelled by this profile. Session and grant are read immediately before execution starts (SB-11); after that the operation follows the broker's native cancellation semantics (draft §18). The broker documents them in its claim | Disclosed here; the broker states the bound for its reads |
| Name reuse | The SAML texts read do not say whether an identity provider may issue a persistent NameID value again to another subject after deleting one (SAML Core §8.3.7), so a reused value could map to an existing principal (identity-mapping IM-6) | Disclosed here; open (OI-4) |
| Forged portal action | A browser can be induced to make the portal action that creates a grant without the user's intent. The SP applies its own request-forgery defences; this profile does not specify them | Disclosed here; no bound |
| Re-stamp detection on session claims | The two session claims carry no `SourceRef`, so the monotonic guard of freshness §7 does not compare them: the integration rests on the gateway's own clock (SB-23) | Disclosed here |

## 10. Fixture index

Seventeen negative cases are listed. The first nine map the G14 closure evidence and the readiness items of example I05 (Annex C); `SAML-17` shows, in the identifier grammar of this profile, the `authenticate_native` properties of the common cases that this adapter replaces. Each expected result is derived from the draft, from identity-mapping and from freshness, not from an implementation. The landed cases are adapter cases of this profile and live in `spec/v1.0/fixtures/adapters/saml/`, each file named after its case id in lower case, such as `saml-04.expired.json`, with the manifest id `adapters/saml/saml-04.expired`; the [cases README](../../fixtures/adapters/saml/README.md) defines their native state, in which a fake SP stands in for the SP's SAML implementation and turns the assertions of a case into sessions. The `fixtures` array lists every landed case file.

### Landed

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `SAML-01` | An assertion addressed to a different SP reaches the SP's SAML implementation, and a request then names a task whose session was never created | No `SPSession`, no principal; native authentication denied with `INVALID_PROOF`; no `OutcomeReport` (draft §13.4, §14.5) | `adapters/saml/saml-01.wrong-audience` (native denial, `CREDENTIAL_REJECTED`). That a pre-authentication failure yields no report is a gateway property (draft §14.5) and has no adapter case | R1, R2, B5 |
| `SAML-02` | An assertion ID that was already consumed is presented again | No second `SPSession`; the first `SPSession` and its grants are unchanged | `adapters/saml/saml-02.session-unchanged` (the first session's principal), `saml-02.replay-session` (a grant naming the session the replay would have created: denied), `saml-02.after-logout` (a replay after logout revives nothing: denied) | B5 |
| `SAML-03` | The presented profile names a principal other than the session's | `native-principal-binding-v1` `FAIL` with `CONTEXT_MISMATCH`; `INADMISSIBLE` (draft §17.5) | Adapter half: `adapters/saml/saml-03.identity-headers` and `saml-03.session-cookie` (headers, a query parameter and a copied session cookie naming another live session's principal: authenticated as the grant's session principal), `saml-03.grant-user-mismatch` (a grant whose user is not its session's principal: denied). Draft §17.5 makes `native-principal-binding-v1` a validator check that is not an input of `check_context`; the comparison is the validator's, and an adapter that names the principal the request claims fails every `SAML-03` case | R1, R2 |
| `SAML-04` | The `SPSession` is past `expires_at`, with the grant otherwise valid | Native authentication denied with `INVALID_PROOF`; nothing executes | `adapters/saml/saml-04.expired`, `saml-04.at-expiry` (no grace), with the control `saml-04.before-expiry`; `saml-04.delegation` (the grant of the expired session fails `native-delegation-v1` with `REVOKED_EVIDENCE`, SB-10, SB-11) | R1, R2, B5 |
| `SAML-05` | The `SPSession` is `logged_out` | Native authentication denied with `INVALID_PROOF`; every grant of the session is revoked and unusable; nothing executes | `adapters/saml/saml-05.logged-out`; `saml-05.delegation` (the grant fails `native-delegation-v1` with `REVOKED_EVIDENCE`, although the broker has not marked it revoked) | R1, R2, B5 |
| `SAML-06` | The `TaskGrant` is past its `expires_at`, with the session live | `native-delegation-v1` `FAIL` with `STALE_EVIDENCE` (draft §17.5; OI-2); `INADMISSIBLE` | `adapters/saml/saml-06.expired-grant`, `saml-06.at-expiry` (no grace) | R1, R2 |
| `SAML-07` | The grant is for a different task, or for a different agent, than the presentation's; the operation is outside the grant's scope; the task has no grant; the operation's principal is not the grant's user; the control: a usable grant | A different task: `native-delegation-v1` `FAIL` with `TASK_MISMATCH` (draft §17.5). A different agent: native authentication denied with `INVALID_PROOF` (SB-16); the validator never sees the request. The same grant evaluated by the check for another agent's binding: `FAIL` with `CONTEXT_MISMATCH` (SB-11, condition 5). Outside scope, or another principal: `FAIL` with `CONTEXT_MISMATCH`; no grant: `FAIL` with `MISSING_FIELD` (SB-11). A usable grant: `PASS` with `REQUIREMENT_SATISFIED` | `adapters/saml/saml-07.other-task`, `saml-07.other-agent` (the reviewer's own credential on the assistant's grant: `CREDENTIAL_REJECTED`), `saml-07.other-agent-check` (`check_context` with the reviewer's principal and binding on the assistant's grant: `FAIL` `CONTEXT_MISMATCH`), `saml-07.grantee-revoked` (the grant's agent revoked on the workload: `CREDENTIAL_REJECTED`), `saml-07.grantee-compromised` (authenticated: the hold is the validator's), `saml-07.outside-scope`, `saml-07.no-grant`, `saml-07.other-principal`, `saml-07.usable` | R1, R2, SB-11, SB-16 |
| `SAML-08` | The login time, or a later read time, is presented as the observation time of a membership fact | `INADMISSIBLE`: `RESTAMPED` when it contradicts an earlier sighting of the same source record, `STALE_EVIDENCE` when older than its `max_age_seconds` (freshness §3.2, §7) | `adapters/saml/saml-08.directory-times` (the directory's own times pass through `read_native_claim`), `saml-08.read-time` (`RESTAMPED`), `saml-08.login-time` (`STALE_EVIDENCE`) | R1, R2, SB-22 |
| `SAML-09` | A valid agent credential and an enrolled agent, with no live `SPSession` ever created | No principal; native authentication denied with `INVALID_PROOF` | `adapters/saml/saml-09.no-session`, `saml-09.no-task-route` (a route that names no task) | R1, R2, U1 |
| `SAML-17` | The agent's own credential through the enforcement point and directly; no credential and a forged one; the same subject from two identity providers; another user's grant | Authenticated as the grant's session principal with the agent's workload through the enforcement point; a direct request `CREDENTIAL_REJECTED`; `NO_CREDENTIAL` and `CREDENTIAL_REJECTED` without the token in the denial; the identity provider and the user of the grant's session kept (SB-4, SB-15, SB-16) | `adapters/saml/saml-17.via-enforcement-point`, `saml-17.direct`, `saml-17.no-credential`, `saml-17.forged-token`, `saml-17.idp-realm`, `saml-17.other-user` | R1, R2 |

### Planned

The identifiers below are reserved names; no file exists for any of them.

| Fixture ID | Negative case (input) | Expected result | Covers |
|---|---|---|---|
| `SAML-10` | An agent credential on a grant creation route | Refused; no grant is created | B1 |
| `SAML-11` | A valid agent credential, enrollment and grant, on a method or route outside R1 and R2 | Not served; no execution and no resource data | B2 |
| `SAML-12` | A grant creation in a live session that names an agent that is not enrolled, or is `REVOKED` or `COMPROMISED` | Refused; no grant is created | SB-8, SB-14 |
| `SAML-13` | A valid session and grant, and the agent's binding is `REVOKED` | `INADMISSIBLE` with `INVALID_PROOF`; for `COMPROMISED`, `SECURITY_HOLD` (identity-mapping §8) | R1, R2, F3 |
| `SAML-14` | The broker would execute under a broader portal credential | `execution-identity-v1` `FAIL` with `EXECUTOR_MISMATCH` (draft §17.5) | R1, R2 |
| `SAML-15` | A valid PACT admission, and the SP's access policy denies the user the record | No execution (draft §22.2) | R1, R2 |
| `SAML-16` | Two enrollment records, for agents A and B, on one broker workload: (a) the enrollment that would add the second record; (b) both records present, a live session and grant, and a presentation by A signed with A's key, and one by B signed with B's key | (a) Refused; (b) neither record is selected, for either agent: the configuration error of identity-mapping §5 (IM-19) | R1, R2, SB-15, section 7 |

### Replaced common cases

The common cases of the adapter conformance suite run against this adapter. A common request names no task, so it reaches no grant and no session; seven `authenticate_native` cases that expect a principal are replaced ([adapters README](../../fixtures/adapters/README.md), "Replaced common cases"; draft §22.2). The others pass, with the deployment-supplied sources that their native state describes.

| Common case | Why this adapter cannot realize it | Replacement |
|---|---|---|
| `COMMON-01.credential-wins` | Expects `https://idp.acme.example/bob` from a bearer credential; the principal is the session principal of the task's grant (SB-16) | `SAML-03.identity-headers`: identity headers and a query parameter naming another live session's principal; authenticated as the grant's session principal |
| `COMMON-02.via-enforcement-point` | Expects `https://idp.acme.example/alice` | `SAML-17.via-enforcement-point`: the agent's own credential and a live grant through the enforcement point; the session principal, the agent's workload, mechanism `broker-token` |
| `COMMON-09.authenticate-realm` | Expects a `globex` principal id | `SAML-17.idp-realm`: the same subject value from two identity providers; the principal keeps the identity provider of the grant's session (SB-4, IM-4) |
| `IDENT-01.authenticate` | Expects a `basic:` account identifier | `SAML-17.other-user`: a task of another user's session authenticates as that user |
| `IDENT-02.authenticate` | Expects an `oauth:` identifier of another tenant | `SAML-17.idp-realm`: the issuing authority is the `idp-entity-id` component |
| `IDENT-03.authenticate` | Splits user and OAuth client | `SAML-17.via-enforcement-point`: the principal is the session user and the workload is the agent's own broker credential, two identifiers of two namespaces (SB-4, SB-15); a grant is served only to its grantee (SB-16, `SAML-07.other-agent`) |
| `IDENT-05.authenticate` | Expects a `basic:` account identifier; an `SPSession` carries no display name | `SAML-17.other-user` |

## Annex A. Native records and actors

### A.1 `SPSession`

The SP's own record of one signed-in user session. The SP creates it after its SAML implementation accepted the assertion that established the session (SB-2). The adapter reads it live and never writes it.

| Field | Meaning | Rules |
|---|---|---|
| `session_id` | The SP's internal identifier of the session record, and the key of the grants made in it. It is not the credential the browser presents, not the assertion ID, and not the SAML `SessionIndex` (identity-mapping §3.3). If the SP's only session identifier is the browser credential, it keys the record by a separate value | SB-3, SB-6 |
| `principal` | The user, in the `saml` namespace of identity-mapping §3.3 | SB-4 |
| `idp_realm` | The configured identifier of the identity provider that authenticated the session. It equals, octet for octet, the `idp-entity-id` component of `principal` before percent-encoding (OI-4) | SB-4, SB-23 |
| `authn_instant` | The `AuthnInstant` of the authentication statement: the time the authentication took place (SAML Core §2.7.2, required attribute). Carried as Unix seconds in the adapter | SB-7 |
| `expires_at` | The end of the session as the SP enforces it | SB-5 |
| `logged_out` | Whether the SP ended the session by logout or termination | SB-6 |

### A.2 `TaskGrant`

The broker's record that a user authorized one enrolled agent to perform one task in one session. It is a native delegation: PACT records and checks it and never creates it (draft §17.5).

| Field | Meaning | Rules |
|---|---|---|
| `user` | The principal of the session in which the grant was made, in the same form as `SPSession.principal` | SB-8 |
| `agent_id` | The enrolled `agent_id` (draft §6.1) the user authorized | SB-8, SB-11, SB-14 |
| `task_id` | Assigned by the broker at creation; it is the `Intent.task_id` of every operation under the grant (draft §10.1) | SB-8, SB-11 |
| `scope` | The permitted purpose, actions and resources, written in the installed mapping's terms. An upper bound, intersected with the user's own native authority: the permitted `purpose_id` values, actions and resources. A grant that records no `scope` permits every purpose, action and resource of the mapping | SB-11, SB-13 |
| `expires_at` | The end of the grant | SB-8, SB-9 |
| `revoked` | Whether the grant was revoked by the user or by the end of its session | SB-9, SB-10 |
| `session_id` | The session in which the grant was made. It is not among the fields of the task text and is added here, because ending a session must revoke the grants of that session (OI-5) | SB-8, SB-10 |

### A.3 Actors and transitions

This table applies draft §17.5 to this profile. It adds no field. Every transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment registry, independent of the SAML sign-in (draft §6.1, §6.2; SB-14) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1`, evaluated by the validator (draft §17.5) | `authenticate_native`: the principal of the live session recorded in the grant the request names (SB-16). `/attributes/environment/idp_realm` equals the session's configured identity provider |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the broker's grant store, which records the task, user, agent and expiry |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | The `TaskGrant` (SB-11, SB-12) |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (draft §4.2): the PACT component in the SP's protected request path |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | The broker, performing the read under the user's session and the grant (SB-19). The SAML assertion is never exported |

### A.4 Lifecycle

| Event | Effect on the `SPSession` | Effect on grants | Effect on a request |
|---|---|---|---|
| Sign-in accepted by the SP's SAML implementation | A new record with a new `session_id` | None | None: no grant exists yet |
| Authenticated portal action creating a grant (SB-8) | Unchanged | A new grant with the session's `session_id` | A request by the grant's agent that names it can be evaluated; a request by another agent is denied (SB-16) |
| Agent enrollment, rotation, revocation or compromise mark | Unchanged | Unchanged | Binding status is read at each evaluation; a revoked or compromised binding is not admitted |
| User revokes a grant | Unchanged | `revoked` becomes true | The grant is unusable (REVOKED) |
| Grant `expires_at` reached | Unchanged | The grant is unusable (stale) | Refused at evaluation |
| SP logout, an applied logout request, or termination | `logged_out` becomes true | Every grant of the session is revoked (SB-10) | No live session: native authentication denied |
| Session `expires_at` reached | Not live | Every grant of the session is unusable | No live session: native authentication denied |
| Replayed or foreign assertion | No new record; the first is unchanged | Unchanged | None |

## Annex B. Rules

The rules carry the identifiers SB-1 to SB-23 so that profiles, fixtures and reviews can cite them. The uppercase requirement words have the meanings given in draft §3. The rules are normative for a deployment that claims this profile. They cite SAML only for the facts of Annex D; where Annex D says a fact is not established, the rule does not rely on it.

### B.1 Boundary

**SB-1. SAML stays in the SP.** The SP's SAML implementation alone decides whether an assertion establishes a session. The adapter does not parse, verify, store, cache or forward a SAML message, an assertion, a signature, a `NameID` or a `SessionIndex`, and it applies no SAML processing rule. No SAML message is processed on the path of an agent request.

**SB-2. One way, after acceptance.** An `SPSession` exists only after the SP's SAML implementation accepted the assertion that established it. An assertion that implementation rejects, replays or never receives leaves no `SPSession`, so no principal exists for the adapter. A replayed assertion creates no second `SPSession` and changes neither the first nor its grants.

**SB-3. SAML material stays in the SP.** No assertion, `SessionIndex`, name identifier other than the mapped `subject`, or SP session credential appears in a profile, evidence artifact, contract, presentation, receipt, outcome report, message to the agent, or log the agent can read. The SP does not hand the agent an assertion or a session credential (SAML Core §2.5.1.4, §2.5.1.5; SAML Profiles §4.1.3.6). The principal identifier carries the `subject`, which can be a persistent identifier; such an identifier MUST NOT appear in log files or similar locations without appropriate controls (SAML Core §8.3.7), so every record that holds a principal identifier carries those controls (C14). The `session_id` is not the browser credential (A.1).

### B.2 The `SPSession`

**SB-4. Principal.** `SPSession.principal` is `saml:{sp-id}:{idp-entity-id}:{subject}` in the grammar of identity-mapping §3, with each component percent-encoded as IM-2 says.

- `sp-id` is the entity ID of the SP and `idp-entity-id` is the entity ID of the identity provider whose assertion the SP accepted, each exactly as configured (SAML Core §8.3.6 defines the entity identifier form; SAML Profiles §4.1.4.2 puts the identity provider's identifier in `Issuer`).
- `subject` is either the value of a persistent `NameID` (format `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, SAML Core §8.3.7) or the immutable identifier of the local account the SP mapped the assertion to. A deployment prefers the local account identifier, because a persistent identifier is sensitive (SB-3).
- `subject` is never a transient `NameID` (an opaque, temporary value, SAML Core §8.3.8), an e-mail-format `NameID` (SAML Core §8.3.2), an attribute value, the assertion ID or the `SessionIndex` (identity-mapping §3.3, IM-5). A `NameID` of unspecified format (SAML Core §8.3.1, interpretation left to implementations) is a `subject` only through the local account it is mapped to.
- A persistent `NameID` whose `NameQualifier` is present and names an entity other than the configured issuer is not mapped to a principal (SAML Core §8.3.7 lets the qualifier name the entity that created the identifier, which can differ from the entity that later issues it). This rule is provisional (OI-3).

**SB-5. Expiry.** `expires_at` is the earlier of the end of the SP's own session policy and the `SessionNotOnOrAfter` of the authentication statement when it is present (SAML Core §2.7.2; SAML Profiles §4.1.4.3 says a security context SHOULD be discarded once that time is reached, unless the identity is established again by the profile; this rule makes that mandatory for the `SPSession`). `expires_at` is never later than `SessionNotOnOrAfter`. It is never taken from the `NotOnOrAfter` of the assertion's `Conditions` or of its bearer confirmation, which limit the validity and delivery of the assertion and have no required relationship to `SessionNotOnOrAfter` (SAML Core §2.7.2, §2.5.1.2; SAML Profiles §4.1.4.2). A session with no bound is not an `SPSession` of this profile. The comparison with the clock allows no grace (draft §7.5).

**SB-6. Logout and liveness.** `logged_out` becomes true when the SP ends the session by any of these: a logout by the user at the SP; a logout request that the SP's SAML implementation authenticated and applied (SAML Core §3.7.3.1: the participant MUST invalidate the sessions the request names, all of the principal's sessions when it names no `SessionIndex`, and the request applies also to a matching assertion that arrives later); a termination by an SP administrator. A logout at one SP alone, without the logout protocol, is outside what SAML specifies (SAML Profiles §4.4) and is a native act of the SP. `logged_out` never returns to false: a new sign-in creates a new `SPSession` with a new `session_id`. An `SPSession` is live when `logged_out` is false and the current time is before `expires_at`. Any other state, including a record that cannot be read, is not live.

**SB-7. `authn_instant`.** `authn_instant` records one past event, the authentication at the identity provider. It is not the observation time of any fact in PACT, it is not a status check time, it does not bound `expires_at`, and it satisfies no freshness requirement. The time conditions of an assertion do not guarantee that its statements stay accurate through their validity (SAML Core §2.5.1.2).

### B.3 The `TaskGrant`

**SB-8. Creation.** A `TaskGrant` is created only by an authenticated portal action: a request that the SP's session mechanism authenticates as a live `SPSession` (SB-6), carrying an explicit act of that user. Then:

- `user` is that session's principal, and `session_id` is that session;
- `agent_id` MUST resolve to an enrollment that is `ACTIVE` in the realm at that moment, so the grant never names an agent that is unknown, revoked or compromised (SB-14);
- the broker assigns `task_id`, and the agent cannot choose or change it (draft §10.1, §14.3);
- `expires_at` is not later than the session's `expires_at` at creation.

Nothing else creates a grant: not an agent credential, not an assertion or any SAML message, not an identity provider-initiated message, not a profile, a discovery response, or a request header (draft §4.2, §6.1, §8.5). Creation on behalf of a user by another actor is not supported.

**SB-9. Fixed terms.** The `user`, `agent_id`, `task_id`, `scope`, `expires_at` and `session_id` of a grant never change. Widening the scope, extending the expiry or changing the agent is a new grant. The user MAY revoke a grant at any time by an authenticated portal action. `revoked` never returns to false. A later extension of the SP session does not extend any grant.

**SB-10. Session end revokes its grants.** When a session stops being live, whether `logged_out` became true or `expires_at` was reached, every grant recorded for that session is revoked. The broker sets `revoked` when it learns of the end. The adapter does not depend on that: SB-11 makes a grant unusable whenever its session is not live.

**SB-11. Usable grant.** A grant is usable for an operation only when all of these hold, read live (F1, F2):

| # | Condition | Failure result |
|---|---|---|
| 1 | The task names a grant | `FAIL` with `MISSING_FIELD` (draft §17.3.1, a required reference absent) |
| 2 | `revoked` is false, and the recorded session is live | `FAIL` with `REVOKED_EVIDENCE` |
| 3 | The current time is before the grant's `expires_at` | `FAIL` with `STALE_EVIDENCE` (OI-2) |
| 4 | `task_id` equals the `Intent.task_id` of the operation | `FAIL` with `TASK_MISMATCH` (draft §17.5) |
| 5 | The grant's `agent_id` equals the `agent_id` of the binding `check_context` receives (draft §17.1) | `FAIL` with `CONTEXT_MISMATCH` (identity-mapping §8: an agent enrolled for another workload) |
| 6 | The operation's `principal_id` equals the grant's `user`, which equals the session's principal | `FAIL` with `CONTEXT_MISMATCH` (draft §13.4, §17.5) |
| 7 | The intent's `purpose_id`, the operation's `action` and each of its `resources` are within `scope` | `FAIL` with `CONTEXT_MISMATCH` (draft §13.4: the actual operation differs) |

`native-delegation-v1` evaluates the table in this order at evaluation and returns `PASS` with `REQUIREMENT_SATISFIED` when every condition holds. SB-16 refuses at native authentication a request whose grant names another agent, so an evaluated operation is under a grant for the agent the presentation names; condition 5 verifies it again from the binding the validator established (draft §11.3 step 2), independently of the broker, and is never the only comparison. The broker evaluates conditions 2 and 3 again immediately before execution starts. If a store cannot answer, the result is `UNKNOWN` with `DEPENDENCY_UNAVAILABLE` (SB-18). Each `FAIL` makes the decision `INADMISSIBLE`.

**SB-12. `authority_ref`.** `/attributes/delegation/authority_ref` carries an opaque reference to exactly one `TaskGrant`. The reference is not a credential: no request is authorized by possessing it, and it only names the grant that SB-11 then evaluates. Its syntax, its binding to the principal, agent and task, who may learn it, and how `native-delegation-v1` resolves it are final only when the delegation binding model of G03 lands. Until then this profile fixes only what this rule states (OI-1).

**SB-13. A grant adds no native authority.** `authorize_native` runs with the session principal and the actual operation (draft §17.5), and a native denial is final (draft §2.3). The grant is not a role, group, ACL entry or token (draft §4.3). `scope` is an upper bound that is intersected with the user's own native authority and never widens it.

### B.4 Agent enrollment

**SB-14. Enrollment is separate from the session.** An agent's enrollment is created, rotated, revoked and marked compromised only by the trusted enrollment actors of identity-mapping §4.2. A SAML sign-in does not enroll an agent, authorize an agent, select an agent, or bind an agent to a user (IM-13, IM-16, identity-mapping §3.4). The user is not a trusted enrollment actor: a portal action creates a grant for an agent that is already enrolled (SB-8), and nothing more. The binding status is read at every evaluation (section 8, F3).

**SB-15. The agent's own credential.** The broker authenticates each agent request with a native credential of the agent's own. That credential is not a SAML assertion, not the user's session credential, and not derived from either. The enrollment record names the workload that this authentication produces (identity-mapping §4.1). Each agent has its own credential, so shared credentials are unsupported (IM-19), and a workload with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states. How the broker authenticates the agent is outside this profile; the deployment states the mechanism and writes the workload in the matching namespace of identity-mapping §3.3 or in an `x-` namespace.

### B.5 The request path

**SB-16. The principal comes only from the session.** For an agent request, the principal is the principal of the session recorded in the grant that the request's task reference names, read live (SB-6). The task reference is the `task_id` of the route (section 2); the broker looks the grant up in its own store. The request supplies that reference and nothing that selects an identity: a header, query parameter, body field, profile attribute or model output never supplies the principal or the session (identity-mapping IM-1; draft §8.5, §10.2). The grant's `user` MUST equal that session's principal; if it does not, authentication is denied. The grant's `agent_id` MUST hold an enrollment in force (identity-mapping IM-18: `ACTIVE` or `COMPROMISED`) on the workload that the agent's own credential produced, looked up by realm, workload and that `agent_id` (draft §17.1); if it does not, authentication is denied: the broker serves a grant only to the agent it names (draft §8.5, the native system decides whether the delegation authorizes the operation). Because a workload has one enrollment in force (section 7), the agent that the presentation names and the validator binds to the same workload (draft §11.3 step 2) is then the grant's agent. A compromised grantee is authenticated and refused by the validator with the `SECURITY_HOLD` receipt of identity-mapping §8; a workload with two enrollments in force is the configuration error of section 7, an `UNSUPPORTED_REQUIREMENT` error and not a denial. A request with no live session, or with a task reference that names no grant, has no principal. A presented `principal_id` is compared with the authenticated one by `native-principal-binding-v1`, and a difference is `FAIL` with `CONTEXT_MISMATCH` (draft §17.5).

**SB-17. Public failures.** A failed native authentication states only the public reasons of draft §13.4 and of the adapter contract (no credential, or credential rejected). It does not reveal whether a task, grant, session or user exists: an unknown task reference, a reference to a grant whose session is not live, and a reference to a grant made for another agent return the same public result. The per-rule reasons of a failed check are for the authenticated agent only (draft §13.4).

**SB-18. An unavailable source defers.** If the session store, the grant store, the enrollment registry or a hold store cannot answer, the result is `DEFERRED` with `DEPENDENCY_UNAVAILABLE`. No cached live session, cached grant or cached `ACTIVE` binding stands in for the source (draft §18; freshness §5).

**SB-19. Executor.** The installed `execution-identity-v1` mapping declares the class `delegated-user` for each (session principal, task, operation): the broker performs the read under the user's session and the recorded grant. A fallback to a broader portal or service credential is `FAIL` with `EXECUTOR_MISMATCH`, and an executor that cannot be determined is `UNKNOWN`, which yields `DEFERRED` (draft §17.5). Every `AUTHORIZATION` and `EXECUTION` report references an immutable native record that identifies the actual executor identity (draft §14.2); a report whose executor class differs from `delegated-user` is `UNQUALIFIED`.

**SB-20. Reads only.** R1 and R2 are reads. An operation with side effects needs transaction, budget and idempotency control (draft §10.3), which is C15 and is not used. The broker's agent-facing route table serves only R1 and R2.

**SB-21. One operation, one contract.** A material change of intent, principal, action, resources, body or consequential header needs a new contract and presentation (draft §10.3). The lifetime of the SP session does not extend a nonce or turn a receipt into a permission for the session. An admission is not a grant, and a grant is not an admission.

### B.6 Freshness

**SB-22. Membership facts.** A membership, role or account-state fact that a contract requires comes from a directory adapter: a configured native source with its own observation time and status time (freshness §4.1, directory row). It never comes from `authn_instant`, from `expires_at`, from the time of an `SPSession` read, or from an attribute statement of the assertion; the adapter does not read, keep or export the assertion's attributes (SB-1). A claim that carries `authn_instant`, or the time of a session read, as the observation time of such a fact is stale or re-stamped under freshness §3 and §7.

**SB-23. Session claims.** The two native claims read from the session store, `/attributes/environment/principal_id` and `/attributes/environment/idp_realm`, are current state read live (section 8, F1). Their observation time and status time are both the instant of that read, which falls inside the evaluation. Their `SourceRef` is empty, because each read establishes the value again (freshness §7). The read is of the authoritative session record: a copy taken earlier is not a live read. Any other native path returns `UNSUPPORTED_REQUIREMENT`.

## Annex C. Map of the G14 closure items

Finding G14 of `docs/handoff.md` asks for a specification of SP-session task authorization, agent enrollment, broker authority, expiry and logout, and supported workflows, while retaining the actual SAML validation. Its closure evidence is the rejection of wrong-SP and replayed assertions, of another session principal, of expired user or broker authority, and of unauthorized agent tasks. The tables map each item to the rules of Annex B and to the cases of section 10: `SAML-01` to `SAML-09` have landed, and `SAML-12` and `SAML-13` are planned. This profile specifies; it closes none of the evidence items until the cases exist and pass.

| G14 work item | Rules and sections |
|---|---|
| SP-session task authorization | SB-4 to SB-8, SB-10, SB-11, SB-13; Annex A |
| Agent enrollment | SB-14, SB-15; section 7 |
| Broker authority | SB-8 to SB-13, SB-19; Annex A.3; OI-1 |
| Expiry and logout | SB-5, SB-6, SB-9, SB-10; section 9 |
| Supported workflows | Sections 2 and 6 (U1 to U10); SB-20, SB-21 |
| Retaining the actual SAML validation | The boundary table; SB-1 to SB-3 |

| G14 closure evidence (or readiness item of example I05) | Case | Rules | Expected result |
|---|---|---|---|
| Reject an assertion for a different SP (wrong audience) | `SAML-01` | SB-1, SB-2 | No session, no principal, no report |
| Reject a replayed assertion | `SAML-02` | SB-2 | No new session; the existing one unaffected |
| Reject another session's principal | `SAML-03` | SB-16 | `CONTEXT_MISMATCH` |
| Reject expired user authority | `SAML-04` | SB-5, SB-6 | Native authentication denied |
| Reject logged-out user authority | `SAML-05` | SB-6, SB-10 | Denied; grants revoked |
| Reject expired broker authority | `SAML-06` | SB-9, SB-11 | `STALE_EVIDENCE` (OI-2) |
| Reject unauthorized agent tasks | `SAML-07`, `SAML-12`, `SAML-13` | SB-8, SB-11, SB-14 | `TASK_MISMATCH`; another agent refused at native authentication (SB-16); no grant for an unenrolled agent; revoked binding not admitted |
| Fresh membership comes from an achievable source, not the login time (example I05, Validation still required) | `SAML-08` | SB-22, SB-23 | `RESTAMPED` or `STALE_EVIDENCE` |
| Unattended agent login is not established (example I05, Deliberate simplifications) | `SAML-09` | SB-16 | No principal |

## Annex D. SAML facts and sources

Every statement about what SAML says is limited to the facts below, each cited to the section of the editions read. SAML Core is the OASIS Standard "Assertions and Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0", 15 March 2005 ([`saml-core-2.0-os.pdf`](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)). SAML Profiles is the OASIS Standard "Profiles for the OASIS Security Assertion Markup Language (SAML) V2.0", 15 March 2005 ([`saml-profiles-2.0-os.pdf`](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)).

| Fact | Source | Used in |
|---|---|---|
| A persistent identifier is a persistent opaque identifier specific to an identity provider and a service provider, a pair-wise pseudonym with no discernible correspondence to the subject's own identifier. It MUST NOT be shared in clear text with other providers and MUST NOT appear in log files or similar locations without appropriate controls. `NameQualifier` names the provider that generated it and `SPNameQualifier` the provider it was generated for, and `NameQualifier` MUST keep identifying the entity that originally created the identifier | SAML Core §8.3.7 | SB-3, SB-4, OI-3 |
| A transient identifier SHOULD be treated as an opaque and temporary value by the relying party | SAML Core §8.3.8 | SB-4 |
| An e-mail-format identifier is an addr-spec; the unspecified format leaves interpretation to implementations | SAML Core §8.3.2, §8.3.1 | SB-4 |
| An entity identifier is a URI of not more than 1024 characters | SAML Core §8.3.6 | SB-4 |
| `AuthnInstant` is required and is the time the authentication took place. `SessionIndex` is optional and indexes a session between the principal and the authenticating authority. `SessionNotOnOrAfter` is optional and is the time instant at which the session with the authority MUST be considered ended; it has no required relationship to a `NotOnOrAfter` condition | SAML Core §2.7.2 | SB-5, SB-7, A.1 |
| An identity provider that supports Single Logout MUST include a `SessionIndex` in the authentication statements of the bearer assertion | SAML Profiles §4.1.4.2 | A.1 |
| An SP MAY establish a security context with any session mechanism it chooses; later use of the assertion is at the discretion of the SP, subject to the restrictions in it | SAML Profiles §4.1.3.6 | SB-3 |
| If an authentication statement used to establish a security context has `SessionNotOnOrAfter`, the context SHOULD be discarded once that time is reached, unless the identity is established again by repeating the profile | SAML Profiles §4.1.4.3 | SB-5 |
| The time conditions of an assertion do not guarantee that its statements are accurate throughout its validity | SAML Core §2.5.1.2 | SB-7 |
| An audience restriction is valid if and only if the relying party is in the audiences; the asserting party makes no representation about accuracy or trustworthiness to a party outside them | SAML Core §2.5.1.4 | SB-3, U3 |
| An assertion with `OneTimeUse` MUST NOT be retained for future use | SAML Core §2.5.1.5 | U3 |
| An assertion with invalid or indeterminate conditions MUST be rejected by the relying party | SAML Core §2.5.1.1 | Boundary |
| Response processing: verify signatures, `Recipient`, `NotOnOrAfter` and `InResponseTo`; POST-binding assertions MUST be signed; used assertion IDs are kept for the `NotOnOrAfter` window | SAML Profiles §4.1.4.2, §4.1.4.3, §4.1.4.5 | Boundary |
| An unsolicited `Response` MUST NOT contain `InResponseTo` | SAML Profiles §4.1.5 | U4 |
| In browser SSO the principal, through an HTTP user agent, requests a resource at the SP, and the scenario assumes a standard commercial browser. The ECP profile is a separate profile for an enhanced client or proxy | SAML Profiles §4.1, §4.1.2 (step 1), §4.2 | U1 |
| A session participant that receives a logout request MUST authenticate it and invalidate the sessions it names, all of the principal's sessions when no `SessionIndex` is given, and MUST apply it to a matching assertion that arrives later | SAML Core §3.7.3.1 | SB-6 |
| A session authority SHOULD send a logout request to each participant, and a `PartialLogout` status reports participants that did not confirm | SAML Core §3.7.3.2 | Section 9 |
| Terminating a session at one participant alone is out of scope of the Single Logout profile; a participant starts the profile with at least one `SessionIndex` | SAML Profiles §4.4, §4.4.3.1 | SB-6 |
| Identifiers match strongly only when their content and attribute values are identical | SAML Core §3.3.4 | Boundary (logout matching is the SP's) |

Facts the texts read do not establish, so no rule relies on them: whether an identity provider may issue a persistent identifier value again to another subject after deleting one (SAML Core §8.3.7 is silent); whether an SP can learn that a session ended at the identity provider other than through the logout protocol (the authentication query of SAML Core §3.3.2.2 asks for statements about past authentication acts, and this profile does not use it); and any delegation, proxying or act-as meaning in SAML for an agent. They are recorded as OI-4, as the identity provider row of section 9, and as the unsupported form U2.

## Annex E. Open items

| ID | Open item | Provisional position in this profile |
|---|---|---|
| OI-1 | The final semantics of `/attributes/delegation/authority_ref`: syntax, binding, disclosure and resolution by `native-delegation-v1`. They depend on the delegation binding model of G03 | SB-12 fixes only that it is an opaque reference to one grant and not a credential |
| OI-2 | Draft §17.5 fixes `TASK_MISMATCH` for a changed task and `STALE_EVIDENCE` or `REVOKED_EVIDENCE` for a stale or revoked delegation. It names no code for an operation outside `scope`, for a task with no grant, or for a principal other than the grant's, and does not say whether an expired grant is stale | Fixed by this profile under draft §13.4 and §17.3.1: outside scope and another principal are `CONTEXT_MISMATCH`, no grant is `MISSING_FIELD`, an expired grant is `STALE_EVIDENCE` (SB-11). A grant for another agent is refused at native authentication (SB-16), and the check repeats the comparison from the binding it receives with `CONTEXT_MISMATCH` (SB-11, condition 5) |
| OI-3 | A persistent `NameID` whose `NameQualifier` names an entity other than the configured issuer (SAML Core §8.3.7) | Not mapped to a principal, which is the stricter choice |
| OI-4 | The persistent identifier reuse question of Annex D, and whether `idp_realm` needs a tenant dimension for an identity provider that serves several tenants | `idp_realm` is the configured identity provider identifier; reuse is a residual limit (IM-6) |
| OI-5 | The task text lists six fields for `TaskGrant`. A seventh, `session_id`, is added so that session end can revoke the grants of that session | `session_id` is part of A.2 |
| OI-6 | The `SPSession` has no field that says it was established by an unsolicited response (SAML Profiles §4.1.5), so the profile cannot tell such sessions apart | Not excluded; no agent session or grant can start from the identity provider side (U4) |
| OI-7 | No directory adapter integration profile has landed, so membership bounds and outage behavior are not declared | A contract that requires a membership fact is not claimed as enforced (section 8) |
| OI-8 | Whether a deployment without Reputation or Learning declares `full` or `single-owner`; the `single-owner` document has not landed | `full` is declared, as in the template's mini-example |
| OI-9 | The SP product and exact version, and a named maintainer | None; a deployment states them in its claim |
| OI-10 | No baseline check consumes `authn_instant`, so a requirement on authentication recency cannot be expressed | Unsupported (U8) |

## Annex F. Reference implementation (informative)

The reference implementation of the adapter contract is the Go package `go/adapter`, with the enrollment registry in `go/adapter/enroll` and the freshness evaluator in `go/adapter/freshness`. The rest of this profile is language-neutral. The table gives the real names that apply to this profile. The contract package `go/adapter` defines no type for an `SPSession` or a `TaskGrant`; they are native records of the SP, which the adapter package models. The adapter of this profile is the Go package `go/adapters/saml`, built with `saml.New` from a `saml.Config`: its `SPSession` and `TaskGrant` types, read through the `SessionStore` and `TaskBroker` interfaces, with the in-memory stores `Sessions` and `Grants`, and the agent's own broker authentication behind the `AgentAuthenticator` interface (SB-15). The integration point is the SP's write of an `SPSession` to its session store: there the SP's SAML implementation, for example a SAML library such as crewjam/saml, produces the session record after it accepted the assertion. That implementation and its SAML processing are outside this repository's claim (SB-1). In that package `native-principal-binding-v1` is not a `check_context` check, because draft §17.5 makes it a check the validator evaluates; `execution-identity-v1` is not built in; and `native-delegation-v1` returns `PASS` only when every condition of SB-11 holds; the grant's agent is checked at native authentication (SB-16) and again by the check against `CheckInput.Binding.AgentID` (SB-11, condition 5).

| Profile function | Name in the packages | Behavior for this profile |
|---|---|---|
| `authenticate_native` | `adapter.NativeAuthenticator.AuthenticateNative`, returning `adapter.Principal` | `ID` is the session principal; `Workload` is the agent's broker workload; `Realm` is the SP's realm; `Mechanism` names how the agent authenticated to the broker (an open set, recorded and not interpreted). No live session or no grant for the task reference returns `*adapter.NativeDenial` with `adapter.DenialCredentialRejected`, as does a grant whose `AgentID` has no enrollment in force on the agent's workload in `Config.Registry` (SB-16); a registry error that wraps `adapter.ErrUnsupportedRequirement` is returned as it is, or `adapter.DenialNoCredential` when no agent credential is present; its code is `INVALID_PROOF`. A store that cannot answer returns an error that wraps `adapter.ErrDependencyUnavailable` |
| `resolve_agent_binding` | `adapter.BindingResolver`, `enroll.Resolver` over an `enroll.Registry`; `enroll/memory.Registry` is the in-memory backend and is not a production store | The workload is the agent's broker workload. The statuses are `adapter.BindingActive`, `BindingRevoked`, `BindingCompromised` and `BindingUnknown`. The package neither refuses a second record for a workload nor detects one, so it does not implement the configuration error of section 7 (identity-mapping §5). The trusted actors are `enroll.Admin` and `enroll.AuthorizedIssuer`; an `enroll.Agent` has no authority, and the user's portal action is not an `enroll.Actor`. `enroll.Registry.Lookup` takes the realm, the workload and the `agent_id` together and selects only among the records of that workload, so grant creation (SB-8) resolves the agent's broker workload first and then the binding of that `agent_id` on it, with its status |
| `map_operation` | `adapter.OperationMapper.MapOperation` | Mapping version `pact-saml-1`; an unknown version returns an error that wraps `adapter.ErrUnsupportedRequirement`, and a request that disagrees with the principal wraps `adapter.ErrContextMismatch` |
| `read_native_claim` | `adapter.ClaimReader.ReadNativeClaim` with an `adapter.ClaimContext`, returning `adapter.NativeClaim` | The two approved paths of SB-23, with `ObservedAt` and `StatusCheckedAt` both the live read and an empty `SourceRef`. Any other path wraps `adapter.ErrUnsupportedRequirement`. The read is scoped by the task: `ClaimContext.Intent.TaskID` names the `TaskGrant`, the record read is the `SPSession` recorded in that grant (SB-16), and `ClaimContext.Principal` is the session principal. No other part of the request selects the grant or the session |
| `check_context` | `adapter.ContextChecker.CheckContext` on an `adapter.CheckInput`, returning `adapter.CheckOutcome` with an `adapter.Verdict` | Check IDs `native-delegation-v1` and `execution-identity-v1`. `adapter.CodeContextMismatch` and the other codes of the package are constants; `TASK_MISMATCH`, `REVOKED_EVIDENCE` and `EXECUTOR_MISMATCH` are check-specific `ReasonCode` strings. A usable grant is `PASS` with `REQUIREMENT_SATISFIED`; `TaskGrant.Scope` carries the grant's scope, nil permitting the whole mapping. The grantee is compared with `CheckInput.Binding.AgentID`; an empty binding never matches. An unknown check ID is `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`; an unreachable store is `UNKNOWN` with `DEPENDENCY_UNAVAILABLE` |
| Freshness comparison | `freshness.Evaluate`, `freshness.Evaluator`, `freshness.Monotonic` (`NewMonotonic`, `Check`, `Forget`) | The reason codes are `freshness.Satisfied`, `StaleEvidence`, `ClockAhead`, `Restamped`, `UnsupportedRequirement` and `DependencyUnavailable`. A membership claim that carries the login time or a later read time is `Restamped` or `StaleEvidence` (SB-22). `Monotonic.Check` returns `NOT_APPLICABLE` for the session claims, which have no `SourceRef` (SB-23) |
| `authorize_native` | `adapter.NativeAuthorizer.AuthorizeNative`, returning `adapter.Decision` | Called with the session principal, never the broker's identity; only `adapter.EffectAllow` permits |
| `record_outcome` | `adapter.OutcomeRecorder.RecordOutcome`, returning `adapter.Signed` or `adapter.NoVisibility` | `Observation.EvidenceRefs` names the immutable native record of the executor identity (SB-19) |
| Adapter descriptor | `adapter.Descriptor{Protocol, Version, MappingRevision}` and its `NativeAdapter` method | `saml`, `2.0`, `pact-saml-1`, published in `GatewayMetadata.adapters` |
