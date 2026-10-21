# PACT integration profile: HTTP Basic authentication

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

It states the exact conformance claim, and the evidence behind it, for an HTTP Basic authentication adapter in front of a legacy invoice API, as sketched in integration sample [I01](../../examples/example_I01.md). It fills the ten sections of the [template](../TEMPLATE.md). The machine-readable form is [`profile.json`](profile.json), which follows [`integration-profile.schema.json`](../integration-profile.schema.json). Where this profile and the draft ([`draft.md`](../../draft.md)) differ, the draft governs.

Status. The fixture index in section 10 lists the cases, and the `fixtures` array of `profile.json` lists the case files. Until those cases pass against an adapter, this profile cannot support an enforced-support claim (draft §4.4, §22.1). Two things stay outside what the adapter fixtures can observe: the controls the profile lists as deployment requirements in section 5, and the real account database and enrollment registry of a deployment.

## Profile header

| Field | Value |
|---|---|
| Profile name | HTTP Basic authentication gateway adapter (I01) |
| Target product and version | The `Basic` HTTP authentication scheme of [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html), used over HTTPS behind a PACT-aware gateway in the request path. The account database and the invoice backend are the deployment's existing systems and are not versioned here |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `1`, 2026-10-16 |
| Maintainer | jadb |
| Reference documents | draft = [`draft.md`](../../draft.md); example = [I01](../../examples/example_I01.md); identity rules = [`identity-mapping.md`](../identity-mapping.md); freshness rules = [`freshness.md`](../freshness.md) |

## 1. Claim scope

The gateway evaluates PACT in its own request path (draft §4.4) and claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over the `header` presentation transport. It is a partial role implementation (draft §22.1): it claims neither Holder, Reputation, nor Learning. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1; the roles it does not claim are supplied by the agent and by connected services of the deployment.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Holder 0.1`, `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced` |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` |
|---|---|---|
| `http-basic` | `rfc7617` | `pact-basic-1` |

- The adapter descriptor names the authentication scheme, not an HTTP version. `Basic` is defined by RFC 7617, and the request and `Authorization` header semantics it relies on are those of [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2). The mapping revision is a first-party `pact-` token, as the registry records `pact-mcp-1` for the MCP adapter (see the [profiles README](../README.md)).
- `header` is the only presentation transport, so it must be usable (draft §13.2, §20.1). Deployment requirement DR6 in section 5 covers the header size.
- Reputation, when a deployment applies it, is a separate connected service (C11 in section 4); an admission or a successful password check adds no positive reputation weight (example I01).

## 2. Protected routes and actions

One read route is protected, with the route ID R1 that later sections use. A route that is not listed is not claimed.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/invoices/{id}` | `GET` | `invoice.read` | `invoice:{id}`, from the path parameter exactly as received; the principal is `basic:{store-id}:{account-id}` (section 7) |

The mapping at revision `pact-basic-1` follows draft §10.2:

- `method` is `GET`. `target_uri` is the HTTPS origin set in gateway configuration plus the exact request path and query; untrusted forwarding headers never select the origin. A path or query with an ambiguous encoding is rejected.
- `body_digest` covers the exact request-body bytes, which for a normal `GET` is the empty body.
- The `Authorization` header and the `PACT-Presentation` header are excluded from the hashed headers, as the draft requires. The identity is bound through `principal_id` and native authentication. This profile binds no application header beyond `content-type` when a body is present (DR5 in section 5).
- The department of an invoice is not part of the request, and this profile approves no native path for it. The native permission lookup resolves it for the invoice of the actual operation (section 3, `authorize_native`).
- The same mapping revision is used when the contract is issued and when the actual operation is validated.

The PACT endpoints (`GET /.well-known/pact-configuration`, `POST /pact/v0.1/requirements`, and the others of draft §13.2) are protocol endpoints, not protected routes of this claim. The requirements endpoint is authenticated by the same `authenticate_native` step, with the agent's Basic credentials (example I01, step 1).

## 3. Enforcement points

The gateway performs all seven functions of draft §17.1 in its own filter chain. The five required steps run in request order, and the four supporting functions are listed after them.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Gateway authentication stage, before routing and before any PACT function | Gateway implementer | Checks the gateway enforcement marker, then verifies the Basic credentials against the account database. Produces the principal `basic:{store-id}:{account-id}`, the realm, and the workload (the same identifier, section 7). Runs at contract issuance and again at the protected request |
| 2 | `map_operation` | Gateway mapping stage, mapping revision `pact-basic-1` | Adapter owner | Builds the operation context of R1 (section 2); the path, query and body bytes are covered |
| 3 | PACT evaluation | In-gateway validator in the same request path | Gateway implementer | Runs after mapping and before native authorization: presentation signature and holder key against the enrolled binding, nonce, required facts. No sidecar handoff applies |
| 4 | `authorize_native` | Gateway invoice permission lookup for the authenticated account | Resource owner | Receives the original principal, never a gateway or backend identity (draft §4.3, §17.5). An invoice of another department is denied. A native denial is final (draft §2.3) |
| 5 | Execution | Forward of the authorized read from the gateway to the backend invoice service | Resource owner | Reached only after steps 1 to 4 pass. The backend takes the account only from a connection that satisfies DR1 and applies the same account's native restrictions |
| support | `resolve_agent_binding` | Enrollment registry lookup inside the gateway | Gateway implementer | Supplies the enrolled agent ID, operator, holder key and status of the agent the presentation names, on the authenticated account; the account alone never names an agent, and an account with more than one enrollment in force is a configuration error (section 7) |
| support | `read_native_claim` | Account database lookup | Adapter owner | Approved native paths `/principal/id` and `/principal/roles`; see the claim mapping below |
| support | `check_context` | Installed gateway checks | Gateway implementer | `purpose-operation-v1`, which admits the `invoice.read` operation only. An unknown check ID returns `UNKNOWN`, never `PASS` |
| support | `record_outcome` | Gateway outcome writer, after the native decision | Gateway implementer | Signs the admission decision and the native authorization result. Execution is recorded only when the backend reports it; otherwise the gateway declares no visibility of execution and assumes no success (draft §14.1) |

Rules specific to Basic:

- **Enforcement marker.** The marker is the authenticated context that the gateway's own filter chain attaches to a request it accepted for the enforced path. It is set inside the gateway and is never read from a request header, so a client cannot supply it. A request without the marker is rejected before any credential is evaluated, even when its credentials and presentation are valid. This is the only part of DR1 that the adapter observes.
- **Credentials.** The credentials are the Base64 encoding of the user-id, a colon, and the password. The first colon separates the user-id from the password, and neither may contain a control character (RFC 7617 §2). The default character encoding of that string is not defined (RFC 7617 §2), and the `charset` parameter is advisory (RFC 7617 §2.1), so the deployment declares the encoding its account store expects. The adapter finds the account by the user-id, then reads its immutable `account-id` and uses only that (section 7).
- **Denials.** A missing credential and a rejected credential both end the exchange as a native denial. The public reason is `NO_CREDENTIAL` or `CREDENTIAL_REJECTED`, the code is `INVALID_PROOF`, and an unknown account and a wrong password give the same public reason, so a denial does not disclose whether an account exists (draft §13.4). A failure before authentication produces no `OutcomeReport` (example I01, with draft §12.2 and §14.5).
- **Credential exclusion.** The password and its Base64 form never appear in a profile, receipt, outcome report, check outcome, error or log (draft §19). The password is not the PACT signing key.

Claim mapping. The profile paths `/attributes/environment/principal_id` and `/attributes/environment/roles` map to the native paths `/principal/id` and `/principal/roles`. The role names of the account store map to PACT role names through an administrator-approved, versioned translation in the mapping revision, so that a same-spelled role from another store does not match by accident (draft §17.2). The comparison for `principal_id` is `equal`, and for `roles` it is `subset`: every role the profile presents must occur in the roles mapped from the account (draft §8.4). Any other native path is unsupported.

## 4. Native dependencies

Eleven of the sixteen components are used, and each of the other five carries the reason it does not apply. Of the systems the rows name, only the account database, the invoice backend, the account permission lookup and the enrollment registry contract exist today; a row marked "to be supplied" is work that the deployment or the adapter still owes.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and filter chain of the PACT-aware gateway | Gateway implementer | The adapter functions exist in the reference implementation; the in-gateway validator and the deployment's filter chain are to be supplied |
| C02 | Native authentication and claim adapters | baseline | Existing account database and Basic credential verification, with the adapter functions `authenticate_native` and `read_native_claim` over it | Account store owner and adapter owner | The database and verification exist; the adapter functions exist in the reference implementation |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry, administrator-run enrollment (section 7) | IAM and security owner | The registry contract and an in-memory backend exist; a production backend is to be supplied by the deployment |
| C04 | Native delegation and task authority | delegated or task execution | none | none | Not used: each agent acts under its own account, and no delegation or task authority is claimed |
| C05 | Evidence and authoritative status sources | baseline | Account database, enrollment registry, security hold store | Adapter owner | The stores exist or are supplied by the deployment; the lookups through the adapter are to be supplied |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the claimed read route declares no external approval; a deployment whose native policy requires one for R1 is outside the claim |
| C07 | Purpose and exact operation mapper | baseline | Mapper at revision `pact-basic-1` | Adapter owner | Exists in the reference implementation: the route table of R1 and the check `purpose-operation-v1`; the installed purposes are deployment configuration |
| C08 | Native resource executor and authorization | the actual resource operation | Existing invoice backend and account permission lookup | Invoice service owner | Exists; preserves the native account's restrictions |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store shared by all gateway replicas | Platform owner | To be supplied by the deployment (DR4) |
| C10 | Task attribution and outcome qualification | baseline | Gateway outcome writer for admission and authorization; backend audit log for execution | Invoice service owner | The audit log exists; the writer is to be supplied |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed; a deployment that applies reputation supplies it separately |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Registry holding the base requirements | Platform owner | To be supplied by the deployment; registry only, no adaptation lifecycle |
| C13 | Revocation and security holds | baseline | Revocation and security hold store | Security and IAM owner | To be supplied by the deployment; read with a fresh check (section 8) |
| C14 | Protected evidence and audit storage | baseline | Access-controlled evidence and audit store | Security and data owner | To be supplied by the deployment; it never holds credentials (draft §19) |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: the claimed route is a read, with no transactions or budgets |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no containment control is claimed, so `runtime.isolation` is attested-only (draft §17.4; section 9) |

## 5. Alternative and bypass paths

Four other ways to reach invoices are listed: one `closed` by a deployment control, and three `out-of-claim`. None is `equivalently-enforced`.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Direct request to the backend invoice service, bypassing the gateway | `closed` | Deployment requirement DR1. Evidence field: `backend rejects connections lacking gateway client certificate`. Adapter-level specialization: a request without the gateway enforcement marker is rejected before any credential is evaluated; fixture group `BASIC-03` |
| B2 | Any route other than R1, on the gateway or the backend, including every list and write operation | `out-of-claim` | Not listed in section 2, so not claimed; excluded in section 6 |
| B3 | Use of the account's Basic credentials against any system other than through the gateway, such as another application that accepts the same account | `out-of-claim` | The credentials are computed from the user-id and the password alone (RFC 7617 §2), so they authenticate wherever the account is accepted; excluded in section 6 (credential forwarding outside the path). The backend case is B1 |
| B4 | Access to invoice data through the account database, administrative consoles or batch jobs | `out-of-claim` | Not a route of the claim; the claim covers only R1 |

Deployment requirements. These are conditions on the deployment that the claim depends on. The adapter fixtures cannot observe them, and a deployer states in writing that each one holds.

| ID | Requirement | Evidence the deployer supplies |
|---|---|---|
| DR1 | The backend is closed to every source but the gateway, by network policy that admits only the gateway, or by gateway-to-backend mutual TLS. The deployment declares which. The backend takes the authenticated account only from such a connection, never from a client-supplied header | `backend rejects connections lacking gateway client certificate` |
| DR2 | The gateway serves R1 and the contract endpoint over HTTPS only, from the origin set in its configuration, with no cleartext listener. Basic is not a secure method of authentication without TLS, because the user-id and password pass as cleartext (RFC 7617 §1, §4) | The listener and origin configuration |
| DR3 | The account database is read from its authoritative primary with no cache, and its `account-id` is never reissued to another account. Deleting an account is applied as a revocation of every enrollment record bound to it (identity-mapping IM-6, IM-29) | The read path, the key policy, and the deletion procedure |
| DR4 | Replay and receipt state is atomic and shared by every gateway replica (draft §7.5, §18) | The store and its consistency domain |
| DR5 | The backend gives no application header an action-changing meaning. A header that has one is added to the published header allowlist and normalization rules (draft §10.2) | The header allowlist |
| DR6 | The advertised `max_presentation_bytes` is no larger than the header size that every server and proxy in the path accepts, because `header` is the only presentation transport (draft §13.2, §20.1) | The advertised limits and the proxy limits |

## 6. Unsupported forms

The first row is the wider claim that sample I01 does not establish, and the other rows come from the dispositions and routes found while filling sections 2 to 5.

| Unsupported form | Source | Why it is not established |
|---|---|---|
| Telling agents apart by a shared Basic password, and PACT enforcement on an unchanged Basic server | I01 Basic: "Shared-password agent distinction or enforcement on an unchanged server" | Only a dedicated account behind the controlled gateway is the established design. A shared password distinguishes no agent, and an unchanged Basic-only server cannot evaluate PACT because a client adds a profile header (example I01) |
| Shared accounts | Section 7; identity-mapping §5 | One dedicated account per agent, the default of identity-mapping §5 (IM-19); an account with more than one enrollment in force is a configuration error (section 7) |
| Digest authentication, and every authentication scheme other than Basic | Section 1 (adapter protocol) | The adapter declares `http-basic` at `rfc7617` only. Digest is a different scheme, defined in [RFC 7616](https://www.rfc-editor.org/rfc/rfc7616.html) |
| Credential forwarding outside the path | Section 5, B1 and B3; example I01: "A fresh PACT signature does not make stolen Basic credentials harmless outside this enforced path." | The credentials are computed from the user-id and the password alone (RFC 7617 §2). Anything that holds them can authenticate wherever the account is accepted. The backend is closed by DR1; every other system is out of claim |
| Any route other than R1, including every list and write operation | Section 2 | Not listed in section 2, so not claimed |
| Cleartext HTTP, or any transport other than `https` | Section 1 (transport profile) | Only the `https` transport profile is claimed (DR2) |
| A declared executor identity class (draft §17.5) and the `execution-identity-v1` check | Section 3, execution row | The check is not installed, so this profile makes no claim about the identity class under which the backend runs the read |
| An enforced data-use or purpose restriction on invoice data after it is read | Section 4, C16; example I01 | `execution-control-v1` is not installed, so `runtime.isolation` is attested-only and invoice data handling is a post-read residual limit (draft §17.4) |

## 7. Identity mapping

Each agent runs under a dedicated Basic account that identity administrators enroll and bind to its holder key in the enrollment registry. All other rules are those of [`identity-mapping.md`](../identity-mapping.md). Rule identifiers `IM-n` refer to that document.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | Account only. The principal and the workload are the same identifier, `basic:{store-id}:{account-id}` (identity-mapping §3.3, §3.4). `store-id` is the configured identifier of the account store. `account-id` is the account's immutable key in that store. The user-id of the `Authorization` header is only the means to find the account and is never part of the identifier (IM-5). Informative example: `basic:legacy-accounts:20417`. The realm is the `tenant_id` and `environment_id` of the gateway configuration. There is no client namespace, because no user acts through a registered client |
| Trusted enrollment actors | The native administrative workflow only (identity-mapping §4.2): identity administrators acting through the environment's existing administrative controls. This profile configures no authorized identity-binding issuer |
| Shared-account handling | Not supported, the default of identity-mapping §5 (section 6). Each agent runs under its own account, the established design of the I01 row of section 6, and no reason for supporting shared accounts is stated. An account with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states (IM-19). The presentation names the agent, whose record must name the authenticated account, and the presentation key must equal its `holder_jkt` (IM-18). A Basic password distinguishes no agent (IM-16), and this profile makes no claim that it does (section 6) |
| Certificate, token, or role-session bindings | None. The Basic password authenticates the account only. The holder key is bound only through the enrollment record (IM-21), and the password is not the signing key. Changing or resetting the password changes no record (IM-20) |
| Lifecycle rules (rotation, compromise, recovery) | Deferred to identity-mapping §7 (IM-25 to IM-29). Specific to Basic: renaming a login changes no record, because the identifier is the `account-id`. Disabling an account is a native authentication failure and not a change to a record. Deleting an account is a revocation event for every record bound to it, applied by an enrollment administrator (IM-6, IM-29; DR3). The propagation bound is in section 9 |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule. Stricter choice: shared accounts refused (IM-19 allows supporting them only with a stated reason) |

## 8. Freshness

Three sources are listed with `max_age` and `status_max_age` in seconds, and every outage ends in `DEFERRED`, which fails closed (draft §18; freshness §5). A `status_max_age` of 0 means a status check made in this evaluation. Declaring a `max_age` of 30 means that a field rule demanding a source observation fresher than 30 seconds cannot be met by this profile, and the result is `DEFERRED` (freshness §4.2).

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Account database lookup (identity, roles, account state) | Current authoritative state, read from the primary with no cache for each evaluation (DR3). `ObservedAt` and `StatusCheckedAt` are the database's own answer time, not the time the gateway received the answer. A store that gives no time leaves `ObservedAt` empty, and the rule is `UNKNOWN`, so `DEFERRED` (freshness §3.1, rule 6). The claim carries no `SourceRef` | 30 | 0 | `DEFERRED` |
| F2 Enrollment registry (agent and key binding status) | Current authoritative state, read for each evaluation. `ObservedAt` is the time of the last change to the record and `StatusCheckedAt` is the time of the read (identity-mapping IM-10) | 30 | 0 | `DEFERRED` |
| F3 Security hold store | Current authoritative state, read for each evaluation (draft §18) | 30 | 0 | `DEFERRED` |

Admission gates on the status time of F2 and F3. The `ObservedAt` of a binding is a last-change time, and no field rule compares it with a limit; the `max_age` of F2 and F3 restates the bound of F1. The source reads happen at contract issuance and at evaluation (freshness §6). The machine-readable form needs a `max_age` for every row, so F2 and F3 carry the same 30.

### 8.1 Membership and status sources

F1 supplies identity, role and account-status facts, so it is listed again here. The adapter asks the account database at evaluation time and the database offers no change feed, so F1 has a live check and its values are current authoritative state. The enrollment registry and the hold store supply binding and hold status, not membership, role or account-state facts, so they are not listed here.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 Account database lookup (identity, roles, account state) | `identity`, `roles`, `account_state` | `true` | Account database query | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

## 9. Residual limits

The profile states five limits.

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Invoice data already returned to the agent is not recalled by a later revocation. No egress or data-use control is claimed, and `runtime.isolation` is attested-only: a verified runtime fact is not a containment guarantee (draft §17.4, §18) | Disclosed here; no bound |
| Revocation propagation | A disabled account or removed role (F1), a revoked, rotated or compromised binding (F2) and a security hold (F3) take effect at the next evaluation, in the consistency domain of each source. An operation already executed is not undone by revoking its receipt, and R1 is a single read, so this profile claims no cancellation of a read that is already in flight (draft §18) | 0 s for a source read from its authoritative primary with no cache; for a replicated or cached source, the lag the deployment declares (DR3) |
| Credential reuse outside the path | A leaked password gives native access to the backend and to any other system that accepts the account, unless that system is closed to it. A leaked password alone does not produce an admissible presentation, because the holder key is separate (IM-21) | Disclosed; the backend is closed by DR1, every other system is out of claim |
| Source reference | Account database claims carry no `SourceRef`, so the monotonic guard of the freshness profile does not compare them and the integration rests on the account database's own clock (freshness §7, §9) | Disclosed; no bound |
| Deployment controls | DR1 to DR6 are not observable by the adapter fixtures. The marker check of section 3 is an adapter-level specialization and is not evidence that the network control is in place | Disclosed; the deployer's written statement per requirement |

## 10. Fixture index

Nine negative cases were planned, `BASIC-01` to `BASIC-09`. Six are adapter cases of this profile and live in `spec/v1.0/fixtures/adapters/basic/`, each file named after its case id in lower case, such as `basic-01.valid.json`, with the manifest id `adapters/basic/basic-01.valid`; the [cases README](../../fixtures/adapters/basic/README.md) defines their native state, `basic/1`, and the fake account database [`assets/accounts.json`](../../fixtures/adapters/basic/assets/accounts.json) that every case reads (manifest id `adapters/basic/accounts`, kind `adapter-asset`). `profile.json` lists the case files in `fixtures`. The other three are not functions of the adapter: `BASIC-02` and `BASIC-05` are outcomes of the validator, which evaluation cases cover, and `BASIC-04` is a property of the gateway's request pipeline, which the adapter's own tests cover. Part (a) of `BASIC-07` is a property of the enrollment registry, covered the same way.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `BASIC-01` | R1 with wrong, unknown, missing, malformed or colon-less Basic credentials, another scheme, a password with a control character, or a disabled account | Native denial with code `INVALID_PROOF` before any PACT function runs, public reason `NO_CREDENTIAL` for a missing credential and `CREDENTIAL_REJECTED` otherwise, the same for an unknown account and a wrong password; no principal | `adapters/basic/basic-01.*`, with the controls `basic-01.valid` (the principal is named by the account-id) and `basic-01.colon-in-password` (the first colon splits) | R1 |
| `BASIC-02` | Valid Basic credentials, presentation signed with a key other than the enrolled holder key | `INVALID_PROOF` through the holder-binding mismatch; no execution (draft §22.2, old holder key) | Evaluation case `admission/old-holder-key`; the enrolled key the adapter reports is checked by `basic-07.dedicated` | R1 |
| `BASIC-03` | Request without the gateway enforcement marker, as a direct backend request would arrive, with valid credentials and presentation, with or without headers that claim the gateway | Rejected before the account database is asked; no principal produced; no execution | `adapters/basic/basic-03.direct`, `adapters/basic/basic-03.forged-marker` | B1 (adapter level only) |
| `BASIC-04` | R1 with valid credentials and no presentation | No execution through the enforced PACT path | Go test of the adapter package (pipeline); no fixture | R1 |
| `BASIC-05` | A presentation that was already consumed | `REPLAY`; the nonce is consumed once (draft §13.4) | Evaluation cases `admission/replay-same-nonce-two-replicas` and `admission/attestation-reuse` (draft §22.2 rows 8 and 10; spec map `R08`, `R10`) | R1 |
| `BASIC-06` | Any exchange: the password and its Base64 form | Neither appears in any denial, operation context, mapping error, check outcome or signed outcome report (draft §19) | `adapters/basic/basic-06.*` | R1, every function |
| `BASIC-07` | Two enrollment records, for agents A and B, on one account: (a) the enrollment that would add the second record; (b) both records present, and a binding lookup for A and one for B | (a) Refused; (b) neither record is selected, for either agent: the configuration error of identity-mapping §5 (IM-19), `UNSUPPORTED_REQUIREMENT`; no execution | (a) Go test of the adapter package against the enrollment registry; (b) `adapters/basic/basic-07.two-agents-a`, `adapters/basic/basic-07.two-agents-b`, with the control `basic-07.dedicated` | R1, section 7 |
| `BASIC-08` | Profile roles that are not among the roles mapped from the account | `/principal/roles` gives only the account's roles through the approved translation, so the native comparison fails and the role requirement is not satisfied (draft §22.2, self-asserted privileged role) | `adapters/basic/basic-08.*` for the adapter's value, with the control `basic-08.principal-id`; evaluation case `admission/self-asserted-privileged-role` for the comparison | R1 |
| `BASIC-09` | Invoice that belongs to another department, valid credentials and presentation | `authorize_native` denies; no invoice contents are returned; no execution (draft §22.2) | `adapters/basic/basic-09.other-department`, with the control `basic-09.same-department` | R1 |

Coverage. R1 is covered by `BASIC-01`, `BASIC-02` and `BASIC-04` to `BASIC-09`. B1 is covered only at adapter level by `BASIC-03`; the network or mutual TLS control behind DR1 has no fixture. B2 to B4 are `out-of-claim` and have none. Of the outage and freshness rows F1 to F3, the outage of F1 is covered by `basic-08.store-down`; the others are exercised through the common freshness cases of the adapter conformance suite. The common cases of that suite also apply; `BASIC-03` and `BASIC-06` specialize its enforcement-point case and its credential-exclusion case.

## Reference implementation (informative)

The sections above are language-neutral. This section ties them to the merged Go packages, whose names and behaviour it does not change. The Basic adapter is the package `go/adapters/basic`, built with `basic.New` from a `basic.Config` that names the account database (`AccountStore`), the enrollment registry, the native permission lookup (`PermissionLookup`), the installed checks and the outcome signing key; it uses the standard library only. Its tests run the common cases and the cases of section 10 against it.

| Draft §17.1 function | Go contract in `go/adapter` | Behaviour this profile relies on |
|---|---|---|
| `authenticate_native` | `NativeAuthenticator.AuthenticateNative` | Returns `*NativeDenial` (an `ErrInvalidProof`) with the public reason `NO_CREDENTIAL` or `CREDENTIAL_REJECTED`; an unreachable source returns an error wrapping `ErrDependencyUnavailable` |
| `resolve_agent_binding` | `BindingResolver.ResolveAgentBinding`, supplied by `enroll.Resolver` over an `enroll.Registry` | `Lookup` takes the realm, the authenticated account and the presented agent ID, and selects that agent's record among the records of the account (identity-mapping IM-18). It answers `UNKNOWN`, not an error, for an agent with no record on the account, including one enrolled only for another account, and returns a `REVOKED` or `COMPROMISED` binding with that status |
| `map_operation` | `OperationMapper.MapOperation` | An uninstalled mapping version returns `ErrUnsupportedRequirement` |
| `read_native_claim` | `ClaimReader.ReadNativeClaim` with a `ClaimContext` | Both approved paths are facts of the account, so the read uses `ClaimContext.Principal` and neither its `Intent` nor its `Operation`. An unapproved native path returns `ErrUnsupportedRequirement`; the result carries `ObservedAt`, `StatusCheckedAt`, `SourceID` and `SourceRef` |
| `check_context` | `ContextChecker.CheckContext` | No error result: an unknown check ID is `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`. `purpose-operation-v1` passes, with `REQUIREMENT_SATISFIED`, when the declared purpose is one the gateway installed and it allows the action of the actual operation; an unrecognized purpose is `FAIL` with `UNSUPPORTED_PURPOSE` (draft §10.1) and an action the purpose does not allow is `FAIL` with `CONTEXT_MISMATCH`. The installed purposes are deployment configuration |
| `authorize_native` | `NativeAuthorizer.AuthorizeNative` | Only an explicit `ALLOW` permits; a denial is final. The `Decision` names the permission lookup in `SourceID` |
| `record_outcome` | `OutcomeRecorder.RecordOutcome` | Returns `Signed` or `NoVisibility`; an absence of visibility is declared, never filled with success |

The age rules of section 8 are evaluated by `go/adapter/freshness` (`Evaluate`, `Evaluator`, and the `Monotonic` guard); an unreachable source maps to `DEFERRED` through `ErrDependencyUnavailable`. The adapter descriptor of section 1 is the `Descriptor` of `go/adapter` with the protocol `http-basic`, the version `rfc7617` and the mapping revision `pact-basic-1`.

## External references

- [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html), The 'Basic' HTTP Authentication Scheme: §1 and §4 (cleartext password, TLS), §2 (credential construction, encoding, control characters), §2.1 (`charset`).
- [RFC 7616](https://www.rfc-editor.org/rfc/rfc7616.html), HTTP Digest Access Authentication: the scheme this profile does not support.
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), HTTP Semantics: §11.6.2, the `Authorization` header field.
