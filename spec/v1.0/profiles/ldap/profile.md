# PACT LDAP identity, groups, and account-state profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

This is the integration profile (template: [`TEMPLATE.md`](../TEMPLATE.md)) for LDAP-backed authentication, group membership, and account state, in the form example [I06](../../examples/example_I06.md) describes. An application authenticates a dedicated directory account with the directory's own mechanism, and PACT consumes the directory's identity, group, and account-state facts while the application keeps its own resource-permission model. The profile specifies directory realms, supported authentication, stable identifiers, group and nested-group resolution, disabled-account semantics, lookup authority, and replication bounds. Its machine-readable form is [`profile.json`](profile.json), which follows [`../integration-profile.schema.json`](../integration-profile.schema.json).

It adds no wire field and no protocol requirement. Where it and the [draft](../../draft.md) differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. The rules of the appendices carry the identifiers LR-1 to LR-30, and the requirement cases carry LDAP-01 to LDAP-10, so that fixtures and reviews can cite them. Identity rules are cited as IM-n from [`identity-mapping.md`](../identity-mapping.md) and freshness rules by section from [`freshness.md`](../freshness.md).

Every statement has one of four bases. *Draft* cites a draft section. *Source* cites an RFC section or a vendor page that was read for this profile; the sources table in Appendix I lists each one. *Profile* marks a convention this profile adds. *To probe* marks a fact that documentation did not establish: the probe is in Appendix H and no rule depends on the unprobed behavior. No statement here describes a directory from memory.

## Profile header

| Field | Value |
|---|---|
| Profile name | LDAP identity, groups, and account state (`ldap`) |
| Target product and version | LDAPv3 (RFC 4511). OpenLDAP slapd 2.6, read from the 2.6 Administrator's Guide and the 2.6.15 manual pages. Active Directory Domain Services, read from the Microsoft Learn pages in Appendix I; the Windows Server version is not fixed by this profile and is recorded per deployment (Appendix H, P4) |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `0.1-draft.1`, 2026-10-16 |
| Maintainer | `jadb` |
| Reference documents | draft = [`draft.md`](../../draft.md); example = [`example_I06.md`](../../examples/example_I06.md); [`identity-mapping.md`](../identity-mapping.md); [`freshness.md`](../freshness.md) |

## 1. Claim scope

**How to fill:** roles, mode, transports, adapter protocol and mapping revision, conformance and transport profiles.

The claim is the native-integration part of a gateway that installs the LDAP adapter in its own request path (draft §4.4, and the "installed adapter" of example I06). It covers three directory facts (the authenticated principal, group membership, and account state), the authority the adapter reads them with, and the freshness it can declare. It does not cover the application's routes, which each deployment lists in section 2, or the application's resource permissions, which stay native (draft §2.3, §17.3).

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, for the adapter capabilities of draft §17.1 only |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Validator 0.1`, `PACT Reputation 0.1`, and `PACT Learning 0.1` are not claimed by this profile, and the gateway capabilities other than the native integration of draft §17.1 (contract issuance, receipts, holds, outcome signing) are supplied by the gateway and the connected services of the deployment |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced` |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |
| Directories in the claim | OpenLDAP slapd 2.6 and Active Directory Domain Services. Any other LDAP server is outside the claim (section 6) |
| Authentication in the claim | The simple bind with a name and a non-empty password, over LDAPS or StartTLS only (LR-4 to LR-9) |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` |
|---|---|---|
| `ldap` | `3` | `pact-ldap-1` |

`3` is the protocol version of RFC 4511 §4.2 ("This document describes version 3 of the protocol"). `pact-ldap-1` names the mapping of this profile: the identifier forms of LR-2, the native paths of section 2, and the state vocabulary of LR-20. A change to any of them is a new mapping revision. The group resolver and the state map carry their own revisions (LR-18, LR-22) because a deployment can change them independently.

## 2. Protected routes and actions

**How to fill:** every route, method, action, and resource mapping the claim covers; a route not listed is not claimed.

An integration profile for a mechanism cannot know the application behind it. The table lists the one route of the example I06 deployment so that the claim is concrete; its path is illustrative, because the example narrative names a read of warehouse stock and no URL. A deployment that adopts this profile writes its own routes in its instance of this section, and a route that is not listed there is not claimed.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/api/v1/warehouses/{warehouse_id}/stock` | `GET` | `stock.read` | `warehouse:{warehouse_id}`, from the path parameter; the principal is the authenticated directory account, never the lookup account (LR-13) |

The directory facts a requirement on R1 can name are the approved native paths of the installed mapping `pact-ldap-1` (draft §9.2, §17.2). Any other native path is refused with `UNSUPPORTED_REQUIREMENT` (LR-12).

| `native_path` | AgentProfile path (example I06) | Comparison | Value | `SourceID` |
|---|---|---|---|---|
| `/principal/id` | `/attributes/environment/principal_id` | `equal` | `ldap:{realm_id}:{unique_id}` of the authenticated account | `ldap:{realm_id}:identity` |
| `/principal/group_ids` | `/attributes/environment/group_ids` | `subset` | Direct group memberships, as group identifiers (LR-16) | `ldap:{realm_id}:groups:{resolver_revision}` |
| `/principal/group_ids_nested` | `/attributes/environment/group_ids` | `subset` | Direct and nested group memberships (LR-17) | `ldap:{realm_id}:groups:{resolver_revision}` |
| `/principal/account_state` | `/attributes/environment/account_state` | `equal` | One value of the vocabulary of LR-20; a requirement names `active` | `ldap:{realm_id}:state:{state_map_revision}` |

A rule uses either group path, never both, so the semantics a contract asks for are visible in the contract and are not decided by a resolver setting. The fourth fact of the I06 table, `/attributes/runtime/isolation`, comes from a trusted runtime issuer and is evidence, not a directory fact; this profile does not cover it.

## 3. Enforcement points

**How to fill:** where each function runs, in request order, and who runs it.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | LDAP adapter, in the gateway's authentication stage before routing | Adapter owner | Search for the account, then a simple bind as that account over a protected connection (LR-4 to LR-11). Produces the principal `ldap:{realm_id}:{unique_id}`, or a native denial, or an outage |
| 2 | `map_operation` | Gateway mapping stage of the application, at the deployment's mapping revision | Application and adapter owners | Not defined by this profile; for R1 it binds the warehouse and the action. The principal it carries is the authenticated account |
| 3 | PACT evaluation | In-gateway validator in the same request path | Gateway implementer | Runs after mapping and before native authorization. The freshness checks of [`freshness.md`](../freshness.md) §3 apply to the claims of section 2 |
| 4 | `authorize_native` | The application's existing authorization, for example the warehouse-level permission check of I06 | Resource owner | Called with the original principal and never with the lookup account (LR-13). A native denial is final (draft §2.3) |
| 5 | Execution | The application's stock read under the authenticated account's native restrictions | Resource owner | Reached only after steps 1 to 4 pass |
| support | `resolve_agent_binding` | Enrollment registry lookup for the realm, the workload `ldap:{realm_id}:{unique_id}`, and the agent ID that the presentation names; the workload alone never names an agent, and a workload with more than one enrollment in force is a configuration error (section 7) | Gateway implementer and IAM owner | The registry contract of [`identity-mapping.md`](../identity-mapping.md) §4; the directory is not an enrollment actor (section 7) |
| support | `read_native_claim` | LDAP adapter, directory reads by the lookup account | Adapter owner | The four native paths of section 2; value, original observation time, status time, and source ID as LR-25 sets them |
| support | `check_context` | Installed gateway checks | Gateway implementer | `execution-identity-v1` (draft §17.5) with the lookup account excluded from every declared executor class (LR-13); `native-principal-binding-v1` as named in draft §17.5. No LDAP-specific check is added |
| support | `record_outcome` | Gateway and application outcome writers | Gateway implementer and resource owner | The directory adds no execution visibility: login, lookup, and admission are not task outcomes (example I06, draft §14.5) |

## 4. Native dependencies

**How to fill:** map each native system to a component C01 to C16 and name its owner.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and filter chain of the deployment | Gateway implementer | Supplied by the deployment; not provided by this profile |
| C02 | Native authentication and claim adapters | baseline | The LDAP adapter, the directory, and the lookup service account | Adapter owner and directory owner | The adapter is `go/adapters/ldap` in the reference implementation; the directory and the account are supplied by the directory owner |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry lookup for the realm, the workload, and the agent ID that the presentation names; the workload alone never names an agent | IAM and security owner | The registry contract and an in-memory backend exist; a durable backend is to be supplied by the deployment |
| C04 | Native delegation and task authority | delegated or task execution | none | none | Not used: the agent acts under its own dedicated account; employee delegation is not claimed |
| C05 | Evidence and authoritative status sources | baseline | The directory (identity, group, and account-state reads) and the enrollment registry | Directory owner and IAM owner | Exists; the freshness each can declare is in section 8 |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the read route needs no external approval |
| C07 | Purpose and exact operation mapper | baseline | Mapper of the application at the deployment's revision | Application owner | Supplied by the deployment for R1 |
| C08 | Native resource executor and authorization | the actual resource operation | The inventory application | Resource owner | Exists in the example; unchanged by this profile |
| C09 | Durable atomic exchange state | baseline | The gateway's replay and receipt store | Gateway and platform owner | Supplied by the deployment; not provided by this profile |
| C10 | Task attribution and outcome qualification | baseline | The gateway's outcome writer and the application's audit log | Resource owner | Supplied by the deployment; not provided by this profile |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | The gateway's policy registry | Platform owner | Registry only; no adaptation lifecycle is claimed |
| C13 | Revocation and security holds | baseline | The gateway's hold store and the enrollment registry | Security and IAM owner | Supplied by the deployment; directory removals and disables are read live through section 8 |
| C14 | Protected evidence and audit storage | baseline | The gateway's evidence and audit store | Security and data owner | Supplied by the deployment; passwords and service secrets are excluded from it (LR-10) |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: the read route has no transaction or budget |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no runtime attestation or data-use guarantee is claimed |

## 5. Alternative and bypass paths

**How to fill:** every other way to reach the protected resource, with its disposition and evidence.

No negative fixture for a bypass path is planned (section 10), and a `closed` or `equivalently-enforced` path needs one. All three paths are therefore `out-of-claim`. A deployment that closes one of them records the control and its fixture in its own instance of this section.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Application login by means other than the directory: local accounts, API keys, or another single sign-on | `out-of-claim` | Excluded in section 6 (authentication other than the simple bind) |
| B2 | Direct requests to the application backend that skip the gateway | `out-of-claim` | The network control belongs to the deployment; excluded in section 6 (routes other than R1) |
| B3 | Direct use of the lookup account's credential against the directory | `out-of-claim` | A directory access control concern: the lookup account is read-only (LR-13), and its credential never reaches a request, a receipt, or a profile (LR-10). Excluded in section 6 |

## 6. Unsupported forms

**How to fill:** what the integration did not establish, starting from the wider claims that sample I06 does not establish.

| Unsupported form | Source | Why it is not established |
|---|---|---|
| Employee delegation, universal schema, or nested-group semantics | I06: "Employee delegation or universal schema/nested-group semantics" | Only the dedicated account and the configured resolver are claimed. Nesting is supported only through the Active Directory resolver of LR-17 and is unsupported for OpenLDAP |
| Application entitlement taxonomy | Example I06, simplifications: "No universal LDAP schema, group expansion, or application entitlement taxonomy is supplied" | A directory group is a fact. What it permits stays with the application |
| Authentication other than the simple bind over LDAPS or StartTLS: anonymous or unauthenticated bind, an unprotected simple bind, every SASL mechanism, the Active Directory Sicily mechanism, LDAPv2 | Section 1 | LR-4 to LR-6 admit one arrangement. RFC 4513 §6.3.1 shows the risk of the unauthenticated bind, and Active Directory supports the simple and SASL mechanisms and a third, Sicily [MS-AUTHM] |
| Shared directory accounts | Identity mapping §5 | One directory account per agent, the default of identity mapping §5 (IM-19); a workload with more than one enrollment in force is a configuration error (section 7) |
| A distinguished name, `cn`, `uid`, `sAMAccountName`, user principal name, mail, or display name as an identifier | Identity mapping §3.3 | LR-2 admits only the unique id |
| A directory other than OpenLDAP 2.6 or Active Directory Domain Services (for example Active Directory Lightweight Directory Services, another LDAP server, a cloud directory) | Section 1 | No documentation for them was read for this profile |
| Nested groups on OpenLDAP; dynamic groups and any other overlay-based expansion | I06 row; LR-17 | An OpenLDAP realm has the nested setting `none`, which lists nesting as unsupported, and a requirement on `/principal/group_ids_nested` ends in `UNSUPPORTED_REQUIREMENT` (LDAP-05) |
| Membership through the Active Directory primary group, through `tokenGroups`, or across domains and forests | LR-16, LR-17 | The direct and chain resolvers do not claim them (Appendix H, P10); `tokenGroups` returns SIDs, needs a global catalog, and is costly for a domain controller [MS-TG] |
| Reads served by a replica or by a domain controller other than the one that takes changes, with no declared bound | LR-26 | No replication bound is published for them; without a declared bound every finite limit is unachievable |
| Referral chasing and truncated results treated as complete | LR-15 | A referral or a limit-exceeded result is never a complete answer |
| Any route other than R1 of this profile's reference deployment | Section 2 | Not listed, so not claimed |

## 7. Identity mapping

**How to fill:** point to [`identity-mapping.md`](../identity-mapping.md) and record only the identity choices this profile makes or narrows.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | The namespace `ldap`: `ldap:{realm_id}:{unique_id}` for the principal and the workload, which are the same for a dedicated account (identity mapping §3.4), and the same form for a group (LR-2). There is no client identifier. `unique_id` is `entryUUID` for `openldap` realms and `objectGUID` for `activedirectory` realms, one per realm, as IM-5 requires a profile to declare |
| Trusted enrollment actors | The two actors of identity mapping §4.2: a native administrative workflow and an authorized identity-binding issuer. Directory rights confer no enrollment authority: the lookup account, a directory administrator acting as one, and a group membership never create or change a record (IM-13) |
| Shared-account handling | Not supported, the default of identity mapping §5 (section 6). A workload with more than one enrollment in force is a configuration error, with the consequence that identity mapping §5 states, and shared directory accounts are unsupported (IM-19) |
| Certificate, token, or role-session bindings | None. The password of the directory account authenticates the workload; the holder key is bound to it only by the enrollment record (IM-21). A client certificate, SASL EXTERNAL, and Kerberos are not supported |
| Lifecycle rules (rotation, compromise, recovery) | Deferred to identity mapping §7. A deleted directory entry cannot authenticate and its record stays until an administrator revokes it (IM-29). A recreated account has a new unique id and needs a new enrollment. The unique id never repeats (RFC 4530 §2.4; [MS-OBJGUID]), so the name reuse of IM-6 does not arise for the identifier. A disabled account changes no record; the directory refuses its bind and the state read reports it (LR-20) |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule. Stricter choices: the lookup account is excluded from every actor role (LR-13); shared directory accounts refused (IM-19 allows supporting them only with a stated reason) |

## 8. Freshness

**How to fill:** for each source, how it is observed, the `max_age` and `status_max_age` it can achieve, and what happens when it is unavailable.

The rows are the reference topology of Appendix F: one server takes every change and answers every read (one OpenLDAP provider, or one Active Directory domain controller with no replication partner), and the adapter keeps no cache. An authoritative source has a best `max_age` equal to its best status bound ([`freshness.md`](../freshness.md) §4.2), which is 0 here. A deployment with replicas, several domain controllers, or a cache declares a bound under LR-26 and LR-27; this profile publishes none for them. Every outage ends in `DEFERRED`, which fails closed (draft §18).

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Directory account state and identity entry | Current authoritative state at the answering server. The observation time is the as-of instant of the read (LR-25); the entry is found by unique id (LR-12) | 0 | 0 | `DEFERRED` (`DEPENDENCY_UNAVAILABLE`) |
| F2 Directory direct group membership | Current authoritative state at the answering server, read for each evaluation; the `memberOf` values and the group entries they name | 0 | 0 | `DEFERRED` (`DEPENDENCY_UNAVAILABLE`) |
| F3 Directory nested group resolution (Active Directory in-chain matching rule) | Current authoritative state, computed by the server at query time | 0 | 0 | `DEFERRED` (`DEPENDENCY_UNAVAILABLE`; `UNSUPPORTED_REQUIREMENT` when the resolver is unsupported) |
| F4 Enrollment registry (agent and key binding status) | Current authoritative state, read for each evaluation; the observation time is the last change of the record and a read does not move it (IM-10) | 0 | 0 | `DEFERRED` (`DEPENDENCY_UNAVAILABLE`) |

For F4 the 0 in `max_age` follows [`freshness.md`](../freshness.md) §4.2 and is the status bound; no field rule bounds the age of an enrollment record, so the schema's required integer carries no further meaning.

### 8.1 Membership and status sources

F1 to F3 supply identity, membership, and account-status facts and are listed again here. F4 supplies none of them and is not an entry. The directory has no change feed that this profile uses: the adapter reads for each evaluation and does not wait for a notification, so a membership change is seen at the next read.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 Directory account state and identity entry | `identity`, `account_state` | `true` | Directory search by unique id over LDAPS or StartTLS | `none` | Not applicable: no change feed | 0 | `authoritative_current` |
| F2 Directory direct group membership | `groups` | `true` | Directory search of the `memberOf` attribute over LDAPS or StartTLS | `none` | Not applicable: no change feed | 0 | `authoritative_current` |
| F3 Directory nested group resolution | `groups` | `true` | Directory search with the in-chain matching rule over LDAPS or StartTLS | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

## 9. Residual limits

**How to fill:** what remains true after a successful admission, covering post-read data and how revocation propagates to each source.

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Stock data already returned to the agent is not recalled by a later removal from a group or a disable; no egress or data-use control is claimed (draft §17.4, §18) | Disclosed here; no bound |
| Revocation propagation, directory | In the reference topology a removal, a disable, or a lock reaches the gateway at the next read of F1 to F3. Elsewhere it reaches the gateway within the deployment's declared bound (LR-26); PACT does not promise instantaneous revocation from a replicated directory (draft §18, example I06). Lock state diverges between servers by design: OpenLDAP records authentication failures on the replica that served them [OL-PP], and Active Directory replicates a lockout urgently to the PDC emulator and to some sites only, and does not replicate an unlock urgently [AD-REPL] | 0 s in the reference topology; the declared `max_age` otherwise |
| Revocation propagation, enrollment | A revocation or compromise mark reaches the gateway within the status bound of F4, which is 0 s, inside the consistency of the registry backend (identity mapping §7.5). The in-memory backend is local to one process | 0 s, within the backend's consistency |
| Session age | A deployment that authenticates once and keeps a session carries the age of the login in `/principal/id`; groups and state are read for each evaluation and a stale session cannot claim a fresh group observation (example I06) | The login age, bounded by the contract's `max_age_seconds` for the rule |
| Directory enforcement | The adapter reads state attributes. It cannot show that the directory enforces them: that an OpenLDAP database loads the password policy overlay, or that Active Directory refuses a disabled account at bind. The bind result is the directory's own enforcement (LR-9) | Disclosed; a deployment records the overlay and policy in its realm record |
| Access control uniformity | The visibility sentinel (LR-14) detects a lookup account that lost access to a whole base. It does not detect an entry-specific denial inside a base; such a denial can only remove a group or hide an account, which yields `FAIL`, never a positive result | Disclosed; the documented scope assumes one uniform grant per base (LR-13) |
| Directory reads are not re-stamp checked | Each read carries an as-of instant and a source reference built from it (LR-25), so the monotonic guard of [`freshness.md`](../freshness.md) §7 never compares two reads of one entry | Disclosed; the guard still protects relayed or re-signed copies |
| Lock expiry | Whether a lapsed temporary lock clears `pwdAccountLockedTime` (OpenLDAP) or sets the computed lockout bit back (Active Directory) is not established; the adapter reports `locked` while the attribute says so (Appendix H, P6, P7) | A lapsed lock can be reported as `locked`, which fails closed |

## 10. Fixture index

**How to fill:** the negative cases that demonstrate the claim and the expected result of each.

Ten cases carry the requirement cases of Appendix G, and `LDAP-11` covers the configuration-error rule of section 7 and is not one of them. The IDs `LDAP-01` to `LDAP-10` are the identifiers of Appendix G. Each is a group of adapter cases of this profile in `spec/v1.0/fixtures/adapters/ldap/`, one file per variant, named by its lower-case ID and variant, such as `ldap-01.empty-password.json`, with the manifest id `adapters/ldap/ldap-01.empty-password`; every file is registered in `spec/v1.0/fixtures/manifest.json` and listed in the `fixtures` array of `profile.json`. The cases run against a directory built from the seed `adapters/ldap/assets/seed.ldif` (two OpenLDAP realms, `hq` and `branch`, in one database) or `adapters/ldap/assets/ad-seed.ldif` (one Active Directory realm, `corp`), in the model `ldap/1` of the [LDAP cases README](../../fixtures/adapters/ldap/README.md), which also states how the request carries the name and the password. The Evidence column names the files, and the part of an item that is a property of the validator rather than of an adapter function says so: an adapter case shows the claim value, and the admission effect of Appendix G (`FAIL`, `INADMISSIBLE`, `DEFERRED`) is the validator's comparison of it with the requirement. The identity, freshness, and request-binding cases of `spec/v1.0/fixtures/adapters/_common/` also apply and are not repeated. Bypass paths B1 to B3 are `out-of-claim` and have no fixture.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `LDAP-01` | Simple bind with a name and an empty password; an empty name; a password of characters that SASLprep maps to nothing; one with a character SASLprep prohibits | Rejected before any PACT function and with no directory request: `NO_CREDENTIAL` (RFC 4513 §5.1.2) for the empty name and the empty or emptied password, `CREDENTIAL_REJECTED` for the prohibited one | `adapters/ldap/ldap-01.empty-password`, `ldap-01.empty-name`, `ldap-01.mapped-to-nothing`, `ldap-01.prohibited`, with the controls `ldap-01.valid`, `ldap-01.identity-headers-ignored` and `ldap-01.wrong-password` | R1, LR-6 |
| `LDAP-02` | Authenticated account whose state attributes say disabled; locked, expired, or reset accounts | `account_state` `disabled` (and `locked`, `expired`, `password_change_required`), not `active`: the validator's comparison is `FAIL`, `INADMISSIBLE` with `INVALID_CLAIM` (draft §11.4, §13.4) | `adapters/ldap/ldap-02.disabled`, `ldap-02.locked`, `ldap-02.expired`, `ldap-02.password-reset`, `ldap-02.ad-disabled`, with the controls `ldap-02.active` and `ldap-02.ad-active` | R1, F1 |
| `LDAP-03` | Login name that matches no entry; and an authenticated account whose entry was deleted before the read | Denial `CREDENTIAL_REJECTED`; `account_state` `absent` and no groups, which the validator compares as `FAIL` with `INVALID_CLAIM` | `adapters/ldap/ldap-03.unknown-login`, `ldap-03.deleted-entry-state`, `ldap-03.deleted-entry-groups`, after the change `adapters/ldap/change-delete-entry` (file `assets/ldap-03.delete-entry.ldif`) | R1, F1 |
| `LDAP-04` | Login name that matches two entries (same `cn` under two organizational units); a login name with a filter character | Not a unique match: denial `CREDENTIAL_REJECTED`; neither entry is chosen, and the name never widens the filter | `adapters/ldap/ldap-04.duplicate-cn`, `ldap-04.wildcard-name`, with the control `ldap-04.same-cn-other-login` | R1, LR-11 |
| `LDAP-05` | Requirement on `/principal/group_ids_nested` in a realm whose nested resolver is unsupported, or whose server does not evaluate the in-chain rule; `/principal/group_ids` in a realm without the memberof overlay | Unsupported-requirement error, which the validator records as `UNKNOWN`, `DEFERRED` with `UNSUPPORTED_REQUIREMENT`; never `PASS` and never an empty list | `adapters/ldap/ldap-05.nested-unsupported`, `ldap-05.chain-unsupported-by-server`, `ldap-05.direct-unsupported`, with the control `ldap-05.ad-chain` | R1, F3 |
| `LDAP-06` | Group or state attribute, or the entries themselves, hidden from the lookup account by a directory access control | Dependency-unavailable error (`UNKNOWN`, `DEFERRED` with `DEPENDENCY_UNAVAILABLE`); not read as non-membership, `active`, or `absent` | `adapters/ldap/ldap-06.hidden-groups`, `ldap-06.hidden-state`, `ldap-06.hidden-entries` | R1, F1, F2 |
| `LDAP-07` | Directory unreachable, or its TLS or the lookup bind failing, at evaluation | Dependency-unavailable error (`UNKNOWN`, `DEFERRED` with `DEPENDENCY_UNAVAILABLE`, draft §18, §22.2), at authentication and at a claim read | `adapters/ldap/ldap-07.unreachable-authenticate`, `ldap-07.unreachable-claim`, `ldap-07.tls-fails`, `ldap-07.lookup-bind-fails` | R1, F1, F2, F3 |
| `LDAP-08` | Membership explicitly removed from the required group | The group list without the group once the authoritative read shows the removal, which the validator compares as `FAIL`, `INADMISSIBLE` with `INVALID_CLAIM` | `adapters/ldap/ldap-08.removed`, after the change `adapters/ldap/change-remove-member` (file `assets/ldap-08.remove-member.ldif`), with the control `ldap-08.member` | R1, F2 |
| `LDAP-09` | Group with the same name in another realm; the same login name in another realm; a unique id under another realm id | Not equal: the identifiers differ by `realm_id` (IM-3, IM-4); the group of the other realm is not listed, the login authenticates as the other realm's entry, and the unique id names no account in the other realm | `adapters/ldap/ldap-09.other-realm-group`, `ldap-09.branch-login`, `ldap-09.other-realm-principal` | R1, LR-2 |
| `LDAP-10` | Lookup account presented as the principal, offered as the executor, or passed to `authorize_native` | Never accepted: denial at authentication, a context mismatch as a principal of a claim read, `FAIL` with `EXECUTOR_MISMATCH` (draft §17.5), and the original principal in every native call. That the lookup account is never an enrollment actor is the registry's rule (IM-13) and has no adapter case | `adapters/ldap/ldap-10.lookup-login`, `ldap-10.lookup-principal`, `ldap-10.executor-lookup`, `ldap-10.authorize-no-substitution`, with the controls `ldap-10.executor-principal` and `ldap-10.authorize-original` | R1, LR-13 |
| `LDAP-11` | Two enrollment records, for agents A and B, on the workload of one directory account: (a) the enrollment that would add the second record; (b) both records present, and a successful bind as the account with a presentation by A signed with A's key, and one by B signed with B's key | (a) Refused; (b) neither record is selected, for either agent: the configuration error of identity mapping §5 (IM-19), `UNSUPPORTED_REQUIREMENT` | (b) `adapters/ldap/ldap-11.two-agents-a`, `ldap-11.two-agents-b`, with the control `ldap-11.dedicated`; (a) is a Go test of the adapter package against the enrollment registry | R1, section 7 |

A stub that maps a login name or a group by `cn` and ignores the realm fails `LDAP-04` and `LDAP-09` (Appendix G); the Go repository keeps such a stub as the red baseline of every LDAP case.

### Replaced common cases

The common cases of the adapter conformance suite run against this adapter. Seven `authenticate_native` cases state a principal that a directory account cannot carry, because LR-2 derives the identifier from the realm and the unique id of the bound entry, and are replaced ([adapters README](../../fixtures/adapters/README.md), "Replaced common cases"; draft §22.2). The others pass, with the deployment-supplied sources that their native state describes.

| Common case | Why a directory account cannot realize it | Replacement |
|---|---|---|
| `COMMON-01.credential-wins` | Expects `https://idp.acme.example/bob` | `LDAP-01.identity-headers-ignored`: identity headers naming another account; authenticated as the bound entry |
| `COMMON-02.via-enforcement-point` | Expects `https://idp.acme.example/alice` | `LDAP-01.valid`: authenticated as `ldap:hq:{entryUUID}`, mechanism `ldap-simple-bind`, realm of the realm record |
| `COMMON-09.authenticate-realm` | Expects a `globex` principal id | `LDAP-09.branch-login`: the same login name in another realm authenticates under that realm's id (LR-1) |
| `IDENT-01.authenticate` | Expects `basic:acme-accounts:20511` | `LDAP-04.same-cn-other-login`: another account authenticates as its own entry, selected by the login attribute (LR-11) |
| `IDENT-02.authenticate` | Expects an `oauth:` identifier of another tenant | `LDAP-09.branch-login`: another realm is another principal (LR-1, LR-2) |
| `IDENT-03.authenticate` | Splits user and client; a dedicated directory account is both | `LDAP-01.valid`: the principal and the workload are the same identifier (identity mapping §3.4) |
| `IDENT-05.authenticate` | Expects `basic:acme-accounts:30981` | `LDAP-04.same-cn-other-login`: an account with the same `cn` and display name authenticates as itself |

## Appendix A. Realms and identifiers

A realm record is configuration of the gateway, changed only through its administrative controls (draft §4.2).

| Field | Meaning |
|---|---|
| `realm_id` | The token that prefixes every principal and group identifier of the directory (LR-1) |
| PACT realm | The `tenant_id` and `environment_id` the directory realm belongs to |
| `directory_kind` | `openldap` or `activedirectory` |
| Server | One `ldaps://` URL, or one `ldap://` URL with StartTLS required. Never taken from a referral, a request, or an AgentProfile |
| TLS | Trust anchors and the reference identity for the server identity check (RFC 4513 §3.1.3) |
| Unique id attribute | `entryUUID` for `openldap`, `objectGUID` for `activedirectory`; no other value (LR-2) |
| Bases and classes | The user base DNs, the group base DNs, and the object classes of accounts and groups |
| Login attribute | The attribute the discovery search matches against the typed name, such as `uid` or `sAMAccountName`. It selects an entry and is never an identity (LR-11) |
| Lookup account | The DN of the read-only service account and a reference to its credential; the credential itself is not in the record (LR-13) |
| ACL scope | The documented grant of the lookup account (LR-13) |
| Sentinel | The sentinel account, group, and parent group (LR-14) |
| Topology | `single-server`, or `replicated` with `replication_bound_seconds` and an optional `cache_bound_seconds` (LR-26, LR-27) |
| Group resolver | The direct resolver, the nested setting (`none` or `ad-chain`), and the `resolver_revision` (LR-16 to LR-18) |
| State map | The attribute map and the `state_map_revision` (LR-21, LR-22) |
| Denied principals | Identifiers that never authenticate as an agent: the lookup account and any other service account (LR-13) |

**LR-1. Realms.** Every directory the adapter reads is a realm declared by an administrator. `realm_id` is unique in the gateway, uses only the `unreserved` characters of identity mapping §3.1, and is compared octet for octet (IM-3). A directory realm belongs to exactly one PACT realm (IM-7), and one PACT realm can hold several directory realms. A request, an AgentProfile, a discovery response, or a signed claim never adds or changes a realm (draft §4.2). *Basis: draft, profile.*

**LR-2. Identifiers.** A principal or workload is `ldap:{realm_id}:{unique_id}` and a group is `ldap:{realm_id}:{unique_id}` with the unique id of the group entry (identity mapping §3.3). `unique_id` is the realm's one unique id attribute (IM-5), written as a lower-case hyphenated UUID. `entryUUID` is assigned by the server to each entry when it is added, is immutable, and is written in the string form of RFC 4122 (RFC 4530 §2.1, §2.4). `objectGUID` is 16 bytes, is set when the object is created, and cannot be changed [MS-OBJGUID]. Whether an identifier names a principal or a group is given by the field that carries it, never by its text. A distinguished name, `cn`, `uid`, `sAMAccountName`, user principal name, mail, or display name is never a component: DNs are not stable identifiers, and a new object can take a DN that named another (RFC 4530 §1). Two identifiers are equal only when equal octet for octet, so a group of another realm never equals a group of this one, whatever its name (IM-3, IM-4). The byte order in which Active Directory presents `objectGUID` is not established, and the text form of a realm of that kind is accepted only after the probe P3 passes. *Basis: source, profile; to probe (P3).*

**LR-3. The unique id must be present.** An entry that has no unique id, or whose value does not convert to a UUID, cannot name a principal. The adapter then returns an error that wraps the dependency-unavailable error for a read, or an outage for an authentication, and never falls back to a name. OpenLDAP maintains `entryUUID` only while `lastmod` is on, which is its default [OL-CONF], and returns an operational attribute only when it is requested by name (RFC 4512 §3.4; RFC 4511 §4.5.1.8), so the adapter always requests it by name, and without the binary option, which would ask for a BER encoding of the value (RFC 4522 §3). *Basis: source, profile.*

## Appendix B. Authentication (`authenticate_native`)

**LR-4. Protected connection.** The adapter reaches a directory only over LDAPS, or over `ldap` followed by a successful StartTLS before any bind. Both arrangements exist: OpenLDAP supports TLS through StartTLS and `ldaps://`, and calls StartTLS the standard track mechanism [OL-SEC §14.2]; Active Directory permits an LDAPS port or the StartTLS operation [MS-TLS]. RFC 4511 §4.14 and RFC 4513 §3 define StartTLS; none of the RFCs read for this profile uses the name LDAPS or the `ldaps` scheme. The adapter performs the server identity check against the configured trust anchors and reference identity and closes the connection on failure (RFC 4513 §3.1.3), and after StartTLS it discards or refreshes what it learned about the server before TLS (RFC 4513 §3.1.5). A StartTLS that does not return `success` leaves the session without TLS (RFC 4511 §4.14.2), so the adapter closes it and sends no bind. The adapter does not rely on the server to refuse an unprotected simple bind: Active Directory "does not require, but supports" a protected connection for it [MS-SIMPLE], and RFC 4513 §2 only says implementations SHOULD disallow it by default. *Basis: source, profile.*

**LR-5. One mechanism.** The only authentication is the name/password mechanism of the simple bind (RFC 4513 §5.1.3): the DN of the account and a non-empty password. The adapter never sends an anonymous bind (RFC 4513 §5.1.1), an unauthenticated bind (§5.1.2), a SASL bind, or a Sicily bind, and it sends a bind request of version 3 only (RFC 4511 §4.2). *Basis: source, profile.*

**LR-6. Empty password.** A simple bind with a name and a zero-length password is the unauthenticated mechanism: it establishes an anonymous authorization state, the name "is not to be authenticated or otherwise validated", and a server "may return a success response" to it, which leaves a client with the impression that the identity was authenticated (RFC 4513 §5.1.2, §6.3.1). The RFC tells clients that use a bind result to make authorization decisions to "actively detect unauthenticated Bind requests (by verifying that the supplied password is not empty)". The adapter therefore rejects an empty password, and an empty login name, before it opens a connection, sends a search, or calls any other PACT function, and returns the native denial with reason `NO_CREDENTIAL`. Emptiness is tested on the octets that would be sent: RFC 4511 §4.2 has clients prepare textual passwords with SASLprep, which maps some characters to nothing (RFC 4013 §2.1, and the soft hyphen example of §3), so a password of such characters becomes empty and is rejected too, and a password SASLprep prohibits is rejected as well. The rule holds whatever the server does. OpenLDAP disables the unauthenticated bind by default and names the options in two places that differ (Appendix H, P2). The Active Directory documents read do not state what Active Directory DS does with it (P1); they state that Active Directory Lightweight Directory Services rejects a zero-length password only when `DenyUnauthenticatedBind` is 1, which is not the default [MS-CFG]. *Basis: source, profile; to probe (P1, P2).*

**LR-7. Bind as the matched entry, on its own connection.** The bind name is the DN of the entry that the unique discovery search returned (LR-11), never the text the caller typed. Active Directory accepts many name forms in the name field of a simple bind, including a display name, and tries them in turn, with the DN first [MS-SIMPLE]; a bind by the DN of the matched entry leaves no room for another form to select another object. A bind moves the session to an anonymous state first and to the new state only if it succeeds, and "an unsuccessful bind always results in the session having an anonymous authorization association" (RFC 4513 §4; [OL-SEC §14.3.1]). The user bind therefore runs on a connection of its own, which carries nothing else and is closed after the bind; the lookup connection is never given a user credential and never rebinds. *Basis: source, profile.*

**LR-8. Anonymous detection after the bind.** When the root DSE lists the Who am I? operation (OID `1.3.6.1.4.1.4203.1.11.3`, RFC 4532 §3), the adapter runs it on the user connection after a successful bind. A response that is present and empty means the server treats the client as anonymous (RFC 4532 §3), and the adapter rejects the authentication. Only the emptiness is used, not the content of the authorization identity. When the operation is not listed, a successful bind with a non-empty password is the evidence (RFC 4513 §5.1.3). Whether each directory lists it is not established (P11). *Basis: source; to probe (P11).*

**LR-9. Bind results.** The adapter maps what the directory answers to one of three results. The result codes and their meanings are RFC 4511 §4.1.9 and Appendix A; servers "may return substituted result codes to prevent unauthorized disclosures", so the adapter reads no more into a code than the table says.

| Directory answer | Adapter result |
|---|---|
| `success` for a non-empty password (and a non-empty Who am I? response where LR-8 applies) | The principal `ldap:{realm_id}:{unique_id}`, with the PACT realm of the directory realm, mechanism `ldap-simple-bind`, and the authentication time |
| `invalidCredentials`, `inappropriateAuthentication`, `unwillingToPerform`, `insufficientAccessRights`, `noSuchObject`, `invalidDNSyntax` | Native denial with reason `CREDENTIAL_REJECTED` (draft §13.4: `INVALID_PROOF`) |
| `busy`, `unavailable`, `timeLimitExceeded`, `adminLimitExceeded`, `authMethodNotSupported`, `strongerAuthRequired`, `confidentialityRequired`, `operationsError`, `protocolError`, `referral`, `other`, a code outside RFC 4511 §4.1.9, a TLS or transport failure, or a timeout | Outage: the dependency-unavailable error (`UNKNOWN`, `DEFERRED`, draft §18) |

The three codes `authMethodNotSupported`, `strongerAuthRequired`, and `confidentialityRequired` say that the directory will not take this arrangement, which is a fault of configuration and not of the caller; they are an outage so that the gateway reports it as one. The denial carries only the closed public reasons `NO_CREDENTIAL` and `CREDENTIAL_REJECTED`, so it never says whether an account exists (draft §13.4). A client reads "any result code that they do not recognize as an unknown error condition" (RFC 4511 Appendix A). *Basis: source, profile.*

**LR-10. Secrets.** A password, the lookup account's credential, and any value derived from them are never written to a receipt, an outcome report, an AgentProfile, a log, or an error (example I06). *Basis: profile.*

## Appendix C. Lookup, unique match, and lookup authority

**LR-11. The login search must match exactly one entry.** The discovery search runs on the lookup connection (LR-13) with the realm's user base, scope `wholeSubtree`, and the filter `(&(objectClass=<account class>)(<login attribute>=<typed name>))`. The typed name is escaped octet by octet where the filter grammar needs it: `*`, `(`, `)`, `\`, and NUL are written `\2a`, `\28`, `\29`, `\5c`, `\00` (RFC 4515 §3), so that a name never changes the filter. The size limit is 2 (RFC 4511 §4.5.1.4). The search requests the DN, the unique id attribute by name (LR-3), and the attributes of the state map. The result is a unique match only when the search ends with `success`, returns exactly one entry, and returns no search result reference. The reason is that names are not unique in a directory: `cn` is a multi-valued name (RFC 4519 §2.3), `cn` (through `name`) and `uid` compare case-insensitively (RFC 4519 §2.18, §2.39; RFC 4517 §4.2.11), and an RDN must be unique only among siblings (RFC 4512 §2.3.1), so one name can match entries in different containers. Active Directory fails its own simple bind when the name maps to more than one object [MS-SIMPLE], which the adapter does not rely on.

| Search result | Adapter result |
|---|---|
| `success`, no entry | Native denial `CREDENTIAL_REJECTED` |
| Two entries, or `sizeLimitExceeded` | Native denial `CREDENTIAL_REJECTED`; the adapter never selects one of the entries |
| `timeLimitExceeded`, `adminLimitExceeded`, `busy`, `unavailable`, `referral`, a search result reference, or any other failure | Outage |

The denial is the same for no entry and for several, so a caller cannot learn which. *Basis: source, profile.*

**LR-12. Reads are by unique id.** For a claim read the adapter parses `Principal.ID` under LR-2; an identifier that is not of the form `ldap:{realm_id}:{unique_id}` for a configured realm is a context mismatch. It searches the realm's user base for `(<unique id attribute>=<value>)`, with the value in the form the server expects (for `objectGUID` the binary escape syntax of RFC 4515 §3, which the Active Directory filter documentation also shows [MS-FILTER]). It never searches by DN, name, or login attribute. The result classes are those of LR-11 with these meanings: no entry is a missing account (LR-24), and two entries for one unique id are an outage, since a unique id that matches twice means the directory is not behaving as documented. A native path outside the four of section 2 is refused with the unsupported-requirement error (`UNSUPPORTED_REQUIREMENT`). *Basis: profile.*

**LR-13. Lookup authority.** The adapter reads the directory with one read-only service account per realm, the lookup account.

| Rule | Content |
|---|---|
| Documented scope | The realm record lists the bases, the attributes, and the access level. For OpenLDAP the grant is `read` on the `entry` pseudo-attribute and on the attributes of the maps, which also gives `search` (levels are cumulative; [OL-AC §8.2.1, §8.2.3]); for Active Directory the equivalent permissions are to probe (P12). The grant holds for a whole base, with no narrower grant inside it |
| Read only | No `write` and no `manage` level, and no `read` or `compare` on a password attribute |
| Own bind | The adapter binds the lookup account with its own non-empty password over a protected connection (LR-4, LR-6). A failed bind is an outage: the adapter sends no lookup on a session whose bind failed or was not made, because that session is anonymous (RFC 4513 §4) and would read different data than the lookup account. Active Directory can allow anonymous reads of any kind subject to access control when `fLDAPBlockAnonOps` is FALSE [MS-ANON] |
| Never the principal | The lookup account's identifier is in the realm's denied principals. A login with it is a native denial, it is never the `Principal`, the `Workload`, or an enrolled workload, and it never appears as the value of `/principal/id` |
| Never the executor | It is never the identity passed to `authorize_native`, which receives the original principal (draft §17.5), and never an allowed executor in any class of `execution-identity-v1`. A connector's service credential "is not evidence that the requesting agent is authorized" and cannot replace the principal's native restrictions (draft §4.3). The check returns `FAIL` with `EXECUTOR_MISMATCH` if it is the executor |
| Never an enrollment actor | Reading the directory confers no authority to enroll, rotate, revoke, or mark an agent (IM-13) |

The requirement case LDAP-10 asserts the last three rules. *Basis: draft, source, profile; to probe (P12).*

**LR-14. Visibility sentinel.** LDAP does not require a server to tell a client that an attribute or an entry was hidden. A search returns the attributes it can "subject to access control", an attribute can come back with no values "when access controls prevent the return of values", and some attributes "may not be included in Search results due to access controls" (RFC 4511 §4.5.1.8, §4.5.2). An entry for which a filter evaluates to false or undefined "is ignored for the Search" without an error (RFC 4511 §4.5.1.7), and OpenLDAP grants `search` "to apply search filters" and `read` "to read search results" [OL-AC §8.2.3]; what a filter on an attribute without `search` evaluates to is not stated in the pages read (P12). A server may also substitute a result code to avoid a disclosure, for example `noSuchObject` for `insufficientAccessRights` (RFC 4511 Appendix A). An empty answer is therefore the same for "none" and for "hidden", and example I06 says "an empty lookup is not proof of membership or non-membership".

The profile closes the gap with a sentinel. Each realm configures a sentinel account S in the user base, a sentinel group G_S in the group base with S as a direct member, and, when the nested resolver is enabled, a parent group G_P with G_S as a member. They exist for this purpose only: they are never enrolled and never given application rights. S carries a value for each attribute the realm's state map reads, set by the directory owner (for OpenLDAP the policy attributes of LR-22, set so that S is not `active`). Every read of Appendix D or E is accompanied, on the same connection and within the same evaluation, by a read of S for the same attributes, and its value stands only if the read of S returns S's configured unique id, a value for each attribute the read depends on, G_S among its direct groups, and, for the nested path, G_P among its nested groups. Otherwise the read is an outage (`UNKNOWN`, `DEFERRED`, `DEPENDENCY_UNAVAILABLE`). The sentinel result is not reused for another evaluation. When the direct sentinel passes and only the nested one fails, the nested resolver is unsupported (LR-17). Hidden data can only remove groups or hide an account, so without the sentinel a hidden attribute yields `FAIL` and never a positive result; the sentinel makes the result `UNKNOWN` where the cause is a lost grant. The sentinel assumes the uniform grant of LR-13. *Basis: source, profile; to probe (P12).*

**LR-15. Incomplete answers.** The adapter does not chase referrals or search result references: they are LDAP URLs (RFC 4516) that name other servers, which are outside the configured realm (draft §4.2; RFC 4511 §4.1.10, §4.5.3). A result that ends in `referral`, carries a search result reference, or ends in `sizeLimitExceeded`, `timeLimitExceeded`, or `adminLimitExceeded` is an incomplete answer and is an outage for a read of Appendix D or E. A partial group list is never compared as if it were complete. The adapter does not use the paged results control, which this profile did not read (P14). *Basis: source, profile; to probe (P14).*

## Appendix D. Group resolution

**LR-16. Direct resolver.** The direct resolver reads the `memberOf` attribute of the subject entry, requested by name. In Active Directory `memberOf` holds "the distinguished name of the groups to which this object belongs" [MS-MEMBEROF]. In OpenLDAP it exists only where the memberof overlay is loaded on the database: the overlay "updates an attribute (by default memberOf) whenever changes occur to the membership attribute (by default member) of entries of the objectclass (by default groupOfNames)", and `memberOf` is operational, so "it must be requested explicitly" [OL-AG §12.8]. The overlay's maintenance operations "are internal to the server on which the overlay is configured and are never replicated", so a consumer needs its own instance [OL-MEMBEROF]. Each value is resolved by a base-scope read of that DN that requests the unique id attribute and the object class. The entry must be of a configured group class and lie under a configured group base, compared as DNs and not as text (RFC 4517 §4.2.15). A value that names no readable entry is dropped, because an overlay can leave dangling references [OL-MEMBEROF] and a hidden group can only remove a membership (LR-14). The result is the sorted, duplicate-free list of group identifiers of LR-2. An OpenLDAP realm without the memberof overlay has no direct resolver, and the path `/principal/group_ids` is refused as unsupported there. Active Directory documents `primaryGroupID` as the relative identifier of the primary group of the user, which by default is that of the Domain Users group [MS-PGID], and the pages read do not say whether `memberOf` lists it, so the primary group is not claimed (P10). The revision is `pact-ldap-groups-direct-1`. *Basis: source, profile; to probe (P10).*

**LR-17. Nested resolver.** Nesting is explicit and per realm. For `activedirectory` the resolver is the matching rule `1.2.840.113556.1.4.1941` (`LDAP_MATCHING_RULE_IN_CHAIN`), "limited to filters that apply to the DN", which walks the chain of ancestry [MS-FILTER]. The documented form that finds every group a user belongs to sets the base to the groups container, the scope to subtree, and the filter `(member:1.2.840.113556.1.4.1941:=<user DN>)` [MS-FILTER]; the adapter adds the group class, escapes the DN (RFC 4515 §3), requests the group unique id, and uses the DN that the same read returned for the subject. The documentation also warns that such queries "may be more processor intensive" and that inefficient searches "will log appropriate event log messages" [MS-FILTER], so the adapter sets a time limit and treats a limit-exceeded result as incomplete (LR-15). The revision is `pact-ldap-groups-ad-chain-1`.

For `openldap` the nesting setting is `none`. The profile lists nesting as unsupported there: no nested-group semantics of OpenLDAP were read for this profile. A server must not return an error for a matching rule it does not recognize: the filter is "Undefined" and the entry is ignored (RFC 4511 §4.5.1.7), so a chain filter sent to a server that lacks the rule returns nothing, which looks like non-membership. The adapter therefore never infers support. A realm with the setting `none` answers `/principal/group_ids_nested` with the unsupported-requirement error without sending a search, and a realm with `ad-chain` proves the rule with the nested sentinel of LR-14 in each read. The rootDSE is not used to detect the rule: it is not established that a directory lists it (P4). *Basis: source, profile; to probe (P4, P5).*

**LR-18. Resolver revision.** `resolver_revision` names the resolver behavior: the group bases, the group classes, the direct attribute, the nested setting and rule, the limits, and the dropping rule of LR-16. The baseline revisions are `pact-ldap-groups-direct-1` and `pact-ldap-groups-ad-chain-1`; a deployment that changes any element of the behavior publishes a new revision string, compared by exact equality. The revision is part of the `SourceID` of every group claim (section 2), so a receipt says which resolver produced the value. *Basis: draft §17.2, profile.*

**LR-19. Empty is not proof.** An empty group list is an answer only when the sentinel of LR-14 passed in the same evaluation. *Basis: profile.*

## Appendix E. Account state

**LR-20. Vocabulary.** The value of `/principal/account_state` is one of `active`, `disabled`, `locked`, `expired`, `password_change_required`, and `absent`. Only `active` satisfies a requirement `equal active`. When several apply, the first in the order `disabled`, `locked`, `expired`, `password_change_required` is reported. `absent` is reported only by LR-24. The vocabulary is closed: a map cannot add a value. *Basis: profile.*

**LR-21. Active Directory map (`pact-ldap-state-ad-1`).**

| Value | Rule | Source |
|---|---|---|
| `disabled` | `userAccountControl` has the bit `0x00000002`, `ADS_UF_ACCOUNTDISABLE` | [MS-UAC] |
| `locked` | `msDS-User-Account-Control-Computed` has the bit `0x0010`, `UF_LOCKOUT`; it is requested by name and holds "additional bits that are not persisted" | [MS-UACC] |
| `expired` | `accountExpires` is neither `0` nor `0x7FFFFFFFFFFFFFFF`, and its time (100-nanosecond intervals since 1601-01-01 UTC) is not after the as-of instant of the read | [MS-EXP] |
| `password_change_required` | `pwdLastSet` is `0` and `userAccountControl` lacks `0x00010000` (`ADS_UF_DONT_EXPIRE_PASSWD`), or `msDS-User-Account-Control-Computed` has the bit `0x00800000` (`UF_PASSWORD_EXPIRED`) | [MS-PWD], [MS-UAC], [MS-UACC] |

`lockoutTime` is not read. A zero value means the account is not locked out, but the attribute "is only reset when the account is logged onto successfully", so a non-zero value can belong to an account that is not locked [MS-LOCK]; telling them apart by `lockoutTime` needs `lockoutDuration` and the directory's time [MS-LOCK, MS-LOCKDUR], which the adapter leaves to the computed bit. That the computed bit follows a lapsed lockout is to probe (P6). The attributes `userAccountControl`, `msDS-User-Account-Control-Computed`, `accountExpires`, and `pwdLastSet` must all be returned and well formed. *Basis: source; to probe (P6).*

**LR-22. OpenLDAP map (`pact-ldap-state-openldap-1`).** The map reads the operational attributes of the password policy overlay [OL-PP], which the OpenLDAP guide describes among the abilities "set an administrative lock on an account", lock "for a specified period of time after repeated authentication failures", and "force a password to be changed at the next authentication" [OL-AG §12.10]. The attributes are operational and requested by name.

| Value | Rule | Source |
|---|---|---|
| `disabled` | `pwdAccountLockedTime` is `000001010000Z`: the account "has been permanently locked and may only be unlocked by an administrator" | [OL-PP] |
| `locked` | `pwdAccountLockedTime` has any other value. The page does not say whether a lapsed temporary lock clears it, so the adapter reports `locked` while a value is present (P7) | [OL-PP] |
| `expired` | `pwdEndTime` is not after the as-of instant, or `pwdStartTime` is after it: "Authentication attempts made after [pwdEndTime] will fail" and those made before `pwdStartTime` fail | [OL-PP] |
| `password_change_required` | `pwdReset` is `TRUE`: the password "was reset and the user must change it upon first authentication" | [OL-PP] |

The page states that account locking "only takes effect when the `pwdLockout` password policy attribute is set to TRUE"; the adapter reads the attribute and does not read the policy, and the directory's enforcement is its own (section 9). OpenLDAP has no other account-state attribute in the pages read. The sentinel (LR-14) carries each of these attributes so that a lost grant on one of them is visible. *Basis: source; to probe (P7).*

**LR-23. Nothing defaults to active.** An attribute the map needs that does not parse, or that has more than one value where the map reads one, is not "not set": the read is an outage (LR-14). Whether a missing attribute is "not set" depends on the map. The Active Directory map (LR-21) needs each of its attributes with one value, so a missing one is an outage. On OpenLDAP a missing attribute of the account means "not set" when the sentinel of the same read (LR-14) shows every attribute of LR-22, which shows that the password policy overlay is active and that the lookup account can read those attributes; otherwise the read is an outage. For `pwdStartTime`, `pwdEndTime` and `pwdReset` the page says so: "If this attribute does not exist, then no restriction applies", "then this restriction does not apply", and "If the attribute does not exist, or is set to "FALSE"," no change is required [OL-PP]. For `pwdAccountLockedTime` the page does not say, and the adapter reads a missing value as no lock (P7). `active` is reported only when the sentinel passed and every rule of the map returned a definite negative. *Basis: profile; source [OL-PP] for three attributes; to probe (P7) for `pwdAccountLockedTime`.*

**LR-24. Missing account.** A read by unique id that ends in `success` with no entry, with the sentinel passed, reports `account_state` `absent` and an empty group list, so a requirement fails (`FAIL`, `INVALID_CLAIM`). Without a passed sentinel it is an outage, since a hidden entry looks the same (LR-14). *Basis: profile.*

## Appendix F. Freshness declarations

The freshness profile defines the vocabulary and the arithmetic. This appendix fixes how the LDAP adapter fills them.

**LR-25. Times and source reference.** The observation time and the status check time of a directory read are the same instant, the as-of instant: the adapter's clock reading immediately before it sends the search that returns the value (the answer reflects the server at or after that instant). For a replicated topology the as-of instant is the send time minus `replication_bound_seconds`, unless a replication watermark is read, which is to probe (P9); this follows [`freshness.md`](../freshness.md) §4.1 (the directory row) and §4.2, convention 1. The adapter never reports the bare read time of a replica. The `SourceID` is that of section 2. The `SourceRef` is `{unique_id}@{as-of seconds}`: each read is a new source record with a new observation time, and a new observation time needs a new reference ([`freshness.md`](../freshness.md) §7). The principal path takes both times from the authentication time. *Basis: draft §8.3, §17.2, profile.*

**LR-26. Declared bounds.** A realm record has a topology. `single-server` means one server takes every change and answers every read: one OpenLDAP provider, or one Active Directory domain controller with no replication partner; Active Directory accepts changes at every domain controller and replicates each originating update to others [AD-REPL], so a domain with several controllers is `replicated`. `replicated` means anything else: OpenLDAP consumers, in which "the consumer polls" at an `interval` or listens, and where an interval of a day is shown as an example [OL-AG §18.1.1, §18.3]; several domain controllers; a load-balanced name. A `replicated` realm declares `replication_bound_seconds`, at least 1: the longest time between a change at the server that takes it and its visibility at the server the adapter reads. The adapter publishes `max_age_seconds` and `status_max_age_seconds` as the bound plus the cache bound (LR-27), rounded up to whole seconds, as [`freshness.md`](../freshness.md) §4.2 asks. A requirement whose limit is smaller is unachievable and ends in `UNSUPPORTED_REQUIREMENT`, `DEFERRED`; a realm with no declared bound has no achievable finite limit. This profile publishes no number for a `replicated` realm, for these reasons that documentation gives: OpenLDAP consumers lag by their synchronization interval; the password-policy attributes written by an authentication on a replica are in general not propagated to the provider, a behavior the manual page says is not guaranteed [OL-PP]; multi-provider replication "breaks the data consistency guarantees of the directory model" and mirror mode keeps writes on one provider [OL-AG §18.2.2.3, §18.2.3]; Active Directory's initial change notification delay defaults to 15 seconds and the delay between later partners to 3 seconds, under the conditions the page states for Windows Server 2003 controllers, a lockout is replicated urgently to the PDC emulator and some sites, and an unlock is not replicated urgently [AD-REPL]. The measured values are to probe (P8). *Basis: source, profile; to probe (P8).*

**LR-27. No cache by default.** The adapter caches no state or membership read. A deployment that caches declares `cache_bound_seconds` of at least 1, the adapter then reports the as-of instant of the cached read and never restamps it, and the published limits include the cache bound (`freshness.md` §4.2, convention 3). *Basis: draft §9.2, profile.*

**LR-28. Outage.** A required directory or registry that cannot answer is `UNKNOWN` with `DEPENDENCY_UNAVAILABLE` and the decision `DEFERRED`; no last-known-good answer is served beyond a declared bound (draft §18, [`freshness.md`](../freshness.md) §5). *Basis: draft, profile.*

**LR-29. The enrollment source.** The registry is read for each evaluation, with status staleness 0 (identity mapping §7.5). The directory is not the enrollment source: a directory attribute never marks a binding revoked or compromised (IM-13, IM-27). *Basis: profile.*

**LR-30. Timeouts.** Every directory request has a client time limit, and no evaluation waits beyond its deadline (draft §12.2; [`freshness.md`](../freshness.md) §5). *Basis: draft, profile.*

## Appendix G. Requirement cases

| ID | Requirement | Input | Adapter result | Admission effect | Rules |
|---|---|---|---|---|---|
| LDAP-01 | Empty bind | Name with an empty password | Native denial `NO_CREDENTIAL` before any directory request | Native authentication fails (`INVALID_PROOF`); no evaluation starts | LR-5, LR-6 |
| LDAP-02 | Disabled account | State attributes say disabled | `account_state` `disabled` | `FAIL`, `INADMISSIBLE` (`INVALID_CLAIM`) | LR-20 to LR-23 |
| LDAP-03 | Missing account | No entry for the login name; or the entry deleted after authentication | Denial `CREDENTIAL_REJECTED`; or `absent` with the sentinel passed | Authentication fails; or `FAIL`, `INADMISSIBLE` (`INVALID_CLAIM`) | LR-11, LR-24 |
| LDAP-04 | Duplicate names | One name matching two entries | Denial `CREDENTIAL_REJECTED`, no entry chosen | Authentication fails | LR-11 |
| LDAP-05 | Unsupported groups | Nested path in a realm with nesting `none`, or an `ad-chain` realm whose nested sentinel fails | Unsupported-requirement error | `UNKNOWN`, `DEFERRED` (`UNSUPPORTED_REQUIREMENT`) | LR-17 |
| LDAP-06 | Denied lookup | Attribute or entry hidden from the lookup account | Dependency-unavailable error (the sentinel fails) | `UNKNOWN`, `DEFERRED` (`DEPENDENCY_UNAVAILABLE`) | LR-14, LR-19, LR-23 |
| LDAP-07 | Outage | Directory unreachable, TLS or lookup bind failing, timeout | Dependency-unavailable error | `UNKNOWN`, `DEFERRED` (`DEPENDENCY_UNAVAILABLE`) | LR-4, LR-13, LR-28 |
| LDAP-08 | Removed membership | Group no longer in the list | List without the group | `FAIL`, `INADMISSIBLE` (`INVALID_CLAIM`) | LR-16, LR-17 |
| LDAP-09 | Same name, other realm | Group of the same display name in another realm | Identifiers differ by `realm_id` | Not equal | LR-2 |
| LDAP-10 | Lookup authority | Lookup account as principal, executor, or enrollment actor | Denial at authentication; never passed to native calls | `FAIL` (`EXECUTOR_MISMATCH`) if offered as executor | LR-13 |

A stub that maps a login name or a group by `cn` and ignores the realm fails LDAP-04 and LDAP-09 and is the mutant those two cases are written against.

## Appendix H. Open items to probe

No rule depends on an unprobed behavior. Each probe states what to run and what each outcome changes.

| ID | Open item | Probe | If the outcome differs |
|---|---|---|---|
| P1 | What Active Directory DS does with a simple bind that has a name and a zero-length password; the pages read cover only AD LDS | Bind with a valid DN and an empty password, then run Who am I? or a read that needs authentication | None: LR-6 rejects the empty password before it is sent |
| P2 | Which OpenLDAP 2.6 option allows the unauthenticated bind: the guide names `allow bind_anon_cred` ([OL-SEC §14.3.1]) and slapd.conf(5) says `bind_anon_cred` allows an anonymous bind with non-empty credentials and `bind_anon_dn` allows an unauthenticated bind when the DN is not empty [OL-CONF] | Bind with a name and an empty password with each option off and on | None: LR-6 does not rely on the server. The probe corrects the guide or the manual page |
| P3 | The byte order of `objectGUID` on the wire against the text form that Active Directory accepts in the name of a bind (`{...}` in the dashed form of RFC 4122 §3 [MS-SIMPLE]); the GUID structure is in [MS-DTYP-GUID], the wire order for LDAP was not read | Read `objectGUID` of an account with a known password, derive the text, bind with the name `{text}` and the password, compare the bound entry | An `activedirectory` realm stays disabled until the conversion is pinned |
| P4 | Which Windows Server versions support `1.2.840.113556.1.4.1941`, and whether the rootDSE lists it | Run the chain query on the sentinel (LR-14) and read the rootDSE | LR-17 already proves the rule by the sentinel and does not read the rootDSE |
| P5 | Whether the target OpenLDAP 2.6 release answers the chain filter with an empty result, as RFC 4511 §4.5.1.7 requires for an unrecognized rule | Send the chain filter for a known nested member | None: nesting is `none` for OpenLDAP |
| P6 | Whether `UF_LOCKOUT` in `msDS-User-Account-Control-Computed` follows a lockout that has lapsed by `lockoutDuration`, and is returned to the lookup account when requested | Lock and wait out a test account, read the attribute | If it does not follow, `locked` fails closed for a lapsed lock |
| P7 | Whether a lapsed temporary lock clears `pwdAccountLockedTime`, and the effect of `pwdLockout` FALSE on the attribute | Lock a test account with a short `pwdLockoutDuration`, read before and after | As P6 |
| P8 | The replication bound of each topology: Active Directory sites and links (changes of `userAccountControl` and `member`, lockout and unlock on a domain controller that is not the PDC emulator), and OpenLDAP consumers (the `interval` and the persist mode) | Change a test account at the originating server and poll the answering server | The measured value becomes the realm's `replication_bound_seconds` |
| P9 | Whether the `contextCSN` of a consumer's suffix entry [OL-AG §18.1.1.2] carries an instant that can serve as the as-of instant | Read it before and after changes at the provider | LR-25 keeps the declared bound |
| P10 | Whether `memberOf` lists the primary group in Active Directory, and which memberships a domain controller returns across domains and for domain-local and universal groups | Read `memberOf` of an account whose primary group is not `Domain Users`, and of an account with a universal group of another domain | The primary group and cross-domain membership stay unsupported |
| P11 | Whether each directory lists Who am I? (`1.3.6.1.4.1.4203.1.11.3`) in `supportedExtension` | Read the rootDSE | Without it LR-8 rests on the bind result alone |
| P12 | The access level that is the equivalent of `search` and `read` in Active Directory, how each directory hides an entry or an attribute (`noSuchObject`, `insufficientAccessRights`, silent omission), and that OpenLDAP omits an attribute silently | Grant and withdraw access for a test account and compare the answers | The sentinel assumes silent omission; a signalled denial is an outage |
| P13 | Whether `security simple_bind=<ssf>` on the target OpenLDAP release makes slapd refuse a simple bind over an unprotected connection ([OL-SEC §14.3.1] says it requires the stated protection) | Bind without TLS with the setting on | None: LR-4 does not rely on the server |
| P14 | The server size and time limits and the paged results control for large group lists | Run the nested query for an account with many groups | A truncated list stays an outage (LR-15) |

## Appendix I. Sources and reference implementation

### Sources read for this profile (retrieved 2026-10-16)

| Label | Source |
|---|---|
| RFC 4511, 4512, 4513, 4515, 4516, 4517, 4519, 4522, 4530, 4532, 4013 | RFC Editor, `https://www.rfc-editor.org/rfc/rfc<number>.txt`; sections are cited inline |
| OL-AG | OpenLDAP Software 2.6 Administrator's Guide, chapters Access Control (8), Overlays (12), Security Considerations (14), Replication (18), `https://www.openldap.org/doc/admin26/` |
| OL-AC, OL-SEC | The Access Control and Security Considerations chapters of OL-AG |
| OL-PP | slapo-ppolicy(5), OpenLDAP 2.6.15, `https://www.openldap.org/software/man.cgi?query=slapo-ppolicy&sektion=5&manpath=OpenLDAP+2.6-Release` |
| OL-MEMBEROF | slapo-memberof(5), OpenLDAP 2.6.15, same site with `query=slapo-memberof` |
| OL-CONF | slapd.conf(5), OpenLDAP 2.6.15, same site with `query=slapd.conf` |
| MS-UAC, MS-UACC, MS-OBJGUID, MS-EXP, MS-LOCK, MS-LOCKDUR, MS-PWD, MS-TG, MS-MEMBEROF, MS-PGID | Microsoft Learn, Active Directory Schema pages `https://learn.microsoft.com/en-us/windows/win32/adschema/` for `a-useraccountcontrol`, `a-msds-user-account-control-computed`, `a-objectguid`, `a-accountexpires`, `a-lockouttime`, `a-lockoutduration`, `a-pwdlastset`, `a-tokengroups`, `a-memberof`, `a-primarygroupid` |
| MS-FILTER | Microsoft Learn, Search Filter Syntax, `https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax` |
| MS-AUTHM, MS-SIMPLE, MS-ANON, MS-TLS, MS-CFG | Microsoft Learn, [MS-ADTS] sections 5.1.1.1 (Supported Authentication Methods), 5.1.1.1.1 (Simple Authentication), 5.1.3 (Authorization), 5.1.1.2 (Using SSL/TLS), and LDAP Configurable Settings, under `https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/` |
| MS-DTYP-GUID | Microsoft Learn, [MS-DTYP] 2.3.4.1, GUID, RPC IDL representation |
| AD-REPL | Microsoft Learn, How the Active Directory Replication Model Works (Windows Server 2003 documentation), `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772726(v=ws.10)` |

### Reference implementation (informative)

The profile is language-neutral. The Go packages below exist and are what an implementation of it uses; the LDAP adapter of the reference implementation is `go/adapters/ldap`, on `github.com/go-ldap/ldap/v3`.

| Need | Go name | Behavior this profile relies on |
|---|---|---|
| The seven functions and the descriptor | `adapter.Adapter`, `adapter.Descriptor{Protocol, Version, MappingRevision}` | The descriptor of this profile is `ldap`, `3`, `pact-ldap-1` |
| `authenticate_native` | `adapter.NativeAuthenticator.AuthenticateNative`, `adapter.Principal`, `*adapter.NativeDenial` with `adapter.DenialNoCredential` and `adapter.DenialCredentialRejected` | A denial is `INVALID_PROOF`; the public reasons are closed; an outage wraps `adapter.ErrDependencyUnavailable`. `Principal.ID` and `Workload` carry the identifier of LR-2 |
| `read_native_claim` | `adapter.ClaimReader.ReadNativeClaim`, `adapter.NativeClaim{Value, ObservedAt, StatusCheckedAt, SourceID, SourceRef}` | An unapproved path wraps `adapter.ErrUnsupportedRequirement`; an unreachable source wraps `adapter.ErrDependencyUnavailable`; the adapter never restamps `ObservedAt` |
| `resolve_agent_binding` | `enroll.Resolver`, `enroll.Registry.Lookup`, `enroll.Actor` with `enroll.Admin` and `enroll.AuthorizedIssuer`, and `memory.Registry` in `adapter/enroll/memory` | An agent actor has no authority. `Lookup` selects the record of the presented agent ID on the authenticated workload; an agent with no record there, including one enrolled only for another workload, returns `adapter.BindingUnknown` |
| Freshness | `freshness.Evaluate`, `freshness.Evaluator`, `freshness.Monotonic` | Reason codes `Satisfied`, `StaleEvidence`, `ClockAhead`, `Restamped`, `UnsupportedRequirement`, `DependencyUnavailable`; a limit of zero means a time not before the evaluation start |
| Error codes | `adapter.CodeOf`, `adapter.ErrContextMismatch` | A principal that is not an `ldap:` identifier of a configured realm wraps `adapter.ErrContextMismatch` (LR-12) |
