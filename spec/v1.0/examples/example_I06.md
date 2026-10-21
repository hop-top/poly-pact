# Integration 06 — LDAP-backed authentication and groups

**Status:** Informative integration example for PACT Protocol v1.0. Organizations, identifiers, routes, requirements, and thresholds are fictional deployment choices. Excerpts are incomplete illustrations, not signed wire fixtures or a tested implementation. The gateway needs the described installed adapter; the named platform is not claimed to support PACT natively.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I06. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- A dedicated directory account is enrolled and the application retains warehouse permissions.
- Its schema/resolver can establish membership/account state at the required age.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C02 | Protected directory authentication, resolver, and lookup authority. |
| C03 | Realm-qualified account/group/key registry. |
| C08 | Inventory authorization under the dedicated account. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G02 | Pin account/group/key namespaces and ambiguous-name handling. | Profile |
| G15 | Define bind/account state, nested groups, lookup access, and replication bounds. Specified for OpenLDAP 2.6 and Active Directory Domain Services by the integration profile [`ldap`](../profiles/ldap/profile.md), whose Appendix G maps each G15 item to rules and cases. | Profile |

### Deliberate simplifications and limitations

- The agent uses its own account; employee delegation is not demonstrated.
- No universal LDAP schema, group expansion, or application entitlement taxonomy is supplied.

### Profile and fixtures

The integration profile [`ldap`](../profiles/ldap/profile.md) states the conformance claim behind this sample: the native-integration part of the gateway, for OpenLDAP 2.6 and Active Directory Domain Services; a simple bind with a non-empty password, over LDAPS or StartTLS only, as the entry that one unique discovery search returned (rules LR-4 to LR-11); the identifier `ldap:{realm_id}:{unique_id}`, with `entryUUID` or `objectGUID` as the unique id, for accounts and groups alike (rule LR-2); a lookup account that is never an actor (rule LR-13); direct groups, and nested groups through the Active Directory in-chain rule only (rules LR-16 and LR-17); and an account-state vocabulary (rule LR-20). Its reference route R1 (`GET /api/v1/warehouses/{warehouse_id}/stock`, action `stock.read`) is illustrative; the inventory application's routes and permissions stay native. The adapter cases are in [`fixtures/adapters/ldap/`](../fixtures/adapters/ldap/README.md), registered in the fixture manifest, and run against a directory built from the seed assets `adapters/ldap/seed` (two OpenLDAP realms) and `adapters/ldap/ad-seed` (one Active Directory realm); the decisions table below names the case group or case for each row. An integration tier runs the cases one OpenLDAP 2.6 server can realize, only when a server is configured; the Active Directory cases run against the unit tier's fake only.

### Validation still required

The cases cover empty and unauthenticated binds, disabled, locked, expired, and reset accounts, duplicate names, unsupported nesting, removal, outages, and the lookup account as principal, executor, or authorizer, at the adapter. These remain unvalidated:

- A live Active Directory domain controller, for every Active Directory case, and the Windows Server version that supports the in-chain rule (probe P4); the `objectGUID` text form, without which an Active Directory realm stays disabled (P3); its handling of an empty-password bind (P1).
- The replication bound of any topology other than one server that takes every change and answers every read, with no cache: replicas, several domain controllers, and lockout replication (P8); without a declared bound no finite freshness limit is achievable.
- Lock expiry (P6, P7), the primary group and cross-domain membership (P10), how each directory hides an entry or attribute from the lookup account (P12), and size and time limits for large group lists (P14).
- That the directory enforces the state it reports, such as a loaded password-policy overlay (profile section 9).
- The bypass paths B1 to B3 (other application logins, direct backend requests, direct use of the lookup credential), which the profile leaves `out-of-claim`.

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Northstar's legacy inventory application authenticates accounts against an LDAP directory. An inventory assistant has a dedicated directory account and belongs to the approved inventory-reader group. It requests stock information for a warehouse that its application account may access.

This sample uses the agent's own native account. Acting for an employee would require an additional, explicitly recognized delegation; it cannot be inferred from a directory group name.

## Native authentication and access

The application authenticates the account using its configured directory workflow over a protected connection. For a password-bind deployment, it rejects empty passwords and verifies that an authenticated user identity was actually established. LDAP supports multiple authentication arrangements; this example does not require a particular directory schema or universal nested-group behavior. The integration profile claims one arrangement: a simple bind with a non-empty password over LDAPS or StartTLS, made as the entry that the lookup found, never as the text the caller typed; anonymous, unauthenticated, and SASL binds are outside the claim (rules LR-4 to LR-7; profile section 6). See [OpenLDAP security guidance](https://www.openldap.org/doc/admin26/security.html).

Directory membership supplies application identity/group facts. The inventory application still decides what those facts permit on each warehouse. Directory ACLs govern which directory entries the application's lookup identity may inspect; they do not automatically become inventory-resource permissions. See [OpenLDAP access controls](https://www.openldap.org/doc/admin26/access-control.html).

## Required profile and mapping

| Profile fact | Gateway rule | Authority | Integration profile |
|---|---|---|---|
| `/attributes/environment/principal_id` | Equals the enrolled directory-account mapping | Authenticated native account and directory realm | Native path `/principal/id`: `ldap:{realm_id}:{unique_id}` of the bound entry (rule LR-2) |
| `/attributes/environment/group_ids` | Contains the required inventory-reader group and is a permitted subset of authoritative membership | Configured directory/group resolver | Native path `/principal/group_ids` (direct groups) or `/principal/group_ids_nested` (with nested groups, Active Directory only), compared with `subset`; a rule names one of them, never both |
| `/attributes/environment/account_state` | Equals `active` | Current authoritative account-state lookup | Native path `/principal/account_state`, one value of the vocabulary of rule LR-20 |
| `/attributes/runtime/isolation` | Satisfies the selected requirement set | Trusted runtime issuer | Outside the profile: evidence, not a directory fact |

Stable account/group identifiers and directory namespaces are preserved. Display names are not sufficient to distinguish two same-named groups in different realms. Group expansion, including any nested groups, is an explicit versioned resolver behavior. Under the integration profile, group identifiers have the form of account identifiers, so a group of another realm never compares equal (`LDAP-09`); nesting is unsupported on OpenLDAP, where a requirement on nested groups ends in `UNSUPPORTED_REQUIREMENT` (`LDAP-05`). The gateway requests only attributes relevant to its requirements.

Enrollment binds the authenticated directory account to the agent ID, operator, and current PACT holder key. LDAP authentication and the PACT signature remain separate checks. Passwords and service-bind secrets are excluded from profiles, receipts, and outcome reports.

## Successful exchange

1. The assistant establishes the application's existing native authenticated session. The application authenticates against LDAP using its supported workflow and maps the account to its native principal.
2. The agent proposes a stock-read operation for warehouse `WH-7` and the recognized replenishment-review purpose.
3. The gateway validates the native session and enrollment, resolves required directory facts, and issues a signed operation-bound PACT contract. The full effective requirements specify the original-fact and status freshness the directory adapter can actually support.
4. The agent fills the required profile view, obtains evidence, and signs the complete presentation with its enrolled holder key.
5. On the actual stock-read request, the gateway verifies request binding, nonce, evidence, field comparison, purpose/task consistency, and current holds. Required native facts are fetched or reused only within their permitted age.
6. Passing requirements produce `ADMISSIBLE`. The inventory system independently checks the account's current warehouse-level permissions and execution conditions before returning data.
7. Gateway and application observations are recorded with distinct admission, authorization, and execution meanings.

If the group resolver uses its own service account, that account's directory-read authority is only a lookup mechanism. It does not replace the requesting agent with a more privileged inventory principal: under the integration profile, the lookup account is refused as a principal, as an executor, and as the subject of `authorize_native` (rule LR-13; `LDAP-10`).

## Decisions and failure variations

| Condition | Expected behavior | Profile case |
|---|---|---|
| Authenticated enrolled account, required group, valid evidence, allowed warehouse | Admit and execute | `adapters/ldap/ldap-01.valid`, `adapters/ldap/ldap-02.active`, `adapters/ldap/ldap-08.member` |
| Correct password but missing enrolled PACT key | Reject agent proof/binding; no protected execution | Evaluation cases `admission/unenrolled-agent` and `admission/old-holder-key` |
| Profile invents group membership | Native comparison fails | The group list that the directory reports, such as `adapters/ldap/ldap-08.removed`; the comparison is the validator's |
| Same group display name in another directory realm | Namespace mapping prevents equivalence | `adapters/ldap/ldap-09.other-realm-group`; the same login in another realm: `adapters/ldap/ldap-09.branch-login` |
| Required account/group state cannot be read | Defer; an empty lookup is not proof of membership or non-membership | `LDAP-06` (hidden from the lookup account), `LDAP-07` (directory unreachable, TLS or lookup bind failing) |
| Group membership was explicitly removed | Fail the corresponding requirement when authoritative state establishes removal | `adapters/ldap/ldap-08.removed` |
| PACT passes, but account cannot read `WH-9` | Native inventory authorization denies | None: the inventory application's own authorization, outside the profile |
| Empty, unauthenticated, or SASLprep-emptied password; empty name | Rejected before any PACT function, with no directory request | `LDAP-01` |
| Account disabled, locked, expired, or due a password change | `account_state` is not `active`, so the requirement fails | `LDAP-02` |
| Unknown login, or an entry deleted after the bind | Native denial, or `account_state` `absent` with no groups | `LDAP-03` |
| Login name matching two entries, or carrying a filter character | Not a unique match: native denial; neither entry is chosen | `LDAP-04` |
| Nested-group requirement on OpenLDAP | `UNSUPPORTED_REQUIREMENT`, `DEFERRED`; never an empty list | `LDAP-05` |
| Lookup account presented as the principal or executor | Refused | `LDAP-10` |

A failed required field and an unavailable source have different decisions: demonstrated missing membership is inadmissible; an unresolved required lookup is deferred. Invalid native authentication is handled before accepting a PACT evaluation.

## Changes, reputation, and learning

The adapter documents directory replication, caching, session invalidation, and group-refresh behavior; the integration profile does so in its sections 8 and 9 and Appendix F. It does not promise instant revocation from every replicated directory: the profile's bound of 0 s holds only for one server that takes every change and answers every read, with no cache, and any other topology declares its own bound. A stale authenticated session cannot claim a fresh group observation. Later operations use the required current checks and fresh PACT exchange.

Directory login, group lookup, and admission are not successful inventory tasks. Only qualified execution and independently assessed task outcomes contribute performance reputation. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, the refused `WH-9` read is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, invalid native authentication is a “Pre-authentication or transport failure” with no `OutcomeReport`, and only “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`) and an “Independent assessment” (`QUALITY`, `task_quality`) count. A required-lookup outage does not automatically count as agent misconduct.

Reputation may vary authorized adaptive evidence requirements, but cannot fabricate a directory group, reactivate a disabled account, or modify the native inventory policy. Required approval follows the application's external workflow and a fresh evaluation after the approval becomes applicable.

## Boundary demonstrated

PACT can consume directory-established identity and membership while the legacy application retains its resource-permission model. There is no requirement to migrate the directory to OAuth or OIDC.

**PACT anchors:** §§4, 6, 8–12, 14–18.

## Primary references

- [OpenLDAP security considerations](https://www.openldap.org/doc/admin26/security.html)
- [OpenLDAP access control](https://www.openldap.org/doc/admin26/access-control.html)
