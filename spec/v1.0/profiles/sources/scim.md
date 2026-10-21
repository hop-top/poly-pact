# PACT source document: SCIM 2.0 service provider as a membership and status source

This document targets spec version 1.0 and wire version 0.1 and is a draft. It describes one membership and status source, a SCIM 2.0 service provider that an identity provider provisions into. It is not an integration profile: it makes no gateway claim, so it has no `profile.json`. An integration profile that reads group memberships and account state from such a service embeds the row of section 4 in its template subsection 8.1 and records `scim` in the row's `source_document` ([`TEMPLATE.md`](../TEMPLATE.md), 8.1).

## Document header

| Field | Value |
|---|---|
| Source name | `scim`: SCIM 2.0 (RFC 7643, RFC 7644) service provider, provisioned by an identity provider |
| Implementation | package `adapter/source/scim` of the Go library, on the shared source package `adapter/source` |
| Spec version, wire version | `1.0`, `0.1` |
| Document revision, date | `1`, 2026-10-18 |
| Reference documents | draft = [`draft.md`](../../draft.md); freshness = [`freshness.md`](../freshness.md); identity mapping = [`identity-mapping.md`](../identity-mapping.md); cases = [`../../fixtures/sources/README.md`](../../fixtures/sources/README.md); RFC 7643, RFC 7644, RFC 6750 |

## 1. Scope and boundary

A SCIM service provider is the receiving end of a protocol the identity provider pushes. The integration operates the service. The identity provider's provisioning client creates, modifies and deletes users and groups in it, and the service keeps, for each user it can join to a principal, two facts: the account state and the group list. It answers the draft 17.1 function `read_native_claim` from those facts (draft 9.2, 17.2, 18). The provisioning requests are the source's change feed (`TEMPLATE.md`, 8.1, `change_feed.mode` `push`). The service never calls the identity provider, and it is not a way to authenticate a request: the principal comes from the authenticating mechanism of the integration profile (for Microsoft Entra ID, an access token, the `oauth` profile), and this source supplies facts about that principal.

The source offers the facts `groups` and `account_state`. It does not offer `identity`, `roles` or `live_check`.

**What this document cites.** A statement about SCIM cites the RFC and section. A statement about what Microsoft Entra ID does cites a Microsoft Learn page, read on 2026-10-18, and is vendor behaviour that can change without a PACT revision; section 8 lists what a deployment must re-check. No other identity provider was read. Where a statement could not be established from a source read for this document, it is an explicit open item in section 9, not a rule.

| Source | Pages read |
|---|---|
| IETF | RFC 7643 sections 2.1, 3.1, 4.1.1, 4.1.2, 4.2, 5; RFC 7644 sections 2, 3.3, 3.4.2, 3.5.2, 3.6, 3.12, 4, 7.2, 7.4; RFC 6750 sections 2.1, 3 |
| Microsoft | "Tutorial: Develop and plan provisioning for a SCIM endpoint in Microsoft Entra ID" (`https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups`); "How provisioning works" (`https://learn.microsoft.com/en-us/entra/identity/app-provisioning/how-provisioning-works`); "Tutorial: Test your SCIM endpoint with the SCIM Validator" (`https://learn.microsoft.com/en-us/entra/identity/app-provisioning/scim-validator-tutorial`) |

## 2. Facts of the protocol and of the vendor

| # | Statement | Source |
|---|---|---|
| P1 | `id` is issued by the service provider, is not specified by the client, is unique, stable and not reassigned. | RFC 7643 3.1 |
| P2 | `externalId` is issued by the provisioning client, scoped to the client's provisioning domain, and its uniqueness is controlled by the client. The RFC does not say that it is immutable. | RFC 7643 3.1 |
| P3 | `meta.lastModified` is when the resource was last updated at the service provider. It is not the time the state became true at the identity provider. | RFC 7643 3.1 |
| P4 | `userName` is required and unique, and `active` is the user's administrative status, the meaning of which the service provider determines. | RFC 7643 4.1.1 |
| P5 | `groups` of a User is read-only; group membership changes through the Group resource, whose `members.value` is the `id` of a member. | RFC 7643 4.1.2, 4.2 |
| P6 | The authentication scheme is outside the protocol; a bearer token MAY be used with TLS and a token framework; the service provider validates the token. | RFC 7644 2 |
| P7 | 401 means the authorization header is invalid or missing; 403 means the operation is not permitted by the supplied authorization; a duplicate create is 409 with `scimType` `uniqueness`; 413 is the listed status for a payload that is too large. | RFC 7644 3.12, Table 8; 3.3 |
| P8 | Remove with a value filter on a multi-valued attribute removes the matching values; removing a member that is not in the group is a success; a PATCH is atomic. | RFC 7644 3.5.2, 3.5.2.2 |
| P9 | DELETE is 204; every later operation on the resource is 404, and the resource is omitted from query results. | RFC 7644 3.6 |
| P10 | The service provider MUST support TLS 1.2. | RFC 7644 7.2 |
| P11 | The `WWW-Authenticate` challenge carries the scheme `Bearer`; it carries an `error` of `invalid_token` for a token that failed and `insufficient_scope` for a token with too few privileges, and carries no error for a request without credentials. | RFC 6750 3, 3.1 |
| P12 | Neither RFC defines a change notification or event feed. | RFC 7643, RFC 7644 (none found) |
| V1 | Entra ID runs a provisioning cycle that "occur[s] approximately every 40 minutes as long as the service is running". | Microsoft, SCIM tutorial, Authorization section |
| V2 | A user removed from scope, unassigned, disabled or soft-deleted in Entra ID is disabled in the target by an update; a user hard-deleted in Entra ID (30 days after the soft delete) is deleted in the target. | Microsoft, How provisioning works |
| V3 | A failed change is retried in the next cycle; a quarantined job gradually reduces its incremental cycles to once per day. | Microsoft, How provisioning works |
| V4 | The tutorial's example attribute mapping maps the Entra attribute `mailNickname` to the SCIM `externalId` and `IsSoftDeleted` to `active`; its matching example queries `externalId` against the user's `mailNickname`, and it says the attribute used for matching is configurable. | Microsoft, SCIM tutorial |
| V5 | Entra ID emits `op` as `Add`, `Replace` and `Remove`, and asks service providers not to require a case-sensitive match. | Microsoft, SCIM tutorial |
| V6 | Entra ID disables a user with `PATCH` `{"op": "Replace", "path": "active", "value": false}`, and removes group members with `{"op": "Remove", "path": "members", "value": [{"value": "<id>"}]}`. | Microsoft, SCIM tutorial |
| V7 | The connection test queries for a user that does not exist and expects 200 with an empty ListResponse. | Microsoft, SCIM tutorial |
| V8 | The provisioning service cannot read or provision users in nested groups. | Microsoft, How provisioning works |
| V9 | Authentication to the SCIM endpoint is by a long-lived bearer token, by OAuth 2.0 client credentials, or by workload identity federation. | Microsoft, SCIM tutorial |
| V10 | The Microsoft SCIM Validator requires an Entra account with an active subscription and a reachable endpoint, and lists "Soft deletes (disables) aren't yet supported" as a known issue. | Microsoft, SCIM Validator tutorial |

## 3. The endpoint

**SC-1. Resources and methods.** The service serves `/Users` and `/Groups` under a configured base path, with POST (create, 201 with `Location` and `meta.location`), GET of one resource and GET of a list with `filter`, `startIndex` and `count`, PATCH (200 with the resource) and DELETE (204). A GET of a list with a filter that matches nothing is 200 with an empty ListResponse (V7). A filter is one equality comparison `attribute eq "value"`: on a user, `userName` (case-insensitive, P4) or `externalId` (exact); on a group, `displayName` (case-insensitive) or `externalId`. Any other filter is 400 `invalidFilter`. The public `/ServiceProviderConfig` is served (RFC 7644 4; RFC 7643 5 asks for the authentication schemes to be public) and states that PATCH and filter are supported and that bulk, sort, ETag and password change are not. *Basis: P1, P4, P7, P9; RFC 7644 3.3, 3.4.2, 3.5.2, 4.*

**SC-2. A create states what it needs.** A User needs `schemas` with the core User schema and a non-empty `userName`; a Group needs the core Group schema and a non-empty `displayName`. A malformed body, a body with duplicate member names, or one with an invalid type for `externalId`, `displayName` or `active` is 400 (`invalidSyntax` or `invalidValue`). A `null` attribute is not asserted. The service issues the `id` and ignores one the client sends (P1). A `userName` held by another user, compared without case, and an `externalId` held by another user or, for a group, by another group, is 409 `uniqueness` (P7); the second record is not created. The uniqueness of `externalId` is the service's rule for the join of section 5, not a protocol rule (P2). *Basis: P1, P2, P4, P7.*

**SC-3. PATCH.** A PATCH body has `schemas` with the PatchOp URN and a non-empty `Operations` list of `add`, `remove` or `replace`, in any letter case (V5). The service applies the operations in order, as a whole or not at all: an operation that fails leaves the resource, and the facts, as they were (P8). On a user it handles `active`, `externalId`, `userName` and `displayName`, with a path or as an attribute object with no path. A value of `active` that is not a JSON boolean is 400 `invalidValue`, and a string such as `"False"` is not read as a boolean. Removing `userName` is 400 `mutability`; removing `active` leaves the account state unknown (section 6). On a group it handles `displayName`, `externalId` and `members`: `add` adds the listed members, `replace` replaces them, `remove` with a path `members[value eq "<id>"]` removes that member, and `remove` of `members` removes the members that its value lists (V6) or, with no value, all of them (RFC 7644 3.5.2.2). A value filter on `add` or `replace` is 400 `invalidPath`. A member is a User of this service; a group id or an unknown id is 400 `invalidValue` (V8). Removing a member that the group does not list is a success (P8). A PATCH to any other attribute is accepted and ignored: the facts do not depend on it, and a provisioning client sends many. *Basis: P5, P8, V5, V6, V8.*

**SC-4. DELETE.** Deleting a user removes its facts before it removes the record, so that a store failure leaves a record a retry can delete. It removes the user from every group. Deleting a group removes its id from the facts of every member. Both are 204; a repeat is 404 (P9). *Basis: P9.*

**SC-5. A change reaches the facts before the response.** A create, PATCH or DELETE that changes a user, a group or a membership publishes the facts of every user it affects before the service answers. If the store cannot take a write, the response is 500; a create is rolled back, a delete keeps the record, and a retry of a PATCH republishes whether or not it changes anything, so that a retry always repairs the facts. *Basis: draft 18 (a revocation visible at the next read), freshness 4.1.*

**SC-6. Not served.** PUT (501), bulk, sorting, ETags, `/Schemas`, `/ResourceTypes`, the `attributes` and `excludedAttributes` parameters, and any attribute other than those of SC-3. The service holds no other attribute of a user and returns none.

## 4. Authentication

**SC-7. Bearer authentication.** Every request except `/ServiceProviderConfig` needs `Authorization: Bearer <token>`, and the service accepts only tokens it was configured with. A request with no `Authorization` header, or with another scheme, is 401 with `WWW-Authenticate: Bearer realm="scim"` and no `error`. A bearer token the service does not know is 401 with `error="invalid_token"`. A known token whose credential does not carry the provisioning right is 403 with `error="insufficient_scope"`. The check runs before routing, so a client with no valid token learns nothing about which paths or ids exist. A rejected request changes nothing. The token is compared in constant time against every configured token. *Basis: P6, P7, P11; RFC 6750 2.1.*

**SC-8. TLS.** The handler does not terminate TLS. The deployment serves it over TLS 1.2 or later (P10) so that a token is never sent in the clear (RFC 7644 7.4). Plain HTTP in front of a TLS-terminating proxy is the deployment's decision and is outside this document. *Basis: P10.*

**SC-9. What the token proves.** The service has a list of configured secrets. It does not validate an Entra-issued JWT (V9, OAuth client credentials and workload identity federation present a signed token the service would have to validate against the issuer's keys). A deployment that uses those methods puts a token-validating front end ahead of the handler, or uses the long-lived bearer token. Entra ID itself says a long-lived token is the less secure method (V9). *Basis: P6, V9.*

## 5. Join of a record to a principal

A SCIM record names no principal. The `id` is the service provider's own identifier (P1) and the `userName`, `emails`, `displayName` and `name` are attributes a user or an administrator can change (P4).

**SC-10. Join.** The service joins a provisioned record to a principal by a single declared join attribute whose value is the immutable local part of the principal's identifier in the authenticating mechanism's namespace (identity mapping IM-5), with the namespace and realm components taken from the service's configuration, never from the record (IM-4). The join attribute is `externalId`. For an Entra ID tenant feeding a SCIM endpoint the deployment maps `externalId` from the object identifier of the Entra user (`objectId`, the `oid` of the access token), not from `mailNickname`, which the tutorial's example mapping uses (V4) and which is a mutable name; a deployment that keeps that mapping does not satisfy this rule. The principal is `oauth:{issuer-id}:{tenant}:{externalId}` under IM-2, with `issuer-id` and `tenant` from the configuration (`oauth` profile, OAUTH-37). `userName`, `emails`, `displayName`, `name`, the SCIM `id` and any attribute the user can change never join. *Basis: IM-4, IM-5, IM-2; draft 8.5.*

**SC-11. A record that cannot join.** A record whose `externalId` is absent or empty joins no principal and answers no fact. The service holds the record and logs it as a provisioning error. Another record cannot hold the same `externalId` (SC-2), so one principal has one record. A change of `externalId` moves the facts: those of the old principal are removed and those of the new one are written. *Basis: IM-5; draft 9.2 (an absent value fails the rule).*

**SC-12. Spelling.** The local part of the principal is the `externalId` exactly as the identity provider sent it, written under IM-2. The service does not fold case. Entra ID writes an `objectId` as a lower-case hyphenated UUID, which is also the form of the `oid` claim ([`../oauth/profile.md`](../oauth/profile.md), OAUTH-37); a deployment whose provisioning writes another case does not join.

**SC-13. Groups.** A group is named in a user's facts by its `externalId`, which the identity provider's group mapping fills from the group's object identifier, never by its `displayName` or by the SCIM `id`. A group without an `externalId` contributes no id and is logged. *Basis: IM-5.*

## 6. Facts

| Native path | Value | Source |
|---|---|---|
| `/principal/account_state` | `"active"` when the user's `active` is true, `"disabled"` when it is false. No fact when `active` was never asserted or was removed. | `active` (P4) |
| `/principal/group_ids` | The array of the `externalId` of each group that lists the user as a member, sorted in byte order. `[]` when the user is in no group that has an `externalId`. | Group `members` (P5) |

Both facts carry the SCIM `id` of the user as `SourceRef` and the configured source ID as `SourceID`. The vocabulary of `account_state` is that of the `ldap` profile (LR-20) restricted to the two values SCIM can state; a requirement that names `active` is satisfied by `"active"` only. A disable (V2), a removal of a member and a delete are visible to the next read after the request that carried them (SC-5). A principal whose record was deleted answers no fact: the read is `MISSING_FIELD` (draft 9.2), and the same for a principal the service never joined.

## 7. Freshness

**SC-14. As-of time.** SCIM carries no as-of time. A push protocol has no "cycle complete" message, and `meta.lastModified` is when a record last changed (P3), not the instant at which the state is known to reflect the identity provider. The service therefore reports, for both `ObservedAt` and `StatusCheckedAt`, the read time minus the declared lag, never the read time and never the time of the last push (freshness 4.1, directory row; 4.2, convention 1). It does not use `meta.lastModified`.

**SC-15. The declared lag.** The deployment declares the lag. It is at least one provisioning cycle of the identity provider: 2400 seconds for Entra ID (V1). A deployment declares one cycle only when it monitors provisioning health and reports the source unavailable (`DEPENDENCY_UNAVAILABLE`, freshness section 5) while the connection is quarantined or the last successful cycle is older than the lag; otherwise it declares the quarantine bound, 86400 seconds (V3). The service refuses a lag below one second, because a pushed source has no live check. A rule whose `status_max_age_seconds` is below the declared lag is `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`: the validator compares the rule with the declared bound before it reads (freshness 4.2, convention 2; draft 17.2), and the source reports an age of exactly the lag so that no claim from it can pass such a rule on the claim's times.

**8.1 row for an integration profile.** The row an integration profile embeds, with `source_document` `scim`:

| Source | `facts` | `live_check.available` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|
| SCIM provisioning endpoint (groups and account state pushed by the identity provider) | `groups`, `account_state` | `false` | `push` | Inbound SCIM 2.0 provisioning requests from the identity provider; Entra ID runs a provisioning cycle about every 40 minutes, retries a failed change at the next cycle, and reduces a quarantined connection to one cycle per day | The declared lag: 2400 for Entra ID under SC-15, otherwise 86400 | `cached_snapshot` |

**What this means for a revocation bound.** A removal from a group, a disable and a delete in the identity provider reach this source with the provisioning client's next cycle (V2), plus the time the cycle takes. The source is fit for provisioning, where a membership is allowed to lag by a cycle. It is not, alone, fit for a tight revocation bound: no rule with a status bound under the declared lag can be met from it. A deployment that needs a tighter bound for a revocation reads an authoritative source for that fact (the directory's live check, token introspection, or a signal receiver) in addition.

## 8. Residual limits

| Limit | Effect |
|---|---|
| The lag is a declaration, not a measurement. | The service cannot see the identity provider's cycle. A deployment that declares one cycle without monitoring it reports ages that are too small during an outage (SC-15). |
| `externalId` immutability is a deployment setting (P2, SC-10). | A deployment whose mapping sources `externalId` from a mutable attribute lets a rename reassign a principal's facts. The service refuses an `externalId` held by two users, but it cannot tell that a name is mutable. |
| Nested groups are not provisioned by Entra ID (V8) and are refused by the service (SC-3). | A membership through a nested group is not a fact of this source. |
| The service keeps its state in memory. | A restart loses every record and every fact. Reads then answer no fact (`MISSING_FIELD`, a failing rule, never a pass) until the identity provider provisions again; an incremental cycle may not send an unchanged user again, so a restart needs a full re-provisioning. |
| The service holds the attributes of SC-3 only. | A provisioning client that checks a round trip of other attributes sees none returned. |
| A static bearer token (SC-9) is a long-lived secret. | The deployment rotates it. |
| The identity provider can be sound and the endpoint still be wrong in what the validator checks (section 9). | Section 9, item 1. |

## 9. Open items

1. **Microsoft SCIM Validator run.** The validator needs an Entra account with an active subscription and an endpoint reachable from Microsoft's service (V10). This repository has neither, and the validator run is not claimed. The local cases below cover the protocol steps the validator's documentation lists (create, get by filter, patch active, patch group members, delete, bad token) against this implementation, but not the validator's own checks. The known gap of the validator (disables are not supported, V10) means the disable case is covered locally in either event. Closing this item is a recorded validator run against a deployed endpoint, by the owner.
2. **Entra `objectId` mapping.** That the Entra attribute mapping can source `externalId` from `objectId`, and the spelling Entra writes, are not established from a page read for this document (V4 shows an example mapping that uses `mailNickname` and says only that the matching attribute is configurable). To probe in a live tenant: provision one user and compare the `externalId` received with the `oid` claim of that user's access token.
3. **Entra request forms.** The forms of V5 and V6 are those of the Microsoft pages. The forms of a live tenant, including a `PATCH` that carries `active` as a string and the order of the operations of a group update, are to probe; the service answers a string `active` with 400 (SC-3) and the provisioning job then records an error.
4. **Integration profile rows.** An integration profile that reads these facts embeds the row of section 7. The `oauth` profile's row for this source and the sentence of OAUTH-33 about where a membership fact comes from are not part of this document's change; the profile owner adds them.
5. **Other identity providers.** Okta, OneLogin and JumpCloud were not read. Their cycle, retry and attribute behaviour is unknown here. The protocol rules apply unchanged; the lag and the join attribute are the deployment's to declare for them under SC-10 and SC-15.

## 10. Cases

The cases are the files of [`../../fixtures/sources/scim`](../../fixtures/sources/scim), kind `source-case`, run by the harness `adapter/sourcetest` ([`../../fixtures/sources/README.md`](../../fixtures/sources/README.md)) with the driver of the model `scim/1` below. A case builds a fresh service, delivers its steps (HTTP requests), and then reads.

| Case | Tests | Rules |
|---|---|---|
| `SCIM-01.join` | A created user joins the principal built from the prefix and its `externalId`; the user name and e-mail local parts do not | SC-10, SC-11 |
| `SCIM-02.as-of-time` | A fact reports the read time minus the lag, not the time of the push or the read time | SC-14 |
| `SCIM-03.disable` | `active` false by `Replace` with a path and by an attribute object disables the account; an unpatched user stays active | SC-3, SC-5, V6 |
| `SCIM-04.member-removed` | PATCH remove of one member removes that group from the member's list and leaves the other; the list is sorted | SC-3, SC-5, SC-13 |
| `SCIM-05.deleted` | DELETE removes the facts, the SCIM id is 404, and the group no longer lists the user | SC-4, P9 |
| `SCIM-06.bound-below-lag` | A source that declares the quarantine bound reports an age of exactly that bound | SC-15 |
| `SCIM-07.join-by-username-refused` | A user name that spells another user's object id, a record with no `externalId`, and an e-mail local part never join | SC-10, SC-11 |
| `SCIM-08.bad-token` | No token, another scheme and a wrong token are 401 with the right challenge; a token without the right is 403; a rejected request changes nothing | SC-7 |
| `SCIM-09.replay` | A create that repeats an `externalId` or a user name in another case is 409 `uniqueness` and changes nothing | SC-2 |
| `SCIM-10.unserved` | A path the source does not serve is `UNSUPPORTED_REQUIREMENT`; a principal never provisioned is `MISSING_FIELD` | section 6 |
| `SCIM-11.group-forms` | Group members change by add, by remove with a value list, by replace and by remove of all; a group without an `externalId` contributes no id; an unknown member is 400 | SC-3, SC-13 |
| `SCIM-12.join-change` | A change of `externalId` moves the facts; an `externalId` already held is 409 | SC-11, SC-2 |
| `SCIM-13.patch-atomic` | A PATCH with one invalid operation changes nothing | SC-3 |
| `SCIM-14.group-deleted` | DELETE of a group removes its id from its members' lists and leaves the others | SC-4, SC-5 |

Not covered by a case: the cases of section 3 that need no fact (pagination, the filter forms, the methods table, the sizes and the syntax errors) are tests of the Go package, not conformance cases.

### 10.1 Model `scim/1`

A case file is the envelope of [`../../fixtures/sources/README.md`](../../fixtures/sources/README.md) with these members of the model.

`source`:

| Member | Meaning |
|---|---|
| `model` | `scim/1` |
| `source_id` | The source ID of every claim |
| `lag_seconds` | The declared lag (SC-15) |
| `base_path` | The base path of the endpoints, such as `/scim/v2` |
| `join` | `{attribute, prefix}`: `externalId`, and the principal identifier up to its local part (SC-10) |
| `credentials` | `[{token, provisioning}]`: the tokens the service accepts (SC-7) |

A step's `inbound`: `{method, path, query, authorization, body}`. `path` includes the base path, `query` is an object of query parameters, `authorization` is the value of the header and is absent for a request with none, and `body` is the JSON body. A step's `expect`:

| Member | Meaning |
|---|---|
| `status` | The HTTP status of the response |
| `scim_type` | The `scimType` of the error body |
| `challenge` | `{scheme, error}`: the `WWW-Authenticate` value starts with the scheme and carries the `error` auth-param, or none when `error` is `null` |
| `body` | A JSON value the response body contains: every member of an expected object is present with a contained value, arrays have equal length and contain element by element, anything else is equal |
| `save_id_as` | A name for the `id` of the resource the response returns |

A string `${name}` in a later `path`, `query`, `body` or `expect` is the `id` saved as `name`. The service issues its ids, so a case cannot state them. The expected members of a group in a body list only one member, because the order of members is not defined. The service never calls the identity provider, so `must_not_call` names `outbound`.
