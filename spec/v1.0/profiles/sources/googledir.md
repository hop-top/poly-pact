# PACT source document: Google Workspace directory as a membership and status source

This document targets spec version 1.0 and wire version 0.1 and is a draft. It describes one membership and status source, a Google Workspace directory read through the Admin SDK Directory API and the Cloud Identity Groups API with a service account that has domain-wide delegation. It is not an integration profile: it makes no gateway claim, so it has no `profile.json`. An integration profile that reads group memberships and account state from a Workspace directory embeds the rows of section 7 in its template subsection 8.1 and records `googledir` in each row's `source_document` ([`TEMPLATE.md`](../TEMPLATE.md), 8.1). The authentication half of the task this source came from is built for Google ID tokens as form G of the `oauth` profile, and not for access tokens; section 10 records the options and what landed.

## Document header

| Field | Value |
|---|---|
| Source name | `googledir`: Google Workspace directory (Admin SDK Directory API, Cloud Identity Groups API), read with a service account under domain-wide delegation |
| Implementation | package `adapter/source/googledir` of the Go library, on the shared source package `adapter/source`; standard library only |
| Spec version, wire version | `1.0`, `0.1` |
| Document revision, date | `1`, 2026-10-19 |
| Reference documents | draft = [`draft.md`](../../draft.md); freshness = [`freshness.md`](../freshness.md); identity mapping = [`identity-mapping.md`](../identity-mapping.md); cases = [`../../fixtures/sources/README.md`](../../fixtures/sources/README.md); sibling sources = [`scim.md`](scim.md), [`ssf.md`](ssf.md); `oauth` profile = [`../oauth/profile.md`](../oauth/profile.md); RFC 7523 |

## 1. Scope and boundary

The source answers the draft 17.1 function `read_native_claim` for three facts of a Workspace user, from the Google APIs (draft 9.2, 17.2, 18):

| Fact | Native path | Value |
|---|---|---|
| Account state | `/principal/account_state` | `"active"` or `"disabled"` |
| Membership, Directory API | `/principal/groups/{group}/member` | boolean |
| Membership, Cloud Identity | `/principal/groups/{group}/transitive_member` | boolean |

It does not offer `identity` or `roles`, a list of the user's groups, or any user attribute. It is not a way to authenticate a request: the principal comes from the authenticating mechanism of the integration profile, and this source supplies facts about that principal (section 10). The groups it serves are the ones its configuration names; any other group is `UNSUPPORTED_REQUIREMENT`.

Two things about the source differ from the SCIM and Shared Signals sources. It reads, so `live_check.available` is `true` and a fact carries the time of the read, not a lag. And the vendor pushes only a hint (section 6): the change feed shortens the time a cached account state takes to be seen, and is never the only way the cache is kept within its bound.

**What this document cites.** Every statement about Google cites a page read on 2026-10-19 (section 12), quoted or marked `(paraphrase)` where the extract of the page was a summary. A statement that no page established is not a rule: it is an item of section 11 with the probe that settles it, and the code fails closed where it matters (a reply with a missing flag, a user the directory resolved to another ID).

## 2. Facts of the vendor

| # | Statement | Source |
|---|---|---|
| V1 | `members.hasMember` is `GET .../admin/directory/v1/groups/{groupKey}/hasMember/{memberKey}`; `groupKey` is the group's address, alias or unique ID; `memberKey` is the user's primary address, alias or unique ID; the reply is `{isMember}`. | Directory API, members.hasMember |
| V2 | "Membership can be direct or nested", but a nested membership is found only when `memberKey` and `groupKey` are in the same domain; to find nested memberships that include entities outside the group's domain the page points to `checkTransitiveMembership` of the Cloud Identity Groups API. | same |
| V3 | `hasMember` accepts any one of these scopes: `admin.directory.group`, `admin.directory.group.member`, `admin.directory.group.member.readonly`, `admin.directory.group.readonly`, and the legacy feeds scope. | same |
| V4 | `checkTransitiveMembership` is `GET https://cloudidentity.googleapis.com/v1/{parent=groups/*}/memberships:checkTransitiveMembership` with a required `query` CEL expression that must include the member specification, for example `member_key_id == 'member_key_id_value'`; for some groups a `member_key_namespace` is also needed. The reply is `{hasMembership}`. The scopes are `cloud-identity.groups.readonly`, `cloud-identity.groups`, `cloud-identity` and `cloud-platform`. | Cloud Identity Groups API, checkTransitiveMembership |
| V5 | The feature is "only available to Google Workspace Enterprise Standard, Enterprise Plus, and Enterprise for Education"; other accounts get 403. A member has membership "as long as there is a single viewable transitive membership"; the caller needs view permission on at least one such membership. | same (paraphrase) |
| V6 | A Directory user has `id` ("The unique ID for the user. A user `id` can be used as a user request URI's `userKey`."), `suspended` ("Indicates if user is suspended"), `archived` ("Indicates if user is archived") and `primaryEmail`. The reference does not call `id` immutable. | Directory API, users resource |
| V7 | The user guide recommends "not using the user email address as a key for persistent data" "because the email address is subject to change"; renaming a user changes the primary address, keeps the old name as an alias and "can take up to 10 minutes to propagate across all services". A user deleted in the last 20 days can be restored by a super administrator, by `id` only. | Directory API, manage users |
| V8 | `users.get`: `userKey` is the primary address, an alias or the unique ID; scopes `admin.directory.user` or `.readonly`. The page does not say what a deleted user returns. | Directory API, users.get |
| V9 | `users.list`: `customer` or `domain` is required; `showDeleted` defaults to false; a page token "is only valid for three days". | Directory API, users.list |
| V10 | Page sizes: users default 100, maximum 500; groups and group members 200. Quota: 2,400 queries per minute per user per Cloud project by default (`403 userRateLimitExceeded`); `429 rateLimitExceeded` is per Workspace account and "can't be increased"; exponential backoff `(2^n) + random_number_milliseconds` with a random part of at most 1000 ms, stopping at n = 5 (about 32 s). | Directory API, usage limits |
| V11 | "there may be a delay of up to 10 minutes before the child group's members appear as members of the parent group"; the API errors on a cycle of memberships. | Directory API, usage limits; manage group members |
| V12 | The Directory API supports push notifications for the Users resource only. | Directory API, push notifications |
| V13 | `users.watch` is `POST .../users/watch` with a channel body: `id` (unique, at most 64 characters), `type` `web_hook`, `address` (HTTPS), optional `token` (at most 256 characters, echoed in a header), optional `expiration` (Unix milliseconds) and `params.ttl` (seconds). The event is one of `add`, `delete`, `makeAdmin`, `undelete`, `update`. | same; users.watch |
| V14 | A channel's lifetime comes from the request or from internal limits and defaults, "the more restrictive value is used"; the page gives no default and no maximum. | same |
| V15 | "there's no automatic way to renew a notification channel": call `watch` again with a new unique `id`; the old and new channels may overlap. A channel is stopped with `POST https://www.googleapis.com/admin/directory_v1/channels/stop` and the channel `id` and `resourceId`; a channel created by a service account can be stopped by any user from the same client. | same |
| V16 | A notification carries `X-Goog-Channel-ID`, `X-Goog-Message-Number`, `X-Goog-Resource-ID`, `X-Goog-Resource-State`, `X-Goog-Resource-URI` always and `X-Goog-Channel-Expiration` and `X-Goog-Channel-Token` sometimes; a user notification body is `{kind: "admin#directory#user", id, etag, primaryEmail}`. After creation a message with state `sync` and message number 1 is sent and may be ignored. Message numbers increase but are not sequential. | same |
| V17 | A 200, 201, 202, 204 or 102 answer is a delivery; with Google's client library a 500, 502, 503 or 504 is retried with exponential backoff; any other status is a failed delivery. The page states no delivery guarantee beyond that. The receiving URL must be HTTPS with a valid certificate. | same |
| V18 | A service account assertion is a JWT with header `alg` `RS256` and `typ` `JWT` and claims `iss` (the service account), `scope` (space delimited), `aud` (the token endpoint), `exp` (at most one hour after `iat`), `iat` and, for delegation, `sub` (the user to act as); it is posted to `https://oauth2.googleapis.com/token` as `application/x-www-form-urlencoded` with `grant_type` `urn:ietf:params:oauth:grant-type:jwt-bearer`. The reply has `access_token`, `token_type` `Bearer`, `expires_in` (3600). | Identity, service accounts |
| V19 | For domain-wide delegation a super administrator authorizes the service account's client ID and a list of scopes in the Admin console (comma delimited there, space delimited in the JWT); the application "cannot access data that the impersonated user themselves cannot access"; a change "usually takes a few minutes". | same |

## 3. Reads

**GD-1. Account state.** A read of `/principal/account_state` is `users.get` of the user ID, and the value is `"disabled"` when `suspended` or `archived` is true and `"active"` otherwise (V6). The vocabulary is that of the `ldap` profile (LR-20) restricted to two values; a requirement that names `active` is satisfied by `"active"` only. A suspended and an archived user are not told apart, because only `active` can satisfy a requirement. A reply without an `id`, `suspended` or `archived` member, or with a member of another type or a duplicate member, is not read as a default: it is `DEPENDENCY_UNAVAILABLE`. A user the directory does not have (404) has no fact: `MISSING_FIELD`.

**GD-2. Membership by `hasMember`.** A read of `/principal/groups/{group}/member` first reads the user (GD-1, GD-4), then calls `hasMember` with the group and the user's unique ID. The value is `isMember`: true for a direct member and for a member of a nested group of the same domain (V1, V2). A suspended or archived user remains a member, so a requirement that needs an active member also names `account_state`. The `member` path reflects the nested-membership delay of V11.

**GD-3. Membership by `checkTransitiveMembership`.** A read of `/principal/groups/{group}/transitive_member` reads the user, takes the user's current primary address from the reply, and calls `checkTransitiveMembership` with the query `member_key_id == '<address>'` (V4). The API's member key is an address, a name that changes (V7), so the address is resolved from the ID at each read and never stored; a rename is seen at the next read, and the join stays on the ID (section 4). An address that holds a quote, a backslash or a control character is refused before any request, because it could end the query's string literal; an empty address is refused. The value is `hasMembership`. The source does not send `member_key_namespace` (open item 4). The API's tier restriction (V5) is a deployment fact: a 403 is `DEPENDENCY_UNAVAILABLE`.

**GD-4. The user ID is verified.** The Directory accepts an address or an alias where the ID goes (V1, V8). The source therefore (a) refuses, before any request, a local part that contains `@`, and (b) refuses a reply whose `id` is not the ID asked for. Either makes the principal a principal without a fact (`MISSING_FIELD`), so that no address and no alias reads the fact of the user it names.

**GD-5. Times.** A live fact carries the time at which the first request of the read was made, for both `ObservedAt` and `StatusCheckedAt` (freshness 4.1, directory row; 4.2, convention 1). The API's reply reflects the directory at an instant between the request and the reply; the earlier instant is the one that is certain. A fact is never stamped with a time later than the read (draft A.2), and the reader's only clock is the configured one.

**GD-6. Errors.** A path or group that is not configured: `UNSUPPORTED_REQUIREMENT`. A principal that is not under the configured prefix, whose local part is not a user ID in its one spelling, or whom the directory does not know: `MISSING_FIELD`. A token endpoint, Directory API or Cloud Identity API that cannot answer (any other status, a transport failure, an unusable reply, a cancelled call) and a group the directory does not know: `DEPENDENCY_UNAVAILABLE`. The source retries nothing; the caller's schedule is the retry (V10 describes the vendor's backoff for a caller that does).

## 4. Join

**GD-7. The join attribute is the user's unique ID.** The principal is the configured prefix followed by the user's `id` written under IM-2 (identity mapping IM-4, IM-5, IM-2). The prefix carries the namespace and realm components of the authenticating mechanism (for the `oauth` profile `oauth:{issuer-id}:{tenant}:`) and comes from configuration, never from a reply. `primaryEmail`, an alias, a name, an organization path and any attribute an administrator or the user can change never join (V7 recommends against an address as a persistent key). The ID is the only attribute the Directory documents as a key besides the address (V6); that it never changes and is never reused is not stated (open item 2).

**GD-8. One spelling.** A principal joins only if its local part, after percent-decoding, re-encodes under IM-2 to the same text: an unreserved octet written as `%XX`, a lower-case `%xx`, a space, an address and a principal of another prefix do not.

**GD-9. The ID must be the authenticating mechanism's.** The local part of the authenticated principal is the identifier the mechanism carries for the user, for a Google ID token the `sub` claim ("unique among all Google Accounts and never reused", "never changed"; Identity, OpenID Connect). That `sub` is the Directory `id` of the same account is not stated by any page read (open item 1). Until it is probed, a deployment whose `sub` differs from the Directory `id` finds no user (`MISSING_FIELD`) and every rule over this source fails; it never reads another user's fact.

## 5. The cached account state

A deployment that cannot afford a Directory call per evaluation fills a `source.Store` with the account state of every user and serves the account state from it (`Config.Cache`). Membership is always read live. A cached fact is the state at the request that returned it: both times are the time at which the request for that page of the listing, or for that user, was made, never the time of the read (draft 8.3). The reader serves a fact no older than the configured maximum age, which the deployment declares as its best status bound; an older fact is `DEPENDENCY_UNAVAILABLE`, so a feed that has stopped fails the rules over this source and never lets them pass on a stale state. A principal with no cached fact has no fact (`MISSING_FIELD`), and the reader does not fall back to a live read.

## 6. The change feed

**GD-10. The feed is a hint plus a sweep.** The feed has two ways to learn of a change, and the bound of the cache rests on the second. (a) A push channel: the source opens a `users.watch` channel for the `update` event (V13); a notification names a user, and the source reads that user back from the API and stores the state. A suspension and an archival are updates. (b) A sweep: every poll interval the source lists every user of the customer (`users.list`, V9) and stores each user's state. Creation, deletion and restoration are seen by the sweep. The API states no delivery guarantee for notifications (V17), so the sweep runs whether or not a channel is open, and the declared bound of the cached state is the poll interval plus the time a sweep takes (section 7, row D).

**GD-11. A notification is verified and read back.** The endpoint accepts a POST only; compares the `X-Goog-Channel-Token` to the configured token in constant time (401 on a mismatch or absence); requires the channel, resource, state and message-number headers (400); accepts only a channel the source opened that has not expired, or that was replaced and could not be stopped until it expires (404); acknowledges a `sync` message and does nothing else with it (V16); and for any other state requires a body of at most 64 KiB with `kind` `admin#directory#user` and an `id` (400, 413). The body's address and etag are not used. The user is read back from the API; the endpoint answers 200 only after the state is stored, so a failed read is a 503 (or 502 when the API resolved the ID to another user) and Google's own retry applies (V17). A user the API does not know (404) has its facts removed. Because the state is read back, a repeated, late or reordered notification changes nothing that a read would not.

**GD-12. Renewal and expiry.** A channel does not renew itself (V15). `Tick` opens a channel under a new ID when none is open or when the open one expires within the renewal margin; the expiration the API returns decides, because the API applies the more restrictive of the request and its own limits (V14) and publishes no maximum (open item 6). A reply without an expiration, or with a channel that is already expired, is not used. When the new channel is open the old one is stopped; if it cannot be stopped it stays accepted until its expiration. A channel past its expiration is dropped and refused. While no channel is open the feed is in poll mode: nothing is wrong, the sweep alone keeps the cache within its bound, and `Tick` tries to open a channel at each call.

**GD-13. A sweep is complete or it is nothing.** A listing that fails part-way stores what it listed, deletes nothing and does not count as a sweep; the next `Tick` repeats it. After a complete listing the source removes the facts of the users it wrote earlier and the listing no longer holds, except a fact written after the sweep began. A fact is never replaced by one with an earlier observation time.

**GD-14. No timer, no goroutine.** The deployment calls `Tick` on its schedule (at least as often as the poll interval and the renewal margin) and serves the handler. A quota response (V10) is an error of that `Tick`.

## 7. Freshness

Four rows for an integration profile's 8.1, each with `source_document` `googledir`. The figures marked vendor are vendor behaviour read on 2026-10-19 and can change without a PACT revision.

| Row | Source | `facts` | `live_check` | `change_feed.mode` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|
| A | Google Workspace Directory API `users.get` (account state, read at each evaluation) | `account_state` | `available` true; endpoint class `Admin SDK Directory API users.get` | `none` | 0. The vendor states no delay between a suspension and the API's answer (open item 7) | `authoritative_current` |
| B | Directory API `members.hasMember` (direct and nested membership) | `groups` | true; `Admin SDK Directory API members.hasMember` | `none` | 600 (vendor, V11): a nested group's members can take up to 10 minutes to appear; the vendor gives no separate figure for a direct member, which is open item 7, and a deployment with no nested group may declare 0 once it is probed | `authoritative_current` |
| C | Cloud Identity Groups API `checkTransitiveMembership` | `groups` | true; `Cloud Identity Groups API checkTransitiveMembership` | `none` | 600, the same group graph as row B; the Cloud Identity page states no figure | `authoritative_current` |
| D | The source's cache of the account state, filled by a sweep and a push channel | `account_state` | false | `push`; mechanism: `Admin SDK Directory API push channel (users.watch, event update) as a hint, read back from the API; a sweep of users.list every poll interval; channels expire, are renewed by the source, and fall back to the sweep alone` | The declared poll interval plus the longest sweep: the `max_age` of the reader | `cached_snapshot` |

A rule whose `status_max_age_seconds` is below the best bound of its row is `UNKNOWN` with `UNSUPPORTED_REQUIREMENT` (freshness 4.2, convention 2). Revocation: a suspension is visible at the next read of row A; a removal from a group at the next read of row B or C, plus the vendor's delay (V11); in row D at the next notification that reaches the source or at the next sweep, whichever is first.

## 8. Credentials and least privilege

**GD-15. A service account with domain-wide delegation.** The source signs an assertion with the service account's RSA key and exchanges it at `https://oauth2.googleapis.com/token` (V18). The token endpoint is the vendor's and is configuration, never taken from the key file. The delegated user (`sub`) is an administrator whose privileges cover the data read (V19); the minimum Admin console role is open item 5. The key is read from the key file once and never logged; the access token is held in memory until 60 seconds before it expires and is replaced then. No redirect is followed, and every endpoint is HTTPS.

**GD-16. One token per API, with the scopes of that API only.** The Directory token carries `https://www.googleapis.com/auth/admin.directory.user.readonly` and `https://www.googleapis.com/auth/admin.directory.group.member.readonly` (V3, V8); the Cloud Identity token, when a transitive group is read, carries `https://www.googleapis.com/auth/cloud-identity.groups.readonly` (V4). All are read-only scopes. Each must be authorized for the service account's client ID in the Admin console (V19). `users.watch` is called with the Directory token, whose `admin.directory.user.readonly` scope the page lists. A deployment that reads no transitive group authorizes no Cloud Identity scope.

## 9. Risk signals through the Shared Signals receiver (when enabled)

Google transmits security events to a receiver the customer operates (the RISC profile; section 9.2 of [`ssf.md`](ssf.md)). The event types that bear on account state are `account-disabled`, `account-enabled`, `account-credential-change-required` and `sessions-revoked`; the subject is the Google Account ID (`sub`), the `aud` is one of the application's client IDs, the issuer is read from the discovery document (the RISC page's sample uses `https://accounts.google.com/`, which has a trailing slash that the issuer of an ID token does not), and a receiver that is down for long can miss events permanently (Identity, Cross-Account Protection). The signals may be used only for security, anti-fraud and session management purposes (same page).

**GD-17. How the two sources combine.** The `ssf` receiver and this source answer `/principal/account_state` from different state: the receiver from the events it was sent, as of each event's time, this source from the directory, as of the read. A deployment installs them as separate sources, and a rule that needs either signal reads both and fails if either is `disabled`. This source needs the receiver only for what the Directory cannot say (a revoked session, a required credential change) or, in cached mode (row D), to see a disable sooner than the poll interval. The `Mapping` of the receiver names each subject, so a deployment that enables RISC generates the table from the same user listing; this source does not generate it.

**Not enabled today, and why.** The sample code of the RISC page verifies with `RS256`, and the `ssf` receiver verifies RS256 only for an issuer whose configuration lists it, ES256 alone by default (`ssf.md`, SR-5 and section 3); until a deployment lists RS256 for the Google issuer, a Google SET is refused with `invalid_key`, and that Google signs with RS256 is a probe item (`ssf.md`, section 11). Whether the Directory `id` is the RISC subject `sub` is open item 1. This source does not depend on RISC for any rule.

## 10. The authentication half: Google ID tokens are form G of the `oauth` profile

**Decision and what landed.** On 2026-10-19 the owner chose option A for ID tokens only. Form G of the `oauth` profile ([`../oauth/profile.md`](../oauth/profile.md), OAUTH-41 to OAUTH-50, case groups `OAUTH-30` to `OAUTH-40`) validates a Google ID token locally as an RS256 JWS against the key set of Google's discovery document, which it keeps as long as the HTTP cache headers of the response say. Its principal is `oauth:https%3A%2F%2Faccounts.google.com:{hd}:{sub}`: `tenant` is the `hd` claim pinned by the issuer entry, because no token carries the Workspace customer ID, and `sub` is the local part, never `email`; a token with no `hd` or another `hd` is refused. The `PrincipalPrefix` of this source is therefore `oauth:https%3A%2F%2Faccounts.google.com:{hd}:`, and `sub` is the attribute GD-7 and GD-9 join on. The access-token form through `tokeninfo` is deferred and not built (open item 9 here, OI-10 of the profile). The rest of this section is what was examined and the options that were weighed.

The task asked for Google ID tokens for workloads (JWT, signature checked against Google's JWKS) and Google access tokens (checked through the tokeninfo endpoint with `aud`, `azp` and scope checks), with the principal written `google:...`. The code to check them is not in this source, because three decisions are the owner's, none made by the approved design.

**What was examined.**

- The `oauth` profile supports "exactly two token forms" (Purpose): form I, introspection (RFC 7662), and form E, an Entra ID v2.0 JWS with RS256 and a pinned tenant. OAUTH-5 and OAUTH-6 make each route name one issuer entry and one form, with no fallback. Its principal is `oauth:{issuer-id}:{tenant}:{subject}` (OAUTH-37) and the Go adapter `adapters/oauth` implements only those two forms.
- Identity mapping 3.1 closes the set of namespace tokens (`basic`, `oauth`, `saml`, `ldap`, `mtls`, `files`, `aws`, `k8s`, `db`) and lets a profile define a token that starts with `x-`. The token `google` is not in the set.
- Google ID tokens (Identity, OpenID Connect): signed with a key of the `jwks_uri` of the discovery document `https://accounts.google.com/.well-known/openid-configuration`; `iss` is `https://accounts.google.com` or `accounts.google.com`; `aud` is the app's client ID; `exp` must not have passed; `hd` must be checked when access is restricted to a domain; `sub` is "unique among all Google Accounts and never reused" and "never changed"; `email` "may not be unique to this account and could change over time". The signing algorithm of an ID token is not stated by that page (open item 8); the key rotation guidance is to respect the HTTP caching headers.
- Google access tokens are opaque. The page that shows tokeninfo calls it "for debugging", says to validate ID tokens locally in production, and warns that the endpoint "may be throttled or otherwise subject to intermittent errors". An article on token types shows `GET https://oauth2.googleapis.com/tokeninfo?access_token=...` "for diagnostic purposes" with an example reply of `aud`, `azp`, `scope`, `exp`, `expires_in`, `email` and `sub` (paraphrase). No page read states the reply's complete field set, which members are always present, or its error behaviour (open item 9).

**Options.**

| | Option | What it needs | Against |
|---|---|---|---|
| A | A third form of the `oauth` profile, form G: a Google ID token validated locally against the discovery document's key set (the RS256 and key-set code of form E applies), and later an access token through tokeninfo. Principal `oauth:https%3A%2F%2Faccounts.google.com:{tenant}:{sub}`. | Profile text: "two forms" becomes three, a new issuer entry kind and rules for the ID token checks (OAUTH-23 to OAUTH-40 style); an adapter change in `adapters/oauth`; a decision on `tenant` (a pinned `hd`, which is a domain name, or the Workspace customer ID, which no token carries) | Edits a landed profile and its adapter; tokeninfo is documented as a debugging aid |
| B | A new adapter and profile `google`, with a namespace token `google` and a principal `google:{customer}:{sub}` as the task text names it. | A new row in identity mapping 3.3 and in the grammar of 3.1; a registry entry of a new profile; a new package `adapters/google` with its own JWS, JWKS and tokeninfo code | Duplicates form E's validation; changes the closed set of namespace tokens |
| C | The same as B with the token `x-google`, defined by its own profile. | A new profile and a new package, but no change to identity mapping | `x-google` is not what the task names; still a new adapter |

**Recommendation (adopted for ID tokens).** Option A for ID tokens only, now: it keeps the namespace set, reuses the RS256 and JWKS code that form E already has, and gives a principal whose local part is `sub`, the identifier this source's join needs (GD-9). Defer the access-token form until the tokeninfo probe (open item 9) shows a reply that can be checked and an availability the owner accepts, because the page that documents the endpoint says not to use it in production. If the owner wants the literal `google:` token, option B is the way and the change to identity mapping comes first. Whichever is chosen, `PrincipalPrefix` of this source is configuration and needs no change.

## 11. Residual limits and open items

| Limit | Effect |
|---|---|
| The API's own delay is not stated except for nested groups (V11). | Rows A and B declare what the vendor states; a measured delay is open item 7. |
| A quota (V10) is shared by every caller of the project and, for `429`, of the Workspace account. | A sweep of a large directory costs one request per page of at most 500 users; the poll interval is the deployment's to size against the quota. |
| The source holds the cache in memory. | A restart loses it; reads answer `MISSING_FIELD` until the next sweep, which a rule reads as a failure, never a pass. |
| The sweep lists every user. | A directory of many users costs many pages; the cache holds one fact per user. |
| Domain-wide delegation is a broad grant. | The key file is a secret; the scopes are read-only and per API (GD-16); the delegated user is the narrowest administrator that can read. |
| A notification does not name the change. | The source reads the user back (GD-11); a deletion is seen by the sweep, or by a 404 when a notification names the user. |

**Open items. Each is to probe; none is assumed by a rule.**

1. **Directory `id` equals the OpenID `sub`.** Probe: for one account, read `users.get` and compare `id` with the `sub` of that account's ID token. Until then GD-9 fails closed.
2. **`id` immutability and non-reuse.** V6 does not state it. Probe: ask the vendor; a rename test shows only that an ID survives a rename.
3. **The Directory group ID is the Cloud Identity group ID.** The paths take one ID per API; a deployment lists both. Probe: compare a group's Directory `id` with its Cloud Identity `groups/{id}`.
4. **`member_key_namespace`.** V4 says some groups need it; which ones, and whether Workspace user groups ever do, is not stated.
5. **Minimum Admin console role of the delegated user**, and whether the Cloud Identity Groups API accepts a delegated service account token. Probe: a custom role with read privileges for users and groups; call each API.
6. **Channel lifetime.** The default and maximum are not published (V14). Probe: create channels with no `ttl`, with a short `ttl` and with a year; record the `expiration` the API returns. Also whether `event` is required, whether it is spelled in lower case as the guide has it or in upper case as the reference lists it, whether one channel can watch more than one event, the values of `X-Goog-Resource-State` for a user change, and whether a reply carries `expiration` when none was requested (the source does not use a channel whose reply has none).
7. **Propagation of a suspension, an archival and a direct membership change** to the API's answer; V11 and V7 state only the nested-group and rename delays. Probe: change, then read in a loop and record the time of the first answer.
8. **Signing algorithm of RISC events** (the sample verifies with `RS256`); `ssf.md` carries it. The ID-token half is established: Google's discovery document lists `["RS256"]` and the members of its key set carry `alg` `RS256` (profile probes G1 and G2, 2026-10-19), and form G accepts RS256 only.
9. **tokeninfo reply**: members always present, the `sub` of an access token without the `openid` scope, error and throttling behaviour.
10. **Listings and deleted users.** Whether `users.list` returns suspended and archived users (the source relies on it; if it did not, such a user would be dropped and read as no fact, which fails every rule), whether the reply always carries `suspended` and `archived` (the source fails closed if not), and what `users.get` returns for a deleted user.
11. **A suspended or archived member's membership**: the pages do not say whether `hasMember` still answers true; GD-2 assumes it does, and the pairing with `account_state` makes the assumption safe for a rule that needs an active member.

## 12. Primary sources read

All read on 2026-10-19 through a page fetch that returns an extract; quotations are as the extract gave them.

| Source | Used for |
|---|---|
| `developers.google.com/workspace/admin/directory/reference/rest/v1/members/hasMember` | V1 to V3 |
| `docs.cloud.google.com/identity/docs/reference/rest/v1/groups.memberships/checkTransitiveMembership` | V4, V5 |
| `developers.google.com/workspace/admin/directory/reference/rest/v1/users`, `.../users/get`, `.../users/list`, `.../users/watch` | V6, V8, V9, V13 |
| `developers.google.com/workspace/admin/directory/v1/guides/manage-users`, `.../manage-group-members` | V7, V11 |
| `developers.google.com/workspace/admin/directory/v1/limits` | V10, V11 |
| `developers.google.com/workspace/admin/directory/v1/guides/push` | V12 to V17 |
| `developers.google.com/identity/protocols/oauth2/service-account` | V18, V19 |
| `developers.google.com/identity/protocols/risc` | section 9 |
| `developers.google.com/identity/protocols/oauth2/openid-connect` | GD-9, section 10 |
| `docs.cloud.google.com/docs/authentication/token-types` | section 10 |
| RFC 7523 | the jwt-bearer grant of V18 |

The pages change; a decision that rests on one is re-checked against it when it is relied on.

## 13. Cases

The cases are the files of [`../../fixtures/sources/googledir`](../../fixtures/sources/googledir), kind `source-case`, run by the harness `adapter/sourcetest` with the driver of the model `googledir/1`. A case builds a stand-in for the Google endpoints that behaves as section 2 states, delivers its steps and reads.

| Row | Case | Tests | Rules |
|---|---|---|---|
| `GOOGLE-01` | `googledir-01.account-state` | Suspended and archived read `disabled`, active reads `active`, a deleted user has no fact; the times are those of the read | GD-1, GD-5 |
| `GOOGLE-02` | `googledir-02.join-refusals` | An address, a renamed address, another tenant's and another issuer's prefix never join; a rename moves nothing; no request is made for an address | GD-4, GD-7, GD-8 |
| `GOOGLE-03` | `googledir-03.member-direct-nested` | `hasMember`: direct, nested, non-member; a suspended member is still a member | GD-2 |
| `GOOGLE-03` | `googledir-04.transitive-membership` | `checkTransitiveMembership` two levels down; the address is resolved from the ID after a rename; an added member is seen at the next read | GD-3 |
| `GOOGLE-04` | `googledir-05.unserved-paths` | A group or path not configured is `UNSUPPORTED_REQUIREMENT` | GD-6 |
| `GOOGLE-04` | `googledir-06.directory-unavailable` | A failing Directory API is `DEPENDENCY_UNAVAILABLE` for every fact | GD-6 |
| `GOOGLE-04` | `googledir-13.identity-unavailable` | A failing Cloud Identity API fails only the transitive fact | GD-6 |
| `GOOGLE-04` | `googledir-14.token-unavailable` | A refusing token endpoint fails every fact | GD-6, GD-15 |
| `GOOGLE-05` | `googledir-07.sweep-cache` | A sweep over several pages fills the cache; its facts carry the sweep's request time; membership stays live | GD-10, section 5 |
| `GOOGLE-05` | `googledir-08.notification-refresh` | A notification is read back at once; a wrong or missing token, an unknown channel, a sync message and a malformed body change nothing | GD-11 |
| `GOOGLE-05` | `googledir-12.deleted-in-sweep` | A user deleted in the directory has no fact after the next sweep | GD-13 |
| `GOOGLE-06` | `googledir-09.channel-renewal` | A channel is renewed before it expires under a new ID, the old one is stopped and refused | GD-12 |
| `GOOGLE-06` | `googledir-10.channel-expiry-fallback` | A channel that cannot be renewed expires; the poll sees a later suspension within the interval; push returns when a channel can be opened | GD-10, GD-12 |
| `GOOGLE-06` | `googledir-11.stale-beyond-bound` | A cached fact is served with its own time up to the maximum age and not after | section 5 |

Not covered by a case: the assertion and the token's reuse, the strict parsing of replies, the query-literal check, paging and the concurrency of the handler are tests of the Go package.

### 13.1 Model `googledir/1`

`source`:

| Member | Meaning |
|---|---|
| `model` | `googledir/1` |
| `source_id` | The source ID of every claim |
| `principal_prefix` | The principal identifier up to its local part (GD-7). The one in the cases is illustrative: the principal of a Google ID token is that of form G of the `oauth` profile (section 10) |
| `groups`, `transitive_groups` | The group IDs served at the `member` and `transitive_member` paths |
| `cache` | Absent: every fact is read live. Present: the account state is served from a cache, `{poll_interval_seconds, max_age_seconds, channel: {address, token, ttl_seconds, renew_before_seconds}}` |
| `directory` | The stand-in's state: `customer`, `page_size`, `channel_max_seconds` (the vendor's own channel limit), `users` (each `{id, primary_email, aliases, suspended, archived}`) and `groups` (each `{id, members, groups}`: member user IDs and child group IDs) |

A step's `inbound` is one of:

- `{"admin": {"op", ...}}`: a change in the directory. `op` is `suspend`, `unsuspend`, `archive`, `delete` or `rename` (with `user`, and `primary_email` for `rename`), `add_member` or `remove_member` (with `group` and `user`), `nest` (with `group` and `child`), `fail` (with `api`: `directory`, `identity`, `token` or `watch`, and `status`) or `heal` (with `api`).
- `{"tick": {}}`: the deployment calls `Tick`.
- `{"notify": {"channel", "state", "message", "user", "token", "body"}}`: a notification. `channel` is the ordinal of a channel the stand-in opened (0: one it did not), `state` the resource state, `user` the ID in the body, `token` the channel token header (empty: the configured one; `-`: none) and `body` a raw body that replaces the generated one.

A step's `expect`: for `notify`, `status`; for `tick`, `mode`, `channel` (the ordinal of the open channel, 0 for none), `expires_at`, `error` (whether `Tick` returned an error), `sweeps` and `stopped` (the ordinals of the channels the stand-in saw stopped). Reads are those of the common envelope. `must_not_call` may name `email-key`, fired by the stand-in whenever the Directory API is asked for a user or a member by an address.
