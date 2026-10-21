# PACT Shared Signals receiver source document

This document targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose and status

This is the source document ([`../../fixtures/sources/README.md`](../../fixtures/sources/README.md)) of a membership and status source that is not an adapter: the receiving end of the OpenID Shared Signals Framework (SSF) 1.0, with the Continuous Access Evaluation Profile (CAEP) 1.0 and the RISC profile 1.0 as the event vocabularies. An identity provider that transmits Security Event Tokens (SETs) about its accounts and sessions is the sender; the integration verifies them, keeps the last reported account state per principal, and answers the draft §17.1 function `read_native_claim` from that state. The messages the provider pushes, or the integration polls, are the change feed ([`../TEMPLATE.md`](../TEMPLATE.md), 8.1). The Go library is the package `adapter/source/ssf` of the source repository.

It is not an integration profile: it makes no gateway claim and has no `profile.json`. An integration profile embeds it by citing it in its 8.1 row (`source_document` `ssf`). Registry entry: kind `source`, id `ssf`, in [`../registry.json`](../registry.json).

The document adds no wire field and no protocol requirement. Where it and [`draft.md`](../../draft.md) differ, the draft governs. The words MUST, SHOULD and MAY have the meanings given in draft §3. Shared rules are not repeated: identifiers and the join of a pushed record to a principal are in [`../identity-mapping.md`](../identity-mapping.md) (IM-2, IM-4, IM-5); the vocabulary of observation and status times is in [`../freshness.md`](../freshness.md) (sections 2, 3, 4.1, 4.2).

Every statement about an external specification cites the section of the document read on 2026-10-18, listed in section 12. Every statement about what a vendor transmits cites a vendor page read on that date, or is marked **to probe** and listed in section 11. A vendor behaviour that no page states is not written as a rule.

## 1. Scope and boundary

| Item | Value |
|---|---|
| Source id | Deployment configuration (`SourceID`); named in every claim |
| Fact served | `account_state`, at the native path `/principal/account_state` only. No `identity`, `groups` or `roles` fact: a SET carries events, never a directory |
| Delivery | Push (RFC 8935) and poll (RFC 8936); the stream is created and read through the SSF management API (SSF 1.0 §8.1) |
| Event vocabulary | CAEP 1.0 §3 and RISC 1.0 §2, mapped in section 5; SSF 1.0 §8.1.4.1 and §8.1.5 control events |
| Not served | A live check (there is none), any fact of a principal no event named, any event type not in section 5 (reported, never applied) |
| Not created | A security hold: the receiver raises hold candidates (section 8) |

The receiver learns only what the transmitter sends. A principal that no event named has no fact, and the read is `MISSING_FIELD`; no event ever asserts that a session is still in force or that an account is healthy, except `account-enabled`, which sets `active` as of its event time. A field rule that needs `active` is therefore satisfied only by an `account-enabled` event younger than the rule's limits, or by another source; see section 10.

## 2. What it serves and what it calls

| Surface | Direction | Rule |
|---|---|---|
| Push endpoint | Inbound HTTPS POST, one SET per request | `Content-Type` `application/secevent+jwt` is required (RFC 8935 §2.1). `202` without a body means the SET was accepted, including a SET applied before (§2.2; and §2: the recipient answers a retransmission as it answered the first delivery). `400` with `Content-Type` `application/json` and the body `{"err", "description"}` means it was rejected (§2.3); `err` is one of `invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`, `authentication_failed`, `access_denied` (§2.4) |
| Push authentication | Inbound | RFC 8935 §3 puts authentication under HTTP's schemes over TLS. The receiver compares the `Authorization` header to the configured value and answers `401` with `WWW-Authenticate` and `err` `authentication_failed` when it differs or is absent. Mutual TLS or another authenticating layer in front of the endpoint is the alternative; the receiver does not require one |
| Dependency failure | Inbound | `503`, after which the transmitter retransmits (RFC 8935 §2 allows retransmission regardless of the response) |
| Poll endpoint | Outbound HTTPS POST, JSON | Request members `maxEvents`, `returnImmediately`, `ack`, `setErrs`; response `sets` (an object of compact SETs by `jti`) and `moreAvailable` (RFC 8936 §2.2, §2.3). Each request acknowledges the SETs the previous response delivered and reports the invalid ones in `setErrs` (§2.4). A SET that could not be handled because a dependency failed is neither acknowledged nor reported, so the transmitter delivers it again |
| Stream management | Outbound HTTPS | Create (`POST`, `201`), read (`GET`, optional `stream_id`), status read and update, verification request (`POST`, `204`) of SSF 1.0 §8.1.1.1, §8.1.1.2, §8.1.2.1, §8.1.2.2, §8.1.4.2. The client confirms that a returned stream names the transmitter's `iss` (§8.1.1) |
| Verification event | Inbound | Event type `https://schemas.openid.net/secevent/ssf/event-type/verification` with the `state` the receiver sent (SSF 1.0 §8.1.4.1). The receiver records the state and reports it; it changes no account state |
| Stream-updated event | Inbound | `https://schemas.openid.net/secevent/ssf/event-type/stream-updated` with `status` (§8.1.5). Reported; a `paused` or `disabled` stream means events may be missing (section 10) |

The source calls the identity provider only to poll, to fetch the signing keys (`jwks_uri`, SSF 1.0 §7.1) and to manage the stream. A source that is only pushed to calls nothing (`must_not_call` `outbound` is valid for it).

## 3. Verification of a SET

A SET is accepted only when every rule holds, checked in this order. A failure is an `Error` with the RFC 8935 §2.4 code in the last column, and the SET changes nothing.

| Rule | Statement | Basis | Code |
|---|---|---|---|
| SR-1 | The compact SET is within the size bound (default 65536 bytes), has three segments, and each segment is canonical unpadded base64url | profile; draft §20.1 | `invalid_request` |
| SR-2 | The protected header is a strict JSON object (no duplicate member) with no `crit`, `b64`, `jku`, `x5u`, `x5c` or `jwk` member: keys come from configuration and nowhere else | draft §7.2 (package `core/jws` profile) | `invalid_request` |
| SR-3 | `typ` is `secevent+jwt` or `application/secevent+jwt`. A JWT of another type is not a SET | RFC 8417 §2.3, §4; SSF 1.0 §4.1.1 | `invalid_request` |
| SR-4 | The payload is a strict JSON object with a string `iss` that is a configured issuer | RFC 8417 §2.2 | `invalid_request`, `invalid_issuer` |
| SR-5 | `alg` is in the algorithm list of that issuer: `ES256` alone by default, `ES256` and `RS256` as configured. A SET whose `alg` is not in the list is refused, whatever its key. Any other value, `none` and the HMAC algorithms included, is refused too, and a configuration that lists one is invalid | draft §7.2 (ES256 is the baseline); RFC 7518 §3.3, §3.4 | `invalid_key` |
| SR-6 | `kid` names a key of that issuer's key set of the type the `alg` needs: an EC P-256 key for `ES256`, an RSA key of at least 2048 bits for `RS256`, and a key of the other type is not used; the signature, 64 octets for `ES256` and as long as the modulus for `RS256`, verifies over the received signing input | RFC 7515; RFC 7518 §3.3, §3.4, §6.2, §6.3; SSF 1.0 §4.1.4, §7.1 | `invalid_key` |
| SR-7 | `aud` (a string or an array of strings) contains the audience configured for that issuer | SSF 1.0 §4.1.8; RFC 8935 §2.4 | `invalid_audience` |
| SR-8 | `jti` is present; there is no `sub` claim and no `exp` claim | RFC 8417 §2.2; SSF 1.0 §4.1.2, §4.1.7 | `invalid_request` |
| SR-9 | `iat` is a NumericDate in seconds, not later than now plus the clock skew and not older than the accepted age (default 24 hours) | draft §7.5, A.2; profile | `invalid_request` |
| SR-10 | `events` is an object of at least one event, each a JSON object; every event conforms to its definition (section 5) and an `event_timestamp` is a NumericDate not later than `iat` plus the skew | RFC 8417 §2.2; CAEP 1.0 §2 | `invalid_request` |
| SR-11 | A `jti` of the issuer that was applied before is a replay (section 4) | RFC 8417 §2.2; RFC 8935 §2 | none, or `invalid_request` for other content |

The signature is verified before the replay store is read or written (SR-5 and SR-6 precede SR-11), so a forged SET cannot occupy a `jti`. The issuer named by the still unauthenticated payload only selects the configured key set (draft §7.3).

**Algorithms.** ES256 is the baseline and the default of every issuer (draft §7.2); the key is an EC P-256 JWK of the key profile of `core/jws`: `alg`, when present, `ES256`; `use`, when present, `sig`; `key_ops`, when present, an array of distinct strings that names `verify` (RFC 7517 §4.2 to §4.4). A key built in configuration rather than parsed is held to the same `alg` and `use`, both when the receiver is configured (a static key set) and when the key is used. RS256, RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3), is accepted for an issuer only when its configuration lists it (`algorithms` of the issuer in the model of section 13; `Issuer.Algorithms` in the Go library). The list is explicit per transmitter: listing RS256 for one transmitter enables it for no other, and a list of `RS256` alone refuses ES256. The list admits `ES256` and `RS256` and nothing else; `none`, the HMAC algorithms and every other RSA, EC or EdDSA algorithm are not implemented, and a configuration that names one is invalid. A transmitter that signs with an algorithm outside its list is refused with `invalid_key`.

The key decides nothing about the algorithm and the header decides nothing about the key: the receiver asks the key set for a key of the type the `alg` needs, and a key of another type, an EC key under an RS256 header or an RSA key under an ES256 header, is not used. HS256 is in no list, so an HMAC whose secret is the bytes of the issuer's RSA public key (the key confusion of RFC 8725 §2.1) is refused before any key is read; the cases pin it for the PEM and the DER form of the key.

An RSA key is a strict JWK: `kty` `RSA`; `n` and `e` the canonical unpadded base64url (RFC 7518 §6.3.1) of an odd modulus and of an odd exponent from 3 to 2^31-1, neither with a leading zero octet; no private member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`); `alg`, when present, `RS256`; `use`, when present, `sig`; `key_ops`, when present, an array of distinct strings that names `verify` (RFC 7517 §4.3); no duplicate member. The modulus is at least 2048 bits, because RFC 7518 §3.3 requires a key of 2048 bits or larger for RS256; it is checked when the key is used, so a published key under 2048 bits makes each SET it signs `invalid_key`, though the signature verifies. A key configured statically, rather than fetched, is checked as a verification would use it, its size included, when the receiver is configured: a key that is not usable is a configuration error, not a rejection of each SET. So is a kid that two configured keys of one type share, which a fetched set answers by trusting neither (Key source, below). A modulus over 16384 bits is refused: that bound is this document's own, to keep one verification cheap, and no standard gives it. A Go receiver run with `GODEBUG=fips140=only` verifies through the FIPS 140 module, whose `crypto/rsa` (Go 1.26) refuses some keys these rules accept: a modulus of an odd number of bits, and an exponent of at most 2^16. A SET signed with such a key is `invalid_key`, reported as the module's refusal of the key rather than as a signature that does not verify; which keys the rules accept does not change. Which algorithm each vendor signs with is a probe item (section 11).

**Key source.** `jwks_uri` is fetched over HTTPS and held at most one refresh interval. A key the transmitter removes stops verifying within one interval. A refresh that fails, by a network or HTTP error or a response that is not a key set, fails the source until the refresh interval ends (`DEPENDENCY_UNAVAILABLE` on the read, a retry for the SET), never a use of keys the source cannot confirm. One fetch runs at a time and no lock is held during it: a verification that needs the set meanwhile waits for that fetch, no longer than its own deadline, and is never served the set being replaced. A fetch cut short because the deadline of the verification running it ended is not a failed refresh: that verification fails with its own deadline, nothing is recorded, and the next verification, a waiting one included, fetches. A key that is neither an EC P-256 key of the profile nor a well-formed RSA key is skipped (the size of an RSA key is checked when it is used). A kid that two keys of one type share is trusted for neither of them. Keys of different types may share a kid, as equivalent alternatives (RFC 7517 §4.5): an EC P-256 key and an RSA key under one kid are each used for the algorithm of its type, and two keys of one type under that kid make it unusable for that type only.

## 4. Replay

A `jti` is unique within a transmitter's feed (RFC 8417 §2.2), so the replay key is the pair (issuer, `jti`). The receiver records the SHA-256 of the received payload, the SET's content and not its signature, for the accepted age plus the skew, after the events were applied.

| Arrival | Result |
|---|---|
| First delivery | Applied, recorded |
| Same (issuer, `jti`) and same payload | Not applied again. Answered as the first delivery was (RFC 8935 §2: "The SET Recipient MUST respond as it would if the SET had not been previously received"): `202`, or an acknowledgment in poll. Reported as `replay` |
| Same (issuer, `jti`), other payload | Rejected `invalid_request`: the issuer broke the uniqueness of `jti` |
| Same `jti`, another issuer | A different SET |

A SET whose apply failed on a dependency records nothing, so its retry is applied. The replay record outlives its use: the age check of SR-9 rejects any SET older than the retention, so a `jti` cannot return after the record expires. A restart of an in-memory store forgets the records; a deployment that cannot tolerate that supplies a durable store.

The stated reason for answering a replay as accepted is the RFC sentence above and the vendor statement that duplicates occur: Google's page says redelivery can duplicate events and the `jti` claim can be used to de-duplicate (section 9). A replay is "rejected" in the sense of not applied and reported; the fixtures assert that.

## 5. Events and the fact

The fact is `/principal/account_state`. Its values extend the vocabulary of the LDAP profile (LR-20: `active`, `disabled`, `locked`, `expired`, `password_change_required`, `absent`). Only `active` satisfies a requirement `equal active`.

| Event type | Applies when | `account_state` | Basis |
|---|---|---|---|
| CAEP `session-revoked` | always | `session_revoked` | CAEP 1.0 §3.1 |
| RISC `sessions-revoked` | always; deprecated in favour of the row above | `session_revoked` | RISC 1.0 §2.11 |
| CAEP `credential-change` | `change_type` `update`, `revoke`, `delete` | `credential_changed` | CAEP 1.0 §3.3.1 |
| CAEP `credential-change` | `change_type` `create`: a new credential invalidates nothing | none (`no-effect`) | CAEP 1.0 §3.3 |
| CAEP `assurance-level-change` | `change_direction` `decrease` or absent | `assurance_changed` | CAEP 1.0 §3.4.1 |
| CAEP `assurance-level-change` | `change_direction` `increase` | none (`no-effect`) | CAEP 1.0 §3.4.1 |
| RISC `account-disabled` | always (`reason` `hijacking`, `bulk-account` or absent) | `disabled` | RISC 1.0 §2.3 |
| RISC `account-enabled` | always | `active` | RISC 1.0 §2.4 |
| RISC `account-purged` | always | `absent` | RISC 1.0 §2.2 |
| RISC `account-credential-change-required` | always | `password_change_required` | RISC 1.0 §2.1 |
| RISC `credential-compromise` | `credential_type` present | `credential_compromised` | RISC 1.0 §2.7 |
| SSF `verification`, `stream-updated` | control events | none; reported | SSF 1.0 §8.1.4.1, §8.1.5 |
| Any other type | | none; reported as `unsupported-event` | profile |

Base URIs: CAEP events `https://schemas.openid.net/secevent/caep/event-type/`, RISC events `https://schemas.openid.net/secevent/risc/event-type/`, SSF events `https://schemas.openid.net/secevent/ssf/event-type/`.

Payload checks (SR-10): `credential-change` needs `credential_type` and a `change_type` of `create`, `revoke`, `update` or `delete`; `assurance-level-change` needs `namespace` and `current_level`, and a `change_direction`, when present, is `increase` or `decrease`; `credential-compromise` needs `credential_type` (the cited sections). `credential_type` is not restricted to the CAEP list, because CAEP §3.3.1 allows "any other credential type supported mutually" and a vendor documents values outside it (section 9).

**Time.** The event time is `event_timestamp` when present, else the SET's `iat`. It is both `ObservedAt` and `StatusCheckedAt`: a real observation time of the transmitter (freshness 2 and 4.2, convention 1). The receiver never reports the read time. An `event_timestamp` later than `iat` plus the skew is not conformant (an event cannot occur after its SET was issued; CAEP 1.0 §2 defines it as the time the event occurred) and is `invalid_request`; this also rejects a value written in milliseconds where CAEP §2 defines seconds.

**Order.** An event older than the fact it would replace is not applied and is reported (`stale-event`); an equal time applies. A hold candidate is still raised for such an event (section 8).

**Several events in one SET.** SSF 1.0 §4.2.1 says a SET SHOULD contain one event; RFC 8417 §2.2 allows several. The receiver validates all events first, then applies them in event-type order, each with its own time.

**Persistence of a state.** A state stays until a later event replaces it. `session_revoked`, `credential_changed` and `assurance_changed` do not expire: no event says the principal authenticated again afterwards. Section 10 states what that costs.

## 6. The 8.1 row

| Field | Value |
|---|---|
| Source | `Shared Signals receiver (account state pushed or polled from the identity provider)` |
| `facts` | `account_state` |
| `live_check.available` | `false` |
| `change_feed.mode` | `push` for RFC 8935 delivery; `poll_delta` for RFC 8936 delivery |
| `change_feed.mechanism` | `Security Event Tokens of the OpenID Shared Signals Framework 1.0, delivered by HTTP POST to the integration (RFC 8935) or fetched from the transmitter's poll endpoint (RFC 8936); CAEP and RISC events; the delivery latency is the transmitter's and is a probe item (section 11)` |
| `best_status_max_age_seconds` | Declared by the deployment from its probe (section 11): the longest time from an event at the identity provider to its application here. No default is given, because no vendor page read for this document states a delivery latency |
| `value_semantics` | `cached_snapshot` |

Freshness section 4.1 has no row for an event feed. This document adds one, with the six columns: **observation semantics** the transmitter's last event about the subject, as a cached snapshot; **`ObservedAt`** the event time; **`StatusCheckedAt`** the event time (a silence confirms nothing, so the status time is never advanced by the absence of events); **revocation visible** when the event is applied, after the transmitter's delivery latency; **bound declared** the delivery latency for an event, never a bound on the age of the state; **consequence** a rule whose `status_max_age_seconds` is below the age of the last event about a principal is not satisfied by that principal's fact. A rule below the declared delivery latency is `UNKNOWN` with `UNSUPPORTED_REQUIREMENT` (freshness 4.2, convention 2).

## 7. The join of a subject to a principal

A SET names a subject; the subject names no principal. The join is the rule of the source library ([`identity-mapping.md`](../identity-mapping.md), IM-4, IM-5): a configured mapping per transmitter takes the subject to the immutable local part of the principal identifier, and the namespace and realm components come from the configuration, never from the event.

| Subject format | Mapping key (with the SET's issuer) | Source |
|---|---|---|
| `iss_sub` | the subject's `iss` and `sub` | RFC 9493 §3.2.3 |
| `opaque` | `id` | RFC 9493 §3.2.4 |
| `email` | the address, byte for byte | RFC 9493 §3.2.2 |
| `complex` | the `user` member, resolved as above; a complex subject without a `user` member resolves to nothing | SSF 1.0 §3.3 |
| `subject_type` `iss-sub` inside the event | as `iss_sub`. The RISC profile deprecated `subject_type` (RISC 1.0 §3.1) and a vendor page documents it (section 9) | profile |
| any other format | resolves to nothing | profile |

- No attribute names a principal by itself. An e-mail address matches only a mapping that lists that exact address for that transmitter. RFC 9493 §3.2.2.1 says e-mail canonicalization is not standardized and the recipient applies its own; this source applies none, so `Ada@Example.com` and `ada+x@example.com` do not match `ada@example.com`. An address is also not matched against a directory attribute of any principal, and it is never the local part of an identifier (IM-5).
- A mapping is for one SET issuer. A subject of another transmitter that repeats a mapped value resolves to nothing.
- A complex subject with a member that the deployment lists as critical (SSF 1.0 §3.6, §7.1 `critical_subject_members`) is discarded: the receiver processes only the `user` member.
- An event whose subject resolves to nothing is **ignored** and reported with kind `unknown-subject`, the reason (`unmapped`, `no-subject`, `unsupported-format`, `unsupported-subject`, `malformed-subject`) and the subject's format. The report never carries the identifier: SSF 1.0 §10.1 asks that the same subject identifier type and values be used between the parties, and a log is a third party. The SET is still acknowledged (RFC 8935 §3: "SET Recipients are free to ignore SETs that are not of interest"; SSF 1.0 §9.3 requires a receiver to tolerate events for subjects removed from the stream, and not to report them as errors).

## 8. Hold candidates

A hold is a separate, attributable security decision of an authority, independent of statistical decay and cleared only by its configured native authority or a preauthorized remediation (draft §14.4, §15.4, §16.5, §6.4). A SET from an identity provider is evidence for that decision, not the decision.

The deployment lists in `HoldOn` the mapped event types that also raise a hold candidate (for example `credential-compromise`; draft §6.4: "A compromise event triggers the configured security hold"). For a mapped subject the receiver then calls the configured sink with the principal, issuer, `jti`, event type and event time, once per event and again on a retried delivery, so the sink is idempotent on (issuer, `jti`). A candidate is raised also for an event too old to change the state, because a compromise is a compromise whatever the state says now. No candidate is raised for an unknown subject, for a rejected SET, or for an event type not listed. A sink that fails fails the delivery (retry); the fact was already written, and the retry writes it again identically.

What a security authority does with a candidate (create a hold, ask for review) is outside this source.

## 9. What the vendors transmit

Read on 2026-10-18. Only what the cited page states is a statement here; the rest is a probe item (section 11).

### 9.1 Okta

Source: Okta developer reference "SSF transmitter SETs" (`developer.okta.com/docs/reference/ssf-transmitter-sets/`, copyright 2026, no publication date) and the Okta help article "Configure a shared signal transmitter" (`help.okta.com/oie/en-us/Content/Topics/Apps/configure-shared-signal-transmitter.htm`).

- The Okta SSF transmitter "currently supports two types" of CAEP events: `session-revoked` and `credential-change`. The help article says the same.
- `session-revoked` is generated from the Okta event `user.session.end`.
- `credential-change` is generated from `user.mfa.factor.activate`, `.deactivate`, `.reset_all`, `.suspend`, `.unsuspend`, `.update`, `user.account.reset_password` and `user.account.update_password`. The examples use `change_type` `create` (activate), `delete` (deactivate), `revoke` (reset all factors, reset or update password) and `update` (suspend, unsuspend, update), and `credential_type` values outside the CAEP list (`ALL_FACTORS`, `OKTA_VERIFY_PUSH`, `DUO_SECURITY`).
- The examples use the `iss_sub` subject format, with Okta's user id as `sub`.
- Stream setup uses an OIDC web app integration with the scopes `ssf.manage` and `ssf.read`; "if those scopes don't appear", Okta's page says to contact the account representative.
- No RISC event is listed. Nothing says Okta sends `account-disabled`, `account-purged` or `credential-compromise`.
- Not stated by either page: the delivery method (push or poll), the signing algorithm, the `typ` header, the retry behaviour, the delivery latency. The `event_timestamp` of the example SETs is 1615304991643, a value of 13 digits, which is milliseconds if read as written; CAEP 1.0 §2 defines seconds. The receiver rejects such a value (section 5). To probe.

### 9.2 Google

Source: Google Identity "Protect user accounts with Cross-Account Protection" (RISC; `developers.google.com/identity/protocols/risc`, "Last updated 2026-03-22 UTC").

- Event types listed: `https://schemas.openid.net/secevent/risc/event-type/sessions-revoked`, `https://schemas.openid.net/secevent/oauth/event-type/tokens-revoked`, `.../oauth/event-type/token-revoked`, `.../risc/event-type/account-disabled` (`reason` `hijacking` or `bulk-account`), `.../risc/event-type/account-enabled`, `.../risc/event-type/account-credential-change-required` and `.../risc/event-type/verification`.
- `account-purged` and `credential-compromise` are not listed on that page. To probe.
- The OAuth `tokens-revoked` and `token-revoked` events are not mapped by this source (reported as `unsupported-event`): the account state of this source is not a token state.
- The subject is written with `subject_type` (for example `iss-sub`), `iss` and `sub`, where `sub` is the Google Account ID. For `id_token_claims` an `email` may appear; this source resolves it to nothing, section 7. OAuth token subjects use `token_type`, `token_identifier_alg` and `token`. RISC 1.0 §3.1 says `subject_type` is deprecated and that relying parties of Google's transmitter need a workaround.
- Delivery: only push is documented (`.../risc/delivery-method/push`); polling is not mentioned. Discovery is `https://accounts.google.com/.well-known/risc-configuration`; management is the `risc.googleapis.com/v1beta/stream` family (update, read, status update, verify).
- Verification the page asks of a receiver: verify the signature with the key found by `kid` in the JWKS, check `aud` against the application's client IDs, check `iss` against the discovery `issuer`; expiration is not checked, "because events are historical"; answer `400` on failure and `202` on success. The page shows `https://www.googleapis.com/oauth2/v3/certs` as the JWKS in its sample code. The page's prose does not name the signing algorithm; its sample code that verifies an event token names `RS256` (Python `jwt.decode` with `algorithms='RS256'`, Java `Algorithm.RSA256`), as does its sample code that signs an authorization token. The `alg` of the keys at that JWKS and of a delivered SET is to probe; a deployment lists `RS256` for this transmitter only once the probe confirms it (section 11).
- Token type: the page, read again on 2026-10-19, names no JOSE header parameter of a security event token but `kid` ("get the signing key ID from the header of the security event token"); it mentions neither `typ` nor `secevent+jwt`, and its decoded example shows the payload only. The `typ` of a delivered SET is to probe (section 11). The receiver requires `secevent+jwt` or `application/secevent+jwt` (SR-3), so a Google SET with another `typ`, or none, would be refused with `invalid_request`.
- Delivery behaviour: redelivery is attempted, "events are delivered with limited retries", duplicates can occur and `jti` can de-duplicate, a disabled stream is not buffered.

### 9.3 Microsoft

Source: Microsoft Learn "Continuous access evaluation in Microsoft Entra" (`learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation`, `ms.date` 2026-04-08).

- The page calls continuous access evaluation (CAE) "an industry standard based on" the OpenID CAEP.
- The critical events it says are currently evaluated: user account deleted or disabled; password of a user changed or reset; multifactor authentication enabled for the user; an administrator explicitly revokes all refresh tokens of a user; high user risk detected by Microsoft Entra ID Protection. These are subscribed to by Microsoft services (Exchange Online, SharePoint Online, Teams); the page says latency of up to 15 minutes may be seen, and that CAE does not support guest users.
- The page does not state that Entra transmits SSF or CAEP SETs to a receiver the customer operates, nor which event types, subject formats, delivery methods or keys such a stream would use. **Microsoft transmission to a customer-operated receiver is not established. To probe.** No statement of Microsoft behaviour towards this receiver is written as a rule.

### 9.4 Summary

| | Okta | Google | Microsoft |
|---|---|---|---|
| Transmits SETs to a customer-operated receiver | Yes (SSF transmitter; page) | Yes (RISC; page) | Not established; to probe |
| `session-revoked` (CAEP) | Yes | No; `sessions-revoked` (RISC) | To probe |
| `credential-change` | Yes | No; `account-credential-change-required` | To probe |
| `assurance-level-change` | Not listed | Not listed | To probe |
| `account-disabled` / `account-enabled` | Not listed | Yes | To probe |
| `account-purged` | Not listed | Not listed; to probe | To probe |
| `credential-compromise` | Not listed | Not listed; to probe | To probe |
| Subject format | `iss_sub` (examples) | `subject_type` `iss-sub` (page) | To probe |
| Delivery | Not stated; to probe | Push (page) | To probe |
| Signing algorithm | Not stated; to probe | Sample code verifies with `RS256` (page); to probe | To probe |

## 10. Residual limits

- **Negative evidence only.** Silence is not a status. The fact exists only for a principal with an event. The status time is the last event's time, so a field rule on `account_state` with a status limit shorter than the age of the last event is not satisfied by a quiet principal. A deployment that needs a positive `active` within a short bound reads it from a live source on a path of its own and uses this source to veto; the library serves the one path `/principal/account_state`, and how an installed mapping combines two sources on one rule is open (section 11).
- **No clearing.** `session_revoked`, `credential_changed` and `assurance_changed` hold until a later event replaces them. No SSF event says the principal authenticated again, so the state blocks a requirement `equal active` after a revocation until an `account-enabled` event arrives or another source takes over. Fail closed is the chosen direction; the alternative that compares the state's event time with the principal's `AuthenticatedAt` is not built (section 11).
- **Missed events.** A transmitter retries a limited number of times (Google's page), does not buffer while a stream is disabled (same page), and may pause a stream (SSF 1.0 §8.1.2). An event lost in an outage is never seen. The mitigations are the stream-updated event, the verification event on a schedule, and a rule limit that does not outlive the declared delivery bound. None repairs a lost event.
- **Subject probing and removal.** SSF 1.0 §9.1: an add-subject `204` does not mean events will arrive; §9.3: events for a removed subject are tolerated. Both are met by ignoring.
- **Email recycled.** A mapped e-mail subject follows the address; the RISC `identifier-recycled` and `identifier-changed` events (RISC 1.0 §2.5, §2.6) are not interpreted, so a mapping by e-mail goes stale when an address is reassigned. Prefer `iss_sub` or `opaque` mappings.
- **Two signature algorithms.** ES256, and RS256 only for an issuer whose configuration lists it (section 3). A transmitter that signs with another algorithm is refused.
- **Order across transmitters.** Event times are the transmitter's own clocks. The receiver trusts them up to the skew in the future direction only.
- **Replay memory.** A restart empties the in-memory replay store; replays inside the accepted age then apply again (idempotent for a state older than the current one, which the order rule drops).

## 11. Open items and probes

| Item | Probe or decision |
|---|---|
| Microsoft transmission | Whether Entra transmits SETs to a customer-operated receiver at all; which events, subject format, delivery and keys. Probe: a test tenant, the vendor's configuration documents, a stream creation attempt |
| Okta delivery, `alg`, `typ`, latency, `event_timestamp` unit | Create a stream in a test org; record the transmitter metadata (`/.well-known/ssf-configuration`), `delivery_methods_supported`, the `jwks_uri` key algorithm, a sample SET header and the unit of `event_timestamp` |
| Google signing algorithm, `typ`, `account-purged`, `credential-compromise`, polling | Fetch the discovery document and the JWKS; trigger or wait for the events; record the `alg` of the keys and the `alg` and `typ` of a SET header. A `typ` other than `secevent+jwt` or `application/secevent+jwt`, or none, is refused by SR-3 and needs a new decision. The receiver supports RS256 per issuer configuration (section 3), so a deployment lists `RS256` for Google once the probe shows it; any other algorithm needs a new decision |
| Delivery latency per vendor | Time from the event at the identity provider to `applied`; this is the declared `best_status_max_age_seconds` |
| Positive `active` and sources on one path | How an installed mapping combines this negative source with a positive account-state source (owner decision) |
| Re-authentication after a revocation | Whether `session_revoked` and its kin should compare their event time with the principal's `AuthenticatedAt` (owner decision; the alternative is not built) |
| Hold candidate sink | Which component is the sink in a deployment: the hold store of the security authority (outside this source) |
| Durable replay store | A deployment that cannot tolerate a restart supplies one; none ships |

## 12. Primary sources read

All read on 2026-10-18, except where a row gives another date.

| Source | Sections used |
|---|---|
| RFC 8417, Security Event Token (`rfc-editor.org/rfc/rfc8417`) | §2.2 core claims, §2.3 explicit typing, §4 confusion with other JWTs |
| RFC 8935, Push-Based SET Delivery (`rfc-editor.org/rfc/rfc8935`) | §2, §2.1 to §2.4, §3 |
| RFC 8936, Poll-Based SET Delivery (`rfc-editor.org/rfc/rfc8936`) | §2, §2.2 to §2.4, §2.6 |
| RFC 9493, Subject Identifiers for SETs (`rfc-editor.org/rfc/rfc9493`) | §3.2.2, §3.2.2.1, §3.2.3, §3.2.4, §4.1 |
| OpenID Shared Signals Framework 1.0, 29 August 2025 (`openid.net/specs/openid-sharedsignals-framework-1_0.html`) | §3.1 to §3.6, §4.1.1 to §4.1.9, §4.2.1, §4.2.3, §6.1, §7.1, §7.2, §8.1.1 to §8.1.5, §9.1 to §9.3, §10.1. Sections 9 and 10 were read in part: the page text was truncated |
| OpenID CAEP 1.0, 29 August 2025 (`openid.net/specs/openid-caep-1_0.html`) | §2, §3.1 to §3.4 |
| OpenID RISC profile 1.0, 29 August 2025 (`openid.net/specs/openid-risc-1_0-final.html`) | §2.1 to §2.7, §2.11, §3.1 |
| Okta developer reference, SSF transmitter SETs; Okta help, configure a shared signal transmitter | section 9.1 |
| Google Identity, Cross-Account Protection (RISC), last updated 2026-03-22 (read again on 2026-10-19 for the algorithm named in its sample code and for the header parameters it names) | section 9.2 |
| RFC 7518, JSON Web Algorithms (`rfc-editor.org/rfc/rfc7518`), read on 2026-10-19 | §3.3 (RS256; "A key of size 2048 bits or larger MUST be used with these algorithms"), §3.4 (ES256), §6.2, §6.3 |
| RFC 7517, JSON Web Key (`rfc-editor.org/rfc/rfc7517`), read on 2026-10-19 | §4 (members not understood are ignored), §4.3 (`key_ops`; "Duplicate key operation values MUST NOT be present"), §4.5 (keys of different `kty` may share a `kid` as "equivalent alternatives") |
| RFC 8725, JWT Best Current Practices (`rfc-editor.org/rfc/rfc8725`), read on 2026-10-19 | §2.1 (an HMAC check that uses the RSA public key as the shared secret), §3.1 (a verifier takes a set of supported algorithms) |
| Microsoft Learn, Continuous access evaluation in Microsoft Entra, `ms.date` 2026-04-08 | section 9.3 |

Section numbers and quotations are those of the pages as retrieved on that date. A statement that a decision rests on is to be re-checked against the page when it is relied on, because the pages change.

## 13. Model `ssf/1` of the source cases

The cases are in [`../../fixtures/sources/ssf/`](../../fixtures/sources/ssf/), run by the harness of [`../../fixtures/sources/README.md`](../../fixtures/sources/README.md).

**`source`** members: `model` `ssf/1`; `source_id`; `principal_prefix` (IM-2: the namespace and realm components with a final `:`); `issuers` (each `{issuer, audience, jwks}` with `jwks` a JWK Set of public keys, RFC 7517, EC P-256 or RSA, served to the receiver as the issuer's `jwks_uri` document, so the rules of section 3, Key source, apply to it, and an optional `algorithms`, the issuer's algorithm list of section 3, `["ES256"]` when absent); `mappings` (each `{issuer, format, subject_iss, value, local}`, section 7); optional `max_age_seconds`, `authorization` (the push header value), `hold_on` (event type URIs), `critical_subject_members`.

**`inbound`** of a step is one of:

- `{"push": {"set", "decoded", "content_type", "authorization"}}`: one HTTP POST to the push endpoint. `set` is the compact SET; `decoded` is a documentation member (`signed_by`, `header`, `claims`) that the Go tests check against `set`; `content_type` defaults to `application/secevent+jwt`; `authorization` is the request header.
- `{"poll": {"sets", "more_available"}}`: the source polls once and the transmitter answers with `sets` (compact SETs by `jti`). The source then polls a second time and the transmitter answers with no SET; `ack` and `set_errs` of the step's `expect` are the members that second request carries.

**`expect`** of a step: `status` and `err` (push), `ack` and `set_errs` (poll), `telemetry` (the kinds of the receiver's records during the step, in order, exactly), and `holds` (the hold candidates raised during the step, in order, each `{principal, event_type, jti, event_time}`).

**`reads`** are the reads of the common envelope; every read is `/principal/account_state`.

The SETs of the cases are signed with the public test keys of [`../../fixtures/keys/`](../../fixtures/keys/README.md): `issuer.jwk.json` (kid `test-issuer-key-1`) stands in for the transmitter, and `adversarial.jwk.json` signs the forgeries under the transmitter's kid. ES256 signatures are randomized, so a regenerated case differs in its signature bytes; the Go tests verify each compact SET against its `decoded` member and its named key.

The RS256 cases (`ssf-20` to `ssf-25`) use RSA test keys that are public and for tests only, like the P-256 keys, and derived from a label so that anyone can recompute them. The `signed_by` of their `decoded` member is `rsa:<kid>` (an RS256 signature by that key, RSASSA-PKCS1-v1_5 being deterministic) or `hmac:<kid>:pkix-pem` and `hmac:<kid>:pkix-der` (an HS256 MAC keyed by the SubjectPublicKeyInfo of that key, in PEM or DER form). For a modulus of B bits, p and q have b = ceil(B/2) bits each. The candidate of p (role `p`) or of q (role `q`) is the first b/8 octets of the concatenation of SHA-256(label, 0x00, role, 0x00, i), i = 0, 1, ... as a four-octet big-endian integer, read big-endian. Its bit b-1 and bit 0 are set; then, for B even, bit b-2 is set, and for B odd, bits b-2 to b-4 are cleared, so that p times q has exactly B bits. The prime is the first of the candidate, candidate + 2, candidate + 4, ... that is prime and for which p-1 is not a multiple of e = 65537. The key is (n = p q, e = 65537).

| `kid` | Label | B | Leading hex of `n` |
|---|---|---|---|
| `test-rsa-key-1` | `ssf-rsa-1` | 2048 | `9c5d387d732ccb7f` |
| `test-rsa-key-1024` | `ssf-rsa-1024` | 1024 | `92e67f403c62a8c1` |
| `test-rsa-key-2047` | `ssf-rsa-2047` | 2047 | `458b132e4ae469f7` |
| (forger, in no key set) | `ssf-rsa-adversarial` | 2048 | `9d382b8e739e88c6` |

The Go tests recompute these keys and check each RSA JWK of the cases against them. `ssf-25` publishes the transmitter's EC key (`issuer.jwk.json`) under the kid `test-rsa-key-1` as well, beside the RSA key of that kid, so that one kid names a key of each type.

## 14. Fixture index

| Row | Case | What it pins |
|---|---|---|
| `SSF-01` | `ssf-01.session-revoked` | A session-revoked event replaces the cached `active` of its subject, with the event time as the as-of time; another principal keeps its state |
| `SSF-01` | `ssf-08.out-of-order` | An event older than the fact is not applied |
| `SSF-01` | `ssf-09.account-events` | Disabled, purged, credential-change (revoke) and assurance-level-change (decrease) set their states |
| `SSF-01` | `ssf-12.no-effect-and-unsupported` | A new credential, a raised assurance level and an unmapped event type change nothing |
| `SSF-01` | `ssf-18.legacy-event-subject` | The documented `subject_type` `iss-sub` placement and the deprecated `sessions-revoked` |
| `SSF-01` | `ssf-19.event-time-from-iat` | Without `event_timestamp` the as-of time is `iat` |
| `SSF-02` | `ssf-02.forged-signature` | A forged SET is rejected |
| `SSF-02` | `ssf-03.unsigned-and-unknown-key` | `alg` `none`, a header that says `HS256` over a valid ES256 signature, and an unknown kid are rejected |
| `SSF-02` | `ssf-13.audience-issuer-and-time` | Wrong audience, unconfigured issuer, `iat` in the future or too old; an audience array that lists the receiver is accepted |
| `SSF-02` | `ssf-14.claim-profile` | `typ` `JWT`, `sub`, `exp`, a malformed event, a millisecond `event_timestamp` and an `event_timestamp` after `iat` are rejected |
| `SSF-07` | `ssf-20.rs256-valid` | An RS256 SET is applied for an issuer whose list names RS256; ES256 still verifies; a forgery under the real RSA kid is rejected |
| `SSF-07` | `ssf-21.rs256-weak-key` | A key under 2048 bits (1024 and 2047) is refused though its signature verifies; a 2048-bit key is accepted |
| `SSF-07` | `ssf-22.alg-key-type-mismatch` | An RS256 header that names an EC key, and an ES256 header that names an RSA key, are rejected |
| `SSF-07` | `ssf-23.alg-not-in-allow-list` | The default list refuses RS256, a list of RS256 alone refuses ES256, per issuer |
| `SSF-07` | `ssf-24.hs256-rsa-public-key-secret` | HS256 keyed by the RSA public key (PEM and DER) is rejected |
| `SSF-07` | `ssf-25.kid-shared-across-key-types` | An EC P-256 key and an RSA key under one kid: an ES256-only issuer verifies ES256 with the EC key and refuses RS256, an RS256 issuer verifies RS256 with the RSA key |
| `SSF-03` | `ssf-04.replayed-jti` | A replay is not applied and cannot roll back a state; other content under a used `jti` is rejected |
| `SSF-04` | `ssf-05.unknown-subject` | Unmapped subjects are ignored with telemetry |
| `SSF-04` | `ssf-06.email-subject` | An e-mail subject resolves only through its exact mapping |
| `SSF-04` | `ssf-07.opaque-and-complex-subjects` | Opaque subjects; complex subjects by `user` |
| `SSF-05` | `ssf-10.compromise-hold-candidate` | A configured hold candidate |
| `SSF-05` | `ssf-11.compromise-no-hold-configured` | None without configuration |
| `SSF-06` | `ssf-15.poll-delivery` | Poll acknowledgments and `setErrs` |
| `SSF-06` | `ssf-16.verification-and-stream-updated` | Control events |
| `SSF-06` | `ssf-17.push-transport` | Media type and authorization of the push endpoint |

Planned: cases for a JWKS rotation and for a `paused` stream need a key-fetching step and are covered by Go tests only (`jwks_test.go`, `stream_test.go`).
