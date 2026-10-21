# PACT freshness and recheck profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose

The [draft](../draft.md) bounds the age of every fact an admission rests on (§7.5, §8.3, §9.2) and requires a gateway to track the current status of what it accepted (§18). It does not say what "age" means for a token, a replicated directory, a login session, an open file handle, a policy engine, or a relationship store, and these differ. This profile fixes the vocabulary, the arithmetic, and the rules that every integration profile (section 8 of the [template](TEMPLATE.md)) and every adapter shares:

- what a source observation time and a status check time are, and how they are compared with a field rule's two limits (sections 2 and 3);
- how each class of native source produces those two times, and the cache and replication bounds a profile declares for it (section 4);
- what an outage does (section 5);
- which facts are re-read at the four points where the draft checks them again: issuance, evaluation, sidecar handoff, and execution (section 6);
- why re-signing cannot make an old observation new (section 7).

It restates the draft's rules with their section and adds profile conventions. The "Basis" column of each table separates the two: "draft §x" cites a rule of the draft, "profile" marks a convention this document adds. A convention is adopted by an integration profile that cites this document. Where this document and the draft differ, the draft governs. Section 8 cross-references the reference implementation; the other sections are language-neutral.

## 1. Where it is used

| Consumer | Uses this profile for |
|---|---|
| Integration profile (template section 8 and 8.1) | The class of each source, its observation semantics, and the achievable bounds it declares |
| Adapter (`read_native_claim`, `check_context`, draft §17.1) | What to put in the observation time and the status time, and what never to put there |
| Validator (draft §11.3 steps 6 to 10) | How to compare the two times with a rule's limits, and which result to record |
| Gateway (draft §11.5, §2.3) | What is checked again at handoff and at execution |
| Conformance fixtures | The reason codes and results of section 3 |

## 2. Definitions

| Term | Meaning | Basis |
|---|---|---|
| Source observation time (`ObservedAt`; `source_observed_at` in a `CheckResult`; the `iat` of an evidence artifact) | The time at which the authoritative source itself established the value. It is not the time an adapter, cache, relay, or re-signing issuer received or forwarded it. The zero or null value means the source gives none. | draft §8.3, §9.2, Appendix A.2 |
| Status check time (`StatusCheckedAt`; `status_checked_at`) | The time of the last check that the value is still in force: an introspection response, a revocation or status list consulted, a membership lookup, or a live read. Null means no check took place. A check that was not performed is never reported as performed. | draft §8.3, §9.2, §17.2 |
| Evaluation instant (`now`) | The validator's clock when a rule is evaluated. Both ages are measured to it. | draft §7.5 |
| Evaluation start | The instant the evaluation began, taken before any source was read for it. An evaluation lasts at most 30 seconds and no longer than its inputs (`evaluation_seconds`). | draft §12.2, §20.1 |
| Clock skew | The tolerance for a clock running ahead. At most 5 seconds; there is no expiry grace. A deployment may tighten it. | draft §7.5, §20.1 |
| Source record | The thing a `SourceRef` names inside a `SourceID`: a token, a directory entry at a version, a session, a policy decision, a relationship revision. | draft §17.1; profile |
| Cached credential snapshot | A value fixed when a credential was issued. It is true as of that time and says nothing about later. | draft §17.2 |
| Current authoritative state | A value the source answers from its own present state. | draft §17.2 |

A field rule carries two limits (draft §9.2). `max_age_seconds` applies to the original source observation. `status_max_age_seconds` bounds cached revocation or membership-status checks, and zero requires a fresh authoritative check for this evaluation. The baseline default for cached evidence-status checks is 30 seconds, and sensitive native authority or hold checks should use zero (draft §18).

## 3. Evaluating the two limits

### 3.1 Rules

For one field rule of source `evidence` or `native` and the claim read for it, with `now` and the clock skew as above:

| # | Rule | Basis |
|---|---|---|
| 1 | A rule limit outside 0 to 2^53-1 is not a limit any source can meet. The result is `UNKNOWN`. | draft §7.1, Appendix A schema; profile |
| 2 | A time later than `now` plus the clock skew is a source clock running ahead. The result is `FAIL`. This outranks every finding but rule 1, because a time that cannot be true says nothing about age. | draft Appendix A.2 |
| 3 | If the claim carries a source reference, and the same record was seen before with an earlier observation time, the claim is a re-stamp. The result is `FAIL` and is treated as stale evidence (section 7). | draft §8.3; profile |
| 4 | An age above its limit is stale. Observation age is `now` minus `ObservedAt` against `max_age_seconds`; status age is `now` minus `StatusCheckedAt` against `status_max_age_seconds`. An age equal to the limit passes. The comparison is exact and is not rounded in the claim's favour. The result is `FAIL`. | draft §9.2, §7.5; profile |
| 5 | A limit of zero means the time was made in this evaluation: it must not precede the evaluation start. The draft defines zero only for `status_max_age_seconds`. This profile reads `max_age_seconds` of zero the same way. It fails closed, and an evidence artifact signed before the evaluation can never meet it. | draft §9.2; profile |
| 6 | A source that gives no time, or a time before the epoch (which has no wire form), cannot establish freshness, and unknown status is not evidence of validity. The result is `UNKNOWN`: the requirement is changed by an authorized publisher, or the exchange is deferred. | draft §8.3, §17.2 |
| 7 | A demonstrable failure outranks a missing time. A claim already known to be stale is `FAIL`, not `UNKNOWN`. | draft §11.4; profile |
| 8 | If the state that records sightings cannot be updated, the result is `UNKNOWN`. | draft §7.5, §18; profile |

The findings are ordered rule 1, then 2, then 3, then 4 and 5 together, then 6, then 8. `PASS` is returned only when none applies. The check never uses the wall clock: the evaluation instant is an input.

A `self` rule carries no source observation and both limits zero (Appendix A.2). It is not evaluated by this profile.

### 3.2 Results and reason codes

| Reason code | `CheckResult.result` | Admission decision | Meaning | Basis |
|---|---|---|---|---|
| `REQUIREMENT_SATISFIED` | `PASS` | Contributes to `ADMISSIBLE` | Both ages are within their limits and no time is ahead | draft §17.3.1 |
| `STALE_EVIDENCE` | `FAIL` | `INADMISSIBLE` | An age is above its limit | draft §13.4, §17.5 |
| `CLOCK_AHEAD` | `FAIL` | `INADMISSIBLE` | A source time is later than `now` plus the clock skew | profile |
| `RESTAMPED` | `FAIL` | `INADMISSIBLE` | A source record returned with a later observation time than the first one seen. It is treated as `STALE_EVIDENCE`: the same decision and the same transport error | profile |
| `UNSUPPORTED_REQUIREMENT` | `UNKNOWN` | `DEFERRED` | The source gives no usable time, or the rule's limit is not a valid one: the demanded freshness cannot be established | draft §13.4, §17.2 |
| `DEPENDENCY_UNAVAILABLE` | `UNKNOWN` | `DEFERRED` | A required source or state store cannot currently answer | draft §13.4, §17.3.1, §18 |

`CLOCK_AHEAD` and `RESTAMPED` are check-specific reason codes: a check returns its own stable reason (draft §17.1, §17.3.1). The §13.4 table has no member for a source clock running ahead.

The claim path has no such code. A `read_native_claim` whose source observation time or status time is later than `now` plus the clock skew is refused with `DEPENDENCY_UNAVAILABLE`: no source observation or status-check time may be later than `now` plus the clock skew (draft Appendix A.2), and the §13.4 table has no member for a claim whose source clock runs ahead. The adapter does not pass such a claim on, and does not replace the time with the time of the read (draft §8.3). A time ahead of `now` by no more than the skew is passed on unchanged. *Basis: draft §8.3, §13.4, §17.1, Appendix A.2; profile.*

### 3.3 Worked evaluations

Each row is one evaluation with the baseline skew of 5 seconds, an evaluation that began at `now`, and a rule of source `native` or `evidence`. Times are seconds relative to `now`. The rows are illustrative; they are not fixtures.

| `ObservedAt` | `StatusCheckedAt` | `max_age_seconds` | `status_max_age_seconds` | Result | Reason code | Why |
|---|---|---|---|---|---|---|
| `-10` | `0` | 30 | 0 | PASS | `REQUIREMENT_SATISFIED` | Within both limits, and the status was checked in this evaluation |
| `-30` | `0` | 30 | 0 | PASS | `REQUIREMENT_SATISFIED` | The observation age equals the limit |
| `-31` | `0` | 30 | 0 | FAIL | `STALE_EVIDENCE` | The observation is older than `max_age_seconds` |
| `-5` | `-1` | 30 | 0 | FAIL | `STALE_EVIDENCE` | Zero requires a check in this evaluation, and a status from one second ago is a cached one |
| `-5` | `-25` | 30 | 30 | PASS | `REQUIREMENT_SATISFIED` | A cached status within a 30 second limit |
| `-5` | `-31` | 30 | 30 | FAIL | `STALE_EVIDENCE` | The status check is older than `status_max_age_seconds` |
| `+5` | `0` | 30 | 0 | PASS | `REQUIREMENT_SATISFIED` | The source clock is ahead by exactly the skew |
| `+6` | `0` | 30 | 0 | FAIL | `CLOCK_AHEAD` | The observation time is later than `now` plus the skew |
| `0` | `+6` | 30 | 0 | FAIL | `CLOCK_AHEAD` | The status time is later than `now` plus the skew |
| `+6` | `-31` | 30 | 30 | FAIL | `CLOCK_AHEAD` | A source clock running ahead outranks staleness |
| `none` | `0` | 30 | 0 | UNKNOWN | `UNSUPPORTED_REQUIREMENT` | The source gives no observation time |
| `-5` | `none` | 30 | 30 | UNKNOWN | `UNSUPPORTED_REQUIREMENT` | No status check is on record |
| `-31` | `none` | 30 | 30 | FAIL | `STALE_EVIDENCE` | A demonstrable failure outranks a missing time |
| `-5` | `0` | 0 | 0 | FAIL | `STALE_EVIDENCE` | A `max_age_seconds` of zero requires an observation made in this evaluation |
| `0` | `0` | 0 | 0 | PASS | `REQUIREMENT_SATISFIED` | Both times were made in this evaluation |

## 4. Source classes, and cache and replication bounds

### 4.1 What each class of source can establish

Every native source an integration reads belongs to one class. The class decides which instant is the observation time and which is the status time, how soon a revocation becomes visible, and what bound the integration can declare. The table gives the default for each class; an integration profile states any departure.

| Class | Observation semantics | `ObservedAt` is | `StatusCheckedAt` is | Revocation is visible | Bound the profile declares |
|---|---|---|---|---|---|
| Token: signed or opaque access token, ID token, assertion | Cached credential snapshot of the issuer's state at issue time | The token's issue time (`iat`, an assertion's `IssueInstant`), never the time the gateway received, exchanged, or re-signed it | The time of the last introspection response, or the publication time (`thisUpdate` or the equivalent) of the last revocation or status list consulted. None when neither is used | At the next introspection, or at the next list publication | `max_age`: at most the token lifetime. `status_max_age`: for introspection, zero if the call reaches the issuer's live state, otherwise its cache time; for a list, its publication interval plus any cache time, at least 1. A token with no status mechanism cannot meet any status limit |
| Directory, replicated: LDAP, SCIM store, cloud directory | Current authoritative state at the answering replica (for a store the identity system pushes to, a SCIM service provider, the state as of the last push) | The instant the answering replica's state is known to reflect: its replication watermark, or the read time minus the declared replication lag when it has no watermark; for a pushed store, the read time minus the declared push lag, since a push protocol carries no as-of time. Never the bare read time of a replica | The same instant: the read is the status check | When a disable or removal replicates, within the replication lag | The replication lag plus any cache time. Zero only when the read reaches the authoritative primary with no cache |
| Session, live at the service provider | Session validity is current at the service provider's session store. Session attributes are a snapshot of the assertion made at login | For attributes, the assertion's issue time, not the last activity time. For session validity, the lookup time | The lookup time of the session record | A logout or termination at the service provider is visible at the next lookup. A revocation at the identity provider reaches it only through logout propagation or re-authentication, which this profile does not promise | `status_max_age`: zero for a live lookup. `max_age` for attributes: the age of the login assertion, bounded by the session lifetime or the re-authentication interval |
| File handle, open connection | Cached snapshot of the authorization decision at open | The time of the decision made when the handle or connection was opened | The same time | Not after open. A revocation takes effect at the next open or at a forced close | Both limits at least the age since open. A rule demanding fresher needs a new open, which is a new source record |
| Policy engine | Current authoritative decision at decision time, over a policy and data revision | The time the decision was computed. `SourceRef` names the immutable decision record, which carries the policy and data revision | The same time. The data the decision consulted may lag its own upstream by the declared data lag | At the next decision after the revision is active, plus the data lag | The data refresh interval |
| Relationship store | Authoritative at a declared consistency mode | The time the snapshot the check evaluated at reflects, not the request time and not the commit time of the last write it contains. `SourceRef` carries the revision or consistency token | The same time | At the next check at a revision that includes the change | Per mode. Fully consistent: reads the latest revision, zero achievable at a cost. At least as fresh as a supplied token: the age of that token. Minimize-latency: the declared maximum staleness of the store |

A class not in the table is described with the same six columns. A source whose observation and status times cannot be stated this way cannot establish the freshness a rule demands (draft §17.2).

### 4.2 Declaring the bounds

An integration profile declares, for each source it reads, in template section 8 and 8.1:

| Declaration | Meaning | Basis |
|---|---|---|
| Class and observation semantics | One class of section 4.1, and `authoritative` or `snapshot` (`value_semantics`: `authoritative_current` or `cached_snapshot`) | draft §17.2 |
| Cache bound | The longest time a cached answer is served after it was obtained | profile |
| Replication bound | The longest time the answering node can lag the authoritative one | profile |
| Best achievable `status_max_age_seconds` | The cache bound plus the replication bound, rounded up to whole seconds. Zero only when both are zero, that is, when the read reaches the authoritative source with no cache. At least 1 for a source with no live check | draft §17.2, §18; profile |
| Best achievable `max_age_seconds` | For a snapshot, the longest age of the snapshot the source produces. For an authoritative source, the best status bound | profile |
| Revocation propagation | How long a revocation takes to reach the gateway, and the consistency domain (template section 9) | draft §18 |

Three conventions follow from the bounds.

1. An adapter that reads a replica or a cache reports the as-of time of the state, not the read time (section 4.1, directory row). It then carries the lag in the time it reports, and no later step adds it. An adapter that cannot tell the as-of time reports the read time minus the declared lag bound. It does not claim a freshness it cannot establish, and it does not restamp a cached snapshot with the time of the read (draft §8.3, §17.2). *Basis: profile.*
2. A requirement is achievable only when each limit is at least the source's best bound. A publisher checks this before it issues a rule, and changes the requirement through its authorized path if it fails (draft §17.2). A validator checks it again before it reads: a rule with a limit below the best bound returns `UNKNOWN` with `UNSUPPORTED_REQUIREMENT`, so the exchange is `DEFERRED` and not `INADMISSIBLE`. Without this check an unachievable rule would fail as stale on every request. *Basis: draft §17.2; profile.*
3. A cache never extends a limit. A cached answer is usable while its reported times are within the rule's limits and not otherwise. *Basis: draft §9.2.*

## 5. Outage

| Condition | Result | Reason code | Decision | Basis |
|---|---|---|---|---|
| A required source cannot be reached | `UNKNOWN` | `DEPENDENCY_UNAVAILABLE` | `DEFERRED` | draft §17.1, §18 |
| The source answers but gives no usable time | `UNKNOWN` | `UNSUPPORTED_REQUIREMENT` | `DEFERRED` | draft §17.2 |
| A cached answer is outside the rule's limits and the source cannot refresh it | `UNKNOWN` | `DEPENDENCY_UNAVAILABLE` | `DEFERRED` | draft §18 |
| A replay store, hold store, active policy registry, receipt store, or the store that records source sightings is full or unavailable | `UNKNOWN` | `DEPENDENCY_UNAVAILABLE` | `DEFERRED` | draft §7.5, §12.2, §18 |

A cached answer outside the rule's limits is the outage of the third row, not the `FAIL` of section 3.1, rule 4, when its source declares no live check and so cannot refresh it: the validator tells the two apart by the source's declared capability, which it compares with the rule before the read (section 4.2, convention 2).

An outage is never a pass and never a failure of the agent. The profile prohibits last-known-good fallback beyond the rule's limits: no integration serves a stale answer because the source is down, and no outage widens a limit. A cached status that is still inside its limit is not an outage, and it is used. A store that is full refuses new records and does not evict old ones under load. The deferred decision carries bounded retry guidance (draft §11.4). An exchange does not wait for a source beyond its evaluation deadline: the evaluation expires, the check that was waiting for the source is `UNKNOWN`, and the receipt is `DEFERRED` with a specific terminal reason (draft §12.2).

PACT does not promise instantaneous global revocation when the underlying identity or policy system is eventually consistent (draft §18). A revocation the gateway acknowledges prevents subsequent admissions in that gateway's consistency domain. An operation already executed is not undone, and an operation in flight follows native cancellation and transaction semantics, which the adapter documents.

## 6. The four check points

The draft checks a fact again at four points. Each reads again the facts that move fastest and relies on a bounded age for the rest.

| Point | Draft anchor | Facts read again | Facts reused, and their bound | Failure |
|---|---|---|---|---|
| Issuance of the contract | §9.1, §11.1, §12.2 | Native authentication of the caller and the current agent/key binding and its status (`authenticate_native`, `resolve_agent_binding`). The active requirement revision and selected set. Security holds. The selection input. The achievability of each rule against the declared bounds of its source (section 4.2) | No field value is read at issuance, so none is reused. The contract is valid for at most 60 seconds | No contract is issued; or a rule the source cannot meet is changed by an authorized publisher before issue |
| Evaluation | §11.3 steps 2 to 10, §12.2 | The native identity and key binding. The requirement publisher and active policy. The time bounds of the presentation and the nonce. The actual operation. For each evidence artifact: signature, issuer scope, subject, holder, audience, realm, original observation age against `max_age_seconds`, expiry, and revocation state against `status_max_age_seconds`. For each native rule: the claim read through `read_native_claim`, with both ages compared as in section 3. Installed context checks, including approval-class checks (§17.3.1) and the selection re-derivation. At step 10, the final check that the contract is still active and that no hold or binding revocation became effective during evaluation | A cached status or membership fact, while inside its own limit | `INADMISSIBLE` for a failed fact; `DEFERRED` for an unavailable or unestablished one. A contract changed during the exchange gives `REQUIREMENTS_CHANGED` or `SELECTION_INPUT_CHANGED` (§11.3 step 9, §13.4) |
| Sidecar handoff | §11.5, §12.1 | The attestation: signature, validator, audience, subject, holder binding, native principal, environment, operation and intent digests, profile and requirement digests, decision, and expiry. Single use: the `jti` is marked consumed atomically. Current local security holds. Active requirement revisions. Native identity validity. Native authorization | The field values and source claims of the attestation: they are not read again. An `ADMISSIBLE` receipt is issued within 30 seconds of the evaluation start and is valid for at most 60 seconds from issuance, so a fact is at most its own limit plus 90 seconds old when the gateway accepts it | A stale positive attestation is rejected even if its signature is valid; a second handoff is rejected (`REPLAY`) |
| Execution | §2.3, §17.5, §17.4 | `authorize_native`, with the original principal and the actual operation: the current native decision, which PACT cannot rewrite and which wins over a PACT pass. The native execution conditions. Where installed: `execution-identity-v1`, and `execution-control-v1` for a containment control verified current for this exact operation | The PACT admission: it is not repeated, and it grants nothing the native decision denies. A native allow is not cached by PACT | A native denial: no execution. A changed executor identity: `FAIL` with `EXECUTOR_MISMATCH` |

Revocation and mid-exchange change are covered by these reads, as follows.

| Event | Where it is caught |
|---|---|
| The requirement revision changes after issuance | Evaluation: `REQUIREMENTS_CHANGED`; the selection input changes: `SELECTION_INPUT_CHANGED` |
| An evidence artifact, binding, or issuer is revoked before evaluation | Evaluation, against `status_max_age_seconds` |
| A hold or binding revocation becomes effective during evaluation | Evaluation step 10 |
| A hold, revision change, or identity change after the receipt is issued | Handoff: current holds, active revisions, native identity validity |
| A native permission or delegation is withdrawn after handoff | Execution: `authorize_native` |
| A revocation after a file handle or connection was opened | Not caught by PACT. The class has no revocation after open (section 4.1) and the adapter documents the residual limit |
| A source clock ahead, a stale snapshot, a re-stamped observation | Evaluation: `CLOCK_AHEAD`, `STALE_EVIDENCE`, `RESTAMPED` |

## 7. Re-signing and the monotonic rule

The observation time of a fact is the time the source established it. It does not move when the fact is copied, cached, forwarded, or signed again (draft §8.3). An adapter or issuer that stamps a stale fact with the time of the read, or re-signs it with a new `iat`, launders it: an hour-old fact reads as fresh.

| Event | `ObservedAt` | `StatusCheckedAt` | `SourceRef` | Basis |
|---|---|---|---|---|
| A cached copy is served again | Unchanged | Unchanged: the cache did not check | Unchanged | draft §17.2 |
| The status of the same record is checked again (introspection, list refresh, a live lookup that confirms the same record) | Unchanged | The time of the new check | Unchanged | draft §9.2 |
| An intermediary re-signs or relays a copy | Unchanged. A new `iat` on the copy is prohibited | Unchanged, unless the intermediary itself checked | Unchanged | draft §8.3 |
| The source establishes the value again and produces a new record: a new token, a new directory entry version, a new policy decision | The new time | The new time | New | profile |
| An adapter stamps `ObservedAt` with the time of the read | Prohibited | n/a | n/a | draft §8.3, §17.2 |

The rule is: a new `ObservedAt` requires a new `SourceRef`. The converse is the adapter's duty: it derives `SourceRef` so that it changes whenever `ObservedAt` does. A session that keeps one identifier while it is re-asserted names the record by the identifier together with the assertion's issue time, not by the identifier alone. An adapter that has no stable reference leaves `SourceRef` empty, and then nothing can be compared; its profile says the integration rests on the source clock alone and names that as a residual limit.

The validator enforces the rule with a monotonic guard. For each source record, identified by `SourceID` and `SourceRef` together, it remembers the first observation time it saw, in whole seconds as the wire carries them. A claim for the same record with a later observation time is `RESTAMPED`: `FAIL`, treated as `STALE_EVIDENCE`. The guard follows these conventions, all of them profile conventions:

- A claim seen once, however stale it was and whatever its result, sets the baseline. A fact refused as stale cannot return with a fresh time.
- A re-stamped time never becomes the baseline. An earlier time lowers the baseline.
- A time that is ahead of the clock by more than the skew is not recorded, because it is not a plausible observation.
- A claim with no `SourceRef`, or no usable `ObservedAt`, is not compared.
- The store is bounded. When it is full it refuses a new record and the result is `UNKNOWN` with `DEPENDENCY_UNAVAILABLE`; it never evicts to make room. The source retires a record with an explicit forget.
- The store is shared like replay state (draft §7.5) when several replicas serve one deployment. A guard local to one replica catches a re-stamp only among the claims that replica has seen.

## 8. Reference implementation (informative)

The reference implementation is the Go package `go/adapter/freshness`. It evaluates the rules of section 3 (`Evaluate`, and `Evaluator` for a tighter skew, an explicit evaluation start, and a guard) and implements the guard of section 7 (`Monotonic`). It takes the clock skew and the lifetimes from the Go package `go/core/clock` and does not re-implement them:

| `go/core/clock` | Value | Used for | Draft |
|---|---|---|---|
| `clock.BaselineSkew` | 5 seconds | The clock skew allowance and its ceiling (section 2, and rule 2 of section 3.1) | §7.5, §20.1 |
| `clock.MaxLifetime(clock.Contract)` | 60 seconds | The validity of a contract issued at the first check point | §9.1, §20.1 |
| `clock.MaxLifetime(clock.Presentation)` | 60 seconds | The validity of a presentation read at evaluation | §7.5, §20.1 |
| `clock.MaxLifetime(clock.Evidence)` | 3600 seconds | The longest lifetime of an evidence artifact; a rule may require fresher | §20.1 |
| `clock.MaxLifetime(clock.Snapshot)` | 300 seconds | The longest lifetime of a reputation snapshot, a source of class snapshot | §15.2, §20.1 |
| `clock.MaxLifetime(clock.Outcome)` | 300 seconds | The validity of an outcome report | §20.1 |
| `clock.MaxLifetime(clock.Profile)` | 86400 seconds | The lifetime of an agent profile | §20.1 |
| `clock.Clock`, `clock.Fake` | | The source of the evaluation instant, and its stand-in in tests | |

`clock.CheckWindow` and `clock.CheckPresentation` apply the window rules of §7.5 to a signed artifact (`nbf`, `iat`, `exp`); the evaluator applies the age rules of §9.2 to a fact the artifact carries or the adapter reads. They are separate checks. The 30-second evaluation deadline and the 60-second receipt validity are not in `go/core/clock`; they are limits and receipt rules of §12 and §20.1.

The achievability check of section 4.2, convention 2, needs the declared bound of the source, which the evaluator does not hold; the validator applies it before it reads. An adapter reports its times as the source gives them and returns an error that wraps `adapter.ErrDependencyUnavailable` when it cannot reach the source, which the validator maps to `UNKNOWN` and `DEFERRED` (section 5).

## 9. Residual limits

- PACT bounds the age of what it reads. It does not make an eventually consistent source consistent, and it does not promise instantaneous revocation.
- A source of class file handle or open connection has no revocation after open. The profile that claims such a source states what an open handle can still do and for how long.
- A claim with no source reference cannot be checked for re-stamping. The guard also does not see a re-stamp the first time a laundered fact arrives, when no earlier sighting exists; it detects the contradiction only against a sighting it holds.
- A source whose clock runs behind the validator's is not detected as ahead; its facts only look older, which fails closed.
- A zero `max_age_seconds` is read by this profile as "observed in this evaluation" and is the one place where this profile reads a value the draft leaves undefined (rule 5). A publisher who means "no age limit" cannot express it with zero.
