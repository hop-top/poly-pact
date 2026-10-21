# PACT multi-operation task, budget, retry, and side-effect profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## 1. Purpose and status

The [draft](../draft.md) says that a passing result for one operation cannot authorize a later action in a multi-step task by implication, that native systems keep transaction, budget, and idempotency enforcement, that `operation_id` is a correlation identifier and not a guarantee of exactly-once execution, and that an ambiguous non-idempotent action is never repeated automatically (§10.3). Every admission uses a new contract, a new presentation, and a new single-use receipt (§11.3, §11.5). Nothing in the draft says where the memory of a task lives across those exchanges. Without it, an agent that obtains a fresh contract starts again with a full budget, repeats an order or a restart that timed out, walks a listing again from its first page, or swaps the task label between calls.

This profile fixes that memory once for every integration profile and adapter that executes more than one downstream request for a task: a task ledger, keyed by the native task reference, that the gateway consults when it executes an admitted operation. It states:

- how a task is identified and how a client's `Intent.task_id` is reconciled with the native task (section 3);
- how approval, exception, and activation state is scoped to a task, and what a late approval cannot change (section 4);
- the budgets of a task, and why a fresh contract cannot reset them (section 5);
- idempotency keys and duplicate suppression, per class of executor (section 6);
- ambiguous effects and their reconciliation (section 7);
- completion tracking of asynchronous operations (section 8);
- cancellation and the terminal states of a task (section 9);
- paging bound to a task (section 10);
- the outcome reports that follow (section 11).

It answers the open finding G26 of the review. Section 12 maps each closure item of that finding to the rules and to the cases `TASK-01` to `TASK-09` of section 15. Section 13 works through samples I02, I03, I08, and I14 and points to U01, U06, and U07.

The document adds no wire field, no message type, and no check identifier to the draft. The ledger is a native-side control of the gateway, in the same position as the transaction and budget controls the draft leaves with the native system (§10.3, §17.3). It enforces after admission and before the downstream request. Where this document and the draft differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. Sections 3 to 11 are normative for a profile that claims enforced support for a route that can cause more than one downstream request for a task, or a downstream side effect that an agent can ask for again; sections 12 to 19 are informative. A profile can make a rule stricter. It MUST NOT weaken one.

The rules carry the identifiers MO-1 to MO-62 so that profiles, fixtures, and reviews can cite them. In the "Basis" column, "draft §x" cites the draft; "RB-n", "GR-n", and "FR" cite the [request binding](request-binding.md), [Graph](graph/profile.md), and [freshness](freshness.md) documents; an RFC, a draft, or a vendor page cites the part read for this document (section 18); and "profile" marks a convention this document adds. A statement about an external system that has no source read for this document is marked "to probe" and listed in section 17.

The textual dependencies of finding G26 are met by the draft as it stands: the approval, exception, and activation check results of §17.3.1 (finding G06) and the asynchronous rows of the native outcome mapping in §14.5 (finding G07). The delegation binding model of §17.5 (finding G03) supplies the principal, agent, and task binding the ledger uses. Draft §13.4 gives the limit refusals of the ledger the code `TASK_LIMIT`, and draft §14.5 gives an asynchronous operation that finishes cancelled its row; section 16 records those and the other gaps this document found.

### 1.1 Draft anchors

| Draft section | What it fixes for multi-operation work |
|---|---|
| §10.1 | `task_id` groups work of one native task or approval; a client-generated value is reconciled with the authoritative task context before it affects reputation deduplication; operations, pages, bytes, and idempotency keys are counted and recorded by the authoritative task reference, never by the client value. |
| §10.3 | A material change needs a new contract and presentation; a pass does not authorize a later action by implication; native systems keep budget and idempotency enforcement; `operation_id` is not exactly-once; native idempotency is used for side effects; an ambiguous non-idempotent action is not repeated automatically; a repeat of an ambiguous action is permitted only when the native idempotency mechanism is documented to suppress a duplicate and a native status check has shown that the action did not take effect. |
| §11.5, §7.5 | A positive attestation is consumed once; replay records are not evicted under load; a full or unavailable store causes deferral. |
| §12.2 | A sealed receipt is never reopened; waiting for an approval does not hold an evaluation open; an approval supports a fresh evaluation. |
| §13.4 | `TASK_LIMIT` (403) for a request refused because its native task has no budget left, is cancelled or completed, or is past its deadline; `CONTEXT_MISMATCH` for a continuation of another task. |
| §14.2, §14.3, §14.5, §14.6 | Executor evidence on every `EXECUTION` and `AUTHORIZATION` report; native denials and outages are not misconduct; the asynchronous, cancelled-completion, and ambiguous-timeout rows; one independence group per native task. |
| §17.3, §17.3.1 | An approval is bound to a native task or operation; the approval-class check results, including `APPROVAL_SCOPE_MISMATCH` for a task. |
| §17.5 | `Intent.task_id` reconciled with the authoritative task context; `native-delegation-v1` and `TASK_MISMATCH`; executor classes. |
| §18, §20.2 | Fail-closed deferral when a store is unavailable; native cancellation of in-flight operations; quotas per authenticated workload and tenant. |

## 2. Terms

| Term | Meaning in this document |
|---|---|
| Native task | The unit of work that the environment's task registry records, to which a native approval or delegation is bound (draft §10.1, §17.3). The registry is the `task_attribution_source` of the deployment (draft §17.5). |
| Native task reference | The registry's identifier of a native task, such as `native-task:september-summary-007` in draft Appendix B.2. It is opaque and compared octet for octet. |
| Task ledger | The gateway's durable store of one entry per native task, with the task's state, budget, counters, and operation records (section 3.2). |
| Ledger key | The tuple (`tenant_id`, `environment_id`, native task reference). |
| Logical operation | One intended downstream effect of a task, identified by its fingerprint (rule MO-27). Several admissions, contracts, and attempts can concern one logical operation of a write; each read is a logical operation of its own (rule MO-28). |
| Attempt | One downstream request sent for a logical operation. |
| Reservation | The atomic step that counts an attempt against the budget and records it before the request is sent. |
| Native status source | A read-only native lookup that tells whether a logical operation took effect or what became of an accepted one. |
| Async handle | The URL or reference in a 201 or 202 response that names where the status of an accepted operation is read. |
| Continuation | As in request binding (RB-57): a value in a downstream response that names the next page. |
| Refusal | The ledger declining to reserve. A refusal is a native control, not a PACT decision, and carries one of the labels of rule MO-11. |

## 3. Task correlation

### 3.1 Which task

| # | Rule | Basis |
|---|---|---|
| MO-1 | The ledger key is the realm (`tenant_id` and `environment_id`) together with the native task reference. A reference of another realm that is spelled the same is another key. | draft §17.2; profile |
| MO-2 | The native task reference comes from the task registry, read through `read_native_claim` over an approved native path of the installed mapping for the task of the declared intent. It never comes from the agent, the profile, the contract, the presentation, or a request header. | draft §10.1, §17.1, §17.5; profile |
| MO-3 | `Intent.task_id` is advisory. The gateway reconciles it with the registry: a value that the registry resolves, for this principal and agent, to exactly one native task reference gives that reference. A value that resolves to no reference, to a reference the principal's delegation does not name, or to more than one reference is refused with the label `task-mismatch`, and no counter changes. An unavailable registry is `DEFERRED` with `DEPENDENCY_UNAVAILABLE`. | draft §10.1, §17.5, §14.6 rule 2; profile |
| MO-4 | Several client values that the registry resolves to one reference share one ledger entry. A client value cannot create a second entry for a task, and changing the value between calls cannot split a budget (draft §10.1). | draft §10.1, §14.3; profile |
| MO-5 | The `task_id` of every `OutcomeReport` is the native task reference. A report that carries a client value that does not reconcile is `UNQUALIFIED`. | draft §14.3, §14.6 rules 1 to 3 |
| MO-6 | An entry exists only for a native task whose registry record is in the state `Active` when the entry is first made. The ledger adopts the limits of the registry record (rule MO-18). The entry is made at the first reservation, from the registry record; no part of it comes from the agent, and a contract issuance, an evaluation, or a receipt makes none. A reference with no registry record is refused with `task-unknown`; a reference whose record is terminal and that has no entry is refused by rule MO-62. | draft §17.5; profile |
| MO-7 | At the first reservation the ledger records the binding of the entry: the `principal_id`, the agent identifier, and the authenticated workload. A later reservation under another principal, another agent, or another workload is refused with `task-mismatch`. A credential that is renewed or refreshed and yields the same identifiers is the same binding; a refreshed credential that yields another principal or workload is not. | draft §17.5; RB-57; profile |
| MO-8 | The registry state of the task is read for each reservation of a side-effecting operation with a status age of zero, and for a read within the status limit the integration profile declares. A source that cannot answer is `DEFERRED` with `DEPENDENCY_UNAVAILABLE`; the ledger never serves a cached `Active` beyond that limit. | draft §18; FR section 3 |

### 3.2 The ledger entry

| Member | Meaning |
|---|---|
| Key | Rule MO-1 |
| Binding | Rule MO-7 |
| State | `Active`, `Completed`, `Cancelled`, or `Expired` (section 9) |
| Limits | `max_operations`, `max_pages`, `max_bytes`, `deadline` (section 5) |
| Counters | operations reserved, pages, bytes released |
| Operation records | Per logical operation: fingerprint, idempotency key, state, attempts, native references, async handle, times |

An operation record is in one of the states `Reserved` (recorded before the request is sent), `Accepted` (the native API acknowledged without completing), `Succeeded`, `Failed`, `Unknown` (an ambiguous effect), and `Released` (provably never sent). `Succeeded`, `Failed`, and `Released` are terminal for the record. A record found in `Reserved` after a restart of the gateway is treated as `Unknown`, because the request may have been sent (rule MO-35).

### 3.3 Where the ledger acts

The ledger acts at execution. With each admitted operation the gateway hands the ledger the authenticated principal, the enrolled agent, the client `Intent.task_id`, the operation context, the translation row, the continuation of a page request, and the length of the request body it sends (rule MO-61). A reservation is one of the native execution conditions of the expression in draft §2.3, and at the execution check point (FR section 6) the order is: the attestation is consumed (§11.5); `authorize_native` runs with the original principal; the ledger reserves; the downstream request is sent; the result is recorded. A denial by `authorize_native` reserves nothing. A deployment MAY also consult the ledger when it issues a contract or evaluates a presentation, to refuse early under an installed check of its own with an identifier it controls (draft §21); that is an optimization and does not replace the reservation.

The order of the ledger's own tests at a reservation is: the task state and the registry (MO-8), the binding (MO-7), the deadline (MO-23), the fingerprint (MO-27 to MO-32), then the budget (MO-19). The fingerprint test comes before the budget test, so that a repeated write (rule MO-28) is answered from the record of the earlier one and is not mistaken for a new operation that finds the budget spent. A read is never a repeat: it meets the budget test each time.

## 4. Approval, exception, and activation scope per task

| # | Rule | Basis |
|---|---|---|
| MO-9 | An approval-class check that applies to a multi-operation route binds the approval to the native task as well as to the agent, principal, purpose, and operation. An approval of another native task is a scope mismatch: `FAIL` with `APPROVAL_SCOPE_MISMATCH`, decision `INADMISSIBLE`. Which task the approval names is established by the check, from the native approval record. | draft §17.3, §17.3.1 |
| MO-10 | An evaluation that ends `DEFERRED` or `INADMISSIBLE` reserves nothing, and a pending approval consumes no operation of the budget. The deadline of the task keeps running while an approval is pending. | draft §12.2, §17.3.1; profile |
| MO-11 | The refusal labels of the ledger are `task-unknown`, `task-mismatch`, `task-completed`, `task-cancelled`, `deadline-elapsed`, `budget-exhausted`, `operation-in-flight`, `outcome-unknown`, and `idempotency-conflict`. They are labels of this profile for fixtures and logs, not reason codes of draft §13.4 and §17.3.1. A refusal labelled `budget-exhausted`, `deadline-elapsed`, `task-cancelled`, or `task-completed` is answered with the code `TASK_LIMIT` (403) of draft §13.4. The other labels have no code of draft §13.4, and the gateway answers them with its own native refusal. | draft §13.4; profile |
| MO-12 | An approval, an exception, or an activation that arrives later supports a fresh evaluation under a new contract. It never reopens a sealed receipt and never changes the ledger: it does not reset a counter, extend the deadline, or move a `Cancelled`, `Completed`, or `Expired` task back to `Active`. | draft §12.2, §17.3, Appendix B.12; profile |
| MO-13 | An approval does not raise a budget. A limit of the task is raised only by the native registry (rule MO-18). An amount, a resource set, or a duration in an approval is a scope of the approval and is checked by the approval-class check; the ledger does not interpret it. | draft §17.3; profile |
| MO-14 | An exception changes only the result of `authorize_native` (draft §17.3.1). Each operation is reserved only while the native decision for it is `allow`. An operation already sent when the exception expires is not undone; it follows native semantics, and later operations need the exception to be current. | draft §17.3.1, §18; FR section 5 |

## 5. Budgets

### 5.1 Dimensions and counting

| Dimension | Counted | Counter changes |
|---|---|---|
| `max_operations` | Each reservation of an attempt, including a page request, a retry that is a new operation, and a request later throttled by the native API | At the reservation |
| `max_pages` | Each reservation of a request that returns a page, the first page included | At the reservation |
| `max_bytes` | The bytes of downstream response bodies released to the agent. For a write, the bytes of the request body sent (rule MO-61) | After the response is read (rule MO-21); for the request body of a write, at the reservation (rule MO-61) |
| `deadline` | An instant, not a counter | Not applicable |

| # | Rule | Basis |
|---|---|---|
| MO-15 | A route that can cause more than one downstream request for a task states all four dimensions in its integration profile. A dimension is unlimited only when the registry or the mapping sets it to an explicit null, and the integration profile lists the dimension in its residual limits. A dimension that is simply not set is a configuration error, and the ledger refuses with `DEPENDENCY_UNAVAILABLE`. | profile |
| MO-16 | A status read of an operation already sent (section 8) is not an operation. Status reads are bounded by the attempts of the tracker (rule MO-45), not by `max_operations`. | profile |
| MO-17 | A reservation is atomic: the counters never pass the limits under concurrent requests, and a refusal changes no counter. The ledger is shared by every replica of the gateway as replay state is (draft §7.5). | draft §7.5; profile |
| MO-18 | The limits come from the native registry record of the task and may be lowered, never raised, by the installed mapping. A lower limit takes effect at the next reservation, even when it is below a counter. A higher limit takes effect only when the registry says so. No agent value, profile attribute, contract, or presentation sets or changes a limit. | draft §10.3, §17.2; profile |
| MO-19 | A reservation that would take `max_operations` or `max_pages` past its limit is refused with `budget-exhausted`, code `TASK_LIMIT` (draft §13.4). | draft §13.4; profile |
| MO-20 | A fresh contract, a fresh presentation, a new nonce, a new `operation_id`, a new access token, a new receipt, a new `Intent`, and the approval of section 4 do not create, reset, or reduce a counter. The ledger does not read any of them as a key. | draft §10.1, §10.3; profile |
| MO-21 | The gateway reads a downstream response through a bounded reader that stops at the remaining bytes plus one. A response that would take the counter past `max_bytes` is not released to the agent; the reservation stays counted and the attempt is recorded as it ended. A byte limit that the gateway cannot enforce on the response stream is not claimed. | RB-60; profile |
| MO-22 | A reservation is released (state `Released`, counters restored) only when the request provably was not sent: a failure to acquire the executor's token, a local validation failure, or a refusal after the reservation and before the send. Once any octet of the request may have left the gateway, the reservation stands. | profile |
| MO-23 | The deadline is the earliest of the registry's deadline for the task and the expiry of the native delegation or authority that the task rests on. A reservation is allowed only while `now` is before the deadline; at the deadline it is refused with `deadline-elapsed`, code `TASK_LIMIT` (draft §13.4). There is no grace. When the deadline passes the task is `Expired` (section 9). An operation already sent keeps its status tracking after the deadline (rules MO-40 and MO-45). | draft §7.5, §13.4, §17.5; profile |
| MO-24 | An entry is never evicted while the task is `Active` or any operation record of the task is not terminal. A terminal task keeps its entry at least as long as the outcome ingestion window (draft §14.3). A full or unavailable ledger is `DEFERRED` with `DEPENDENCY_UNAVAILABLE`; it is never read as an empty ledger, and a missing entry never means a fresh budget. | draft §7.5, §18; FR section 5; profile |
| MO-61 | The length of the request body of a write, which counts against `max_bytes` (section 5.1), is the number of octets that `body_digest` hashes: the exact request-body bytes after HTTP transfer decoding (draft §10.2), as the gateway sends them. The gateway hands the length to the ledger with the request (section 3.3). The ledger counts it at the reservation, before the request is sent. A write whose body would take the bytes past `max_bytes` is refused with `budget-exhausted`, code `TASK_LIMIT` (draft §13.4), as rule MO-19 refuses a reservation past its limit; nothing is sent and no counter changes (rule MO-17). An excess is never discovered after the send. An empty body has the length zero. | draft §10.2, §13.4; profile |
| MO-62 | A task whose ledger entry is missing and whose state is terminal is refused with the label of that state, as rule MO-50 does: `task-completed` when the registry reports it `Completed`, `task-cancelled` when it reports it `Cancelled`, and `deadline-elapsed` when its deadline (rule MO-23) has passed, code `TASK_LIMIT` (draft §13.4). No entry is made and no counter changes. `task-unknown` stays for a reference the registry has no record of (rule MO-6). | draft §13.4; profile |

A task whose entry is missing and that the registry reports `Completed` or `Cancelled`, or whose deadline has passed, is refused with the label of its state and no entry is made (rule MO-62), so the loss of a terminal entry does not reset the budget of a finished task.

## 6. Idempotency and duplicate suppression

### 6.1 Classes of executor

The integration profile states the class of each route that causes a downstream request.

| Class | The downstream request | Duplicate suppression | Examples |
|---|---|---|---|
| Read | A safe, idempotent method (RFC 9110 §9.2.2) | None needed. Each attempt is a new operation (MO-28, MO-34) | Graph message reads (I02, I08), a CRM read (I03) |
| Keyed write | A write for which the native API accepts a key and suppresses the repeat | The key from the ledger or the client; the native API suppresses, the ledger records | A procurement order (U06) |
| Ledger-deduplicated write | A write with no native key that the integration relies on | The ledger sends at most one request per logical operation, and the native status source reconciles | An Azure virtual machine restart (I14) |

| # | Rule | Basis |
|---|---|---|
| MO-25 | A write route has the class keyed write only when the integration profile cites the native documentation of the key: its header or field, how long the native API retains it, and what it does when the key returns with a different payload or while the first request is in flight. Without that citation the route is a ledger-deduplicated write. | draft §10.3, §17.3; profile |
| MO-26 | The key and the record are written before the request is sent (write-ahead). A gateway that restarts between the write and the send finds the record in `Reserved` and applies rule MO-35. | profile |
| MO-27 | The fingerprint of a logical operation is the `object_digest` (draft §7.4) of the JSON object with the members `task` (the native task reference), `principal_id`, `action`, `resources`, `method`, `target_uri`, `body_digest`, and `headers` of the operation context. It leaves out `operation_id` and `environment_id`, which can differ between exchanges for one effect (RB-29, open item O9 of request binding). | draft §7.4, §10.2; RB-29; profile |
| MO-28 | A write whose fingerprint equals that of a record of the same task that is not in `Failed` is a repeat of that logical operation. It is answered from the record (rule MO-31) and sends nothing. A record in `Failed` answers no repeat: a write whose fingerprint equals only that of records in `Failed` is a new logical operation and a new reservation (rule MO-32). Two intended writes that are identical in every covered member are one logical operation; an agent that needs both distinguishes them in a covered member, such as a line number in the body or a client-supplied key (rule MO-29). The rule applies to writes only. A read whose fingerprint equals that of an earlier read of the task is a new operation: it is reserved, counted, and sent again (rule MO-34). | RFC 9110 §9.2.2 [S1]; profile |
| MO-29 | When the route covers the `idempotency-key` header (RB-18, RB-55), the logical operation is identified by (task, client key), and the fingerprint is stored with it. The client key is copied unchanged to the native API. The same client key in the same task with another fingerprint is refused with `idempotency-conflict`; the same client key in another task is another logical operation. | RB-55; draft-ietf-httpapi-idempotency-key-header-07 §2.2, §2.4, §2.6; profile |
| MO-30 | For a keyed write with no client key, the ledger generates the key: a random identifier, a UUID or an identifier of equal strength, drawn once for the logical operation and retained. Every attempt of the logical operation sends that key. The key is never derived from `operation_id`, a nonce, or a token. | draft-ietf-httpapi-idempotency-key-header-07 §2.2, §5; profile |
| MO-31 | A repeat is answered from the record of the earlier request: `Succeeded`, `Accepted`, `Unknown`, or `Reserved`. A record in `Failed` answers no repeat: it does not block its fingerprint (rule MO-32). The answer carries the state and the native references. It does not replay a response body, which the ledger does not keep (draft §19). A repeat of a record in `Reserved` or `Accepted` that is still in flight is refused with `operation-in-flight`; one in `Unknown` is refused with `outcome-unknown`. | draft-ietf-httpapi-idempotency-key-header-07 §2.6; profile |
| MO-32 | A record in `Failed` does not block its fingerprint. A new request with the same fingerprint is a new logical operation and a new reservation. For a keyed write whose `Failed` came from reconciliation (rule MO-38) and not from a definitive rejection (rule MO-37), the new operation reuses the key of the failed one, because the status source can lag the native API; the native API then suppresses a duplicate. For a ledger-deduplicated write whose `Failed` came from reconciliation, a new attempt is allowed only after the native status source authoritatively confirms that the first attempt had no effect: a terminal native state that shows no effect, read under rule MO-38. An absence of evidence is not that confirmation; while it is missing the record stays `Unknown` and a request for the operation is refused with `outcome-unknown`, never repeated. Such a new attempt is not a repeat under draft §10.3, because the effect is no longer ambiguous. | draft §10.3; draft-ietf-httpapi-idempotency-key-header-07 §2.6; profile |
| MO-33 | A ledger-deduplicated write sends at most one request per logical operation. After it is sent, no further request is sent for that logical operation, whatever the response was, until the record is `Failed` (rule MO-32). | draft §10.3; profile |
| MO-34 | A read has no key. Graph reads follow GR-25: one downstream attempt per operation. A throttled read ends the operation, and a retry is a new operation under a new contract in the same task. It is reserved again and counts against `max_operations`. Graph states that retries accrue against its usage limits and recommends waiting the `Retry-After` period [S5]. | GR-25; RB-54; [S5]; profile |

### 6.2 Automatic repeats

| Condition | Repeat allowed |
|---|---|
| A read ended by a throttle or an error | Only as a new operation (MO-34) |
| A keyed write ended ambiguously | Only after reconciliation found no effect, as a new operation under the same key (MO-32), counted against the budget, and only if the integration profile cites the native API's behaviour for the key (MO-25, MO-36) |
| A ledger-deduplicated write ended ambiguously | Never automatically and never as a repeat (MO-33, MO-36). Only as a new attempt, counted against the budget, after the native status source authoritatively confirms that the first attempt had no effect (MO-32, MO-38); otherwise refused with `outcome-unknown` |
| Any write after a definitive failure | As a new logical operation (MO-32) |
| An accepted asynchronous operation | Never. The tracker reads its status (section 8) |

HTTP defines an idempotent method as one whose repeat has the same intended effect, lets a client repeat an idempotent request after a communication failure, and says that a client should not automatically retry a non-idempotent request unless it has some means to know the request semantics are actually idempotent or some means to detect that the original was never applied [S1]. The table is the gateway's means: a key the native API honours, or a status source that detects the effect. The draft goes further: a repeat of an ambiguous action is not automatic, and it is permitted only when the native system's idempotency mechanism is documented to suppress a duplicate and a native status check has shown that the action did not take effect (§10.3). The table's keyed-write row is that case: the ledger has first established that the effect did not occur, and the native API suppresses a duplicate if that finding was early. The ledger-deduplicated row is not a repeat in that sense: a new attempt follows only an authoritative native confirmation that the first attempt had no effect, after which the effect is no longer ambiguous (MO-32).

## 7. Ambiguous effects

| # | Rule | Basis |
|---|---|---|
| MO-35 | An effect is ambiguous when a request that may change native state has been sent, or may have been sent, and no response establishes the result: a timeout, a connection closed after the request was written, a response that cannot be read, a gateway restart with the record in `Reserved`, or a status the integration profile has not listed as definitive. | draft §14.5; profile |
| MO-36 | On an ambiguous effect the record becomes `Unknown` before anything else happens. The ledger sends no further request for the logical operation until reconciliation (rule MO-37) says it may. | draft §10.3; RFC 9110 §9.2.2 [S1]; profile |
| MO-37 | A response is a definitive failure only when the integration profile lists its status as one the native API documents as rejected before any effect. Success statuses are `Succeeded` or, for 201 and 202, `Accepted`. Every other response and every transport failure after the send is ambiguous. | profile |
| MO-38 | Reconciliation reads the native status source named by the integration profile. A result that shows the effect makes the record `Succeeded`, or `Accepted` with the handle. A result that shows no effect, from a source that is `authoritative_current` and read with a status age of zero, makes the record `Failed` (not applied). Any other result leaves the record `Unknown`. Reconciliation is bounded by the attempts of the tracker (rule MO-45). It only learns the outcome of a request already sent: it never reserves and never sends a request for the logical operation, so it continues after the deadline and after the task leaves `Active` (rule MO-50). The deadline bounds new sends, not learning the outcome: a reservation at or after it is refused with `deadline-elapsed` (rule MO-23). | draft §13.4, §17.2, §18; FR section 4; profile |
| MO-39 | A route whose integration profile names no native status source cannot be reconciled. Its `Unknown` records stay `Unknown`, and the integration profile lists that in its residual limits. A further attempt then needs a new native task, which is a native action. | profile |
| MO-40 | A reconciliation read is a native lookup of the integration profile and not a downstream request of the translation row (RB-54). The integration profile lists it with its enforcement points. It carries the executor identity class of the row. | RB-54; draft §17.5 |

## 8. Completion tracking

| # | Rule | Basis |
|---|---|---|
| MO-41 | A 201 or a 202 means accepted, not completed. HTTP defines 202 as accepted for processing with the processing not completed, noncommittal, with no facility to send a status later by HTTP itself, and expects a representation that points to a status monitor [S1]. The record becomes `Accepted` and the handle is stored. | draft §14.5; [S1]; [S2]; profile |
| MO-42 | For Azure Resource Manager the handle is the `Azure-AsyncOperation` URL if the response carries that header, and otherwise the `Location` URL; `Retry-After` gives the seconds to wait. The reference of the virtual machine restart operation lists a 202 response with `Location` and `Retry-After` and does not list `Azure-AsyncOperation` [S3]. Whether the restart response also carries `Azure-AsyncOperation` is to probe (P2). | [S2]; [S3]; profile |
| MO-43 | A handle is data from the native API. It is followed only when its origin and path prefix equal those configured for the native service in trusted gateway configuration, as a continuation is (RB-58), and never when it names another host. | RB-58; draft §20.2; profile |
| MO-44 | Azure: a status read of an `Azure-AsyncOperation` URL returns an object whose `status` is `Succeeded`, `Failed`, or `Canceled` for a finished operation, or another value, such as `InProgress` or `Running`, for one still running [S2]. `Succeeded` is completion, `Failed` and `Canceled` are terminal without success; a `Canceled` status is reported under the cancelled-completion row of draft §14.5. A read of a `Location` URL answers 202 while the operation runs; what a finished compute restart answers there is to probe (P3). The `provisioningState` of a resource is not read as the completion of an operation: the page ties `provisioningState` to create, update, and delete operations, and names the same three finishing values [S2]. | draft §14.5; [S2]; profile |
| MO-45 | The tracker waits the `Retry-After` period before each read: the seconds the native API gives, or the HTTP-date form of RFC 9110 [S1]. When the response has none, the integration profile declares a minimum interval and a back-off. Reads are bounded by `max_status_reads` per operation. When the bound is reached the record stays `Accepted`; exhaustion is not failure and is not success. | [S2]; RFC 9110 §10.2.3 [S1]; profile |
| MO-46 | Azure: to read the status of an asynchronous operation, permission at resource group level is needed, and a principal with permission on the resource only can start the operation and not track it [S2]. When the delegated principal's role is scoped to the single resource (example I14), the tracker may be unable to read. Then the record stays `Accepted`, the tracker reports `DEPENDENCY_UNAVAILABLE`, and no success is inferred. | [S2]; profile |
| MO-47 | The completion of an operation is not the completion of the task. The task is `Completed` only when the native registry says so (section 9). | example I14; profile |
| MO-48 | The native status read of a tracker uses the executor identity class of the row (draft §17.5), never a broader credential. | draft §17.5; RB-53 |

## 9. Cancellation

### 9.1 Task states

| State | Meaning | Set by |
|---|---|---|
| `Active` | The registry reports the task active and `now` is before the deadline | The registry |
| `Completed` | The registry reports the task done | The registry |
| `Cancelled` | The registry, or the requestor through authenticated native session control, cancelled the task | The registry |
| `Expired` | The deadline passed | The clock (rule MO-23) |

| # | Rule | Basis |
|---|---|---|
| MO-49 | A state other than `Active` is terminal and immutable. The first terminal state wins. A fresh contract, an approval, a new token, or a registry record that reappears under the same reference does not return the task to `Active` (rule MO-12). | draft §12.2; profile |
| MO-50 | In any state but `Active`, a reservation is refused: `task-completed`, `task-cancelled`, or `deadline-elapsed`, code `TASK_LIMIT` (draft §13.4). The same labels answer a terminal task whose entry is missing (rule MO-62). Status reads and reconciliation of operations already sent continue (rules MO-40, MO-45). | draft §13.4; profile |
| MO-51 | Cancelling the task does not undo an operation already sent. Revocation does not undo an executed operation, and an in-flight operation follows native cancellation and transaction semantics, which the adapter documents. | draft §18; FR section 5 |
| MO-52 | Cancellation of the local call is not a cancellation of the native effect. If the context of a call ends before the request was sent, the record is `Released`. If it ends after the request may have been sent, the record is `Unknown` (rule MO-35). | RFC 9110 §9.2.2 [S1]; profile |
| MO-53 | Native cancellation is used only where the native API documents it and the integration profile lists the cancel request as a downstream request of the row (RB-54), with its executor class. A cancel request sent for an accepted operation is recorded; the operation is `Failed` only when the native status says so. Azure reports a `Canceled` operation status [S2]; a cancel request for a virtual machine restart is not established by any source read, and none is claimed (P4). | RB-54; [S2]; profile |
| MO-54 | A cancellation of an evaluation through native authenticated session control is a transition of draft §12.2 and receives a `DEFERRED` receipt. It reserves nothing and does not cancel the task. | draft §12.2 |

## 10. Paging bound to a task

| # | Rule | Basis |
|---|---|---|
| MO-55 | Each page is its own operation (RB-56, GR-24). A page request reserves one operation and one page. The first page counts as a page. | RB-56; GR-24; profile |
| MO-56 | The continuation record of RB-57 names the native task reference. A continuation presented under another native task, principal, agent, row, or mapping version is refused with `CONTEXT_MISMATCH` before any reservation (RB-58), and no counter changes. Changing `Intent.task_id` for the second page changes nothing: the reference is resolved by rule MO-3, and a value that resolves to another task meets this rule. | RB-57; RB-58; draft §13.4; profile |
| MO-57 | Starting the listing again from the first page counts again. Pages are counted per task, not per listing, so a new listing does not reset `max_pages`. | profile |
| MO-58 | A continuation ends with its task. A token presented after the deadline of the task has elapsed is refused with `deadline-elapsed`, one presented after the task is completed with `task-completed`, and one presented after it is cancelled with `task-cancelled`: the labels of rule MO-50, code `TASK_LIMIT` (draft §13.4). The refusal changes no counter (rule MO-17). The lifetime of a continuation does not exceed the deadline of the task. | draft §13.4; profile |
| MO-59 | A page whose response would take `max_bytes` past its limit is not released (rule MO-21), and its continuation is not recorded. | profile |
| MO-60 | The link followed for page n+1 is the link of the last successful response. For directory resources Graph says that a token obtained from a retry is not guaranteed to be valid for later pages, and tells clients to use the token of the last successful, non-retry response [S4]. Whether this applies to message listings is to probe (P5). | [S4]; profile |

## 11. Outcomes and reputation

The ledger adds no row to draft §14.5. Each event of this profile maps to a row of that table.

| Event | Report (draft §14.5) | Weight and notes |
|---|---|---|
| A refusal of the ledger (`budget-exhausted`, `deadline-elapsed`, `task-cancelled`, `task-completed`, `task-mismatch`, `task-unknown`, `idempotency-conflict`) | "Native denial": `AUTHORIZATION`, `FAILURE`, `none` | Zero weight and not misconduct (draft §14.3). The limit refusals are answered with `TASK_LIMIT` (draft §13.4, rule MO-11). A repeated attempt past a spent budget is not a detected policy violation unless the integration profile says so under draft §14.2 |
| A repeat answered from the record (`operation-in-flight`, `outcome-unknown`) | None | No new execution took place |
| An attempt answered `Succeeded` with data | "Execution completed with data returned": `EXECUTION`, `SUCCESS`, `reliability` | One report per operation, under that operation's `operation_id` |
| An attempt accepted, not completed | "Asynchronous request accepted": `EXECUTION`, `UNKNOWN`, `none` | Zero weight, new `event_id` |
| Completion observed by the tracker | "Asynchronous completion observed": `EXECUTION`, `SUCCESS` or `FAILURE`, `reliability` | Separate `event_id` |
| Completion observed by the tracker with the native status `Canceled` | "Asynchronous completion observed with status cancelled": `EXECUTION`, `FAILURE`, `reliability` | Counts toward `reliability`; `details` is `"cancelled"`; `causal_assessment` is `UNKNOWN` unless the executor establishes who cancelled, so zero negative weight (draft §14.6 rule 8) |
| An ambiguous effect (`Unknown`) | "Ambiguous timeout": `EXECUTION`, `UNKNOWN`, `none` | Zero weight; reconcile natively |
| A reconciliation that shows the effect | The report of the observed result, under a new `event_id` | The deduplication tuple differs by dimension (draft §14.3) |

Every `EXECUTION` and `AUTHORIZATION` report references the immutable native record of the actual executor (draft §14.2). Subdivided or repeated operations within one native task collapse into one independence group (draft §14.6 rule 3), so a ledger that admits many operations does not multiply the positive weight of a task.

## 12. G26 closure map

| Closure item (finding G26) | Rules | Cases (section 15.1) |
|---|---|---|
| Task correlation | MO-1 to MO-8, MO-62 | `TASK-07` |
| Page correlation | MO-55 to MO-60 | `TASK-04` |
| Approval scope per task | MO-9 to MO-14 | `TASK-09`; existing approval and delegation cases (section 15.2) |
| Native idempotency keys | MO-25 to MO-34 | `TASK-02` |
| Limits: operations, pages, bytes, deadline | MO-15 to MO-24, MO-61 | `TASK-01`, `TASK-04`, `TASK-08` |
| Ambiguous effects | MO-35 to MO-40 | `TASK-05` |
| Completion tracking | MO-41 to MO-48 | `TASK-03` |
| Cancellation across new contracts | MO-49 to MO-54 | `TASK-06` |
| Evidence: fresh contracts cannot reset budgets | MO-18, MO-20, MO-24 | `TASK-01`, `TASK-07` |
| Evidence: fresh contracts cannot duplicate orders or restarts | MO-26 to MO-33 | `TASK-02`, `TASK-05` |
| Evidence: paging stays task-bound | MO-55 to MO-58 | `TASK-04` |
| Evidence: ambiguous effects are reconciled, not retried blindly | MO-35 to MO-39 | `TASK-05` |

The cases are tests of the Go package `go/adapter/task` of the source repository, not part of the mirror (section 15.1).

## 13. Worked tables

Every number below is illustrative. Counters read operations, pages, and bytes after the row.

### 13.1 I02: mailbox pages (GD1, GD2 of the [Graph profile](graph/profile.md))

Task `native-task:mailbox-summary-0731`. Limits: `max_operations` 12, `max_pages` 5, `max_bytes` 1,048,576, deadline 1,800 seconds after the task start. Each page releases 40,000 bytes.

| # | Event | Result | Counters |
|---|---|---|---|
| 1 | First page, contract C1 | Reserved, sent, continuation recorded under the reference (RB-57) | 1 / 1 / 40,000 |
| 2 | Page 2, contract C2, same task | Reserved | 2 / 2 / 80,000 |
| 3 | The page-2 token presented with an `Intent.task_id` that resolves to another task | `CONTEXT_MISMATCH` (MO-56); no reservation | 2 / 2 / 80,000 |
| 4 | The agent starts the listing again, contract C3 | Counts (MO-57) | 3 / 3 / 120,000 |
| 5 | Page 2 of the new listing | Reserved | 4 / 4 / 160,000 |
| 6 | Page 3 | Reserved | 5 / 5 / 200,000 |
| 7 | Page 4 | `budget-exhausted`: pages 5 of 5, operations 5 of 12 | 5 / 5 / 200,000 |
| 8 | A new contract and presentation for a first page | `budget-exhausted` (MO-20); nothing reset | 5 / 5 / 200,000 |

Cases: `TASK-04` (rows 3 and 7), `TASK-01` (row 8), `TASK-07` (row 3).

### 13.2 I03: customer record reads

Task `crm-task:renewal-C-481`, bound to Maya, the agent, and the client. Limits: `max_operations` 3, deadline 900 seconds.

| # | Event | Result | Counters |
|---|---|---|---|
| 1 | Read C-481 with token t1 | Reserved | 1 / 0 / n |
| 2 | Token refreshed to t2 (same `oid`, same client); fresh contract; read | Same entry (MO-7, draft §17.5); the refresh is not an operation | 2 / 0 / n |
| 3 | Token t3 of another user, same client | `task-mismatch` (MO-7) | 2 / 0 / n |
| 4 | Third read | Reserved | 3 / 0 / n |
| 5 | Fourth read, new contract | `budget-exhausted` | 3 / 0 / n |

If the registry lowers `max_operations` to 2 after row 2, row 4 is `budget-exhausted` (MO-18). Cases: `TASK-01` (row 5), `TASK-07` (row 3). Row 2 is the refreshed-authority detection of rule MO-7.

### 13.3 I08: scheduled queue summary

Task `native-task:queue-summary-run-0412`, issued by the scheduler's registry for one run. Limits: `max_operations` 8, `max_pages` 6, deadline 600 seconds. Each page 50,000 bytes.

| # | Event | Result | Counters |
|---|---|---|---|
| 1 | Page 1 | Reserved | 1 / 1 / 50,000 |
| 2 | Page 2, new contract | Reserved | 2 / 2 / 100,000 |
| 3 | The agent names run 0413, not yet started | `task-unknown` (MO-6) | 2 / 2 / 100,000 |
| 4 | The scheduler marks run 0412 done | `Completed` (MO-49) | 2 / 2 / 100,000 |
| 5 | Page 3 of run 0412 | `task-completed` (MO-50) | 2 / 2 / 100,000 |
| 6 | Run 0413 starts; the registry issues the reference | A new entry with new counters (registry action, MO-6) | 0 / 0 / 0 |

The budget of a run is renewed only by a new reference that the registry issues. If the registry names the schedule and not the run, the budget spans every run of the schedule; the integration profile states which (section 14). Cases: `TASK-06` (rows 4 and 5), `TASK-07` (row 3).

### 13.4 I14: virtual machine restart

Task `native-task:incident-1177-vm-restart`. The restart row is a ledger-deduplicated write. Limits: `max_operations` 1, deadline 3,600 seconds.

| # | Event | Result | Counters |
|---|---|---|---|
| 1 | Activation pending | `UNKNOWN`, `APPROVAL_PENDING`, `DEFERRED`; nothing reserved (MO-10) | 0 / 0 / 0 |
| 2 | Activation completes; fresh contract; `ADMISSIBLE`; `authorize_native` allows | Reserved; record `Reserved`; `POST .../restart?api-version=2025-04-01` sent [S3] | 1 / 0 / 0 |
| 3 | Azure answers 202 with `Location` and `Retry-After` | Record `Accepted`; handle stored (MO-42); `EXECUTION`, `UNKNOWN`, `none` | 1 / 0 / 0 |
| 4 | The agent, impatient, obtains contract C3 and asks again | Fingerprint equals the record: answered `operation-in-flight` (MO-31); no request | 1 / 0 / 0 |
| 5 | The tracker reads the handle after `Retry-After`; the operation runs | Stays `Accepted` (MO-45) | 1 / 0 / 0 |
| 6a | The status is `Succeeded` | Record `Succeeded`; `EXECUTION`, `SUCCESS`, `reliability`; the task stays `Active` (MO-47) | 1 / 0 / 0 |
| 6b | The status is `Failed` | Record `Failed`; `EXECUTION`, `FAILURE`, `reliability`; a new restart is a new reservation and is `budget-exhausted` until the registry raises the limit (MO-18, MO-32) | 1 / 0 / 0 |
| 6c | The POST times out before any response | Record `Unknown` (MO-35); no second POST (MO-33); reconcile through the native status source (P1) or stay `Unknown` | 1 / 0 / 0 |
| 6d | The tracker cannot read the handle for lack of permission | Stays `Accepted`; `DEPENDENCY_UNAVAILABLE`; no success inferred (MO-46) | 1 / 0 / 0 |

Cases: `TASK-02` (row 4), `TASK-03` (rows 3, 5, 6a, 6b, 6d), `TASK-05` (row 6c), `TASK-09` (rows 1, 2).

### 13.5 U01, U06, U07

| Use case | What the profile adds | Rules | Cases |
|---|---|---|---|
| U01: invoices | Every invoice is its own bound operation under the registered task. The ledger counts them against `max_operations` and `max_bytes`; the independence group stays one (draft §14.6 rule 3). A task label turns nothing into a session permission | MO-1 to MO-7, MO-15 to MO-20 | `TASK-01`, `TASK-07` |
| U06: purchase | The order is a keyed write. The first exchange is `DEFERRED` and reserves nothing. After approval, a fresh exchange reserves once, with the ledger's key; a retry after a timeout reconciles first and never sends a second order without the same key | MO-9 to MO-13, MO-25 to MO-31, MO-35 to MO-38 | `TASK-02`, `TASK-05`, `TASK-09` |
| U07: exception | Each later read reserves while the exception is current. An exception that expires does not undo a read already sent. A read past the deadline is refused | MO-14, MO-23, MO-50, MO-51 | `TASK-08`, `TASK-09` |

## 14. Using this document in an integration profile

| Template section | What the profile states |
|---|---|
| 1. Claim scope | That the claim uses this document at version 0.1 and which routes it applies to, and every rule made stricter |
| 2. Protected routes | The class of each route (section 6.1), and the native task reference path of the mapping |
| 3. Enforcement points | The ledger reservation at execution (section 3.3); the reconciliation lookup (MO-40); the task registry read (MO-2, MO-8) |
| 4. Native dependencies | The task registry under C04; the ledger and async tracker under C15; the executor under C08 |
| 6. Unsupported forms | Routes that cause more than one downstream request and have no registry task; a keyed write with no cited key behaviour (MO-25) |
| 8. Freshness | The status limit of the registry for reads (MO-8); the reconciliation source's class and bound (MO-38) |
| 9. Residual limits | Unlimited dimensions (MO-15), routes without reconciliation (MO-39), identical writes that the agent cannot distinguish (MO-28), and the schedule-or-run choice for scheduled tasks (section 13.3) |
| 10. Fixtures | The cases of section 15 that the routes can meet |

## 15. Fixtures

### 15.1 Cases

Until a scenario case kind exists (section 15.3), the cases below are tests of the Go package `go/adapter/task` of the source repository, not part of the mirror: the test `TestTaskCases`, one subtest per id. They are not fixture cases. None is registered in the fixture manifest, and an integration profile does not list one in its `fixtures`. The expected values come from the rules above and the worked tables of section 13, not from an implementation; each case cites its rules. The ids follow the style `TASK-NN` and `TASK-NN.variant` of the adapter case families.

| Id | Variants | Setup and expected result | Rules |
|---|---|---|---|
| `TASK-01` | `max-operations`, `max-bytes`, `registry-lowered-limit` | The task has reached its limit; a new contract for the same native task is refused with `budget-exhausted`, no counter changes, and the fake native service sees no request. Identical reads are each reserved and sent (MO-28). For bytes, a response past the remaining bytes is not released, and the request body of a write counts at the reservation: a write whose body would pass `max_bytes` is `budget-exhausted` and is not sent. A lowered registry limit applies at the next reservation | MO-15 to MO-22, MO-28, MO-61 |
| `TASK-02` | `keyed-write`, `restart-dedupe`, `key-other-payload`, `key-other-task` | The same logical operation presented under a second contract: exactly one native request. The same client key with another payload: `idempotency-conflict`. The same key in another task: a separate operation | MO-25 to MO-33 |
| `TASK-03` | `accepted-not-completed`, `succeeded`, `failed`, `cancelled`, `poll-exhausted`, `handle-other-origin`, `tracking-forbidden` | A 202 gives `Accepted` and an `EXECUTION`, `UNKNOWN`, `none` report until a terminal status; a `Canceled` status gives the cancelled-completion row of draft §14.5; exhaustion of polls stays `Accepted`; a handle on another origin is not followed; an unreadable handle stays `Accepted` | MO-41 to MO-47 |
| `TASK-04` | `other-task`, `beyond-max-pages`, `listing-restart`, `unknown-token`, `expired-task` | A continuation under another task is refused with `CONTEXT_MISMATCH` and no reservation; a page past `max_pages` is `budget-exhausted`; a new listing counts again; a continuation of a task past its deadline is `deadline-elapsed`, of a cancelled task `task-cancelled`, of a completed task `task-completed` | MO-55 to MO-60 |
| `TASK-05` | `timeout-reconcile`, `status-indeterminate`, `restart-timeout` | A timed-out write: the record is `Unknown`, the native status source is read, and the fake native service sees no second write. An indeterminate status leaves `Unknown` | MO-35 to MO-40 |
| `TASK-06` | `cancel-mid-task`, `completed-task`, `context-after-send`, `context-before-send`, `fresh-contract-after-cancel` | After the registry cancels the task, a new reservation is `task-cancelled`; after it completes the task, `task-completed`; a call cancelled after the send is `Unknown`; before the send it is `Released` and the counters are restored; an ambiguous write sent before the cancellation is still reconciled, with no new request | MO-38, MO-49 to MO-54 |
| `TASK-07` | `alias-same-reference`, `unknown-reference`, `unreconciled-id`, `other-principal`, `swap-between-calls`, `terminal-no-entry` | A client value that resolves to the same reference shares the budget; one that does not resolve is `task-mismatch`; a reference with no registry record is `task-unknown`; a `Completed`, `Cancelled`, or past-deadline task with no entry is `task-completed`, `task-cancelled`, or `deadline-elapsed`; another principal under the reference is `task-mismatch`; counters are unchanged by every refusal | MO-1 to MO-7, MO-62 |
| `TASK-08` | `deadline-elapsed`, `just-before-deadline`, `status-after-deadline` | At the deadline a reservation is `deadline-elapsed`; one second before it is admitted; the status of an operation already sent is still read, and an ambiguous one is still reconciled, with no new request | MO-23, MO-38, MO-50 |
| `TASK-09` | `approval-other-task`, `late-approval-no-reset`, `pending-reserves-nothing` | An approval bound to another native task: `APPROVAL_SCOPE_MISMATCH`; an approval that arrives after the task is `Expired` does not revive it; a `DEFERRED` evaluation changes no counter | MO-9 to MO-13 |

The fake native service of these cases counts the requests it receives per route, so that "exactly one request" and "no second write" are assertions on the fake and not on the ledger's own record. A stub ledger keyed on the client `task_id` must fail `TASK-01` and `TASK-07`; the package's tests hold such a ledger and check that it does.

### 15.2 Existing cases that bear on this profile

| Case | Bears on |
|---|---|
| `approval/wrong-scope-resource`, `approval/wrong-scope-amount`, `approval/approved-fresh-exchange` | Rules MO-9 and MO-12: the scope of an approval is checked, and a later approval is a fresh exchange. No existing approval case varies the task |
| `delegation/changed-task` | `native-delegation-v1` with `TASK_MISMATCH` (draft §17.5); rule MO-3 |
| `adapters/graph/graph-09.other-principal`, `adapters/graph/graph-09.other-row`, `adapters/graph/graph-10.continuation` | Continuations of another principal or row are refused (RB-58); no existing case varies the task, and none counts pages |

### 15.3 Case format

The adapter case format ([`fixtures/adapters/README.md`](../fixtures/adapters/README.md)) has a case call one of the seven functions of draft §17.1. The ledger is not one of them, and the manifest has no outcome value for a ledger result. The cases need a scenario form: a sequence of steps against a task registry, a ledger, and a fake native service, with the counters and the fake's request count as assertions. Open item OI-1 records the gap. Until it is closed the cases are Go package tests (section 15.1).

## 16. Gaps in the draft

This section is informative. It records the gaps this document found in the draft. D1 to D4 were proposed here and are applied to the draft.

| # | Gap | Status |
|---|---|---|
| D1 | No code for a protected request refused because a native task limit is spent, a task is cancelled or completed, or its deadline passed | Applied: draft §13.4 `TASK_LIMIT` (403); rules MO-11, MO-19, MO-23, MO-50 |
| D2 | No row for an asynchronous operation that finishes with the native status `Canceled` | Applied: draft §14.5 row "Asynchronous completion observed with status cancelled"; rule MO-44, section 11 |
| D3 | No statement of when a repeat of an ambiguous action is permitted | Applied: draft §10.3; section 6.2, rule MO-32 |
| D4 | Reconciliation of `task_id` required before reputation deduplication, not before a budget or an idempotency record | Applied: draft §10.1; rules MO-4, MO-20 |
| D5 | No budget or retention limit for a task ledger in draft §20.1 | Open. No text proposed; section 5 leaves the numbers to the integration profile |

## 17. Open items and probes

### 17.1 Open items

| # | Item | What settles it |
|---|---|---|
| OI-1 | The adapter case format cannot express a ledger scenario (section 15.3), and the manifest `outcome` enum has no value for a refusal. | A scenario case kind with its own README and schema, and a manifest outcome value; or a decision that the ledger is tested as a Go package only. Decided for now: the ledger is tested as a Go package only (section 15.1); a scenario case kind stays open |
| OI-2 | The suite of adapter cases runs `_common` cases for every adapter (`fixtures/adapters/README.md`); the ledger cases are for adapters that execute more than one request for a task. The format has a `workloads` member and no member for a capability. | A capability member for the case format, or an adapter directory for the cases |
| OI-3 | The native task reference path (MO-2) has no name in the draft. The delegation `authority_ref` is an opaque reference until the delegation binding model names its structure (Graph profile, GR-27). | The structure of the task reference in the delegation binding model |
| OI-4 | Rules MO-9 and MO-13 rest on a check that reads the task out of the native approval record. The baseline checks of draft §9.3 do not include an approval check, and the fixtures use `native-approval-v1`, which is an installed check of the fixtures. | A baseline approval check, or the deployment's installed check |
| OI-5 | The fingerprint (MO-27) treats two identical covered writes of a task as one operation (MO-28). A deployment that legitimately repeats an effect needs a covered distinguishing member. | Maintainer decision; a per-route rule in the integration profile |
| OI-6 | Section 16 gaps D1 to D4. | Closed: applied to the draft (section 16) |
| OI-7 | The lower bound on `max_status_reads` and the retention of terminal entries beyond the ingestion window. | Per-deployment numbers in the integration profile; a baseline in the draft if wanted |
| OI-8 | Section 6.2 and rule MO-32 let a ledger-deduplicated write be sent again after reconciliation; draft §10.3 permits a repeat of an ambiguous action only with a documented native idempotency mechanism. | Closed: rule MO-32 allows a new attempt only after an authoritative native confirmation of no effect, which is not a repeat under draft §10.3; otherwise the request is refused |

### 17.2 Probes

Each probe needs an Azure test subscription and was not run for this document. A rule that depends on one fails closed until it is run: the record stays `Unknown` or `Accepted`.

| ID | Question | Probe | If the outcome differs |
|---|---|---|---|
| P1 | Which Azure read tells that a restart request took effect when no 202 was received? Candidates: the virtual machine instance view, the activity log filtered by the request's correlation. None was read for this document | Send a restart with a deliberately dropped response and read each candidate | If none is authoritative, a restart row has no native status source and rule MO-39 applies |
| P2 | Does the response to the compute restart operation carry `Azure-AsyncOperation` in addition to `Location` and `Retry-After`? | POST a restart to a test virtual machine and read the headers | MO-42 already prefers `Azure-AsyncOperation` when present |
| P3 | What does a read of the `Location` URL of a finished compute restart answer, and with what body? The ARM page shows 200 for a storage account create, not for compute [S2] | Poll the `Location` to completion | The tracker's completion test is adjusted to the observed form |
| P4 | Is there a cancel request for a running virtual machine restart? | Read the compute reference and try on a test machine | None is claimed (MO-53) |
| P5 | Does the retry-token caveat of Graph paging [S4] apply to message listings, and does `@odata.nextLink` keep `$select` and `$top` (Graph profile P1)? | Retry a page request after a dropped response and follow each link | The tracker keeps the link of the last successful response either way (MO-60) |
| P6 | What does the status read answer to a principal with permission on the virtual machine only (MO-46)? | Read the handle with a token scoped to the resource | The tracker reports `DEPENDENCY_UNAVAILABLE` for any failure |

## 18. Sources

Each source was read on 2026-10-18.

| Label | Source | Sections read | Used for |
|---|---|---|---|
| S1 | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), HTTP Semantics | §9.2.2, §10.2.3, §15.3.3 | Idempotent methods and automatic retry; `Retry-After` syntax; 202 Accepted, noncommittal, with no facility to send a later status |
| S2 | Microsoft Learn: [Status of asynchronous operations](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/async-operations) | Whole page | 201 and 202; `Azure-AsyncOperation` before `Location`; `Retry-After`; `status` values; `provisioningState`; resource group permission to track |
| S3 | Microsoft Learn: [Virtual Machines, Restart](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/restart?view=rest-compute-2025-04-01), API version 2025-04-01 | Request, responses, security | The request line, 200 and 202, the 202 headers `Location` and `Retry-After`, `user_impersonation` |
| S4 | Microsoft Learn: [Paging Microsoft Graph data in your app](https://learn.microsoft.com/en-us/graph/paging) | Whole page | The whole `@odata.nextLink`; page sizes vary; the token of a retry |
| S5 | Microsoft Learn: [Microsoft Graph throttling guidance](https://learn.microsoft.com/en-us/graph/throttling) | Whole page | 429, `Retry-After`, retries accrue against limits |
| S6 | [draft-ietf-httpapi-idempotency-key-header-07](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/07/), expired 18 April 2026 | §2.1 to §2.7, §5 | Key syntax, uniqueness, fingerprint, enforcement, 409 and 422 for conflicts, key strength |

References to the Idempotency-Key draft in the rules use its full name. It is an expired Internet-Draft, not a standard; request binding records the same limit (RB open item O13).

## 19. Residual limits

- The ledger bounds what the gateway sends. It does not make a native API transactional, and it does not undo an effect (MO-51).
- A route without a native status source cannot be reconciled (MO-39), and a ledger-deduplicated write is sent once; a lost response leaves the outcome `Unknown` until a human acts.
- Identical writes in one task are one operation (MO-28); identical reads are each sent.
- A ledger replica that is not shared with the others enforces budgets only among the requests it sees (MO-17).
- Tracking an Azure operation needs permission that a resource-scoped role may not carry (MO-46).
- The numbers (limits, polls, intervals, retention) are the integration profile's; the document sets none.
