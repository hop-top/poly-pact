# Use case 06 — Purchase requires supervisor approval

**Status:** Informative worked example for PACT Protocol v1.0. Names, amounts, policies, and thresholds are fictional deployment choices, not protocol defaults. Profile paths below are gateway-defined attributes. This is a behavioral example, not a complete signed wire fixture.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** U06. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- The procurement system defines the supervisor's authority and exact order, amount, and supplier scope.
- A legitimate pending approval reference can be resolved through a trusted adapter.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | Jordan-to-agent native purchase task. |
| C06 | Supervisor workflow and approval applicability/status. |
| C08 | Native purchase executor. |
| C15 | Order idempotency, amount limits, and ambiguous-effect reconciliation. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G06 | Normalize missing/pending/rejected approval and fresh evaluation after approval. | Clarification / profile |
| G26 | Preserve order scope and idempotency across new contracts/retries. Specified by the [multi-operation profile](../profiles/multi-operation.md) (section 13.5): the order is a keyed write, the deferred exchange reserves nothing, the fresh exchange after approval reserves once with the ledger's key, and a retry after a timeout reconciles first (rules MO-9 to MO-13, MO-25 to MO-31, MO-35 to MO-38; `TASK-02`, `TASK-05`, `TASK-09`). | Profile / deployment |

### Deliberate simplifications and limitations

- Notifications, approver authentication, and approval routing are assumed external infrastructure.
- Mandatory native approval is not an adaptive reputation waiver.

### Validation still required

- Test wrong approver/order/amount and pending, rejected, expired, revoked, and unavailable approvals.
- Approve after contract expiry; require a fresh exchange and native duplicate-order protection.

No finding is closed by this narrative. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Northstar's procurement assistant prepares a CAD 12,000 purchase order for Jordan. The existing procurement system permits Jordan to initiate purchases, but requires a supervisor's approval before submitting an order above CAD 10,000.

The approval workflow belongs to the procurement system. PACT requires verified context showing that the applicable approval exists; it does not choose the supervisor, send notifications, or collect a conversational confirmation.

## Gateway requirements

| Requirement | How it is established |
|---|---|
| Agent, principal, and delegation binding | Current native identity and delegation systems |
| Purchase purpose and exact operation | Installed mapping for the purchase-order submission and its consequential request data |
| `/attributes/approvals/purchase_ref` | Native approval reference compared with authenticated approval-system state |
| Approval applicability | Installed check confirms agent, principal, purpose, order/task, amount, currency, and validity |
| Current native permission and transaction conditions | Existing procurement authorization and execution controls |

A deployment may instead use trusted approval evidence issued by an authorized adapter. In either form, the gateway checks the original approval's status and scope. A reference string by itself is insufficient.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the procurement assistant (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: Jordan's authenticated identity in the procurement system (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the native purchase task for the CAD 12,000 order |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Native delegation system: Jordan's authorization of the assistant for this purchase task |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the procurement gateway |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | Native purchase executor, which submits the order under Jordan's own permission to initiate purchases |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for Jordan, the purchase task, and the order submission. The check returns `PASS` only when the executor that will run the submission equals that class and binding. `authorize_native` is invoked with Jordan as the principal, never with the executor's own authority. The supervisor's approval is an approval-class check (Section 17.3.1). It is not an actor transition and changes neither the principal nor the executor class.

Adversarial results (Section 17.5):

- A purchaser other than Jordan presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- The submission presented under a task other than the registered purchase task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- Jordan's delegation to the assistant is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- The submission would run under a broader procurement credential: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): the `AUTHORIZATION` report for the native allow and the `EXECUTION` report for the submission each reference, in `evidence_refs`, an immutable native record identifying the actual executor identity. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`.

## First exchange: approval pending

1. The existing procurement system creates an approval request and returns a pending reference. The assistant includes that reference in the required profile field.
2. The gateway authenticates the request and issues a signed contract for submitting this purchase order.
3. The assistant returns a signed presentation. Identity, delegation, request binding, and field checks pass, but the installed approval check establishes that a legitimate request for this exact order scope is open and undecided. The check returns `UNKNOWN` with reason code `APPROVAL_PENDING` (17.3.1).
4. The validator records `DEFERRED` and seals the evaluation as `SEALED_DEFERRED`. The gateway does not submit the order.
5. The receipt records the pending dependency. It does not remain open while a person decides.

This example deliberately supplies a valid pending reference. An absent required reference and a rejected approval are different conditions: each returns `FAIL` and produces `INADMISSIBLE`, with reason codes `MISSING_FIELD` and `APPROVAL_REJECTED` respectively (17.3.1).

## External action and second exchange

1. The authorized supervisor reviews the order in the procurement system and approves its specified scope. Any notifications and identity checks occur in that system.
2. The assistant learns of the changed approval state through an existing authorized workflow. The human review may take far longer than a PACT contract's validity.
3. The assistant obtains a fresh requirement contract and nonce, refreshes relevant profile/evidence as needed, and submits a fresh signed presentation for the actual order submission.
4. The gateway verifies that the approval remains current and covers this agent, principal, task, order details, and amount. The approval check returns `PASS` with reason code `REQUIREMENT_SATISFIED` (17.3.1). The gateway also performs all other required checks.
5. PACT returns `ADMISSIBLE`. Native procurement authorization independently allows the purchase, and native transaction/idempotency controls ensure that retry handling does not duplicate the order.

## Decision history

| Evaluation | Approval check (17.3.1) | PACT decision | Native execution |
|---|---|---|---|
| First, with pending approval | `UNKNOWN` / `APPROVAL_PENDING` | `DEFERRED` | No submission |
| Second, after applicable approval | `PASS` / `REQUIREMENT_SATISFIED` | `ADMISSIBLE`, assuming all checks pass | Submission only if current native authorization also allows |

The first receipt remains terminal and unchanged. The second exchange is linked through the native task and approval references, not by reopening or reusing the first receipt.

## Reputation and learning

Waiting for approval is neither misconduct nor task success. Admission and approval do not add positive performance weight. Attributable execution and later quality observations may contribute within the qualified task context. Section 14.5 has no row for an approval wait, so the pending approval and the `DEFERRED` evaluation produce no `OutcomeReport`; the later “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, and only the submission's “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`) and an “Independent assessment” (`QUALITY`, `task_quality`) can contribute.

This supervisor checkpoint is mandatory under the example's native policy. Reputation cannot waive it. Removing it requires an authorized policy change; a learning controller cannot infer permission from a history of approved purchases.

## Variations to verify

Approval-check outcomes follow 17.3.1, written as check result / decision / reason code.

- The order amount, supplier, or other consequential detail changes: obtain a new contract and presentation, and check whether native policy requires new approval. An earlier approval presented for the changed order no longer covers it: `FAIL` / `INADMISSIBLE` / `APPROVAL_SCOPE_MISMATCH`.
- The approval expires before submission: block execution. `FAIL` / `INADMISSIBLE` / `APPROVAL_EXPIRED`.
- The approval is revoked before submission: block execution. `FAIL` / `INADMISSIBLE` / `APPROVAL_REVOKED`.
- A model or chat message says “approved”: reject it as authoritative evidence. With no approval reference, the required reference is absent: `FAIL` / `INADMISSIBLE` / `MISSING_FIELD`.
- The approval service is unavailable: defer rather than execute. `UNKNOWN` / `DEFERRED` / `DEPENDENCY_UNAVAILABLE`.
- The supervisor rejects the request: do not treat rejection as approval still pending. `FAIL` / `INADMISSIBLE` / `APPROVAL_REJECTED`; it is not a reputation event.

## What this demonstrates

PACT can wait for externally governed human authorization without implementing a human approval subsystem or extending an evaluation indefinitely.

**Specification anchors:** §§8–12, 14.3, 14.5, 15.5, 16.2, 17.3, 18; 17.3.1.
