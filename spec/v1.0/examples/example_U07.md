# Use case 07 — Authorized person grants an exceptional pass

**Status:** Informative worked example for PACT Protocol v1.0. Names, amounts, policies, and thresholds are fictional deployment choices, not protocol defaults. Profile paths below are gateway-defined attributes. This is a behavioral example, not a complete signed wire fixture.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** U07. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- Native policy expressly permits the security lead to exempt the operating-hours rule only.
- Exception beneficiary, scope, expiry, and current status can be established authoritatively.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | Incident principal/agent/task authority. |
| C06 | Native exceptional-pass authority and current scoped record. |
| C08 | Diagnostic execution retaining other native restrictions. |
| C15 | Task limits and in-flight semantics. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G06 | Clarify changed current native decisions versus immutable earlier receipts. | Clarification / profile |
| G26 | Define later operations, expiry, and in-flight handling. Specified by the [multi-operation profile](../profiles/multi-operation.md) (section 13.5): each later read reserves only while the exception is current, an exception that expires does not undo a read already sent, and a read past the deadline is refused (rules MO-14, MO-23, MO-50, MO-51; `TASK-08`, `TASK-09`). | Profile / deployment |

### Deliberate simplifications and limitations

- The first trace intentionally locates the operating-hours decision in native authorization.
- No generic break-glass or emergency-authority subsystem is implemented.

### Validation still required

- Try unauthorized approvers, other services, expired exceptions, and an active hold.
- Verify a fresh exchange after approval and no implicit authorization of later requests.

No finding is closed by this narrative. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

At 02:00, Northstar's incident-response assistant needs to read production diagnostics to investigate a service outage. Its principal has the normal diagnostic-read role, but native policy ordinarily restricts this access to operating hours.

The organization's established incident process permits an on-call security lead to approve a temporary exception to the operating-hours restriction. The lead cannot waive identity checks, grant unrelated resource access, or clear a security hold through this exception.

## Native exception policy

| Property | Example scope |
|---|---|
| Approving authority | Currently designated on-call security lead |
| Beneficiary | Named incident-response agent acting for the specified incident principal |
| Purpose | Investigate incident `INC-842` |
| Permitted operation class | Read production diagnostics for service `billing-api` |
| Duration | Fifteen minutes |
| Rule changed | Operating-hours restriction only |
| Other controls | Roles, resource permissions, runtime requirements, holds, and native execution controls remain applicable |

These permissions come from native policy. PACT does not create the security lead's exception authority.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the incident-response assistant (Sections 6.1 and 6.2); the exception check compares the exception's named beneficiary with this agent |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: the incident principal's authenticated native context (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the investigation of incident `INC-842` |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Native incident system: the incident principal's authorization of this agent for the task |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the diagnostics gateway |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | Diagnostic execution under the incident principal's own diagnostic-read role, retaining every other native restriction |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for the incident principal, the incident task, and the diagnostic read of `billing-api`. The check returns `PASS` only when the executor that will run the read equals that class and binding. `authorize_native` is invoked with the incident principal, never with the executor's own authority. The native exception changes only the operating-hours result of `authorize_native`. It is checked as an approval (Section 17.3.1), is not an actor transition, and changes neither the principal nor the executor class.

Adversarial results (Section 17.5):

- A principal other than the incident principal presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- The read presented under a task other than the incident task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The incident delegation to the agent is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- The read would run under a broader diagnostic or service credential: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this without exception for the initial native denial. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`.

## First exchange: no exception

1. The agent authenticates, receives a requirement contract, and presents its valid identity, role, delegation, runtime evidence, and diagnostic intent for one exact read operation.
2. Under this deployment, the operating-hours decision resides in native authorization. PACT requirements pass and the validator records `ADMISSIBLE`.
3. Native authorization denies the after-hours operation. The gateway returns the denial and no diagnostic data.
4. The assistant uses the existing incident process to request an exception. That request does not rewrite the completed PACT receipt or native decision.

A deployment that requires an exception reference within PACT can instead defer while the external request is pending: the exception check returns `UNKNOWN` with reason code `APPROVAL_PENDING` and the evaluation seals `DEFERRED` (17.3.1). Neither arrangement permits access before the native exception is effective.

## External exception and fresh exchange

1. The security lead reviews the incident and grants the scoped exception in the existing incident/access system. The native system validates the lead's authority and records the exception's limits and expiry.
2. The assistant obtains a fresh requirement contract. It supplies `/attributes/approvals/exception_ref` if required by the applicable contract, backed by native state or an authorized approval issuer.
3. A fresh signed presentation binds the updated profile, evidence, intent, exact diagnostic read, contract, and nonce.
4. The gateway verifies the exception's beneficiary, approving authority, current status, service scope, purpose, and time bounds, along with all other required checks.
5. PACT returns `ADMISSIBLE`; where the contract names an exception check, it returns `PASS` with reason code `REQUIREMENT_SATISFIED` (17.3.1). Native authorization now allows this operation because its current policy decision incorporates the authorized exception.
6. The read executes if native execution conditions also pass. Each subsequent protected operation undergoes its required admission and authorization checks.

## Decision history

| Point | PACT admission | Current native authorization | Execution |
|---|---|---|---|
| Before exception | `ADMISSIBLE` | Deny: operating-hours restriction | Blocked |
| After applicable exception | `ADMISSIBLE` | Allow under scoped exception | Permitted |
| After exception expiry | Reevaluate under current requirements | Deny unless another valid native basis exists | Blocked |

“Native denial wins” applies to the current decision. An authorized native exception can change that decision; it does not make PACT capable of overriding a denial.

When the effective contract names an exception check (an approval-class check), its result follows 17.3.1:

| Exception state established by the check | Check result | PACT decision | Reason code |
|---|---|---|---|
| Valid and applicable to this agent, incident, service, and time window | `PASS` | Contributes to `ADMISSIBLE` | `REQUIREMENT_SATISFIED` |
| Request open for this exact scope, undecided | `UNKNOWN` | `DEFERRED` | `APPROVAL_PENDING` |
| Required exception reference absent | `FAIL` | `INADMISSIBLE` | `MISSING_FIELD` |
| Granted by an approver who lacks this exception authority | `FAIL` | `INADMISSIBLE` | `APPROVAL_AUTHORITY_MISMATCH` |
| Exception covers another service, agent, or incident | `FAIL` | `INADMISSIBLE` | `APPROVAL_SCOPE_MISMATCH` |
| Expired | `FAIL` | `INADMISSIBLE` | `APPROVAL_EXPIRED` |

## Reputation, learning, and audit

An exceptional pass is an authorization fact, not evidence that the incident was resolved correctly. Execution and incident-quality outcomes are reported separately. The initial denial alone does not penalize reputation. Section 14.5 has no row for waiting on an exception or approval, so an open request produces no `OutcomeReport`; the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, the initial “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) carries zero weight and is not misconduct, and only the diagnostic read's “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`) and an incident-quality “Independent assessment” (`QUALITY`, `task_quality`) can contribute.

Record the exception reference, authorized scope, source/status checks, PACT receipts, native decisions, and attributable execution outcomes. Avoid copying sensitive diagnostic contents into reputation records. Repeated exception use may inform an authorized policy review; it does not establish permission for the learning controller to remove the operating-hours rule.

## Variations to verify

- The agent requests diagnostics for another service: the exception does not apply (`APPROVAL_SCOPE_MISMATCH`).
- The person approving is a manager but lacks this exception authority: reject the exception (`APPROVAL_AUTHORITY_MISMATCH`).
- A hold or identity revocation takes effect: the exception does not bypass it.
- The exception expires during an ongoing incident: subsequent operations require a current native basis (`APPROVAL_EXPIRED` where the contract names the exception check); in-flight handling follows native semantics.

## What this demonstrates

A human-granted exceptional pass can be accommodated through the environment's current authorization decision, with explicit scope and without reopening completed evaluations.

**Specification anchors:** §§2.3, 8–12, 15.5, 17–18; 17.3.1.
