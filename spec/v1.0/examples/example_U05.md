# Use case 05 — Valid profile, insufficient resource permissions

**Status:** Informative worked example for PACT Protocol v1.0. Names, amounts, policies, and thresholds are fictional deployment choices, not protocol defaults. Profile paths below are gateway-defined attributes. This is a behavioral example, not a complete signed wire fixture.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** U05. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- Native department policy remains authoritative and the connector preserves Maya's restrictions.
- This profile deliberately leaves the department-level resource decision to native authorization.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | Current native delegation bounded by Maya's authority. |
| C08 | Native resource check and execution under the original restrictions. |
| C10 | Distinct admission, denial, and any attributable quality observation. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G07 | Adopt the Section 14.5 mapping: the “PACT admission decision” and the “Native denial” are separate zero-weight reports, and neither is task success or misconduct. | Profile / clarification |

### Deliberate simplifications and limitations

- Other profiles may also check entitlements inside PACT; the resulting admission trace would differ.
- No connector or negative native-denial test has been executed.

### Validation still required

- Combine high reputation and a broad connector credential with an unauthorized invoice; access must remain blocked.
- Verify separate decision records without hidden-resource disclosure.

No finding is closed by this narrative. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Northstar's invoice assistant acts for Maya, an operations employee. Its organizational identity, finance role, native delegation, and managed-runtime evidence are all valid. It requests invoice `SALES-2088`, which belongs to the sales department.

Northstar's installed purpose check recognizes invoice summarization as a permitted task category. Department-level resource access is evaluated by the native authorization system. Maya has no access to sales invoices.

## Gateway requirements and access boundary

| Check | Established fact | Owner of the decision |
|---|---|---|
| Agent enrollment and holder key | Current, correctly bound agent | Native identity system and PACT validator |
| Principal and role fields | Maya is a recognized employee with the local `invoice-reader` role | Native directory comparison |
| Delegation reference | Maya authorized the assistant to act within her own authority | Native delegation system |
| Runtime evidence | Current managed-runtime attestation | Configured runtime issuer |
| Purpose/operation relation | An invoice read matches the recognized summary task category | Installed gateway context check |
| Access to `SALES-2088` | Maya lacks the required department entitlement | Native resource authorization |

The gateway does not treat the general role as proof of access to every invoice. A valid delegation cannot convey authority Maya does not possess.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the invoice assistant, with the holder key bound by the native identity system (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: Maya's authenticated native context and directory comparison (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the invoice-summary task category recognized by the installed purpose check |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Native delegation system: Maya's authorization of the assistant to act within her own authority |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the finance gateway |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | Native resource check and execution under Maya's original restrictions, not the connector's technical credential |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for Maya, the invoice-summary task, and `invoice.read` on `SALES-2088`. The check returns `PASS` only when the executor that will run the read equals that class and binding. `authorize_native` is invoked with Maya as the principal, so the sales-department denial comes from Maya's entitlements and not from the connector's.

Adversarial results (Section 17.5):

- A principal other than Maya presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- The request presented under a task other than the recognized summary task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- Maya's delegation to the assistant is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- Fallback to the connector's broader service-account credential after the denial: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): the `AUTHORIZATION` report for the native denial references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this for every `AUTHORIZATION` report and makes no exception for a denial. No `EXECUTION` report exists because the read never executes. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`.

## Exchange

1. The gateway authenticates the principal and agent, then maps the actual request to `invoice.read` on `SALES-2088`.
2. It issues a signed, operation-bound contract. The assistant returns a fresh signed presentation with the required profile and evidence.
3. Every applicable PACT requirement passes. The validator records `ADMISSIBLE` for this request.
4. The native authorization system evaluates Maya's effective permissions and the delegation against the sales invoice. It denies access.
5. The gateway blocks the read and records the native denial separately from the PACT result. It returns an appropriately restricted native error without unnecessarily disclosing protected resource details.

## Decision and records

| Question | Result |
|---|---|
| Does the agent meet the published PACT requirements? | `ADMISSIBLE` |
| Does the principal have native access to the requested invoice? | Deny |
| Does the invoice read execute? | No |
| Should the admission receipt be rewritten as a PACT failure? | No; the two decisions describe different checks. |

This outcome is valid for the specified deployment. Another gateway could also require a resource-entitlement context check within PACT; that deployment would record the corresponding admission failure. In either design, native denial blocks execution.

## What the agent may do next

The assistant can report that it cannot access the requested invoice, continue with resources within the task that Maya can access, or use the organization's existing access-request process if appropriate. Any changed operation needs its own contract and presentation. Repeated presentation of the same receipt cannot change the native decision.

It cannot switch to a broadly privileged connector account to bypass Maya's restriction. A connector's technical credential does not establish the requesting principal's entitlement.

## Reputation and learning

Record the admission and authorization outcomes with correct attribution. The denial alone is not evidence of agent misconduct and contributes no positive performance reputation. A mistaken resource selection may warrant a separate task-quality assessment if an authorized evaluator establishes the error. Deliberate probing requires separately qualified security evidence; it cannot be inferred merely from a denial. Section 14.5 maps this exchange: the “PACT admission decision” (`ADMISSION`) and the “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) both carry zero weight and the denial is not misconduct (Section 14.3), no `EXECUTION` report exists because the read never executes, a mistaken resource selection counts only through an “Independent assessment” (`QUALITY`, `task_quality`), and deliberate probing counts only as a “Confirmed incident” (`SECURITY`, reported by `security_authority` only).

Neither a strong score nor a learned selection rule can turn the native denial into an allow.

## Variations to verify

- The assistant presents a perfect reputation snapshot: native denial still blocks execution.
- The assistant supplies a role with the same spelling from another tenant: provenance and namespace checks reject that substitution.
- Maya later receives access through a legitimate native process: a fresh evaluation and current native decision are required.
- The policy source is unavailable: absence of a decision does not authorize execution.

## What this demonstrates

`ADMISSIBLE` means the required PACT checks passed. Execution still requires the environment's independent authorization.

**Specification anchors:** §§2.3, 4.3, 8.5, 11.4, 14.3, 14.5, 15.5, 17.
