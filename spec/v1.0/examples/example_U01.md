# Use case 01 — Finance assistant reads invoices

**Status:** Informative worked example for PACT Protocol v1.0. Names, amounts, policies, and thresholds are fictional deployment choices, not protocol defaults. Profile paths below are gateway-defined attributes. This is a behavioral example, not a complete signed wire fixture.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** U01. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- Native finance permissions, Maya-to-agent delegation, task registration, and trusted runtime evidence already exist.
- The environment can bind each invoice read to the summary task and observe reads separately from summary quality.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | Maya-to-agent summary task and native delegation. |
| C08 | Invoice executor retaining department/resource restrictions. |
| C10 | Resource reporter and independent summary-quality evaluator. |
| C16 | Runtime evidence and actual data-use controls where claimed. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G08 | Establish independent task attribution without rewarding every invoice read as a separate task. | Deployment / validation |
| G25 | Distinguish attested from enforced data-use controls per §17.4. | Deployment / coverage |
| G26 | Define multi-invoice/page scope, limits, and fresh bindings. Specified by the [multi-operation profile](../profiles/multi-operation.md) (section 13.5): each invoice is its own bound operation of the registered task, counted against the task's budget, and a task label grants no session permission (rules MO-1 to MO-7, MO-15 to MO-20; `TASK-01`, `TASK-07`). | Profile / deployment |

### Deliberate simplifications and limitations

- Only one invoice read is traced; the complete summary workflow is not implemented.
- Runtime containment and summary-quality assessment have not been demonstrated.
- `execution-control-v1` is not required, so the runtime guarantee is labeled "attested-only": trusted `managed` isolation evidence establishes a verified fact only, and invoice data use or export is a post-read residual limit.

### Validation still required

- Mutate invoice, principal, task, or delegation before use; verify rejection/native denial.
- Test multi-read attribution and qualify execution and summary quality independently.

No finding is closed by this narrative. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Maya, a Northstar employee in the operations department, asks an invoice assistant to summarize September supplier invoices. The company's existing finance system permits Maya to read operations invoices. The assistant has a native delegation recognized by that system.

This example follows one read operation for invoice `OPS-1042`. Reading further invoices requires separately bound operations; the task label does not turn one admission into a reusable session permission.

## Participants and authority

| Participant | Responsibility |
|---|---|
| Maya | Requests the summary using her existing organizational authority. |
| Invoice assistant | Presents its enrolled identity, profile, intent, and evidence. |
| Finance gateway | Publishes requirements, maps the actual request, and enforces native permissions. |
| Organizational identity and delegation services | Establish current principal, membership, and delegation facts. |
| Runtime issuer | Attests the assistant's execution environment. |
| Resource service and task evaluator | Report execution and independently assessed task quality. |

## Gateway requirements

| Profile path or context | Required value or condition | Authoritative source |
|---|---|---|
| `/attributes/environment/principal_id` | Maya's native principal identifier | Authenticated native context |
| `/attributes/environment/roles` | Presented roles include `invoice-reader` and satisfy the configured subset comparison | Native directory membership |
| `/attributes/delegation/authority_ref` | Current delegation from Maya to this agent | Native delegation service |
| `/attributes/runtime/isolation` | `managed` | Trusted runtime evidence issuer |
| Purpose and operation | Reading this invoice is consistent with the registered September-summary task | Installed gateway context check |

The gateway separately checks identity/key binding, freshness, evidence status, request binding, and security holds. The role's meaning is local to Northstar; PACT does not define or assign it.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the invoice assistant (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: Maya's authenticated native context (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: native registration of the September-summary task |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Native delegation service: current delegation from Maya to this agent |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the finance gateway |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | Invoice executor, which runs the read under Maya's own department and resource restrictions |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for Maya, the September-summary task, and `invoice.read` on `OPS-1042`. The check returns `PASS` only when the executor that will run the read equals that class and binding. `authorize_native` is invoked with Maya as the principal, never with the executor's own authority.

Adversarial results (Section 17.5):

- A principal other than Maya presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- The read presented under a task other than the registered September-summary task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The delegation from Maya to the agent is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- The read would run under a broader finance credential: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this without exception for the native denial of the lost-access variation. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`.

## Exchange

1. The gateway authenticates the workload and Maya's principal, resolves the enrolled agent/key binding, and maps the proposed request to `invoice.read` on `OPS-1042`.
2. The assistant requests a contract for that operation and the environment's recognized invoice-summary purpose. The gateway returns signed effective requirements and a single-use nonce.
3. The assistant prepares the required profile view and obtains current runtime evidence. Authoritative role and delegation facts come from the configured native sources.
4. The assistant signs a presentation binding the profile, evidence, intent, exact operation, contract, and nonce, and submits it with the read request.
5. The validator verifies the presentation and all required facts. It records `ADMISSIBLE` and issues a signed admission receipt.
6. The gateway independently checks Maya's current access to `OPS-1042`, the delegation's applicability, and native execution conditions. These checks allow the read.
7. The resource service returns the invoice. Further reads repeat the applicable exchange for their own operations.

## Decision and records

| Question | Result |
|---|---|
| Does the agent meet this operation's PACT requirements? | `ADMISSIBLE` |
| Does native policy permit this principal and delegation to read the invoice? | Allow |
| Does the operation execute? | Yes |
| Does the receipt authorize another invoice read? | No |

The admission receipt identifies the checked requirements and bound operation. Native authorization and actual execution are recorded separately. The receipt is not an access token and does not prove that the eventual summary is accurate.

## Reputation and learning

Admission alone adds no positive performance reputation. An authorized executor can report the completed read as an execution observation. A task evaluator can later assess the summary's quality using attributable evidence. Qualified observations update their respective dimensions in the correct context; repeated reads within one independent task group cannot manufacture many positive task contributions. Section 14.5 maps these observations: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, the “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) in the lost-access variation also carries zero weight and is not misconduct, the reported read is “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`), and the summary assessment is an “Independent assessment” (`QUALITY`, `task_quality`).

## Variations to verify

- Changing the invoice identifier or request body requires a new contract and presentation; reusing the original binding fails.
- Missing runtime evidence prevents admission. An unavailable required status source produces deferral rather than assumed validity.
- If Maya loses access before execution, current native authorization blocks the read despite the PACT pass.
- A successful read does not establish that subsequent use or export of invoice data is permitted; the environment supplies those controls.

## What this demonstrates

PACT establishes the required agent context for a specific operation. The finance system continues to decide whether that operation is authorized.

**Specification anchors:** §§2.3, 8–12, 14–15, 17–18.
