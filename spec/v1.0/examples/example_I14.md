# Integration 14 — Privileged access management and just-in-time activation

**Status:** Informative integration example for PACT Protocol v1.0. Organizations, identifiers, routes, requirements, and thresholds are fictional deployment choices. Excerpts are incomplete illustrations, not signed wire fixtures or a tested implementation. The gateway needs the described installed adapter; the named platform is not claimed to support PACT natively.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I14. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- Native PIM eligibility, configured human workflow, activation status, and scope can be established.
- A supported delegated credential workflow preserves the user's actual resource actor and scope.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | User/agent incident delegation for the exact VM. |
| C06 | PIM request/approval/authentication/activation applicability. |
| C08 | Native delegated Azure executor. |
| C15 | Restart completion, ambiguous effects, and task limits. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G06 | Normalize activation states and fresh evaluation after activation. | Clarification / profile |
| G17 | Specify audience-correct credentials, refresh, and interaction. The operations gateway's inbound access token is specified as form E (a Microsoft Entra ID v2.0 access token) by the integration profile [`oauth`](../profiles/oauth/profile.md), whose G17 closure map ties each item to rules and case groups; the downstream Azure credential and the activation interaction are outside that profile. | Profile |
| G26 | Preserve restart/task semantics and avoid blind retries. Specified across operations by the [multi-operation profile](../profiles/multi-operation.md), whose G26 closure map (section 12) ties each item to rules and to the cases `TASK-01` to `TASK-09`, and whose section 13.4 works this sample: the restart is a ledger-deduplicated write sent at most once per logical operation, and a repeat under a fresh contract is answered from the record (rules MO-26 to MO-33; `TASK-02`); a 202 is accepted, not completed (rules MO-41 to MO-47; `TASK-03`); a restart that times out is `Unknown` and is reconciled, never repeated (rules MO-35 to MO-39; `TASK-05`); and a pending activation reserves nothing (rule MO-10; `TASK-09`). | Profile / deployment |

### Deliberate simplifications and limitations

- Human action and native elevation stay external; no agent-operated MFA or generic privilege service is implemented.
- An observed activation or accepted restart is not proof of current resource permission or completed recovery.

### Profile and fixtures

The integration profile [`oauth`](../profiles/oauth/profile.md) covers one part of this sample: the access token with which the operations gateway authenticates Maya's requests, validated as form E against the key set of one pinned tenant (rules OAUTH-19 to OAUTH-33), with the principal `oauth:{issuer-id}:{tid}:{oid}` (rule OAUTH-37) and the client as the enrolled workload (rule OAUTH-38). Its form E case groups (`OAUTH-09` to `OAUTH-16`, `OAUTH-18`, `OAUTH-19`, `OAUTH-22`, `OAUTH-23`, and `OAUTH-27`; profile section 10) are in [`fixtures/adapters/oauth/`](../fixtures/adapters/oauth/README.md), registered in the fixture manifest, and run on the profile's route R2; they test the adapter against key sets that the harness serves itself. The profile does not claim the restart route, the activation check, or the downstream Azure call (profile section 2 and section 6), so no case of it covers the activation or restart rows below.

### Validation still required

- Test pending/missing/rejected/expired/wrong-scope activation, unavailable status, and downstream denial.
- Activate after contract expiry and test fresh admission plus async completion or ambiguous timeout.
- The Azure facts that the multi-operation profile leaves to probes P1 to P4 and P6: which read reconciles a restart that received no 202, whether the restart response carries `Azure-AsyncOperation`, what the `Location` URL answers once the restart has finished, whether a running restart can be cancelled, and what a principal scoped to the virtual machine reads at the handle. Each rule that depends on a probe fails closed until it is run.
- The restart route as a route row of the deployment's own profile, with its mapping and binding; the integration profile claims routes R1 and R2 only.
- The audience-bound, user-delegated Azure credential workflow and its executor record (C08); the inbound token is never forwarded (rule OAUTH-36).
- The live tenant facts that the integration profile leaves to probes P1 to P5 and P7, and its application registration (deployment requirement DR6).

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

An incident assistant acts for Maya to restart one Azure virtual machine during an outage. Maya is eligible for the required resource role under the organization's Privileged Identity Management (PIM) process, but that role is not currently active.

Northstar's configured activation policy requires the applicable human authentication step, business justification, and approval before time-limited activation. The assistant cannot complete a human MFA action on Maya's behalf or convert eligibility into active authority.

## Native activation and resource authority

PIM supports externally governed activation of eligible Azure resource roles. Activation requirements and duration come from its native configuration; they are not universal defaults. See [Azure resource-role activation](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-activate-your-roles) and [PIM role settings](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings).

The controlled operations gateway verifies activation context and performs the restart using the deployment's correctly audience-bound, user-delegated Azure credential workflow. It preserves Maya's native principal and scope and does not replace them with an administrator's app-only access. The native resource API remains responsible for its authorization decision.

## Required PACT context

| Fact | Authoritative source and condition |
|---|---|
| Inbound credential | The operations gateway's access token, validated as form E of the integration profile [`oauth`](../profiles/oauth/profile.md) (rules OAUTH-19 to OAUTH-33); never forwarded to Azure and never a substitute for the delegated Azure credential (rule OAUTH-36) |
| `/attributes/environment/principal_id` | Current native principal for Maya: `oauth:{issuer-id}:{tid}:{oid}` from that token (rule OAUTH-37), compared by `native-principal-binding-v1` |
| `/attributes/delegation/authority_ref` | Existing incident-task authority binding Maya, this agent, purpose, and permitted operation |
| `/attributes/approvals/activation_ref` | Existing activation-request reference, resolved through the trusted native adapter |
| Activation applicability | Installed check confirms principal, role, resource scope, current state, validity, and required external approval/authentication completion |
| Required runtime facts | Trusted evidence specified by the effective contract |

The activation reference is a lookup/evidence reference, not an access token. A profile string such as `role: administrator` cannot activate a role. The native workflow determines who may approve, what authentication is required, and the permitted activation duration.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the incident assistant, resolved by the gateway (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: Maya's current native principal (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the incident task for the exact VM restart |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Existing incident-task authority binding Maya, this agent, the purpose, and the permitted operation |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the controlled operations gateway |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | The audience-bound, user-delegated Azure credential workflow, which preserves Maya's native principal and scope |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for Maya, the incident task, and the restart of the named VM. The check returns `PASS` only when the executor that will run the restart equals that class and binding. `authorize_native` is invoked with Maya as the principal, never with the executor's own authority. PIM activation is a native change in Maya's effective authority, carried out by the native workflow and checked as an approval (Section 17.3.1). It is not an actor transition and does not change the declared class.

Adversarial results (Section 17.5):

- A principal other than Maya presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- The restart presented under a task other than the incident task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The incident delegation to the agent is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- The restart would run under an administrator's app-only access in place of Maya's delegated credential: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this for every `EXECUTION` and `AUTHORIZATION` report. It makes no exception for the native denial or for the “Asynchronous request accepted” and “Ambiguous timeout” reports (`EXECUTION`, `UNKNOWN`, `none`), and Section 14.5 does not state `evidence_refs` for those rows. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`.

## First exchange: activation pending

1. The gateway authenticates the user/workload, resolves the enrolled agent/key and incident delegation, and maps the requested restart for the exact VM resource.
2. The native activation process has a valid pending request. The assistant obtains a PACT requirement contract and presents that activation reference with the required evidence.
3. The installed check establishes that required activation is pending for this exact principal, role, and resource scope. It returns `UNKNOWN` with reason code `APPROVAL_PENDING` (17.3.1). PACT records `DEFERRED` and seals the evaluation as `SEALED_DEFERRED`. The gateway does not call the restart API.
4. The receipt remains terminal. It does not hold a PACT evaluation open for the human workflow, and it does not prove that native resource authorization was allowed.

This case supplies a legitimate pending reference. A missing required reference, a rejected activation, or a scope mismatch is handled according to the corresponding demonstrated failure, rather than being indefinitely described as pending: each returns `FAIL` and produces `INADMISSIBLE`, with reason codes `MISSING_FIELD`, `APPROVAL_REJECTED`, and `APPROVAL_SCOPE_MISMATCH` respectively (17.3.1).

## External activation and fresh exchange

1. Maya completes the required authentication/justification through the native workflow. An authorized approver approves where required. PIM activates the role for its configured principal, resource scope, and time window.
2. The assistant obtains a fresh contract and nonce, refreshes relevant profile/evidence, and signs a new presentation for the actual restart request.
3. The gateway verifies current activation applicability and all other PACT requirements, including incident delegation, key binding, evidence/status, purpose, exact VM, action, and holds. The activation check returns `PASS` with reason code `REQUIREMENT_SATISFIED` (17.3.1). Passing checks produce `ADMISSIBLE`.
4. Native authorization is evaluated for the actual Azure operation using the correct delegated identity. Activation observed in one system does not justify ignoring a downstream denial or claiming propagation is instantaneous.
5. If the native resource API accepts the restart, the gateway records that observed response and tracks completion through the supported native operation mechanism. It does not equate an accepted asynchronous request with a completed restart.

The gateway's native adapter uses the supported [Azure VM restart operation](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/restart?view=rest-compute-2025-04-01). Resource identifiers, API version, query, body, and consequential headers are bound under its installed operation mapping. The receipt does not authorize a different VM or later administrative action.

The [multi-operation profile](../profiles/multi-operation.md) fixes how the restart runs under the incident task (its section 13.4). The restart is a ledger-deduplicated write: the gateway reserves it in the task ledger before the POST, sends at most one request for it, and answers a repeat under a fresh contract from the record, with `operation-in-flight` while it runs and no second request (rules MO-26, MO-31, MO-33; `TASK-02.restart-dedupe`). A 202 makes the record `Accepted` with the handle; the tracker waits the `Retry-After` period and reads the `status` of the asynchronous operation, never the virtual machine's `provisioningState`, and a status it is not permitted to read leaves the record `Accepted` with no success inferred (rules MO-41 to MO-46; `TASK-03`). A POST that times out leaves the record `Unknown`; it is reconciled only through a native status source and is never sent again (rules MO-35 to MO-39; `TASK-05.restart-timeout`). Which Azure read can serve as that source is to probe (profile probe P1).

The source repository has an executor for this restart, the Go package `go/adapters/graph/azurerm` (not part of the mirror). It runs the restart under the task ledger as above and reads the `status` of the asynchronous operation, not `provisioningState` (rule MO-44). Its activation check is an interface, `ActivationGate`, that the deployment supplies, because the normalization of activation states (finding G06) is not yet specified; the executor reserves and sends nothing unless that check returns `PASS` (rule MO-10).

## Decisions and failure variations

| Condition | Expected behavior | Check result / decision / reason code (17.3.1) |
|---|---|---|
| Eligible role, valid pending activation request | Defer; no restart | `UNKNOWN` / `DEFERRED` / `APPROVAL_PENDING` |
| Approved/current activation covers principal, VM, and action | Fresh evaluation may pass; native API must also allow | `PASS` / contributes to `ADMISSIBLE` / `REQUIREMENT_SATISFIED` |
| Activation covers another resource scope | No exception for the requested VM | `FAIL` / `INADMISSIBLE` / `APPROVAL_SCOPE_MISMATCH` |
| Activation rejected | Block under the applicable current checks; not described as pending | `FAIL` / `INADMISSIBLE` / `APPROVAL_REJECTED` |
| Activation expired | Block under the applicable current checks | `FAIL` / `INADMISSIBLE` / `APPROVAL_EXPIRED` |
| Activation revoked | Block under the applicable current checks | `FAIL` / `INADMISSIBLE` / `APPROVAL_REVOKED` |
| Required activation state cannot be established | Defer rather than infer active authority | `UNKNOWN` / `DEFERRED` / `DEPENDENCY_UNAVAILABLE` |
| PACT passes, but native resource API denies | No restart; preserve the native denial | `PASS` / `ADMISSIBLE` / `REQUIREMENT_SATISFIED` |
| Restart request times out with ambiguous outcome | Use native status/idempotency handling; do not automatically repeat the side effect | Not an activation-check state |
| Agent claims its reputation replaces MFA or approval | Reject; the native requirement remains mandatory | Not an activation-check state; reputation cannot change a base approval requirement |

Role activation changes effective native authority through an authorized external process. PACT only verifies the context and preserves the current native decision. It does not reopen a prior sealed receipt or activate a role itself.

## Outcomes, reputation, and learning

Waiting for activation is neither misconduct nor successful incident remediation. Record admission, native authorization, command acceptance, actual completion, and incident quality separately. Section 14.5 maps them: waiting for activation has no row and produces no `OutcomeReport`; the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, a refusal by the resource API is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, the accepted restart is “Asynchronous request accepted” (`EXECUTION`, `UNKNOWN`, `none`) with zero weight and a new `event_id`, the observed completion is a separate “Asynchronous completion observed” (`EXECUTION`, `SUCCESS` or `FAILURE`, `reliability`) under its own `event_id`, an unresolved timeout is an “Ambiguous timeout” (`EXECUTION`, `UNKNOWN`, `none`) to reconcile natively and never retry blindly (Section 10.3), and incident quality is an “Independent assessment” (`QUALITY`, `task_quality`). Only qualified attributable outcomes update the relevant dimensions. An accepted command or human approval is not proof that the incident was resolved.

PACT learning may vary explicitly adaptive evidence checks inside its own authorized envelope. It cannot grant role eligibility, extend activation, remove native MFA/approval, bypass resource scope, or clear a security hold. Any native privilege-policy change follows its existing administrative process.

## Boundary demonstrated

A human-governed, time-limited privilege lifecycle can remain external to PACT. Fresh admission and actual native resource authorization are required after the authority becomes active.

**PACT anchors:** §§2.3, 8–12, 14–18; 17.3.1.

## Primary references

- [Microsoft: Activate Azure resource roles in PIM](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-activate-your-roles)
- [Microsoft: PIM role settings](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings)
- [Microsoft: Azure VM restart API](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/restart?view=rest-compute-2025-04-01)
