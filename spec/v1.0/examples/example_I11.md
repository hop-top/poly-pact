# Integration 11 — Attribute-based access control (ABAC)

**Status:** Draft
This example is informative: it does not establish a live integration, interoperability, or an end-to-end security result.


## Assumptions, components, and limitations

Component IDs C01 to C16 are the components of section 4 of the integration profile [template](../profiles/TEMPLATE.md); they are editorial identifiers, not protocol fields or registered reason codes.

### Assumptions

- Subject, resource, device, and environment sources are authoritative and satisfy freshness requirements.
- The gateway enforces the native policy decision and any obligations before disclosure.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | User/agent contract-review task authority. |
| C05 | HR/security/device/catalog source authority. |
| C08 | ABAC decision and actual obligation enforcement. |
| C16 | Runtime/output controls where claimed. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Deliberate simplifications and limitations

- The rules are a fictional native policy, not a universal taxonomy or PACT policy language.
- A complete typed policy-engine adapter and obligation executor are assumed.
- `execution-control-v1` is not required, so the runtime guarantee is labeled "attested-only": runtime class from trusted evidence establishes a verified fact only, and disclosed data use or export is a post-read residual limit.

### Profile and fixtures

The integration profile [`abac`](../profiles/abac/profile.md) states the conformance claim behind this sample with Open Policy Agent (OPA) as the native policy decision point, queried through its REST Data API: route R1 (`GET /api/documents/{document_id}`, action `document.read`); a policy input of exactly four members whose every fact comes from one native authority and never from the agent (rules ABAC-1 to ABAC-10); clearance as a configured chain of levels (rule ABAC-11); a decision document with `allow`, `obligations`, and a pinned `policy_version` (rules ABAC-13 to ABAC-20); a recheck of device, zone, and time before release (rules ABAC-21 to ABAC-24); and three obligation types that the document service enforces before any byte is disclosed (rules ABAC-25 to ABAC-30). The principal is the identifier of the mechanism that authenticated Maya; the policy engine authenticates nobody (profile section 7). The adapter cases are in [`fixtures/adapters/abac/`](../fixtures/adapters/abac/README.md), registered in the fixture manifest, with this sample's rule written in Rego as the asset `adapters/abac/policy`; the decision variations below name the case group or case for each row. The cases state the decision point's answer or its policy, the zone map, and the fact sources. The recheck, the gateway's use of a decision, and the executor's enforcement of obligations are Go tests of the adapter package; an integration tier that loads the policy into OPA runs only when an OPA server is configured.

### Limitations and open points

Open in every example: the enforced integration scope; native identity and the enrolled agent and key mapping; exact request binding and native translation; achievable source freshness and execution-time rechecks; native outcome and visibility mappings; executed end-to-end conformance evidence; privacy, retention, correction, and lineage operations; and transport, latency, capacity, and outage budgets. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Open points specific to this example:

- Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check.
- Specify input provenance, policy/obligations, and execution-time condition checks. Specified for an Open Policy Agent decision point by the integration profile [`abac`](../profiles/abac/profile.md), whose section 16 maps each requirement to rules and cases.
- Distinguish attested from enforced data-use controls per §17.4.

The cases and Go tests cover tampered clearance, classification, device, and network facts, stale and unavailable sources, changed conditions before release, and obligations that cannot be met, at the adapter. These remain unvalidated:

- The OPA release the deployment runs: the profile pins none, and a probe of each answer class of rule ABAC-14 against that release is open (open item O1); decision-log delivery under outage or overload (O3).
- The deployment's fact sources and their freshness: the bounds of the profile's section 8 are proposed defaults, unmeasured, and the device-compliance bound rests on an assumed evaluation interval (O7); whether the device fact describes the agent's host or Maya's device (O5).
- PDP authentication and the refusal of other clients and of policy or data writes (`ABAC-22`), and the refusal of direct requests to the document service from hosts other than the gateway (`ABAC-21`): deployment configuration with no fixture.
- The decision-to-release window for the facts that are not reread at execution (open item O8), and policy changes that keep the same `policy_version` label (profile section 9).
- Clearance with compartments or any order that is not one chain (O6), and obligation types other than the three of rule ABAC-25.

Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

A procurement assistant acts for Maya to read a supplier contract. Northstar's native authorization policy considers the subject's department and clearance, the contract's classification and owning department, the requested operation, and the current device/network state.

A job title or static role is insufficient. The same principal can be allowed from an approved environment and denied when relevant attributes or conditions differ.

## Native policy and enforcement

ABAC evaluates subject, object, operation, and sometimes environmental attributes against policy; see [NIST SP 800-162](https://csrc.nist.gov/pubs/sp/800/162/upd2/final). Northstar's existing document gateway already uses an installed policy engine for this decision. PACT validates required agent facts and supplies verified context to that integration; it does not define a replacement attribute-policy language.

The following is Northstar's illustrative rule, not a universal ABAC rule:

- The principal belongs to the contract's owning department.
- The security authority's subject-clearance value permits the catalogued document classification under an explicit comparison policy.
- The actual operation is a document read for the approved supplier-review task.
- The managed device and current network zone satisfy native policy.
- No applicable native restriction or required approval blocks the request.

## Facts, provenance, and PACT boundary

| Fact | Authoritative source | PACT treatment | Integration profile |
|---|---|---|---|
| Principal ID and department | Current native identity/HR mapping | Required native profile comparisons | F1 and F2; the department as `x-dept:{hr-source-id}:{department-id}` (rule ABAC-4) |
| Subject clearance | Approved security-attribute service | Required native comparison | F3, compared for equality; scoped trusted evidence is not used for clearance (rule ABAC-12; profile section 6) |
| Agent runtime class | Runtime authority | Required trusted evidence | Outside the policy input; attested-only (C16) |
| Device compliance | Native device-management adapter | Required native context check where configured | F4, for the device named by an authenticated attribute of the request, never a header (rule ABAC-6) |
| Document classification/department | Authoritative document catalog | Resource context used by native policy; not an agent-authored classification | F5 and F6, read for the resource that `map_operation` produced (rule ABAC-5) |
| Network zone and request time | Trusted gateway environment | Native policy context, not caller-declared headers | F7 from the connection's peer address and the configured zone map, F8 from the gateway clock (rule ABAC-7) |
| Agent/user/task authority | Existing delegation registry | Required native reference and context check | `native-delegation-v1`; the policy input carries no agent, task, or purpose (rule ABAC-2) |

A profile excerpt might disclose `/attributes/environment/department` and `/attributes/environment/clearance`. Each must satisfy its published field rule and authoritative provenance. The profile cannot relabel the contract as less sensitive or claim a trusted network location merely by writing a value. Under the integration profile, each field rule compares the disclosed value with the authoritative one for equality, and the policy input always carries the authoritative value, never the disclosed one (rules ABAC-1 and ABAC-12). Every fact is read with the bounds of the profile's section 8; a fact that cannot be established yields no policy query and a `DEFERRED` or `INADMISSIBLE` result (rules ABAC-8 to ABAC-10).

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the procurement assistant, resolved by the gateway (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: Maya's authenticated context, with department from the current native identity and HR mapping (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the supplier-review task in the existing delegation registry |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Existing delegation registry: agent, user, and task authority |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the document gateway and its installed policy engine |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | The document service, which performs the read for Maya after the native ABAC decision and enforces any obligations before disclosure |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for Maya, the supplier-review task, and the contract read. The check returns `PASS` only when the executor that will run the read equals that class and binding. The native ABAC request is assembled from Maya's authoritative subject facts, so `authorize_native` is invoked with Maya as the principal, never with the executor's own authority.

Adversarial results (Section 17.5):

- A principal other than Maya presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- The read presented under a task other than the supplier-review task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The user-to-agent delegation is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- The read would run under a broader document-service credential: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this without exception for a clearance or device-condition refusal. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`.

## Successful exchange

1. The gateway authenticates Maya and the workload, resolves the enrolled agent/key and native delegation, and derives the exact document-read operation.
2. It obtains the current authoritative context needed to select requirements. The gateway issues a signed contract for this principal, agent, purpose, and operation.
3. The agent prepares the profile and trusted runtime evidence, then signs the complete presentation with the enrolled holder key.
4. The validator verifies identity/key binding, nonce, request and purpose binding, field schemas, provenance, required attribute freshness/status, installed context checks, and holds. PACT can return `ADMISSIBLE` when these requirements pass.
5. The gateway assembles the native ABAC request from authoritative subject, resource, operation, and environmental facts. It does not treat unchecked profile attributes as trusted policy input.
6. The native policy engine evaluates its current policy. If it allows and execution conditions remain satisfied, the document service performs the read. A native deny blocks execution despite an admissible PACT result.

For this deployment, PACT verifies the subject facts while native ABAC decides whether those facts authorize this particular document. A deployment may also include a corresponding installed PACT context check, but the native decision remains independently required.

## Decision variations

| Condition | PACT/native consequence | Profile case |
|---|---|---|
| Verified procurement subject, sufficient clearance, compliant device, permitted document/task | PACT passes and native ABAC allows | `adapters/abac/abac-02.control`, `adapters/abac/abac-10.rank-permits`, `adapters/abac/abac-37.provenance` |
| Correct role but wrong department for this document | Native ABAC denies | `adapters/abac/abac-19.native-deny` |
| Valid subject facts, document classification rises above allowed clearance | Native ABAC denies under current resource facts | `adapters/abac/abac-10.rank-denies`; a level outside the configured chain: `ABAC-09` |
| Agent invents a stronger clearance | Profile/source comparison fails: the field rule fails with `INVALID_CLAIM`, and the policy input never contains the claimed value | `ABAC-01` |
| Department, classification, zone, or device supplied by the agent | The value never enters the policy input | `ABAC-02`; a forwarding header naming a trusted zone: `ABAC-03` |
| Device-management source required by PACT is unavailable | Defer; do not assume compliance | `adapters/abac/abac-07.device`; other sources: `ABAC-07` |
| A fact older than its bound | Not `ADMISSIBLE`; no policy query | `ABAC-05`, `ABAC-06` |
| Environment changes before execution | Recheck the applicable current conditions; no execution on a stale allow. Device, zone, and time are reread before release when their status age has passed its bound, and a new decision governs | `ABAC-23` to `ABAC-27`, Go tests of the adapter package |
| The decision point fails, gives no decision, or gives a malformed or unattributable one | No execution: `DEFERRED` | `ABAC-11`, `ABAC-12`, `ABAC-15`, `ABAC-16` |
| The decision carries another `policy_version` than the pinned one | `REQUIREMENTS_CHANGED`; obtain a new contract | `adapters/abac/abac-14.other-version`; an absent or empty version: `ABAC-13` |
| An allow with an obligation that is unknown or cannot be met | Nothing is disclosed | `adapters/abac/abac-28.unknown-type`; the executor's enforcement: `ABAC-29` to `ABAC-34`, Go tests |
| User may read but agent requests an export outside the task | Fresh operation binding and native action/purpose rules apply; a read receipt is insufficient | `adapters/abac/abac-36.export`, with the control `adapters/abac/abac-36.read` |

Unknown required facts never imply authorization. The adapter documents how long facts may be cached and which conditions must be checked at execution: the integration profile does so in its sections 8 and 14. If the policy engine returns obligations, such as field filtering, the resource gateway must enforce them before disclosing data; recording an obligation in a profile is insufficient. Under the integration profile, the document service holds the content, applies `filter_fields`, `redact`, and `watermark` in that order, verifies each result, and only then releases; an obligation of any other type, or one it cannot apply, means no disclosure (rules ABAC-25 to ABAC-28).

## Reputation and learning

Qualified supplier-review outcomes can update contextual reliability, quality, and policy adherence. A denial caused by insufficient clearance or a changed device condition is not automatically agent misconduct. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, a clearance or device-condition refusal is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, the permitted read is “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`), and quality needs an “Independent assessment” (`QUALITY`, `task_quality`).

PACT learning may vary preauthorized adaptive requirements, such as capability-assessment freshness. It cannot raise a person's clearance, change HR facts, reclassify documents, mark a device compliant, or rewrite the native ABAC policy. Such changes require their existing authorized processes. PACT does not guarantee appropriate post-read use without the environment's actual runtime and output controls.

## Boundary demonstrated

Verified agent context can feed an existing attribute-based decision while authoritative resource and environment facts remain outside the agent's control. Passing profile checks and satisfying native authorization remain distinguishable.

**PACT anchors:** §§2.3, 4, 8–12, 14–19.

## Primary references

- [NIST SP 800-162 — ABAC definition and considerations](https://csrc.nist.gov/pubs/sp/800/162/upd2/final)
- [Open Policy Agent — Policy decision/enforcement integration](https://www.openpolicyagent.org/docs)
