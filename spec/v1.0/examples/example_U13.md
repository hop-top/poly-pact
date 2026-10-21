# Use case 13 — Gateway learns a better admission policy

**Status:** Informative worked example for PACT Protocol v1.0. Names, amounts, policies, and thresholds are fictional deployment choices, not protocol defaults. Profile paths below are gateway-defined attributes. This is a behavioral example, not a complete signed wire fixture.

This example is informative: it does not establish a live integration, interoperability, or an end-to-end security result.


## Assumptions, components, and limitations

Component IDs C01 to C16 are the components of section 4 of the integration profile [template](../profiles/TEMPLATE.md); they are editorial identifiers, not protocol fields or registered reason codes.

### Assumptions

- A signed policy, authorized controllers/evaluators, metric gates, current version registry, and compatible fallback exist.
- Native task provenance, qualified outcomes, evaluation data, and release evidence are inspectable.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C10 | Qualified training/evaluation evidence and corrections. |
| C11 | Reputation updates and accepted scoring epochs. |
| C12 | Controller, independent gates, storage, shadow/rollout, monitoring, and recovery. |
| C14 | Protected training/evaluation lineage. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Deliberate simplifications and limitations

- All rollout, regression, and recovery outcomes are hypothetical.
- Empirical safety of autonomous relaxation remains unresolved.
- The numeric choices in this example, such as the task count, observation duration, and initial rollout percentage, are illustrative and are evaluated per Appendix E.

### Limitations and open points

Open in every example: the enforced integration scope; native identity and the enrolled agent and key mapping; exact request binding and native translation; achievable source freshness and execution-time rechecks; native outcome and visibility mappings; executed end-to-end conformance evidence; privacy, retention, correction, and lineage operations; and transport, latency, capacity, and outage budgets. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Open points specific to this example:

- Prove independent tasks/reporters and resist poisoning.
- Justify counts, durations, metrics, bounds, and rollout choices.
- Define changing selection inputs and contract invalidation.
- Demonstrate atomic releases, bounded rollout, freeze, and rollback.
- Adopt the Section 16.3 registration model and the Section 16.5 transition table: the controller stages privately, registers one signed manifest whose `evaluation_report_digest` is the digest of its pre-registration candidate report, and registers a new manifest for any later change.

Still to validate:

- Produce a schema-valid signed lifecycle: registration, `EVALUATED`, `SHADOW`, `ACTIVE`, `ROLLED_BACK` with stable manifest digests and no mutation of an accepted manifest.
- Exercise concurrent promotion, poisoned-data correction, expired policy, incompatible fallback, and contract invalidation.

Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Northstar's reporting gateway currently selects a conservative requirement set for nearly every assistant. Qualified execution and quality outcomes suggest that a combination of contextual reputation and verified runtime state could identify agents eligible for an already authorized established set without unacceptable quality regression.

The learning controller proposes a new requirement selector. It changes how allowed sets are selected; it does not create roles, grant access, enroll issuers, or alter immutable requirements. All observations and results described below are hypothetical.

## Preauthorized learning envelope

| Policy element | Example configuration |
|---|---|
| Mode | `bounded_autonomous` |
| Immutable base | Native identity/key binding, claim provenance, request binding, current required status/holds, and native-denial preservation |
| Allowed requirement sets | Conservative and established sets approved by the administrator |
| Adaptive control | Capability-assessment freshness within approved bounds |
| Allowed implementation | An installed, authorized requirement-selector implementation |
| Coverage gate | At least 100 independent qualified tasks over at least seven days |
| Shadow gate | At least 24 hours of shadow comparison |
| Initial rollout | At most 10% of the eligible declared context |
| Safety and regression gates | Zero native-denial overrides; quality and admission metrics satisfy explicit policy bounds |
| Recovery | Compatible evaluated rollback artifact, conservative fallback, and defined triggers |

These gates are examples, not evidence that a sample size or duration is sufficient for every deployment. The signed policy must specify the metric definitions, evaluators, bounds, and context coverage actually required.

## Learning progression

1. **Collect and qualify.** Authorized reporters submit execution, quality, and relevant security observations linked to native tasks, operations, and admission receipts. The service checks authority, evidence, independence, and duplication. Disputed or unqualified data cannot support autonomous promotion as successful evidence. Under Section 14.5, completed executions that return data enter as “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`), quality observations as an “Independent assessment” (`QUALITY`, `task_quality`), and security observations only as a “Confirmed incident” (`SECURITY`, reported by `security_authority` only), while each “PACT admission decision” (`ADMISSION`) carries zero weight.
2. **Build and register a candidate.** The controller stages a candidate for the installed selector implementation privately, outside PACT, and produces its candidate report covering training and validation on its own data. It then registers one signed manifest, a versioned `LearningArtifact`, with `POST /pact/v0.1/learning/artifacts`. The manifest binds source-data lineage, feature schema, training configuration, intended contexts, parent artifact, base revision, and declared output controls, and contains all required fields, including `evaluation_report_digest`, the `bytes_digest` of that pre-registration report. The report does not contain the manifest and is not the sole promotion evidence. The artifact enters `CANDIDATE` on acknowledgment, and its identity from then on is the `artifact_digest` of the manifest. An accepted manifest is never mutated: any later change registers a new manifest with an incremented `version` and a `parent_artifact_digest` equal to the prior manifest's digest, and a `LearningEvent` retires the prior candidate.
3. **Evaluate.** Authorized evaluators use disjoint or time-separated data and immutable tests. They test native-denial preservation, required provenance, tenant isolation, injection resistance, farming resistance, security holds, and context-specific performance. The proposing artifact cannot be the sole source of its promotion evidence.
4. **Shadow.** The candidate moves through `CANDIDATE → EVALUATED → SHADOW`. It proposes sets alongside the active selector, but does not affect enforced admission. The controller records comparisons and checks the required observation period and gates.
5. **Promote within scope.** If every preauthorized gate passes, the authorized controller emits a signed learning event and atomically activates the candidate for the permitted rollout scope. The event identifies the expected prior active version, policy, candidate, evaluation evidence, and effective time. Concurrent conflicting promotions fail rather than silently overwriting each other.
6. **Apply through contracts.** The gateway uses the active selector to choose an allowed set for each eligible request. Every new contract includes the full effective rules and pins the policy and selector artifact. When the chosen set differs from the policy's conservative set, the contract also lists `selection-consistency-v1` in `context_checks` and expresses every reputation threshold the selector relied on as field rules under `/attributes/reputation` (Sections 9.3 and 9.4). At presentation, the validator re-derives the set with the pinned selector from the presented snapshot and the gateway's own current selection input (Section 11.3, step 9): a stricter result fails the check with `SELECTION_INPUT_CHANGED`, the decision is `DEFERRED`, and the agent obtains a new contract; an equal or weaker result passes and the contract's set stands. The agent presents against that contract; typed checks still determine admission, followed by native authorization.
7. **Monitor and recover.** The controller monitors configured security, quality, drift, and data-integrity thresholds. A trigger causes the policy-defined freeze, tightening, or rollback. Expanding beyond the initial rollout requires its own authorized scope and gates.

## Hypothetical rollout result

During the limited rollout, an authorized evaluator identifies a quality-regression threshold breach in a covered context. The controller records the adverse evidence, then atomically rolls back to the compatible previous selector or uses the conservative fallback where policy requires it. Affected outstanding contracts are invalidated; agents obtain fresh contracts and presentations.

The rollback preserves event history, evidence lineage, and security holds. It does not undo already executed business operations. Corrected or poisoned source observations trigger recomputation and examination of other snapshots and releases that consumed them.

## Who decides what

| Decision | Authority |
|---|---|
| Which controls may adapt and what gates apply | Native administrator through signed learning policy |
| Whether the candidate meets the gates | Authorized evaluation process with attributable evidence |
| Per-release activation within those bounds | Authorized controller; no new human approval is required in bounded-autonomous mode |
| Resource access on a request | Existing native authorization system |
| Changes outside the envelope | Require a separate authorized policy change |

In `observe` mode, recording a promising candidate does not permit autonomous activation. Expired learning-policy authority freezes autonomous changes and permits only a separately current native base policy or deferral.

## Variations to verify

- The candidate proposes removing a mandatory human approval or adding a role: reject the out-of-envelope change.
- A candidate “passes” only its own generated evaluation: promotion is blocked.
- Source feedback contains instructions to ignore controls: treat them as untrusted data.
- The active artifact changes before promotion commits: reject the conflicting version transition.
- Rollback cannot safely restore the old artifact under the current base policy: use a compatible conservative fallback or defer.

## What this demonstrates

Continuous learning can autonomously change admission behavior through an auditable release lifecycle, within authority established in advance and with explicit recovery.

**Specification anchors:** §§9.3, 9.4, 11.3, 14–16, 18, 22; Appendix B.9–B.11.
