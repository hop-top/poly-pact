# Use case 09 — Reliable agent earns reduced scrutiny

**Status:** Informative worked example for PACT Protocol v1.0. Names, amounts, policies, and thresholds are fictional deployment choices, not protocol defaults. Profile paths below are gateway-defined attributes. This is a behavioral example, not a complete signed wire fixture.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** U09. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- Current authorized selector/scorer, qualified outcomes, native task registry, and learning policy already exist.
- All score/confidence margins, task counts, observation windows, and assessment ages are explicit local policy choices.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C10 | Independent tasks and qualified assessors/reporters. |
| C11 | Contextual dimensions, confidence, provenance, and snapshots. |
| C12 | Active scorer/selector/policy registry and allowed sets. |
| C16 | Capability/runtime assessments retaining original observation time. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G08 | Establish genuine independent performance history. | Deployment / validation |
| G09 | Empirically justify thresholds and ten/forty-five-minute assessment ages. | Validation |
| G10 | Selection inputs, `selection-consistency-v1`, and the changed-input outcomes are defined in Sections 9.4 and 11.3 (step 9). Remaining: validate each outcome in the table under "Variations to verify"; state which outcome fixes the terminal decision when several apply to one changed input (degraded snapshot, new hold). | Clarification / validation |
| G25 | Distinguish attested from enforced data-use controls per §17.4. | Deployment / coverage |

### Deliberate simplifications and limitations

- This is selection under an already active artifact, not a model release.
- The local numerical choices and claimed reduction in scrutiny are uncalibrated and unmeasured.
- The numeric choices in this example, such as the task count and the ten and forty-five minute assessment ages, are illustrative and are evaluated per Appendix E.
- `execution-control-v1` is not required, so the runtime guarantee is labeled "attested-only": both sets require managed-runtime evidence and reduced scrutiny changes neither the label nor post-read residual limits.

### Validation still required

- Test sparse/wrong-context/duplicated history, decay, new holds, and changed eligibility before handoff.
- Evaluate reduced scrutiny independently while preserving immutable checks and mandatory native approvals.

No finding is closed by this narrative. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Northstar's reporting assistant prepares weekly departmental summaries. It already has native access to the underlying reports. New or unfamiliar agents enter the conservative admission set, which requires a recent capability assessment and a managed-runtime attestation.

The signed learning policy also permits an established set. That set retains all immutable requirements and runtime checks but allows an older capability assessment. An already activated, evaluated selector chooses between these sets using qualified contextual reputation. This example follows an agent's changing evidence under that existing selector; it does not assume a new model release for every score update.

## Requirements that can and cannot change

| Control | Conservative set | Established set |
|---|---|---|
| Native authentication and enrolled holder key | Required | Required |
| Trusted principal/role/delegation provenance | Required | Required |
| Request, purpose, audience, and realm binding | Required | Required |
| Current required status and hold checks | Required | Required |
| Managed-runtime evidence | Required | Required |
| Maximum age of capability assessment | Ten minutes | Forty-five minutes |
| Current native resource authorization | Required | Required |

Both assessment ages are within this deployment's authorized adaptive bounds and the baseline's one-hour maximum evidence lifetime. The evidence must also remain unexpired and satisfy its required status freshness. Re-signing cannot make an old assessment appear newly performed; original observation times remain authoritative.

## Reputation inputs

The selector uses verified reputation for this tenant, environment, agent, reporting purpose, action/resource classes, and runtime class. It considers reliability, task quality, policy adherence, confidence, and independent task coverage separately.

The deployment requires its configured score and confidence margins, at least 100 independent qualified tasks, and 30 days of observations before established-set eligibility. These are local policy choices; 100 tasks alone does not guarantee eligibility. Applicable holds block admission regardless of favorable statistics. Under Section 14.5, the performance inputs are the authorized resource services' “Execution completed with data returned” reports (`EXECUTION`, `SUCCESS`, `reliability`) and the independent evaluators' “Independent assessment” reports (`QUALITY`, `task_quality`), while every “PACT admission decision” (`ADMISSION`) carries zero weight however many are repeated.

## Exchange and progression

1. With insufficient history, the gateway selects the conservative set and publishes its complete effective rules in the signed contract. The agent cannot request a weaker set.
2. The assistant completes separately attributable reporting tasks over time. Authorized resource services report execution; independent evaluators report task quality. The reputation service qualifies, deduplicates, and updates the relevant dimensions.
3. On a later request, the gateway's authorized selector uses a fresh, trusted contextual snapshot to establish that all established-set conditions are met. The gateway keeps a record of the selection inputs it used (its "selection record", Section 9.4): the active `learning_policy_digest`, the selector's `learning_artifact_digest`, the snapshot's `jti`, the current hold status, and `base_revision`.
4. The gateway issues a contract containing the established set, pinned to the active policy and selector artifact. Because the selected set differs from the policy's conservative set, the contract lists `selection-consistency-v1` in `context_checks` and expresses every reputation threshold the selector relied on as field rules under `/attributes/reputation` (Section 9.4). The assistant presents evidence satisfying that exact contract.
5. PACT evaluates every required check. In step 9 of the validator algorithm (Section 11.3), `selection-consistency-v1` re-derives the effective set with the contract's pinned selector, using (i) the presented snapshot and (ii) the gateway's own current trusted selection input. If both yield a set equal to or weaker than the contract's `selected_set`, the check result is `PASS` and the contract's set stands; it is never changed to a weaker set mid-exchange. If either yields a stricter set, the check result is `FAIL` with reason code `SELECTION_INPUT_CHANGED`, the decision is `DEFERRED`, and the retry guidance is "obtain a new contract". The check's `CheckResult` carries the presented snapshot's `jti` in `evidence_ids`, and its `source_ref` identifies the selection record (Appendix A.2). If the exchange is admissible, the gateway independently evaluates native authorization and execution conditions.

## Result

The assistant performs fewer capability reassessments while continuing to prove identity, provenance, request binding, and current required status. Its native access does not expand. It does not gain a general-purpose “trusted agent” token.

## Feedback loop and deterioration

Qualified performance observations continue after the change. If relevant confidence declines, evidence becomes stale, or the selector's conditions cease to hold, later contracts use the conservative set or another authorized stricter set. Missing favorable reputation evidence triggers the configured conservative fallback only where policy permits; it never justifies a permissive guess.

A security hold blocks admission through its own current check. Statistical decay cannot clear it. A source outage is not automatically misconduct.

## Variations to verify

- Repeated admission passes with no executed tasks: no positive performance reputation.
- Hundreds of reads from one reporting task: task-group caps prevent fabricated independent history.
- Strong invoice-reading history instead of reporting history: no positive cross-context transfer in the baseline.
- A native supervisor approval becomes required for a particular report: the established set cannot waive it.

For a contract that selected the established set, each row changes one input between contract issuance and presentation (Sections 9.4, 11.3 step 9, 13.4, and 16.5):

| Input changed before presentation | Outcome |
|---|---|
| Same snapshot, no other input changed | The re-derivation yields the established set: `selection-consistency-v1` is `PASS` and the contract's set stands. |
| A newer snapshot is presented and still meets every established-set condition and field rule | `PASS`; the exchange continues under the contract's set, never a weaker one. |
| The presented snapshot has degraded below a threshold field rule under `/attributes/reputation` | That rule fails: `INADMISSIBLE`, `INVALID_CLAIM` on the rule. The same snapshot also gives the re-derivation a stricter set; see the G10 item above. |
| The gateway's own trusted input now selects a stricter set | `selection-consistency-v1` is `FAIL` with `SELECTION_INPUT_CHANGED`; decision `DEFERRED`; retry guidance "obtain a new contract", selected from the current inputs. Reusing the old contract gives the transport error `REQUIREMENTS_CHANGED`. |
| A security hold becomes applicable | The mandatory security-hold check blocks admission with `SECURITY_HOLD`. A fresh favorable snapshot cannot waive it, and statistical decay cannot clear it (Sections 15.2 and 15.4). |
| The active policy or the pinned selector artifact is replaced: changed policy digest or base revision, or selector artifact rolled back or frozen | The contract is no longer active: `REQUIREMENTS_CHANGED`; obtain a new contract. |

## What this demonstrates

Reputation can reduce permitted scrutiny through explicit, bounded requirements while every immutable check and native permission remains effective.

**Specification anchors:** §§8.3, 9.3, 9.4, 11.3, 13.4, 14–16, 18, 20.1; Appendix A.2.
