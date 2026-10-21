# Delegation cases

Cases for row `CL-17.5` of the [conformance map](../../spec-map.md): the actor transitions of [draft Section 17.5](../../draft.md#175-actor-binding-and-execution-identity), from the principal through the authorized task and the native delegation to the downstream executor. Eight are evaluation cases (kind `evaluate`); `executor-class-mismatch-outcome` is an outcomes case (kind `outcomes`). The files of each follow [../README.md](../README.md), format v2.

## Evaluation cases

### Common setup

Every evaluation case is the exchange of [admission/valid](../admission/valid) (draft Appendix B) with these changes:

- `config.json` installs the baseline check `execution-identity-v1` (Sections 9.3 and 17.5), and `contract.json` names it in `context_checks` after the four B.4 checks.
- `config.json` carries `executor_classes`, the installed execution-identity mapping, with one entry for the principal, task and operation of the exchange: its declared `class` and its `executor_id`, the identity the declared binding names. `execution-identity-v1` compares them with `native_context.json`'s `executor.class` and `executor.principal_id`.
- Each case has its own contract `jti`, `contract_id` and `nonce`, and its own presentation `jti`, which the receipt carries as `presentation_id`. The evidence and the reputation snapshot are those of B.5 and B.6, byte for byte.

Unless a case below says otherwise, the mapping declares `delegated-user` with `executor_id` alice, and the native executor is `delegated-user` alice, as in `valid-user-delegated`. The native delegation of B.1 binds alice and the task `native-task:september-summary-007` and is `active`. Its age is bounded by the `max_age_seconds` of the field rule whose `native_path` maps `/attributes/delegation/authority_ref`: the B.4 rule `supervisor-approval`, 30 seconds (Sections 9.2 and 18).

### Expected results

A positive case lists the 20 checks of B.7, all `PASS` with `REQUIREMENT_SATISFIED`, then `execution-identity-v1` `PASS`. A negative case lists only the check whose result Section 17.5 fixes for its change; other checks may fail as a consequence, and the case does not constrain their results. Every check the contract's `context_checks` names still appears in the receipt exactly once, `UNKNOWN` with `NOT_EVALUATED` when it was not evaluated (Section 12.1). A decision with a `FAIL` check is `INADMISSIBLE` (Section 11.4); an `UNKNOWN` check with no `FAIL` is `DEFERRED`. `EXECUTOR_MISMATCH` and `TASK_MISMATCH` are check reason codes, not transport codes (Section 17.5). Every evaluation completes, so the receipt's `terminal_reason` is `COMPLETED`; its `principal_id` is the native principal (Section 12.1). Only an `ADMISSIBLE` case with native authorization executes.

| Case | Adversarial claim | Change from the common setup | Expected result | Draft |
|---|---|---|---|---|
| `valid-user-delegated` | (positive control, sample I02 shape) | none: principal alice, the task reconciled with the native task, the delegation current, the executor `delegated-user` alice as declared | `ADMISSIBLE`; `execution-identity-v1` `PASS` `REQUIREMENT_SATISFIED`; `executed` `true` | 17.5, 8.5 |
| `valid-app-only` | (positive control, sample I08 shape) | No signed-in user: the principal is the workload `https://identity.example/workloads/invoice-summary-scheduler` in the native authentication, the native `/principal/id`, the native approval and delegation, the profile and both operation contexts. The mapping declares `registered-app-executor` with `executor_id` `https://identity.example/apps/invoice-summary-executor`, and that application is the native executor. | `ADMISSIBLE`; `execution-identity-v1` `PASS` `REQUIREMENT_SATISFIED`; `executed` `true` | 17.5 |
| `principal-substitution` | An agent acting for alice may present itself as acting for bob. | The profile's `/attributes/environment/principal_id` is `https://identity.example/principals/bob`; the native authentication stays alice. | `INADMISSIBLE`; `native-principal-binding-v1` `FAIL` `CONTEXT_MISMATCH` | 17.5, 8.5 |
| `broader-credential-fallback` | When the declared executor is not used, the operation may run under the connector's own broader credential. | The mapping declares `dedicated-role` with `executor_id` `https://identity.example/roles/invoice-reader-alice`; the native executor is `registered-app-executor` `https://identity.example/apps/finance-connector`. | `INADMISSIBLE`; `execution-identity-v1` `FAIL` `EXECUTOR_MISMATCH` | 17.5, 17.3 |
| `changed-task` | A delegation for one task covers another task the agent names. | The intent's `task_id` is `native-task:october-summary-011`, and the contract's `intent_digest` binds that intent; the native delegation stays bound to `native-task:september-summary-007`. | `INADMISSIBLE`; `native-delegation-v1` `FAIL` `TASK_MISMATCH` | 17.5, 10.1 |
| `stale-delegation` | A delegation read some time ago is still current. | The native delegation's `observed_at` is 1792079880, 120 seconds before `now`, beyond the 30-second bound with a margin wider than the 5-second clock skew. | `INADMISSIBLE`; `native-delegation-v1` `FAIL` `STALE_EVIDENCE` | 17.5, 9.2, 18 |
| `revoked-delegation` | A revoked delegation still covers the request. | The native delegation's `state` is `revoked`. | `INADMISSIBLE`; `native-delegation-v1` `FAIL` `REVOKED_EVIDENCE` | 17.5, 18 |
| `executor-indeterminate` | When the executor cannot be established, the request may proceed. | `native_context.json`'s `executor` is `null`: the native environment establishes no executor. | `DEFERRED`; `execution-identity-v1` `UNKNOWN` `DEPENDENCY_UNAVAILABLE`; `executed` `false` | 17.5, 11.4 |

`changed-task` keeps the mapping keyed by the native task; which mapping entry `execution-identity-v1` reads for a task that does not reconcile is not fixed by the draft, so the case does not constrain that check.

## Outcomes case: executor-class-mismatch-outcome

The adversarial claim: an `EXECUTION` `SUCCESS` counts for the agent although the native record it cites shows that the operation ran under another executor class than the one the execution-identity mapping declares.

- `config.json` is that of the `outcomes/mapping` cases, with one `trust` record: the executor `https://executor.example/finance`, reporter role `executor`, key `keys/executor.jwk.json`, which signs the report. `executor_classes` declares `delegated-user` for alice, the task and the operation, with no `executor_id`, so only the class is compared.
- `native_context.json` has the task of B.1 and one record, `native-execution-log:finance-read-0001`: a completed execution that returned data, whose executor is `registered-app-executor` `https://identity.example/apps/finance-connector`.
- `execution-event-0001` is an `EXECUTION` `SUCCESS` report on `reliability`, observed at 1792079950, citing that record. `steps.json` ingests it, then queries the B.6 context.

Expected, under `expected/delegation/executor-class-mismatch-outcome/`: `classifications.json` classifies the report `UNQUALIFIED` with reason `executor-class-mismatch` (Section 14.2), so it contributes nothing (Section 14.3). `snapshot.json` therefore holds the empty-history values of Section 15.3 in every dimension: `score_bps` 5000, `confidence_bps` 0, `independent_tasks` 0 and `qualified_events` 0, and empty `qualified_event_ids` and `superseded_event_ids` (Section 15.2). The manifest outcome is `UNQUALIFIED`.
