# Qualification cases

These cases test the baseline qualification policy `pact-qualification-v1` and the reporter independence policy `pact-reporter-independence-v1` of draft Section 14.6, together with deduplication (Section 14.3), correction (Section 14.4), the provenance manifest (Section 15.2), `beta-decay-v1` (Section 15.3) and cold starts after a key change (Sections 6.4 and 15.4). Each case is a sequence of signed `OutcomeReport`s and reputation queries against one reputation service. The expected results say what each query's snapshot carries and, for a case about one report, how that report is classified. The cases are outcomes cases in the format of [../../README.md](../../README.md), section Format v2, Outcomes cases; the runner verb is `outcomes`. Spec-map row `CL-14.3` lists them all; rows `R13`, `R14`, `R15` and `R18` list the ones of their Section 22.2 rows.

| Case | Adversarial claim | Expected | Manifest outcome |
|---|---|---|---|
| `repeated-admissions` | Repeated successful admissions build task-performance reputation. | Seven `ADMISSION` `SUCCESS` reports, each `ACCEPTED` and of zero weight; every dimension 5000, 0; nothing listed. | `MATCH` |
| `subdivided-task-100-reads` | One native task split into 100 reads earns 100 independent units. | All 100 reports listed; `reliability` 6666, 476, `independent_tasks` 1, `qualified_events` 100. | `MATCH` |
| `duplicate-reports-same-tuple` | A completion reported twice under two `event_id`s counts twice. | Second report `DUPLICATE`; one unit: 6666, 476. | `QUALIFIED` (the original) |
| `self-praise-executor-as-evaluator` | A task's executor, also registered as evaluator, praises its own task. | `QUALITY` report `UNQUALIFIED` (rule 5); `task_quality` 5000, 0; `reliability` 6666, 476 from the execution report. | `UNQUALIFIED` |
| `reciprocal-endorsements` | Two operators endorse each other's agents through the evaluators they run. | Both positive reports `DISPUTED` (rule 7); `task_quality` 6666, 476 after the first report, 5000, 0 after the second. | `DISPUTED` |
| `environmental-failure-misattributed` | A failure caused by an outage counts against the agent. | `QUALIFIED` with zero weight (rule 8); every dimension 5000, 0; nothing listed. | `QUALIFIED` |
| `correction-recompute` | A correction is a second vote, or the snapshot keeps the superseded success. | 6666, 476 before; 3333, 476 after, with the success in `superseded_event_ids`. | `QUALIFIED` (the correction) |
| `rotated-key-same-agent` | The agent's history follows it to a new holder key without a recorded rotation. | 6666, 476 under the holder key; 5000, 0 in every dimension under `holder-2`. | `MATCH` |
| `client-task-id-unreconciled` | A client-chosen task id makes a second read an independent task. | That report `UNQUALIFIED` (rule 2); one unit: 6666, 476. | `UNQUALIFIED` |
| `correction-retracts-unknown` | An `UNKNOWN` correction is refused as invalid, or leaves the success it retracts in the score. | 6666, 476 before; 5000, 0 after, nothing listed, the success in `superseded_event_ids`. | `QUALIFIED` (the correction) |
| `correction-cannot-inject-dimension` | A correction reports what its signer could not: an executor's unqualified quality report becomes a positive unit. | Both reports `UNQUALIFIED` (Section 14.2; rule 10); `task_quality` 5000, 0; nothing listed or superseded. | `UNQUALIFIED` (the correction) |
| `evaluator-policy-adherence` | An evaluator's assessment of policy adherence is ignored, or counts only when negative. | `QUALITY` `SUCCESS` and `FEEDBACK` `FAILURE` on `policy_adherence` both `QUALIFIED`; 6666, 476 after the first, 5000, 909 after the second. | `QUALIFIED` |
| `feedback-task-quality` | Verified feedback does not count, or an agent's self-feedback counts positively, or feedback needs no evidence. | The evaluator's `FEEDBACK` citing its assessment `QUALIFIED`, one unit; the agent's own `QUALIFIED` with zero weight; the evaluator's `FEEDBACK` without an assessment `UNQUALIFIED`; `task_quality` 6666, 476. | `QUALIFIED` (the evaluator's feedback) |
| `affiliated-feedback` | An affiliated evaluator's praise counts when sent as feedback. | Positive `FEEDBACK` `UNQUALIFIED` (rule 6); negative `FEEDBACK` `QUALIFIED`, one failure; `task_quality` 3333, 476. | `UNQUALIFIED` (the positive feedback) |

## Common setup

Every case uses the B.9 data policy in `config.json`'s `data_policy`, the reputation service `https://reputation.example/finance` (tenant `acme`, environment `https://gateway.example/environments/finance`), `visibility` `execution`, and `now` 1792080000. The agent is `https://identity.example/agents/invoice-assistant` of operator `https://identity.example/operators/acme`, on the task `native-task:september-summary-007` with the independence group `native-task-group:september-summary-007`, under the holder test key (`holder_jkt` `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M`). Every query asks for that agent and holder key in the B.8 context (`invoice.read` on `department-finance-invoice`) for the audience `https://gateway.example/finance`.

Each reporter signs with its own test key ([../../keys/README.md](../../keys/README.md)), and `config.json`'s `trust` registers it for its `reporter_role`:

| Reporter | `iss` | `reporter_role` | Key | Cases |
|---|---|---|---|---|
| Gateway | `https://gateway.example/finance` | `gateway` | `issuer` | `repeated-admissions` |
| Resource service | `https://executor.example/finance` | `executor` | `executor` | every other case but `reciprocal-endorsements`, `evaluator-policy-adherence`, `feedback-task-quality` and `affiliated-feedback` |
| The same resource service | `https://executor.example/finance` | `evaluator` (a second `trust` record) | `executor` | `self-praise-executor-as-evaluator` |
| Evaluator run by operator `ledgerworks` | `https://evaluator.ledgerworks.example/quality` | `evaluator` | `evaluator` | `reciprocal-endorsements` |
| Evaluator run by operator `acme` | `https://evaluator.acme.example/quality` | `evaluator` | `issuer` | `reciprocal-endorsements` |
| Evaluator | `https://evaluator.example/quality` | `evaluator` | `evaluator` | `evaluator-policy-adherence`, `feedback-task-quality`, `affiliated-feedback` |
| The agent itself | `https://identity.example/agents/invoice-assistant` | `agent` | `holder` | `feedback-task-quality` |

The issuer key stands in for the second evaluator, as it stands in for every reporter of the mapping cases; the two evaluators are told apart by their `iss` and their `trust` records.

Every report is issued at 1792080000 and expires 300 seconds later (Section 14.3), except the corrections of `correction-recompute` and `correction-retracts-unknown`, issued at 1792080010 (their `signing.json` entries state `iat` and `exp`). Each step runs at its `received_at` or `now`, 1792080000 unless the case says otherwise. `EXECUTION` reports cite an execution record of `native_context.json` that names the executor class `config.json`'s `executor_classes` declares (Section 14.2); `QUALITY` reports, and `FEEDBACK` reports from an evaluator, cite an assessment record and name it in `attribution.assessment_ref`.

## Cases

**`repeated-admissions`.** Seven reads of one native task, each admitted once: seven `ADMISSION` `SUCCESS` reports on `none`, with seven `operation_id`s and receipts, so no tuple repeats and each gets an `ACCEPTED` acknowledgment (`acks.json`). An admission decision has zero weight (Section 14.5) and admission passes generate no positive task-performance reputation (Section 14.3). A zero-weight report is not listed (Section 15.2), so `qualified_event_ids` is empty and every dimension stays at the empty history of Section 15.3. The expected values do not depend on the number of reports: zero weight times seven or times seven thousand adds nothing to alpha or beta. Row `R13` names seven thousand admissions; this case carries seven, which tests the same rule at a fraction of the size, and its result holds for any count.

**`subdivided-task-100-reads`.** One native task split into 100 reads: 100 `EXECUTION` `SUCCESS` reports on `reliability` with 100 `operation_id`s, all in the task's one independence group, observed from 1792079881 to 1792079980. Every report is qualified and listed (Section 15.2: the per-group cap limits weight, not the reports listed), so `qualified_events` is 100, while subdivided operations collapse to one group (Section 14.6 rule 3) and the group contributes at most one positive unit (Section 15.3): `independent_tasks` 1.

**`duplicate-reports-same-tuple`.** The resource service reports the same completed read twice, under `execution-event-0001` and `execution-event-0002`, with different `jti` values. The second has the tuple (`task_id`, `operation_id`, `event_kind`, `dimension`, reporter) of the first, so it gets a `DUPLICATE` acknowledgment and casts no second vote (Section 14.6 rule 4); its `qualification` in `classifications.json` is `null`, and the subject is the original. It is not an identical retry, which would carry the same `jti` (Section 7.5).

**`self-praise-executor-as-evaluator`.** The resource service reports the task's execution as executor, then assesses the same task as evaluator under its second `trust` record. Rule 5 of Section 14.6 forbids accepting the executor of a task as its evaluator, so the `QUALITY` report is `UNQUALIFIED` and `task_quality` stays at 5000, 0. The execution report keeps its own unit on `reliability`.

**`reciprocal-endorsements`.** The evaluator run by `ledgerworks`, whose own agent is `https://identity.example/agents/ledger-reviewer` (`config.json`'s `evaluator_agents`), assesses the invoice assistant positively. Then the evaluator run by `acme`, the invoice assistant's operator, assesses the ledger reviewer's task positively. With the second report, evaluator E's own agent has been evaluated by the agent's operator within the ingestion window, so both positive reports are `DISPUTED` pending review (Section 14.6 rule 7). `affiliations` is empty, so rule 6 does not apply. The first query, before the second report, sees the first report qualified: `task_quality` 6666, 476. The second query sees both disputed: they are excluded from positive reputation (Section 14.4) and not qualified, so nothing is listed and `task_quality` is 5000, 0.

**`environmental-failure-misattributed`.** A read fails during a storage outage, and the resource service reports `EXECUTION` `FAILURE` on `reliability` with `causal_assessment` `ENVIRONMENT`. The report is qualified with zero negative weight (Section 14.6 rule 8; Section 14.3: outages are not misconduct), so it is not listed and `reliability` stays at 5000, 0 rather than 3333, 476.

**`correction-recompute`.** The case of the example in [../../README.md](../../README.md), section Example: outcomes/qualification/correction-recompute, with the same `jti` values. The resource service reports a success observed at 1792079980; a query at 1792080000 sees one unit. Reconciliation then finds the read failed, and the resource service sends `correction-event-0002`, a `CORRECTION` `FAILURE` on `reliability` with `supersedes` `["execution-event-0001"]`, the same task, operation and reporter, and `observed_at` 1792079980, the time of the observation it corrects; it cites the reconciled execution record. The correction is scored as one event in place of the success (Section 14.6 rule 10): the query at 1792080010 lists the correction in `qualified_event_ids` and the success in `superseded_event_ids`. The two provenance manifests differ, so the two snapshots' `provenance_digest` values differ; a harness checks each digest against the printed manifest.

**`rotated-key-same-agent`.** The history accrues under the holder key that the task's admission bound (`native_context.json`'s `tasks[].holder_jkt`). The service records no rotation, so a query under `holder-2` (`ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg`) gets the cold-start values: the service MUST NOT silently transfer the score (Section 6.4), and a new key inherits no positive reputation without verified continuity (Section 15.4). The case asserts only that rule. Preserving history across a verified rotation is a MAY of Section 6.4 and is not asserted.

**`client-task-id-unreconciled`.** A first read of the task earns one unit. The second read's report carries `native-task:september-summary-007-retry-1`, a task id the client supplied, which no authoritative task record holds; the native record it cites belongs to the real task. It is `UNQUALIFIED` (Section 14.6 rule 2), the independence group comes from the task registry and not from the report (rule 1), and the snapshot stays at one unit, not two independent tasks.

**`correction-retracts-unknown`.** The resource service reports a success observed at 1792079980; a query at 1792080000 sees one unit. It then withdraws the report: `correction-event-0002` is a `CORRECTION` `UNKNOWN` on `reliability`, with `supersedes` `["execution-event-0001"]`, the same task, operation and reporter, citing the execution record of the task and operation. A correction carries the dimension of the events it supersedes whatever its result (Appendix A.2), so it is valid, and with `result` `UNKNOWN` it retracts the success (Section 14.6 rule 10). Its weight is zero (Section 15.3), so the query at 1792080010 lists nothing in `qualified_event_ids` and the success in `superseded_event_ids` (Section 15.2).

**`correction-cannot-inject-dimension`.** The resource service, registered only as executor, reports `QUALITY` `SUCCESS` on `task_quality`, citing a completed assessment of the task; it may not report quality (Section 14.2), so the report is `UNQUALIFIED`. It then sends a `CORRECTION` `SUCCESS` on `task_quality` that supersedes it. Rule 10 of Section 14.6 accepts only the correction of `QUALIFIED` or `DISPUTED` events, so the correction is `UNQUALIFIED`, supersedes nothing, and `task_quality` stays at 5000, 0. Were the correction qualified, it would weigh one positive unit from a reporter that may not assess quality.

**`evaluator-policy-adherence`.** The evaluator `https://evaluator.example/quality` assesses the task's policy adherence: `QUALITY` `SUCCESS` on `policy_adherence`, citing its completed assessment, then `FEEDBACK` `FAILURE` on `policy_adherence` with `causal_assessment` `AGENT`, citing the same assessment. Section 14.5 counts an evaluator's assessment of policy adherence positively and negatively under the eligibility of a quality assessment; the evaluator did not execute the task and is not affiliated with its operator (rules 5 and 6), and the two reports differ in `event_kind`, so their tuples differ (rule 4). The query after the first sees one positive unit, the query after the second one unit of each.

**`feedback-task-quality`.** The verified feedback row of Section 14.5. The evaluator reports `FEEDBACK` `SUCCESS` on `task_quality` for `invoice-read-operation-0001`, citing the completed assessment it conveys: it counts as an assessment does, one positive unit. The agent itself, registered for `reporter_role` `agent` under the holder key, reports `FEEDBACK` `SUCCESS` on the same task and operation as a diagnostic: it needs no record and is `QUALIFIED`, but an agent's own event is never positive (Section 14.6 rule 11), so it has zero weight and is not listed. Its tuple differs from the evaluator's by reporter (rule 4). The evaluator then reports `FEEDBACK` `SUCCESS` for `invoice-read-operation-0002` citing nothing: verified feedback from an evaluator cites the assessment it conveys, so it is `UNQUALIFIED` `no-assessment-record`. The query sees one unit.

**`affiliated-feedback`.** `config.json`'s `affiliations` pairs the evaluator with the operator `https://identity.example/operators/acme`. The evaluator reports `FEEDBACK` `SUCCESS` on `task_quality` for `invoice-read-operation-0001` and `FEEDBACK` `FAILURE` for `invoice-read-operation-0002`, each citing a completed assessment of that operation. Rule 6 of Section 14.6 classifies an affiliated evaluator's positive `QUALITY` and `FEEDBACK` reports `UNQUALIFIED` and leaves its negative reports unaffected: the success is `affiliated-evaluator`, the failure one attributable failure.

## Expected snapshots

The values follow `beta-decay-v1` (Section 15.3) at the query's `now`, computed from the draft and not from an implementation. A dimension with no listed report has alpha = beta = 1: `score_bps` 5000, `confidence_bps` 0, `independent_tasks` 0 and `qualified_events` 0. A qualified success observed `s` seconds before `t` weighs 2^(-s/2592000); so does a failure.

| Case, step | Listed reports | Dimension values |
|---|---|---|
| `repeated-admissions`, 7 | none | every dimension 5000, 0, 0, 0 |
| `subdivided-task-100-reads`, 100 | 100 successes, one group, `s` from 20 to 119 | `reliability` 6666, 476, 1 task, 100 events |
| `duplicate-reports-same-tuple`, 2 | `execution-event-0001`, `s` 20: alpha 1.99999465 | `reliability` 6666, 476, 1, 1 |
| `self-praise-executor-as-evaluator`, 2 | `execution-event-0001`, `s` 20: alpha 1.99999465 | `reliability` 6666, 476, 1, 1; `task_quality` 5000, 0, 0, 0 |
| `reciprocal-endorsements`, 1 | `quality-event-0001`, `s` 30: alpha 1.99999198 | `task_quality` 6666, 476, 1, 1 |
| `reciprocal-endorsements`, 3 | none | every dimension 5000, 0, 0, 0 |
| `environmental-failure-misattributed`, 1 | none | every dimension 5000, 0, 0, 0 |
| `correction-recompute`, 1 | `execution-event-0001`, `s` 20: alpha 1.99999465 | `reliability` 6666, 476, 1, 1 |
| `correction-recompute`, 3 | `correction-event-0002`, a failure, `s` 30: beta 1.99999198 | `reliability` 3333, 476, 1, 1 |
| `rotated-key-same-agent`, 1 | `execution-event-0001`, `s` 20: alpha 1.99999465 | `reliability` 6666, 476, 1, 1 |
| `rotated-key-same-agent`, 2 | none (holder key `holder-2`) | every dimension 5000, 0, 0, 0 |
| `client-task-id-unreconciled`, 2 | `execution-event-0001`, `s` 20: alpha 1.99999465 | `reliability` 6666, 476, 1, 1 |
| `correction-retracts-unknown`, 1 | `execution-event-0001`, `s` 20: alpha 1.99999465 | `reliability` 6666, 476, 1, 1 |
| `correction-retracts-unknown`, 3 | none; `execution-event-0001` superseded | every dimension 5000, 0, 0, 0 |
| `correction-cannot-inject-dimension`, 2 | none | every dimension 5000, 0, 0, 0 |
| `evaluator-policy-adherence`, 1 | `quality-event-0001`, `s` 20: alpha 1.99999465 | `policy_adherence` 6666, 476, 1, 1 |
| `evaluator-policy-adherence`, 3 | both reports, `s` 20: alpha = beta = 1.99999465 | `policy_adherence` 5000, 909, 1 task, 2 events |
| `feedback-task-quality`, 3 | `feedback-event-0001`, `s` 20: alpha 1.99999465 | `task_quality` 6666, 476, 1, 1 |
| `affiliated-feedback`, 2 | `feedback-event-0002`, a failure, `s` 20: beta 1.99999465 | `task_quality` 3333, 476, 1, 1 |

Dimensions the table does not name are 5000, 0, 0, 0. With one unit, `score_bps` = floor(10000 alpha / (alpha + 1)) = 6666 and `confidence_bps` = floor(10000 (alpha - 1) / (alpha + 19)) = 476; with one failure, floor(10000 / (1 + beta)) = 3333 and 476; with one of each, 5000 and floor(10000 (alpha + beta - 2) / (alpha + beta + 18)) = 909.

For `subdivided-task-100-reads`, Section 15.3 caps the decayed sum of the group's successes at one unit (alpha 2). The other readings of the cap give the same values: one unit at the newest observation (alpha 1.99999465), at the oldest (1.99996818), 1/100 of a unit per report (1.99998141), or the decayed sum capped at 1 (alpha 2) all yield 6666 and 476.

A harness compares `score_bps` and `confidence_bps` within one basis point, the recomputation tolerance of Section 15.3, and every other member exactly. Each snapshot's `value` also names the queried context and the B.6 scoring pins, and its `claims` carry the service's `iss` and the query's `sub`, `aud` and `holder_jkt`. `provenance` lists the qualified reports with nonzero weight, sorted by `iss` and then `jti`; zero-weight, unqualified, disputed and duplicate reports are not listed (Section 15.2).

The expected files are `expected/outcomes/qualification/<case>/snapshot.json`, `classifications.json` for the cases about one report (the manifest's `expected`), and `acks.json` for `repeated-admissions`, `subdivided-task-100-reads` and `duplicate-reports-same-tuple`. The `reason` tokens of `classifications.json` are those of [../../README.md](../../README.md), section classifications.json.
