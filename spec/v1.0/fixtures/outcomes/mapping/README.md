# Outcome mapping cases

These cases test the baseline native outcome mapping of draft Section 14.5. Each case is a short sequence of signed `OutcomeReport`s about one native task. The expected result says, for every report, whether the reputation service classifies it `QUALIFIED` or `UNQUALIFIED` (Section 14.3), why, and what it adds to each reputation dimension. Every case names the adversarial claim it must reject: a reading of a native observation that the mapping forbids. Spec-map row `CL-14.1` lists the cases; the runner verb is `outcomes` ([../../README.md](../../README.md), section Runner contract).

| Case | Adversarial claim | Expected |
|---|---|---|
| `hidden-row-read-as-task-success` | A filtered read that returned no rows is reported as `EXECUTION` `SUCCESS` on `task_quality`. | That report `UNQUALIFIED` (A.2: invalid); the honest `reliability` report with `details` `"empty"` counts once. |
| `accepted-restart-as-completed` | An accepted restart is reported as `EXECUTION` `SUCCESS` on `reliability`, citing only the acceptance record. | That report `UNQUALIFIED`; the `UNKNOWN` acceptance report has zero weight. |
| `admission-as-task-success` | An admission pass is reported on `reliability`. | That report `UNQUALIFIED` (A.2: invalid); the `none` report has zero weight. |
| `denial-as-misconduct` | A native denial is reported as `AUTHORIZATION` `FAILURE` on `policy_adherence`. | That report `UNQUALIFIED` (A.2: invalid); no negative weight. |
| `async-accept-then-complete` | An asynchronous export counts at acceptance and again at completion, or its completion is dropped as a duplicate. | Both reports `QUALIFIED`; exactly one positive `reliability` unit. |
| `visibility-unavailable` | A gateway without execution visibility reports assumed success. | The declared `UNKNOWN` report `QUALIFIED` with zero weight; the assumed success `UNQUALIFIED`. |
| `policy-violation-as-adherence-failure` | A detected policy violation places a security hold, or a gateway's report that it saw no violation earns positive `policy_adherence` weight. | The `SECURITY` `FAILURE` on `policy_adherence` `QUALIFIED`, one negative unit, no hold; the `SECURITY` `SUCCESS` of another operation `UNQUALIFIED`. |
| `denial-as-policy-violation` | A native denial is reported as a detected policy violation, `SECURITY` `FAILURE` on `policy_adherence` citing the denial record. | The denial report `QUALIFIED` with zero weight; the `SECURITY` report `UNQUALIFIED` (no violation record); no negative weight. |
| `assessment-as-reliability` | An evaluator's assessment earns reliability without an execution record: `QUALITY` `SUCCESS` on `reliability`. | The assessment refused `INVALID_MESSAGE`, `UNQUALIFIED` (A.2: invalid); the executor's `EXECUTION` report counts once. |
| `execution-as-policy-adherence` | An execution report raises the agent's policy adherence: `EXECUTION` `SUCCESS` on `policy_adherence`. | That report refused `INVALID_MESSAGE`, `UNQUALIFIED` (A.2: invalid); `policy_adherence` 5000, 0; the `reliability` report counts once. |
| `incident-without-record` | A security authority's signature alone holds an agent, an incident of another operation holds this one, or a hold hides on a dimension. | Every `SECURITY` report `UNQUALIFIED`: two without the incident record of their task and operation, one on `policy_adherence`; `CLEAR`, no hold. |

## Case files

A case is the directory `outcomes/mapping/<case>/`:

| File | Content |
|---|---|
| `config.json` | Trusted configuration of the reputation service, below. |
| `native_context.json` | The native task and the immutable native records the reports may cite, below. |
| `reports/<event_id>.json` | Each report, decoded, in RFC 8785 canonical form with no trailing newline: the payload of its signed form byte for byte. |
| `signed/<event_id>.jws` | Each signed report, typ `pact-outcome+jwt`. |
| `signing.json` | What `pactfix generate` signs: one artifact entry per report ([../../README.md](../../README.md), section Generator contract: signing.json). |
| `steps.json` | The ingestions and the query, below. |

The reports are ingested in the order of their file names. Signed reports are made by `pactfix generate`, as for evaluation cases ([../../README.md](../../README.md), section Signed artifacts): `iat` and `nbf` are `1792080000`, `exp` is 300 seconds later (Section 14.3), and every `jti` is fixed in advance. The issuer test key stands in for every reporter, as [../../vectors/jws/README.md](../../vectors/jws/README.md) describes.

`steps.json` ingests the reports in that order at `config.json`'s `now`, then queries the reputation of the task's agent, under the holder test key, in the context of its reports, for the audience `https://gateway.example/finance` (Appendix B.6), at `now`.

### config.json

| Member | Content |
|---|---|
| `now` | The ingestion time, Unix seconds. |
| `clock_skew_seconds` | The allowed clock skew (Section 7.5). |
| `data_policy` | The data policy of B.9: `qualification_policy_id` and `reporter_independence_policy_id`, the baselines `pact-qualification-v1` and `pact-reporter-independence-v1` (Section 14.6); `ingestion_window_seconds`, the 7-day baseline of Section 14.3; `positive_weight_cap_per_task` 1, `maximum_failure_weight` 5 and `task_attribution_source` `native-task-registry`. |
| `reputation_service` | `service_id` (the audience of every report), `tenant_id` and `environment_id`. |
| `visibility` | What the gateway profile declares: `execution` when execution is observable, `none` when it is not (Section 14.5). The values are those of the adapter cases ([../../adapters/README.md](../../adapters/README.md)). |
| `trust` | The trusted registration of each signer (A.2): `iss`, `role` `reporter`, the `reporter_role` the signer is registered for, and `keys`, the paths of its public JWK files under `keys/`. |
| `executor_classes` | The installed mapping of the executor identity class (Section 17.5): `principal_id`, `task_id`, `operation_id` and `class`. |

### native_context.json

| Member | Content |
|---|---|
| `tasks` | The authoritative task records: `task_id`, `agent_id`, `operator_id`, `principal_id` and `independence_group`, the group that `task_attribution_source` assigns (Section 14.6, rule 1). |
| `records` | Object from a native record reference, the value an `evidence_refs` entry cites, to the record: `kind` (`execution`, `authorization`, `violation`, `assessment` or `incident`), `state` (`accepted`, `completed` or `failed` for an execution; `allowed` or `denied` for an authorization; `recorded` for the gateway's record of a violating request; `completed` for an assessment; `confirmed` for an incident), `returned` (`data` or `empty` for a completed execution, otherwise `null`), `task_id`, `operation_id`, `executor` (`class` and `principal_id`, Section 17.5; `null` for a violation, assessment or incident record) and `observed_at`. |

## Expected result

The expected results are under `expected/outcomes/mapping/<case>/`. `classifications.json`, which the manifest entry names, classifies each report:

| Member | Content |
|---|---|
| `case` | The fixture id. |
| `adversarial_claim` | The claim the case must reject. |
| `subject_event_id` | The report the case is about. Its qualification is the manifest `outcome` of the case. |
| `events` | One entry per report: `event_id`, `report` and `signed` (paths in the case directory), `qualification`, `reason`, `contribution` and `rationale`, the draft rules that fix the result. |
| `dimension_deltas` | For each of `reliability`, `task_quality` and `policy_adherence`, the `positive` and `negative` weight units the case adds (Section 15.3), the sum of the contributions. |

`contribution` is the report's `dimension` with the `positive` and `negative` weight units the report adds to it after the cap of one positive unit per independent task group and dimension (Section 15.3). A report that is not `QUALIFIED`, or whose dimension is `none`, adds nothing.

| `reason` | `qualification` | Meaning |
|---|---|---|
| `mapped` | `QUALIFIED` | The report follows a row of the Section 14.5 table and passes the checks of Section 14.2. Its weight is the row's: zero, or one unit toward its dimension. |
| `invalid-report` | `UNQUALIFIED` | The report breaks a dimension rule of A.2. The receiver refuses it at ingestion. |
| `no-executor-record` | `UNQUALIFIED` | An `EXECUTION` or `AUTHORIZATION` report, other than a report of absent execution visibility (Section 14.5), cites no immutable native record that identifies the actual executor (Sections 14.2, 14.5 and A.2). |
| `no-completion-record` | `UNQUALIFIED` | An `EXECUTION` `SUCCESS` or `FAILURE` report cites no record of a completed or failed execution, only one of an accepted request (Sections 14.2 and 14.5). |
| `reporter-not-authorized` | `UNQUALIFIED` | A report of a kind whose Section 14.5 row admits only its reporter, but with another `result` or `dimension` than the row's, such as a gateway `SECURITY` `SUCCESS` or a security authority's `SECURITY` on `policy_adherence` (Section 14.6 rule 12). |
| `record-mismatch` | `UNQUALIFIED` | A report of the detected policy violation row that cites no `violation` record of its task and operation, or of the confirmed incident row that cites no confirmed `incident` record of its task and operation (Sections 14.2, 14.5 and 15.4). |

A report of absent execution visibility has empty `evidence_refs`, as its Section 14.5 row requires, and is `mapped` when `config.json` declares `visibility` `none`.

### snapshot.json

`snapshot.json` is the expected snapshot of the query step, in the format of [../../README.md](../../README.md), section Format v2, Outcomes cases. Its `value` names the queried context, the three mandatory dimensions and the scoring pins of B.6; its `provenance` lists the qualified reports with a nonzero weight, sorted by `iss` and `jti`, and no superseded report (Section 15.2); its `claims` are the `iss` of the reputation service and the `sub`, `aud` and `holder_jkt` of the query.

The values follow beta-decay-v1 (Section 15.3) at `t` = `now` = 1792080000, with the weight units of `classifications.json`. A dimension with no listed report has alpha = beta = 1: `score_bps` 5000, `confidence_bps` 0, `independent_tasks` 0 and `qualified_events` 0. A dimension with one qualified success observed `s` seconds before `t` has alpha = 1 + 2^(-s/2592000) and beta = 1:

| Case | Listed report | `reliability` | `task_quality`, `policy_adherence` |
|---|---|---|---|
| `accepted-restart-as-completed` | none | 5000, 0, 0 tasks, 0 events | 5000, 0, 0, 0 |
| `admission-as-task-success` | none | 5000, 0, 0 tasks, 0 events | 5000, 0, 0, 0 |
| `async-accept-then-complete` | `execution-event-0002`, `s` = 20: alpha 1.99999465 | 6666, 476, 1 task, 1 event | 5000, 0, 0, 0 |
| `denial-as-misconduct` | none | 5000, 0, 0 tasks, 0 events | 5000, 0, 0, 0 |
| `hidden-row-read-as-task-success` | `execution-event-0001`, `s` = 50: alpha 1.99998663 | 6666, 476, 1 task, 1 event | 5000, 0, 0, 0 |
| `visibility-unavailable` | none | 5000, 0, 0 tasks, 0 events | 5000, 0, 0, 0 |
| `policy-violation-as-adherence-failure` | `security-event-0001`, a failure, `s` = 20: beta 1.99999465 | 5000, 0, 0 tasks, 0 events | `task_quality` 5000, 0, 0, 0; `policy_adherence` 3333, 476, 1, 1 |
| `denial-as-policy-violation` | none | 5000, 0, 0 tasks, 0 events | 5000, 0, 0, 0 |
| `assessment-as-reliability` | `execution-event-0001`, `s` = 20: alpha 1.99999465 | 6666, 476, 1 task, 1 event | 5000, 0, 0, 0 |
| `execution-as-policy-adherence` | `execution-event-0001`, `s` = 20: alpha 1.99999465 | 6666, 476, 1 task, 1 event | 5000, 0, 0, 0 |
| `incident-without-record` | none | 5000, 0, 0 tasks, 0 events | 5000, 0, 0, 0 |

For the four cases with a listed success, `score_bps` = floor(10000 alpha / (alpha + 1)) = 6666 and `confidence_bps` = floor(10000 (alpha - 1) / (alpha + 19)) = 476; for the listed failure, floor(10000 / (1 + beta)) = 3333 and 476. The snapshot of `incident-without-record` carries `security_status` `CLEAR` and `hold_refs` `[]`: a security authority's report places a hold only as the confirmed incident of Section 14.5, `FAILURE` on `none` citing the confirmed incident record of its task and operation (Sections 14.6 rule 12 and 15.4). The refused reports of `assessment-as-reliability` and `execution-as-policy-adherence` get no acknowledgment: `acks.json` gives their step `status` `null` and `transport_code` `INVALID_MESSAGE` (Section 13.4). The snapshots of `policy-violation-as-adherence-failure` and `denial-as-policy-violation` also carry `security_status` `CLEAR` and `hold_refs` `[]`: a gateway's report places no hold (Section 15.4). A harness compares `score_bps` and `confidence_bps` within one basis point (Section 15.3) and every other member exactly. The zero-weight reports (the `none` rows of Section 14.5) and the `UNQUALIFIED` reports are not listed.

## Format v2

These cases are the first of the outcomes case format of [../../README.md](../../README.md) (section Format v2, Outcomes cases), which generalizes the files above to every outcomes case. They were migrated to it as that file's section Migration of committed cases lists:

- each case gained a `signing.json` with its `jti` values, and the signed reports stayed as they are;
- `qualification_policy_id`, `reporter_independence_policy_id` and `ingestion_window_seconds` moved into the `config.json` member `data_policy`;
- the expected file `qualification.json` was renamed `classifications.json`, with its content unchanged;
- each case gained a `steps.json`, which ingests the reports in file-name order and then queries the task's context, and an expected `snapshot.json` for that query (section snapshot.json above), so that the `outcomes` verb can judge the case from what the implementation prints.
