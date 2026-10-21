# hold-survives-correction

Row `R17` of the spec map; draft Sections 14.6 rules 10 and 12, 15.4 and 16.5. Adversarial claim: an authority retracts its incident report and the hold lifts without remediation. The common setup is in [../README.md](../README.md), without the run of `EXECUTION` reports: the case has no statistical history.

Two security authorities are registered in `config.json`'s `trust`, both with `reporter_role` `security_authority`: `https://security.example/soc`, for which the `issuer` key stands in, and `https://security.example/finance`, signing with the `security-authority` key. Only the second is in `hold_clearance_authorities`, as in B.9, so the authority that places the hold cannot clear it (Section 16.5).

Every report concerns the task `native-task:invoice-review-0011` and its operation `invoice-read-operation-0011`, is issued at 1792080000 and expires 300 seconds later; every step runs at 1792080000.

| Step | Input | Expected snapshot |
|---|---|---|
| 0 | `security-event-0001`: `SECURITY` `FAILURE` on `none` from `https://security.example/soc`, observed at 1792079980, citing the confirmed incident record of the task and operation | |
| 1 | query | `HOLD`, `hold_refs` `["security-event-0001"]`; nothing listed or superseded |
| 2 | `correction-event-0002`: `CORRECTION` `UNKNOWN` on `none` from the same authority, `supersedes` `["security-event-0001"]`, observed at 1792079980, citing the same incident record | |
| 3 | query | `HOLD`, `hold_refs` `["security-event-0001"]`; `superseded_event_ids` `[["https://security.example/soc", "lJmE2OHn59MJYwLeAFsHNw"]]`, nothing listed |
| 4 | `remediation-event-0003`: `REMEDIATION` `SUCCESS` on `none` from `https://security.example/finance`, observed at 1792079990, naming `security-event-0001` beside the completed remediation record | |
| 5 | query | `CLEAR`, `hold_refs` `[]`; `superseded_event_ids` as at step 3, nothing listed |

Every dimension is 5000, 0, 0 tasks, 0 events in every snapshot: a security authority's reports have zero weight in every dimension (Sections 14.5 and 14.6 rule 12), and the retraction has zero weight too (rule 10).

- Step 1: the incident is the confirmed incident row of Section 14.5, `FAILURE` on `none` citing the confirmed incident record of its task and operation, so it places a hold that `hold_refs` names by its `event_id` (Section 15.4).
- Step 3: the correction names a `QUALIFIED` event of its task, operation, kind and dimension from its own signer, so it is `QUALIFIED` and supersedes the incident in provenance (rule 10): the incident is listed in `superseded_event_ids`. A correction is never a clearance: the hold stays, and `hold_refs` keeps the superseded report's `event_id` (Section 15.4; rule 12: a correction places and clears no hold).
- Step 5: the remediation of a hold clearance authority names the original `event_id` beside its completion evidence, which records the withdrawal, and clears the hold (Section 15.4). The incident stays superseded.

Every ingestion is acknowledged `ACCEPTED` (`acks.json`): the three reports differ in `event_kind` or reporter, so no deduplication tuple repeats (Section 14.6 rule 4). The case asserts no classification; the draft fixes the classifications above through the snapshots: incident `QUALIFIED` `mapped`, correction `QUALIFIED` `correction`, remediation `QUALIFIED` `mapped`.

Expected files: `expected/reputation/hold-survives-correction/snapshot.json` and `acks.json`; manifest outcome `MATCH`.
