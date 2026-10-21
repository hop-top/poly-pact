# security-hold-no-decay

Row `R17` of the spec map; draft Sections 15.4 and 16.5 and invariant 8 of Section 5. Adversarial claims: a security hold decays with time, or any security authority's remediation clears it. The common setup is in [../README.md](../README.md).

Two security authorities are registered in `config.json`'s `trust`, both with `reporter_role` `security_authority`: `https://security.example/finance`, signing with the `security-authority` key, and `https://security.example/soc`, for which the `issuer` key stands in. Only the first is in `hold_clearance_authorities`, as in B.9.

| Step | Time | Input | Expected snapshot |
|---|---|---|---|
| 0 to 9 | 1792080000 | Ten `EXECUTION` `SUCCESS` reports on `reliability`, report `n` observed `20 + 43200 (n - 1)` seconds earlier | |
| 10 | 1792080000 | query | `reliability` 9130, 3220, 10 tasks, 10 events; `security_status` `CLEAR`, `hold_refs` `[]` |
| 11 | 1792080000 | `security-event-0001`: `SECURITY` from `https://security.example/finance`, citing the confirmed incident record | |
| 12 | 1792080000 | query | `reliability` 9130, 3220, 10, 10; `HOLD`, `["security-event-0001"]` |
| 13 | 1826640000 | query, 400 days later | `reliability` 5002, 0, 10, 10; `HOLD`, `["security-event-0001"]` |
| 14 | 1826640000 | `remediation-event-0001`: `REMEDIATION` from `https://security.example/soc` | |
| 15 | 1826640000 | query | `reliability` 5002, 0, 10, 10; `HOLD`, `["security-event-0001"]` |
| 16 | 1826640060 | `remediation-event-0002`: the same remediation from `https://security.example/finance` | |
| 17 | 1826640060 | query | `reliability` 5002, 0, 10, 10; `CLEAR`, `[]` |

`task_quality` and `policy_adherence` are 5000, 0, 0, 0 in every snapshot.

The incident and its remediation concern the task `native-task:invoice-review-0011`. The `SECURITY` report has `result` `FAILURE`, `dimension` `none` and `severity` `high`; it was observed at 1792079990. A hold is independent of the statistical score (Section 15.4), so the report adds no weight to any dimension. It sets the hold that `hold_refs` names by its `event_id`.

Both `REMEDIATION` reports have `result` `SUCCESS` and `dimension` `none`. Each names the hold it clears by its `event_id` in `evidence_refs`, beside the completed remediation record of `native_context.json` (Section 15.4). They were observed at 1826639980, and each is issued at its step's time, so its `signing.json` entry states `iat` and `exp`. The two carry different `event_id`s: a case names each report file by its `event_id`. The two reports also differ in reporter, so they do not share a deduplication tuple (Section 14.6 rule 4).

- Steps 10 and 12: ten units, alpha 10.49859757, beta 1: `score_bps` 9130 (exact 9130.33), `confidence_bps` 3220 (exact 3220.02). The hold leaves the statistics as they are.
- Step 13: 400 days are 13.33 half-lives, so alpha is 1.00092029: `score_bps` 5002 (exact 5002.30), `confidence_bps` 0 (exact 0.46). The statistics have decayed. The hold has not: a hold cannot decay away (Section 15.4), and data decay may not erase it (Section 16.5). The decayed score is not the cold start; 5002 is two basis points from 5000, beyond the tolerance.
- Step 15: the remediation is signed by a security authority that is not one of the learning policy's `hold_clearance_authorities`, so it does not clear the hold (Section 15.4).
- Step 17: the configured clearance authority signs the remediation, which clears the hold: `security_status` `CLEAR`, `hold_refs` empty. Alpha at 1826640060 is 1.00092028; the values are unchanged.

`qualified_event_ids` lists the ten `EXECUTION` reports in every snapshot. The `SECURITY` and `REMEDIATION` reports have no weight in any dimension, so they are not listed (Section 15.2); `hold_refs` is how the snapshot attributes the hold. The case asserts no acknowledgment and no qualification for the remediation from `https://security.example/soc`: the draft fixes only that it does not clear the hold.

Expected file: `expected/reputation/security-hold-no-decay/snapshot.json`; manifest outcome `MATCH`.
