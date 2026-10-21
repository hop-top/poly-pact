# Selection cases

Evaluation cases for row `CL-9.4` of the [conformance map](../../spec-map.md): the requirement set that a gateway selected for a contract stays consistent between contract issuance and presentation. A changed snapshot, gateway input, hold, policy revision or selector yields a deterministic result, and no case keeps a weaker set after a stricter input. The rules come from [draft Sections 9.3 and 9.4](../../draft.md#93-context-checks), [11.3, step 9](../../draft.md#113-validator-algorithm), [11.4](../../draft.md#114-decisions) and [12.2](../../draft.md#122-state-transitions). Every case uses format v2 of [../README.md](../README.md) (section Format v2, `config.json` member `selection`), and its expected result is `expected/selection/<case>/decision.json`.

## Common setup

Every case is the exchange of [admission/valid](../admission/valid) (draft Appendix B) with these changes:

- Time. The contract is issued, and its set selected, at `1792080000`, the Appendix B time. The newer snapshots below are issued at `1792080005`. The presentation is signed at `1792080010`, which is `config.json`'s `now`, the time of every native observation, status check and authentication in `native_context.json`, and the receipt's `iat`.
- `config.json` installs `selection-consistency-v1` (draft Section 9.3), and the reputation-service trust record may also assert the three reliability paths below.
- `config.json` carries `selection`. Its selector is `finance-selector-v1` (B.9) pinned to the contract's `learning_artifact_digest`, with `order` `["supervised", "established"]`: `supervised` is the policy's `conservative_set` (B.9), and `established` is the weaker set. The set `supervised` has the five field rules of B.4. The set `established` has the same rules without `supervisor-approval`, plus three rules under `/attributes/reputation` (draft Section 9.4 (b)), each of source `evidence`, issuer `https://reputation.example/finance`, `max_age_seconds` 30:

  | Rule | Path | Schema |
  |---|---|---|
  | `reputation-reliability-score` | `/attributes/reputation/dimensions/reliability/score_bps` | `{"minimum":9000,"type":"integer"}` |
  | `reputation-reliability-confidence` | `/attributes/reputation/dimensions/reliability/confidence_bps` | `{"minimum":5000,"type":"integer"}` |
  | `reputation-reliability-tasks` | `/attributes/reputation/dimensions/reliability/independent_tasks` | `{"minimum":20,"type":"integer"}` |

  The `established` threshold is those three minimums and `security_status` `CLEAR`, which the B.4 rule `reputation-status` also requires. The draft sets no numeric threshold (Appendix E); these values are the fixture's, chosen so that the B.6 snapshot meets them with a margin (Section 15.3).
- The contract of every case except `agent-requests-weaker-set` and `conservative-set-no-check` has `selected_set` `established`, the field rules of that set, and `selection-consistency-v1` after the four B.4 checks in `context_checks` (draft Section 9.4 (a)). `active_policy.selected_set` is the contract's set.
- The selection record has the `record_ref` `configured-selection-record:<case>`, the B.4 learning digests, `base_revision` `finance-base-3`, `hold_refs` `[]`, and the `jti` of the snapshot used at issuance: the B.6 snapshot, or `null` in the two cases with a `supervised` contract, where the agent had no snapshot when it asked for the contract, so the selector yielded the conservative set.

Each case has its own contract `jti`, `contract_id` and `nonce`, and its own presentation `jti`, which the receipt carries as `presentation_id`. The runtime evidence is that of B.5. The profile carries the presented snapshot's value at `/attributes/reputation` (draft Section 15.2); a case that presents a newer snapshot has a profile of `revision` 2 created at `1792080005`.

## Snapshots

| Name | `jti` | Issued | Reliability `score_bps` / `confidence_bps` / `independent_tasks` | `security_status` | Meets `established` |
|---|---|---|---|---|---|
| B.6 | `VW7HSF227CWWBU7wN09Q5A` | `1792080000` | 9259 / 5555 / 25 | `CLEAR` | yes |
| newer, eligible | `B4jqsRY111cD8G4fMEzpGQ` | `1792080005` | 9285 / 5652 / 26 | `CLEAR` | yes |
| newer, degraded | `tuGqrHbP7nSDBthOkQBfOA` | `1792080005` | 8800 / 5400 / 22 | `CLEAR` | no: score below 9000 |
| newer, caution | `zpfwLFgQwo8l3LQWwwFHNw` | `1792080005` | 9259 / 5555 / 25 | `CAUTION` | no: status not `CLEAR` |

The newer snapshots keep the other B.6 dimensions. They are signed by the reputation-service key when presented. As the gateway's current input (`selection.current_snapshot`, the file `gateway_snapshot.json`) they are decoded and unsigned: trusted gateway input. Their `provenance_digest` values are placeholders, the SHA-256 of a label: the manifest a provenance digest hashes is not a wire object (draft Section 15.2), and no case depends on it.

`native_context.json`'s `security_holds` lists each hold in force by the `event_id` of its confirmed `SECURITY` report, as a snapshot's `hold_refs` and the record's `hold_refs` do (draft Section 15.4).

## Cases

| Case | Adversarial claim | Change | Expected result | Draft |
|---|---|---|---|---|
| `same-snapshot` | | The agent presents the B.6 snapshot of the record; the gateway's current input is the presented snapshot. | `ADMISSIBLE`; every check `PASS`, `selection-consistency-v1` included | 9.4, 11.3 step 9 |
| `newer-snapshot-still-eligible` | A snapshot other than the one the gateway selected with invalidates the contract. | The agent presents the newer eligible snapshot. | `ADMISSIBLE`; every check `PASS` | 11.3 step 9 |
| `snapshot-degraded-below-rule` | A contract selected while the agent was eligible still admits it after its reputation degraded. | The agent presents the newer degraded snapshot. | `INADMISSIBLE`; `reputation-reliability-score` `FAIL` `INVALID_CLAIM`; `selection-consistency-v1` `FAIL` `SELECTION_INPUT_CHANGED` | 9.2, 11.3 steps 7 and 9, 11.4 |
| `gateway-input-now-stricter` | Only what the agent presents counts; the gateway's newer knowledge does not. | The agent presents the B.6 snapshot; the gateway's current input is the newer caution snapshot. | `DEFERRED`; `selection-consistency-v1` `FAIL` `SELECTION_INPUT_CHANGED`; the reliability rules `PASS` | 11.3 step 9, 11.4 |
| `hold-added-after-issuance` | A hold placed after the contract was issued does not apply to it. | A hold, `security-incident-event-0001`, is in force; the record has none. | `INADMISSIBLE`; `security-hold` and `security-hold-v1` `FAIL` `SECURITY_HOLD`; `selection-consistency-v1` `FAIL` `SELECTION_INPUT_CHANGED` | 9.4, 11.3 steps 9 and 10, 11.4, 15.4, 15.5 |
| `policy-revision-changed` | A contract stays valid after the base policy it pins was replaced. | `active_policy.base_revision` is `finance-base-4`; the contract and the record pin `finance-base-3`. | `DEFERRED`; `active-policy` `FAIL` `REQUIREMENTS_CHANGED` | 9.4, 12.2 |
| `selector-rolled-back` | A contract stays valid after the selector it pins was rolled back. | `active_policy.learning_artifact_digest` is `rzz4zv_9KiTRHF7_aQVAYUILJEYi0VlrBJDdRRgzCzg`, standing in for the fallback selector artifact (the SHA-256 of a label); the contract and the record pin the B.4 digest. | `DEFERRED`; `active-policy` `FAIL` `REQUIREMENTS_CHANGED` | 9.4, 12.2, 16.5 |
| `agent-presents-stale-favorable` | An agent may present an older, favorable snapshot while a newer one exists. | The agent presents the B.6 snapshot; the gateway's current input is the newer degraded snapshot. | `DEFERRED`; `selection-consistency-v1` `FAIL` `SELECTION_INPUT_CHANGED`; the reliability rules `PASS` | 9.4, 11.3 step 9, 11.4 |
| `agent-requests-weaker-set` | The agent may choose a weaker set by editing its contract. | The gateway issued a `supervised` contract (`contract-as-issued.json`); the agent changed its `selected_set` to `established`, replaced its field rules with those of that set and added `selection-consistency-v1`. `signing.json` signs the issued payload with `payload_signed` and embeds the edited one, so the signature does not verify. | Transport `INVALID_PROOF`, no receipt | 9.4, 11.3 step 3, 12.2, 13.4 |
| `conservative-set-no-check` | | The contract has `selected_set` `supervised`, the conservative set, and does not list `selection-consistency-v1`, which the gateway has installed. | `ADMISSIBLE`; the 20 checks of B.7 `PASS`; `selection-consistency-v1` absent | 9.4, 12.1 |

## Reading the expected results

- `selection-consistency-v1` re-derives the set with the contract's pinned selector from the presented snapshot and from the gateway's current input, and fails with `SELECTION_INPUT_CHANGED` when either yields a set earlier in `order` than the contract's (draft Section 11.3, step 9). The selector yields the conservative set while a hold is in force. In `snapshot-degraded-below-rule` and `hold-added-after-issuance` another required check also fails for a reason other than a stale contract, so the decision is `INADMISSIBLE`, not `DEFERRED` (draft Section 11.4).
- Under a contract that a changed base revision or selector has invalidated, the presentation is evaluated, `active-policy` fails with `REQUIREMENTS_CHANGED`, and the decision is `DEFERRED`; the transport error `REQUIREMENTS_CHANGED` is reserved for a sealed contract presented again (draft Section 12.2).
- The checks `reputation-context` and `selection-consistency-v1`, where a case lists them, carry `evidence_ids_include` with the presented snapshot's `jti` and `source_ref` with the record's `record_ref` (draft Appendix A.2). `admission/valid` pins the same two members for the Appendix B record, `configured-selection-record:example-selection` (B.7).
- The `ADMISSIBLE` cases list every check of the contract: the eleven protocol checks of B.7, one per field rule, and one per context check. The other cases list the checks the change fixes, as the admission cases do ([../admission/README.md](../admission/README.md)). Checks whose result the draft leaves open for the change are not listed: in `hold-added-after-issuance`, `active-policy` (Section 9.4 says a relevant hold invalidates outstanding contracts but names no check for it), `reputation-context` and `reputation-status` (the presented snapshot says `CLEAR` while the gateway knows of a hold); in `policy-revision-changed` and `selector-rolled-back`, `selection-consistency-v1`, since the draft does not say whether the base revision or the active selector artifact is an input of the pinned selector.
- `receipt.claims` follow the approval cases; `requirements_digest` is the `artifact_digest` of the case's own `signed/contract.jws` and `profile_digest` the `object_digest` of its `profile.json`. `selector-rolled-back` leaves out `learning_artifact_digest`, which may be the pinned or the active digest. `exp_max` is `1792080060`, the contract's `exp`, for an `ADMISSIBLE` receipt, and `1792080070`, 60 seconds after issuance, otherwise (draft Section 12.1).
- `executed` is `true` only for the `ADMISSIBLE` cases, whose native authorization allows the operation.
