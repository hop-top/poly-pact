# beta-decay-v1 scoring vectors

`vectors.json` pins the baseline scoring model `beta-decay-v1` of draft Section 15.3. Its manifest entry is `reputation/beta-decay-v1`, of kind `vector` and scope `runner`; the file carries its expectations inline.

## Formula

Draft Section 15.3, for one dimension at evaluation time `t` (Unix seconds):

```text
alpha            = 1 + sum(w_i * 2 ** (-(t - observed_at_i) / 2592000))   over qualified successes
beta             = 1 + sum(w_i * 2 ** (-(t - observed_at_i) / 2592000))   over qualified failures
score_bps        = floor(10000 * alpha / (alpha + beta))
effective_weight = alpha + beta - 2
confidence_bps   = floor(10000 * effective_weight / (effective_weight + 20))
```

The half-life is 30 days (2592000 seconds). Empty history gives score 5000 and confidence 0. `UNKNOWN` and `NOT_APPLICABLE` contribute zero weight. A success weighs at most one unit, the cap for one independent task group in one dimension. A failure weighs 1, or up to 5 under an approved severity rule. The draft requires at least IEEE 754 binary64 precision and the floor operation as stated.

## File format

`vectors.json` is a JSON array. Every element has exactly these members:

| Member | Value |
|---|---|
| `id` | Name of the vector, unique in the file. |
| `dimension` | The dimension that `expected` describes: `reliability`, `task_quality` or `policy_adherence`. |
| `events` | The scoring inputs, each `{observed_at, result, weight, dimension}`. `result` and `dimension` take the `OutcomeReport` values of draft Section 14.1. |
| `t` | The evaluation time, Unix seconds. |
| `expected` | `{score_bps, confidence_bps}` for `dimension` at `t`. |
| `note` | What the vector shows, for readers. |

The events are what the scorer sees after qualification and deduplication (draft Section 14.3): each one is a qualified event of a distinct independent task group. An event counts only when its `dimension` equals the vector's `dimension` and its `result` is `SUCCESS` or `FAILURE`. Following draft Appendix A.2, an `UNKNOWN` event uses dimension `none`.

## Expected values and tolerance

Each expected value applies the formula in binary64, summing the events in array order, and then floors. A 60-digit decimal computation of the same formula gives the same integer for every vector, so each expected value is also the floor of the exact value.

A harness compares `score_bps` and `confidence_bps` with one basis point of tolerance, as draft Section 15.3 recommends for recomputation. The floor-boundary vectors lie close to an integer: `floor-confidence-below-5000` and `floor-score-below-8000` are less than 0.001 bp below one, and `floor-score-exact-7500-decayed` is exactly on one. Rounding to nearest instead of flooring gets the first two wrong by one; summing in another order can move the third by one. The other vectors have no such margin issue.

## Appendix B.6

Three vectors reproduce the dimensions of the snapshot in draft Appendix B.6. All its events are observed at `t`, so nothing decays.

| Vector | Events | `alpha`, `beta` | Score | Confidence |
|---|---|---|---|---|
| `b6-reliability` | 24 successes, 1 failure | 25, 2 | `floor(250000 / 27)` = 9259 | `floor(250000 / 45)` = 5555 |
| `b6-task-quality` | 17 successes, 1 failure | 18, 2 | `floor(180000 / 20)` = 9000 | `floor(180000 / 38)` = 4736 |
| `b6-policy-adherence` | 6 successes | 7, 1 | `floor(70000 / 8)` = 8750 | `floor(60000 / 26)` = 2307 |

The effective weight of each equals the `qualified_events` and `independent_tasks` that B.6 prints (25, 18 and 6), and with unit weights at `t` only the success and failure split above gives the printed scores.
