# Reputation fixtures

The `reputation` group holds the scoring vectors of `beta-decay-v1` and three scenario cases for the reputation service: context scoping and security holds. The vectors are registered in [`../manifest.json`](../manifest.json) with kind `vector` and scope `runner`. The scenario cases are outcomes cases (kind `outcomes`, scope `runner`) in the format of [../README.md](../README.md), section Format v2, Outcomes cases; the runner verb is `outcomes`.

| Id | Content | Draft section | Spec map row | Manifest outcome |
|---|---|---|---|---|
| `reputation/beta-decay-v1` | Scoring vectors, [beta-decay-v1/README.md](beta-decay-v1/README.md) | 15.3 | CL-15.3 | `MATCH` |
| `reputation/context-no-transfer` | A history in one context gives no reputation in an unrelated one, [context-no-transfer/README.md](context-no-transfer/README.md) | 15.1 | R16 | `MATCH` |
| `reputation/security-hold-no-decay` | A hold survives decay and an unauthorized remediation, and an authorized one clears it, [security-hold-no-decay/README.md](security-hold-no-decay/README.md) | 15.4 | R17 | `MATCH` |
| `reputation/hold-survives-correction` | A correction of a confirmed incident leaves its hold, and only a clearance authority's remediation clears it, [hold-survives-correction/README.md](hold-survives-correction/README.md) | 15.4 | R17 | `MATCH` |

## Scenario cases

The cases use the common setup of [../outcomes/qualification/README.md](../outcomes/qualification/README.md): the B.9 data policy, the reputation service `https://reputation.example/finance`, `visibility` `execution`, `now` 1792080000, and the agent `https://identity.example/agents/invoice-assistant` of operator `https://identity.example/operators/acme` under the holder test key. The history is a run of `EXECUTION` `SUCCESS` reports on `reliability` from the resource service `https://executor.example/finance`, signed with the `executor` key. Each report covers its own native task, `native-task:invoice-review-<n>`, with its own independence group, so each contributes one positive unit (Section 15.3). Every report cites a completed execution record of `native_context.json` that names the executor class `config.json`'s `executor_classes` declares (Section 14.2). Every query is for that agent and holder key, for the audience `https://gateway.example/finance`.

The history is in the B.8 context: purpose `https://policies.example/purposes/invoice-summary/v1`, `action_class` `invoice.read`, `resource_class` `department-finance-invoice`. The cases take it and every other context they name to be administrator-approved contexts of the deployment (Section 15.1).

No case has a `classifications.json`: each is judged by its snapshots, and the entry's `expected` is `snapshot.json`.

## Expected snapshots

The values follow `beta-decay-v1` (Section 15.3) at the query's `now`, computed from the draft with IEEE 754 binary64 and the floor operation, not from an implementation. A success observed `s` seconds before `t` weighs 2^(-s/2592000). A dimension with no listed report has alpha = beta = 1: `score_bps` 5000, `confidence_bps` 0, `independent_tasks` 0 and `qualified_events` 0. Each case README gives alpha and the results.

A harness compares `score_bps` and `confidence_bps` within one basis point, the recomputation tolerance of Section 15.3, and every other member exactly. No expected value lies within one basis point of a floor boundary. Each snapshot's `value` names the queried context and the B.6 scoring pins, and its `claims` carry the service's `iss` and the query's `sub`, `aud` and `holder_jkt`. `provenance` lists the qualified reports with nonzero weight, sorted by `iss` and then `jti` (Section 15.2).
