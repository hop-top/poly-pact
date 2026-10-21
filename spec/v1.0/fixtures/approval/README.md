# Approval cases

Evaluation cases for row `CL-17.3.1` of the [conformance map](../../spec-map.md): the native state of an approval, as an approval-class check establishes it, mapped to a check result, an admission decision and a reason code by the table of [draft Section 17.3.1](../../draft.md#1731-approval-exception-and-activation-check-results). The files of a case follow [../README.md](../README.md).

## Common setup

Every case is the exchange of [admission/valid](../admission/valid) (draft Appendix B) with two changes:

- `config.json` installs the check `native-approval-v1`, and `contract.json` names it in `context_checks` after the four B.4 checks. It is the approval-class check of these cases: it reads the native approval of `native_context.json` and returns the result that Section 17.3.1 assigns to its state.
- The native approval has its own reference, `native-approval:inv-1042-supervisor-review`, bound to the agent, principal, purpose and task of the exchange. It is distinct from the delegation reference of B.1, so the delegation and the `supervisor-approval` field rule of B.4 pass in every case and only the approval-class check varies.

Each case, and each exchange of a multi-exchange case, has its own contract `jti`, `contract_id` and `nonce`, and its own presentation `jti`, which the receipt carries as `presentation_id`. The evidence and the reputation snapshot are those of B.5 and B.6, except in `mandatory-survives-high-reputation` and in the second exchanges below.

`native_context.json` writes the approval state in lower case. `pending` means that the adapter has established that a legitimate request exists for this exact scope and is undecided. `unavailable` means that the approval status source could not be reached, so `status_checked_at` is `null`. A `null` approval means that no approval and no approval request exists for the exchange: the required reference is absent.

An `approved` approval is valid and applicable unless one of the format v2 members ([../README.md](../README.md), section native_context.json additions) shows otherwise: `approver_authority` whose `required_role` the approver does not hold, an `amount` whose `requested` exceeds `approved`, or `resources` that do not cover every resource of `actual_operation.json`. The approver then lacks authority, or the approval's scope does not cover the request, and the check fails although the native state is `approved`.

## Expected results

`decision.json` lists the 20 checks of B.7, all `PASS` with `REQUIREMENT_SATISFIED`, then `native-approval-v1` with the result of the table below. Every evaluation completes, so the receipt's `terminal_reason` is `COMPLETED`. `executed` is `true` only for an `ADMISSIBLE` decision under a native allow (`authorize` `true`); for every other decision native authorization is never reached (Section 11.4).

| Case | Adversarial claim | Native approval | `native-approval-v1` | Decision | Draft |
|---|---|---|---|---|---|
| `pending-established-request` | An approval that has been requested is as good as granted. | `pending` | `UNKNOWN`, `APPROVAL_PENDING` | `DEFERRED` | 17.3.1, 12.2, B.12 step 1 |
| `rejected` | A rejected approval is still pending and may be retried as if undecided. | `rejected` | `FAIL`, `APPROVAL_REJECTED` | `INADMISSIBLE` | 17.3.1, 11.4, B.12 step 6 |
| `expired` | An approval that was valid once still covers the request. | `expired` | `FAIL`, `APPROVAL_EXPIRED` | `INADMISSIBLE` | 17.3.1, 11.4 |
| `revoked` | A revoked approval still covers the request. | `revoked` | `FAIL`, `APPROVAL_REVOKED` | `INADMISSIBLE` | 17.3.1, 11.4 |
| `status-unavailable` | When the approval service cannot be reached, the request may proceed. | `unavailable` | `UNKNOWN`, `DEPENDENCY_UNAVAILABLE` | `DEFERRED` | 17.3.1, 18 |
| `missing-reference` | With no approval request at all, the case is merely pending. | `null` | `FAIL`, `MISSING_FIELD` | `INADMISSIBLE` | 17.3.1, B.12 step 1 |
| `chat-says-approved` | A statement in the conversation that the user approved is approval evidence. The profile carries the self-asserted attribute `/attributes/approvals/supervisor` with status `approved` and source `chat`. | `null` | `FAIL`, `MISSING_FIELD` | `INADMISSIBLE` | 17.3, 9.2, 17.3.1 |
| `wrong-approver-authority` | Any decided approval is valid, whoever decided it. Here a finance manager approved a scope that requires the role `finance-supervisor`. | `approved`, `approver_authority` without the required role | `FAIL`, `APPROVAL_AUTHORITY_MISMATCH` | `INADMISSIBLE` | 17.3.1, 17.3 |
| `wrong-scope-amount` | An approval for a smaller amount covers a larger one: CAD 12000 requested under an approval for CAD 9000 (example U06). | `approved`, `amount` 9000 approved, 12000 requested | `FAIL`, `APPROVAL_SCOPE_MISMATCH` | `INADMISSIBLE` | 17.3.1, 17.3 |
| `wrong-scope-resource` | An approval for one resource covers another of the same kind: another service (example U07) or another VM (example I14). The approval covers `INV-1043`; the request reads `INV-1042`. | `approved`, `resources` without the requested resource | `FAIL`, `APPROVAL_SCOPE_MISMATCH` | `INADMISSIBLE` | 17.3.1, 10.2 |
| `mandatory-survives-high-reputation` | A high reputation waives a mandatory approval. The snapshot has `score_bps` 9900 and `confidence_bps` 9000 in every dimension. | `pending` | `UNKNOWN`, `APPROVAL_PENDING` | `DEFERRED` | 17.3.1, 15.5, 16.2 |
| `approved-fresh-exchange` | An approval granted after a `DEFERRED` evaluation reopens or converts that receipt. Two exchanges. | `pending`, then `approved` | `UNKNOWN`, `APPROVAL_PENDING`, then `PASS`, `REQUIREMENT_SATISFIED` | `DEFERRED`, then `ADMISSIBLE` | 12.2, B.12, 17.3.1 |
| `exception-recognized-natively` | A native exception has to show in the PACT decision, or a PACT `ADMISSIBLE` lets the operation run past a native denial. Two exchanges; `authorize` is `false`, then `true` (example U07). | `approved`, both times | `PASS`, `REQUIREMENT_SATISFIED`, both times | `ADMISSIBLE`, both times | 17.3, 17.3.1, 11.4 |

In `chat-says-approved` no field rule names `/attributes/approvals`, and Section 9.2 prohibits source `self` for approval, so the self-asserted attribute satisfies nothing. Only its `profile_digest` differs from `missing-reference`, whose result it must equal.

### Scope and authority

The three cases of an `approved` approval that does not cover the request use the format v2 approval members. Every other member of the approval is that of the common setup, bound to the agent, principal, purpose and task of the exchange. In `wrong-approver-authority`, `approver_id` names the approver and `approver_authority` records the role the scope requires and the roles the approver holds. In `wrong-scope-amount`, both amounts are CAD decimal strings. In `wrong-scope-resource`, `resources` lists the only resource the approval covers.

### Mandatory approval and reputation

`mandatory-survives-high-reputation` is `pending-established-request` with a stronger reputation snapshot, of its own `jti`: `score_bps` 9900, `confidence_bps` 9000, and 180 independent tasks and qualified events in each dimension. The profile's `/attributes/reputation` is the same value, so the profile digest differs. The values are not derived from a report history: the signed output of the reputation service is authoritative for admission (Section 15.3). The `reputation-context` check passes with the snapshot `jti` in its `evidence_ids` (`evidence_ids_include`), and the approval-class check stays `UNKNOWN` with `APPROVAL_PENDING`, so the decision is `DEFERRED`, as in `pending-established-request`.

The validator applies the contract's effective rules and MUST NOT replace them (Section 11.3, step 9). The contract keeps `native-approval-v1` in `context_checks` and the configuration carries no requirement-set selection, so no snapshot can drop the approval. The rule that an approval requirement of `base_revision` is not in `adaptive_fields` (Section 17.3.1) constrains the learning policy; its cases belong to the learning group.

### Multi-exchange cases

`approved-fresh-exchange` and `exception-recognized-natively` each have a `sequence.json` and two exchanges, `exchanges/1/` and `exchanges/2/`, and the expected result of each exchange is `expected/approval/<case>/exchanges/<n>/decision.json` ([../README.md](../README.md), section Multi-exchange cases). The subject is `exchanges/2`, whose decision is the manifest outcome, `ADMISSIBLE` for both. The evaluate command prints two receipts, one per exchange.

The first exchange is evaluated at 1792080000, like the single-exchange cases. The second is a fresh exchange 30 seconds later, at `now` 1792080030: a new contract (`iat` 1792080030, `exp` 1792080090), a new nonce and a new presentation (`iat` 1792080030). The runtime evidence and the reputation snapshot are reissued at that time with their own `jti` values and an `exp` 300 seconds later, and every native observation and status check of `native_context.json` is at 1792080030. Without that, the B.4 sources would be exactly as old as their 30-second bound, and the case would depend on a boundary that the draft does not settle. The profile, intent and operation are unchanged, so their digests are those of the first exchange.

In `approved-fresh-exchange`, the first exchange is `pending-established-request` with its own identifiers: `DEFERRED` with `APPROVAL_PENDING`. Between the exchanges the approval becomes `approved` in the native system. The second exchange is `ADMISSIBLE` and executes. The first receipt is not reopened, amended or converted: the second exchange produces its own receipt, under a contract, nonce and presentation that differ from the first (Section 12.2, B.12 steps 3 and 4).

In `exception-recognized-natively`, the approval is `approved` in both exchanges, so both PACT evaluations are `ADMISSIBLE` with every check `PASS`. Only `authorize` changes: `false` in the first exchange, which models the native denial before the exception (example U07, operating hours), and `true` in the second, after the exception is granted in the native system. `executed` is `false`, then `true`. The exception is never PACT evidence: it changes only the `authorize_native` result (Section 17.3.1), and a native denial wins over an `ADMISSIBLE` decision (B.12 step 5).
