# context-no-transfer

Row `R16` of the spec map; draft Sections 15.1 and 15.5. Adversarial claim: a strong history in one resource and action context carries over into an unrelated context. The common setup is in [../README.md](../README.md).

1. Steps 0 to 11 ingest twelve `EXECUTION` `SUCCESS` reports on `reliability`, `execution-event-0001` to `execution-event-0012`, all in the invoice context (`action_class` `invoice.read`, `resource_class` `department-finance-invoice`). Each is issued at 1792080000 and received then; report `n` was observed `20 + 43200 (n - 1)` seconds earlier, the oldest about 5.5 days, inside the 7-day ingestion window (Section 14.3).
2. Step 12 queries the invoice context at 1792080000. Twelve units: alpha 12.27015269, beta 1, so `reliability` `score_bps` 9246 (exact 9246.43), `confidence_bps` 3604 (exact 3604.12), `independent_tasks` 12, `qualified_events` 12, with all twelve reports in `qualified_event_ids`. `task_quality` and `policy_adherence` have no reports: 5000, 0.
3. Step 13 queries the payment-approval context of the same tenant, environment, agent, purpose and runtime (`action_class` `payment.approve`, `resource_class` `department-finance-payment`) at the same time. The baseline transfers no positive evidence between contexts (Section 15.1), so every dimension is the empty history of Section 15.3: 5000, 0, 0 tasks, 0 events, and `qualified_event_ids` is empty. No report of the invoice context contributes.

Expected file: `expected/reputation/context-no-transfer/snapshot.json`; manifest outcome `MATCH`.
