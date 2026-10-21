// Package reputation is the library form of the PACT reputation service
// (draft Sections 14 and 15), for gateways that colocate it. It is standard
// library and hop.top/pact-go packages only.
//
// A [Service] ingests signed OutcomeReports ([Service.Ingest]) and answers
// reputation queries with signed ReputationSnapshots ([Service.Query]):
//
//   - ingestion verifies the report under the keys of its registered signer,
//     decodes it strictly, applies the OutcomeReport schema and the rules of
//     Appendix A.2, the time and context rules of Sections 7.5 and 13.4 and
//     the ingestion window of Section 14.3, and deduplicates by (iss, jti)
//     (Section 7.5) and by the tuple of Section 14.6 rule 4;
//   - qualification follows the baseline pact-qualification-v1 and
//     pact-reporter-independence-v1 of Section 14.6: reporter registration
//     and who may report what (Section 14.2), task reconciliation, the
//     native evidence and executor class of Sections 14.2, 14.5 and 17.5,
//     self-praise, affiliation, reciprocal endorsement, causal assessment,
//     correction, classified as a report of the corrected kind from its
//     signer, and the gateway's detected policy violations
//     ([Service.Classifications]);
//   - a snapshot scores each dimension of the queried context with
//     beta-decay-v1 ([Score], Section 15.3), counts only that context and
//     the holder key the tasks bound, caps the positive weight of an
//     independence group at one unit, never counts admission passes or
//     native decisions, and lists its reports in a [ProvenanceManifest]
//     whose digest the value carries (Section 15.2);
//   - security holds are independent of the score (Section 15.4): a
//     SECURITY FAILURE on none of a registered security authority, citing
//     the confirmed incident record of its task and operation, places one,
//     only a REMEDIATION of a hold clearance authority clears it, and
//     neither time nor a correction lifts it ([Service.Holds]); a
//     gateway's policy violation is a policy_adherence failure and never
//     holds.
//
// Storage and trust are behind interfaces: [Store] keeps the reports and
// the deduplication indexes ([MemoryStore] in memory), [Registry] the
// reporters and their keys ([StaticRegistry]), [Tasks] and [Records] the
// authoritative task and native records, and [Signer] the snapshot key
// ([ES256Signer]).
//
// The scorer exists once: the conformance runner's reference oracle scores
// with it too. It is the formula of Section 15.3, pinned by the
// beta-decay-v1 vectors, which were computed from the draft independently
// of any implementation, so sharing it hides nothing. Qualification,
// provenance and holds are written separately in the oracle and here; the
// tests run the library through the runner's outcomes verb against every
// committed outcomes case, and against the oracle on cases the fixtures do
// not reach.
//
// The package follows the draft where it is easy to misread: the per-group
// cap limits the decayed sum of a group's successes to one unit (Section
// 15.3); a signer is the executor of a task for rule 5 when it is
// registered as executor and reported that task's execution, whichever
// report came first (Section 14.6); each event_kind has the dimensions
// Section 14.5 gives it, any other pair being invalid (Appendix A.2);
// verified feedback from an evaluator or the task owner cites the
// assessment it conveys (Section 14.5); a hold is the agent's, in every
// context and under every holder key (Section 15.4); an identical retry is
// answered DUPLICATE (Section 7.5).
package reputation
