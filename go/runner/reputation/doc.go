// Package reputation is the reference of the conformance runner for the
// reputation service of draft Sections 14 and 15: an Oracle that ingests
// outcome reports, classifies them under pact-qualification-v1 and
// pact-reporter-independence-v1 (Section 14.6) and answers reputation
// queries with values, a provenance manifest (Section 15.2) and the
// security status of Section 15.4.
//
// The Oracle scores with beta-decay-v1 of package hop.top/pact-go/reputation,
// the library form of the reputation service. The scorer is the formula of
// Section 15.3, pinned by the beta-decay-v1 vectors, which were computed
// independently of any implementation, so it exists once. The Oracle's
// qualification, provenance and holds are its own: the library's are an
// implementation under test, and the two meet only in the expected files.
//
// The tests replay every committed outcomes case through the Oracle and
// check that the expected acknowledgments, classifications and snapshots
// are what the draft computes. The runner judges an implementation against
// the expected files alone; the Oracle and the goldens of the fake
// implementation agree with them.
//
// MatchValue is the comparison of a snapshot's value with an expected one:
// score_bps and confidence_bps within one basis point, every other member
// exactly.
//
// The Oracle follows the draft where it is easy to misread: the cap caps
// the decayed sum of a group's successes at one unit (Section 15.3); a
// signer is the executor of a task for rule 5 when a trust record
// registers it as executor and it reported that task's execution, whichever
// report came first (Section 14.6); a hold is the agent's, in every context
// and under every holder key (Section 15.4). A correction is classified as
// a report of the kind it supersedes, from its signer (rule 10), and a
// gateway's detected policy violation weighs on policy_adherence, never
// holds (rule 12). Each event_kind has the dimensions Section 14.5 gives it,
// any other pair being invalid (Appendix A.2); verified feedback from an
// evaluator or the task owner cites the assessment it conveys; a security
// authority's report holds only as a FAILURE on none citing the confirmed
// incident record of its task and operation, and a correction of it
// leaves the hold in place (Section 15.4).
package reputation
