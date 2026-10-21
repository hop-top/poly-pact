// Package freshness evaluates the two age limits of a field rule against a
// [adapter.NativeClaim] (PACT draft Sections 8.3, 9.2, 17.2 and 18).
//
// A field rule bounds two different ages (Section 9.2):
//
//   - max_age_seconds bounds the original source observation,
//     NativeClaim.ObservedAt. It is the time the source gave, never an
//     intermediary's receipt time;
//   - status_max_age_seconds bounds the last confirmation that the value is
//     still in force, NativeClaim.StatusCheckedAt. Zero requires a check made
//     in this evaluation.
//
// The package is one function, [Evaluate]; one type that carries its
// parameters, [Evaluator]; and the guard against re-stamping, [Monotonic].
// Evaluate uses the baseline clock skew. An Evaluator tightens it, says when
// the evaluation began, and attaches a Monotonic guard. The freshness profile
// (spec/v1.0/profiles/freshness.md) defines the vocabulary, the source classes, and
// the check points these rules serve.
//
// # Rules
//
// With now the instant of the evaluation, skew the clock skew allowance (at
// most [clock.BaselineSkew], Section 7.5), and each limit read as whole
// seconds:
//
//   - A time later than now+skew is a source clock that runs ahead. The claim
//     fails with [ClockAhead] (Appendix A.2: no observation or status-check
//     time may be later than now+skew). This outranks every finding but an
//     invalid limit, because a time that cannot be true says nothing about age.
//   - A source that gives no time cannot establish freshness (Section 17.2),
//     and unknown status is not evidence of validity (Section 8.3). The result
//     is UNKNOWN with [UnsupportedRequirement]: the requirement is changed by
//     an authorized publisher or the exchange is deferred. A time before the
//     epoch counts as no time, because it has no wire form.
//   - An age above its limit fails with [StaleEvidence]. The age may equal the
//     limit: now-ObservedAt <= max_age_seconds, the way Section 7.5 phrases
//     its own bounds. The comparison is exact, to the nanosecond, and is not
//     rounded in the claim's favour.
//   - A limit of zero means the time must not precede the start of this
//     evaluation ([Evaluator.Start]). The draft defines zero only for
//     status_max_age_seconds (Section 9.2); this package reads
//     max_age_seconds = 0 the same way, which fails closed.
//   - A limit outside 0..2^53-1 cannot come from a valid contract and no
//     source can satisfy it. The result is UNKNOWN with
//     [UnsupportedRequirement].
//   - With a [Monotonic] guard, a later ObservedAt for a source record already
//     seen is a re-stamp and fails with [Restamped], which is treated as
//     [StaleEvidence].
//
// A demonstrable failure outranks a missing time: a claim already known to be
// stale is FAIL, not UNKNOWN. After an invalid limit, the order of the
// findings is [ClockAhead], [Restamped], [StaleEvidence], then the UNKNOWN
// findings: no usable time ([UnsupportedRequirement]) and a guard that cannot
// record ([DependencyUnavailable]).
//
// # Calling it
//
// The evaluator does not read a clock. The caller passes now, normally from a
// [clock.Clock], so a test drives it with [clock.Fake]. To honour a zero
// limit the caller also gives the instant the evaluation began, taken before
// any source was read for it. Without Start, the instant now stands in for it,
// which suits a caller that reads now immediately before it reads the source.
//
// Evaluate reads only the two age limits. A self rule has none (Appendix
// A.2) and is not evaluated here.
package freshness
