// Package source is the shared shape of a membership or status source that
// is not an adapter: an integration that operates the receiving end of a
// protocol the identity system pushes, such as a SCIM 2.0 service provider,
// a directory push channel or a Shared Signals receiver, and answers the
// draft 17.1 function read_native_claim from the state it was pushed.
//
// A source is three parts. A receiver, in a subpackage per protocol, accepts
// the pushed messages, which are the source's change feed, and writes the
// last pushed state of each principal into a [Store]. A [Reader] is the
// [adapter.ClaimReader] over that store. [Join] is the identity rule that
// joins a pushed record, which names no principal, to one.
//
// # Times
//
// A pushed store is a replicated directory in the sense of the freshness
// profile (spec/v1.0/profiles/freshness.md, section 4.1): what it answers is the
// state as of the last push. A [Fact] carries the as-of time when the push
// gives one, such as the event time of a security event; the Reader then
// reports it unchanged. A push protocol that carries no as-of time, such as
// SCIM, gives none, and the Reader reports the read time minus the declared
// push lag for both the observation and the status time (freshness profile,
// section 4.2, convention 1). It never reports the read time itself, and it
// never restamps a cached fact (draft 8.3, 17.2).
//
// # Errors
//
// A path the reader does not serve is [adapter.ErrUnsupportedRequirement]. A
// principal the store holds no value for, including one whose record was
// deleted, is [adapter.ErrMissingField]: the fact is absent, and an absent
// value fails the rule that requires it (draft 9.2). A store that cannot
// answer, and a source time later than now plus the skew, are
// [adapter.ErrDependencyUnavailable] (draft 18, A.2).
//
// The package needs no change-event model: every draft consumer of a
// membership or status change reads at a check point, so the pushed state is
// what it reads.
package source
