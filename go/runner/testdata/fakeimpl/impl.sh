#!/bin/sh
# Fake implementation of the pactc adapter contract, driven by golden files.
#
#   impl.sh evaluate <dir> [<state>]  print the response to the evaluation case;
#                                     with a state path, keep what it printed there
#   impl.sh receipt <state> <id>      print the receipt with the jti <id> that the
#                                     evaluate run of that state printed
#   impl.sh outcomes <dir> <state>    print the outcomes result of the case
#   impl.sh learning <dir> <state>    print the registry state of the case
#   impl.sh schema <dir>              print the result of the schema case
#
# The response to a case is golden/<id>/<verb>.out, where <id> is the
# manifest id whose path ends <dir>. FAKEIMPL_MODE picks the behaviour:
#
#   good            print the golden response (default)
#   wrong-decision  print golden/<id>/<verb>.wrong-decision.out instead: a
#                   validly signed receipt with another decision
#   swapped-order   print golden/<id>/<verb>.swapped-order.out instead: the
#                   lines of a multi-line response in another order
#   problem         print golden/<id>/<verb>.problem.out: a Problem where a receipt
#                   is expected
#   receipt-for-rejected
#                   print a validly signed receipt for a request that the draft
#                   rejects before an authenticated evaluation (draft 12.2)
#   bad-signature, bad-typ, bad-aud, bad-sub, bad-holder-jkt, bad-digest,
#   bad-exp, bad-terminal-reason, bad-check-result, bad-reason-code,
#   missing-check, absent-check-present, bad-evidence-ids, bad-source-ref,
#   two-admissible, alg-eddsa, ed25519-unnegotiated, omit-context-check,
#   unperformed-check-passed
#                   print golden/<id>/<verb>.<mode>.out: the good receipt of the
#                   case with that one defect. Only the cases that have such a
#                   file differ; every other case prints its good golden.
#                   mutants_test.go states each defect and checks the file;
#                   ed25519_test.go those of alg-eddsa (alg EdDSA with a valid
#                   Ed25519 signature) and ed25519-unnegotiated (an Ed25519
#                   receipt from a gateway that publishes ES256 only).
#   wrong-state, context-not-activated, accepts-gate-not-met, wrong-reason-code,
#   accepts-self-evaluated, accepts-concurrent-promotion, duplicate-as-new,
#   accepts-mutated-manifest, wrong-conflict-code, accepts-expired-policy,
#   refuses-freeze-after-expiry, accepts-incompatible-fallback,
#   rollback-clears-hold, no-reevaluation, correction-resets-state,
#   installs-policy-without-gate, accepts-out-of-envelope, observe-activates,
#   obeys-assessment, retired-stays-active, frozen-cannot-reevaluate,
#   revision-keeps-parent
#                   learning only: print golden/learning/<case>/learning.<mode>.out,
#                   the registry state of the case with that one defect. Only the
#                   one case a mode breaks differs; every other learning case
#                   prints its good golden. learning_golden_test.go states each
#                   defect and checks the file.
#   double-counts-duplicate, transfers-context, hold-decays,
#   unauthorized-clears-hold, admission-raises-reputation, value-off-2bp,
#   value-off-1bp, bad-snapshot-signature, unsigned-snapshot,
#   accepts-self-praise, bad-provenance-digest, no-classifications,
#   qualifies-executor-mismatch, counts-executor-mismatch
#                   outcomes only: print golden/<id>/outcomes.<mode>.out, the
#                   outcomes result of the case with that one defect. Only the
#                   one case a mode breaks differs; every other outcomes case
#                   prints its good golden. value-off-1bp stays within the one
#                   basis point of tolerance and no-classifications only omits
#                   what the runner then skips, so both pass.
#                   outcomes_golden_test.go states each defect and checks the
#                   file.
#   pending-inadmissible, chat-approval-honored, reputation-waives-approval,
#   reused-jti, weaker-set-kept, omit-snapshot-jti, fallback-executor-admitted,
#   fallback-executor-passes, ignores-capability
#                   as the modes above: the good receipt of the one case that
#                   has a golden/<id>/evaluate.<mode>.out, with one defect
#   selection-source-configured
#                   as the modes above, for each selection case that has a
#                   golden/<id>/evaluate.<mode>.out: the checks
#                   reputation-context and selection-consistency-v1 that its
#                   expected result does not list name a configured validation
#                   record in source_ref, not the selection record
#   reopen-first-receipt
#                   print golden/<id>/receipt.reopen-first-receipt.out for every
#                   receipt query of the case that has it: the receipt of the
#                   later exchange, which has taken the place of the first
#   flip-flop       print the good golden the first time a case is evaluated and
#                   golden/<id>/evaluate.flip-flop.out, where there is one, every
#                   time after. FAKEIMPL_COUNTER names a directory that holds the
#                   count of each case
#   ignores-profile-disclosure
#                   print the good golden of every case, as good does, but
#                   disclose no conformance profile: an implementation that
#                   answers every case and ignores the profile it runs under.
#                   No committed entry lists single-owner yet, so a
#                   single-owner run selects nothing and is never green
#                   (profile_test.go); the single-owner fixtures that check
#                   the disclosure turn this mode red
#   schema-accepts-all, schema-wrong-code, schema-rejects-valid,
#   schema-altered-object
#                   schema only: print golden/<id>/schema.<mode>.out, the lines
#                   of the schema case with that one defect: the decoded payload
#                   of the rejected parse/appendix-c-wrong-version as if accepted,
#                   INVALID_PROOF for its INVALID_MESSAGE, a Problem for the B.5
#                   object of schema/appendix-b-valid, and its B.9 object with exp
#                   raised by one. schemaverb_test.go states each defect
#   no-receipt      exit 0 and print nothing
#   crash           print a message on stderr and exit 70, printing nothing
#
# The golden receipts are compact pact-admission+jwt JWS signed with the
# validator test key (spec/v1.0/fixtures/keys/validator.jwk.json, P-256 scalar 6).
# The payload of admission/valid is the Appendix B.7 receipt with the
# requirements_digest of expected/admission/valid/decision.json. The payload
# of every other admission case is that receipt with its own jti, the claims
# of its decision.json, and the results and reason codes of the checks that
# file lists. reputation-context of every evaluate case outside the selection
# group carries the Appendix B selection record,
# configured-selection-record:example-selection, as source_ref. A case rejected before an authenticated evaluation gets a
# Problem object with the expected transport_code instead. An admission case
# with an exchange.json prints one such line per expected response, then
# {"handoff":"accepted"} or a Problem per handoff attempt.
# The receipt of an approval case carries the decision, the receipt claims
# and the native-approval-v1 result of its expected/approval/<case>/decision.json,
# and an exp of iat + 60. A multi-exchange approval case prints one such
# receipt per exchange, from expected/approval/<case>/exchanges/<n>/decision.json.
# The receipt of a delegation evaluation case is built the same way from its
# expected/delegation/<case>/decision.json, with the check
# execution-identity-v1 after the 20 checks of B.7.
# The receipt of a selection case carries the claims of its
# expected/selection/<case>/decision.json, an exp of exp_max, and one check
# per check of its contract, with the result and reason code that file lists
# and PASS otherwise; reputation-context and selection-consistency-v1 carry
# the record_ref of the case's selection record as source_ref.
# The schema goldens are the lines of the schema case (spec/v1.0/fixtures/README.md,
# Runner contract, Schema): for a REJECTED case such as
# parse/appendix-c-wrong-version, one Problem INVALID_MESSAGE of its expected
# decision.json per document; for an ACCEPTED case such as
# schema/appendix-b-valid, each object as compact JSON, one per line.
# The outcomes goldens are the outcomes result object of the case
# (spec/v1.0/fixtures/README.md, section Outcomes output): the reference oracle's
# replay of the case, each snapshot signed with the reputation-service test
# key (P-256 scalar 4), computed by outcomes_golden_test.go.
# The learning goldens are the registry state JSON of the case (spec/v1.0/fixtures/README.md,
# section Learning output), computed from its expected registry.json by
# learning_golden_test.go.
# The v2/ goldens answer the synthetic format v2 cases of testdata/fixtures-v2:
# one line per response and per handoff attempt, each line a golden receipt
# above, a Problem, or {"handoff":"accepted"}.
# The ed25519/ goldens answer the synthetic case of testdata/fixtures-ed25519,
# which negotiates Ed25519 (draft 7.2) by listing it in gateway.jws_algorithms
# and naming the Ed25519 test key as its validator key: the admission/valid
# receipt signed with that key, alg Ed25519 (RFC 9864).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
golden="$here/golden"
mode="${FAKEIMPL_MODE:-good}"

usage() {
  echo "usage: impl.sh evaluate|schema <dir> [<state>] | impl.sh outcomes|learning <dir> <state> | impl.sh receipt <state> <id>" >&2
  exit 2
}

# case_of prints the id of the golden case whose directory ends <dir>. A
# single-file fixture matches with its extension dropped.
case_of() {
  dir=${1%/}
  for id in $(cd "$golden" && find . -type f -name '*.out' | sed 's|^\./||; s|/[^/]*$||' | sort -u); do
    case "$dir" in
    */"$id" | */"$id".*)
      echo "$id"
      return 0
      ;;
    esac
  done
  return 1
}

[ $# -ge 2 ] || usage
verb=$1 dir=$2
case "$verb" in
evaluate) [ $# -le 3 ] || usage ;;
schema) [ $# -eq 2 ] || usage ;;
outcomes | learning | receipt) [ $# -eq 3 ] || usage ;;
*)
  echo "impl.sh: unknown verb: $verb" >&2
  exit 2
  ;;
esac

case "$mode" in
good | wrong-decision | swapped-order | problem | receipt-for-rejected | bad-signature | bad-typ | bad-aud | bad-sub | bad-holder-jkt | bad-digest | bad-exp | bad-terminal-reason | bad-check-result | bad-reason-code | missing-check | absent-check-present | bad-evidence-ids | bad-source-ref | two-admissible | alg-eddsa | ed25519-unnegotiated | omit-context-check | unperformed-check-passed) ;;
pending-inadmissible | chat-approval-honored | reputation-waives-approval | reused-jti | weaker-set-kept | omit-snapshot-jti | fallback-executor-admitted | fallback-executor-passes | ignores-capability | selection-source-configured | reopen-first-receipt | flip-flop) ;;
schema-accepts-all | schema-wrong-code | schema-rejects-valid | schema-altered-object) ;;
ignores-profile-disclosure) mode=good ;;
no-receipt) exit 0 ;;
crash)
  echo "impl.sh: crash mode: aborting before any output" >&2
  exit 70
  ;;
*)
  # A bad learning or outcomes mode is named by its golden files.
  if [ -z "$(find "$golden" \( -name "learning.$mode.out" -o -name "outcomes.$mode.out" \) 2>/dev/null | head -n 1)" ]; then
    echo "impl.sh: unknown FAKEIMPL_MODE: $mode" >&2
    exit 2
  fi
  ;;
esac

# jti_of prints the jti of a compact receipt.
jti_of() {
  p=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
  while [ $((${#p} % 4)) -ne 0 ]; do p="$p="; done
  printf '%s' "$p" | base64 -d 2>/dev/null | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p'
}

if [ "$verb" = receipt ]; then
  # impl.sh receipt <state> <id>: the state holds the id of the golden case and
  # the lines the evaluate run printed.
  state=$dir want=$3
  [ -f "$state/case" ] || {
    echo "impl.sh: no evaluate run in state $state" >&2
    exit 2
  }
  id=$(cat "$state/case")
  if [ "$mode" = reopen-first-receipt ] && [ -f "$golden/$id/receipt.$mode.out" ]; then
    cat "$golden/$id/receipt.$mode.out"
    exit 0
  fi
  while IFS= read -r line; do
    [ "$(jti_of "$line")" = "$want" ] && {
      printf '%s\n' "$line"
      exit 0
    }
  done <"$state/receipts"
  echo "impl.sh: no receipt $want in state $state" >&2
  exit 1
fi

id=$(case_of "$dir") || {
  echo "impl.sh: no golden response for $dir" >&2
  exit 2
}
if [ "$mode" = flip-flop ]; then
  [ -n "${FAKEIMPL_COUNTER:-}" ] || {
    echo "impl.sh: flip-flop mode needs FAKEIMPL_COUNTER" >&2
    exit 2
  }
  count="$FAKEIMPL_COUNTER/$(echo "$id" | tr / _)"
  n=0
  [ -f "$count" ] && n=$(cat "$count")
  echo $((n + 1)) >"$count"
  [ "$n" -eq 0 ] && mode=good
fi
out="$golden/$id/$verb.out"
if [ "$mode" != good ] && [ -f "$golden/$id/$verb.$mode.out" ]; then
  out="$golden/$id/$verb.$mode.out"
fi
[ -f "$out" ] || {
  echo "impl.sh: no golden $verb response for $id" >&2
  exit 2
}
if [ "$verb" = evaluate ] && [ $# -eq 3 ]; then
  # Keep what is printed, for a later receipt query.
  mkdir -p "$3"
  echo "$id" >"$3/case"
  cp "$out" "$3/receipts"
fi
cat "$out"
