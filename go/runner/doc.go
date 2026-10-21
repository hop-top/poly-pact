// Package runner is the PACT conformance runner: it drives an implementation
// under test, written in any language, through the adapter contract and
// compares what it returns with the conformance fixtures of spec/v1.0/fixtures.
// Command pactc is its command-line front end; nothing of the implementation
// is imported or linked.
//
// # Adapter contract
//
// The implementation is reached through commands given as argv templates,
// one per verb. [BuildArgv] splits a template on white space and then
// replaces {dir}, {state} and {id} inside each argument; no shell is
// involved, so quotes, pipes and globs are passed on literally. A
// substituted value stays one argument even when it has white space in it.
//
//   - evaluate, "tool evaluate {dir} {state}", {state} optional: stdin
//     none; stdout is the compact pact-admission+jwt receipt of the
//     evaluation, or an RFC 9457 Problem JSON object (draft Section 13.4)
//     when the request is rejected before an authenticated evaluation
//     (draft Section 12.2). A format v2 case with
//     several submissions, handoff attempts or exchanges prints one such
//     response per line, and {"handoff":"accepted"} or a Problem for each
//     handoff attempt.
//   - receipt, "tool receipt {state} {id}", optional: stdout is the compact
//     receipt whose jti is {id}, as the evaluate command of the same case
//     recorded it. The evaluate template may also name {state}: both commands
//     get the same {state} for the entry, so the gateway state of a
//     multi-exchange case can carry over to the query.
//   - outcomes, "tool outcomes {dir} {state}": run the ingestions and
//     queries of the case; stdout is the outcomes result object: the answer
//     to each ingestion, and the signed ReputationSnapshot and provenance
//     manifest of each query.
//   - learning, "tool learning {dir} {state}": apply the policy and events of
//     the case; stdout is the registry state JSON.
//   - schema, "tool schema {dir}", optional: stdout is one line per document
//     of the schema case (spec/v1.0/fixtures/schema/README.md): the decoded
//     object the implementation accepts, as JSON, or a Problem for one it
//     rejects.
//
// {dir} is the absolute path of the entry's fixture: its case directory, or
// for a schema entry its file. A
// verb that keeps state gets {state}, a scratch path of its own for the case
// that does not exist yet; the implementation may create a file or a
// directory there. The evaluate and receipt commands of one entry share their
// {state}.
//
// A verb whose command is not given is SKIP for every entry, never FAIL. An
// entry whose manifest capabilities the implementation does not declare
// (Config.Capabilities, pactc run --capability) is SKIP with the missing
// capabilities, never PASS: it tests an optional feature, applicable only to
// an implementation that has it (draft 22.2). A run has one conformance
// profile (Config.Profile, default full) and one or more transports
// (Config.Transport, default https); only the entries that list the profile
// and share a transport with the run are selected, and the others are
// counted as not applicable in [Report.ByProfile], never run and never PASS
// (spec/v1.0/fixtures/README.md, Manifest entry fields). The report lists
// the roles the profile claims, [RolesClaimed]. The exit status of an
// evaluate, outcomes or learning command is informational, as the response
// on stdout is what is judged: a command that prints neither a receipt nor a
// Problem, no outcomes result or no registry state fails, whatever its exit
// status.
//
// # Fixture selection
//
// [Run] reads manifest.json from the fixture directory with package
// [hop.top/pact-go/runner/manifest] and runs only the entries whose kind a verb
// handles (evaluate, outcomes, learning, schema), in manifest order.
// [Config.Fixtures] selects entries by manifest id or id prefix, such as
// "admission/". The runner never walks the tree to find cases: it checks
// the manifest against the fixture directory, and a file no entry covers
// makes the manifest check FAIL as [RuleManifestIncomplete].
//
// # Checks
//
// evaluate reads the case with package [hop.top/pact-go/runner/evalcase] and
// compares each line the command prints with the entry's expected
// decision.json (spec/v1.0/fixtures/README.md). A case whose expected file names a
// transport_code needs a Problem with that code and no receipt (draft 12.2,
// 13.4). Otherwise the line must be a compact JWS of typ pact-admission+jwt
// with the expected decision, and every difference from the expected result
// is a detail of the FAIL:
//
//   - the signature verifies under the public key of receipt.signer, else
//     config.json validator.key, with the receipt's kid in that key set; its
//     alg is listed in config.json gateway.jws_algorithms, the algorithms
//     the gateway publishes (draft 13.1, A.3; ES256 alone by default), and
//     is the algorithm of that key (draft 7.2): ES256 for a P-256 key, the
//     baseline, and Ed25519 (RFC 9864) for an OKP Ed25519 key (RFC 8037); a
//     case negotiates Ed25519 by listing it and naming such a key; the EdDSA
//     identifier never passes; a case that names no key fails, as a receipt
//     is never accepted unverified;
//   - each member of receipt.claims is in the payload with the same JSON
//     value (RFC 8785 canonical form), and the payload is an
//     AdmissionAttestation (unknown members are rejected, draft 7.1);
//   - profile_digest and intent_digest are the object_digest of profile.json
//     and intent.json, requirements_digest the artifact_digest of
//     signed/contract.jws (draft 7.4), when the expected claims do not name
//     them;
//   - exp is at most receipt.exp_max and at most 60 seconds after iat
//     (draft 12.1);
//   - every listed check appears with its result and reason_code, its
//     evidence_ids include evidence_ids_include and its source_ref equals
//     source_ref when listed (every receipt check of that check_id must
//     agree), and no check of absent_checks appears;
//   - each check the context_checks of signed/contract.jws names appears
//     exactly once, listed or not (draft 12.1); the result of an unlisted
//     one is not judged;
//   - when the submission's native reads were outstanding at the end of its
//     evaluation (native_reads_at after cancelled_at or the Section 12.2
//     deadline), no unlisted check that needs a native read is PASS: a
//     native field rule, or a context check other than
//     native-principal-binding-v1 (draft 12.1, 17.1, 17.5);
//   - an unlisted check of a native field rule whose mapping names its
//     source's declared capability (config.json native_mappings[].source)
//     is UNKNOWN UNSUPPORTED_REQUIREMENT when a limit is below the source's
//     bound (draft 17.2), and UNKNOWN DEPENDENCY_UNAVAILABLE when the
//     source has no live check and the claim's status age at the start of
//     the evaluation is above status_max_age_seconds (draft 18).
//
// A format v2 case reads exchange.json and, for a multi-exchange case,
// sequence.json and expected/<id>/exchanges/<n>/decision.json: each exchange
// prints its responses in submission order, those of the concurrent
// submissions in any order at the place of the first of them (each line
// must match an expected response in full, one line to one response), then
// one line per handoff attempt. Every line is judged.
//
// A case of several exchanges is also judged across them (draft 12.2). Each
// exchange produces its own receipt, so the receipts have distinct jti
// values. A sealed receipt is never reopened, amended or converted, so once
// every exchange has run, the receipt command is asked for each receipt of
// an earlier exchange by its jti and must return the compact JWS the evaluate
// command printed. Without a receipt command that sub-check is skipped, with
// its reason in [Result.Skipped], and the entry is judged without it.
//
// Every case is also judged on a rule of draft A.2 that its expected results
// do not state check by check: every reputation-context and
// selection-consistency-v1 check of a receipt has the presented snapshot's
// jti in evidence_ids and, as source_ref, the record_ref of the exchange's
// selection record, that of config.json or, when config.json names no
// selection, the Appendix B record configured-selection-record:example-selection
// (draft 9.4, B.7), unless the expected result already states that for the
// check. A selection case, one whose gateway installs
// selection-consistency-v1 or selects a requirement set, is judged on a rule
// of draft 11.3 step 9 too. The re-derivation of the set is deterministic, so
// the evaluate command is run a second time on the same case with a fresh
// {state}, and the decision, terminal reason and the result and reason code
// of every check must be those of the first run (the jti and signature of a
// receipt differ and are not compared).
//
// Not judged: executed, rejected_before_crypto and reason of decision.json,
// since the evaluate command prints a receipt or a Problem and nothing of
// what the gateway does after it, or in which order it checked.
//
// learning reads the case with [hop.top/pact-go/runner/evalcase.ReadLearning]
// and compares the registry state the command prints with the entry's
// expected registry.json (spec/v1.0/fixtures/README.md, section Learning cases).
// The output is one strict JSON object with the members of registry.json
// except subject, whose artifacts are named by the artifact_digest of their
// signed manifests; the harness computes those digests from the committed
// files and maps them back to paths. Every difference is a detail of the
// FAIL:
//
//   - the lifecycle state of each artifact, and no artifact the case did not
//     register;
//   - the artifact in force in each context, null for the conservative set;
//   - for each step, the acknowledgment (ACCEPTED or DUPLICATE) or the
//     rejection (the draft Section 13.4 code and the Section 16.5 reason
//     codes), and no answer to a step the expected registry leaves
//     unanswered; entries are matched by step and reason codes as a set;
//   - the holds and the artifacts that require re-evaluation, as sets;
//   - the form of the answers: each acknowledgment carries its Acknowledgment
//     object as ack, with the same status, and each rejection its RFC 9457
//     Problem as problem, with the same code and in
//     extensions.reason_codes the same reason codes.
//
// Package [hop.top/pact-go/runner/learning] holds the reference registry state
// machine of draft Section 16, which the tests replay every committed case
// through to check that the expected registries are what the draft computes.
// The runner judges an implementation against the expected file alone.
//
// outcomes reads the case with [hop.top/pact-go/runner/evalcase.ReadOutcomes]
// and judges the outcomes result object the command prints
// (spec/v1.0/fixtures/README.md, sections Runner contract and Outcomes output).
// Every difference is a detail of the FAIL:
//
//   - one entry per step of steps.json; an ingestion answered by an
//     Acknowledgment or an RFC 9457 Problem, with the status or code of
//     acks.json when the case has one, and an identical retry of an
//     (iss, jti) by the original acknowledgment or DUPLICATE (draft 7.5);
//   - a query answered by a compact pact-reputation+jwt that verifies under
//     config.json reputation_service.key, whose payload is a
//     ReputationSnapshot issued by the service for the query's subject,
//     audience, holder key and context, valid at the query's time for at
//     most 300 seconds and not after exp_max, with an evidence cutoff no
//     later than its issuance, the configured scoring pins, and HOLD
//     exactly while hold_refs is not empty (draft 15.2, 15.4, A.2); its
//     value carries every member of snapshot.json, score_bps and
//     confidence_bps within one basis point (draft 15.3), every other
//     member and the claims exactly;
//   - the printed ProvenanceManifest: its lists those of snapshot.json,
//     sorted and naming acknowledged reports, each dimension's
//     qualified_events the number of listed reports of that dimension, the
//     data policy's qualification policy, the value's revision and cutoff,
//     and the value's provenance_digest its object_digest (draft 15.2);
//   - when the command prints classifications, the qualification of every
//     report classifications.json does not leave null; null for a refused
//     report meets an UNQUALIFIED invalid-report, which the receiver
//     refuses at ingestion. Without classifications that sub-check is
//     skipped, with its reason in [Result.Skipped] ([SkipQualification]).
//
// Package [hop.top/pact-go/runner/reputation] holds the reference oracle of
// draft Sections 14 and 15, which the tests replay every committed outcomes
// case through, and the beta-decay-v1 scorer's tolerance; the fake
// implementation's outcomes goldens are its answers.
//
// The schema verb judges each line against the entry's outcome: for
// REJECTED, a Problem with the transport_code of its decision.json; for
// ACCEPTED, the document's decoded object, compared as RFC 8785 canonical
// JSON. With [Config.Validator], a [SchemaValidator] for the Appendix A.3
// schema, it first applies the verdict of spec/v1.0/fixtures/schema/README.md to
// the input ([CheckSchemaFixture]): a case whose expectation the schema
// contradicts fails. Without one that sub-check is skipped, with its reason
// in [Result.Skipped]. [Config.SchemaCheck] sets that sub-check:
// [SchemaCheckGate], the default, runs it; [SchemaCheckOff] leaves it out, so
// the entry is judged on the command alone, and lists it in [Result.Skipped]
// with the flag's name; [ParseSchemaCheck] validates a mode. [TypDef] is the
// typ to definition table of that verdict.
//
// # Report
//
// [Report.WriteJSON] writes the pactc/v1 report ([SchemaID]), whose JSON
// Schema is schemas/pactc-report.v1.schema.json; a test keeps the two in
// lockstep. [Report.Failed] is true when any check is FAIL; pactc exits 0
// only when it is false and [Report.Empty] is false, and 3 for an empty run.
package runner
