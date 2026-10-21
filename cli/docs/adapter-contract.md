# pactc adapter contract

`pactc run` runs the conformance fixtures of the specification (`v1.0/fixtures`
in [hop-top/spec-pact](https://github.com/hop-top/spec-pact), `spec/v1.0/fixtures`
in the source repository) against an implementation under test. The
implementation may be written in any language: the runner reaches it only
through the commands given on its command line, and never imports or links it.
The runner is the package `runner` of
[hop.top/pact-go](https://github.com/hop-top/pact-go); `pactc run --help` prints
the same contract.

Paths of the form `spec/v1.0/...` are in the source repository; in the
specification mirror they start at `v1.0/`.

```
pactc run --fixtures-root spec/v1.0/fixtures \
  --evaluate-cmd "tool evaluate {dir} {state}" \
  --receipt-cmd "tool receipt {state} {id}" \
  --outcomes-cmd "tool outcomes {dir} {state}" \
  --learning-cmd "tool learning {dir} {state}"
```

Each `--*-cmd` value is an argv template. It is split on white space, then
`{dir}`, `{state}` and `{id}` are replaced inside each argument
(`--case={dir}` works). No shell is involved: quotes, pipes and globs are
passed on literally, and a replaced value stays one argument even when it
holds white space.

- `{dir}` is the absolute path of the entry's case directory under the
  fixtures root. Its files are described in `spec/v1.0/fixtures/README.md`.
- `{state}` is a scratch path for the case, fresh for each entry. It does
  not exist yet; the command may create a file or a directory there. The
  evaluate and receipt commands of an entry share it, so the gateway state
  of a multi-exchange case carries over to the receipt query; the second
  evaluation of a selection case gets a fresh one.
- `{id}` is the `jti` of a receipt, for the receipt command.

| Flag | Template | The command | Standard output |
|---|---|---|---|
| `--evaluate-cmd` | `tool evaluate {dir} {state}`, `{state}` optional | evaluates the case; standard input is empty | the compact `pact-admission+jwt` receipt, or an RFC 9457 Problem JSON object (draft Section 13.4) when the request is rejected before an authenticated evaluation (draft Section 12.2) |
| `--receipt-cmd` | `tool receipt {state} {id}`, optional | returns a receipt that the evaluate command of the entry printed | the compact receipt whose `jti` is `{id}` |
| `--outcomes-cmd` | `tool outcomes {dir} {state}` | runs the ingestions and queries of the case | the outcomes result object: the answer to each ingestion, and the signed `ReputationSnapshot` and provenance manifest of each query |
| `--learning-cmd` | `tool learning {dir} {state}` | applies the learning policy and events of the case | the registry state JSON |
| `--schema-cmd` | `tool schema {dir}`, optional; `{dir}` is the absolute path of the entry's file | reads the documents of the schema case, a compact JWS or an object list (`spec/v1.0/fixtures/schema/README.md`) | one line per document, in order: the decoded object it accepts as JSON (the payload for a compact JWS), or an RFC 9457 Problem JSON object (draft Section 13.4) for a document it rejects |

Rules:

- Every command is optional. The entries of a verb whose command is not
  given are reported as `SKIP`, never `FAIL`.
- The exit status of an evaluate command is informational: the response on
  standard output is judged. A command that prints neither a receipt nor a
  Problem fails, whatever its exit status.
- Cases come only from `manifest.json` in the fixtures root
  (`--fixtures-root`, default `spec/v1.0/fixtures`). The runner never walks the
  tree to find them, and runs only the entries of kind `evaluate`,
  `outcomes`, `learning` and `schema`, each with the verb of that name. A
  fixture file that no manifest entry covers fails the manifest check as
  `manifest-incomplete`; it is not a skipped case.
- `--fixture` (repeatable) selects entries by manifest id or id prefix, such
  as `admission/valid` or `admission/`. A selector that selects nothing is a
  usage error.
- `pactc run` exits 0 when no check is `FAIL`, 1 when one is, 2 on a
  usage error or when the run cannot start, and 3 when no check is `FAIL`
  but the profile and transports of the run select no entry.
- `--json` writes the `pactc/v1` report. Its JSON Schema is
  [runner/schemas/pactc-report.v1.schema.json](https://github.com/hop-top/pact-go/blob/main/runner/schemas/pactc-report.v1.schema.json).
  Its `summary` counts the
  manifest check as well as every entry, as the schema states, so a run
  whose manifest check passes has a `summary.pass` one higher than the
  `pass` of `by_profile`, which counts the entries alone. An entry's optional
  `skipped` array lists the sub-checks that were not run, each with its
  reason, while the entry itself is `PASS` or `FAIL`; the table lists them
  under the entry.

Evaluate entries are judged as the Runner contract of
`spec/v1.0/fixtures/README.md` states: the receipt's signature, decision,
claims, digests, expiry and check results, or the Problem code. After a case
of several exchanges, the receipt command is asked for each earlier receipt
by its `jti` and must print it unchanged (draft Section 12.2); without
`--receipt-cmd` that sub-check is listed in `skipped`. A selection case is
evaluated a second time with a fresh `{state}` and must yield the same
decision, terminal reason and check results (draft Section 11.3, step 9).
Learning entries are judged as section Learning output of
`spec/v1.0/fixtures/README.md` states: the registry state the command prints is
compared with the entry's `registry.json` (the state of each artifact, the
artifact in force in each context, the acknowledgment or the rejection of
each step with its code and reason codes, the holds and the artifacts that
require re-evaluation), and each answer must carry its Acknowledgment or
its Problem. Outcomes entries are judged as section Outcomes output of
`spec/v1.0/fixtures/README.md` states: each ingestion's Acknowledgment or
Problem, against `acks.json` when the case has one, and the original
acknowledgment or `DUPLICATE` for an identical retry of an `(iss, jti)`
(draft Section 7.5); each query's
snapshot, verified under the case's reputation key and bound to the query,
with `score_bps` and `confidence_bps` within one basis point of
`snapshot.json` and every other member exactly; and its provenance manifest
and digest. The qualifications are compared with `classifications.json`
when the command prints them; otherwise that sub-check is listed in
`skipped`. Schema entries are judged as section Runner contract of
`spec/v1.0/fixtures/README.md` states: one line per document; each line of a
`REJECTED` entry a Problem with the `transport_code` of its
`decision.json`, each line of an `ACCEPTED` entry its document, compared
as RFC 8785 canonical JSON. `pactc` also applies the expected verdict to
the input itself with the Appendix A.3 schema (`--schema FILE`, default
`schemas/pact.schema.json` beside the fixtures root), and an entry whose
expectation the schema contradicts fails; without that file the sub-check
is listed in `skipped`.
`--schema-check MODE` sets that sub-check: `gate`, the default, runs it;
`off` does not run it, so each entry is judged on the `--schema-cmd` output
alone and the sub-check is listed in `skipped`, naming `--schema-check`. `off`
is a local diagnostic, not a conformance run; any other `MODE` is a usage
error (exit 2). The report keeps the `pactc/v1` format.
