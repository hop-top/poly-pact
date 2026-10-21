# PACT: agent steering

This repository is the source of truth for PACT: the specification, its
language-neutral conformance fixtures, the Go reference implementation, and
the language SDKs. Every component is published from here to a read-only
mirror. Each rule below names the CI job or Makefile target that enforces it,
or is marked *convention* (enforced by review).

## Authority

- **`spec/v1.0/draft.md` wins.** Where code, fixtures, schemas, profiles or docs
  disagree with the draft, they change, or the draft is amended first. A
  plan, issue or task description is not normative. *Convention.*

## Layout

```
spec/            mirrored to hop-top/spec-pact as its root (README.md, LICENSE)
  v1.0/          one directory per spec version
    draft.md  schemas/pact.schema.json  diagrams/  examples/
    profiles/  fixtures/ (manifest.json is the index)  spec-map.md
go/              module hop.top/pact-go (library) -> mirror hop-top/pact-go
  core/  adapter/  adapters/  reputation/  runner/  internal/depcheck
cli/             module hop.top/pact: pactc, pactconf, pactfix,
                 pactvalidate -> mirror hop-top/pact
go.work          joins the two Go modules
ts/ py/ rs/ php/  SDKs
docs/            repository documents, never mirrored
scripts/ tools/  spec and manifest checks, spec tooling, vector generators
```

## Reference

- `tools/parity/README.md`: how the SDKs are held to parity with Go (result
  grammar, gates file, API ledger rules, mutation checks).
- `docs/sdk/parity-ledger.md`: the API parity ledger, one row per exported Go
  symbol.
- `docs/sdk/deps-{ts,py,rs,php}.md`: dependency vetting records; the guard
  tests of each SDK read them, so a dependency change updates its record.
- `go/docs/deps.md`: the same for the Go modules.

## Build and test

`make help` lists every target. Run `make setup` once, then `make check`
before a pull request. Useful subsets:

- Go: `make go-fmt go-vet go-lint go-test go-build go-vectors`. `go-vet` runs
  twice, the second time with `GOOS=windows`. Every go invocation needs
  `-buildvcs=false` in a worktree; the targets pass it.
- Spec: `make spec-validate spec-examples spec-links spec-map spec-manifest
  spec-parity`.
- SDKs: `make <lang>-test <lang>-lint <lang>-build <lang>-vectors` for `ts`,
  `py`, `rs`, `php`. A target whose package has not landed prints a `NOTICE`
  and succeeds.
- Conformance: `make conformance` (pactc against `spec/v1.0/fixtures`).

## Editing rules

- **Draft and schema move together.** A change to `spec/v1.0/draft.md` lands with
  the matching change to `spec/v1.0/schemas/pact.schema.json`. A draft change
  that leaves the schema unchanged carries a commit trailer
  `Schema-Unchanged: <reason>`. CI: `Spec / Move together`
  (`scripts/check-spec-together.sh`).
- **The schema is valid JSON Schema 2020-12.** `make spec-validate`.
- **Examples are tests.** Every JSON block in `spec/v1.0/examples` parses
  strictly; a block with a schema annotation validates against the
  schema. `make spec-examples`.
- **The spec map follows the draft.** `spec/v1.0/spec-map.md` rows, sections and
  the draft pin are checked against the draft and the fixtures. `make
  spec-map`.
- **Fixtures and schemas keep every language aligned.** A change under
  `spec/v1.0/fixtures` or `spec/v1.0/schemas` lands with all five languages green,
  unless the manifest entries it touches have scope `runner` or `adapter`,
  which excludes the SDKs. The Go, TypeScript, Python, Rust and PHP CI
  workflows all run on such a change; `make test`.
- **Signed fixtures are generated, never edited by hand.** Run `pactfix
  generate`; `generate -check` must report nothing stale. `make go-test`
  (`cli/pactfix`, `TestRepoChecks`).
- **Fixture bytes are exact.** No reformatting, no line-ending changes;
  `.gitattributes` disables conversion. CI: `Go / Test (windows-latest)`,
  step "Verify spec bytes".
- **Versions are immutable once tagged.** Tags are `<component>/v<version>`.
  Never retag, never move or force-push a tag; a published Go module version
  is permanent. *Convention.*

## Fixture invariant

- `spec/v1.0/fixtures` and `spec/v1.0/profiles` are language-neutral: only the file
  types allow-listed in `scripts/check-spec-selfcontained.py` (JSON, YAML,
  Markdown, `.jws`, `.txt`, `.pem`, plus native adapter formats under
  `spec/v1.0/fixtures/adapters` only). No source code. `make spec-links`.
- `spec/v1.0/fixtures/manifest.json` is the single index every harness reads;
  every fixture file is registered there. `make spec-manifest`, and `make
  spec-parity` for the agreement of the Python and Go checkers.
- `spec/` is self-contained: no relative link leaves it, except the entries in
  `spec/.links-allow`. `make spec-links`.

## What belongs here

- The specification, schema, examples, profiles, fixtures and spec map.
- The Go reference implementation: core, adapter contract, adapters,
  reputation, runner, and the commands in `cli`.
- SDKs in `ts`, `py`, `rs` and `php`: strict JSON, JCS, digests, ES256 JWS,
  RFC 7638 thumbprints, schema validation and the shared vectors. The
  TypeScript and Python ports follow the Go library to parity
  (`tools/parity/README.md`); Rust and PHP stay core-only.

## What does not belong

- A conformance runner or fixture tool outside Go: `pactc` is the single
  cross-language runner; `pactconf` and `pactfix` stay Go-only. *Convention.*
- Native adapters in an SDK before the Go adapter prints NDJSON results and
  its gate row is set for that language (`tools/parity/README.md`, Native
  adapters and sources). *Convention.*
- Task, track or ticket identifiers of any tracking system, in commits, code,
  comments, docs, ADRs or branch names. *Convention.*
- Any change made in a mirror.

## Mirrors

`hop-top/pact-go`, `hop-top/pact`, `hop-top/pact-ts`, `hop-top/pact-py`,
`hop-top/pact-rs`, `hop-top/pact-php` and `hop-top/spec-pact` are
read-only. Never commit there. Each release force-pushes the
`git subtree split` history of the component's directory to its mirror; the
first tag of a component creates its mirror, public. Release mechanics:
`RELEASING.md`. *Convention.*

## Packages

- **No `../spec` at runtime or in a package build.** Each SDK mirror is
  self-contained: the schema is vendored inside the package and
  drift-checked. `make <lang>-check-schema` (`make <lang>-sync-schema`
  refreshes the copy).
- **Library dependencies are allow-listed.** The library module `go/` imports
  only what `go/internal/depcheck` permits; third-party Go dependencies are
  vetted in `go/docs/deps.md` first. `make go-test`.
- **Go code is gofmt-clean and vets on Windows.** `make go-fmt go-vet`.

## Commits

- Conventional Commits, scope = top-level directory: `go`, `ts`, `py`, `rs`,
  `php`, `spec`, `docs`, `ci` (for example `fix(go): ...`). *Convention.*
- Bodies are terse: noun phrases, what changed and why, no narrative.
  *Convention.*
- No attribution or co-author trailers. The only trailer in use is
  `Schema-Unchanged`. *Convention.*
- `chore(release)` commits belong to release-please; never write one by hand.
  *Convention.*
