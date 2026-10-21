# Contributing to PACT

`poly-pact` holds the PACT specification, its conformance fixtures, the Go
reference implementation and the language SDKs. A change that affects
protocol behavior must keep the specification, the fixtures and every
language package aligned.

## Getting started

1. Clone `hop-top/poly-pact`.
2. Run `make setup` (installs the toolchains pinned in `mise.toml` with
   [mise](https://mise.jdx.dev), then each package's dependencies).
   PHP and Composer are not in `mise.toml`: for the PHP package, install
   PHP 8.4.1 or later (with the `openssl`, `mbstring`, `iconv` and `json`
   extensions) and Composer 2 with your system package manager, so that
   `php` and `composer` are on `PATH`. Without them the `php-*` targets
   print a `NOTICE` and succeed.
3. Create one branch per change.
4. Make a focused change, with tests.
5. Run `make check`.
6. Commit using Conventional Commits (below).
7. Open a pull request; it is squash-merged.

Which branch a pull request targets is described in `RELEASING.md`.

## Development areas

| Area | Path | Make targets |
| --- | --- | --- |
| Go library and commands | `go/`, `cli/` | `go-test`, `go-vet`, `go-lint`, `go-fmt`, `go-build`, `go-vectors` |
| TypeScript | `ts/` | `ts-test`, `ts-lint`, `ts-build`, `ts-vectors` |
| Python | `py/` | `py-test`, `py-lint`, `py-build`, `py-vectors` |
| Rust | `rs/` | `rs-test`, `rs-lint`, `rs-build`, `rs-vectors` |
| PHP | `php/` | `php-test`, `php-lint`, `php-build`, `php-vectors` |
| Specification and fixtures | `spec/` | `spec-validate`, `spec-examples`, `spec-links`, `spec-map`, `spec-manifest`, `spec-parity` |
| Repository documents | `docs/` | `spec-links` |

`make help` lists every target. A language target whose package has not
landed prints a `NOTICE` line and succeeds.

## Specification and fixture changes

- `spec/v1.0/draft.md` is the authority. Where code, fixtures or documents
  disagree with it, they change, or the draft is amended first.
- The draft and `spec/v1.0/schemas/pact.schema.json` change together. A draft
  change that leaves the schema as it is needs a commit trailer
  `Schema-Unchanged: <reason>`; CI checks this on every pull request that
  changes the draft.
- A change under `spec/v1.0/fixtures/` or `spec/v1.0/schemas/` keeps all languages
  aligned: it lands with every language package green, unless the manifest
  entries it touches carry a `runner` or `adapter` scope that excludes the
  SDKs (see `spec/v1.0/fixtures/README.md`).
- Fixture files are byte-exact inputs. Do not reformat them, and do not let an
  editor add or strip line endings; `.gitattributes` keeps git from
  converting them.
- Every fixture is registered in `spec/v1.0/fixtures/manifest.json`, which every
  harness reads.
- Do not let one language define behavior that the others cannot reproduce.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
with the top-level directory as the scope:

```text
feat(ts): add the strict JSON decoder
fix(go): reject duplicate members in nested objects
docs(spec): clarify the approval lifetime
test(py): port the digest vectors
ci: run the Windows leg on fixture changes
```

Scopes: `go`, `cli`, `ts`, `py`, `rs`, `php`, `spec`, `docs`, `ci`. Use `feat` for
public behavior additions; do not downgrade a user-visible change to `chore`
to avoid a release bump. `chore(release)` commits are made by the release
tooling only.

## Pull requests

- Keep pull requests small and reviewable.
- Make sure CI passes before requesting review.
- Update the documentation when behavior, API or workflow changes.
- If a toolchain is not available locally, say in the pull request which
  checks you could not run.

## Read-only mirrors

The component mirrors (`hop-top/pact-go`, `hop-top/pact`, `hop-top/pact-ts`,
`hop-top/pact-py`, `hop-top/pact-rs`, `hop-top/pact-php`,
`hop-top/spec-pact`) are written only by the release process,
which force-pushes each release as the `git subtree split` history of the
component's directory (RELEASING.md).
Do not commit to a mirror or open issues or pull requests there; open them in
`hop-top/poly-pact`.

## Security

Report vulnerabilities as described in [SECURITY.md](SECURITY.md), not in a
public issue.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Be
respectful, specific and constructive; focus reviews on correctness,
maintainability and cross-language parity.
