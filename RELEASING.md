# Releasing PACT

Every component of this repository is versioned and released by
release-please, run with the target-versioning extension of
[hop-top/.github](https://github.com/hop-top/.github). Nobody picks a
version, writes a `Release-As:` footer, edits the manifest or pushes a tag
by hand: the branch a change lands on decides the version, and merging a
release pull request tags it.

The rules are the shared ones in
[Version by target](https://github.com/hop-top/.github/blob/main/references/how-to/target-versioning.md)
and
[Version a spec tree](https://github.com/hop-top/.github/blob/main/references/how-to/spec-versioning.md).
This file says how they apply here.

## Components

| Component | Package path | Tag | Mirror | Registry |
|---|---|---|---|---|
| `pact-go` | `go` | `pact-go/v<version>` | `hop-top/pact-go` | Go module `hop.top/pact-go` (module proxy, no upload) |
| `pact` | `cli` | `pact/v<version>` | `hop-top/pact` | Go module `hop.top/pact` (module proxy, no upload) |
| `pact-ts` | `ts` | `pact-ts/v<version>` | `hop-top/pact-ts` | npm `@hop-top/pact` |
| `pact-py` | `py` | `pact-py/v<version>` | `hop-top/pact-py` | PyPI `hop-top-pact` |
| `pact-rs` | `rs` | `pact-rs/v<version>` | `hop-top/pact-rs` | crates.io `hop-top-pact` |
| `pact-php` | `php` | `pact-php/v<version>` | `hop-top/pact-php` | Packagist `hop-top/pact` (read from the mirror) |
| `pact-spec` | `spec/v1.0` | `pact-spec/v<version>` | `hop-top/spec-pact` | none |

- `pact-go`, `pact-ts`, `pact-py`, `pact-rs` and `pact-php` form the linked group `pact-sdk`
  (`conditional-linked-versions`): they move together only when one of
  them opens a new major line, and version independently otherwise
  ([Linked group](#linked-group)).
- `pact-spec` is independent of the group.
- `pact` is the command module `hop.top/pact` in `cli/` (pactc,
  pactconf, pactfix, pactvalidate). It is independent of the group and
  has its own changelog (`cli/CHANGELOG.md`) and mirror. Decision
  (2026-10-20): the commands left `go/cmd` for their own top-level
  directory, because the mirror push replaces a mirror's `main` with one
  directory and tags it `v<version>`, so the commands cannot share
  `hop-top/pact-go` with the library ([Mirrors](#mirrors)). Releasing the
  commands follows an order ([Command module](#command-module)).
- `go` keeps `go/cmd` in its `exclude-paths`: the directory is gone, but
  the commits that touched it before the move, the move included, stay out
  of `pact-go`. release-please skips a commit for a package only when every
  file it touches inside the package path is under an excluded path.
- `pact-php` is released from the mirror `hop-top/pact-php`: Packagist reads the
  package from it, and `composer.json` has no `version` field, so
  release-please writes only `php/CHANGELOG.md` and Packagist takes the
  version from the mirror tag `v<version>`.
- There is no root package: nothing outside the seven package paths is
  released, and a commit touching only `docs/`, `tools/`, `scripts/`,
  `.github/` or the root `go.work` releases nothing.

Configuration: `.github/release-please-config.json` and
`.github/.release-please-manifest.json`. The publish map in
`.github/workflows/publish.yml` names the same seven components, each with
its own mirror (`make release-check`).

## Branch model

Decision (2026-10-20): main plus next, with `release/x.y` maintenance
lines. `next` is the default branch of this repository; the mirrors keep
`main`.

| Branch | Role | What release-please proposes there |
|---|---|---|
| `next` | prerelease (default branch) | alpha, beta and rc releases of the line each package previews |
| `main` | stable | the stable version an rc previewed; patches for packages already stable |
| `release/x.y` | maintenance | stable patches only |

Where work lands first:

- Features, fixes, spec changes, dependency updates: a pull request into
  `next`.
- A hotfix for a package already stable: a pull request into `main`
  (`fix` only; a `feat` or a breaking change there blocks that package),
  then a merge of `main` into `next` (forward-port), never a cherry-pick.
- A patch for an older stable line: a pull request into `release/x.y`,
  cut from that line's last stable tag. Forward-port the fix to `main` and
  `next` as well.

Merges between `next` and `main` are ordinary merge commits in either
direction. The manifest travels with them; the promotion gate checks that
every manifest entry is one of the two branches' values.

## Commits

Conventional Commits with the top-level directory as the scope
(CONTRIBUTING.md). What a commit does to a package's next version:

| Commit | Before 1.0 | From 1.0 |
|---|---|---|
| breaking (`!`, `BREAKING CHANGE:`) | new minor line | new major line |
| `feat` | new minor line | new minor line |
| `fix`, `perf` | patch | patch |
| `docs` under `spec/v1.0/` | patch | patch |
| other `docs`, `test`, `refactor`, `build`, `ci`, `chore` | no release | no release |

On `next` a change that the line already covers only bumps the
prerelease counter: while no stable `1.0.0` exists, `1.0.0-alpha.3` plus a
`feat`, or a breaking change, is `1.0.0-alpha.4`. Hidden types never cut a
release on their own; they ship with the next release of their package.
For `pact-spec` only, `docs` is a visible changelog section
(Specification), so a `docs(spec)` commit touching `spec/v1.0/` cuts a
spec release; every other package keeps `docs` hidden.

A spec commit carries no breaking-change syntax and stays inside one
version directory; a breaking change to the contract opens a new
directory (`spec-commit-rules`).

## Release flow

1. A pull request merges into `next` (or `main`, `release/x.y`).
2. The push runs `.github/workflows/release-please.yml`, which keeps one
   release pull request per component open on that branch, titled
   `chore(release): <component> <version>` and labelled
   `status:release-pending`.
3. For a `pact-spec` release pull request, `spec-status-line` rewrites the
   `**Status:**` line of every spec document from the channel (alpha:
   Draft, beta: Pre-release, rc: Release Candidate, stable: General
   Availability) and pushes the change to the pull request branch.
4. Merging a release pull request tags `<component>/v<version>`, creates
   the GitHub release and labels the pull request `status:release-tagged`.
5. The tag runs `.github/workflows/publish.yml`: the registry publish for
   the component's ecosystem, then the mirror push
   ([Mirrors](#mirrors)).

## First release

The manifest seeds all seven packages at `1.0.0-alpha.0`. release-please
reads a manifest entry as a version already released, so the seed is the
starting point of the line, not a tag: the first release pull requests on
`next` propose `1.0.0-alpha.1` for every package with a releasable commit,
and `1.0.0-alpha.1` is the first tag of each component.

The seed is required. The python strategy ignores `initial-version` and
opens a package with no manifest entry at a stable `0.1.0`, which the
group blocks, and the rust strategy ignores it as well; seeding every
package keeps the seven first versions on one
line (bootstrap checklist of hop-top/.github, section 5).

`release-as` is not used to make the first tag `1.0.0-alpha.0`: target
versioning refuses it. The shared preflight fails a target package that
sets `release-as`, the extension's runner refuses the config and proposes
no release pull request, and it drops `Release-As:` commit footers. The
first tags are therefore `1.0.0-alpha.1`.

The seed is on the 1.0 line from the start. The group opens 1.0 here
without `x-open-line`: no member has a stable release or a 0.x line, so
the group is not before 1.0, and each member counts on its own until a
member opens 2.0.0 or `main` cuts 1.0.0
([Linked group](#linked-group)).

No component is tagged until public exposure is approved. Before the
first release pull request is merged:

- The repository exists on GitHub with `next` as its default branch and
  `main` created from it.
- The labels `status:release-pending` and `status:release-tagged` exist.
- The release-bot App is installed on the repository and the secrets
  below reach it ([Secrets](#secrets)).
- The old `hop-top/spec-pact` is deleted; the first `pact-spec` tag
  recreates it with `v1.0/` at its root. The earlier `specs/v0.1/`
  layout is not carried over.
- npm: `@hop-top/pact` is claimed by a local maintainer publish, then a
  trusted publisher is bound. PyPI: `hop-top-pact` uses the token path
  (`pypi-auth: token` in the publish map). crates.io: `hop-top-pact` is
  published with `CARGO_REGISTRY_TOKEN`.
- Packagist: `hop-top/pact` is submitted once, from the mirror
  `hop-top/pact-php` after the first `pact-php` tag creates it; later tags
  reach Packagist through the notify step of the publish workflow.
- Required checks are added to the branch rulesets last, once each has
  reported on a pull request into `next`, `main` and every `release/x.y`.

## Promotion

Every line starts on alpha. Moving a line to beta, then rc, is a recorded
decision: an `x-channel` record in the config, written by
`.github/scripts/promote-release.sh` (a wrapper around the extension's
`promote.js` at the commit `release-please.yml` pins):

```sh
.github/scripts/promote-release.sh channel beta --group pact-sdk
.github/scripts/promote-release.sh channel beta --package pact-spec
.github/scripts/promote-release.sh channel rc --group pact-sdk
.github/scripts/promote-release.sh channel beta --group pact-sdk --dry-run
```

The script commits the config change alone as
`chore(release): promote ...`. Open a pull request with that commit into
`next` (the config and the manifest are code-owned by `@hop-top/release`,
CODEOWNERS); the `validate-promotion` check (`release-promote-gate.yml`)
replays the record on the base branch and fails anything `promote.js`
would not write: a skipped channel, a step backwards, a record for
another line, or other config edits in the same pull request. Once merged,
the release run on `next` cuts `<line>-beta.0` (or `-rc.0`) at once; later
changes count on that channel.

Path to stable for `1.0.0`:

1. `next`: `1.0.0-alpha.N` (counter on every releasable change).
2. Promote to beta on `next`: `1.0.0-beta.0`, then `beta.N`.
3. Promote to rc on `next`: `1.0.0-rc.0`, then `rc.N`.
4. Merge `next` into `main`: `main` proposes `1.0.0` for every package at
   an rc, and skips packages still on alpha or beta.

A new major line, or a line no change would open on its own, is opened
with `x-open-line` (`promote-release.sh open-line 2.0.0 --group
pact-sdk`).

## Linked group

`pact-sdk` (`pact-go`, `pact-ts`, `pact-py`, `pact-rs`, `pact-php`) links only when a member's
proposal opens a new major line, on `next` and on `main` alike. A new
minor or a patch from 1.0 is cut for that member alone.

- On `next`, when the group links, one release pull request carries every
  member at the group's line; each member keeps its channel when it is
  already on that line, otherwise starts it on alpha.
- On `main`, the `1.0.0` cut (and every later major) is held until every
  member is at an rc of it; then all four are cut together in one group
  pull request. A member still on alpha or beta blocks the group, and the
  run fails naming it.

`pact` and `pact-spec` are not in the group: each reaches `1.0.0` when its
own rc is merged into `main`.

## Stable and maintenance lines

- On `main`, a package already stable takes fixes only: `fix` gives
  `x.y.(z+1)`; a `feat` or breaking change blocks it (land it on `next`).
- A hotfix that releases the version `next` previews moves `next` on: its
  next release opens the following line.
- `release/x.y` releases stable patches only; prereleases and packages
  with no release are skipped there.

## Adding a package

A new linked member is added in one pull request
into `next`: the package in the config with `versioning: "target"`,
`prerelease-type: "alpha.0"`, `bump-minor-pre-major: true` and an
`initial-version` on the group's line (the line open above the group's
highest stable, or else the patch line after that stable, at `alpha.0`),
its component in the `pact-sdk` group, its entry in the publish map, its
secrets in `publish.yml` (`CARGO_REGISTRY_TOKEN`; `PACKAGIST_USERNAME`,
`PACKAGIST_TOKEN`), and its manifest in the preflight path list when it
has one. A rust package ignores `initial-version`: seed its manifest
entry on the group's line instead.

A new spec contract line is a new package `spec/vX.Y` (`release-type:
simple`, its own component and tags) next to `spec/v1.0`; it is published
to the same mirror, where it appears as a sibling `vX.Y/` directory.

## Mirrors

Each tag publishes its component's directory to a read-only mirror
(`mirror-subtree.yml` of hop-top/.github, called by `publish-on-tag.yml`):

- The directory (`go`, `cli`, `ts`, `py`, `php`, or `spec` for `pact-spec`) is split
  from a full-history checkout with `git subtree split --prefix=<dir>`:
  the mirror carries the rewritten history of the commits that touched
  that directory, rooted at it. No entry sets a target prefix, so nothing
  is grafted or squashed.
- The split commit is force-pushed to the mirror's `main`, and the tag
  (`v<version>`, the component prefix stripped) is force-pushed with it.
- A missing mirror is created public, with issues and the wiki disabled,
  description `READ-ONLY MIRROR of hop-top/poly-pact <component>`,
  homepage `https://github.com/hop-top/poly-pact`. After the push it is
  set back to read-only.
- `pact-spec` publishes `spec/`, not `spec/v1.0/`, with no target prefix:
  the mirror root holds `README.md`, `LICENSE` and `v1.0/`.
- The Go proxy caches a fetched module version forever: a `pact-go/v*` or
  `pact/v*` tag is permanent once pushed. Never retag or move a tag.

Do not open issues or pull requests on a mirror, and never push to one.

## Command module

`cli/go.mod` requires `hop.top/pact-go` at the placeholder
`v0.0.0-00010101000000-000000000000`, and the root `go.work` replaces it
with `./go`, so the commands build against the library of the tree. No
mirror carries `go.work`, and `go install` never reads one: a `pact` tag
cut while the placeholder is in `cli/go.mod` publishes a module that does
not build outside this repository. The first release of the commands
therefore goes in this order:

1. Release the library: merge the `pact-go` release pull request, so that
   `pact-go/v<version>` is tagged and `hop.top/pact-go@v<version>` resolves
   through the module proxy.
2. In one pull request, make `cli/go.mod` require `hop.top/pact-go
   v<version>` (`go -C cli get hop.top/pact-go@v<version>`, then `go -C cli
   mod tidy`) and delete the `replace` line of `go.work`. The workspace
   still joins both modules, so the commands keep building against the
   library of the tree.
3. Release the commands: merge the `pact` release pull request, which tags
   `pact/v<version>`.

A later library change the commands need repeats the order: library tag,
requirement bump in `cli/go.mod`, then the `pact` release.

Import paths: `hop.top/pact-go` (library) and `hop.top/pact` (commands)
are vanity paths, each named after its mirror. The server behind `hop.top`
must answer `https://hop.top/pact-go?go-get=1` and
`https://hop.top/pact?go-get=1`, and the same request for every path below
each (for example `https://hop.top/pact-go/core?go-get=1` and
`https://hop.top/pact/pactc?go-get=1`), with

```html
<meta name="go-import" content="hop.top/pact-go git https://github.com/hop-top/pact-go">
<meta name="go-import" content="hop.top/pact git https://github.com/hop-top/pact">
```

The go command matches a tag's prefix by whole path elements, so
`hop.top/pact` is not a prefix of `hop.top/pact-go/core`: each import path
matches exactly one of the two tags.

Then `go install hop.top/pact/pactc@v<version>` resolves through the
mirror tag `v<version>`. Release binaries are a later addition, from the
shared goreleaser-on-tag workflow of hop-top/.github; nothing builds them
yet.

## Secrets

Organization secrets (hop-top) that must reach this repository:

| Secret | Used by | Purpose |
|---|---|---|
| `RELEASE_BOT_APP_ID` | `release-please.yml`, `spec-status-line.yml` | release-bot App ID (passed as the App's client ID) |
| `RELEASE_BOT_PRIVATE_KEY` | `release-please.yml`, `spec-status-line.yml` | release-bot App private key |
| `GH_MIRROR_PAT` | `publish.yml` | fine-grained PAT, Administration and Contents read-write on every mirror |
| `NPM_REGISTRY_TOKEN` | `publish.yml` (`pact-ts`) | npm granular publish token; unused once the trusted publisher is bound |
| `PYPI_REGISTRY_TOKEN` | `publish.yml` (`pact-py`) | PyPI API token (`pypi-auth: token`) |
| `CARGO_REGISTRY_TOKEN` | `publish.yml` (`pact-rs`) | crates.io API token with the publish-new and publish-update scopes |
| `PACKAGIST_USERNAME` | `publish.yml` (`pact-php`) | Packagist account of the maintainer that owns `hop-top/pact` |
| `PACKAGIST_TOKEN` | `publish.yml` (`pact-php`) | Packagist API token; without both, the mirror is pushed and the Packagist notify step is skipped with a notice |

The release-bot App needs Contents, Pull requests and Workflows
read-write on this repository. `GITHUB_TOKEN` stays read-only everywhere.
`CARGO_REGISTRY_TOKEN`, `PACKAGIST_USERNAME` and `PACKAGIST_TOKEN` are
used by the Rust and PHP packages.

## Workflows

| File | Runs on | Does |
|---|---|---|
| `release-please.yml` | push to `main`, `next`, `release/*`; manual | release pull requests and tags (shared `release-please-on-push`, target versioning) |
| `publish.yml` | tags `*/v*` | registry publish and mirror push (shared `publish-on-tag`) |
| `release-please-preflight.yml` | every pull request | config, manifest, publish map and records shape (shared preflight) |
| `release-promote-gate.yml` | every pull request | manifest written by release pull requests only; promotion records as `promote.js` writes them |
| `spec-commit-rules.yml` | pull requests touching `spec/` | one version directory per commit, no breaking-change syntax |
| `spec-status-line.yml` | labelled release pull requests | `**Status:**` lines from the channel |
| `version-check.yml` | push to role branches, every pull request | no stray release-version literal; every `spec/vX.Y` path is a manifest version |

`release-please.yml` and `release-please-preflight.yml` call hop-top/.github
at one full commit SHA, that of a release tag (v0.15.0, the first with the
target-versioning extension), rather than the moving `v0` tag, so the
release run and the promotion replay use the same code;
`promote-release.sh` reads that pin. Move both pins together.
The other shared workflows are called at `v0`.

The gate's tests: `bats .github/tests/release-promote-gate.bats`. The
tests that run the real `promote.js` need `RELEASE_PLEASE_TARGET_DIR`
pointing at an installed `scripts/release-please-target` of hop-top/.github
at the pinned commit; they are skipped otherwise.

## Verifying a release

```sh
go list -m hop.top/pact-go@v<version>
go list -m hop.top/pact@v<version>
npm view @hop-top/pact versions
pip index versions hop-top-pact --pre
cargo info hop-top-pact@<version>
composer show --all hop-top/pact
git ls-remote --tags https://github.com/hop-top/spec-pact
```

release-please writes a Python release into `py/pyproject.toml` in its
SemVer spelling (`1.0.0-alpha.1`), which PEP 440 accepts; the built package
and PyPI show the normalized form (`1.0.0a1`). The tag keeps the SemVer
form. The seed in `py/pyproject.toml` is `1.0.0a0`. release-please writes a
Rust release into `rs/Cargo.toml` and `rs/Cargo.lock`; the seed in
`rs/Cargo.toml` is `1.0.0-alpha.0`.
