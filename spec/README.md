# PACT (Specification)

Purpose-bound Access Control & Trust: AI agents prove who they act for and why, on every request — on top of the auth you already run, from HTTP Basic and files to OAuth, LDAP, Entra, Kubernetes and AWS.

The draft, its JSON Schema, integration profiles and conformance fixtures.

Read-only mirror of `spec/` in [hop-top/poly-pact](https://github.com/hop-top/poly-pact); open issues and pull requests there.

**Status:** Draft

The spec version and status of each version directory are in its front matter; see [Versions](#versions).

PACT is a protocol for agent profiles, intent,
reputation and adaptive admission: a gateway admits an agent's signed, purpose-bound request,
and native authorization stays final. This repository holds no code and nothing to install.
Every implementation reads the same files: the draft, the schema, the profiles and the
fixtures of a version directory.

## Versions

| Version | Directory | Front matter |
|---|---|---|
| v1.0 | [`v1.0/`](v1.0/) | [`v1.0/README.md`](v1.0/README.md) |

Cite and implement against a version directory, not a branch. Versions are independent
directories: a breaking change opens a new version directory and never changes an existing one
incompatibly.

## What a version contains

Read v1.0 in this order:

1. [`v1.0/draft.md`](v1.0/draft.md): the protocol draft, the authority. Where anything else in
   this tree disagrees with it, the other file changes.
2. [`v1.0/schemas/pact.schema.json`](v1.0/schemas/pact.schema.json): JSON Schema (Draft
   2020-12) of the wire objects. It changes together with the draft.
3. [`v1.0/profiles/`](v1.0/profiles/README.md): integration profiles per native mechanism, the
   conformance and transport profiles, the documents they build on, and the profile registry.
4. [`v1.0/examples/`](v1.0/examples/README.md): informative examples and integration samples.
5. [`v1.0/diagrams/`](v1.0/diagrams/): Mermaid diagrams of the architecture, admission and
   approval, and the learning loop.
6. [`v1.0/fixtures/`](v1.0/fixtures/README.md): the language-neutral conformance fixtures.
7. [`v1.0/spec-map.md`](v1.0/spec-map.md): each conformance check of the draft mapped to its
   sections and fixtures, with the digest of the draft it was written against.

## Conformance

The fixtures are files, not a test suite: test keys, test vectors, adapter cases and evaluation,
outcomes and learning cases, each with the result the draft requires.

- [`v1.0/fixtures/manifest.json`](v1.0/fixtures/manifest.json) is the single index. A harness
  reads its entries and never walks the directory tree to find a case; a file no entry covers
  is a failure of the manifest check.
- Each entry's `kind` names the harness verb that runs it (`vector`, `key`, `schema`,
  `evaluate`, `outcomes`, `learning`, `adapter-case` and the others), and its `scope` says
  which harnesses run it. An entry that lists `capabilities` tests a feature the draft makes
  optional, and counts only for an implementation that declares it.
- The format of every case and the contract a runner applies are in
  [`v1.0/fixtures/README.md`](v1.0/fixtures/README.md).

To check an implementation, in any language, run `pactc` of
[hop-top/pact](https://github.com/hop-top/pact) over `v1.0/fixtures`, with the commands of the
implementation as argv templates; `pactconf vectors verify` of the same module runs the shared
vectors. The SDKs read the same files in their own test harnesses.

## Implementations

Each is a read-only mirror of [hop-top/poly-pact](https://github.com/hop-top/poly-pact):

| Repository | What it is |
|---|---|
| [hop-top/pact-go](https://github.com/hop-top/pact-go) | Go reference implementation, module `hop.top/pact-go` |
| [hop-top/pact](https://github.com/hop-top/pact) | commands `pactc`, `pactconf`, `pactfix`, `pactvalidate`, module `hop.top/pact` |
| [hop-top/pact-ts](https://github.com/hop-top/pact-ts) | TypeScript SDK, npm `@hop-top/pact` |
| [hop-top/pact-py](https://github.com/hop-top/pact-py) | Python SDK, PyPI `hop-top-pact` |

## Contributing

Changes land in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) under `spec/`; this
mirror accepts no issues or pull requests. See its
[contributing guide](https://github.com/hop-top/poly-pact/blob/HEAD/CONTRIBUTING.md) for the
rules of specification and fixture changes.

Link a document outside `spec/` by its absolute URL; a relative link to it breaks in this
mirror. `make spec-links` in the source repository checks every link of the tree.

## License

MIT, © 2026 Idea Crafters LLC and jadb. See [LICENSE](LICENSE).
