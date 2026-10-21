# PACT

Purpose-bound Access Control & Trust: AI agents prove who they act for and why, on every request — on top of the auth you already run, from HTTP Basic and files to OAuth, LDAP, Entra, Kubernetes and AWS. Go, TypeScript, Python, Rust and PHP SDKs.

**Status:** prerelease. The protocol is a draft, and every component is on the `1.0.0-alpha`
line. The wire version, the version of the message format that gateways advertise, is `0.1` and
stays `0.x` until the format is declared stable.

[![ci-spec](https://github.com/hop-top/poly-pact/actions/workflows/ci-spec.yml/badge.svg)](https://github.com/hop-top/poly-pact/actions/workflows/ci-spec.yml)
[![ci-parity](https://github.com/hop-top/poly-pact/actions/workflows/ci-parity.yml/badge.svg)](https://github.com/hop-top/poly-pact/actions/workflows/ci-parity.yml)

## Table of contents

- [Why](#why)
- [Components](#components)
- [Development](#development)
- [Adding a package](#adding-a-package)
- [Documentation](#documentation)
- [Security](#security)
- [License](#license)

## Why

PACT is for gateways that already authenticate and authorize requests and now receive them
from AI agents. An agent presents its profile, declared intent and verifiable evidence; the
gateway publishes the requirements of each operation, checks the signed presentation against
them, records the result, and feeds attributable outcomes into a contextual reputation and
learning loop. Authentication, roles, permissions and the final authorization decision stay
with the environment.

PACT works with any identity provider and authentication mechanism: the native system
authenticates the principal, and PACT binds the agent and its request to that principal. Each
mechanism has an integration profile; adding one needs no protocol change.

**Why use it**
- Native authorization stays final: a PACT pass never grants access, and a native denial always
  wins.
- Each result is bound to one request: profile, intent, principal, gateway, requirement version
  and operation are signed together, with single-use challenges and a signed receipt for every
  evaluation.
- Fails closed: missing evidence, stale state or an unavailable dependency never yields
  `ADMISSIBLE`.
- Reputation comes from attributable outcomes, per context; a security hold survives score
  decay.
- [Integration profiles](spec/v1.0/profiles/README.md) for what you already run:
  - OAuth 2.0 and OIDC: any server issuing RFC 9068 JWT access tokens or supporting RFC 7662
    introspection (Okta, Auth0, Keycloak and others), Microsoft Entra ID, and Google ID tokens.
  - Other authentication: SAML, LDAP and Active Directory, mutual TLS, HTTP Basic.
  - Platforms: Kubernetes service accounts, AWS IAM, NTFS file servers, PostgreSQL.
  - Policy engines: OPA and OpenFGA.
  - Membership sources: SCIM, Google Directory, Shared Signals (SSF).

  For rollout, observation mode records outcomes without enforcing admission.

**When not to use it**
- You need an IAM system, a role taxonomy or an access-token service: PACT replaces none of
  them and issues no bearer tokens.
- Your gateway cannot authenticate the principal, map the request, or enforce an extra
  condition: it cannot claim enforced PACT support.
- You need protection against later misuse of information: that takes controls in the
  execution environment.
- You need a finished interoperability suite or an independent security assessment: the draft
  claims neither.

## Components

This repository holds the PACT specification, its conformance fixtures, and the Go, TypeScript
and Python implementations. A protocol change updates the draft, the schema, the fixtures and
every package together; each implementation reads the same language-neutral fixtures, and CI
compares the languages on the shared vectors.

| Component | Directory | Purpose | Registry | Mirror |
|---|---|---|---|---|
| [`pact-spec`](spec/README.md) | `spec/v1.0` | protocol draft, JSON Schema, integration profiles, conformance fixtures | not published to a registry | `hop-top/spec-pact` |
| [`pact-go`](go/README.md) | `go` | Go reference implementation (library) | Go module `hop.top/pact-go` | `hop-top/pact-go` |
| [`pact`](cli/README.md) | `cli` | commands: `pactc` conformance runner, `pactconf`, `pactfix`, `pactvalidate` | Go module `hop.top/pact` | `hop-top/pact` |
| [`pact-ts`](ts/README.md) | `ts` | TypeScript SDK | npm `@hop-top/pact` | `hop-top/pact-ts` |
| [`pact-py`](py/README.md) | `py` | Python SDK | PyPI `hop-top-pact` | `hop-top/pact-py` |
| [`pact-rs`](rs/README.md) | `rs` | Rust SDK | crates.io `hop-top-pact` | `hop-top/pact-rs` |
| [`pact-php`](php/README.md) | `php` | PHP SDK | Packagist `hop-top/pact` | `hop-top/pact-php` |

Cross-language parity: [tools/parity/README.md](tools/parity/README.md), the API ledger [docs/sdk/parity-ledger.md](docs/sdk/parity-ledger.md) and the dependency vetting records `docs/sdk/deps-*.md` ([TypeScript](docs/sdk/deps-ts.md), [Python](docs/sdk/deps-py.md), [Rust](docs/sdk/deps-rs.md), [PHP](docs/sdk/deps-php.md)).

Each component has its own version and tags, such as `pact-go/v1.0.0-alpha.1`; `pact-go`,
`pact-ts`, `pact-py`, `pact-rs` and `pact-php` start each new major version together. Each component is published to
its read-only mirror; open issues and pull requests here, never on a mirror.

## Development

Requirements: [mise](https://mise.jdx.dev), which installs the toolchains pinned in
[`mise.toml`](mise.toml).

```sh
make setup        # pinned toolchains, then each package's dependencies
make check        # lint, tests, builds, and the spec and release gates
make go-test      # one package; also ts-test, py-test, rs-test, and -lint, -build per language
make conformance  # pactc over spec/v1.0/fixtures
make help         # every target
```

Targets of a language without a package directory print a `NOTICE` line and succeed.

Pull requests target `next`, the default branch, and are squash-merged; commits follow
Conventional Commits, scoped by top-level directory. Process: [CONTRIBUTING.md](CONTRIBUTING.md);
releases: [RELEASING.md](RELEASING.md). Questions and bugs:
[issues](https://github.com/hop-top/poly-pact/issues). This project follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Adding a package

1. Create the language directory with its manifest, plus the Makefile targets, `mise.toml` pins,
   `mise run install` step and CI workflow of the language.
2. Vendor the spec schema into the package with its `-sync-schema` Makefile target, such as
   `make rs-sync-schema`; `-check-schema` fails on drift.
3. Add its release and publish entries as [RELEASING.md](RELEASING.md#adding-a-package)
   describes; `make release-check` compares the publish map with the release config.

All in one pull request into `next`.

## Documentation

- [spec/README.md](spec/README.md): how to read the specification;
  [spec/v1.0/draft.md](spec/v1.0/draft.md) is the authority
- [spec/v1.0/fixtures/README.md](spec/v1.0/fixtures/README.md): conformance fixtures and the
  runner contract
- [tools/parity/README.md](tools/parity/README.md): how the SDKs are held to parity with Go
- [docs/sdk/parity-ledger.md](docs/sdk/parity-ledger.md): the API parity ledger
- dependency vetting: [TypeScript](docs/sdk/deps-ts.md), [Python](docs/sdk/deps-py.md),
  [Rust](docs/sdk/deps-rs.md), [PHP](docs/sdk/deps-php.md)
- [CHANGELOG.md](CHANGELOG.md): where each component's changelog lives

## Security

Report vulnerabilities to security@hop.top, not in a public issue; see
[SECURITY.md](SECURITY.md).

## License

MIT, © Idea Crafters LLC and jadb; see [LICENSE](LICENSE). `spec/`, `ts/`, `py/`, `rs/` and `php/` carry
the same license in their own `LICENSE` files. The RFC 8785 vectors in
`spec/v1.0/fixtures/vectors/jcs/` are third-party data under Apache-2.0; see
[LICENSE-NOTE.md](spec/v1.0/fixtures/vectors/jcs/LICENSE-NOTE.md).
