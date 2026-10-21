# PACT (Go SDK)

Purpose-bound Access Control & Trust: AI agents prove who they act for and why, on every request — on top of the auth you already run, from HTTP Basic and files to OAuth, LDAP, Entra, Kubernetes and AWS.

Go reference implementation: holder, validator, gateway middleware and native adapters.

Read-only mirror of `go/` in [hop-top/poly-pact](https://github.com/hop-top/poly-pact); open issues and pull requests there.

Status: prerelease. The protocol is a [draft](https://github.com/hop-top/spec-pact), and the API may change between prerelease versions.

[![Go Reference](https://pkg.go.dev/badge/hop.top/pact-go.svg)](https://pkg.go.dev/hop.top/pact-go)
[![ci-go](https://github.com/hop-top/poly-pact/actions/workflows/ci-go.yml/badge.svg)](https://github.com/hop-top/poly-pact/actions/workflows/ci-go.yml)

## Table of contents

- [Install](#install)
- [Usage](#usage)
- [Limitations](#limitations)
- [API](#api)
- [Conformance](#conformance)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

[PACT](https://github.com/hop-top/spec-pact) is a protocol
for agent profiles, intent, reputation and adaptive admission: a gateway admits an agent's
signed, purpose-bound request, and native authorization stays final. This module is its Go
reference implementation: the holder, the validator, the gateway middleware, the reputation
service, the native adapters and the conformance runner library.

## Install

```sh
go get hop.top/pact-go@latest
```

Requirements: Go 1.26 or later. The library uses the standard library only, except three
adapter packages that each use one module: `adapters/files` (`golang.org/x/sys`), `adapters/db`
(`github.com/jackc/pgx/v5`) and `adapters/ldap` (`github.com/go-ldap/ldap/v3`). A program that
imports none of them does not download those modules.

## Usage

Put PACT admission in front of an HTTP handler. `gateway.New` returns net/http middleware that
serves the requirements endpoint, and admits a request only when native authentication, the
agent's signed presentation and native authorization all hold:

```go
mw := must(gateway.New(gateway.Config{
	Adapter:        native,
	Validator:      val,
	Publisher:      pub,
	Requirements:   reqs,
	Records:        gateway.NewMemoryRecords(1024),
	MappingVersion: mapping,
}))
app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	adm, _ := gateway.FromContext(r.Context())
	_, _ = fmt.Fprintf(w, "invoice for %s, receipt %s", adm.Principal.ID, adm.Receipt.Attestation.Decision)
})
protected := mw(app)
```

The agent sends the same request twice: once with its native credential only, then with the
presentation its `holder.Holder` signs over the contract the gateway issued:

```
401 INVALID_PROOF
200 invoice for https://identity.example/principals/alice, receipt ADMISSIBLE
```

The runnable program, with the in-memory reference adapter, keys, stores and the holder side, is
[gateway/example_test.go](gateway/example_test.go):

```sh
go test -run '^Example$' -v ./gateway
```

## Limitations

- The protocol is a draft. Its specification claims no interoperability suite and no
  independent security assessment.
- The in-memory stores (`gateway.MemoryRecords`, `gateway.MemoryHolds`,
  `validator.MemoryReceipts`, `contract.MemoryReplay` and the others) serve one process.
  Replicas of a gateway share one store of each kind, supplied by the deployment through the
  store interfaces.

## API

Reference documentation: [pkg.go.dev/hop.top/pact-go](https://pkg.go.dev/hop.top/pact-go).

| Package | What it gives |
|---|---|
| `core` | Go types of the wire objects, enums and limits |
| `core/strictjson`, `core/jcs`, `core/digest`, `core/clock` | strict JSON decoding, RFC 8785 canonicalization, the three digests and the time rules of the draft |
| `core/jws` | compact JWS signing and verification under the PACT profile (ES256, optional Ed25519) |
| `core/binding` | the operation context of the baseline HTTP mapping, from a received `*http.Request` |
| `contract` | issue and verify requirement contracts |
| `holder` | the agent side of an admission exchange: contract verification, profile disclosure, request binding and key proof |
| `validator` | the admission validator: decisions, receipts and their state machine |
| `gateway` | admission as net/http middleware |
| `reputation` | the reputation service as a library: ingestion, qualification, holds and signed snapshots |
| `adapter` | the native adapter contract, with `adaptertest` (its conformance suite), `enroll`, `freshness`, `installed`, `source` and `task` |
| `adapters/memory` | the in-memory reference adapter |
| `adapters/basic`, `oauth`, `mtls`, `aws`, `saml`, `ldap`, `graph`, `k8s`, `files`, `db`, `abac`, `rebac` | native adapters of the integration profiles |
| `runner` | the conformance runner library behind `pactc` |

The package layout in full is in [CONTRIBUTING.md](CONTRIBUTING.md#layout).

## Conformance

The language-neutral fixtures of the [specification](https://github.com/hop-top/spec-pact)
(`v1.0/fixtures`, indexed by `v1.0/fixtures/manifest.json`) are run against this module in the
source repository: the shared vectors through the `core` packages, the adapter cases through
`adapter/adaptertest` and `adapters/memory`, and the evaluation cases through
`validator/conformance`. The command that runs them against any implementation, in any language,
is `pactc` of [hop-top/pact](https://github.com/hop-top/pact).

## Contributing

Changes land in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) under `go/`; this
mirror accepts no issues or pull requests. See [CONTRIBUTING.md](CONTRIBUTING.md) for the layout,
the dependency rule and the build and test commands, and the
[code of conduct](https://github.com/hop-top/poly-pact/blob/HEAD/CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities to security@hop.top, not in a public issue; see
[SECURITY.md](https://github.com/hop-top/poly-pact/blob/HEAD/SECURITY.md).

## License

MIT, © 2026 Idea Crafters LLC and jadb. See [LICENSE](LICENSE).
