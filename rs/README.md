# PACT (Rust SDK)

Purpose-bound Access Control & Trust: AI agents prove who they act for and why, on every request — on top of the auth you already run, from HTTP Basic and files to OAuth, LDAP, Entra, Kubernetes and AWS.

Rust SDK: wire types, strict JSON, JCS, digests, ES256 JWS and schema validation.

Read-only mirror of `rs/` in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) (component
`pact-rs`); open issues and pull requests there.

Status: prerelease. The protocol is a [draft](https://github.com/hop-top/spec-pact), and the API
may change between prerelease versions.

[![crates.io](https://img.shields.io/crates/v/hop-top-pact)](https://crates.io/crates/hop-top-pact)
[![ci-rs](https://github.com/hop-top/poly-pact/actions/workflows/ci-rs.yml/badge.svg)](https://github.com/hop-top/poly-pact/actions/workflows/ci-rs.yml)

## Table of contents

- [Install](https://github.com/hop-top/pact-rs#install)
- [Usage](https://github.com/hop-top/pact-rs#usage)
- [Limitations](https://github.com/hop-top/pact-rs#limitations)
- [API](https://github.com/hop-top/pact-rs#api)
- [Conformance](https://github.com/hop-top/pact-rs#conformance)
- [Contributing](https://github.com/hop-top/pact-rs#contributing)
- [Security](https://github.com/hop-top/pact-rs#security)
- [License](https://github.com/hop-top/pact-rs#license)

[PACT](https://github.com/hop-top/spec-pact) is a protocol
for agent profiles, intent, reputation and adaptive admission: a gateway admits an agent's
signed, purpose-bound request, and native authorization stays final. This crate is its Rust
SDK for the core of the protocol: the wire objects and the primitives every implementation
shares. Its modules follow the `core` packages of the Go reference implementation,
[pact-go](https://github.com/hop-top/pact-go), and read the same conformance fixtures.

## Install

```sh
cargo add hop-top-pact
```

The library name is `hop_top_pact`.

Requirements: Rust 1.88 or later; CI tests Rust 1.88 and the latest stable release on Linux,
and the latest stable release on Windows. Dependencies: `p256` (ECDSA), `sha2`, `base64`, `serde`, `serde_json`,
`jsonschema` (with its default features off, so it never fetches a schema over the network)
and `regex`; none of them compiles C code. The crate has no `unsafe` code.

## Usage

Sign a payload as a requirement publisher, verify it as a gateway that trusts the publisher's
key, and compute an object digest:

```rust
use std::collections::HashMap;

use hop_top_pact::core::digest::object_digest_json;
use hop_top_pact::core::jws::p256::ecdsa::SigningKey;
use hop_top_pact::core::jws::{self, Header, KeySet, Role, StaticResolver, TYP_REQUIREMENTS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A requirement publisher signs a payload with its P-256 key (ES256).
    // Load the key from your key store; a fixed scalar keeps the example short.
    let key = SigningKey::from_slice(&[0x11; 32])?;
    let payload = br#"{"pact_version":"0.1","jti":"contract-1"}"#;
    let header = Header { typ: TYP_REQUIREMENTS.into(), kid: "publisher-1".into(), ..Header::default() };
    let compact = jws::sign(&header, payload, &key)?;

    // A gateway that trusts the publisher's public key verifies the compact JWS.
    let mut publisher = jws::public_jwk(key.verifying_key());
    publisher.kid = "publisher-1".into();
    let trusted = StaticResolver {
        key_sets: HashMap::from([(Role::RequirementPublisher, KeySet::new([publisher])?)]),
        ..StaticResolver::default()
    };
    let parsed = jws::verify(&compact, &trusted)?;
    println!("{} {} {}", parsed.role, parsed.header.kid, String::from_utf8(parsed.payload)?);

    // Object digest: unpadded base64url SHA-256 of the RFC 8785 canonical form.
    println!("{}", object_digest_json(br#"{"jti":"contract-1","pact_version":"0.1"}"#)?);
    Ok(())
}
```

```text
requirement-publisher publisher-1 {"pact_version":"0.1","jti":"contract-1"}
J0GfvClw7hrBhHyvkkriLn5ZbdWqmdwQtBHF_DZCYo4
```

The program is
[examples/sign_verify.rs](https://github.com/hop-top/pact-rs/blob/main/examples/sign_verify.rs);
run it with `cargo run --example sign_verify`.

Decode what a peer sends with `core::strictjson`, which applies the JSON rules of the draft
before any value reaches your type:

```rust
use hop_top_pact::core::Intent;
use hop_top_pact::core::strictjson::{self, Kind, Limits};

let err = strictjson::unmarshal::<Intent>(br#"{"intent_id":"a","intent_id":"b"}"#, Limits::default())
    .unwrap_err();
assert_eq!(err.kind, Kind::DuplicateKey);
assert_eq!(err.path, "/intent_id");
```

## Limitations

- The protocol is a draft. Its specification claims no interoperability suite and no
  independent security assessment.
- ES256 is the only signature algorithm. Ed25519, optional in the draft, is not implemented:
  `core::jws` rejects Ed25519 keys and signatures.
- The crate covers the core of the protocol only. It has no HTTP request binding, no native
  adapter contract or adapters, and no requirement contracts, holder, validator, gateway
  middleware, reputation service or conformance runner. Use
  [pact-go](https://github.com/hop-top/pact-go) for those.

## API

Every module carries its reference in its documentation, on
[docs.rs/hop-top-pact](https://docs.rs/hop-top-pact) or with `cargo doc --open`. Each one
mirrors the Go package of the same path, documented at
[pkg.go.dev/hop.top/pact-go](https://pkg.go.dev/hop.top/pact-go).

| Module | What it gives |
|---|---|
| `hop_top_pact::core` | the wire objects, one struct per definition of the PACT JSON Schema, their enums, `Digest` and the limits of the draft |
| `core::strictjson`, `core::jcs`, `core::digest` | strict JSON decoding into any `serde` type, RFC 8785 canonicalization, and the object, artifact and bytes digests |
| `core::jws` | compact JWS signing and verification under the PACT profile (ES256), JWKs, key sets, resolvers and RFC 7638 thumbprints |
| `core::clock` | a replaceable clock and the time rules of the draft: validity windows, lifetimes, presentation age and replay retention |
| `core::schema` | validation against the bundled PACT JSON Schema, with the `uri` format checker every PACT SDK shares |

## Conformance

The language-neutral fixtures of the [specification](https://github.com/hop-top/spec-pact)
(`v1.0/fixtures`, indexed by `v1.0/fixtures/manifest.json`) run against this crate in the
source repository, through the harness `cargo run --example vectors`. A failure fails CI for:

- the shared vectors of `strictjson`, `jcs`, `digest`, `jws` and `schema`;
- the key fixtures, except the Ed25519 key;
- the schema cases (`parse`, `schema`).

The HTTP binding vectors and the adapter cases are outside the scope of this crate. The
evaluation, outcome and learning cases judge an implementation under test, and are run with
`pactc` of [hop-top/pact](https://github.com/hop-top/pact).

## Contributing

Changes land in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) under `rs/`; this
mirror accepts no issues or pull requests. See
[CONTRIBUTING.md](https://github.com/hop-top/poly-pact/blob/next/CONTRIBUTING.md) and the
[code of conduct](https://github.com/hop-top/poly-pact/blob/next/CODE_OF_CONDUCT.md).

From `rs/`:

```sh
cargo test
```

`Cargo.toml` pins every dependency to an exact version and `Cargo.lock` holds the whole tree.
From the repository root, `make rs-lint rs-test rs-vectors rs-check-schema rs-build` runs the
checks CI runs.

## Security

Report vulnerabilities to security@hop.top, not in a public issue; see
[SECURITY.md](https://github.com/hop-top/poly-pact/blob/next/SECURITY.md).

## License

MIT, © 2026 Idea Crafters LLC and Jad Bitar. See
[LICENSE](https://github.com/hop-top/pact-rs/blob/main/LICENSE).
