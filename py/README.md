# PACT (Python SDK)

Purpose-bound Access Control & Trust: AI agents prove who they act for and why, on every request — on top of the auth you already run, from HTTP Basic and files to OAuth, LDAP, Entra, Kubernetes and AWS.

Python SDK: wire types, strict JSON, JCS, digests, ES256 JWS and the native adapter contract.

Read-only mirror of `py/` in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) (component
`pact-py`); open issues and pull requests there.

Status: prerelease. The protocol is a [draft](https://github.com/hop-top/spec-pact), and the API
may change between prerelease versions.

[![PyPI](https://img.shields.io/pypi/v/hop-top-pact)](https://pypi.org/project/hop-top-pact/)
[![ci-py](https://github.com/hop-top/poly-pact/actions/workflows/ci-py.yml/badge.svg)](https://github.com/hop-top/poly-pact/actions/workflows/ci-py.yml)

## Table of contents

- [Install](https://github.com/hop-top/pact-py#install)
- [Usage](https://github.com/hop-top/pact-py#usage)
- [Limitations](https://github.com/hop-top/pact-py#limitations)
- [API](https://github.com/hop-top/pact-py#api)
- [Conformance](https://github.com/hop-top/pact-py#conformance)
- [Contributing](https://github.com/hop-top/pact-py#contributing)
- [Security](https://github.com/hop-top/pact-py#security)
- [License](https://github.com/hop-top/pact-py#license)

[PACT](https://github.com/hop-top/spec-pact) is a protocol
for agent profiles, intent, reputation and adaptive admission: a gateway admits an agent's
signed, purpose-bound request, and native authorization stays final. This package is its Python
SDK. Its modules follow the packages of the Go reference implementation,
[pact-go](https://github.com/hop-top/pact-go), and read the same conformance fixtures.

## Install

```sh
pip install hop-top-pact
```

Import it as `hop_top_pact`; `pact` is the import name of the unrelated `pact-python`
distribution.

Requirements: Python 3.11 or later; CI tests 3.11 and the latest 3.x release on Linux, plus
Windows and macOS arm64. Dependencies: `cryptography`, `jsonschema` and `referencing`.
`cryptography` ships wheels for Linux (x86_64, aarch64 and others), macOS arm64 and Windows
amd64; on other platforms pip builds it from the sdist, which needs a Rust toolchain.

## Usage

Sign a payload as a requirement publisher, verify it as a gateway that trusts the publisher's
key, and compute an object digest:

```python
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.core.digest import object_digest
from hop_top_pact.core.jws import (
    TYP_REQUIREMENTS,
    Header,
    Role,
    StaticResolver,
    new_key_set,
    public_jwk,
    sign,
    verify,
)

# A requirement publisher signs a payload with its P-256 key (ES256).
key = ec.generate_private_key(ec.SECP256R1())
payload = b'{"pact_version":"0.1","jti":"contract-1"}'
compact = sign(Header(typ=TYP_REQUIREMENTS, kid="publisher-1"), payload, key)

# A gateway that trusts the publisher's public key verifies the compact JWS.
publisher = replace(public_jwk(key.public_key()), kid="publisher-1")
trusted = StaticResolver(key_sets={Role.REQUIREMENT_PUBLISHER: new_key_set(publisher)})
parsed = verify(compact, trusted)
print(parsed.role, parsed.header.kid, parsed.payload.decode())

# Object digest: unpadded base64url SHA-256 of the RFC 8785 canonical form.
print(object_digest({"jti": "contract-1", "pact_version": "0.1"}))
```

```text
requirement-publisher publisher-1 {"pact_version":"0.1","jti":"contract-1"}
J0GfvClw7hrBhHyvkkriLn5ZbdWqmdwQtBHF_DZCYo4
```

The program is
[examples/sign_verify.py](https://github.com/hop-top/pact-py/blob/main/examples/sign_verify.py);
run it with `python examples/sign_verify.py`.

## Limitations

- The protocol is a draft. Its specification claims no interoperability suite and no
  independent security assessment.
- ES256 is the only signature algorithm. Ed25519, optional in the draft, is not implemented:
  `core.jws` rejects Ed25519 keys and signatures.
- The package has no requirement contracts, holder, validator, gateway middleware, reputation
  service or conformance runner, and no native adapter other than the in-memory one. Those are
  in [pact-go](https://github.com/hop-top/pact-go).
- `adapters.memory` keeps its native stores in the process; it is the reference adapter for
  tests and the adapter conformance suite.

## API

Every module carries its reference in its docstrings, for example
`python -m pydoc hop_top_pact.core.jws`. Each one mirrors the Go package of the same path,
documented at [pkg.go.dev/hop.top/pact-go](https://pkg.go.dev/hop.top/pact-go).

| Module | What it gives |
|---|---|
| `hop_top_pact.core` | dataclasses of the wire objects, enums and limits; re-exported by `hop_top_pact` |
| `core.strictjson`, `core.jcs`, `core.digest`, `core.clock` | strict JSON decoding, RFC 8785 canonicalization, the object, artifact and bytes digests, and the time rules of the draft |
| `core.schema` | the `uri` format checker for validation against the PACT JSON Schema with `jsonschema` |
| `core.jws` | compact JWS signing and verification under the PACT profile (ES256), JWKs, key resolution and RFC 7638 thumbprints |
| `core.binding` | the operation context of the baseline HTTP mapping, from a WSGI environ, an ASGI scope or a raw request |
| `adapter` | the native adapter contract, with `enroll` (agent enrollment registry) and `freshness` (field-rule age limits) |
| `adapter.adaptertest` | the adapter conformance suite |
| `adapters.memory` | the in-memory reference adapter |
| `runner.manifest` | reading and checking the fixture manifest |
| `conformance` | evaluation-case loading for an implementation under test |
| `errors` | `PactError`, the root of the package's exceptions |

## Conformance

The language-neutral fixtures of the [specification](https://github.com/hop-top/spec-pact)
(`v1.0/fixtures`, indexed by `v1.0/fixtures/manifest.json`) run against this package through
the harness `python -m hop_top_pact.vectors`. CI requires these to pass:

- the shared vectors of `strictjson`, `jcs`, `digest`, `jws`, `schema` and `binding`;
- the key fixtures, except the Ed25519 key;
- the common adapter cases (`adapters/_common`), run by `adapter.adaptertest` against
  `adapters.memory`.

The harness does not run the schema cases (`parse`, `schema`). The evaluation, outcome and
learning cases judge an implementation under test, and are run with `pactc` of
[hop-top/pact](https://github.com/hop-top/pact).

## Contributing

Changes land in [hop-top/poly-pact](https://github.com/hop-top/poly-pact) under `py/`; this
mirror accepts no issues or pull requests. See
[CONTRIBUTING.md](https://github.com/hop-top/poly-pact/blob/next/CONTRIBUTING.md) and the
[code of conduct](https://github.com/hop-top/poly-pact/blob/next/CODE_OF_CONDUCT.md).

From `py/`, in a virtual environment:

```sh
python -m pip install -c constraints.txt -e ".[dev]"
python -m pytest
```

`pyproject.toml` holds the dependency ranges and `constraints.txt` the exact versions. From the
repository root, `make py-lint py-test py-vectors py-check-schema py-build` runs the checks CI
runs.

## Security

Report vulnerabilities to security@hop.top, not in a public issue; see
[SECURITY.md](https://github.com/hop-top/poly-pact/blob/next/SECURITY.md).

## License

MIT, © 2026 Idea Crafters LLC and Jad Bitar. See
[LICENSE](https://github.com/hop-top/pact-py/blob/main/LICENSE).
