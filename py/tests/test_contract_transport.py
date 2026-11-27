"""The transport a contract names. Port of go/contract/transport_test.go."""

from __future__ import annotations

from typing import Any

import pytest

from hop_top_pact import contract
from hop_top_pact.core import strictjson
from hop_top_pact.core.enums import Mode
from hop_top_pact.core.types import JSONObject, RequirementContract

STDIO = (
    b'{"channels":["uds"],"framing":"ndjson","identity_assurance":["kernel-peer"],'
    b'"max_frame_bytes":360448,"transport_profile":"stdio-ipc","version":"0.1"}'
)


def ext(**members: bytes) -> JSONObject:
    parsed = strictjson.parse(
        b"{" + b",".join(b'"%s":%s' % (k.encode(), v) for k, v in members.items()) + b"}"
    )
    assert isinstance(parsed, dict)
    return parsed


def claims_with(extensions: JSONObject | None) -> RequirementContract:
    return RequirementContract(
        pact_version="0.1",
        iss="",
        sub="",
        aud="",
        jti="",
        iat=0,
        nbf=0,
        exp=0,
        tenant_id="",
        contract_id="",
        environment_id="",
        holder_jkt="",
        operation_digest="",
        intent_digest="",
        base_revision="",
        selected_set="",
        field_rules=(),
        context_checks=(),
        learning_policy_digest="",
        learning_artifact_digest="",
        nonce="",
        mode=Mode.ENFORCED,
        extensions=extensions,
    )


CASES: list[tuple[str, JSONObject | None, str]] = [
    ("no extensions", None, "https"),
    (
        "other extension",
        {"https://ext.example/pact/hint": {"transport_profile": "stdio-ipc"}},
        "https",
    ),
    (
        "stdio-ipc declaration",
        {"pact-transport-profile-v1": strictjson.parse(STDIO)},
        "stdio-ipc",
    ),
    ("no transport_profile", ext(**{"pact-transport-profile-v1": b'{"version":"0.1"}'}), ""),
    ("not an object", ext(**{"pact-transport-profile-v1": b'"stdio-ipc"'}), ""),
    ("not a string", ext(**{"pact-transport-profile-v1": b'{"transport_profile":7}'}), ""),
    ("null profile", ext(**{"pact-transport-profile-v1": b'{"transport_profile":null}'}), ""),
]


@pytest.mark.parametrize(("name", "extensions", "want"), CASES, ids=[c[0] for c in CASES])
def test_transport(name: str, extensions: JSONObject | None, want: str) -> None:
    # The transport a contract names is the transport_profile of the
    # TransportDeclaration its extensions carry under pact-transport-profile-v1, or
    # the HTTPS baseline when they carry none (draft 13.3.1, Appendix A.2); a
    # declaration that names no transport profile names no transport, which no channel
    # matches.
    c = contract.Contract(compact="", claims=claims_with(extensions), digest="")
    assert c.transport() == want
    r = contract.Requirements(
        policy=contract.Policy(),
        selected_set="",
        conservative_set="",
        field_rules=(),
        context_checks=(),
        mode=Mode.ENFORCED,
        extensions=extensions,
    )
    assert r.transport() == want


def test_identifiers() -> None:
    assert contract.EXTENSION_TRANSPORT_PROFILE == "pact-transport-profile-v1"
    assert contract.TRANSPORT_HTTPS == "https"
    assert contract.TRANSPORT_STDIO_IPC == "stdio-ipc"


@pytest.mark.parametrize(
    ("case", "want"),
    [
        ("transport/stdio-ipc-contract-over-https", "stdio-ipc"),
        ("transport/https-contract-over-stdio-ipc", "https"),
        ("admission/valid", "https"),
    ],
)
def test_transport_of_fixtures(ck: Any, case: str, want: str) -> None:
    # The signed contracts of the transport cases name the transports their decoded
    # files declare.
    c = ck.b4_verifier().verify(ck.compact_of(f"{case}/signed/contract.jws"), ck.at(1792080000))
    assert c.transport() == want
