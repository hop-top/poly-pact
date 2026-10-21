"""Appendix B examples through the strict decoder. Port of go/core/roundtrip_test.go.

Reads spec/v1.0/draft.md of the source repository: fails when it is absent under
PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise (a mirror
checkout). The re-encoding is json.dumps over the decoded dataclasses in
schema member order, with absent optional members left out (Go's omitzero)
and a two-space indent as in the draft examples.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core import Digest, Mode, strictjson, types
from hop_top_pact.core.strictjson import StrictJSONError, StrictJSONErrorKind
from hop_top_pact.core.types import AgentProfile, OperationContext, RequirementContract

DRAFT = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "draft.md"


def draft_block(section: str) -> bytes:
    """The first json fence under the Appendix B heading "### <section> "."""
    if not DRAFT.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{DRAFT} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    text = DRAFT.read_text(encoding="utf-8")
    m = re.search(
        r"(?m)^### "
        + re.escape(section)
        + r" [^\n]*\n(?:[^\n#][^\n]*\n|\n)*?```json\n(.*?)\n```\n",
        text,
        re.S,
    )
    assert m is not None, f"draft has no json block under {section}"
    return m.group(1).encode("utf-8")


def plain(v: Any) -> Any:
    """The JSON value of a decoded wire value, in schema member order."""
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        members: Mapping[str, Any] = type(v)._MEMBERS  # type: ignore[attr-defined]
        out = {}
        for name, m in members.items():
            x = getattr(v, name)
            if x is None and not m.required:
                continue
            out[name] = plain(x)
        return out
    if isinstance(v, Mapping):
        return {k: plain(x) for k, x in v.items()}
    if isinstance(v, tuple):
        return [plain(x) for x in v]
    return v


def encode(v: Any) -> bytes:
    return json.dumps(plain(v), indent=2, ensure_ascii=False).encode("utf-8")


@pytest.mark.parametrize(
    ("section", "cls"), [("B.3", OperationContext), ("B.4", RequirementContract)]
)
def test_round_trip_byte_stable(section: str, cls: type[Any]) -> None:
    src = draft_block(section)
    v = strictjson.decode(src, cls)
    got = encode(v)
    assert got == src, f"re-encode differs from the draft\n--- got\n{got.decode()}"


APPENDIX_B = [
    ("B.1", "AgentProfile"),
    ("B.2", "Intent"),
    ("B.3", "OperationContext"),
    ("B.4", "RequirementContract"),
    ("B.5", "Evidence"),
    ("B.6", "ReputationSnapshot"),
    ("B.7", "AdmissionAttestation"),
    ("B.8", "OutcomeReport"),
    ("B.9", "LearningPolicy"),
    ("B.10", "LearningArtifact"),
    ("B.11", "LearningEvent"),
    ("B.13", "GatewayMetadata"),
]


@pytest.mark.parametrize(("section", "name"), APPENDIX_B, ids=[s for s, _ in APPENDIX_B])
def test_appendix_b_decodes(section: str, name: str) -> None:
    # Every Appendix B artifact decodes strictly into its type, and
    # re-encoding loses and adds nothing.
    src = draft_block(section)
    v = strictjson.decode(src, getattr(types, name))
    assert type(v).__name__ == name
    assert json.loads(encode(v)) == json.loads(src)


def test_draft_digests_validate() -> None:
    c = strictjson.decode(draft_block("B.4"), RequirementContract)
    for name in (
        "holder_jkt",
        "operation_digest",
        "intent_digest",
        "learning_policy_digest",
        "learning_artifact_digest",
    ):
        Digest(getattr(c, name)).validate()
    assert c.mode == Mode.ENFORCED
    assert Mode.is_valid(c.mode)


def test_duplicate_key_rejected() -> None:
    src = draft_block("B.3").decode("utf-8")
    dup = src.replace(
        '"action": "invoice.read",', '"action": "invoice.read", "action": "invoice.write",', 1
    )
    assert '"invoice.write"' in dup, "could not build the duplicate-key input"
    with pytest.raises(StrictJSONError) as ei:
        strictjson.decode(dup.encode("utf-8"), OperationContext)
    assert ei.value.kind is StrictJSONErrorKind.DUPLICATE_KEY


def profile(revision: str) -> bytes:
    return (
        '{"profile_id":"p","revision":' + revision + ',"agent_id":"https://a.example/x",'
        '"operator_id":"https://o.example/x","tenant_id":"t",'
        '"holder_jkt":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","created_at":1,'
        '"expires_at":2,"attributes":{}}'
    ).encode("utf-8")


def test_core_integers_are_range_checked() -> None:
    for ok in ("1", "0", "9007199254740991"):
        assert strictjson.decode(profile(ok), AgentProfile).revision == int(ok)
    for bad in ("-1", "9007199254740992", "1.5", "1e3", "null", '"1"'):
        with pytest.raises(StrictJSONError):
            strictjson.decode(profile(bad), AgentProfile)


def test_open_maps_accept_additional_members() -> None:
    src = (
        '{"operation_id":"o","environment_id":"https://e.example/x",'
        '"principal_id":"https://p.example/x","action":"a",'
        '"resources":["https://r.example/x"],"method":"GET","target_uri":"https://t.example/x",'
        '"body_digest":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","headers":{"x-extra":"1"},'
        '"extensions":{"https://x.example/ext":{"k":[1,2]}}}'
    )
    op = strictjson.decode(src.encode("utf-8"), OperationContext)
    assert op.headers["x-extra"] == "1"
    assert op.extensions == {"https://x.example/ext": {"k": (1, 2)}}
    bare = src.replace(',"extensions":{"https://x.example/ext":{"k":[1,2]}}', "", 1)
    op2 = strictjson.decode(bare.encode("utf-8"), OperationContext)
    assert op2.extensions is None, "absent extensions decoded as a value"
    assert b'"extensions"' in encode(op)
    assert b'"extensions"' not in encode(op2)


def test_absent_required_members_take_go_zero_values() -> None:
    # As in Go, the decoder checks syntax and shape, not required members (a
    # schema validator does): an absent required member holds its zero value.
    op = strictjson.decode(b'{"operation_id":"o"}', OperationContext)
    assert op.operation_id == "o"
    assert (op.environment_id, op.resources, op.headers, op.extensions) == ("", (), {}, None)
    p = strictjson.decode(b"{}", AgentProfile)
    assert (p.revision, p.created_at, p.attributes) == (0, 0, {})
