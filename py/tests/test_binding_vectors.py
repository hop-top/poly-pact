"""The binding vectors. Port of go/core/binding/vectors_test.go.

Go runs every vector twice: parsed from its HTTP/1.1 text by the net/http
server parser, and built field line by field line. Here the "decoded" leg is
the conformance path: the shared request decoder turns the vector's request
object into a RawRequest. The "asgi" leg hands the same request to
from_asgi as an ASGI server's scope, so the helper is exercised on every
vector too.
"""

from __future__ import annotations

import base64
import dataclasses
import os
import re
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.core import binding, digest, jcs, strictjson
from hop_top_pact.core.binding import RawRequest, RequestError, RequestErrorKind, Rule
from hop_top_pact.core.strictjson import Limits

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
PREFIX = "vectors/binding/"

# The vectors the binding vector set must hold, with the outcome each expects.
REQUIRED_VECTORS = {
    "bind-01-appendix-b3": "ACCEPTED",
    "bind-02-query-order-ab": "ACCEPTED",
    "bind-02-query-order-ba": "ACCEPTED",
    "bind-03-space-percent-20": "ACCEPTED",
    "bind-03-space-plus": "ACCEPTED",
    "bind-04-duplicate-key": "ACCEPTED",
    "bind-05-fragment": "REJECTED",
    "bind-06-userinfo": "REJECTED",
    "bind-07-content-encoding-gzip": "REJECTED",
    "bind-08-body-compact": "ACCEPTED",
    "bind-08-body-spaced": "ACCEPTED",
    "bind-09-header-plain": "ACCEPTED",
    "bind-09-header-case-and-whitespace": "ACCEPTED",
    "bind-10-header-not-allowlisted": "ACCEPTED",
    "bind-11-forwarding-headers": "ACCEPTED",
    "bind-12-default-port": "ACCEPTED",
    "bind-13-encoded-unreserved": "REJECTED",
    "bind-14-encoded-slash-path": "REJECTED",
    "bind-15-non-ascii-host": "REJECTED",
    "bind-16-repeated-header": "ACCEPTED",
    "bind-17-lowercase-hex-path": "REJECTED",
    "bind-17-lowercase-hex-query": "REJECTED",
    "bind-18-overlong-utf8": "REJECTED",
    "bind-18-invalid-utf8-query": "REJECTED",
    "bind-19-normal-form-query": "ACCEPTED",
    "bind-20-dot-segment": "REJECTED",
    "bind-20-dots-in-segment": "ACCEPTED",
    "bind-21-duplicate-host": "REJECTED",
    "bind-22-host-allowlisted": "REJECTED",
    "bind-23-missing-host": "REJECTED",
    "bind-24-invalid-host": "REJECTED",
}

# The rule this package names for each refused vector. The files carry only
# the draft 13.4 code, INVALID_MESSAGE.
VECTOR_RULE = {
    "bind-05-fragment": Rule.FRAGMENT,
    "bind-06-userinfo": Rule.USERINFO,
    "bind-07-content-encoding-gzip": Rule.CONTENT_ENCODING,
    "bind-13-encoded-unreserved": Rule.ENCODED_UNRESERVED,
    "bind-14-encoded-slash-path": Rule.ENCODED_SLASH,
    "bind-15-non-ascii-host": Rule.NON_ASCII_HOST,
    "bind-17-lowercase-hex-path": Rule.LOWERCASE_HEX,
    "bind-17-lowercase-hex-query": Rule.LOWERCASE_HEX,
    "bind-18-overlong-utf8": Rule.INVALID_UTF8,
    "bind-18-invalid-utf8-query": Rule.INVALID_UTF8,
    "bind-20-dot-segment": Rule.DOT_SEGMENT,
    "bind-21-duplicate-host": Rule.DUPLICATE_HOST,
    "bind-23-missing-host": Rule.MISSING_HOST,
    "bind-24-invalid-host": Rule.INVALID_HOST,
}

SPEC_MAP_ROW = re.compile(r"BIND-[0-9]{2}")


def read_json(rel: str) -> Any:
    path = FIXTURES / rel
    if not path.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{path} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return strictjson.parse(path.read_bytes(), Limits(max_bytes=1 << 20))


def binding_entries() -> list[Any]:
    m = read_json("manifest.json")
    assert m["manifest_version"] == 1
    out = [e for e in m["entries"] if e["id"].startswith(PREFIX)]
    assert out, "manifest lists no binding vectors"
    return out


def test_binding_vectors_listed() -> None:
    # Every file under vectors/binding is in the manifest, every required
    # vector is there with its outcome, and each entry has the form the
    # vectors README gives.
    listed = set()
    for e in binding_entries():
        stem = e["id"].removeprefix(PREFIX)
        listed.add(stem)
        assert (e["kind"], e["scope"]) == ("vector", "adapter"), e["id"]
        assert e["path"] == e["id"] + ".json", e["id"]
        assert e["expected"] == e["path"], e["id"]
        assert SPEC_MAP_ROW.fullmatch(e["spec_map_row"]), e["id"]
        assert e["draft_section"] == "10.2", e["id"]
        if stem in REQUIRED_VECTORS:
            assert e["outcome"] == REQUIRED_VECTORS[stem], e["id"]
    missing = sorted(set(REQUIRED_VECTORS) - listed)
    assert not missing, f"required vectors missing: {missing}"
    for f in sorted((FIXTURES / PREFIX).glob("*.json")):
        assert f.stem in listed, f"{PREFIX}{f.name} is not listed in manifest.json"


def asgi_request(req: Any) -> RawRequest | None:
    """The vector's request as an ASGI server's scope, through from_asgi.

    None when the target has an empty query, which a scope cannot carry.
    """
    target = req["raw_request_uri"].encode("utf-8")
    raw_path, sep, query = target.partition(b"?")
    if sep and not query:
        return None
    scope = {
        "type": "http",
        "method": req["method"].upper(),
        "path": "(decoded; not read)",
        "raw_path": raw_path,
        "query_string": query,
        "headers": [
            (h["name"].lower().encode("latin-1"), h["value"].encode("utf-8"))
            for h in req["headers"]
        ],
    }
    return binding.from_asgi(scope, base64.b64decode(req["body_b64"], validate=True))


def wire_value(op: Any) -> dict[str, Any]:
    out = {k: getattr(op, k) for k in type(op)._MEMBERS if getattr(op, k) is not None}
    out["headers"] = dict(out["headers"])
    return out


@pytest.mark.parametrize("leg", ["decoded", "asgi"])
def test_binding_vectors(leg: str) -> None:
    # Every binding vector through from_request.
    for e in binding_entries():
        v = read_json(e["path"])
        assert v["id"] == e["id"]
        run_binding_vector(e, v, leg)


def run_binding_vector(e: Any, v: Any, leg: str) -> None:
    where = f"{e['id']} ({leg})"
    expect = v["expect"]
    accept = bool(expect.get("operation_context"))
    config_error = expect.get("config_error") is True
    want_digest = v["expect_operation_digest"]
    if config_error:
        assert "reject_reason" not in expect, where
        assert e["outcome"] == "REJECTED", where
        assert want_digest is None, where
    elif accept:
        assert "reject_reason" not in expect, where
        assert e["outcome"] == "ACCEPTED", where
        assert want_digest is not None, where
    else:
        assert expect["reject_reason"] == "INVALID_MESSAGE", where
        assert e["outcome"] == "REJECTED", where
        assert want_digest is None, where
    c = v["config"]
    cfg = binding.Config(
        origin=c["origin"],
        header_allowlist=c["header_allowlist"],
        header_normalization_id=c["normalization_id"],
        mapping_version=c["mapping_version"],
        max_body=1 << 20,
    )
    req = binding.decode_request(v["request"]) if leg == "decoded" else asgi_request(v["request"])
    if req is None:
        return
    if config_error:
        # A configuration error, never a refused request (INVALID_MESSAGE).
        for call in (cfg.validate, lambda: binding.from_request(cfg, req, "p", "a", [])):
            with pytest.raises(RequestError) as info:
                call()
            assert info.value.kind is RequestErrorKind.INVALID_CONFIG, where
        return
    refused: RequestError | None = None
    try:
        op = binding.from_request(cfg, req, v["principal_id"], v["action"], v["resources"])
    except RequestError as err:
        refused = err
    if refused is not None:
        assert not accept, f"{where}: refused ({refused}), want an operation context"
        assert refused.kind is RequestErrorKind.INVALID_REQUEST, where
        want = VECTOR_RULE.get(e["id"].removeprefix(PREFIX))
        assert want is None or refused.rule is want, f"{where}: rule {refused.rule}, want {want}"
        return
    assert accept, f"{where}: got an operation context, want a refusal"
    op = dataclasses.replace(op, operation_id=v["operation_id"], environment_id=c["environment_id"])
    value = wire_value(op)
    got = jcs.canonicalize_value(value)
    assert got == jcs.canonicalize_value(expect["operation_context"]), where
    assert digest.object_digest(value) == want_digest, where
