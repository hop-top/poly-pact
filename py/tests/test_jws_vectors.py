"""The vectors under spec/v1.0/fixtures/vectors/jws. Port of go/core/jws/vectors_test.go.

Reads spec/v1.0/fixtures/manifest.json: fails when it is absent under
PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise (a mirror checkout).
signature_valid is recomputed with cryptography alone, so a vector rejected
for another reason does not also carry a bad signature by accident.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from hop_top_pact.core import VERSION, jws, limits, strictjson
from hop_top_pact.core.strictjson import Limits
from hop_top_pact.core.types import Evidence

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"
PREFIX = "vectors/jws/"
THUMBPRINT_ID = PREFIX + "thumbprint"
JWK_REJECT_ID = PREFIX + "jwk-reject"
KEYS_ID = PREFIX + "appendix-c-keys"
HOLDER_JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
VERIFY_FIELDS = [
    "compact",
    "decode_as",
    "description",
    "expect",
    "expected_holder_jkt",
    "expected_payload",
    "expected_typ",
    "id",
    "reject_reason",
    "signature_valid",
    "signer_jwk",
    "trusted_keysets",
]


def read_json(rel: str) -> Any:
    path = FIXTURES / rel
    if not path.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{path} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return strictjson.parse(path.read_bytes(), Limits(max_bytes=1 << 20))


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jws_entries() -> dict[str, dict[str, Any]]:
    out = {e["id"]: e for e in read_json("manifest.json")["entries"] if e["id"].startswith(PREFIX)}
    assert out, "manifest lists no vectors/jws entries"
    return out


def test_manifest_lists_every_jws_file() -> None:
    entries = jws_entries()
    listed = set()
    for eid, e in entries.items():
        assert (e["kind"], e["scope"]) == ("vector", "core"), eid
        assert e["spec_map_row"], eid
        assert e["draft_section"], eid
        assert e["path"] == eid + ".json" == e["expected"], eid
        listed.add(e["path"])
    for p in sorted((FIXTURES / PREFIX).rglob("*")):
        if p.is_file() and p.name != "README.md":
            assert p.relative_to(FIXTURES).as_posix() in listed, p


# The vectors the draft requires, with their expected result, so deleting one or
# changing its expectation fails here.
REQUIRED_VECTORS = {
    "appendix-c": "accept",
    "appendix-c-version-mismatch": "payload-schema",
    "rfc7515-a3": "typ-unsupported",
    "header-alg-none": "alg-unsupported",
    "header-alg-hs256": "alg-unsupported",
    "header-alg-rs256": "alg-unsupported",
    "header-alg-ps256": "alg-unsupported",
    "header-alg-eddsa": "alg-unsupported",
    "header-jwk-private": "jwk-private",
    "header-jku": "header-jku",
    "header-x5u": "header-x5u",
    "header-x5c": "header-x5c",
    "header-crit": "header-crit",
    "header-b64-false": "header-b64",
    "payload-detached": "payload-detached",
    "header-jwk-p384": "jwk-curve",
    "header-jwk-off-curve": "jwk-off-curve",
    "holder-jkt-mismatch": "holder-jkt-mismatch",
    "es256-valid": "accept",
    "es256-noncanonical-payload": "accept",
    "es256-noncanonical-header": "accept",
    "es256-leading-zero-r": "accept",
    "es256-signature-63-bytes": "signature-length",
    "es256-signature-der": "signature-length",
    "es256-signature-padded": "base64url",
    "es256-high-s": "accept",
    "typ-requirements": "accept",
    "typ-evidence": "accept",
    "typ-presentation": "accept",
    "typ-admission": "accept",
    "typ-outcome": "accept",
    "typ-reputation": "accept",
    "typ-learning-policy": "accept",
    "typ-learning-artifact": "accept",
    "typ-learning-event": "accept",
    "typ-admission-signed-by-issuer": "kid-unknown",
}


def test_required_vectors() -> None:
    entries = jws_entries()
    for stem, want in REQUIRED_VECTORS.items():
        assert PREFIX + stem in entries, f"required vector {stem} is missing"
        v = read_json(entries[PREFIX + stem]["path"])
        got = v["reject_reason"] if v["reject_reason"] is not None else v["expect"]
        assert got == want, stem
    # Every typ of the draft 7.3 table has a required accept vector.
    for typ in jws.typs():
        stem = "typ-" + typ.removeprefix("pact-").removesuffix("+jwt")
        assert REQUIRED_VECTORS.get(stem) == "accept", typ


def lenient_verify(pub: ec.EllipticCurvePublicKey, signing_input: str, seg: str) -> bool:
    s = seg.replace("\r", "").replace("\n", "").replace("=", "")
    s = s.replace("+", "-").replace("/", "_")
    try:
        sig = b64d(s)
    except ValueError:
        return False
    if len(sig) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    try:
        pub.verify(der, signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def check_signature_valid(v: dict[str, Any]) -> None:
    parts = v["compact"].split(".")
    got: bool | None = None
    signer = v["signer_jwk"]
    if (
        len(parts) == 3
        and isinstance(signer, dict)
        and signer.get("kty") == "EC"
        and signer.get("crv") == "P-256"
    ):
        k = jws.parse_jwk(json.dumps(signer).encode())
        got = lenient_verify(jws.public_key_of(k), parts[0] + "." + parts[1], parts[2])
    assert got == v["signature_valid"], f"signature_valid {v['signature_valid']}, recomputed {got}"


def decode_as(typ: str, payload: bytes) -> str | None:
    """The artifact layer after a verification: a strict decode as typ and the
    pact_version constant of the schema; payload-schema when it refuses."""
    assert typ == "Evidence", f"decode_as {typ!r} is not handled"
    try:
        ev = strictjson.decode(payload, Evidence, limits.artifact_json(limits.defaults()))
    except strictjson.StrictJSONError:
        return "payload-schema"
    return None if ev.pact_version == VERSION else "payload-schema"


def run_verify_vector(v: dict[str, Any], e: dict[str, Any]) -> None:
    reject = v["reject_reason"]
    assert (v["expect"] == "accept" and reject is None and e["outcome"] == "ACCEPTED") or (
        v["expect"] == "reject" and reject is not None and e["outcome"] == "REJECTED"
    ), (v["expect"], reject, e["outcome"])
    sets: dict[jws.Role | str, jws.KeySet] = {}
    for role, keys in v["trusted_keysets"].items():
        sets[role] = jws.new_key_set(*(jws.parse_jwk(json.dumps(k).encode()) for k in keys))
    res = jws.StaticResolver(key_sets=sets, expected_holder_jkt=v["expected_holder_jkt"] or "")
    verifier = jws.Verifier(keys=res, typ=v["expected_typ"])
    check_signature_valid(v)
    reason: str | None = None
    payload = b""
    try:
        p = verifier.verify(v["compact"])
    except jws.JWSError as err:
        reason = str(jws.reason_of(err) or f"no reason: {err}")
    else:
        payload = p.payload
        if v["decode_as"] is not None:
            reason = decode_as(v["decode_as"], payload)
    if v["expect"] == "accept":
        assert reason is None, f"rejected ({reason}), want accept"
        assert payload == v["expected_payload"].encode()
        return
    assert reason == reject


def test_verify_vectors() -> None:
    entries = jws_entries()
    n = 0
    for eid, e in sorted(entries.items()):
        if eid in (THUMBPRINT_ID, JWK_REJECT_ID, KEYS_ID):
            continue
        n += 1
        v = read_json(e["path"])
        assert sorted(v) == VERIFY_FIELDS, eid
        assert v["id"] == eid
        try:
            run_verify_vector(v, e)
        except AssertionError as err:
            raise AssertionError(f"{eid}: {err}") from err
    assert n >= 40, f"only {n} verify vectors"


def test_thumbprint_vectors() -> None:
    e = jws_entries()[THUMBPRINT_ID]
    assert e["outcome"] == "ACCEPTED"
    seen = set()
    for v in read_json(e["path"]):
        seen.add(v["id"])
        k = jws.parse_jwk(json.dumps(v["jwk"]).encode())
        assert jws.thumbprint(k) == v["expected_thumbprint"], v["id"]
        if v["id"].startswith("appendix-c-holder"):
            assert v["expected_thumbprint"] == HOLDER_JKT
    for want in (
        "appendix-c-holder",
        "holder-with-optional-members",
        "holder-reordered-extra-member",
        "leading-zero-x",
    ):
        assert want in seen, f"thumbprint vector {want} missing"


def test_jwk_reject_vectors() -> None:
    e = jws_entries()[JWK_REJECT_ID]
    assert e["outcome"] == "REJECTED"
    vs = read_json(e["path"])
    assert len(vs) >= 10, f"only {len(vs)} jwk-reject vectors"
    for v in vs:
        got: jws.Reason | None = None
        try:
            jws.thumbprint(jws.parse_jwk(json.dumps(v["jwk"]).encode()))
        except jws.JWSError as err:
            got = jws.reason_of(err)
        assert got == v["reject_reason"], v["id"]


def test_appendix_c_key_vectors() -> None:
    vs = read_json(jws_entries()[KEYS_ID]["path"])
    assert len(vs) == 2, "want holder and issuer"
    for v in vs:
        d = b64d(v["d"])
        assert len(d) == 32, v["id"]
        key = ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())
        k = jws.public_jwk(key.public_key())
        assert (k.x, k.y) == (v["expected_x"], v["expected_y"]), v["id"]
        assert jws.thumbprint(k) == v["expected_thumbprint"], v["id"]
    assert vs[0]["expected_thumbprint"] == HOLDER_JKT
