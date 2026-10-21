"""The vectors/jws group and the key rule.

The rules are spec/v1.0/fixtures/vectors/jws/README.md and keys/README.md.

Same contract as _groups: return on a pass, raise Fail or Skipped otherwise.
Only a JWSError counts as a rejection; a stub's NotImplementedError is a fail.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.core import jws, limits, strictjson
from hop_top_pact.core.types import Evidence
from hop_top_pact.vectors._common import (
    OUT_OF_SCOPE,
    Entry,
    Fail,
    Skipped,
    array,
    b64url,
    dump_json,
    obj,
    parse_json,
    read_fixture,
    read_json,
    single_file,
    string,
)

# The only pact_version value of the draft.
PACT_VERSION = "0.1"
# The reason the harness reports when a verified payload fails the artifact
# layer: a strict decode as the decode_as type and its pact_version.
PAYLOAD_SCHEMA = "payload-schema"

# The array files of vectors/jws; every other file holds one verify vector.
THUMBPRINT_ID = "vectors/jws/thumbprint"
JWK_REJECT_ID = "vectors/jws/jwk-reject"
KEYS_ID = "vectors/jws/appendix-c-keys"

VERIFY_MEMBERS = (
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
)

# The private test values, relative to the fixture directory.
KEY_SCALARS_PATH = "keys/test-private-scalars.json"
# The holder_jkt of draft Appendix C: the RFC 7638 thumbprint of the holder
# key, P-256 scalar 1.
APPENDIX_C_HOLDER_JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
KEY_RECORD_MEMBERS = ("role", "kid", "alg", "kty", "crv", "d", "public_jwk")


def reason(err: Exception) -> str:
    """The Reason of a rejection; a NotImplementedError is passed on as the failure it is."""
    if isinstance(err, NotImplementedError):
        raise err
    r = jws.reason_of(err)
    if r is None:
        raise Fail(f"error without a reason: {err!r}") from err
    return str(r)


def parse_jwk(raw: Any, where: str) -> jws.JWK:
    try:
        return jws.parse_jwk(dump_json(raw))
    except jws.JWSError as err:
        raise Fail(f"{where}: {err}") from err


def run_jws(root: Path, e: Entry) -> None:
    """Verify the vector's compact JWS with core.jws, or run one of the array files."""
    single_file(e)
    if e.id == THUMBPRINT_ID:
        run_thumbprints(root, e)
        return
    if e.id == JWK_REJECT_ID:
        run_jwk_rejects(root, e)
        return
    if e.id == KEYS_ID:
        run_keys(root, e)
        return
    v = obj(read_json(root, e.path), e.path, VERIFY_MEMBERS)
    if v["id"] != e.id:
        raise Fail(f"vector id {v['id']!r}, manifest id {e.id!r}")
    want_reason = v["reject_reason"]
    if not (
        (v["expect"] == "accept" and want_reason is None and e.outcome == "ACCEPTED")
        or (v["expect"] == "reject" and isinstance(want_reason, str) and e.outcome == "REJECTED")
    ):
        raise Fail(f"expect {v['expect']!r}, reject_reason and outcome {e.outcome!r} do not agree")
    keysets = v["trusted_keysets"]
    if not isinstance(keysets, dict):
        raise Fail("trusted_keysets: not an object")
    sets: dict[str, jws.KeySet] = {}
    for role, keys in keysets.items():
        if not isinstance(keys, list):
            raise Fail(f"trusted_keysets.{role}: not an array")
        parsed = [parse_jwk(k, f"trusted key for {role}") for k in keys]
        try:
            sets[role] = jws.new_key_set(*parsed)
        except jws.JWSError as err:
            raise Fail(f"key set for {role}: {err}") from err
    resolver = jws.StaticResolver(
        key_sets=sets,
        expected_holder_jkt=string(v["expected_holder_jkt"], "expected_holder_jkt", null=True),
    )
    typ = v["expected_typ"]
    verifier = jws.Verifier(
        keys=resolver, typ=string(typ, "expected_typ") if typ is not None else None
    )
    got: str | None = None
    payload = b""
    try:
        p = verifier.verify(string(v["compact"], "compact"))
    except Exception as err:
        got = reason(err)
    else:
        payload = p.payload
        if v["decode_as"] is not None:
            got = decode_artifact(string(v["decode_as"], "decode_as"), payload)
    if v["expect"] == "accept":
        if got is not None:
            raise Fail(f"rejected ({got}), want accept")
        want = v["expected_payload"]
        if not isinstance(want, str) or payload != want.encode("utf-8"):
            raise Fail(f"payload {payload!r} differs from expected_payload")
        return
    if got != want_reason:
        raise Fail(f"reason {got!r}, want {want_reason!r}")


def decode_artifact(typ: str, payload: bytes) -> str | None:
    """Apply the artifact layer after verification; payload-schema when it refuses."""
    if typ != "Evidence":
        raise Fail(f"decode_as {typ!r} is not handled")
    try:
        ev = strictjson.decode(payload, Evidence, limits.artifact_json(limits.defaults()))
    except strictjson.StrictJSONError:
        return PAYLOAD_SCHEMA
    return None if ev.pact_version == PACT_VERSION else PAYLOAD_SCHEMA


def run_thumbprints(root: Path, e: Entry) -> None:
    if e.outcome != "ACCEPTED":
        raise Fail(f"outcome {e.outcome!r} is not ACCEPTED")
    for i, raw in enumerate(array(read_json(root, e.path), e.path)):
        v = obj(raw, f"vector {i}", ("id", "jwk", "expected_thumbprint"), ("description", "source"))
        tp = jws.thumbprint(parse_jwk(v["jwk"], v["id"]))
        if tp != v["expected_thumbprint"]:
            raise Fail(f"{v['id']}: thumbprint {tp}, want {v['expected_thumbprint']}")


def run_jwk_rejects(root: Path, e: Entry) -> None:
    if e.outcome != "REJECTED":
        raise Fail(f"outcome {e.outcome!r} is not REJECTED")
    for i, raw in enumerate(array(read_json(root, e.path), e.path)):
        v = obj(raw, f"vector {i}", ("id", "jwk", "reject_reason"), ("description",))
        got: str | None = None
        try:
            jws.thumbprint(jws.parse_jwk(dump_json(v["jwk"])))
        except Exception as err:
            got = reason(err)
        if got != v["reject_reason"]:
            raise Fail(f"{v['id']}: reason {got!r}, want {v['reject_reason']!r}")


def private_key(d: bytes, where: str) -> ec.EllipticCurvePrivateKey:
    try:
        return ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())
    except ValueError as err:
        raise Fail(f"{where}: {err}") from err


def run_keys(root: Path, e: Entry) -> None:
    for i, raw in enumerate(array(read_json(root, e.path), e.path)):
        v = obj(
            raw,
            f"vector {i}",
            ("id", "d", "expected_x", "expected_y", "expected_thumbprint"),
            ("description",),
        )
        vid = v["id"]
        d = b64url(string(v["d"], "d"), vid)
        if len(d) != 32:
            raise Fail(f"{vid}: d is not 32 octets of base64url")
        k = jws.public_jwk(private_key(d, vid).public_key())
        if (k.x, k.y) != (v["expected_x"], v["expected_y"]):
            raise Fail(
                f"{vid}: derived x={k.x} y={k.y}, want x={v['expected_x']} y={v['expected_y']}"
            )
        tp = jws.thumbprint(k)
        if tp != v["expected_thumbprint"]:
            raise Fail(f"{vid}: thumbprint {tp}, want {v['expected_thumbprint']}")


def _p256(record: Mapping[str, Any]) -> bool:
    return record.get("kty") == "EC" and record.get("crv") == "P-256"


def _jwk_path(record: Mapping[str, Any]) -> str:
    return posixpath.join(posixpath.dirname(KEY_SCALARS_PATH), str(record.get("public_jwk")))


def run_key(root: Path, e: Entry) -> None:
    """The key rule of tools/parity/README.md (Key rule).

    A P-256 JWK passes when it parses as a public key and its point is its
    record's scalar times the base point, and, for the record of role
    holder, when its thumbprint is the holder_jkt of Appendix C. An Ed25519
    JWK is out of scope (optional, draft section 7.2). The entry of the
    scalars file passes when every P-256 record derives and a holder exists.
    """
    doc = obj(
        read_json(root, KEY_SCALARS_PATH),
        KEY_SCALARS_PATH,
        ("keys",),
        ("label", "warning", "encoding"),
    )
    records = [
        obj(r, f"keys[{i}]", KEY_RECORD_MEMBERS, ("scalar", "seed_hex"))
        for i, r in enumerate(array(doc["keys"], "keys"))
    ]
    if e.path == KEY_SCALARS_PATH:
        holder = False
        for r in records:
            if not _p256(r):
                continue
            try:
                check_key_record(root, r)
            except Fail as err:
                raise Fail(f"record of role {r['role']}: {err}") from err
            holder = holder or r["role"] == "holder"
        if not holder:
            raise Fail("no P-256 record of role holder, the key of Appendix C holder_jkt")
        return
    head = read_json(root, e.path)
    if isinstance(head, dict) and head.get("kty") == "OKP" and head.get("crv") == "Ed25519":
        raise Skipped(
            OUT_OF_SCOPE,
            "Ed25519 key: the algorithm is optional (draft section 7.2) and not verified here",
        )
    for r in records:
        if _jwk_path(r) == e.path:
            check_key_record(root, r)
            return
    raise Fail(f"no record in {KEY_SCALARS_PATH} names {posixpath.basename(e.path)}")


_DECIMAL = re.compile(r"[0-9]+")


def check_key_record(root: Path, r: Mapping[str, Any]) -> None:
    """Derive the public point of a P-256 record from d and compare it with its public JWK."""
    if not _p256(r):
        raise Fail(f"kty {r.get('kty')!r} crv {r.get('crv')!r}, want EC P-256")
    d = b64url(string(r["d"], "d"), "d")
    if len(d) != 32:
        raise Fail("d is not 32 octets of base64url")
    scalar = r.get("scalar")
    if (
        not isinstance(scalar, str)
        or not _DECIMAL.fullmatch(scalar)
        or not 0 < int(scalar) < 1 << 256
    ):
        raise Fail(f"scalar {scalar!r} is not a positive decimal integer")
    n = int(scalar)
    if int.from_bytes(d, "big") != n:
        raise Fail(f"d is not scalar {n} as 32 big-endian octets")
    want = jws.public_jwk(private_key(d, f"scalar {n}").public_key())
    rel = _jwk_path(r)
    raw = read_fixture(root, rel)
    try:
        parse_json(raw)
    except ValueError as err:
        raise Fail(f"{rel}: {err}") from err
    try:
        got = jws.parse_jwk(raw)
    except jws.JWSError as err:
        raise Fail(f"{rel}: {err}") from err
    if (got.x, got.y) != (want.x, want.y):
        raise Fail(
            f"{rel}: public point x={got.x} y={got.y},"
            f" but scalar {n} times G is x={want.x} y={want.y}"
        )
    if r["role"] == "holder":
        tp = jws.thumbprint(got)
        if tp != APPENDIX_C_HOLDER_JKT:
            raise Fail(
                f"{rel}: holder thumbprint {tp}, want Appendix C holder_jkt {APPENDIX_C_HOLDER_JKT}"
            )
