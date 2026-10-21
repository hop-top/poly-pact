"""The profile against the draft: the section 7.3 typ table, the section 20.1 frame
minimum and the Appendix C keys and JWS. Port of go/core/jws/draft_test.go, plus
TestSignMatchesAppendixCHeader of sign_test.go, which reads the same appendix.

It reads spec/v1.0/draft.md and spec/v1.0/fixtures: it fails when they are absent under
PACT_REQUIRE_VECTORS=1 (make py-test) and skips otherwise (a mirror checkout).
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.core import VERSION, jws, limits, strictjson
from hop_top_pact.core.types import Evidence

REPO = Path(__file__).resolve().parents[2]
DRAFT = REPO / "spec" / "v1.0" / "draft.md"
FIXTURES = REPO / "spec" / "v1.0" / "fixtures"
HOLDER_JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"


def require(path: Path) -> Path:
    if not path.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{path} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return path


def read_draft() -> str:
    return require(DRAFT).read_text(encoding="utf-8")


def section(draft: str, start: str, end: str) -> str:
    """The draft text from the heading start up to the heading end."""
    i = draft.find(start)
    assert i >= 0, f"draft has no {start!r}"
    j = draft.find(end, i)
    assert j >= 0, f"draft has no {end!r} after {start!r}"
    return draft[i:j]


def fenced(text: str, marker: str, lang: str) -> str:
    """The body of the first fenced block of lang after marker."""
    i = text.find(marker)
    assert i >= 0, f"no {marker!r}"
    open_ = "```" + lang + "\n"
    j = text.find(open_, i)
    assert j >= 0, f"no {lang} block after {marker!r}"
    body = text[j + len(open_) :]
    k = body.find("\n```")
    assert k >= 0, f"unterminated {lang} block after {marker!r}"
    return body[:k]


def appendix_c() -> str:
    return section(read_draft(), "## Appendix C.", "## Appendix D.")


def appendix_c_compact() -> str:
    return fenced(appendix_c(), "Exact compact evidence JWS:", "text").strip()


def appendix_b5() -> str:
    return fenced(read_draft(), "### B.5 Runtime evidence", "json")


def scalar_key(n: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(n, ec.SECP256R1())


def fixture_jwk(name: str) -> jws.JWK:
    return jws.parse_jwk(require(FIXTURES / "keys" / f"{name}.jwk.json").read_bytes())


def want_reason(f: Callable[[], object], want: jws.Reason) -> jws.JWSError:
    with pytest.raises(jws.JWSError) as info:
        f()
    assert jws.reason_of(info.value) == want, str(info.value)
    return info.value


# The "Required signer" cells of the draft 7.3 table and their roles. A changed
# cell fails test_typ_table_matches_draft until it is mapped.
SIGNER_ROLES = {
    "Gateway-authorized requirement publisher": jws.Role.REQUIREMENT_PUBLISHER,
    "Issuer authorized for its claim paths and scope": jws.Role.ISSUER,
    "Enrolled agent holder key": jws.Role.HOLDER,
    "Gateway-authorized validator": jws.Role.VALIDATOR,
    "Authorized reporter for the observation type": jws.Role.REPORTER,
    "Authorized reputation service": jws.Role.REPUTATION_SERVICE,
    "Native administrator or delegated policy authority": jws.Role.POLICY_AUTHORITY,
    "Authorized learning controller": jws.Role.LEARNING_CONTROLLER,
    "Controller authorized for that transition": jws.Role.LEARNING_CONTROLLER,
}


def test_typ_table_matches_draft() -> None:
    table = section(read_draft(), "### 7.3 Artifact types and claims", "### 7.4")
    rows = re.findall(r"(?m)^\| ([^|]+?) \| `([^`]+)` \| ([^|]+?) \|$", table)
    assert rows, "no typ rows found in draft 7.3"
    typs = []
    for _, typ, signer in rows:
        typs.append(typ)
        assert signer in SIGNER_ROLES, f"draft 7.3 signer {signer!r} (typ {typ}) has no role"
        assert jws.typ_role(typ) == SIGNER_ROLES[signer], typ
    assert list(jws.typs()) == typs
    for typ in ("", "JWT", "pact-profile+jwt", "pact-evidence+JWT"):
        assert jws.typ_role(typ) is None, typ
    # The constants name the same values, in the table's order.
    assert typs == [
        jws.TYP_REQUIREMENTS,
        jws.TYP_EVIDENCE,
        jws.TYP_PRESENTATION,
        jws.TYP_ADMISSION,
        jws.TYP_OUTCOME,
        jws.TYP_REPUTATION,
        jws.TYP_LEARNING_POLICY,
        jws.TYP_LEARNING_ARTIFACT,
        jws.TYP_LEARNING_EVENT,
    ]


def test_default_max_compact_bytes_matches_draft() -> None:
    # Section 20.1: the frame minimum covers an encoded 256 KiB payload plus the
    # JOSE header and signature.
    assert "349526 + 10922 = 360448" in read_draft()
    assert jws.DEFAULT_MAX_COMPACT_BYTES == 360448


def test_appendix_c_keys() -> None:
    """The public keys of P-256 scalars 1 (holder) and 2 (issuer) are the JWKs printed in
    Appendix C, and the holder thumbprint is the printed holder_jkt."""
    c = appendix_c()
    issuer_printed = fenced(c, "Issuer public JWK", "json")
    holder_printed = strictjson.parse(
        fenced(c, "Holder public JWK and thumbprint", "json").encode()
    )
    assert isinstance(holder_printed, dict)
    hp_jwk = holder_printed["jwk"]
    assert isinstance(hp_jwk, dict)
    ip = jws.parse_jwk(issuer_printed.encode())
    for scalar, x, y in ((1, hp_jwk["x"], hp_jwk["y"]), (2, ip.x, ip.y)):
        k = jws.public_jwk(scalar_key(scalar).public_key())
        assert (k.x, k.y) == (x, y), f"scalar {scalar}"
        if scalar == 1:
            assert jws.thumbprint(k) == holder_printed["holder_jkt"] == HOLDER_JKT
    assert ip.kid == "test-issuer-key-1"


def test_appendix_c_jws() -> None:
    """The exact compact evidence JWS of Appendix C verifies under the printed issuer JWK
    and meets every expectation the appendix states."""
    c = appendix_c()
    issuer = jws.parse_jwk(fenced(c, "Issuer public JWK", "json").encode())
    res = jws.StaticResolver(key_sets={jws.Role.ISSUER: jws.new_key_set(issuer)})
    p = jws.Verifier(keys=res, typ=jws.TYP_EVIDENCE).verify(appendix_c_compact())
    assert (p.header.typ, p.role) == ("pact-evidence+jwt", jws.Role.ISSUER)
    assert p.payload == appendix_b5().encode()
    ev = strictjson.decode(p.payload, Evidence, limits.artifact_json(limits.defaults()))
    assert ev.pact_version == VERSION
    assert ev.sub == "https://identity.example/agents/invoice-assistant"
    assert [(cl.path, cl.value) for cl in ev.claims] == [
        ("/attributes/runtime/isolation", "managed")
    ]
    assert ev.holder_jkt == HOLDER_JKT
    # Not under the holder key.
    hk = fixture_jwk("holder")
    wrong = jws.StaticResolver(
        key_sets={
            jws.Role.ISSUER: jws.new_key_set(
                jws.JWK(kty=hk.kty, crv=hk.crv, x=hk.x, y=hk.y, kid="test-issuer-key-1")
            )
        }
    )
    want_reason(lambda: jws.verify(appendix_c_compact(), wrong), jws.Reason.SIGNATURE_INVALID)


def test_appendix_c_version_mismatch() -> None:
    """The earlier Appendix C JWS has a valid signature but carries pact_version 0.2,
    which the schema constant (0.1) rejects."""
    compact = require(FIXTURES / "parse" / "appendix-c-wrong-version.jws").read_text().strip()
    res = jws.StaticResolver(key_sets={jws.Role.ISSUER: jws.new_key_set(fixture_jwk("issuer"))})
    p = jws.Verifier(keys=res, typ=jws.TYP_EVIDENCE).verify(compact)
    ev = strictjson.decode(p.payload, Evidence, limits.artifact_json(limits.defaults()))
    assert ev.pact_version == "0.2"
    assert ev.pact_version != VERSION


def test_sign_matches_appendix_c_header() -> None:
    """The header sign writes for an evidence artifact is the protected header of the
    Appendix C JWS, byte for byte, and the payload is signed as given."""
    want = appendix_c_compact().split(".")
    compact = jws.sign(
        jws.Header(typ=jws.TYP_EVIDENCE, kid="test-issuer-key-1"),
        appendix_b5().encode(),
        scalar_key(2),
    )
    got = compact.split(".")
    assert got[0] == want[0]
    assert got[1] == want[1], "the payload bytes were changed"
