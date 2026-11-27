"""Building and signing a presentation (draft 11.1 steps 4 and 5, 11.2)."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from hop_top_pact import contract
from hop_top_pact.adapter import Code
from hop_top_pact.core import VERSION, _wire, digest, jws, limits
from hop_top_pact.core.jws import base64url
from hop_top_pact.core.strictjson import StrictJSONError
from hop_top_pact.core.types import AgentProfile
from hop_top_pact.core.types import Presentation as PresentationClaims
from hop_top_pact.errors import PactError
from hop_top_pact.holder._artifact import (
    Snapshot,
    StoredEvidence,
    parse_evidence,
    parse_snapshot,
)
from hop_top_pact.holder._disclose import Disclosure, check_profile
from hop_top_pact.holder._errors import HolderError
from hop_top_pact.holder._keysource import KeySource
from hop_top_pact.holder._types import Input, Presentation

if TYPE_CHECKING:
    from hop_top_pact.holder._holder import Holder, HolderKey

__all__ = ["present"]

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def present(h: Holder, in_: Input, now: datetime) -> Presentation:
    """Holder.present."""
    lifetime, keys = h.check()
    k = h.key(keys)
    c = h.verified(in_.contract, in_.intent, in_.operation, k, now)
    check_profile(h, in_.profile, k, now)
    view, ev, rep = _view(h, in_, c, k, now)
    jti = _jti(h)
    d = now - _EPOCH
    iat = d.days * 86400 + d.seconds
    claims = PresentationClaims(
        pact_version=VERSION,
        iss=h.agent_id,
        sub=h.agent_id,
        aud=h.gateway,
        jti=jti,
        iat=iat,
        nbf=iat,
        exp=iat + lifetime,
        tenant_id=h.realm.tenant_id,
        contract=c.compact,
        profile=view,
        intent=in_.intent,
        operation=in_.operation,
        evidence=tuple(ev),
        reputation=rep,
        nonce=c.claims.nonce,
    )
    payload = _canonical(claims)
    try:
        limits.validate_presentation(limits.defaults(), claims, len(payload))
    except limits.LimitError as e:
        raise HolderError(Code.INVALID_MESSAGE, str(e)) from e
    compact = _sign(h, keys, k, payload)
    try:
        artifact = digest.artifact_digest(compact)
        profile_digest = digest.object_digest(view)
    except (ValueError, TypeError, PactError) as e:
        raise HolderError(Code.INVALID_MESSAGE, str(e)) from e
    return Presentation(
        compact=compact,
        claims=claims,
        contract=c,
        digest=artifact,
        profile_digest=profile_digest,
    )


def _view(
    h: Holder, in_: Input, c: contract.Contract, k: HolderKey, now: datetime
) -> tuple[AgentProfile, list[str], str | None]:
    """Build the disclosed profile and select the evidence and snapshot it needs."""
    evidence: list[StoredEvidence] = [parse_evidence(compact) for compact in in_.evidence]
    snap: Snapshot | None = parse_snapshot(in_.reputation) if in_.reputation else None
    d = Disclosure(h, k, now, in_.profile, evidence, snap)
    attrs = d.disclose(c.claims.field_rules)
    view = replace(in_.profile, attributes=attrs)
    try:
        limits.validate_profile_size(limits.defaults(), len(_canonical(view)))
    except limits.LimitError as err:
        raise HolderError(Code.INVALID_MESSAGE, str(err)) from err
    ev: list[str] = []
    for i, e in enumerate(d.evidence):
        if d.used[i] and e.compact not in ev:
            ev.append(e.compact)
    rep = snap.compact if snap is not None and d.snap_used else None
    return view, ev, rep


def _jti(h: Holder) -> str:
    """128 random bits, base64url without padding (Appendix A.2)."""
    try:
        b = h.random(16) if h.random is not None else os.urandom(16)
    except Exception as e:
        raise HolderError(Code.DEPENDENCY_UNAVAILABLE, f"random: {e}") from e
    if len(b) != 16:
        raise HolderError(Code.DEPENDENCY_UNAVAILABLE, f"random: {len(b)} bytes, want 16")
    return base64url.encode(b)


def _header_text(alg: str, jwk: jws.JWK) -> bytes:
    """The protected header of a presentation: alg, typ and the embedded public key, which
    the gateway accepts only after matching the enrolled holder_jkt (draft 7.2). It
    carries no kid."""
    members = [("kty", jwk.kty), ("crv", jwk.crv), ("x", jwk.x), ("y", jwk.y)]
    key = ",".join(f'"{n}":"{v}"' for n, v in members if v or n != "y")
    return f'{{"alg":"{alg}","typ":"{jws.TYP_PRESENTATION}","jwk":{{{key}}}}}'.encode()


def _sign(h: Holder, keys: KeySource, k: HolderKey, payload: bytes) -> str:
    """Have the key source sign the presentation and verify its signature as the gateway
    will: the embedded key's thumbprint is the holder key's (draft 6.2, 7.2)."""
    signing_input = base64url.encode(_header_text(k.alg, k.jwk)) + "." + base64url.encode(payload)
    try:
        sig = keys.sign(signing_input.encode("ascii"))
    except Exception as e:
        raise HolderError(Code.DEPENDENCY_UNAVAILABLE, f"key source: {e}") from e
    compact = signing_input + "." + base64url.encode(sig)
    v = jws.Verifier(
        keys=jws.StaticResolver(expected_holder_jkt=k.jkt),
        typ=jws.TYP_PRESENTATION,
        algorithms=h.algorithms,
    )
    try:
        v.verify(compact)
    except jws.JWSError as e:
        raise HolderError(
            Code.INVALID_PROOF, f"the key source's signature does not verify under its key: {e}"
        ) from e
    return compact


def _canonical(v: object) -> bytes:
    """The RFC 8785 form of v."""
    try:
        return _wire.payload(v)
    except (StrictJSONError, TypeError, ValueError) as e:
        raise HolderError(Code.INVALID_MESSAGE, str(e)) from e
