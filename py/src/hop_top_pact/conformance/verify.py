"""Verification of the committed signed files of a directory. Mirrors
go/runner/evalcase/verify.go."""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hop_top_pact.conformance.dirs import Dir, at
from hop_top_pact.conformance.errors import CaseError, wrap
from hop_top_pact.conformance.keys import Key
from hop_top_pact.conformance.types import Authenticated, TrustRecord
from hop_top_pact.conformance.walk import File, walk
from hop_top_pact.core import jcs, strictjson
from hop_top_pact.core.jws import (
    JWK,
    Role,
    StaticResolver,
    Verifier,
    new_key_set,
    parse_jwk,
    typ_role,
)
from hop_top_pact.errors import PactError

__all__ = ["Signed", "verify"]


@dataclass(frozen=True, slots=True)
class Signed:
    """A committed signed file of a directory, in signing.json order: the artifacts,
    then the presentations."""

    path: str
    """The signed file, relative to the directory."""
    typ: str
    compact: str
    payload: bytes
    """The decoded payload the compact JWS carries."""
    trust: Exception | None
    """None when the compact JWS verifies against the directory's trust records: for a
    service-signed artifact, under a key of a trust record of the typ's signer role
    whose iss is the payload's iss; for a presentation, by the embedded key whose
    thumbprint is the authenticated holder_jkt of native_context.json. Otherwise the
    failure, a JWSError whose reason jws.reason_of returns. A case may fail it by
    design, as a payload_signed entry always does."""


@dataclass(frozen=True, slots=True)
class _Trust:
    trust: tuple[TrustRecord, ...] = ()


@dataclass(frozen=True, slots=True)
class _Auth:
    authenticated: Authenticated | None = None


def verify(fixtures: str | os.PathLike[str], d: Dir, keys: dict[str, Key]) -> list[Signed]:
    """Check the committed signed files of the directory d against the generator
    contract and return them, each with its trust result. The trust records are the
    trust member of the directory's config.json; the holder_jkt, read when the
    directory has a presentation, is the authenticated member's of its
    native_context.json. Raise CaseError when a signed file is stale, that is not what
    the generator keeps (File.check), or when a decoded file's digests are not those
    the generator sets."""
    root = Path(fixtures)
    dir = at(root, d.path)
    try:
        trust = _read_member(dir / "config.json", "trust", _Trust).trust
    except (PactError, OSError) as e:
        raise wrap(d.id + "/config.json", e) from e
    jkt = ""
    if d.signing.presentations:
        try:
            auth = _read_member(dir / "native_context.json", "authenticated", _Auth)
        except (PactError, OSError) as e:
            raise wrap(d.id + "/native_context.json", e) from e
        if auth.authenticated is not None:
            jkt = auth.authenticated.holder_jkt or ""
    return verify_dir(root, d, keys, trust, jkt)


def _read_member(path: Path, name: str, cls: type[Any]) -> Any:
    """The member name of the strict JSON object file path, decoded into the one-field
    dataclass cls; cls() when the file or member is missing."""
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return cls()
    obj = strictjson.parse(data)
    if not isinstance(obj, dict):
        raise CaseError("not a JSON object")
    if name not in obj:
        return cls()
    # The member alone, strictly: an object holding only it.
    try:
        return strictjson.decode(jcs.canonicalize_value({name: obj[name]}), cls)
    except strictjson.StrictJSONError as e:
        raise wrap(name, e) from e


def verify_dir(
    fixtures: Path, d: Dir, keys: dict[str, Key], trust: Sequence[TrustRecord], holder_jkt: str
) -> list[Signed]:
    """verify with the trust records and holder_jkt given."""
    dir = at(fixtures, d.path)
    out: list[Signed] = []

    def check(f: File) -> str:
        if f.digests_changed:
            raise CaseError(
                f"stale: the digests of {f.decoded} are not the artifact_digest values of"
                " the files they name; run pactfix generate"
            )
        compact = at(dir, f.signed).read_text(encoding="utf-8")
        f.check(compact)
        out.append(
            Signed(
                path=f.signed,
                typ=f.typ,
                compact=compact,
                payload=f.payload,
                trust=_trusted(fixtures, compact, f.typ, f.payload, trust, holder_jkt),
            )
        )
        return compact

    try:
        walk(fixtures, d, keys, check)
    except CaseError as e:
        raise wrap(d.id, e) from e
    return out


def _trusted(
    fixtures: Path,
    compact: str,
    typ: str,
    payload: bytes,
    trust: Sequence[TrustRecord],
    holder_jkt: str,
) -> Exception | None:
    """The failure of verifying compact as typ against the trust records and the
    enrolled holder_jkt, None when it verifies."""
    role = typ_role(typ)
    try:
        if role == Role.HOLDER:
            res = StaticResolver(expected_holder_jkt=holder_jkt)
        else:
            claims = strictjson.parse(payload)
            iss = claims.get("iss") if isinstance(claims, dict) else None
            if iss is not None and not isinstance(iss, str):
                return CaseError("payload iss is not a string")
            keys: list[JWK] = []
            for r in trust:
                if r.role != role or r.iss != (iss or ""):
                    continue
                for k in r.keys:
                    try:
                        jwk = parse_jwk(at(fixtures, k).read_bytes())
                    except PactError as e:
                        return wrap(k, e)
                    if not any(s.kid == jwk.kid and s.x == jwk.x and s.y == jwk.y for s in keys):
                        keys.append(jwk)
            res = StaticResolver(key_sets={role or "": new_key_set(*keys)})
        Verifier(keys=res, typ=typ).verify(compact)
    except (PactError, OSError) as e:
        return e
    return None
