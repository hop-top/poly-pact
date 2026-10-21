"""The generator contract of signing.json applied to a signed directory: what each
signed file must carry and which key signs it. Mirrors go/runner/evalcase/walk.go and
digests.go."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hop_top_pact.conformance.dirs import Dir
from hop_top_pact.conformance.errors import CaseError, q, wrap
from hop_top_pact.conformance.keys import Key
from hop_top_pact.conformance.signing import (
    ABSENT,
    FIXED_TIME,
    PRESENTATION_LIFETIME,
    Artifact,
    Presentation,
)
from hop_top_pact.core import jcs, strictjson
from hop_top_pact.core.digest import artifact_digest
from hop_top_pact.core.jws import (
    JWK,
    TYP_EVIDENCE,
    TYP_PRESENTATION,
    TYP_REPUTATION,
    Header,
    Role,
    StaticResolver,
    Verifier,
    base64url,
    new_key_set,
    sign,
    thumbprint,
    typ_role,
)
from hop_top_pact.errors import PactError

__all__ = ["File", "read_decoded", "walk"]

# What a sign callback or a step of the walk may raise and walk wraps.
_ERRORS = (PactError, OSError, ValueError)


@dataclass(frozen=True, slots=True)
class File:
    """One signed file of a directory as the generator contract defines it: what its
    compact JWS must carry and which key signs it."""

    signed: str
    """The signed file, relative to the directory."""
    typ: str
    key: Key
    payload: bytes
    """What the compact JWS carries: the decoded file, with its digests set, or the
    presentation payload built from the case files."""
    over: bytes
    """What the signature covers: payload, or the payload_signed file."""
    decoded: str = ""
    """The artifact's decoded file, "" for a presentation."""
    digested: bool = False
    """Set when the artifact entry has digests: payload is then the decoded file with
    them set, which the generator writes back."""
    digests_changed: bool = False
    """payload differs from the decoded file read."""

    def _header(self) -> Header:
        """The protected header the generator writes: typ, and the kid of the signing
        key unless a holder signs (the key is then embedded)."""
        kid = "" if typ_role(self.typ) == Role.HOLDER else self.key.public.kid
        return Header(typ=self.typ, kid=kid)

    def sign(self) -> str:
        """A fresh compact JWS: the protected header, payload, and an ES256 signature
        over the header and over. ES256 signatures are randomized, so two calls differ
        in the signature only."""
        seg = sign(self._header(), self.over, self.key.private).split(".")
        return seg[0] + "." + base64url.encode(self.payload) + "." + seg[2]

    def check(self, compact: str) -> None:
        """Raise CaseError unless compact is a signed file the generator keeps
        (spec/v1.0/fixtures/README.md, section Signed artifacts): its protected header and
        payload are those sign writes, and its signature verifies over them, over over
        for a payload_signed entry, under the file's key. The error says what is
        stale."""
        if _signing_input(compact) != _signing_input(self.sign()):
            raise CaseError(
                "stale: its protected header or payload is not the one the generator writes"
            )
        if not _verifies(_resigned(compact, self.over), self.typ, self.key.public):
            raise CaseError(f"stale: its signature does not verify under the {self.key.role} key")


def _resigned(compact: str, over: bytes) -> str:
    """compact with its payload segment replaced by over, so that its signature can be
    checked over the payload it was computed on."""
    seg = compact.split(".")
    if len(seg) != 3:
        return compact
    return seg[0] + "." + base64url.encode(over) + "." + seg[2]


def _signing_input(compact: str) -> str:
    i = compact.rfind(".")
    return compact[:i] if i >= 0 else ""


def _verifies(compact: str, typ: str, jwk: JWK) -> bool:
    """Whether compact verifies as typ under jwk: by kid in a key set of the typ's
    role, or, for a holder, by the thumbprint of the embedded key."""
    role = typ_role(typ)
    try:
        if role == Role.HOLDER:
            res = StaticResolver(expected_holder_jkt=thumbprint(jwk))
        else:
            res = StaticResolver(key_sets={role or "": new_key_set(jwk)})
        Verifier(keys=res, typ=typ).verify(compact)
    except PactError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class _SignedArtifact:
    """An artifact signed earlier in a walk: its compact JWS, the payload that the JWS
    carries, and its typ."""

    compact: str
    payload: bytes
    typ: str


@dataclass(slots=True)
class _State:
    signed: dict[str, _SignedArtifact] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)


def walk(
    fixtures: str | os.PathLike[str],
    d: Dir,
    keys: dict[str, Key],
    sign: Callable[[File], str],
) -> None:
    """Apply the generator contract to the directory d of the fixture directory: for
    each entry of its signing.json, in order, read the decoded file (read_decoded),
    set its digests, check its jti and times, or build the presentation payload (draft
    Section 11.2), and call sign with the resulting File. sign returns the compact JWS
    that later entries embed or digest: the committed file or a fresh one. Raises
    CaseError."""
    dir = Path(fixtures).joinpath(*d.path.split("/"))
    st = _State()
    for a in d.signing.artifacts:
        f = _artifact(dir, a, st, keys)
        try:
            compact = sign(f)
        except _ERRORS as e:
            raise wrap(a.signed, e) from e
        st.signed[a.signed] = _SignedArtifact(compact, f.payload, a.typ)
        st.order.append(a.signed)
    for p in d.signing.presentations:
        try:
            sign(_presentation(dir, p, st, keys))
        except _ERRORS as e:
            raise wrap(p.signed, e) from e


def _artifact(dir: Path, a: Artifact, st: _State, keys: dict[str, Key]) -> File:
    payload = read_decoded(dir, a.decoded)
    if payload == b"null":
        raise CaseError(
            f"{a.decoded} is null: a decoded file whose content is null has no artifact entry"
        )
    digested = changed = False
    if a.digests:
        try:
            filled = _fill_digests(payload, a.digests, st.signed)
        except _ERRORS as e:
            raise wrap(a.decoded, e) from e
        digested, changed = True, filled != payload
        payload = filled
    _check_claims(a, payload)
    over = payload if a.payload_signed is None else read_decoded(dir, a.payload_signed)
    k = keys.get(a.signer)
    if k is None:
        raise CaseError(f"{a.decoded}: no test key for role {a.signer}")
    return File(
        signed=a.signed,
        typ=a.typ,
        key=k,
        payload=payload,
        over=over,
        decoded=a.decoded,
        digested=digested,
        digests_changed=changed,
    )


def _thaw(v: Any) -> Any:
    """A parsed value with lists and dicts in place of its tuples and mappings."""
    if isinstance(v, tuple | list):
        return [_thaw(x) for x in v]
    if isinstance(v, dict):
        return {k: _thaw(x) for k, x in v.items()}
    return v


def _fill_digests(
    payload: bytes, digests: dict[str, str] | Any, signed: dict[str, _SignedArtifact]
) -> bytes:
    """payload with the member that each RFC 6901 pointer of digests names set to the
    artifact_digest (draft Section 7.4) of the signed file its path names, which an
    earlier entry signed, in RFC 8785 canonical form."""
    doc = _thaw(strictjson.parse(payload))
    for ptr in sorted(digests):
        a = signed.get(digests[ptr])
        if a is None:
            raise CaseError(
                f"digests {ptr}: {digests[ptr]} is not the signed file of an earlier entry"
            )
        try:
            _set_pointer(doc, ptr, str(artifact_digest(a.compact)))
        except CaseError as e:
            raise wrap(f"digests {ptr}", e) from e
    return jcs.canonicalize_value(doc)


def _set_pointer(doc: Any, ptr: str, v: str) -> None:
    """Set the member or array element that the RFC 6901 pointer ptr names in doc to v.
    Every step but the last must exist; the last may add a member to an object, but
    only replace an element of an array."""
    if not ptr.startswith("/"):
        raise CaseError(f"{q(ptr)} does not name a member")
    tokens = ptr[1:].split("/")
    cur = doc
    for i, raw in enumerate(tokens):
        tok = raw.replace("~1", "/").replace("~0", "~")
        last = i == len(tokens) - 1
        if isinstance(cur, dict):
            if last:
                cur[tok] = v
                return
            if tok not in cur:
                raise CaseError(f"no member {q(tok)}")
            cur = cur[tok]
        elif isinstance(cur, list):
            n = int(tok) if tok.isdigit() and tok.isascii() else -1
            if n < 0 or n >= len(cur) or str(n) != tok:
                raise CaseError(f"no array element {q(tok)}")
            if last:
                cur[n] = v
                return
            cur = cur[n]
        else:
            raise CaseError(f"{q(tok)} is inside a value that is not an object or array")


def _object(payload: bytes, where: str) -> dict[str, Any]:
    v = strictjson.parse(payload)
    if not isinstance(v, dict):
        raise CaseError(f"{where}: not a JSON object")
    return v


def _member(obj: dict[str, Any], name: str, typ: type, where: str) -> Any:
    """The member name of obj as Go's json.Unmarshal into a field of typ reads it: None
    when absent or null, else a value of typ."""
    v = obj.get(name)
    if v is None:
        return None
    if not isinstance(v, typ) or (typ is int and isinstance(v, bool)):
        raise CaseError(f"{where}: {name} is not a {'string' if typ is str else 'integer'}")
    return v


def _embedded(st: _State, rel: str) -> _SignedArtifact:
    a = st.signed.get(rel)
    if a is None:
        raise CaseError(f"{rel} is not the signed file of an artifact entry")
    return a


def _presentation(dir: Path, p: Presentation, st: _State, keys: dict[str, Key]) -> File:
    """The presentation p built from the case files and the artifacts signed before it
    (draft Section 11.2)."""
    contract_path = "signed/contract.jws" if p.contract is None else p.contract
    try:
        contract = _embedded(st, contract_path)
    except CaseError as e:
        raise wrap("contract", e) from e
    claims = _object(contract.payload, f"contract {contract_path}")
    where = f"contract {contract_path}"
    pact_version = _member(claims, "pact_version", str, where) or ""
    aud = _member(claims, "aud", str, where) or ""
    nonce = _member(claims, "nonce", str, where) or ""

    evidence: list[str] = []
    reps: list[str] = []
    for rel in st.order:
        typ = st.signed[rel].typ
        if typ == TYP_EVIDENCE and p.evidence is None:
            evidence.append(st.signed[rel].compact)
        elif typ == TYP_REPUTATION:
            reps.append(rel)
    for rel in p.evidence or ():
        try:
            evidence.append(_embedded(st, rel).compact)
        except CaseError as e:
            raise wrap("evidence", e) from e
    reputation: str | None = None
    if p.reputation is ABSENT:
        if len(reps) > 1:
            raise CaseError(f"reputation: {len(reps)} snapshot artifacts; name one")
        if reps:
            reputation = st.signed[reps[0]].compact
    elif p.reputation is not None:
        if not isinstance(p.reputation, str):
            raise CaseError("reputation: not a path or null")
        try:
            reputation = _embedded(st, p.reputation).compact
        except CaseError as e:
            raise wrap("reputation", e) from e

    parts: dict[str, Any] = {}
    for name, file in (("profile", p.profile), ("intent", p.intent), ("operation", p.operation)):
        parts[name] = strictjson.parse(read_decoded(dir, name + ".json" if file is None else file))
    profile = parts["profile"]
    if not isinstance(profile, dict):
        raise CaseError("profile: not a JSON object")
    agent_id = _member(profile, "agent_id", str, "profile") or ""
    tenant_id = _member(profile, "tenant_id", str, "profile") or ""
    iat = FIXED_TIME if p.iat is None else p.iat
    nbf = iat if p.nbf is None else p.nbf
    exp = iat + PRESENTATION_LIFETIME if p.exp is None else p.exp
    payload = jcs.canonicalize_value(
        {
            "pact_version": pact_version,
            "iss": agent_id,
            "sub": agent_id,
            "aud": aud,
            "jti": p.jti,
            "iat": iat,
            "nbf": nbf,
            "exp": exp,
            "tenant_id": tenant_id,
            "contract": contract.compact,
            "profile": parts["profile"],
            "intent": parts["intent"],
            "operation": parts["operation"],
            "evidence": evidence,
            "reputation": reputation,
            "nonce": nonce,
        }
    )
    k = keys.get(p.signer)
    if k is None:
        raise CaseError(f"no test key for role {p.signer}")
    return File(signed=p.signed, typ=TYP_PRESENTATION, key=k, payload=payload, over=payload)


def read_decoded(dir: str | os.PathLike[str], rel: str) -> bytes:
    """The decoded file rel of the directory dir, which must be RFC 8785 canonical with
    no trailing newline: it is the payload byte for byte. Raises CaseError."""
    try:
        b = Path(dir).joinpath(*rel.split("/")).read_bytes()
    except OSError as e:
        raise wrap(rel, e) from e
    try:
        canon = jcs.canonicalize(b)
    except strictjson.StrictJSONError as e:
        raise wrap(rel, e) from e
    if canon != b:
        raise CaseError(
            f"{rel} is not in RFC 8785 canonical form"
            " (no white space, sorted members, no trailing newline)"
        )
    return b


def _check_claims(a: Artifact, payload: bytes) -> None:
    """The entry's jti, iat, nbf and, when the entry states one, exp in a decoded
    artifact. iat defaults to FIXED_TIME and nbf to the iat."""
    claims = _object(payload, a.decoded)
    jti = _member(claims, "jti", str, a.decoded) or ""
    got = {n: _member(claims, n, int, a.decoded) for n in ("iat", "nbf", "exp")}
    iat = FIXED_TIME if a.iat is None else a.iat
    nbf = iat if a.nbf is None else a.nbf

    def show(v: int | None) -> str:
        return "absent" if v is None else str(v)

    if jti != a.jti:
        raise CaseError(f"{a.decoded}: jti {q(jti)}, want the fixed {q(a.jti)}")
    for name, want in (("iat", iat), ("nbf", nbf), ("exp", a.exp)):
        if want is not None and got[name] != want:
            raise CaseError(f"{a.decoded}: {name} {show(got[name])}, want the fixed {want}")
