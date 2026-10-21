"""RawRequest, the request the binding reads, and the decoder of its JSON form."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from hop_top_pact.core.types import JSONValue
from hop_top_pact.errors import PactError


@dataclass(frozen=True, slots=True, kw_only=True)
class TLSPeer:
    """The client certificate of a mutual-TLS connection: the attributes an adapter reads."""

    subject_cn: str = ""
    issuer_cn: str = ""
    dns_names: tuple[str, ...] = ()
    uris: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class RawRequest:
    """An HTTP request as a gateway received it.

    method is the request method as sent. raw_request_uri is the
    request-target of the request line, unchanged (RFC 9112 3.2): nothing
    decoded, re-encoded or normalized. headers are the field lines in the
    order received, as (name, value) pairs; a value that was not valid UTF-8
    on the wire holds the undecodable octets as lone surrogates (the
    "surrogateescape" error handler), so the binding can tell it apart. body
    is the request body after transfer decoding. tls_peer describes the
    client certificate of a mutual-TLS connection, when there is one.

    Every octet the binding accepts in a request-target is ASCII, so whether
    a server decoded the target as UTF-8 or Latin-1 does not change a
    verdict.
    """

    method: str
    raw_request_uri: str
    headers: Sequence[tuple[str, str]] = ()
    body: bytes = b""
    tls_peer: TLSPeer | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class DecodedRequest:
    """A decoded request object: the RawRequest, and the two members of an adapter
    case request that the conformance suite reads itself. native_state_ref names
    the native identity whose credential the request presents; arrival is
    "enforcement_point", "direct", or "" when absent (the suite's default,
    enforcement_point). Both are "" for a binding vector's request."""

    request: RawRequest
    native_state_ref: str = ""
    arrival: str = ""


class RequestObjectError(PactError, ValueError):
    """A JSON request object is malformed: a fixture error, not a refused request."""


_MEMBERS: Final = frozenset(
    {
        "method",
        "raw_request_uri",
        "url",
        "headers",
        "body_b64",
        "tls_peer",
        "native_state_ref",
        "arrival",
    }
)
_TLS_PEER_MEMBERS: Final = frozenset({"subject_cn", "issuer_cn", "dns_names", "uris"})
_ARRIVALS: Final = ("", "enforcement_point", "direct")


def decode_request(value: Mapping[str, JSONValue]) -> RawRequest:
    """The RawRequest of a JSON request object, as strictjson parsed it.

    It reads both forms the fixtures use. The binding vectors' request
    (spec/v1.0/fixtures/vectors/README.md) names the target raw_request_uri and
    lists headers as an array of {"name", "value"} objects in order. An
    adapter case file's request names the target url, kept octet for octet
    as the absolute-form request-target, and gives headers as an object, read
    in member order; it may carry tls_peer, and native_state_ref and arrival,
    which decode_request_object keeps for the conformance suite. Either form
    has method and may
    have body_b64, standard base64 with padding, empty or absent for no body.

    Raises RequestObjectError for a malformed object; nothing here refuses a
    request, which is from_request's job.
    """
    return decode_request_object(value).request


def decode_request_object(value: Mapping[str, JSONValue]) -> DecodedRequest:
    """decode_request, keeping the native_state_ref and arrival members of an
    adapter case request: the one decoder of both fixture forms. An arrival other
    than "enforcement_point" or "direct" is a RequestObjectError."""
    if not isinstance(value, Mapping):
        raise RequestObjectError("request: not an object")
    unknown = sorted(set(value) - _MEMBERS)
    if unknown:
        raise RequestObjectError(f"request: unknown members {unknown}")
    method = _string(value, "method", required=True)
    if ("raw_request_uri" in value) == ("url" in value):
        raise RequestObjectError("request: exactly one of raw_request_uri and url")
    target_member = "raw_request_uri" if "raw_request_uri" in value else "url"
    target = _string(value, target_member, required=True)
    native_state_ref = _string(value, "native_state_ref")
    arrival = _string(value, "arrival")
    if arrival not in _ARRIVALS:
        raise RequestObjectError(f"request: arrival {arrival!r} is not enforcement_point or direct")
    raw = RawRequest(
        method=method,
        raw_request_uri=target,
        headers=_headers(value.get("headers")),
        body=_body(value),
        tls_peer=_tls_peer(value.get("tls_peer")),
    )
    return DecodedRequest(request=raw, native_state_ref=native_state_ref, arrival=arrival)


def _string(obj: Mapping[str, JSONValue], name: str, *, required: bool = False) -> str:
    if name not in obj:
        if required:
            raise RequestObjectError(f"request: {name} is missing")
        return ""
    v = obj[name]
    if not isinstance(v, str):
        raise RequestObjectError(f"request: {name} is not a string")
    return v


def _headers(v: JSONValue) -> tuple[tuple[str, str], ...]:
    if v is None:
        return ()
    if isinstance(v, Mapping):
        out = []
        for name, value in v.items():
            if not isinstance(value, str):
                raise RequestObjectError(f"request.headers.{name}: not a string")
            out.append((name, value))
        return tuple(out)
    if not isinstance(v, list | tuple):
        raise RequestObjectError("request.headers: not an array or an object")
    lines: list[tuple[str, str]] = []
    for i, h in enumerate(v):
        if not isinstance(h, Mapping) or set(h) != {"name", "value"}:
            raise RequestObjectError(f"request.headers[{i}]: not a {{name, value}} object")
        hn, hv = h["name"], h["value"]
        if not isinstance(hn, str) or not isinstance(hv, str):
            raise RequestObjectError(f"request.headers[{i}]: name and value must be strings")
        lines.append((hn, hv))
    return tuple(lines)


def _body(obj: Mapping[str, JSONValue]) -> bytes:
    s = _string(obj, "body_b64")
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as e:
        raise RequestObjectError(f"request.body_b64: not standard padded base64: {e}") from None


def _strings(peer: Mapping[str, JSONValue], name: str) -> tuple[str, ...]:
    v = peer.get(name, ())
    if not isinstance(v, list | tuple):
        raise RequestObjectError(f"request.tls_peer.{name}: not an array")
    if not all(isinstance(x, str) for x in v):
        raise RequestObjectError(f"request.tls_peer.{name}: not an array of strings")
    return tuple(str(x) for x in v)


def _tls_peer(v: JSONValue) -> TLSPeer | None:
    if v is None:
        return None
    if not isinstance(v, Mapping):
        raise RequestObjectError("request.tls_peer: not an object")
    unknown = sorted(set(v) - _TLS_PEER_MEMBERS)
    if unknown:
        raise RequestObjectError(f"request.tls_peer: unknown members {unknown}")
    return TLSPeer(
        subject_cn=_string(v, "subject_cn"),
        issuer_cn=_string(v, "issuer_cn"),
        dns_names=_strings(v, "dns_names"),
        uris=_strings(v, "uris"),
    )
