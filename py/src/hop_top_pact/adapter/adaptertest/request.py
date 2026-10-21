"""The request of a case (Go adaptertest, request.go).

build_request turns a case's Request into the RawRequest the adapter receives,
before the suite attaches a credential or marks the arrival. The url is kept
as the case states it, octet for octet: it is the request-target the gateway
received, in absolute-form (RFC 9112 3.2.2), so a fragment or userinfo
reaches the adapter intact. Headers are the field lines in member order, with
their names as the case spells them; a host member stays a field line, since
RawRequest has no separate host. The TLS peer is the case's own TLSPeer.
"""

from __future__ import annotations

import re
from typing import Final

from hop_top_pact.adapter.adaptertest.casefile import ARRIVAL_DIRECT, Request, decode_body
from hop_top_pact.adapter.adaptertest.compare import CaseRun, error_text
from hop_top_pact.core.binding import RawRequest, RequestObjectError
from hop_top_pact.errors import PactError

__all__ = ["build_request"]

# RFC 9110 5.6.2: a method is a token.
_TOKEN: Final = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", re.ASCII)
# A percent sign that does not start a percent-encoded octet (RFC 3986 2.1).
_BAD_ESCAPE: Final = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _check_reference(what: str, s: str) -> None:
    """Refuse what a URI reference cannot hold: a control character, white space or
    a malformed percent-encoding. Go's url.Parse refuses the same."""
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in s):
        raise RequestObjectError(f"{what} {s!r} holds a control character or white space")
    if _BAD_ESCAPE.search(s):
        raise RequestObjectError(f"{what} {s!r} holds a malformed percent-encoding")


def build_request(r: Request) -> tuple[RawRequest, bytes]:
    """The RawRequest of a case request and its body. Raises RequestObjectError
    for a request a server could not have received: a method that is not a
    token, a malformed url or TLS peer URI, or a body that is not standard padded
    base64."""
    try:
        body = decode_body(r.body_b64)
    except ValueError as e:
        raise RequestObjectError(str(e)) from None
    if not _TOKEN.fullmatch(r.method):
        raise RequestObjectError(f"request: method {r.method!r} is not a token")
    _check_reference("request: url", r.url)
    if r.tls_peer is not None:
        for u in r.tls_peer.uris:
            _check_reference("request.tls_peer.uris:", u)
    req = RawRequest(
        method=r.method,
        raw_request_uri=r.url,
        headers=tuple(r.headers.items()),
        body=body,
        tls_peer=r.tls_peer,
    )
    return req, body


def case_request(r: CaseRun) -> tuple[RawRequest, bytes] | None:
    """Build the case's request, attach the credential and mark the arrival; the
    request to hand the adapter and its body. None means a failure was
    recorded."""
    cr = r.case.request
    subj = r.subject
    if cr is None or subj is None:
        r.fail("the case has no request")
        return None
    try:
        req, body = build_request(cr)
    except RequestObjectError as e:
        r.fail(str(e))
        return None
    if cr.native_state_ref:
        if subj.credential is None:
            r.fail(
                "factory returned no credential hook, and the case presents native"
                f" identity {cr.native_state_ref!r}"
            )
            return None
        try:
            with_credential: object = subj.credential(req, cr.native_state_ref)
        except Exception as e:
            r.fail(f"credential for native identity {cr.native_state_ref!r}: {error_text(e)}")
            return None
        if not isinstance(with_credential, RawRequest):
            r.fail(f"credential returned {type(with_credential).__name__}, want a RawRequest")
            return None
        req = with_credential
    if cr.arrival != ARRIVAL_DIRECT:
        try:
            arrived: object = subj.arrive(req)
        except Exception as e:
            kind = "" if isinstance(e, PactError) else type(e).__name__ + ": "
            r.fail(f"arrive raised {kind}{error_text(e)}")
            return None
        if not isinstance(arrived, RawRequest):
            r.fail(f"arrive returned {arrived!r}, want a RawRequest")
            return None
        req = arrived
    return req, body
