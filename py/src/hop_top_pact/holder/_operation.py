"""The operation context of an outgoing request."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from urllib.parse import urlsplit
from urllib.request import Request

from hop_top_pact.adapter import Code
from hop_top_pact.core import binding
from hop_top_pact.core.types import OperationContext
from hop_top_pact.holder._errors import HolderError

__all__ = ["operation_from_request"]


def operation_from_request(
    cfg: binding.Config,
    req: Request | None,
    operation_id: str,
    environment_id: str,
    principal_id: str,
    action: str,
    resources: Sequence[str],
) -> OperationContext:
    """Derive the operation context of the baseline HTTP mapping (draft 10.2) from req, a
    urllib.request.Request the agent is about to send, so that the contract request and
    the presentation bind the request the gateway will receive. It applies
    binding.from_request, with the gateway's mapping cfg, to the request as the client
    writes it: the request-target is the path and query of the URL, and the Host line
    req.host.

    The principal, action and resources are those the gateway's mapping derives for the
    request (draft 10.2); operation_id and environment_id are set as given. A body that
    is not bytes is read once and replaced by an in-memory copy, so req can still be
    sent. A request the mapping refuses is INVALID_MESSAGE, with the
    core.binding.RequestError as its cause.
    """
    if req is None:
        raise HolderError(Code.INVALID_MESSAGE, "no request")
    parts = urlsplit(req.full_url)
    target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
    body = _body(req)
    headers = [("Host", req.host)] if req.host else []
    headers += list(req.header_items())
    raw = binding.RawRequest(
        method=req.get_method(), raw_request_uri=target, headers=tuple(headers), body=body
    )
    try:
        op = binding.from_request(cfg, raw, principal_id, action, resources)
    except binding.RequestError as e:
        raise HolderError(Code.INVALID_MESSAGE, str(e)) from e
    return replace(op, operation_id=operation_id, environment_id=environment_id)


def _body(req: Request) -> bytes:
    """The request body as bytes; a file or an iterable of bytes is read and replaced by the
    bytes."""
    data = req.data
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    b = bytes(data.read()) if hasattr(data, "read") else b"".join(data)  # type: ignore[arg-type]
    req.data = b
    return b
