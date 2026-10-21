"""map_operation of the memory adapter (Go adapters/memory, operation.go)."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from typing import TYPE_CHECKING, Final

from hop_top_pact.adapter import (
    ContextMismatch,
    DependencyUnavailable,
    InvalidMessage,
    Principal,
    UnsupportedRequirement,
)
from hop_top_pact.adapters.memory.identity import bearer
from hop_top_pact.adapters.memory.state import Mapping
from hop_top_pact.core.binding import RawRequest, RequestError, RequestErrorKind, from_request
from hop_top_pact.core.types import OperationContext

if TYPE_CHECKING:
    from hop_top_pact.adapters.memory.memory import MemoryAdapter

_UNRESERVED: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")


def map_operation(
    a: MemoryAdapter, r: RawRequest | None, p: Principal, mapping_version: str
) -> OperationContext:
    """The operation context of draft 10.2 of the request, the authenticated principal
    and the installed mapping.

    The baseline HTTP mapping is core.binding.from_request: method, target_uri
    from the configured origin and the exact path and query of the
    request-target, body_digest of the exact body, and the allowlisted headers.
    A Host, Forwarded or X-Forwarded-* header cannot choose the target. The
    adapter adds what the binding leaves to it: action and resources from the
    installed route that matches the method and the bound path, never from a list
    the client supplied; principal_id, the authenticated principal;
    environment_id, from the gateway configuration; and operation_id.

    A request the baseline mapping refuses, such as one with a fragment,
    userinfo, a content encoding or an ambiguous encoding, raises InvalidMessage
    (INVALID_MESSAGE, draft 13.4) from the RequestError that names the rule. A
    body that cannot be read raises DependencyUnavailable.
    """
    if r is None:
        raise InvalidMessage("memory: no request")
    m = a.mappings.get(mapping_version)
    if m is None:
        raise UnsupportedRequirement(
            f"memory: mapping version {mapping_version!r} is not installed"
        )
    if not p.id or p.realm != a.realm():
        raise ContextMismatch("memory: the principal does not belong to this gateway's realm")
    match_credential(a, r, p)

    try:
        op = from_request(a.binding_config(mapping_version), r, p.id, "", ())
    except RequestError as e:
        if e.kind == RequestErrorKind.INVALID_REQUEST:
            raise InvalidMessage(f"memory: {e}") from e
        if e.kind == RequestErrorKind.BODY_READ:
            raise DependencyUnavailable(f"memory: {e}") from e
        # new_adapter validated the configuration of every installed mapping, so
        # this is not reached; an unusable mapping is not supported.
        raise UnsupportedRequirement(f"memory: mapping {mapping_version!r}: {e}") from e

    path = bound_path(op.target_uri)
    route = match_route(m, op.method, path)
    if route is None:
        raise UnsupportedRequirement(
            f"memory: mapping {mapping_version!r} has no route for {op.method} {path}"
        )
    action, resource = route
    return replace(
        op,
        operation_id=operation_id(p.id, op.method, op.target_uri, op.body_digest, mapping_version),
        environment_id=a.st.gateway.environment_id,
        action=action,
        resources=(resource,),
    )


def bound_path(target: str) -> str:
    """The path of a target URI that the binding built: what follows the origin, up
    to the query. The origin has no "/" and the path starts with one."""
    rest = target.removeprefix("https://")
    return rest[rest.index("/") :].partition("?")[0]


def match_credential(a: MemoryAdapter, r: RawRequest, p: Principal) -> None:
    """Refuse a request whose bearer token authenticates somebody other than p. A
    token the identity store does not know says nothing about who sent the
    request, so it is not a mismatch."""
    token, _ = bearer(r)
    if not token:
        return
    i = a.identity_by_secret(token)
    if i is not None and (
        i.id != p.id
        or i.realm.tenant_id != p.realm.tenant_id
        or i.realm.environment_id != p.realm.environment_id
    ):
        raise ContextMismatch(
            "memory: the request authenticates a different principal than the one given"
        )


def match_route(m: Mapping, method: str, path: str) -> tuple[str, str] | None:
    """The action and the resource, with the placeholders filled in, of the route
    for method and path. path is the path as sent, so a segment with an escape
    matches no placeholder."""
    segs = path.split("/")
    for rt in m.routes:
        if rt.method != method:
            continue
        variables = match_path(rt.path.split("/"), segs)
        if variables is None:
            continue
        res = rt.resource
        for k, v in variables.items():
            res = res.replace("{" + k + "}", v)
        return rt.action, res
    return None


def match_path(tmpl: list[str], segs: list[str]) -> dict[str, str] | None:
    """Match the segments of a request path against a template. A {name} segment
    matches one non-empty segment of unreserved characters."""
    if len(tmpl) != len(segs):
        return None
    variables: dict[str, str] = {}
    for t, s in zip(tmpl, segs, strict=True):
        if t.startswith("{") and t.endswith("}"):
            if not s or not set(s) <= _UNRESERVED:
                return None
            variables[t[1:-1]] = s
        elif t != s:
            return None
    return variables


def operation_id(principal: str, method: str, target: str, digest: str, mapping: str) -> str:
    """A stable correlation identifier: the same request of the same principal under
    the same mapping has the same id."""
    h = hashlib.sha256()
    for part in (principal, method, target, digest, mapping):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return "op-" + base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode("ascii")[:22]
