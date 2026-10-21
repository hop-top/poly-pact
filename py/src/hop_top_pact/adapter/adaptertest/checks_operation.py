"""The checks of map_operation (Go adaptertest, checks_operation.go).

A RawRequest is immutable and its body is bytes, so an adapter cannot consume
the body and leave the request without it: Go's check that MapOperation
restores what it reads becomes the check that the adapter got the body of
the case.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from hop_top_pact.adapter.adaptertest.casefile import OUT_ERROR, OUT_MAPPED, ExpectOperation
from hop_top_pact.adapter.adaptertest.compare import (
    CaseRun,
    error_text,
    format_map,
)
from hop_top_pact.adapter.adaptertest.leak import scan_error, scan_value
from hop_top_pact.adapter.adaptertest.request import case_request
from hop_top_pact.core import Digest
from hop_top_pact.core.types import OperationContext


def map_operation(r: CaseRun) -> None:
    """Run a map_operation case."""
    got = case_request(r)
    if got is None:
        return
    req, body = got
    if req.body != body:
        r.fail(
            f"the request reached the adapter with {len(req.body)} body bytes, want the"
            f" original {len(body)}; the credential and arrival hooks must keep the body"
        )
    p = r.principal()
    version = r.case.call.mapping_version
    assert r.subject is not None
    a = r.subject.adapter
    op, err, ok = r.call("map_operation", lambda: a.map_operation(req, p, version))
    if not ok:
        return
    scan_error(r, "map_operation", err)
    if op is not None:
        scan_value(r, "map_operation operation", op)

    e = r.case.expect
    if e.outcome == OUT_MAPPED:
        if err is not None or op is None:
            r.fail(
                f"map_operation raised {error_text(err) if err else 'nothing'},"
                " want an operation context"
            )
            return
        if not isinstance(op, OperationContext):
            r.fail(f"map_operation returned {type(op).__name__}, want an OperationContext")
            return
        check_operation(r, op, p.id, e.operation)
    elif e.outcome == OUT_ERROR:
        if err is None:
            what = f"{op.method} {op.target_uri}" if isinstance(op, OperationContext) else op
            r.fail(f"map_operation mapped the request to {what}, want an error")
            return
        r.want_reason("map_operation", err)


def check_operation(
    r: CaseRun, op: OperationContext, principal_id: str, want: ExpectOperation | None
) -> None:
    """Check a mapped operation against the invariants of the baseline HTTP mapping
    (draft 10.2) and the case."""
    if not op.operation_id:
        r.fail("operation_id is empty")
    if op.principal_id != principal_id:
        r.fail(
            f"principal_id is {op.principal_id!r}, want the authenticated principal"
            f" {principal_id!r}: the principal comes from native authentication, never"
            " from the request"
        )
    if op.method != op.method.upper():
        r.fail(f"method {op.method!r} is not uppercase")
    if not op.target_uri.startswith("https://"):
        r.fail(f"target_uri {op.target_uri!r} is not an https URI")
    if "#" in op.target_uri:
        r.fail(f"target_uri {op.target_uri!r} carries a fragment")
    try:
        Digest(op.body_digest).validate()
    except ValueError as e:
        r.fail(f"body_digest: {e}")
    # The wire form has an array and an object here; None would encode as null.
    resources = cast(object, op.resources)
    headers = cast(object, op.headers)
    if not isinstance(resources, tuple | list):
        r.fail(f"resources is {resources!r}, so it does not encode as an array; it must be one")
    if not isinstance(headers, Mapping):
        r.fail(f"headers is {headers!r}, so it does not encode as an object; it must be one")
    else:
        for name in headers:
            if name != str(name).lower():
                r.fail(f"header name {name!r} is not lowercase")
    if want is None:
        return
    if want.environment_id and op.environment_id != want.environment_id:
        r.fail(f"environment_id is {op.environment_id!r}, want {want.environment_id!r}")
    if want.principal_id and op.principal_id != want.principal_id:
        r.fail(f"principal_id is {op.principal_id!r}, want {want.principal_id!r}")
    if want.action and op.action != want.action:
        r.fail(f"action is {op.action!r}, want {want.action!r}")
    if want.resources is not None and (
        not isinstance(resources, tuple | list) or tuple(resources) != tuple(want.resources)
    ):
        r.fail(
            f"resources are {list(op.resources or ())}, want {list(want.resources)}: the"
            " resources come from the request and the installed mapping, never from a"
            " client-supplied list"
        )
    if want.method and op.method != want.method:
        r.fail(f"method is {op.method!r}, want {want.method!r}")
    if want.target_uri and op.target_uri != want.target_uri:
        r.fail(f"target_uri is {op.target_uri!r}, want {want.target_uri!r}")
    if want.body_digest and op.body_digest != want.body_digest:
        r.fail(f"body_digest is {op.body_digest!r}, want {want.body_digest!r}")
    if want.headers is not None and (
        not isinstance(headers, Mapping) or dict(headers) != dict(want.headers)
    ):
        r.fail(f"headers are {format_map(op.headers)}, want {format_map(want.headers)}")
