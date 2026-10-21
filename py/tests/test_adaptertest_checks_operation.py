"""The checks of map_operation.

Port of go/adapter/adaptertest/checks_operation_test.go. A RawRequest is
immutable, so an adapter cannot consume the body of the request it is given:
Go's body restoration test becomes the check that the request reaches the
adapter with the body of the case, whatever the hooks do.
"""

from __future__ import annotations

import base64
from dataclasses import replace
from typing import Any, ClassVar

from hop_top_pact.adapter import (
    AdapterError,
    Code,
    ContextMismatch,
    InvalidMessage,
    Principal,
    UnsupportedRequirement,
)
from hop_top_pact.adapter.adaptertest import Env, ExpectOperation, Request, Subject
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.types import OperationContext


def test_map_operation_checks(at: Any) -> None:
    good = at.good_op()
    loose = ExpectOperation()
    case, fake = at.map_case, at.map_fake

    def mapped(**kw: Any) -> Any:
        return case("mapped", operation=ExpectOperation(**kw))

    at.run_rows(
        [
            (
                "mapped",
                fake(good, None),
                mapped(
                    environment_id=good.environment_id,
                    principal_id=good.principal_id,
                    action="invoice.read",
                    resources=("https://invoices.example/invoices/1",),
                    method="GET",
                    target_uri=good.target_uri,
                    body_digest=good.body_digest,
                    headers={},
                ),
                (),
            ),
            (
                "mapped but errors",
                fake(None, ContextMismatch()),
                case("mapped", operation=loose),
                ("want an operation context",),
            ),
            (
                "not an operation context",
                fake({"operation_id": "op-1"}, None),
                case("mapped", operation=loose),
                ("want an OperationContext",),
            ),
            (
                "no operation id",
                fake(replace(good, operation_id=""), None),
                case("mapped", operation=loose),
                ("operation_id is empty",),
            ),
            (
                "principal from elsewhere",
                fake(replace(good, principal_id="https://idp.example/mallory"), None),
                case("mapped", operation=loose),
                ("never from the request",),
            ),
            (
                "lowercase method",
                fake(replace(good, method="get"), None),
                case("mapped", operation=loose),
                ("not uppercase",),
            ),
            (
                "http target",
                fake(replace(good, target_uri="http://gateway.example/x"), None),
                case("mapped", operation=loose),
                ("not an https URI",),
            ),
            (
                "fragment in target",
                fake(replace(good, target_uri="https://gateway.example/x#f"), None),
                case("mapped", operation=loose),
                ("carries a fragment",),
            ),
            (
                "bad body digest",
                fake(replace(good, body_digest="abc"), None),
                case("mapped", operation=loose),
                ("body_digest",),
            ),
            (
                "no resources",
                fake(replace(good, resources=None), None),
                case("mapped", operation=loose),
                ("resources is None",),
            ),
            (
                "no headers",
                fake(replace(good, headers=None), None),
                case("mapped", operation=loose),
                ("headers is None",),
            ),
            (
                "uppercase header name",
                fake(replace(good, headers={"X-Kind": "a"}), None),
                case("mapped", operation=loose),
                ("not lowercase",),
            ),
            (
                "wrong environment",
                fake(good, None),
                mapped(environment_id="other"),
                ("environment_id is",),
            ),
            (
                "wrong principal expectation",
                fake(good, None),
                mapped(principal_id="other"),
                ("principal_id is",),
            ),
            ("wrong action", fake(good, None), mapped(action="invoice.approve"), ("action is",)),
            (
                "wrong resources",
                fake(good, None),
                mapped(resources=("https://invoices.example/invoices/2",)),
                ("resources are",),
            ),
            ("wrong method", fake(good, None), mapped(method="POST"), ("method is",)),
            (
                "wrong target",
                fake(good, None),
                mapped(target_uri="https://x.example/"),
                ("target_uri is",),
            ),
            ("wrong digest", fake(good, None), mapped(body_digest="yy"), ("body_digest is",)),
            (
                "wrong headers",
                fake(good, None),
                mapped(headers={"x-request-kind": "approval"}),
                ("headers are",),
            ),
            (
                "error",
                fake(None, ContextMismatch()),
                case("error", reason_code="CONTEXT_MISMATCH"),
                (),
            ),
            ("error expected, mapped", fake(good, None), case("error"), ("want an error",)),
        ]
    )


class CodedOnly(AdapterError):
    """Carries a draft 13.4 code but is not the InvalidMessage class, so isinstance
    does not match it."""

    code: ClassVar[Code] = Code.INVALID_MESSAGE
    text = "coded only"


def test_map_operation_malformed_request_code(at: Any) -> None:
    """The code a refused malformed request reports, INVALID_MESSAGE (draft 13.4), is
    checked against the case, and the error must be an InvalidMessage or wrap
    one."""
    case, fake = at.map_case, at.map_fake
    at.run_rows(
        [
            (
                "the sentinel",
                fake(None, InvalidMessage()),
                case("error", reason_code="INVALID_MESSAGE"),
                (),
            ),
            (
                "wrapped",
                fake(None, at.wrap("target: fragment", at.wrap("map", InvalidMessage()))),
                case("error", reason_code="INVALID_MESSAGE"),
                (),
            ),
            (
                "another code",
                fake(None, UnsupportedRequirement()),
                case("error", reason_code="INVALID_MESSAGE"),
                ("code is UNSUPPORTED_REQUIREMENT, want INVALID_MESSAGE",),
            ),
            (
                "no code",
                fake(None, at.Wrapped("cannot map")),
                case("error", reason_code="INVALID_MESSAGE"),
                ("carries no draft 13.4 code, want INVALID_MESSAGE",),
            ),
            (
                "the code without the sentinel",
                fake(None, CodedOnly()),
                case("error", reason_code="INVALID_MESSAGE"),
                ("does not wrap the sentinel",),
            ),
        ]
    )


def test_map_operation_restores_the_body(at: Any) -> None:
    body = b'{"amount":"1"}'
    req = Request(
        method="POST",
        url="https://gateway.example/invoices/1",
        body_b64=base64.b64encode(body).decode("ascii"),
    )
    got: list[bytes] = []

    def mapper(r: RawRequest, p: Principal, v: str) -> OperationContext:
        got.append(r.body)
        op: OperationContext = at.good_op()
        return op

    def factory(keep: Any) -> Any:
        def f(env: Env) -> Subject:
            return Subject(
                adapter=at.FakeAdapter(map_op=mapper),
                arrive=keep,
                credential=lambda r, ref: r,
            )

        return f

    c = at.complete(at.map_case("mapped", req, operation=ExpectOperation()))
    at.want_clean(at.case_failures(factory(lambda r: r), c))
    assert got == [body], "the adapter gets the body of the case"
    at.want_fails(
        at.case_failures(factory(lambda r: replace(r, body=b"")), c),
        "the original 14",
        "keep the body",
    )
    at.want_fails(
        at.case_failures(factory(lambda r: replace(r, body=body[:3])), c), "with 3 body bytes"
    )


def test_map_operation_receives_the_case(at: Any) -> None:
    got: list[tuple[RawRequest, Principal, str]] = []

    def mapper(r: RawRequest, p: Principal, v: str) -> OperationContext:
        got.append((r, p, v))
        op: OperationContext = at.good_op()
        return op

    url = "https://svc:pw@gateway.example/invoices/1?a=%2f&b=2#frag"
    c = at.map_case(
        "mapped",
        Request(
            method="POST",
            url=url,
            headers={"X-One": "1", "Host": "attacker.example"},
            native_state_ref="alice",
        ),
        operation=ExpectOperation(),
    )
    at.want_clean(at.run_fake(at.FakeAdapter(map_op=mapper), c))
    assert len(got) == 1
    req, p, version = got[0]
    assert (req.method, req.raw_request_uri) == ("POST", url), (
        "the URL exactly as the case states it"
    )
    assert list(req.headers) == [
        ("X-One", "1"),
        ("Host", "attacker.example"),
        ("Authorization", "Bearer tok-alice"),
    ], "the case's headers, then the one the credential hook adds"
    assert p.id == "https://idp.example/alice"
    assert p.realm == at.ACME
    assert p.mechanism == "test"
    assert p.authenticated_at == at.NOW
    assert version == "map-1"
