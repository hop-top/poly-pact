"""The memory adapter's state, authentication and descriptor (port of
go/adapters/memory/memory_unit_test.go, first part; the binding, operation,
native and outcome tests are in test_memory_unit_*.py).

A Python call takes no context argument, so Go's cancelled-context rows have
no counterpart.
"""

from __future__ import annotations

import threading
from dataclasses import replace
from typing import Any

import pytest

from hop_top_pact.adapter import (
    Adapter,
    CheckInput,
    ClaimContext,
    DenialReason,
    InvalidProof,
    NativeDenial,
    Principal,
)
from hop_top_pact.adapters import memory as m
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.clock import FakeClock


def _edit(field: str, f: Any) -> Any:
    return lambda st: replace(st, **{field: f(getattr(st, field))})


def _gateway(**kw: Any) -> Any:
    return _edit("gateway", lambda g: replace(g, **kw))


def _first(field: str, **kw: Any) -> Any:
    return _edit(field, lambda xs: (replace(xs[0], **kw), *xs[1:]))


def _route(**kw: Any) -> Any:
    def mapping(xs: tuple[m.Mapping, ...]) -> tuple[m.Mapping, ...]:
        mp = xs[0]
        return (replace(mp, routes=(replace(mp.routes[0], **kw), *mp.routes[1:])), *xs[1:])

    return _edit("mappings", mapping)


def _set(field: str, value: Any) -> Any:
    return lambda st: replace(st, **{field: value})


def _enrollment(**kw: Any) -> Any:
    return _set("enrollments", (m.Enrollment(**kw),))


NEW_VALIDATES: list[tuple[str, Any, str]] = [
    ("valid", lambda st: st, ""),
    ("wrong model", _set("model", "common/2"), "model"),
    ("no tenant", _gateway(tenant_id=""), "tenant_id"),
    ("http origin", _gateway(origin="http://gateway.example"), "https origin"),
    ("origin with a path", _gateway(origin="https://gateway.example/api"), "bare origin"),
    ("origin with userinfo", _gateway(origin="https://u:p@gateway.example"), "bare origin"),
    # The baseline mapping's own configuration checks apply too.
    ("origin with a trailing slash", _gateway(origin="https://gateway.example/"), "configuration"),
    (
        "presentation header on the allowlist",
        _gateway(header_allowlist=("pact-trace",)),
        "configuration",
    ),
    ("allowlist entry is not a token", _gateway(header_allowlist=("x kind",)), "configuration"),
    ("mapping version too long", _first("mappings", version="v" * 1025), "configuration"),
    (
        "credential header on the allowlist",
        _gateway(header_allowlist=("authorization",)),
        "never belong",
    ),
    (
        "hop-by-hop header on the allowlist",
        _gateway(header_allowlist=("connection",)),
        "never belong",
    ),
    ("uppercase allowlist entry", _gateway(header_allowlist=("X-Kind",)), "lowercase"),
    ("mapping without a version", _first("mappings", version=""), "no version"),
    ("incomplete route", _route(action=""), "incomplete route"),
    ("identity without a secret", _first("identities", secret=""), "needs a ref"),
    (
        "duplicate identity ref",
        _edit("identities", lambda xs: (xs[0], replace(xs[1], ref="alice"))),
        "used twice",
    ),
    (
        "bad enrollment status",
        _enrollment(
            workload="w", status="SUSPENDED", agent_id="https://a.example/a", source_id="s"
        ),
        "status",
    ),
    (
        "enrollment without a source",
        _enrollment(workload="w", status="ACTIVE", agent_id="https://a.example/a"),
        "source_id",
    ),
    (
        "enrollment agent is not a URI",
        _enrollment(workload="w", status="ACTIVE", agent_id="agent", source_id="s"),
        "absolute URI",
    ),
    (
        "enrollment holder key is not a thumbprint",
        _enrollment(
            workload="w",
            status="ACTIVE",
            agent_id="https://a.example/a",
            source_id="s",
            holder_jkt="x",
        ),
        "digest",
    ),
    ("claim outside the approved paths", _first("claims", path="/other"), "approved path"),
    ("claim without a value", _first("claims", value=m.ClaimRecord().value), "no value"),
    ("claim without a source", _first("claims", source_id=""), "source_id"),
    ("check with a bad result", _first("checks", result="OK"), "needs an id"),
    (
        "policy with a bad effect",
        _set("policy", (m.PolicyRule(principal="p", action="a", effect="PERMIT"),)),
        "needs a principal",
    ),
    ("bad visibility", _set("visibility", "partial"), "visibility"),
    ("reporting without a key id", _edit("reporting", lambda r: replace(r, kid="")), "reporting"),
]


def test_new_validates_the_state(mem: Any) -> None:
    for name, mutate, want in NEW_VALIDATES:
        st = mutate(mem.state())
        if not want:
            m.new_adapter(st, FakeClock(mem.T0))
            continue
        with pytest.raises(m.MemoryAdapterError) as e:
            m.new_adapter(st, FakeClock(mem.T0))
        assert want in str(e.value), f"{name}: {e.value}"

    # no clock
    with pytest.raises(m.MemoryAdapterError, match="no clock"):
        m.new_adapter(mem.state(), None)


def test_parse_state_is_strict(mem: Any) -> None:
    base = (
        '{"model":"common/1","gateway":{"tenant_id":"t","environment_id":"e",'
        '"origin":"https://g.example"}'
    )
    for name, doc in {
        "unknown member": base + ',"surprise":1}',
        "duplicate member": base + ',"visibility":"none","visibility":"none"}',
        "unknown in nested": base.replace('"origin"', '"extra":1,"origin"', 1) + "}",
        "not an object": "[]",
    }.items():
        with pytest.raises(m.MemoryAdapterError):
            m.parse_state(doc.encode())
        assert name
    m.parse_state((base + "}").encode())
    m.from_json((base + "}").encode(), FakeClock(mem.T0))
    with pytest.raises(m.MemoryAdapterError):
        m.from_json(b"{", FakeClock(mem.T0))


def test_normalize_origin() -> None:
    for given, want in {
        "https://gateway.example": "https://gateway.example",
        "HTTPS://Gateway.Example:443": "https://gateway.example",
        "https://gateway.example:8443": "https://gateway.example:8443",
        "https://gateway.example/": "https://gateway.example",
        "https://[::1]:443": "https://[::1]",
        "https://[2001:db8::1]:8443": "https://[2001:db8::1]:8443",
    }.items():
        assert m.normalize_origin(given) == want, given
    for bad in (
        "",
        "gateway.example",
        "http://gateway.example",
        "https://",
        "https://g.example/x",
        "https://g.example?x=1",
        "https://g.example#f",
        "mailto:a@b.example",
    ):
        with pytest.raises(m.MemoryAdapterError):
            m.normalize_origin(bad)


def test_authenticate(mem: Any) -> None:
    a, _ = mem.new_adapter()

    def req(authz: str, arrive: bool) -> RawRequest:
        headers = (("Authorization", authz),) if authz else ()
        r = mem.get("https://gateway.example/invoices/1", *headers)
        return m.arrive(r) if arrive else r

    p = a.authenticate_native(req("Bearer tok-alice-secret-1", True))
    assert (p.id, p.workload, p.mechanism, p.authenticated_at) == (
        "https://idp.example/alice",
        "w-alice",
        "bearer",
        mem.T0,
    )
    p = a.authenticate_native(req("bearer tok-bob-secret-2", True))
    assert p.id == "https://idp.example/bob", "a lowercase scheme"
    for name, r, reason in (
        ("no header", req("", True), DenialReason.NO_CREDENTIAL),
        ("no header, direct", req("", False), DenialReason.NO_CREDENTIAL),
        ("unknown token", req("Bearer tok-nobody", True), DenialReason.CREDENTIAL_REJECTED),
        ("basic scheme", req("Basic dXNlcjpwdw==", True), DenialReason.CREDENTIAL_REJECTED),
        ("empty token", req("Bearer ", True), DenialReason.CREDENTIAL_REJECTED),
        (
            "direct, valid",
            req("Bearer tok-alice-secret-1", False),
            DenialReason.CREDENTIAL_REJECTED,
        ),
        ("token prefix only", req("Bearer tok-alice", True), DenialReason.CREDENTIAL_REJECTED),
        (
            "token plus suffix",
            req("Bearer tok-alice-secret-1x", True),
            DenialReason.CREDENTIAL_REJECTED,
        ),
        (
            "token in uppercase",
            req("Bearer TOK-ALICE-SECRET-1", True),
            DenialReason.CREDENTIAL_REJECTED,
        ),
    ):
        with pytest.raises(NativeDenial) as e:
            a.authenticate_native(r)
        assert e.value.reason == reason, name
        assert isinstance(e.value, InvalidProof), name

    # a header cannot carry the mark
    r = req("Bearer tok-alice-secret-1", False)
    r = replace(r, headers=(*r.headers, ("X-Arrived", "true"), ("Arrived", "true")))
    with pytest.raises(NativeDenial):
        a.authenticate_native(r)
    assert not m.arrived(r), "arrived is true for an unmarked request"
    assert m.arrived(m.arrive(r))

    # attributes are copied
    a, _ = mem.new_adapter(
        lambda st: replace(
            st,
            identities=(
                replace(st.identities[0], attributes={"groups": ("finance",)}),
                *st.identities[1:],
            ),
        )
    )
    p = a.authenticate_native(req("Bearer tok-alice-secret-1", True))
    p.attributes["groups"] = "changed"
    p2 = a.authenticate_native(req("Bearer tok-alice-secret-1", True))
    assert p2.attributes["groups"] == ("finance",), "the store changed through a returned principal"


def test_credential_hook(mem: Any) -> None:
    a, _ = mem.new_adapter()
    r = a.credential(mem.get("https://gateway.example/"), "bob")
    assert list(r.headers) == [("Authorization", "Bearer tok-bob-secret-2")]
    r = mem.get("https://gateway.example/", ("Authorization", "Bearer explicit"))
    assert a.credential(r, "alice") is r, "an explicit header was replaced"
    with pytest.raises(m.MemoryAdapterError):
        a.credential(r, "nobody")
    # The arrival mark survives the hook.
    assert m.arrived(a.credential(m.arrive(mem.get("https://gateway.example/")), "bob"))


def test_describe(mem: Any) -> None:
    a, _ = mem.new_adapter()
    d = a.describe()
    assert d.protocol
    assert d.version
    assert d.mapping_revision
    assert isinstance(a, Adapter)


def test_concurrent_use(mem: Any) -> None:
    """After construction the adapter only reads its state, so calls from several
    threads are safe."""
    a, _ = mem.new_adapter()
    errors: list[BaseException] = []

    def work() -> None:
        try:
            for _ in range(50):
                r = m.arrive(
                    mem.get(
                        "https://gateway.example/invoices/1",
                        ("Authorization", "Bearer tok-alice-secret-1"),
                    )
                )
                p: Principal = a.authenticate_native(r)
                a.map_operation(r, p, "map-1")
                a.read_native_claim("/roles", ClaimContext(principal=p))
                a.check_context("approval-v1", CheckInput(principal=p, operation=_zero_op()))
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors


def _zero_op() -> Any:
    from hop_top_pact.core.types import OperationContext

    return OperationContext(
        operation_id="",
        environment_id="",
        principal_id="",
        action="",
        resources=(),
        method="",
        target_uri="",
        body_digest="",
        headers={},
    )
