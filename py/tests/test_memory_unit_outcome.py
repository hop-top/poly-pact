"""record_outcome and verify_outcome of the memory adapter (port of
TestRecordOutcome of go/adapters/memory/memory_unit_test.go)."""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest

from hop_top_pact.adapter import (
    ContextMismatch,
    NoVisibility,
    Observation,
    Signed,
    UnsupportedRequirement,
)
from hop_top_pact.adapters import memory as m
from hop_top_pact.core import strictjson
from hop_top_pact.core.enums import (
    CausalAssessment,
    Dimension,
    EventKind,
    OutcomeResult,
    ReporterRole,
    Severity,
)
from hop_top_pact.core.types import Attribution, OutcomeReport, ReputationContext
from hop_top_pact.errors import PactError

ENV = "https://gateway.example/environments/finance"
CTXT = ReputationContext(
    tenant_id="acme",
    environment_id=ENV,
    agent_id="https://identity.example/agents/a",
    purpose_id="p",
    action_class="a",
    resource_class="r",
    runtime_class="managed",
)


def b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def test_record_outcome(mem: Any) -> None:
    def obs(kind: EventKind) -> Observation:
        return Observation(
            event_id="event-1",
            event_kind=kind,
            context=CTXT,
            task_id="task-1",
            operation_id="op-1",
            observed_at=mem.T0 - timedelta(seconds=5),
            result=OutcomeResult.SUCCESS,
            dimension=Dimension.RELIABILITY,
            severity=Severity.INFO,
            attribution=Attribution(
                native_task_ref="task-1",
                independence_group="g",
                causal_assessment=CausalAssessment.UNKNOWN,
                assessment_ref=None,
            ),
        )

    a, clk = mem.new_adapter()

    def payload(r: object) -> OutcomeReport:
        assert isinstance(r, Signed), f"recorded {type(r).__name__}, want Signed"
        raw = b64(r.jws.split(".")[1])
        return strictjson.decode(raw, OutcomeReport, strictjson.Limits(max_bytes=1 << 20))

    # roles by kind
    for kind, role in (
        (EventKind.ADMISSION, ReporterRole.GATEWAY),
        (EventKind.AUTHORIZATION, ReporterRole.GATEWAY),
        (EventKind.EXECUTION, ReporterRole.EXECUTOR),
    ):
        r = a.record_outcome(obs(kind))
        rep = payload(r)
        assert (rep.reporter_role, rep.event_kind) == (role, kind), kind
        assert isinstance(r, Signed)
        a.verify_outcome(r.jws)

    # report fields
    rep = payload(a.record_outcome(obs(EventKind.EXECUTION)))
    t0 = mem.T0_SEC
    assert (rep.iat, rep.nbf, rep.exp, rep.observed_at) == (t0, t0, t0 + 300, t0 - 5)
    assert (rep.iss, rep.aud, rep.sub, rep.tenant_id) == (
        "https://gateway.example/reporters/finance",
        "https://reputation.example/",
        CTXT.agent_id,
        "acme",
    )
    assert (rep.evidence_refs, rep.supersedes, len(rep.jti)) == ((), (), 22)
    clk.advance(timedelta(hours=1))
    assert payload(a.record_outcome(obs(EventKind.EXECUTION))).iat == t0 + 3600, (
        "iat follows the clock"
    )
    clk.advance(-timedelta(hours=1))

    # a retry carries the same jti
    j1 = payload(a.record_outcome(obs(EventKind.ADMISSION))).jti
    j2 = payload(a.record_outcome(obs(EventKind.ADMISSION))).jti
    j3 = payload(a.record_outcome(replace(obs(EventKind.ADMISSION), event_id="event-2"))).jti
    assert j1 == j2
    assert j1 != j3, "jti is a function of the event id"

    # no execution visibility
    for vis in ("none", ""):
        blind, _ = mem.new_adapter(lambda st, v=vis: replace(st, visibility=v))
        for result in (OutcomeResult.SUCCESS, OutcomeResult.FAILURE, OutcomeResult.UNKNOWN):
            r = blind.record_outcome(replace(obs(EventKind.EXECUTION), result=result))
            assert isinstance(r, NoVisibility), (vis, result)
            r.validate()
        assert isinstance(blind.record_outcome(obs(EventKind.ADMISSION)), Signed)

    # refusals
    other = replace(obs(EventKind.ADMISSION), context=replace(CTXT, tenant_id="globex"))
    with pytest.raises(ContextMismatch):
        a.record_outcome(other)
    other = replace(obs(EventKind.ADMISSION), context=replace(CTXT, environment_id="other"))
    with pytest.raises(ContextMismatch):
        a.record_outcome(other)
    with pytest.raises(PactError):
        a.record_outcome(replace(obs(EventKind.ADMISSION), event_id=""))
    for kind in (
        EventKind.QUALITY,
        EventKind.SECURITY,
        EventKind.FEEDBACK,
        EventKind.CORRECTION,
        EventKind.REMEDIATION,
    ):
        with pytest.raises(UnsupportedRequirement):
            a.record_outcome(obs(kind))
    unsigned, _ = mem.new_adapter(lambda st: replace(st, reporting=None))
    with pytest.raises(UnsupportedRequirement):
        unsigned.record_outcome(obs(EventKind.ADMISSION))
    with pytest.raises(m.MemoryAdapterError):
        unsigned.verify_outcome("a.b.c")

    # credentials are removed
    o = replace(
        obs(EventKind.EXECUTION),
        details=(
            "rejected: Authorization: Bearer tok-alice-secret-1 and tok-bob-secret-2 inline\n"
            "Cookie: session=abcdef123456; other=1\nset-cookie: sid=zzzzzzzz\n"
            "Cookie: sc=cookievalue9999; plain=1\n"
            "pact-presentation: eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln\nbasic dXNlcjpwYXNzd29yZA==\n"
            "token eyJhbGciOiJFUzI1NiJ9.eyJhIjoxfQ.c2ln and password=hunter22 api_key=abcdef12"
        ),
        evidence_refs=(
            "native-record:1",
            "https://e.example/x?access_token=abc123456&keep=1",
            "tok-alice-secret-1",
        ),
    )
    rep = payload(a.record_outcome(o))
    text = rep.details + "\n" + "\n".join(rep.evidence_refs)
    for secret in (
        "tok-alice-secret-1",
        "tok-bob-secret-2",
        "abcdef123456",
        "zzzzzzzz",
        "cookievalue9999",
        "eyJhbGci",
        "dXNlcjpwYXNzd29yZA",
        "hunter22",
        "abcdef12",
        "abc123456",
    ):
        assert secret not in text, f"{secret!r} survived in {text!r}"
    assert rep.evidence_refs[0] == "native-record:1"
    assert "keep=1" in rep.evidence_refs[1], "a reference without a credential was changed"
    assert "rejected:" in rep.details, "the free text was dropped"

    # signature
    r = a.record_outcome(obs(EventKind.ADMISSION))
    assert isinstance(r, Signed)
    jws = r.jws
    parts = jws.split(".")

    def tamper(i: int) -> str:
        raw = bytearray(b64(parts[i]))
        raw[len(raw) // 2] ^= 1
        p = list(parts)
        p[i] = enc(bytes(raw))
        return ".".join(p)

    a.verify_outcome(jws)
    for bad in (
        tamper(0),
        tamper(1),
        tamper(2),
        "a.b",
        "a.b.c",
        parts[0] + "." + parts[1] + ".",
        parts[0] + "." + parts[1] + "." + enc(bytes(64)),
    ):
        with pytest.raises(m.MemoryAdapterError):
            a.verify_outcome(bad)
    other_adapter, _ = mem.new_adapter()
    with pytest.raises(m.MemoryAdapterError):
        other_adapter.verify_outcome(jws)
    hdr = json.loads(b64(parts[0]))
    assert hdr == {"alg": "ES256", "kid": "k1", "typ": "pact-outcome+jwt"}
    assert len(b64(parts[2])) == 64, "the 64 octets of an ES256 R||S"
