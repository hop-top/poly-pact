"""The checks of record_outcome (port of
go/adapter/adaptertest/checks_record_test.go). A Go pointer to Signed or
NoVisibility becomes a value of another type, here the compact JWS string
itself."""

from __future__ import annotations

import json
from typing import Any

from hop_top_pact.adapter import NoVisibility, Signed, UnsupportedRequirement
from hop_top_pact.adapter.adaptertest import Env, Subject
from hop_top_pact.core.enums import EventKind, OutcomeResult

EXECUTION, SUCCESS = EventKind.EXECUTION, OutcomeResult.SUCCESS


def _set(member: str, value: Any) -> Any:
    def mod(p: Any) -> None:
        p.rep[member] = value

    return mod


def _payload(b: bytes) -> Any:
    def mod(p: Any) -> None:
        p.payload = b

    return mod


def _hdr(member: str, value: Any) -> Any:
    def mod(p: Any) -> None:
        if value is None:
            del p.hdr[member]
        else:
            p.hdr[member] = value

    return mod


def _drop(member: str) -> Any:
    def mod(p: Any) -> None:
        rep = dict(p.rep)
        del rep[member]
        p.payload = json.dumps(rep).encode("utf-8")

    return mod


def test_record_signed_checks(at: Any) -> None:
    signed = at.record_case("signed", EXECUTION, SUCCESS)
    sf, rf = at.signed_fake, at.record_fake
    now = at.NOW_SEC

    def context(p: Any) -> None:
        p.rep["context"] = {**p.rep["context"], "purpose_id": "other"}

    def lifetime(p: Any) -> None:
        p.rep["exp"] = p.rep["iat"] + 301

    at.run_rows(
        [
            ("signed", sf(), signed, ()),
            (
                "signed but declares no visibility",
                rf(NoVisibility(reason="r"), None),
                signed,
                ("want a signed outcome",),
            ),
            ("signed but errors", rf(None, UnsupportedRequirement()), signed, ("want signed",)),
            ("signed but None", rf(None, None), signed, ("returned None",)),
            ("signed as another type", rf("a.b.c", None), signed, ("not another type",)),
            ("not a compact JWS", rf(Signed(jws="abc"), None), signed, ("not a compact JWS",)),
            (
                "header is not base64url",
                rf(Signed(jws="!.e30.c2ln"), None),
                signed,
                ("header is not unpadded base64url",),
            ),
            (
                "payload is not base64url",
                rf(Signed(jws="e30.!.c2ln"), None),
                signed,
                ("payload is not unpadded base64url",),
            ),
            ("wrong typ", sf(_hdr("typ", "JWT")), signed, ("JWS typ is JWT",)),
            ("alg none", sf(_hdr("alg", "none")), signed, ("JWS alg is none",)),
            ("alg HS256", sf(_hdr("alg", "HS256")), signed, ("JWS alg is HS256",)),
            ("alg EdDSA", sf(_hdr("alg", "EdDSA")), signed, ("JWS alg is EdDSA",)),
            ("alg Ed25519", sf(_hdr("alg", "Ed25519")), signed, ()),
            ("no kid", sf(_hdr("kid", None)), signed, ("no kid",)),
            (
                "jku in header",
                sf(_hdr("jku", "https://x.example/keys")),
                signed,
                ("carries 'jku'",),
            ),
            ("payload is not an object", sf(_payload(b"[1]")), signed, ("not an outcome report",)),
            (
                "unknown member",
                sf(_payload(b'{"pact_version":"0.1","surprise":1}')),
                signed,
                ("not an outcome report",),
            ),
            (
                "duplicate member",
                sf(_payload(b'{"jti":"a","jti":"b"}')),
                signed,
                ("not an outcome report",),
            ),
            (
                "required member missing",
                sf(_drop("evidence_refs")),
                signed,
                ("lacks the required member 'evidence_refs'",),
            ),
            (
                "array member null",
                sf(_set("supersedes", None)),
                signed,
                ("not an outcome report", "/supersedes"),
            ),
            ("wrong pact version", sf(_set("pact_version", "0.2")), signed, ("pact_version",)),
            ("wrong event id", sf(_set("event_id", "other")), signed, ("event_id",)),
            ("wrong operation id", sf(_set("operation_id", "other")), signed, ("operation_id",)),
            ("wrong task id", sf(_set("task_id", "other")), signed, ("task_id",)),
            ("wrong kind", sf(_set("event_kind", "QUALITY")), signed, ("event_kind",)),
            ("assumed result", sf(_set("result", "FAILURE")), signed, ("result is",)),
            ("wrong dimension", sf(_set("dimension", "NONE")), signed, ("dimension",)),
            ("wrong severity", sf(_set("severity", "HIGH")), signed, ("severity",)),
            ("wrong tenant", sf(_set("tenant_id", "globex")), signed, ("tenant_id",)),
            ("wrong environment", sf(_set("environment_id", "other")), signed, ("environment_id",)),
            (
                "wrong subject",
                sf(_set("sub", "https://x.example/agents/other")),
                signed,
                ("sub is",),
            ),
            (
                "restamped observation",
                sf(_set("observed_at", now)),
                signed,
                ("original observation time",),
            ),
            ("wrong context", sf(context), signed, ("context is",)),
            (
                "undefined reporter role",
                sf(_set("reporter_role", "robot")),
                signed,
                ("reporter_role",),
            ),
            ("short jti", sf(_set("jti", "short")), signed, ("jti has 5 characters",)),
            ("expired", sf(_set("exp", now)), signed, ("validity",)),
            ("issued in the future", sf(_set("iat", now + 60)), signed, ("validity",)),
            ("valid for too long", sf(lifetime), signed, ("lifetime",)),
            ("no issuer", sf(_set("iss", "")), signed, ("iss is empty",)),
            ("no audience", sf(_set("aud", "")), signed, ("aud is empty",)),
        ]
    )


def test_record_outcomes(at: Any) -> None:
    def execution(outcome: str, result: OutcomeResult) -> Any:
        return at.record_case(outcome, EXECUTION, result)

    no_vis = NoVisibility(reason="execution happens in a system the adapter cannot observe")
    sf, rf = at.signed_fake, at.record_fake
    unknown, failure = OutcomeResult.UNKNOWN, OutcomeResult.FAILURE

    at.run_rows(
        [
            ("no visibility", rf(no_vis, None), execution("no_visibility", unknown), ()),
            (
                "no visibility but signed",
                sf(),
                execution("no_visibility", unknown),
                ("want a declared absence",),
            ),
            (
                "no visibility without a reason",
                rf(NoVisibility(reason=" "), None),
                execution("no_visibility", unknown),
                ("no-visibility declaration",),
            ),
            (
                "no visibility as another type",
                rf(no_vis.reason, None),
                execution("no_visibility", unknown),
                ("not another type",),
            ),
            (
                "no success, declared",
                rf(no_vis, None),
                execution("no_execution_success", SUCCESS),
                (),
            ),
            (
                "no success, assumed",
                sf(),
                execution("no_execution_success", SUCCESS),
                ("although the case gives the adapter no execution visibility",),
            ),
            ("no success, unknown signed", sf(), execution("no_execution_success", unknown), ()),
            ("no success, failure signed", sf(), execution("no_execution_success", failure), ()),
            (
                "no success, admission signed",
                sf(),
                at.record_case("no_execution_success", EventKind.ADMISSION, SUCCESS),
                (),
            ),
            (
                "no success, bad declaration",
                rf(NoVisibility(reason=""), None),
                execution("no_execution_success", SUCCESS),
                ("no-visibility declaration",),
            ),
            ("error", rf(None, UnsupportedRequirement()), execution("error", SUCCESS), ()),
            (
                "error with a code",
                rf(None, UnsupportedRequirement()),
                at.record_case(
                    "error", EventKind.QUALITY, SUCCESS, reason_code="UNSUPPORTED_REQUIREMENT"
                ),
                (),
            ),
            ("error expected, recorded", sf(), execution("error", SUCCESS), ("want an error",)),
            (
                "error of another code",
                rf(None, at.Wrapped("x")),
                at.record_case(
                    "error", EventKind.QUALITY, SUCCESS, reason_code="UNSUPPORTED_REQUIREMENT"
                ),
                ("carries no draft 13.4 code",),
            ),
        ]
    )

    # verification
    fake = sf()

    def verify(err: BaseException | None) -> Any:
        def check(jws: str) -> None:
            if err is not None:
                raise err

        def factory(env: Env) -> Subject:
            s: Subject = at.factory_for(fake)(env)
            return Subject(
                adapter=s.adapter, arrive=s.arrive, credential=s.credential, verify_outcome=check
            )

        return factory

    c = at.complete(execution("signed", SUCCESS))
    at.want_clean(at.case_failures(verify(None), c))
    at.want_fails(
        at.case_failures(verify(at.Wrapped("bad signature")), c),
        "signature of the outcome does not verify",
    )
