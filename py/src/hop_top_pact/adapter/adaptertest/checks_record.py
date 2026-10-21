"""The checks of record_outcome (Go adaptertest, checks_record.go)."""

from __future__ import annotations

from collections.abc import Mapping

from hop_top_pact.adapter._types import NoVisibility, Observation, Signed
from hop_top_pact.adapter.adaptertest.casefile import (
    OUT_ERROR,
    OUT_NO_EXEC_SUCCESS,
    OUT_NO_VISIBILITY,
    OUT_SIGNED,
)
from hop_top_pact.adapter.adaptertest.compare import (
    SKEW,
    CaseRun,
    at,
    error_text,
    raw_url_decode,
    unix,
)
from hop_top_pact.adapter.adaptertest.leak import json_text, scan_error, scan_jws, scan_text
from hop_top_pact.core import VERSION, strictjson
from hop_top_pact.core.clock import Artifact, ClockError, check_lifetime, check_window
from hop_top_pact.core.enums import EventKind, OutcomeResult, ReporterRole
from hop_top_pact.core.limits import defaults
from hop_top_pact.core.types import OutcomeReport

OUTCOME_TYP = "pact-outcome+jwt"
"""The JWS typ of an outcome report (draft 7.3)."""

_HEADER_LIMITS = strictjson.Limits(max_bytes=4 << 10)


def observation(r: CaseRun) -> Observation | None:
    """The case's observation argument as the adapter type."""
    o = r.case.call.observation
    if o is None:
        return None
    return Observation(
        event_id=o.event_id,
        event_kind=o.event_kind,
        context=o.context,
        task_id=o.task_id,
        operation_id=o.operation_id,
        admission_receipt_id=o.admission_receipt_id,
        observed_at=at(o.observed_at),
        result=o.result,
        dimension=o.dimension,
        severity=o.severity,
        evidence_refs=o.evidence_refs,
        attribution=o.attribution,
        supersedes=o.supersedes,
        details=o.details,
    )


def record(r: CaseRun) -> None:
    """Run a record_outcome case."""
    obs = observation(r)
    if obs is None:
        r.fail("the case has no observation")
        return
    assert r.subject is not None
    a = r.subject.adapter
    rec, err, ok = r.call("record_outcome", lambda: a.record_outcome(obs))
    if not ok:
        return
    scan_error(r, "record_outcome", err)

    e = r.case.expect
    if e.outcome == OUT_ERROR:
        if err is None:
            r.fail("record_outcome recorded the observation, want an error")
            return
        r.want_reason("record_outcome", err)
        return
    if err is not None:
        r.fail(f"record_outcome raised {error_text(err)}, want {e.outcome}")
        return
    v: object = rec
    if v is None:
        r.fail("record_outcome returned None and raised nothing")
    elif isinstance(v, Signed):
        signed(r, v, obs)
    elif isinstance(v, NoVisibility):
        no_visibility(r, v)
    else:
        r.fail(
            f"record_outcome returned {type(v).__name__}; return a Signed or a"
            " NoVisibility value, not another type"
        )


def no_visibility(r: CaseRun, n: NoVisibility) -> None:
    scan_text(r, "record_outcome declaration", n.reason)
    try:
        n.validate()
    except ValueError as e:
        r.fail(f"no-visibility declaration: {e}")
    if r.case.expect.outcome == OUT_SIGNED:
        r.fail(f"record_outcome declared no visibility ({n.reason!r}), want a signed outcome")


def signed(r: CaseRun, s: Signed, obs: Observation) -> None:
    e = r.case.expect
    if e.outcome == OUT_NO_VISIBILITY:
        r.fail("record_outcome returned a signed outcome, want a declared absence of visibility")
        return
    try:
        s.validate()
    except ValueError as err:
        r.fail(f"signed outcome: {err}")
        return
    scan_jws(r, "signed outcome", s.jws)
    assert r.subject is not None
    verify = r.subject.verify_outcome
    if verify is not None:
        try:
            verify(s.jws)
        except Exception as err:
            r.fail(f"signature of the outcome does not verify: {error_text(err)}")
    rep = check_outcome_jws(r, s.jws, obs)
    if rep is None:
        return
    if (
        e.outcome == OUT_NO_EXEC_SUCCESS
        and rep.event_kind == EventKind.EXECUTION
        and rep.result == OutcomeResult.SUCCESS
    ):
        r.fail(
            "record_outcome signed an EXECUTION report with result SUCCESS although the case"
            " gives the adapter no execution visibility (draft 14.1: missing visibility is"
            " declared, never assumed to be success)"
        )


def check_outcome_jws(r: CaseRun, jws: str, obs: Observation) -> OutcomeReport | None:
    """Decode a compact JWS and check it as an outcome report of the observation: the
    JOSE header of draft 7.2, a payload that strict-parses as an OutcomeReport with
    every required member, the fields the adapter does not choose, and the time
    rules of draft 7.5 and 14.3."""
    parts = jws.split(".")
    try:
        hdr_raw = raw_url_decode(parts[0])
    except ValueError as err:
        r.fail(f"JWS header is not unpadded base64url: {err}")
        return None
    try:
        pay_raw = raw_url_decode(parts[1])
    except ValueError as err:
        r.fail(f"JWS payload is not unpadded base64url: {err}")
        return None

    try:
        hdr = strictjson.parse(hdr_raw, _HEADER_LIMITS)
    except strictjson.StrictJSONError as err:
        r.fail(f"JWS header: {err}")
        return None
    if not isinstance(hdr, Mapping):
        r.fail("JWS header: not a JSON object")
        return None
    if hdr.get("typ") != OUTCOME_TYP:
        r.fail(f"JWS typ is {hdr.get('typ')}, want {OUTCOME_TYP}")
    alg = hdr.get("alg")
    if alg not in ("ES256", "Ed25519"):
        r.fail(f"JWS alg is {alg}, want ES256 or Ed25519 (draft 7.2)")
    kid = hdr.get("kid")
    if not isinstance(kid, str) or not kid:
        r.fail("JWS header has no kid: a service-signed artifact names its key")
    for banned in ("jku", "x5u", "jwk", "crit"):
        if banned in hdr:
            r.fail(f"JWS header carries {banned!r}, which an outcome report must not (draft 7.2)")

    limits = strictjson.Limits(max_bytes=defaults().artifact_payload_bytes)
    try:
        rep = strictjson.decode(pay_raw, OutcomeReport, limits)
    except strictjson.StrictJSONError as err:
        r.fail(f"JWS payload is not an outcome report: {err}")
        return None
    require_members(r, pay_raw)
    check_report(r, rep, obs)
    return rep


def require_members(r: CaseRun, payload: bytes) -> None:
    """Fail for each member of the outcome report schema that the payload lacks.
    strictjson has already refused a null where the schema wants an array or an
    object, but it does not require members to be present."""
    try:
        members = strictjson.parse(payload, strictjson.Limits(max_bytes=len(payload) + 1))
    except strictjson.StrictJSONError as err:
        r.fail(f"JWS payload: {err}")
        return
    if not isinstance(members, Mapping):
        return
    for name, m in OutcomeReport._MEMBERS.items():
        if m.required and name not in members:
            r.fail(f"outcome report lacks the required member {name!r}")


def check_report(r: CaseRun, rep: OutcomeReport, obs: Observation) -> None:
    """Check the members of the report that the adapter does not choose against the
    observation, and the validity window."""
    if rep.pact_version != VERSION:
        r.fail(f"pact_version is {rep.pact_version!r}, want {VERSION!r}")
    for name, got, want in (
        ("event_id", rep.event_id, obs.event_id),
        ("operation_id", rep.operation_id, obs.operation_id),
        ("task_id", rep.task_id, obs.task_id),
        ("event_kind", rep.event_kind, obs.event_kind),
        ("result", rep.result, obs.result),
        ("dimension", rep.dimension, obs.dimension),
        ("severity", rep.severity, obs.severity),
        ("tenant_id", rep.tenant_id, obs.context.tenant_id),
        ("environment_id", rep.environment_id, obs.context.environment_id),
        ("sub", rep.sub, obs.context.agent_id),
    ):
        if str(got) != str(want):
            r.fail(
                f"outcome report {name} is {str(got)!r}, want {str(want)!r} from the observation"
            )
    want_observed = unix(obs.observed_at) if obs.observed_at is not None else 0
    if rep.observed_at != want_observed:
        r.fail(
            f"outcome report observed_at is {rep.observed_at}, want {want_observed}: the"
            " original observation time"
        )
    if rep.context != obs.context:
        r.fail(
            f"outcome report context is {json_text(rep.context)}, want the observation's"
            f" {json_text(obs.context)}"
        )
    if not ReporterRole.is_valid(rep.reporter_role):
        r.fail(f"reporter_role {rep.reporter_role!r} is not a defined role")
    if not 22 <= len(rep.jti) <= 128:
        r.fail(f"jti has {len(rep.jti)} characters, want 22 to 128")
    try:
        check_window(rep.iat, rep.nbf, rep.exp, r.now, SKEW)
    except ClockError as err:
        r.fail(f"outcome report validity: {err}")
    try:
        check_lifetime(Artifact.OUTCOME, rep.iat, rep.exp)
    except ClockError as err:
        r.fail(f"outcome report lifetime: {err}")
    for name, value in (("iss", rep.iss), ("aud", rep.aud)):
        if not value:
            r.fail(f"outcome report {name} is empty")
