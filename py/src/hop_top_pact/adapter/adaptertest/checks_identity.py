"""The checks of authenticate_native and resolve_agent_binding (Go adaptertest,
checks_identity.go)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast
from urllib.parse import urlsplit

from hop_top_pact.adapter._errors import Code, DependencyUnavailable, InvalidProof, NativeDenial
from hop_top_pact.adapter._errors import code_of as adapter_code_of
from hop_top_pact.adapter._types import AgentBinding, BindingStatus, Principal, Realm
from hop_top_pact.adapter.adaptertest.casefile import (
    ABSENT,
    OUT_AUTHENTICATED,
    OUT_BOUND,
    OUT_DENIED,
    OUT_ERROR,
    OUT_NOT_ENROLLED,
    OUT_UNUSABLE,
    ExpectBinding,
    ExpectPrincipal,
    RealmJSON,
)
from hop_top_pact.adapter.adaptertest.compare import (
    SKEW,
    CaseRun,
    binding_empty,
    error_text,
    find,
    json_equal,
    principal_empty,
    render,
)
from hop_top_pact.adapter.adaptertest.leak import scan_error, scan_value
from hop_top_pact.adapter.adaptertest.request import case_request
from hop_top_pact.core import Digest


def authenticate(r: CaseRun) -> None:
    """Run an authenticate_native case."""
    got = case_request(r)
    if got is None:
        return
    req, _ = got
    assert r.subject is not None
    a = r.subject.adapter
    res, err, ok = r.call("authenticate_native", lambda: a.authenticate_native(req))
    if not ok:
        return
    scan_error(r, "authenticate_native", err)
    if err is None and not isinstance(res, Principal):
        r.fail(f"authenticate_native returned {type(res).__name__}, want a Principal")
        return
    p = res if isinstance(res, Principal) else None
    if p is not None:
        scan_value(r, "authenticate_native principal", p)

    e = r.case.expect
    if e.outcome == OUT_AUTHENTICATED:
        if err is not None:
            r.fail(f"authenticate_native raised {error_text(err)}, want an authenticated principal")
            return
        if e.principal is not None and p is not None:
            check_principal(r, p, e.principal)
    elif e.outcome == OUT_DENIED:
        want_denial(r, p, err)
    elif e.outcome == OUT_ERROR:
        if err is None:
            r.fail(f"authenticate_native authenticated {_id_of(p)!r}, want an error")
            return
        r.want_reason("authenticate_native", err)
    if p is not None and principal_empty(p):
        r.fail("authenticate_native returned a zero principal and raised nothing")


def _id_of(p: Principal | None) -> str:
    return p.id if p is not None else ""


def want_denial(r: CaseRun, p: Principal | None, err: BaseException | None) -> None:
    """Check a native denial: a NativeDenial, which is an InvalidProof."""
    if err is None:
        r.fail(f"authenticate_native authenticated {_id_of(p)!r}, want a native denial")
        return
    d = find(err, NativeDenial)
    if d is None:
        r.fail(
            f"authenticate_native raised {type(err).__name__} ({error_text(err)}),"
            " want a NativeDenial"
        )
        return
    if find(err, InvalidProof) is None:
        r.fail("denial is not an InvalidProof")
    code = adapter_code_of(err)
    if code != Code.INVALID_PROOF:
        r.fail(f"denial code is {code}, want {Code.INVALID_PROOF}")
    want = r.case.expect.reason_code
    if want and d.public_reason() != want:
        r.fail(f"denial reason is {d.public_reason()}, want {want}")


def check_principal(r: CaseRun, p: Principal, want: ExpectPrincipal) -> None:
    """Check an authenticated principal against the case."""
    if principal_empty(p):
        return
    if want.id and p.id != want.id:
        r.fail(f"principal id is {p.id!r}, want {want.id!r}")
    if want.realm is not None:
        got = RealmJSON(tenant_id=p.realm.tenant_id, environment_id=p.realm.environment_id)
        if got != want.realm:
            r.fail(f"principal realm is {got}, want {want.realm}")
    if want.workload and p.workload != want.workload:
        r.fail(f"principal workload is {p.workload!r}, want {want.workload!r}")
    if want.mechanism and p.mechanism != want.mechanism:
        r.fail(f"principal mechanism is {p.mechanism!r}, want {want.mechanism!r}")
    check_attributes(r, p.attributes, want.attributes)
    r.not_after("principal authenticated_at", p.authenticated_at, r.now + SKEW)


def check_attributes(r: CaseRun, got: Mapping[str, object], want: object) -> None:
    """Compare the authenticated attributes the case names with those of the
    principal, each as JSON data: object member order is ignored, array order is
    not (draft 8.4). An attribute the case does not name is not checked."""
    if want is ABSENT or not isinstance(want, Mapping):
        return
    members = cast(Mapping[str, object], want)
    for name in sorted(members):
        if name not in got:
            r.fail(f"principal has no attribute {name!r}, want {render(members[name])}")
            continue
        try:
            eq = json_equal(members[name], got[name])
        except ValueError as e:
            r.fail(f"principal attribute {name!r} does not encode as JSON: {e}")
            continue
        if not eq:
            r.fail(
                f"principal attribute {name!r} is {render(got[name])}, want {render(members[name])}"
            )


def binding(r: CaseRun) -> None:
    """Run a resolve_agent_binding case."""
    k = r.case.call
    realm_json = k.realm if k.realm is not None else RealmJSON()
    realm = Realm(tenant_id=realm_json.tenant_id, environment_id=realm_json.environment_id)
    assert r.subject is not None
    a = r.subject.adapter
    res, err, ok = r.call(
        "resolve_agent_binding", lambda: a.resolve_agent_binding(realm, k.workload, k.agent_id)
    )
    if not ok:
        return
    scan_error(r, "resolve_agent_binding", err)
    if err is None and not isinstance(res, AgentBinding):
        r.fail(f"resolve_agent_binding returned {type(res).__name__}, want an AgentBinding")
        return
    b = res if isinstance(res, AgentBinding) else None

    e = r.case.expect
    if b is not None and not BindingStatus.is_valid(b.status):
        r.fail(f"binding status {b.status!r} is not a defined status")
    check_elsewhere_only_with_unknown(r, b)
    if e.outcome == OUT_BOUND:
        if err is not None or b is None:
            r.fail(f"resolve_agent_binding raised {_text(err)}, want an active binding")
            return
        check_bound(r, b, e.binding)
    elif e.outcome == OUT_NOT_ENROLLED:
        if err is not None or b is None:
            r.fail(f"resolve_agent_binding raised {_text(err)}, want status UNKNOWN with no error")
        elif b.status != BindingStatus.UNKNOWN:
            r.fail(f"binding status is {b.status}, want UNKNOWN: no binding exists in this realm")
        elif not binding_empty(b):
            r.fail(
                f"binding of status UNKNOWN names agent {b.agent_id!r} and a holder key;"
                " it must name none"
            )
        else:
            check_elsewhere(r, b, e.binding)
    elif e.outcome == OUT_UNUSABLE:
        check_unusable(r, b, err)
    elif e.outcome == OUT_ERROR:
        if err is None:
            status = b.status if b is not None else None
            r.fail(f"resolve_agent_binding returned a {status} binding, want an error")
            return
        r.want_reason("resolve_agent_binding", err)


def _text(err: BaseException | None) -> str:
    return "nothing" if err is None else error_text(err)


def check_elsewhere_only_with_unknown(r: CaseRun, b: AgentBinding | None) -> None:
    """Only an UNKNOWN result reports the agent ID enrolled for another workload of
    the realm (draft 17.1). A binding on the authenticated workload, revoked and
    compromised ones included, never carries the report. (A Python call that
    raises returns nothing, so no report comes with an error.)"""
    if b is None or not b.enrolled_elsewhere:
        return
    if b.status != BindingStatus.UNKNOWN:
        r.fail(
            f"binding of status {b.status} reports the agent ID enrolled for another"
            " workload; only an UNKNOWN result carries that report (draft 17.1)"
        )


def check_elsewhere(r: CaseRun, b: AgentBinding, want: ExpectBinding | None) -> None:
    """Compare the report that the agent ID is enrolled for another workload of the
    realm with the case, when the case requires a value."""
    if want is None or want.enrolled_elsewhere is None:
        return
    if b.enrolled_elsewhere != want.enrolled_elsewhere:
        r.fail(
            "agent ID enrolled for another workload is "
            f"{str(b.enrolled_elsewhere).lower()}, want "
            f"{str(want.enrolled_elsewhere).lower()} (draft 17.1)"
        )


def check_bound(r: CaseRun, b: AgentBinding, want: ExpectBinding | None) -> None:
    """Check an active binding against the case and the invariants of every binding
    the adapter calls active."""
    if b.status != BindingStatus.ACTIVE:
        r.fail(f"binding status is {b.status}, want ACTIVE")
    check_record(r, b, want)


def _absolute_uri(s: str) -> bool:
    try:
        return urlsplit(s).scheme != ""
    except ValueError:
        return False


def check_record(r: CaseRun, b: AgentBinding, want: ExpectBinding | None) -> None:
    """Check a binding that names an enrollment record, active, revoked or
    compromised, against the case: the record's agent, operator and holder key, a
    named source, and times within the skew."""
    if not _absolute_uri(b.agent_id):
        r.fail(f"agent id {b.agent_id!r} is not an absolute URI (draft 6.1)")
    try:
        Digest(b.holder_jkt).validate()
    except ValueError as e:
        r.fail(f"holder key thumbprint: {e}")
    if not b.source_id:
        r.fail("binding names no source")
    # Draft A.2: no source observation or status-check time may be later than
    # now plus the skew.
    r.not_after("binding observed_at", b.observed_at, r.now + SKEW)
    r.not_after("binding status_checked_at", b.status_checked_at, r.now + SKEW)
    if want is None:
        return
    if want.agent_id and b.agent_id != want.agent_id:
        r.fail(f"agent id is {b.agent_id!r}, want {want.agent_id!r}")
    if want.operator_id and b.operator_id != want.operator_id:
        r.fail(f"operator id is {b.operator_id!r}, want {want.operator_id!r}")
    if want.holder_jkt and b.holder_jkt != want.holder_jkt:
        r.fail(f"holder key thumbprint is {b.holder_jkt!r}, want {want.holder_jkt!r}")
    if want.status and b.status != want.status:
        r.fail(f"binding status is {b.status}, want {want.status}")
    check_elsewhere(r, b, want)


def check_unusable(r: CaseRun, b: AgentBinding | None, err: BaseException | None) -> None:
    """Check the result for a binding the source holds as revoked or compromised: no
    result that a caller can use as an active binding.

    Identity mapping IM-11 fixes the form: resolve_agent_binding returns the
    record's status, REVOKED or COMPROMISED, with the agent, operator and holder
    key, and raises nothing, so that a validator can state the reason (IM-29)
    and tell a revocation from a compromise. An error is not accepted: it hides
    the status, and an unavailable source would defer a request that must be
    refused. The call must never return an ACTIVE binding.
    """
    want = r.case.expect.binding
    if err is not None or b is None:
        status = want.status if want is not None and want.status else "REVOKED or COMPROMISED"
        if find(err, DependencyUnavailable) is not None:
            r.fail(
                f"a revoked or compromised binding was reported as an unavailable source"
                f" ({_text(err)}); that defers instead of refusing"
            )
        r.fail(
            f"resolve_agent_binding raised {_text(err)}, want the binding with status"
            f" {status}, its agent, operator and holder key, and no error (identity"
            " mapping IM-11)"
        )
        return
    if b.status in (BindingStatus.REVOKED, BindingStatus.COMPROMISED):
        check_record(r, b, want)
    elif b.status == BindingStatus.ACTIVE:
        r.fail(
            f"resolve_agent_binding returned an ACTIVE binding for agent {b.agent_id!r}"
            " whose binding the source holds as revoked or compromised"
        )
    else:
        r.fail(
            f"binding status is {b.status}, want REVOKED or COMPROMISED with the agent,"
            " operator and holder key of the record (identity mapping IM-11)"
        )
