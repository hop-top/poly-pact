"""The checks of authenticate_native and resolve_agent_binding.

Port of go/adapter/adaptertest/checks_identity_test.go. An error is raised,
not returned next to a value, so the Go rows of a principal or a binding
returned together with an error have no counterpart; a wrapped Go error is a
PactError raised from its cause (at.wrap).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

from hop_top_pact.adapter import (
    AgentBinding,
    BindingStatus,
    ContextMismatch,
    DependencyUnavailable,
    InvalidProof,
    NativeDenial,
    Principal,
    Realm,
)
from hop_top_pact.adapter.adaptertest import ExpectBinding, ExpectPrincipal
from hop_top_pact.adapter.adaptertest.compare import SKEW


def test_authenticate_checks(at: Any) -> None:
    good = at.good_principal()
    want = ExpectPrincipal(id=good.id, realm=at.ACME_JS, workload="w-1", mechanism="bearer")
    denial = NativeDenial("NO_CREDENTIAL")
    case, fake = at.auth_case, at.auth_fake

    at.run_rows(
        [
            ("authenticated", fake(good, None), case("authenticated", principal=want), ()),
            (
                "authenticated but errors",
                fake(None, denial),
                case("authenticated", principal=want),
                ("want an authenticated principal",),
            ),
            (
                "wrong id",
                fake(replace(good, id="other"), None),
                case("authenticated", principal=want),
                ("principal id",),
            ),
            (
                "wrong tenant",
                fake(replace(good, realm=replace(good.realm, tenant_id="globex")), None),
                case("authenticated", principal=want),
                ("principal realm",),
            ),
            (
                "wrong environment",
                fake(replace(good, realm=replace(good.realm, environment_id="other")), None),
                case("authenticated", principal=want),
                ("principal realm",),
            ),
            (
                "wrong workload",
                fake(replace(good, workload="w-2"), None),
                case("authenticated", principal=want),
                ("principal workload",),
            ),
            (
                "wrong mechanism",
                fake(replace(good, mechanism="mtls"), None),
                case("authenticated", principal=want),
                ("principal mechanism",),
            ),
            (
                "authenticated in the future",
                fake(replace(good, authenticated_at=at.NOW + timedelta(minutes=1)), None),
                case("authenticated", principal=want),
                ("authenticated_at",),
            ),
            (
                "authenticated at the skew edge",
                fake(replace(good, authenticated_at=at.NOW + SKEW), None),
                case("authenticated", principal=want),
                (),
            ),
            (
                "zero principal without error",
                fake(Principal(), None),
                case("authenticated", principal=ExpectPrincipal()),
                ("zero principal",),
            ),
            (
                "not a principal",
                fake("alice", None),
                case("authenticated", principal=want),
                ("want a Principal",),
            ),
            ("denied", fake(None, denial), case("denied", reason_code="NO_CREDENTIAL"), ()),
            (
                "denied through wrapping",
                fake(None, at.wrap("authn", denial)),
                case("denied", reason_code="NO_CREDENTIAL"),
                (),
            ),
            (
                "denied but authenticated",
                fake(good, None),
                case("denied"),
                ("want a native denial",),
            ),
            (
                "denied with a plain error",
                fake(None, at.Wrapped("no")),
                case("denied"),
                ("want a NativeDenial",),
            ),
            (
                "denied with the wrong reason",
                fake(None, NativeDenial("CREDENTIAL_REJECTED")),
                case("denied", reason_code="NO_CREDENTIAL"),
                ("denial reason is CREDENTIAL_REJECTED",),
            ),
            (
                "denied with free text is a rejection",
                fake(None, NativeDenial("user alice unknown")),
                case("denied", reason_code="NO_CREDENTIAL"),
                ("denial reason is CREDENTIAL_REJECTED",),
            ),
            (
                "denied with an exception that is not a PactError",
                fake(None, RuntimeError("no")),
                case("denied"),
                ("raised RuntimeError",),
            ),
            (
                "error with a code",
                fake(None, at.wrap("x", DependencyUnavailable())),
                case("error", reason_code="DEPENDENCY_UNAVAILABLE"),
                (),
            ),
            ("error expected, none returned", fake(good, None), case("error"), ("want an error",)),
            (
                "error with the wrong code",
                fake(None, ContextMismatch()),
                case("error", reason_code="DEPENDENCY_UNAVAILABLE"),
                ("error code is CONTEXT_MISMATCH",),
            ),
            (
                "error without a code",
                fake(None, at.Wrapped("boom")),
                case("error", reason_code="DEPENDENCY_UNAVAILABLE"),
                ("carries no draft 13.4 code",),
            ),
        ]
    )


def test_binding_call_arguments(at: Any) -> None:
    """The suite hands resolve_agent_binding the realm, the workload and the agent ID
    of the call, unchanged (draft 17.1)."""
    calls: list[tuple[Realm, str, str]] = []

    def bind(realm: Realm, workload: str, agent: str) -> AgentBinding:
        calls.append((realm, workload, agent))
        return AgentBinding(status=BindingStatus.UNKNOWN)

    c = at.bind_case("unknown")
    c = replace(
        c,
        call=replace(
            c.call,
            workload="k8s:prod-eu-1:system:serviceaccount:payments:agent-runner",
            agent_id="https://identity.example/agents/payments-runner-b",
        ),
    )
    at.want_clean(at.run_fake(at.FakeAdapter(bind=bind), c))
    assert calls == [
        (
            at.ACME,
            "k8s:prod-eu-1:system:serviceaccount:payments:agent-runner",
            "https://identity.example/agents/payments-runner-b",
        )
    ], "called once with the realm, the workload and the agent ID of the call"


def test_binding_checks(at: Any) -> None:
    good = at.good_binding()
    want_bound = ExpectBinding(
        agent_id=good.agent_id,
        operator_id=good.operator_id,
        holder_jkt=good.holder_jkt,
        status="ACTIVE",
    )
    revoked = replace(good, status=BindingStatus.REVOKED)
    compromised = replace(good, status=BindingStatus.COMPROMISED)

    def want_status(s: str) -> ExpectBinding:
        return replace(want_bound, status=s)

    want_revoked, want_compromised = want_status("REVOKED"), want_status("COMPROMISED")
    bound_err = at.wrap("binding", InvalidProof())
    unknown = AgentBinding(status=BindingStatus.UNKNOWN)
    loose = ExpectBinding()
    case, fake = at.bind_case, at.bind_fake

    at.run_rows(
        [
            ("bound", fake(good, None), case("bound", binding=want_bound), ()),
            (
                "bound but errors",
                fake(None, bound_err),
                case("bound", binding=want_bound),
                ("want an active binding",),
            ),
            (
                "bound but revoked",
                fake(revoked, None),
                case("bound", binding=want_bound),
                ("want ACTIVE",),
            ),
            (
                "agent id is not a URI",
                fake(replace(good, agent_id="agent-1"), None),
                case("bound", binding=loose),
                ("not an absolute URI",),
            ),
            (
                "holder key is not a thumbprint",
                fake(replace(good, holder_jkt="short"), None),
                case("bound", binding=loose),
                ("holder key thumbprint",),
            ),
            (
                "no source",
                fake(replace(good, source_id=""), None),
                case("bound", binding=loose),
                ("names no source",),
            ),
            (
                "observed in the future",
                fake(replace(good, observed_at=at.NOW + timedelta(hours=1)), None),
                case("bound", binding=loose),
                ("binding observed_at",),
            ),
            # Draft A.2: no status-check time may be later than now plus the skew.
            (
                "status checked past the skew",
                fake(replace(good, status_checked_at=at.NOW + SKEW + timedelta(seconds=1)), None),
                case("bound", binding=loose),
                ("binding status_checked_at",),
            ),
            (
                "status checked at the skew edge",
                fake(replace(good, status_checked_at=at.NOW + SKEW), None),
                case("bound", binding=loose),
                (),
            ),
            (
                "wrong agent",
                fake(good, None),
                case("bound", binding=ExpectBinding(agent_id="https://other.example/a")),
                ("agent id is",),
            ),
            (
                "wrong operator",
                fake(good, None),
                case("bound", binding=ExpectBinding(operator_id="https://other.example/o")),
                ("operator id is",),
            ),
            (
                "wrong holder key",
                fake(good, None),
                case(
                    "bound",
                    binding=ExpectBinding(holder_jkt="yy0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"),
                ),
                ("holder key thumbprint is",),
            ),
            (
                "undefined status",
                fake(replace(good, status="SUSPENDED"), None),
                case("bound", binding=loose),
                ("not a defined status",),
            ),
            (
                "not a binding",
                fake("ACTIVE", None),
                case("bound", binding=loose),
                ("want an AgentBinding",),
            ),
            ("not enrolled", fake(unknown, None), case("unknown"), ()),
            ("not enrolled but active", fake(good, None), case("unknown"), ("want UNKNOWN",)),
            (
                "not enrolled but errors",
                fake(None, bound_err),
                case("unknown"),
                ("status UNKNOWN with no error",),
            ),
            (
                "not enrolled but names an agent",
                fake(replace(good, status=BindingStatus.UNKNOWN), None),
                case("unknown"),
                ("names agent",),
            ),
            # Identity mapping IM-11: a REVOKED or COMPROMISED binding comes back
            # as its status, with the agent, operator and holder key of the
            # record, and no error.
            (
                "unusable as REVOKED",
                fake(revoked, None),
                case("unusable", binding=want_revoked),
                (),
            ),
            (
                "unusable as COMPROMISED",
                fake(compromised, None),
                case("unusable", binding=want_compromised),
                (),
            ),
            (
                "unusable as an error",
                fake(None, bound_err),
                case("unusable", binding=want_revoked),
                ("want the binding with status REVOKED", "IM-11"),
            ),
            (
                "unusable but ACTIVE",
                fake(good, None),
                case("unusable", binding=want_revoked),
                ("returned an ACTIVE binding",),
            ),
            (
                "unusable but UNKNOWN",
                fake(unknown, None),
                case("unusable", binding=want_revoked),
                ("want REVOKED or COMPROMISED",),
            ),
            (
                "unusable as unavailable",
                fake(None, at.wrap("x", DependencyUnavailable())),
                case("unusable", binding=want_revoked),
                ("unavailable source",),
            ),
            (
                "unusable with the wrong status",
                fake(revoked, None),
                case("unusable", binding=want_compromised),
                ("binding status is REVOKED, want COMPROMISED",),
            ),
            (
                "unusable status without the agent",
                fake(replace(good, status=BindingStatus.REVOKED, agent_id=""), None),
                case("unusable", binding=ExpectBinding(status="REVOKED")),
                ("not an absolute URI",),
            ),
            (
                "unusable status without the holder key",
                fake(replace(good, status=BindingStatus.REVOKED, holder_jkt=""), None),
                case("unusable", binding=ExpectBinding(status="REVOKED")),
                ("holder key thumbprint",),
            ),
            (
                "unusable status that names no source",
                fake(replace(good, status=BindingStatus.REVOKED, source_id=""), None),
                case("unusable", binding=ExpectBinding(status="REVOKED")),
                ("names no source",),
            ),
            (
                "unusable status checked past the skew",
                fake(
                    replace(
                        good,
                        status=BindingStatus.REVOKED,
                        status_checked_at=at.NOW + SKEW + timedelta(seconds=1),
                    ),
                    None,
                ),
                case("unusable", binding=ExpectBinding(status="REVOKED")),
                ("binding status_checked_at",),
            ),
            (
                "unusable status of another agent",
                fake(replace(revoked, agent_id="https://identity.example/agents/b"), None),
                case("unusable", binding=want_revoked),
                ("agent id is",),
            ),
            (
                "unusable status with another operator",
                fake(replace(revoked, operator_id="https://identity.example/operators/p"), None),
                case("unusable", binding=want_revoked),
                ("operator id is",),
            ),
            (
                "unusable status with another key",
                fake(
                    replace(revoked, holder_jkt="lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU"), None
                ),
                case("unusable", binding=want_revoked),
                ("holder key thumbprint is",),
            ),
            ("error", fake(None, bound_err), case("error", reason_code="INVALID_PROOF"), ()),
            (
                "error expected, binding returned",
                fake(good, None),
                case("error"),
                ("want an error",),
            ),
        ]
    )


def test_binding_enrolled_elsewhere(at: Any) -> None:
    """Draft 17.1 has UNKNOWN come with whether the agent ID is enrolled for another
    workload of the realm. A case can require the value; the suite requires it
    false for every result that is not an UNKNOWN."""
    unknown = AgentBinding(status=BindingStatus.UNKNOWN)
    elsewhere = AgentBinding(status=BindingStatus.UNKNOWN, enrolled_elsewhere=True)
    good = at.good_binding()
    revoked = replace(good, status=BindingStatus.REVOKED)

    def want(v: bool | None) -> ExpectBinding:
        return ExpectBinding(enrolled_elsewhere=v)

    def want_record(s: str, v: bool | None) -> ExpectBinding:
        return ExpectBinding(
            agent_id=good.agent_id,
            operator_id=good.operator_id,
            holder_jkt=good.holder_jkt,
            status=s,
            enrolled_elsewhere=v,
        )

    case, fake = at.bind_case, at.bind_fake
    at.run_rows(
        [
            (
                "unknown, enrolled elsewhere as required",
                fake(elsewhere, None),
                case("unknown", binding=want(True)),
                (),
            ),
            (
                "unknown, not enrolled elsewhere as required",
                fake(unknown, None),
                case("unknown", binding=want(False)),
                (),
            ),
            (
                "unknown, enrolled elsewhere not reported",
                fake(unknown, None),
                case("unknown", binding=want(True)),
                ("enrolled for another workload is false, want true",),
            ),
            (
                "unknown, enrolled elsewhere reported wrongly",
                fake(elsewhere, None),
                case("unknown", binding=want(False)),
                ("enrolled for another workload is true, want false",),
            ),
            ("unknown, not required either way", fake(elsewhere, None), case("unknown"), ()),
            (
                "bound, false as required",
                fake(good, None),
                case("bound", binding=want_record("ACTIVE", False)),
                (),
            ),
            (
                "bound with the flag",
                fake(replace(good, enrolled_elsewhere=True), None),
                case("bound", binding=want_record("ACTIVE", None)),
                ("status ACTIVE reports the agent ID enrolled for another workload",),
            ),
            (
                "unusable with the flag",
                fake(replace(revoked, enrolled_elsewhere=True), None),
                case("unusable", binding=want_record("REVOKED", None)),
                ("status REVOKED reports the agent ID enrolled for another workload",),
            ),
        ]
    )
