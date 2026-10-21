"""resolve_agent_binding of the memory adapter (port of the binding tests of
go/adapters/memory/memory_unit_test.go)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest

from hop_top_pact.adapter import (
    AgentBinding,
    BindingStatus,
    Code,
    DependencyUnavailable,
    UnsupportedRequirement,
    code_of,
)
from hop_top_pact.adapter import Realm as AdapterRealm
from hop_top_pact.adapters import memory as m

ENV = "https://gateway.example/environments/finance"
REALM = m.Realm(tenant_id="acme", environment_id=ENV)
OTHER = m.Realm(tenant_id="globex", environment_id=ENV)
AR = AdapterRealm(tenant_id="acme", environment_id=ENV)
JKT = KA = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
KB = "lHkry8t631MLf-lKvuVhoHKwGhJta35vQQ3PCjI0bVU"
KD = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
AG = "https://identity.example/agents/"
OPERATOR = "https://identity.example/operators/o"


def enrollments(*rows: m.Enrollment) -> Any:
    return lambda st: replace(st, enrollments=rows)


def test_resolve_agent_binding(mem: Any) -> None:
    def enroll(
        w: str, status: str, r: m.Realm, observed: int | None, checked: int | None
    ) -> m.Enrollment:
        return m.Enrollment(
            realm=r,
            workload=w,
            agent_id=AG + w,
            operator_id=OPERATOR,
            holder_jkt=JKT,
            status=status,
            observed_at=observed,
            status_checked_at=checked,
            source_id="registry",
            source_ref="ref-" + w,
        )

    past, future, edge, past_skew = mem.at(-60), mem.at(3600), mem.at(5), mem.at(6)
    a, _ = mem.new_adapter(
        enrollments(
            enroll("active", "ACTIVE", REALM, past, past),
            enroll("checked-edge", "ACTIVE", REALM, past, edge),
            enroll("checked-past", "ACTIVE", REALM, past, past_skew),
            enroll("revoked", "REVOKED", REALM, None, None),
            enroll("compromised", "COMPROMISED", REALM, None, None),
            enroll("unknown", "UNKNOWN", REALM, None, None),
            enroll("future", "ACTIVE", REALM, future, None),
            enroll("globex-only", "ACTIVE", OTHER, None, None),
        )
    )

    # resolve names the agent enrolled for w, so that only the realm and the
    # workload decide; test_resolve_agent_binding_selects_the_agent varies it.
    def resolve(realm: AdapterRealm, w: str) -> AgentBinding:
        b: AgentBinding = a.resolve_agent_binding(realm, w, AG + w)
        return b

    def at(sec: int) -> Any:
        return mem.EPOCH + timedelta(seconds=sec)

    b = resolve(AR, "active")
    assert (b.status, b.agent_id, b.holder_jkt, b.source_id, b.source_ref) == (
        BindingStatus.ACTIVE,
        AG + "active",
        JKT,
        "registry",
        "ref-active",
    )
    assert (b.observed_at, b.status_checked_at) == (at(past), at(past))
    # Identity mapping IM-11: a revoked or compromised binding is returned as its
    # status, with the agent, operator and holder key, and no error.
    for w, status in (
        ("revoked", BindingStatus.REVOKED),
        ("compromised", BindingStatus.COMPROMISED),
    ):
        assert resolve(AR, w) == AgentBinding(
            agent_id=AG + w,
            operator_id=OPERATOR,
            holder_jkt=JKT,
            status=status,
            source_id="registry",
            source_ref="ref-" + w,
        )
    for w in ("unknown", "no-such-workload", "globex-only"):
        assert resolve(AR, w) == AgentBinding(status=BindingStatus.UNKNOWN), w
    globex = AdapterRealm(tenant_id="globex", environment_id=ENV)
    assert resolve(globex, "globex-only").status == BindingStatus.ACTIVE
    with pytest.raises(DependencyUnavailable):
        resolve(AR, "future")
    # Draft A.2: no status-check time may be later than now plus the skew.
    b = resolve(AR, "checked-edge")
    assert (b.status, b.status_checked_at) == (BindingStatus.ACTIVE, at(edge))
    with pytest.raises(DependencyUnavailable):
        resolve(AR, "checked-past")


def _rec(
    r: m.Realm, w: str, agent: str, jkt: str, status: str = "ACTIVE", source: str = "registry"
) -> m.Enrollment:
    return m.Enrollment(
        realm=r,
        workload=w,
        agent_id=AG + agent,
        operator_id=OPERATOR,
        holder_jkt=jkt,
        status=status,
        source_id=source,
        source_ref="ref-" + agent,
    )


def test_resolve_agent_binding_selects_the_agent(mem: Any) -> None:
    """The agent ID the request names selects among the records of the
    authenticated workload in the realm, and only there (draft 17.1). An agent
    with no record on the workload, one enrolled only on another workload of the
    realm or only in another realm, a near-miss spelling of the agent ID and no
    agent ID at all answer UNKNOWN; a workload alone never names an agent."""
    a, _ = mem.new_adapter(
        enrollments(
            _rec(REALM, "shared", "a", KA),
            _rec(REALM, "shared", "b", KB),
            _rec(REALM, "dedicated", "d", KD),
            _rec(OTHER, "shared", "g", KD),
        ),
        shared=True,
    )
    for w, agent, jkt in (
        ("shared", AG + "a", KA),
        ("shared", AG + "b", KB),
        ("dedicated", AG + "d", KD),
        ("shared", AG + "c", ""),
        ("shared", AG + "d", ""),
        ("dedicated", AG + "a", ""),
        ("shared", AG + "g", ""),
        ("shared", AG + "A", ""),
        ("shared", AG + "a/", ""),
        ("shared", "", ""),
        ("dedicated", "", ""),
    ):
        b = a.resolve_agent_binding(AR, w, agent)
        if not jkt:
            assert (b.status, b.agent_id, b.holder_jkt) == (BindingStatus.UNKNOWN, "", ""), (
                w,
                agent,
            )
            continue
        assert (b.status, b.agent_id, b.holder_jkt) == (BindingStatus.ACTIVE, agent, jkt), (
            w,
            agent,
        )


def test_resolve_agent_binding_enrolled_elsewhere(mem: Any) -> None:
    """An UNKNOWN answer reports whether the agent ID is enrolled for another
    workload of the realm, in any status (draft 17.1). A binding on the
    authenticated workload never carries the report, and an enrollment in another
    realm never sets it. A record of the agent on another workload whose source
    cannot answer leaves the report unknown: DEPENDENCY_UNAVAILABLE."""
    other_env = m.Realm(tenant_id="acme", environment_id=ENV + "-staging")
    a, _ = mem.new_adapter(
        enrollments(
            _rec(REALM, "shared", "a", KA),
            _rec(REALM, "shared", "b", KB),
            _rec(REALM, "dedicated", "d", KD),
            _rec(REALM, "retired", "r", KA, "REVOKED"),
            _rec(REALM, "quarantine", "q", KB, "COMPROMISED"),
            _rec(REALM, "dedicated", "both", KD),
            _rec(REALM, "shared", "both", KA, "REVOKED"),
            _rec(OTHER, "shared", "g", KD),
            _rec(other_env, "elsewhere", "x", KD),
            _rec(REALM, "far", "down", KD, "ACTIVE", "registry-down"),
        ),
        lambda st: replace(st, unavailable_sources=("registry-down",)),
        shared=True,
    )
    U, A, R = BindingStatus.UNKNOWN, BindingStatus.ACTIVE, BindingStatus.REVOKED
    for w, agent, status, elsewhere in (
        ("shared", "a", A, False),
        ("shared", "both", R, False),
        ("dedicated", "both", A, False),
        ("shared", "d", U, True),
        ("dedicated", "a", U, True),
        ("shared", "r", U, True),
        ("shared", "q", U, True),
        ("shared", "c", U, False),
        ("shared", "g", U, False),
        ("shared", "x", U, False),
        ("elsewhere", "x", U, False),
        ("shared", "", U, False),
    ):
        b = a.resolve_agent_binding(AR, w, AG + agent if agent else "")
        assert (b.status, b.enrolled_elsewhere) == (status, elsewhere), (w, agent)
    with pytest.raises(DependencyUnavailable):
        a.resolve_agent_binding(AR, "shared", AG + "down")
    b = a.resolve_agent_binding(AR, "far", AG + "a")
    assert (b.status, b.enrolled_elsewhere) == (U, True), "unavailable source of another agent"


SHARED_W = "k8s:prod-eu-1:system:serviceaccount:payments:agent-runner"


def test_resolve_agent_binding_shared_workload(mem: Any) -> None:
    """On a workload that two agents share, each agent ID resolves to that agent's
    own record, whatever the status of the other agent's record and the order of
    the records (identity mapping IM-16, IM-18)."""

    def rec(agent: str, jkt: str, status: str) -> m.Enrollment:
        return m.Enrollment(
            realm=REALM,
            workload=SHARED_W,
            agent_id=agent,
            operator_id=OPERATOR,
            holder_jkt=jkt,
            status=status,
            source_id="registry",
        )

    def own(b: AgentBinding, status: str, agent: str, jkt: str) -> bool:
        if status == "UNKNOWN":
            return (b.status, b.agent_id, b.holder_jkt) == (BindingStatus.UNKNOWN, "", "")
        # ACTIVE, REVOKED and COMPROMISED: the status with the agent's own record
        # (identity mapping IM-11).
        return (b.status, b.agent_id, b.holder_jkt) == (status, agent, jkt)

    statuses = ("ACTIVE", "REVOKED", "COMPROMISED", "UNKNOWN")
    for sa in statuses:
        for sb in statuses:
            for order in ("a first", "b first"):
                rows = [rec(AG + "a", KA, sa), rec(AG + "b", KB, sb)]
                if order == "b first":
                    rows.reverse()
                a, _ = mem.new_adapter(enrollments(*rows), shared=True)
                for agent, jkt, status in ((AG + "a", KA, sa), (AG + "b", KB, sb)):
                    b = a.resolve_agent_binding(AR, SHARED_W, agent)
                    assert own(b, status, agent, jkt), (sa, sb, order, agent, b)


def test_resolve_agent_binding_several_records_of_the_agent(mem: Any) -> None:
    """When the source holds more than one record of the named agent on the
    workload, the rule of IM-18 applies among those records only. A record that is
    not REVOKED is in force, a COMPROMISED one included; a single record in force
    is the answer, several are UNKNOWN; with none in force a single revoked
    record is the answer and several are UNKNOWN. Records of another agent on the
    same workload never take part, and the order never matters."""
    k1, k2 = KA, KD

    def rec(agent: str, jkt: str, status: str) -> m.Enrollment:
        return m.Enrollment(
            realm=REALM,
            workload=SHARED_W,
            agent_id=agent,
            operator_id=OPERATOR,
            holder_jkt=jkt,
            status=status,
            source_id="registry",
        )

    unknown = (BindingStatus.UNKNOWN, "")
    for name, s1, s2, (status, jkt) in (
        ("both active", "ACTIVE", "ACTIVE", unknown),
        ("one revoked", "ACTIVE", "REVOKED", (BindingStatus.ACTIVE, k1)),
        ("one compromised", "ACTIVE", "COMPROMISED", unknown),
        ("one unknown", "ACTIVE", "UNKNOWN", unknown),
        ("both revoked", "REVOKED", "REVOKED", unknown),
        # The single record in force is COMPROMISED: it is the answer, as its
        # status with its own key (identity mapping IM-11, IM-18).
        ("compromised and revoked", "COMPROMISED", "REVOKED", (BindingStatus.COMPROMISED, k1)),
        ("both compromised", "COMPROMISED", "COMPROMISED", unknown),
    ):
        for order in ("first", "second"):
            # Agent B's ACTIVE record on the same workload sits between agent A's
            # two records; it is never part of A's answer.
            rows = [rec(AG + "a", k1, s1), rec(AG + "b", KB, "ACTIVE"), rec(AG + "a", k2, s2)]
            if order == "second":
                rows[0], rows[2] = rows[2], rows[0]
            a, _ = mem.new_adapter(enrollments(*rows), shared=True)
            b = a.resolve_agent_binding(AR, SHARED_W, AG + "a")
            want_agent = "" if status == BindingStatus.UNKNOWN else AG + "a"
            assert (b.status, b.agent_id, b.holder_jkt) == (status, want_agent, jkt), (name, order)
            assert a.resolve_agent_binding(AR, SHARED_W, AG + "b").holder_jkt == KB, (name, order)


def test_resolve_agent_binding_dedicated_workload(mem: Any) -> None:
    """By default a workload serves one agent, and a workload with more than one
    enrollment in force is a configuration error: whichever agent ID the request
    names, UNSUPPORTED_REQUIREMENT (draft 17.1, identity mapping IM-19). Only
    records in force count, as IM-18 defines them: a REVOKED record does not, a
    COMPROMISED one does, and so does every other status. Records of another
    workload or of another realm never count. With with_shared_workloads the same
    records select by the agent ID instead."""
    w = SHARED_W

    def config_error(a: m.MemoryAdapter) -> None:
        for agent in (AG + "a", AG + "b", AG + "c", ""):
            with pytest.raises(UnsupportedRequirement) as e:
                a.resolve_agent_binding(AR, w, agent)
            assert code_of(e.value) == Code.UNSUPPORTED_REQUIREMENT, agent

    def selects(a: m.MemoryAdapter, want: dict[str, BindingStatus]) -> None:
        for agent, status in want.items():
            b = a.resolve_agent_binding(AR, w, AG + agent)
            want_agent = "" if status == BindingStatus.UNKNOWN else AG + agent
            assert (b.status, b.agent_id) == (status, want_agent), agent

    A, R, C, U = (
        BindingStatus.ACTIVE,
        BindingStatus.REVOKED,
        BindingStatus.COMPROMISED,
        BindingStatus.UNKNOWN,
    )
    for name, rows, in_error, want in (
        ("two active", [_rec(REALM, w, "a", KA), _rec(REALM, w, "b", KB)], True, {}),
        (
            "compromised and active",
            [_rec(REALM, w, "a", KA, "COMPROMISED"), _rec(REALM, w, "b", KB)],
            True,
            {},
        ),
        (
            "two compromised",
            [_rec(REALM, w, "a", KA, "COMPROMISED"), _rec(REALM, w, "b", KB, "COMPROMISED")],
            True,
            {},
        ),
        (
            "unknown status and active",
            [_rec(REALM, w, "a", KA, "UNKNOWN"), _rec(REALM, w, "b", KB)],
            True,
            {},
        ),
        (
            "two active and a revoked",
            [_rec(REALM, w, "d", KD, "REVOKED"), _rec(REALM, w, "a", KA), _rec(REALM, w, "b", KB)],
            True,
            {},
        ),
        (
            "revoked and active",
            [_rec(REALM, w, "a", KA, "REVOKED"), _rec(REALM, w, "b", KB)],
            False,
            {"a": R, "b": A, "c": U},
        ),
        (
            "revoked and compromised",
            [_rec(REALM, w, "a", KA, "REVOKED"), _rec(REALM, w, "b", KB, "COMPROMISED")],
            False,
            {"a": R, "b": C},
        ),
        (
            "two revoked",
            [_rec(REALM, w, "a", KA, "REVOKED"), _rec(REALM, w, "b", KB, "REVOKED")],
            False,
            {"a": R, "b": R},
        ),
        (
            "another realm",
            [_rec(REALM, w, "a", KA), _rec(OTHER, w, "b", KB)],
            False,
            {"a": A, "b": U},
        ),
        (
            "another workload",
            [_rec(REALM, w, "a", KA), _rec(REALM, w + "-2", "b", KB)],
            False,
            {"a": A, "b": U},
        ),
    ):
        for order in ("as listed", "reversed"):
            ordered = rows if order == "as listed" else rows[::-1]
            a, _ = mem.new_adapter(enrollments(*ordered))
            if in_error:
                config_error(a)
            else:
                selects(a, want)
            assert name

    # a record of the workload that cannot be read
    a, _ = mem.new_adapter(
        enrollments(_rec(REALM, w, "a", KA), _rec(REALM, w, "b", KB, "REVOKED", "down")),
        lambda st: replace(st, unavailable_sources=("down",)),
    )
    with pytest.raises(DependencyUnavailable):
        a.resolve_agent_binding(AR, w, AG + "a")

    # shared workloads select by the agent ID
    a, _ = mem.new_adapter(
        enrollments(_rec(REALM, w, "a", KA), _rec(REALM, w, "b", KB, "COMPROMISED")), shared=True
    )
    selects(a, {"a": A, "b": C, "c": U})
