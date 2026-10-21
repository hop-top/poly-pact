"""Replaced common cases (port of go/adapter/adaptertest/replaced_test.go).

Go's Run checks the declarations before any case runs; here
conformance_cases does, and run_case applies the verdict to one case.
"""

from __future__ import annotations

from typing import Any

import pytest

from hop_top_pact.adapter import DependencyUnavailable, NativeDenial, Principal
from hop_top_pact.adapter.adaptertest import (
    CaseFailure,
    LoadError,
    Options,
    Replacement,
    conformance_cases,
    evaluate_conformance,
    run_case,
)
from hop_top_pact.adapter.adaptertest.casefile import load_tree
from hop_top_pact.adapter.adaptertest.suite import check_replaced, verdict

CALL_PRINCIPAL = (
    '"principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}'
)
CALL_OPERATION = (
    '"operation": {"operation_id": "o", "environment_id": "e", "principal_id": "p", "action": "a",'
    ' "resources": [], "method": "GET", "target_uri": "https://x.example/", "body_digest": "",'
    ' "headers": {}}'
)


def case_with(at: Any, cid: str, outcome: str) -> str:
    """The minimal case, an authenticate_native case that expects a denial, with
    another id and outcome."""
    return str(
        at.MINIMAL_CASE.replace("COMMON-01.one", cid, 1).replace('"denied"', '"' + outcome + '"', 1)
    )


def binding_case_json(cid: str) -> str:
    """A resolve_agent_binding case that expects UNKNOWN."""
    return (
        '{"case_version": 1, "id": "' + cid + '", "title": "A binding case", "draft": ["17.1"],'
        ' "native_state": {"model": "common/1"}, "call": {"realm": {"tenant_id": "acme",'
        ' "environment_id": "https://gateway.example/environments/finance"}, "workload": "w-1",'
        ' "agent_id": "https://identity.example/agents/a"},'
        ' "expect": {"function": "resolve_agent_binding", "outcome": "unknown"}}'
    )


def call_case_json(cid: str, fn: str, outcome: str, call: str) -> str:
    """A case of the function fn with the call members call that expects outcome."""
    return (
        '{"case_version": 1, "id": "' + cid + '", "title": "A ' + fn + ' case", "draft": ["17.1"],'
        ' "native_state": {"model": "common/1"}, "call": {' + call + "},"
        ' "expect": {"function": "' + fn + '", "outcome": "' + outcome + '"}}'
    )


def authorize_case_json(cid: str, outcome: str) -> str:
    return call_case_json(cid, "authorize_native", outcome, CALL_PRINCIPAL + ", " + CALL_OPERATION)


def replaced_tree(at: Any) -> dict[str, str]:
    """Common cases of four functions and the cases of the adapter "mech": a
    denial, an authenticated principal, a binding, an error, two authorize_native
    decisions and a check_context verdict."""
    claim = CALL_PRINCIPAL + ', "native_path": "/x"'
    return {
        "adapters/_common/a.json": case_with(at, "COMMON-01.one", "error"),
        "adapters/_common/b.json": binding_case_json("COMMON-08.one"),
        "adapters/_common/c.json": authorize_case_json("COMMON-06.one", "ALLOW"),
        "adapters/_common/d.json": call_case_json(
            "COMMON-04.one", "read_native_claim", "error", claim
        ),
        "adapters/mech/mech-01.json": case_with(at, "MECH-01.denied", "denied"),
        "adapters/mech/mech-02.json": case_with(at, "MECH-02.authenticated", "authenticated"),
        "adapters/mech/mech-03.json": binding_case_json("MECH-03.binding"),
        "adapters/mech/mech-04.json": case_with(at, "MECH-04.error", "error"),
        "adapters/mech/mech-05.json": authorize_case_json("MECH-05.allow", "ALLOW"),
        "adapters/mech/mech-06.json": authorize_case_json("MECH-06.deny", "DENY"),
        "adapters/mech/mech-07.json": call_case_json(
            "MECH-07.check",
            "check_context",
            "PASS",
            CALL_PRINCIPAL + ", " + CALL_OPERATION + ', "check_id": "c"',
        ),
        "adapters/mech/mech-08.json": call_case_json(
            "MECH-08.claim", "read_native_claim", "error", claim
        ),
        "adapters/other/other-01.json": case_with(at, "OTHER-01.denied", "denied"),
    }


def test_check_replaced(at: Any) -> None:
    tree = replaced_tree(at)
    # MECH-02 expects a principal, so its case needs one.
    tree["adapters/mech/mech-02.json"] = tree["adapters/mech/mech-02.json"].replace(
        '"outcome": "authenticated"}', '"outcome": "authenticated", "principal": {"id": "p"}}', 1
    )
    cases, common = load_tree(at.tree_of(tree), "mech")

    def check(replaced: dict[str, Replacement], adapter: str = "mech") -> None:
        check_replaced(cases, common, Options(adapter=adapter, replaced=replaced))

    ok = Replacement(by="MECH-01.denied", reason="the mechanism has no bearer token")
    check({"COMMON-01.one": ok})
    # a replacement with another rejected outcome
    check({"COMMON-01.one": Replacement(by="MECH-04.error", reason="r")})
    # An authorize_native case may be replaced as well, under the same rules
    # (spec/v1.0/fixtures/adapters/README.md, "Replaced common cases").
    check(
        {
            "COMMON-06.one": Replacement(
                by="MECH-05.allow", reason="the decision answer carries no decision time"
            )
        }
    )
    check({"COMMON-01.one": ok, "COMMON-06.one": Replacement(by="MECH-05.allow", reason="r")})

    for name, cid, rep, want in (
        ("unknown id", "COMMON-01.none", ok, "is not a common case"),
        ("adapter case as the original", "MECH-04.error", ok, "is not a common case"),
        (
            "original of another function",
            "COMMON-08.one",
            Replacement(by="MECH-03.binding", reason="r"),
            "only authenticate_native and authorize_native cases",
        ),
        (
            "read_native_claim original",
            "COMMON-04.one",
            Replacement(by="MECH-08.claim", reason="r"),
            "only authenticate_native and authorize_native cases",
        ),
        (
            "authorize_native replaced by check_context",
            "COMMON-06.one",
            Replacement(by="MECH-07.check", reason="r"),
            "is a check_context case",
        ),
        (
            "authorize_native replaced by authenticate_native",
            "COMMON-06.one",
            Replacement(by="MECH-02.authenticated", reason="r"),
            "is a authenticate_native case",
        ),
        (
            "authorize_native replaced by the other outcome class",
            "COMMON-06.one",
            Replacement(by="MECH-06.deny", reason="r"),
            "other outcome class",
        ),
        (
            "authorize_native with an empty reason",
            "COMMON-06.one",
            Replacement(by="MECH-05.allow", reason=""),
            "gives no reason",
        ),
        ("no replacement", "COMMON-01.one", Replacement(by="", reason="r"), "names no replacement"),
        (
            "unknown replacement",
            "COMMON-01.one",
            Replacement(by="MECH-09.none", reason="r"),
            "not a case of adapters/mech",
        ),
        (
            "common case as the replacement",
            "COMMON-01.one",
            Replacement(by="COMMON-01.one", reason="r"),
            "not a case of adapters/mech",
        ),
        (
            "replacement of another function",
            "COMMON-01.one",
            Replacement(by="MECH-03.binding", reason="r"),
            "is a resolve_agent_binding case",
        ),
        (
            "replacement of the other outcome class",
            "COMMON-01.one",
            Replacement(by="MECH-02.authenticated", reason="r"),
            "other outcome class",
        ),
        (
            "empty reason",
            "COMMON-01.one",
            Replacement(by="MECH-01.denied", reason=" "),
            "gives no reason",
        ),
    ):
        with pytest.raises(LoadError) as e:
            check({cid: rep})
        assert want in str(e.value), f"{name}: {e.value}"

    # another adapter's case is no replacement
    other, common = load_tree(at.tree_of(tree), "other")
    with pytest.raises(LoadError, match="not a case of adapters/other"):
        check_replaced(other, common, Options(adapter="other", replaced={"COMMON-01.one": ok}))

    # conformance_cases checks the declarations before any case runs
    with pytest.raises(LoadError, match="is not a common case"):
        conformance_cases(
            Options(fixtures=at.tree_of(tree), adapter="mech", replaced={"COMMON-01.none": ok})
        )


def test_verdict() -> None:
    rep = Replacement(by="MECH-01.denied", reason="no bearer token")
    fails = ["principal id is 'x'"]

    errs, logs = verdict("COMMON-01.one", fails, None)
    assert (errs, logs) == (fails, []), "an undeclared failing case fails with its failures"
    errs, logs = verdict("COMMON-01.one", [], None)
    assert (errs, logs) == ([], [])
    errs, _ = verdict("COMMON-01.one", [], rep)
    assert len(errs) == 1
    assert "declared replaced by MECH-01.denied but passes" in errs[0]
    errs, logs = verdict("COMMON-01.one", fails, rep)
    assert errs == []
    assert fails[0] in logs
    assert "no bearer token" in logs[0]


def test_run_replaced(at: Any) -> None:
    denying = at.auth_fake(Principal(), NativeDenial("NO_CREDENTIAL"))
    tree = at.tree_of(
        {
            "adapters/_common/a.json": case_with(at, "COMMON-01.one", "error").replace(
                '"outcome": "error"',
                '"outcome": "error", "reason_code": "DEPENDENCY_UNAVAILABLE"',
                1,
            ),
            "adapters/mech/mech-01.json": case_with(at, "MECH-01.denied", "denied"),
        }
    )
    rep = Replacement(by="MECH-01.denied", reason="the mechanism cannot produce this error")
    opts = Options(fixtures=tree, adapter="mech", replaced={"COMMON-01.one": rep})

    # declared, failing, valid replacement
    cases, ids = conformance_cases(opts)
    assert ids == ["COMMON-01.one", "MECH-01.denied"]
    logs = run_case(at.factory_for(denying), cases[0], opts)
    assert "replaced by MECH-01.denied" in logs[0]
    assert len(logs) > 1, "the failures are logged"
    assert run_case(at.factory_for(denying), cases[1], opts) == []

    # a declared case that passes fails: the declaration is stale
    erring = at.auth_fake(None, at.wrap("x", DependencyUnavailable()))
    with pytest.raises(CaseFailure, match="drop the declaration"):
        run_case(at.factory_for(erring), cases[0], opts)

    # evaluate ignores the declaration
    res = evaluate_conformance(at.factory_for(denying), opts)
    assert [r.id for r in res] == ["COMMON-01.one", "MECH-01.denied"]
    assert not res[0].passed(), "the replaced case is reported as run and failed"
    assert res[1].passed()
