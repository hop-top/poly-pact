"""Rulings of the validator over the shared evaluation cases. Port of
go/validator/rulings_test.go and transport_test.go."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact import contract, validator
from hop_top_pact.adapter import Code, Realm
from hop_top_pact.core.enums import CheckStatus, Decision, Mode
from hop_top_pact.core.types import CheckResult
from hop_top_pact.validator import _problem
from validator_support import Fixture, prepare

FIXTURES = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures"

B7_CHECKS = [
    "native-authentication", "agent-holder-binding", "contract-validity", "nonce",
    "operation-binding", "intent-binding", "profile-validity", "evidence-validity",
    "reputation-context", "security-hold", "active-policy", "principal", "roles",
    "supervisor-approval", "isolation", "reputation-status", "native-principal-binding-v1",
    "purpose-operation-v1", "native-delegation-v1", "security-hold-v1",
]  # fmt: skip


def case(id_: str) -> Fixture:
    if not FIXTURES.exists():
        pytest.skip("no spec/ tree (mirror checkout)")
    return prepare(FIXTURES / id_)


def check(res: validator.Result, id_: str) -> CheckResult:
    return next(c for c in res.attestation.checks if c.check_id == id_)


def want_check(res: validator.Result, id_: str, result: CheckStatus, reason: str) -> None:
    c = check(res, id_)
    assert (c.result, c.reason_code) == (result, reason), id_


class FailingHolds:
    def holds(self, realm: Realm, agent_id: str) -> Sequence[str]:
        from hop_top_pact.adapter import DependencyUnavailable

        raise DependencyUnavailable("holds")


def test_reputation_rule_ages() -> None:
    # For a field rule under /attributes/reputation, max_age_seconds bounds the age of the
    # snapshot's iat and status_max_age_seconds the age of the validator's own security-hold
    # check; the result records the snapshot's iat as source_observed_at and the time of the
    # hold check as status_checked_at (draft 9.2, Appendix A.2).
    f = case("admission/valid")
    f.clock.advance(timedelta(seconds=10))  # within the snapshot's 30 s bound
    res = f.validator.evaluate(f.request)
    snap = check(res, "reputation-context")
    rule = check(res, "reputation-status")
    now = int(f.clock.now().timestamp())
    assert snap.source_observed_at is not None
    assert snap.source_observed_at != now, "the case must present a snapshot issued before now"
    assert rule.result == CheckStatus.PASS, rule
    assert rule.source_observed_at == snap.source_observed_at
    assert rule.status_checked_at == now


def test_reputation_rule_hold_outage() -> None:
    # When the hold check cannot be made, the status of a reputation rule is not
    # established: UNKNOWN DEPENDENCY_UNAVAILABLE, whatever the snapshot says.
    f = case("admission/valid")
    f.validator.holds = FailingHolds()
    res = f.validator.evaluate(f.request)
    want_check(res, "reputation-status", CheckStatus.UNKNOWN, "DEPENDENCY_UNAVAILABLE")
    assert res.attestation.decision == Decision.DEFERRED


class ChecksSelector:
    """A selector whose table lists checks as the authorized context_checks of every set, or
    no entry when ok is false."""

    def __init__(self, inner: Any, checks: Sequence[str], ok: bool) -> None:
        self.inner, self._checks, self._ok = inner, list(checks), ok

    def order(self) -> Sequence[str]:
        return self.inner.order()  # type: ignore[no-any-return]

    def select(self, in_: validator.SelectionInput) -> str:
        return self.inner.select(in_)  # type: ignore[no-any-return]

    def rules(self, set_: str) -> Any:
        return self.inner.rules(set_)

    def checks(self, set_: str) -> Sequence[str] | None:
        return list(self._checks) if self._ok else None


class ChecksRegistry:
    def __init__(self, inner: Any, checks: Sequence[str], ok: bool) -> None:
        self.inner, self._checks, self._ok = inner, checks, ok

    def active(self) -> validator.ActivePolicy:
        return self.inner.active()  # type: ignore[no-any-return]

    def selection(self, c: contract.Contract) -> validator.Selection:
        s: validator.Selection = self.inner.selection(c)
        if s.selector is not None:
            s = replace(s, selector=ChecksSelector(s.selector, self._checks, self._ok))
        return s


ISSUED = [
    "native-principal-binding-v1", "purpose-operation-v1", "native-delegation-v1",
    "security-hold-v1", "selection-consistency-v1",
]  # fmt: skip

CHECKS = {
    "the table's entry": (ISSUED, True, CheckStatus.PASS),
    "another order": (
        [ISSUED[1], ISSUED[0], *ISSUED[2:]],
        True,
        CheckStatus.FAIL,
    ),
    "one check fewer": (ISSUED[:4], True, CheckStatus.FAIL),
    "one check more": ([*ISSUED, "native-approval-v1"], True, CheckStatus.FAIL),
    "no entry for the set": (ISSUED, False, CheckStatus.FAIL),
}


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_contract_checks_authorized(name: str) -> None:
    # A validator holding the table compares the contract's context_checks with the entry of
    # its selected set, as JSON data with array order significant; a difference is
    # contract-validity FAIL CONTEXT_MISMATCH (draft 11.3 step 3).
    checks, ok, want = CHECKS[name]
    f = case("selection/same-snapshot")
    f.validator.policies = ChecksRegistry(f.validator.policies, checks, ok)
    res = f.validator.evaluate(f.request)
    c = check(res, "contract-validity")
    if want == CheckStatus.PASS:
        assert c.result == CheckStatus.PASS
        assert res.attestation.decision == Decision.ADMISSIBLE
    else:
        assert (c.result, c.reason_code) == (CheckStatus.FAIL, "CONTEXT_MISMATCH")


class FailingReceipts:
    def __init__(self, inner: Any) -> None:
        self.inner = inner

    def put(self, r: validator.Result) -> None:
        raise OSError("disk full")

    def get(self, jti: str) -> validator.Result:
        return self.inner.get(jti)  # type: ignore[no-any-return]

    def by_contract(self, d: str) -> list[validator.Result]:
        return self.inner.by_contract(d)  # type: ignore[no-any-return]


def test_receipt_store_check_order() -> None:
    # receipt-store is a protocol check, listed after active-policy and before the field
    # rules (draft 12.1).
    f = case("admission/valid")
    f.validator.receipts = FailingReceipts(f.validator.receipts)
    with pytest.raises(_problem.Rejection) as ei:
        f.validator.evaluate(f.request)
    res = ei.value.result
    assert isinstance(res, validator.Result)
    ids = [c.check_id for c in res.attestation.checks]
    assert ids == [*B7_CHECKS[:11], "receipt-store", *B7_CHECKS[11:]]


def case_copy(tmp: Path, id_: str, edit: Callable[[dict[str, Any]], None]) -> Fixture:
    """Copy the manifest, the test keys and the case and expected directories of id into a
    fresh fixture tree, apply edit to the case's config.json, and prepare the case from the
    copy."""
    if not FIXTURES.exists():
        pytest.skip("no spec/ tree (mirror checkout)")
    for rel in ("manifest.json", "keys", id_, "expected/" + id_):
        src, dst = FIXTURES / rel, tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copy(src, dst)
    p = tmp / id_ / "config.json"
    cfg = json.loads(p.read_bytes())
    edit(cfg)
    # hop_top_pact.conformance rejects the config.json members it does not read: the support
    # package reads them from config.extras.json.
    extras: dict[str, Any] = {}
    for key in ("purposes", "reputation_context"):
        if key in cfg:
            extras[key] = cfg.pop(key)
    if "scoring_policy_revisions" in cfg.get("active_policy", {}):
        extras["active_policy"] = {
            "scoring_policy_revisions": cfg["active_policy"].pop("scoring_policy_revisions")
        }
    sel = cfg.get("selection", {}).get("selector", {})
    if "checks" in sel:
        extras["selection"] = {"selector": {"checks": sel.pop("checks")}}
    p.write_text(json.dumps(cfg))
    (tmp / id_ / "config.extras.json").write_text(json.dumps(extras))
    return prepare(tmp / id_)


B2_PURPOSE = "https://policies.example/purposes/invoice-summary/v1"
CLASS = {"prefix": "https://invoices.example/invoices/", "class": "department-finance-invoice"}
SELECTION_CHECKS = ["native-principal-binding-v1", "purpose-operation-v1", "native-delegation-v1",
                    "security-hold-v1", "selection-consistency-v1"]  # fmt: skip


def _set(key: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def edit(c: dict[str, Any]) -> None:
        c[key] = value

    return edit


def _revisions(revs: list[str]) -> Callable[[dict[str, Any]], None]:
    def edit(c: dict[str, Any]) -> None:
        c["active_policy"]["scoring_policy_revisions"] = revs

    return edit


def _checks(checks: list[str]) -> Callable[[dict[str, Any]], None]:
    def edit(c: dict[str, Any]) -> None:
        c["selection"]["selector"]["checks"] = {"established": checks}

    return edit


def _context(prefix: str, cls: str, runtime: str = "managed-v1") -> dict[str, Any]:
    return {"resource_classes": [{"prefix": prefix, "class": cls}], "runtime_class": runtime}


CONFIGURED = [
    ("same purposes", "admission/valid", _set("purposes", {B2_PURPOSE: ["invoice.read"]}),
     "purpose-operation-v1", CheckStatus.PASS, "REQUIREMENT_SATISFIED"),
    ("purpose not installed", "admission/valid",
     _set("purposes", {"https://policies.example/purposes/other/v1": ["invoice.read"]}),
     "purpose-operation-v1", CheckStatus.UNKNOWN, "UNSUPPORTED_PURPOSE"),
    ("action outside the purpose", "admission/valid",
     _set("purposes", {B2_PURPOSE: ["invoice.export"]}),
     "purpose-operation-v1", CheckStatus.FAIL, "CONTEXT_MISMATCH"),
    ("same reputation context", "admission/valid",
     _set("reputation_context", _context(CLASS["prefix"], CLASS["class"])),
     "reputation-context", CheckStatus.PASS, "REQUIREMENT_SATISFIED"),
    ("resource with no class", "admission/valid",
     _set("reputation_context", _context("https://invoices.example/archive/", CLASS["class"])),
     "reputation-context", CheckStatus.UNKNOWN, "UNSUPPORTED_REQUIREMENT"),
    ("other resource class", "admission/valid",
     _set("reputation_context", _context("https://invoices.example/", "any-invoice")),
     "reputation-context", CheckStatus.FAIL, "CONTEXT_MISMATCH"),
    ("other runtime class", "admission/valid",
     _set("reputation_context", _context(CLASS["prefix"], CLASS["class"], "managed-v2")),
     "reputation-context", CheckStatus.FAIL, "CONTEXT_MISMATCH"),
    ("scoring revision accepted", "admission/valid",
     _revisions(["finance-scoring-2", "finance-scoring-1"]),
     "reputation-context", CheckStatus.PASS, "REQUIREMENT_SATISFIED"),
    ("scoring revision not accepted", "admission/valid", _revisions(["finance-scoring-2"]),
     "reputation-context", CheckStatus.FAIL, "CONTEXT_MISMATCH"),
    ("authorized checks", "selection/same-snapshot", _checks(SELECTION_CHECKS),
     "contract-validity", CheckStatus.PASS, "REQUIREMENT_SATISFIED"),
    ("checks not authorized", "selection/same-snapshot",
     _checks([SELECTION_CHECKS[0], SELECTION_CHECKS[1], SELECTION_CHECKS[3], SELECTION_CHECKS[4]]),
     "contract-validity", CheckStatus.FAIL, "CONTEXT_MISMATCH"),
]  # fmt: skip


@pytest.mark.parametrize(
    ("name", "id_", "edit", "check_id", "result", "reason"),
    CONFIGURED,
    ids=[c[0] for c in CONFIGURED],
)
def test_configured_gateway(
    tmp_path: Path,
    name: str,
    id_: str,
    edit: Callable[[dict[str, Any]], None],
    check_id: str,
    result: CheckStatus,
    reason: str,
) -> None:
    # The conformance gateway takes its purpose mapping, reputation-context mapping,
    # accepted scoring revisions and authorized context checks from config.json
    # (spec/v1.0/fixtures/README.md, config.json additions and selection.selector), not from
    # the Appendix B values.
    f = case_copy(tmp_path, id_, edit)
    res = f.validator.evaluate(f.request)
    want_check(res, check_id, result, reason)


TRANSPORT = [
    ("transport/stdio-ipc-contract-over-https", "https", "stdio-ipc"),
    ("transport/https-contract-over-stdio-ipc", "stdio-ipc", "https"),
    ("admission/valid", "https", "https"),
]


@pytest.mark.parametrize(("id_", "arrived", "named"), TRANSPORT)
def test_transport_binding(id_: str, arrived: str, named: str) -> None:
    # An enforced-mode presentation received over a transport other than the one its
    # contract names is rejected with CONTEXT_MISMATCH before an authenticated evaluation,
    # so no receipt is issued and the nonce is not consumed (draft 13.3.1, the downgrade
    # rule; 12.2; 13.4). Over the transport the contract names, the same presentation is
    # evaluated and admitted.
    f = case(id_)
    assert f.request.transport == arrived
    for other in ("", "https", "stdio-ipc", "HTTPS", "http"):
        if other == named:
            continue
        f.request = replace(f.request, transport=other)
        with pytest.raises(_problem.Rejection) as ei:
            f.validator.evaluate(f.request)
        assert ei.value.code == Code.CONTEXT_MISMATCH
        p = validator.problem_of(ei.value, "r1")
        assert p is not None
        assert (p.code, p.status) == ("CONTEXT_MISMATCH", 403)
    f.request = replace(f.request, transport=named)
    a = f.validator.evaluate(f.request).attestation
    assert (a.decision, a.mode) == (Decision.ADMISSIBLE, Mode.ENFORCED), (
        "the rejections consumed no nonce"
    )
