"""Self-rule and threshold rulings of the contract package. Port of
go/contract/rulings_test.go."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from hop_top_pact import contract
from hop_top_pact.adapter import Code
from hop_top_pact.core import strictjson
from hop_top_pact.core.enums import Comparison, RuleSource, SecurityStatus
from hop_top_pact.core.types import FieldRule

Edit = Callable[[Any], None]


def self_rule(rule_id: str, path: str) -> FieldRule:
    """A self rule on path, in the form Appendix A.2 gives it: no issuers, native_path
    null, comparison equal, both ages zero."""
    return FieldRule(
        rule_id=rule_id,
        path=path,
        schema=True,
        source=RuleSource.SELF,
        comparison=Comparison.EQUAL,
        allowed_issuers=(),
        native_path=None,
        max_age_seconds=0,
        status_max_age_seconds=0,
    )


def self_edit(path: str) -> Edit:
    def edit(m: dict[str, Any]) -> None:
        r = m["field_rules"][3]
        r.update(
            source="self",
            allowed_issuers=[],
            max_age_seconds=0,
            status_max_age_seconds=0,
            path=path,
        )

    return edit


def with_rule3(r: contract.Requirements, rule: FieldRule) -> contract.Requirements:
    rules = list(r.field_rules)
    rules[3] = rule
    return replace(r, field_rules=tuple(rules))


RESERVED = [
    "/attributes/environment/principal_id",
    "/attributes/delegation",
    "/attributes/delegation/authority_ref",
    "/attributes/delegation/principal_id",
    "/attributes/reputation",
    "/attributes/reputation/security_status",
    "/attributes/reputation/dimensions/reliability/score_bps",
]
# Paths that only share a prefix of characters are not descendants.
NOT_DESCENDANTS = [
    "/attributes/environment/principal_id_hint",
    "/attributes/delegations",
    "/attributes/reputationx",
    "/attributes/runtime/isolation",
]


@pytest.mark.parametrize("path", RESERVED)
def test_self_rule_reserved_paths_verify(ck: Any, path: str) -> None:
    # A self rule on the principal, delegation or reputation paths is invalid (draft
    # 9.2, Appendix A.2), for the verifier as for the publisher: INVALID_MESSAGE.
    compact = ck.compact_of(ck.VALID_CONTRACT)
    with ck.raises(Code.INVALID_MESSAGE):
        ck.b4_verifier().verify(ck.resigned(compact, self_edit(path)), ck.at(ck.B4_TIME))


@pytest.mark.parametrize("path", RESERVED)
def test_self_rule_reserved_paths_issue(ck: Any, path: str) -> None:
    r = ck.b4_requirements()
    r = with_rule3(r, self_rule(r.field_rules[3].rule_id, path))
    with ck.raises(Code.INVALID_MESSAGE):
        ck.new_publisher(contract.MemoryReplay()).issue(
            ck.b4_request(), ck.b4_auth(), r, ck.at(ck.B4_TIME)
        )


@pytest.mark.parametrize("path", NOT_DESCENDANTS)
def test_self_rule_prefix_lookalikes_accepted(ck: Any, path: str) -> None:
    compact = ck.compact_of(ck.VALID_CONTRACT)
    ck.b4_verifier().verify(ck.resigned(compact, self_edit(path)), ck.at(ck.B4_TIME))
    r = ck.b4_requirements()
    r = with_rule3(r, self_rule(r.field_rules[3].rule_id, path))
    ck.new_publisher(contract.MemoryReplay()).issue(
        ck.b4_request(), ck.b4_auth(), r, ck.at(ck.B4_TIME)
    )


@pytest.mark.parametrize(
    "path", ["/attributes/environment/roles", "/attributes/environment/roles/0"]
)
def test_issue_protected_paths(ck: Any, path: str) -> None:
    # The publisher also refuses a self rule on a path its installed mapping
    # classifies as identity, tenant or role membership, delegation or approval, and
    # on its descendants (Appendix A.2).
    p = ck.new_publisher(contract.MemoryReplay())
    p.protected_paths = ("/attributes/environment/roles",)
    r = ck.b4_requirements()
    r = with_rule3(r, self_rule(r.field_rules[3].rule_id, path))
    with ck.raises(Code.INVALID_MESSAGE):
        p.issue(ck.b4_request(), ck.b4_auth(), r, ck.at(ck.B4_TIME))


def test_issue_protected_paths_other_path_accepted(ck: Any) -> None:
    p = ck.new_publisher(contract.MemoryReplay())
    p.protected_paths = ("/attributes/environment/roles",)
    r = ck.b4_requirements()
    r = with_rule3(r, self_rule(r.field_rules[3].rule_id, "/attributes/environment/rolesx"))
    p.issue(ck.b4_request(), ck.b4_auth(), r, ck.at(ck.B4_TIME))


def threshold_rule(rule_id: str, path: str, schema: str) -> FieldRule:
    """A field rule in the canonical form of draft 9.4 (b)."""
    parsed = strictjson.parse(schema.encode())
    assert isinstance(parsed, dict)
    return FieldRule(
        rule_id=rule_id,
        path=path,
        schema=parsed,
        source=RuleSource.EVIDENCE,
        comparison=Comparison.EQUAL,
        allowed_issuers=("https://reputation.example/finance",),
        native_path=None,
        max_age_seconds=30,
        status_max_age_seconds=0,
    )


def established(ck: Any) -> contract.Requirements:
    """Selects the weaker set "established" on the thresholds of the selection fixtures:
    reliability score_bps 9000, confidence_bps 5000, independent_tasks 20 and security
    status CLEAR."""
    r: contract.Requirements = ck.b4_requirements()
    return replace(
        r,
        selected_set="established",
        context_checks=(*r.context_checks, contract.SELECTION_CONSISTENCY_CHECK),
        thresholds=(
            contract.ThresholdRule(dimension="reliability", statistic="score_bps", minimum=9000),
            contract.ThresholdRule(
                dimension="reliability", statistic="confidence_bps", minimum=5000
            ),
            contract.ThresholdRule(
                dimension="reliability", statistic="independent_tasks", minimum=20
            ),
            contract.ThresholdRule(security_status=SecurityStatus.CLEAR),
        ),
        field_rules=(
            *r.field_rules,
            threshold_rule(
                "reputation-reliability-score",
                "/attributes/reputation/dimensions/reliability/score_bps",
                '{"type":"integer","minimum":9000}',
            ),
            threshold_rule(
                "reputation-reliability-confidence",
                "/attributes/reputation/dimensions/reliability/confidence_bps",
                '{"type":"integer","minimum":5000}',
            ),
            threshold_rule(
                "reputation-reliability-tasks",
                "/attributes/reputation/dimensions/reliability/independent_tasks",
                '{"minimum":2e1,"type":"integer"}',
            ),
        ),
    )


def rule_index(r: contract.Requirements, rule_id: str) -> int:
    return next(i for i, fr in enumerate(r.field_rules) if fr.rule_id == rule_id)


def edit_rule(rule_id: str, **kw: Any) -> Callable[[contract.Requirements], contract.Requirements]:
    def edit(r: contract.Requirements) -> contract.Requirements:
        rules = list(r.field_rules)
        i = rule_index(r, rule_id)
        rules[i] = replace(rules[i], **kw)
        return replace(r, field_rules=tuple(rules))

    return edit


def drop_rule(rule_id: str) -> Callable[[contract.Requirements], contract.Requirements]:
    def edit(r: contract.Requirements) -> contract.Requirements:
        i = rule_index(r, rule_id)
        return replace(r, field_rules=(*r.field_rules[:i], *r.field_rules[i + 1 :]))

    return edit


def schema(text: str) -> Any:
    return strictjson.parse(text.encode())


THRESHOLDS: list[tuple[str, Callable[[contract.Requirements], contract.Requirements]]] = [
    ("minimum rule missing", drop_rule("reputation-reliability-score")),
    (
        "minimum differs",
        edit_rule(
            "reputation-reliability-confidence", schema=schema('{"type":"integer","minimum":4999}')
        ),
    ),
    (
        "no minimum keyword",
        edit_rule(
            "reputation-reliability-tasks",
            schema=schema('{"type":"integer","exclusiveMinimum":20}'),
        ),
    ),
    (
        "minimum on another path",
        edit_rule(
            "reputation-reliability-score",
            path="/attributes/reputation/dimensions/task_quality/score_bps",
        ),
    ),
    (
        "minimum not an evidence rule",
        edit_rule(
            "reputation-reliability-score",
            source=RuleSource.NATIVE,
            allowed_issuers=(),
            native_path="/reputation/reliability/score_bps",
        ),
    ),
    ("status rule missing", drop_rule("reputation-status")),
    ("status differs", edit_rule("reputation-status", schema=schema('{"const":"CAUTION"}'))),
    (
        "threshold names nothing",
        lambda r: replace(r, thresholds=(*r.thresholds, contract.ThresholdRule())),
    ),
    (
        "threshold names a statistic and a status",
        lambda r: replace(
            r,
            thresholds=(
                *r.thresholds,
                contract.ThresholdRule(
                    dimension="reliability",
                    statistic="score_bps",
                    minimum=9000,
                    security_status=SecurityStatus.CLEAR,
                ),
            ),
        ),
    ),
]


def issue(ck: Any, r: contract.Requirements) -> contract.Contract:
    c: contract.Contract = ck.new_publisher(contract.MemoryReplay()).issue(
        ck.b4_request(), ck.b4_auth(), r, ck.at(ck.B4_TIME)
    )
    return c


def test_issue_threshold_rules_every_threshold_a_rule(ck: Any) -> None:
    issue(ck, established(ck))


@pytest.mark.parametrize(("name", "edit"), THRESHOLDS, ids=[n for n, _ in THRESHOLDS])
def test_issue_threshold_rules_refused(
    ck: Any, name: str, edit: Callable[[contract.Requirements], contract.Requirements]
) -> None:
    # A contract whose selected set is not the conservative one expresses every
    # threshold the selector relied on as an evidence field rule of the canonical
    # form; a publisher does not issue one that lacks one of them (draft 9.4 (b)).
    with ck.raises(Code.INVALID_MESSAGE):
        issue(ck, edit(established(ck)))


def test_issue_threshold_rules_conservative_set(ck: Any) -> None:
    # The conservative set is selected on no threshold: draft 9.4 (b) does not apply
    # to it.
    r = established(ck)
    base = ck.b4_requirements()
    issue(ck, replace(r, selected_set=r.conservative_set, field_rules=base.field_rules[:-1]))
