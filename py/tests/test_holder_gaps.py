"""Holder behaviour the Go tests leave unchecked: the draft 20.1 presentation limits and
disclosure through an array (draft 8.1, 19)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from hop_top_pact import contract
from hop_top_pact.adapter import Code
from hop_top_pact.core import _wire, limits
from hop_top_pact.core.enums import Comparison, RuleSource
from hop_top_pact.core.types import Claim, FieldRule


def issue_with(ck: Any, hk: Any, extra: tuple[FieldRule, ...]) -> str:
    r = replace(ck.b4_requirements(), field_rules=(*ck.b4_requirements().field_rules, *extra))
    c = hk.issue(contract.MemoryReplay(4), ck.B4_HOLDER_JKT, r, hk.b_operation(), ck.at(ck.B4_TIME))
    compact: str = c.compact
    return compact


def evidence_rules(hk: Any, n: int) -> tuple[tuple[FieldRule, ...], tuple[str, ...]]:
    """n evidence rules on distinct attribute paths, each backed by its own evidence."""
    base = hk.b_evidence()
    rule = next(r for r in hk.ck.b4_requirements().field_rules if r.rule_id == "isolation")
    rules, evidence = [], []
    for i in range(n):
        path = f"/attributes/extra{i}/value"
        rules.append(replace(rule, rule_id=f"extra-{i}", path=path))
        e = replace(base, claims=(Claim(path=path, value="v"),), jti=f"extraEvidence{i:010d}")
        evidence.append(hk.sign_evidence(2, "test-issuer-key-1", e))
    return tuple(rules), tuple(evidence)


def test_evidence_artifact_limit(ck: Any, hk: Any) -> None:
    # A presentation over the draft 20.1 limit of evidence artifacts is refused, never
    # truncated to fit; one at the limit is built.
    most = limits.defaults().evidence_artifacts
    for n, ok in ((most - 1, True), (most, False)):
        # the B.5 evidence backs the isolation rule, so n extra artifacts make n + 1
        rules, evidence = evidence_rules(hk, n)
        in_ = replace(hk.b_input(), contract=issue_with(ck, hk, rules))
        in_ = replace(in_, evidence=(*in_.evidence, *evidence))
        h = hk.b_holder(hk.memory_key(1))
        if ok:
            assert len(h.present(in_, ck.at(ck.B4_TIME)).claims.evidence) == most
        else:
            with hk.raises(Code.INVALID_MESSAGE):
                h.present(in_, ck.at(ck.B4_TIME))


def test_rule_through_an_array_discloses_the_array(ck: Any, hk: Any) -> None:
    # A path that passes through an array discloses the whole array, the smallest JSON
    # value that holds it (draft 8.1, 19).
    rule = FieldRule(
        rule_id="first-language",
        path="/attributes/capabilities/languages/0",
        schema=True,
        source=RuleSource.SELF,
        comparison=Comparison.EQUAL,
        allowed_issuers=(),
        native_path=None,
        max_age_seconds=0,
        status_max_age_seconds=0,
    )
    in_ = replace(hk.b_input(), contract=issue_with(ck, hk, (rule,)))
    p = hk.b_holder(hk.memory_key(1)).present(in_, ck.at(ck.B4_TIME))
    got = _wire.payload(p.claims.profile.attributes["capabilities"])
    assert got == b'{"languages":["en","fr"]}'
