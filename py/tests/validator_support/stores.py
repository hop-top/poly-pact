"""The gateway's stores, as a case's files state them."""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from hop_top_pact import contract, validator
from hop_top_pact.adapter import CheckInput, DependencyUnavailable, Realm, UnsupportedRequirement
from hop_top_pact.conformance import EvidenceStatus as CaseStatus
from hop_top_pact.conformance import Selector as CaseSelector
from hop_top_pact.conformance import Threshold
from hop_top_pact.core import clock, strictjson
from hop_top_pact.core.types import (
    FieldRule,
    ReputationContext,
    ReputationSnapshot,
    ReputationValue,
)

DEFAULT_SELECTION_RECORD = "configured-selection-record:example-selection"


def at(sec: int) -> datetime:
    return datetime.fromtimestamp(sec, UTC)


@dataclass(slots=True)
class _Record:
    rec: contract.NonceRecord
    issued: datetime
    until: datetime
    consumed: bool = False


class ReplayStore:
    """The gateway's replay store: a contract.MemoryReplay in which the publisher registered
    the nonce of each contract it issued, answering as availability.replay_store says, and
    able to evict the records whose retention has passed, as a store under load may (draft
    7.5)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inner = contract.MemoryReplay()
        self._mode = "available"
        self._recs: dict[str, _Record] = {}

    def set_mode(self, m: str) -> None:
        with self._lock:
            self._mode = m or "available"

    def register_contract(self, c: contract.Contract) -> None:
        """Record the nonce of a contract the gateway's publisher issued, until the later of
        its exp and iat + 65 s (draft 7.5, baseline skew)."""
        with self._lock:
            if c.claims.nonce in self._recs:
                return
            issued = at(c.claims.iat)
            until = clock.replay_retention(c.claims.exp, c.claims.iat, clock.BASELINE_SKEW)
            r = _Record(c.nonce_record(), issued, until)
            try:
                self._inner.register(r.rec, issued, until)
            except contract.ContractError:
                return
            self._recs[c.claims.nonce] = r

    def consume(self, r: contract.NonceRecord, now: datetime, until: datetime) -> None:
        with self._lock:
            mode = self._mode
        if mode != "available":
            raise contract.ContractError("DEPENDENCY_UNAVAILABLE", f"replay store {mode}")
        self._inner.consume(r, now, until)
        with self._lock:
            rec = self._recs.get(r.nonce)
            if rec is not None:
                rec.consumed = True
                rec.until = max(rec.until, until)

    def register(self, r: contract.NonceRecord, now: datetime, until: datetime) -> None:
        self._inner.register(r, now, until)

    def evict(self, now: datetime) -> None:
        """Drop every record whose retention bound has passed at now."""
        with self._lock:
            fresh = contract.MemoryReplay()
            for nonce, r in list(self._recs.items()):
                if r.until <= now:
                    del self._recs[nonce]
                    continue
                fresh.register(r.rec, r.issued, r.until)
                if r.consumed:
                    fresh.consume(r.rec, r.issued, r.until)
            self._inner = fresh


class HoldStore:
    """native_context.json's security_holds."""

    def __init__(self, holds: Sequence[str]) -> None:
        self._holds = list(holds)

    def holds(self, realm: Realm, agent_id: str) -> Sequence[str]:
        return list(self._holds)


class StatusChecker:
    """native_context.json's evidence_status; a status reference listed in
    availability.sources cannot be checked."""

    def __init__(self, states: Mapping[str, CaseStatus], unavailable: Sequence[str]) -> None:
        self._states = states
        self._unavailable = tuple(unavailable)

    def evidence_status(self, issuer: str, status_ref: str) -> validator.EvidenceStatus:
        st = self._states.get(status_ref)
        if status_ref in self._unavailable:
            raise DependencyUnavailable(f"status source of {status_ref!r}")
        if st is None:
            raise DependencyUnavailable(f"no status for {status_ref!r}")
        if st.status == "valid":
            return validator.EvidenceStatus(
                checked_at=at(st.checked_at), source_id="fixture:evidence-status"
            )
        if st.status == "revoked":
            return validator.EvidenceStatus(
                revoked=True, checked_at=at(st.checked_at), source_id="fixture:evidence-status"
            )
        raise DependencyUnavailable(f"status {st.status!r} of {status_ref!r}")


def _meets(v: ReputationValue, t: Threshold) -> bool:
    if t.security_status and str(v.security_status) != t.security_status:
        return False
    dims = {
        "reliability": v.dimensions.reliability,
        "task_quality": v.dimensions.task_quality,
        "policy_adherence": v.dimensions.policy_adherence,
    }
    for name, m in t.dimensions.items():
        d = dims.get(name)
        if (
            d is None
            or d.score_bps < m.score_bps
            or d.confidence_bps < m.confidence_bps
            or d.independent_tasks < m.independent_tasks
        ):
            return False
    return True


class Selector:
    """config.json's selection.selector: the last set of order whose threshold the snapshot
    meets, and the conservative set when it meets none, when there is no snapshot or when a
    hold is in force. contract_checks are the context_checks of the contract it was looked
    up for."""

    def __init__(
        self,
        s: CaseSelector,
        checks: Mapping[str, Sequence[str]],
        contract_checks: Sequence[str],
    ) -> None:
        self.s = s
        self._checks = checks
        self._contract_checks = list(contract_checks)

    def order(self) -> Sequence[str]:
        return list(self.s.order)

    def rules(self, set_: str) -> Sequence[FieldRule] | None:
        return self.s.sets.get(set_)

    def checks(self, set_: str) -> Sequence[str] | None:
        """selection.selector's checks for the set, or the contract's own context_checks for
        a set it does not list."""
        if set_ in self._checks:
            return list(self._checks[set_])
        return list(self._contract_checks)

    def select(self, in_: validator.SelectionInput) -> str:
        if not self.s.order:
            raise ValueError("selector has no sets")
        chosen = self.s.order[0]
        if in_.snapshot is None or in_.holds:
            return chosen
        for set_ in self.s.order[1:]:
            t = self.s.thresholds.get(set_)
            if t is not None and _meets(in_.snapshot, t):
                chosen = set_
        return chosen


class Registry:
    """config.json's active_policy and selection."""

    def __init__(
        self,
        active: validator.ActivePolicy,
        sel: Any,
        current: ReputationValue | None,
        checks: Mapping[str, Sequence[str]],
    ) -> None:
        self._active = active
        self._sel = sel
        self._current = current
        self._checks = checks

    def active(self) -> validator.ActivePolicy:
        return self._active

    def selection(self, c: contract.Contract) -> validator.Selection:
        if self._sel is None:
            return validator.Selection(record_ref=DEFAULT_SELECTION_RECORD)
        out = validator.Selection(record_ref=self._sel.record.record_ref, current=self._current)
        if c.claims.learning_artifact_digest == self._sel.selector.learning_artifact_digest:
            return validator.Selection(
                record_ref=out.record_ref,
                current=out.current,
                selector=Selector(self._sel.selector, self._checks, c.claims.context_checks),
            )
        return out


def decode_snapshot_value(b: bytes) -> ReputationValue:
    return strictjson.decode(b, ReputationSnapshot).value


class ContextMapper:
    """config.json's reputation_context (B.6 by default): the action class is the
    operation's action, a resource has the class of the first entry whose prefix it starts
    with, and every resource of the operation must have the same class; the runtime class is
    the gateway's."""

    def __init__(self, realm: Realm, m: Mapping[str, Any]) -> None:
        self._realm = realm
        self._m = m

    def reputation_context(self, in_: CheckInput) -> ReputationContext:
        op = in_.operation
        b = in_.binding
        if op is None or not op.resources or b is None or not b.agent_id:
            raise UnsupportedRequirement("no context")
        cls = ""
        for r in op.resources:
            c = self._class_of(r)
            if c is None:
                raise UnsupportedRequirement(f"resource {r!r} has no mapped class")
            if cls and c != cls:
                raise UnsupportedRequirement(f"resources of classes {cls!r} and {c!r}")
            cls = c
        assert in_.intent is not None
        return ReputationContext(
            tenant_id=self._realm.tenant_id,
            environment_id=self._realm.environment_id,
            agent_id=b.agent_id,
            purpose_id=in_.intent.purpose_id,
            action_class=op.action,
            resource_class=cls,
            runtime_class=self._m["runtime_class"],
        )

    def _class_of(self, resource: str) -> str | None:
        for rc in self._m["resource_classes"]:
            if resource.startswith(rc["prefix"]):
                return str(rc["class"])
        return None
