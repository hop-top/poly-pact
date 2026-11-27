"""The state of one evaluate call."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from hop_top_pact import contract
from hop_top_pact.adapter import AgentBinding, CheckInput
from hop_top_pact.core.enums import TerminalReason
from hop_top_pact.core.types import CheckResult, Presentation, ReputationSnapshot
from hop_top_pact.validator._config import ActivePolicy, Request, Selection
from hop_top_pact.validator._outcome import Outcome, ok
from hop_top_pact.validator._state import Machine

if TYPE_CHECKING:
    from hop_top_pact.validator._validator import Validator


@dataclass(slots=True)
class AuthClaim:
    """An authoritative value the validator accepted for a profile path: an evidence claim or
    a reputation snapshot value (draft 8.3, A.2). hold_check marks a snapshot value, whose
    status check is the validator's own security-hold check (Appendix A.2)."""

    path: str
    issuer: str
    value: Any
    observed_at: datetime
    status_at: datetime | None
    evidence_id: str
    source_id: str
    hold_check: bool = False


@dataclass(slots=True)
class Evaluation:
    """The state of one evaluate call."""

    v: Validator
    req: Request
    m: Machine
    start: datetime
    cancelled: Callable[[], bool] | None = None
    ended: TerminalReason | None = None
    ended_at: datetime | None = None

    p: Presentation | None = None
    profile_raw: str = ""
    intent_raw: str = ""
    op_raw: str = ""
    profile: Any = None
    schemas: dict[str, Any] = field(default_factory=dict)
    jkt: str = ""
    c: contract.Contract | None = None
    deadline: datetime | None = None

    binding: AgentBinding = field(default_factory=AgentBinding)
    binding_known: bool = False

    nonce: Outcome = field(default_factory=ok)
    checks: dict[str, CheckResult] = field(default_factory=dict)

    claims: list[AuthClaim] = field(default_factory=list)
    failed_paths: dict[str, str] = field(default_factory=dict)
    pending_paths: dict[str, str] = field(default_factory=dict)
    evidence_ids: list[str] = field(default_factory=list)
    expiries: list[int] = field(default_factory=list)
    snapshot: ReputationSnapshot | None = None
    snapshot_jti: str = ""

    active: ActivePolicy = field(default_factory=ActivePolicy)
    active_err: Exception | None = None
    sel: Selection = field(default_factory=Selection)
    sel_err: Exception | None = None
    holds: list[str] = field(default_factory=list)
    holds_err: Exception | None = None
    holds_at: datetime | None = None

    @property
    def pres(self) -> Presentation:
        assert self.p is not None
        return self.p

    @property
    def con(self) -> contract.Contract:
        assert self.c is not None
        return self.c

    def check_input(self) -> CheckInput:
        return CheckInput(
            principal=self.req.principal,
            binding=self.binding,
            intent=self.pres.intent,
            operation=self.req.operation,
            evidence_refs=tuple(self.evidence_ids),
        )
