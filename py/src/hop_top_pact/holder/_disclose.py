"""Requirement-driven profile disclosure (draft 8, 9.2, 15.2)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from hop_top_pact.adapter import Code
from hop_top_pact.core import _wire, clock
from hop_top_pact.core.clock import ClockError
from hop_top_pact.core.enums import RuleSource
from hop_top_pact.core.types import AgentProfile, Evidence, FieldRule
from hop_top_pact.holder._artifact import (
    MISSING,
    Snapshot,
    StoredEvidence,
    lookup,
    pointer,
    same_json,
)
from hop_top_pact.holder._errors import CODE_CONFLICTING_EVIDENCE, CODE_EXPIRED, HolderError

if TYPE_CHECKING:
    from hop_top_pact.holder._holder import Holder, HolderKey

__all__ = ["Disclosure", "check_profile"]


@dataclass(slots=True)
class _Whole:
    """A disclosed value, as a leaf of the view."""

    value: object


class Disclosure:
    """The profile view one contract asks for."""

    def __init__(
        self,
        h: Holder,
        key: HolderKey,
        now: datetime,
        profile: AgentProfile,
        evidence: list[StoredEvidence],
        snap: Snapshot | None,
    ) -> None:
        self.h = h
        self.key = key
        self.now = now
        self.source = _wire.to_json(profile)
        self.source_attrs = profile.attributes
        self.evidence = evidence
        self.snap = snap
        self.view: dict[str, Any] = {}
        self.used = [False] * len(evidence)
        self.snap_used = False

    def disclose(self, rules: tuple[FieldRule, ...]) -> dict[str, Any]:
        """The attributes of the view for rules; the evidence and snapshot the rules use
        are marked."""
        self.view = {}
        self.used = [False] * len(self.evidence)
        for r in rules:
            try:
                self._rule(r)
            except HolderError as e:
                raise e.prefixed(f"rule {r.rule_id!r}") from e
        return {k: _unwrap(x) for k, x in self.view.items()}

    def _rule(self, r: FieldRule) -> None:
        """Disclose the value one field rule requires (draft 9.2: every listed path is
        required)."""
        try:
            tokens = pointer(r.path)
        except ValueError as e:
            raise HolderError(Code.INVALID_MESSAGE, str(e)) from e
        if r.source == RuleSource.EVIDENCE and _reputation_path(tokens):
            self._reputation(r, tokens)
            return
        value = lookup(self.source, tokens)
        if r.source == RuleSource.EVIDENCE:
            value = self._from_evidence(r, value)
        elif value is MISSING:
            # A native or self value the agent does not hold is missing; the holder does not
            # invent one (draft 8.6).
            raise HolderError(Code.MISSING_FIELD, f"no value at {r.path}")
        self._set(tokens, value)

    def _reputation(self, r: FieldRule, tokens: list[str]) -> None:
        """Disclose the snapshot value at /attributes/reputation for an evidence rule on it
        or a descendant: the complete value, so that every required subfield matches the
        signed snapshot (draft 15.2). A self-asserted reputation in the source profile is
        never disclosed."""
        if self.snap is None:
            raise HolderError(Code.MISSING_FIELD, f"no reputation snapshot for {r.path}")
        s = self.snap.claims
        if s.iss not in r.allowed_issuers or not self._applies(
            s.sub, s.aud, s.tenant_id, s.environment_id, s.holder_jkt, s.iat, s.nbf, s.exp
        ):
            raise HolderError(
                Code.MISSING_FIELD, f"the reputation snapshot does not apply to {r.path}"
            )
        if lookup(self.snap.value, tokens[2:]) is MISSING:
            raise HolderError(
                Code.MISSING_FIELD, f"the reputation snapshot has no value at {r.path}"
            )
        self.view["reputation"] = _Whole(self.snap.value)
        self.snap_used = True

    def _from_evidence(self, r: FieldRule, value: object) -> object:
        """The value of an evidence rule: the profile value, or, when the profile has none,
        the value of the applicable evidence claims. Every applicable claim from an allowed
        issuer must equal it: a value that differs from any of them, or claims that
        disagree, conflict (draft 8.4: the holder does not pick the evidence that permits
        access). The first applicable evidence backs the rule."""
        candidates: list[int] = []
        for i, e in enumerate(self.evidence):
            c = e.claims
            if (
                c.iss in r.allowed_issuers
                and self._applies(
                    c.sub, c.aud, c.tenant_id, c.environment_id, c.holder_jkt, c.iat, c.nbf, c.exp
                )
                and _claim_at(c, r.path) is not MISSING
            ):
                candidates.append(i)
        if not candidates:
            raise HolderError(Code.MISSING_FIELD, f"no applicable evidence for {r.path}")
        if value is MISSING:
            value = _claim_at(self.evidence[candidates[0]].claims, r.path)
        for i in candidates:
            if not same_json(_claim_at(self.evidence[i].claims, r.path), value):
                raise HolderError(
                    CODE_CONFLICTING_EVIDENCE,
                    f"the profile value and the applicable evidence at {r.path} disagree",
                )
        self.used[candidates[0]] = True
        return value

    def _applies(
        self,
        sub: str,
        aud: str,
        tenant: str,
        env: str,
        jkt: str,
        iat: int,
        nbf: int,
        exp: int,
    ) -> bool:
        """Whether an artifact binds this agent, key, gateway and realm and is valid now
        (draft 7.5, 8.3, 15.2)."""
        h = self.h
        if not (
            sub == h.agent_id
            and aud == h.gateway
            and tenant == h.realm.tenant_id
            and env == h.realm.environment_id
            and jkt == self.key.jkt
        ):
            return False
        try:
            clock.check_window(iat, nbf, exp, self.now, h.skew)
        except ClockError:
            return False
        return True

    def _set(self, tokens: list[str], value: object) -> None:
        """Place value at tokens in the view. Only /attributes paths are view paths: the core
        fields of the profile are always disclosed. A path that passes through an array
        discloses the whole array, the smallest JSON value that holds it."""
        if not tokens or tokens[0] != "attributes":
            return
        tokens = tokens[1:]
        if not tokens:
            for k, v in self.source_attrs.items():
                self.view[k] = _Whole(v)
            return
        for i in range(1, len(tokens)):
            enclosing = lookup(self.source, ["attributes", *tokens[:i]])
            if isinstance(enclosing, list | tuple):
                tokens, value = tokens[:i], enclosing
                break
        node = self.view
        for i, t in enumerate(tokens):
            if i == len(tokens) - 1:
                node[t] = _Whole(value)
                return
            nxt = node.get(t)
            if not isinstance(nxt, dict):
                if isinstance(nxt, _Whole):
                    return  # an enclosing value is already disclosed
                nxt = {}
                node[t] = nxt
            node = nxt


def _unwrap(v: object) -> object:
    if isinstance(v, _Whole):
        return v.value
    if isinstance(v, dict):
        return {k: _unwrap(x) for k, x in v.items()}
    return v


def _reputation_path(tokens: list[str]) -> bool:
    """Whether a path is at or under /attributes/reputation, whose authoritative value is
    the snapshot's (Appendix A.2, draft 15.2)."""
    return len(tokens) >= 2 and tokens[0] == "attributes" and tokens[1] == "reputation"


def _claim_at(e: Evidence, path: str) -> object:
    """The value of e's claim on exactly path, or MISSING (draft 8.4: the path must
    match)."""
    for c in e.claims:
        if c.path == path:
            return c.value
    return MISSING


def check_profile(h: Holder, p: AgentProfile, k: HolderKey, now: datetime) -> None:
    """Apply the profile rules of draft 8.1, 11.2 and Appendix A.2 to the source profile: it
    names this agent, key and tenant, and it is current with a lifetime of at most 24
    hours."""
    if p.agent_id != h.agent_id:
        raise HolderError(Code.CONTEXT_MISMATCH, f"profile agent_id {p.agent_id!r}")
    if p.tenant_id != h.realm.tenant_id:
        raise HolderError(Code.CONTEXT_MISMATCH, f"profile tenant_id {p.tenant_id!r}")
    if p.holder_jkt != k.jkt:
        raise HolderError(
            Code.INVALID_PROOF, f"profile holder_jkt {p.holder_jkt}, key source {k.jkt}"
        )
    try:
        clock.check_lifetime(clock.Artifact.PROFILE, p.created_at, p.expires_at)
    except ClockError as e:
        raise HolderError(Code.INVALID_MESSAGE, f"profile: {e}") from e
    try:
        clock.check_window(p.created_at, p.created_at, p.expires_at, now, h.skew)
    except ClockError as e:
        code = CODE_EXPIRED if e.kind == clock.ClockErrorKind.EXPIRED else Code.INVALID_MESSAGE
        raise HolderError(code, f"profile: {e}") from e
