"""The gateway of one exchange, built from a case's files, and its replicas."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

from hop_top_pact import contract, validator
from hop_top_pact.adapter import Principal, Realm, Verdict
from hop_top_pact.adapters import memory
from hop_top_pact.conformance import BINDING_UNKNOWN, Exchange, HandoffAttempt, Submission
from hop_top_pact.core import digest, strictjson
from hop_top_pact.core.clock import FakeClock
from hop_top_pact.core.jws import base64url
from hop_top_pact.core.types import AgentProfile, Intent, OperationContext, RequirementContract
from validator_support.keys import PrivateKey, key_set, signer_for, validator_config
from validator_support.native import (
    DEFAULT_CHECK_AGE,
    DELEGATION_PATH,
    ENROLLMENT_SOURCE,
    WORKLOAD,
    TimedNative,
    approval_record,
    delegation_record,
    executor_record,
    origin_of,
    purpose_record,
    verdict,
)
from validator_support.stores import (
    ContextMapper,
    HoldStore,
    Registry,
    ReplayStore,
    StatusChecker,
    at,
    decode_snapshot_value,
)

AGENT1 = "https://identity.example/agents/fixture-enrollment-1"
AGENT2 = "https://identity.example/agents/fixture-enrollment-2"
DEFAULT_PURPOSES = {"https://policies.example/purposes/invoice-summary/v1": ["invoice.read"]}
DEFAULT_REPUTATION_CONTEXT = {
    "resource_classes": [
        {"prefix": "https://invoices.example/invoices/", "class": "department-finance-invoice"}
    ],
    "runtime_class": "managed-v1",
}


@dataclass
class GatewayState:
    """What carries over between the exchanges of a sequence: the replay store, the receipt
    store and the consumed attestations."""

    replay: ReplayStore = field(default_factory=ReplayStore)
    receipts: validator.MemoryReceipts = field(default_factory=validator.MemoryReceipts)
    consumed: validator.MemoryAttestations = field(default_factory=validator.MemoryAttestations)


def jws_payload(compact: str) -> bytes | None:
    parts = compact.split(".")
    if len(parts) != 3:
        return None
    try:
        return base64url.decode(parts[1])
    except ValueError:
        return None


def embedded_contract(presentation: str) -> contract.Contract | None:
    """The contract a presentation embeds, without verifying anything: the gateway's
    publisher issued it, and the validator verifies it."""
    payload = jws_payload(presentation)
    if payload is None:
        return None
    try:
        p = json.loads(payload)
        compact = p["contract"]
        cp = jws_payload(compact)
        assert cp is not None
        claims = strictjson.decode(cp, RequirementContract)
        d = digest.artifact_digest(compact)
    except (ValueError, KeyError, TypeError, AssertionError, strictjson.StrictJSONError):
        return None
    return contract.Contract(compact=compact, claims=claims, digest=d)


class Gateway:
    """The gateway of one exchange."""

    def __init__(
        self,
        fixtures: Path,
        x: Exchange,
        keys: dict[str, PrivateKey],
        gs: GatewayState,
    ) -> None:
        nc = x.native_context
        if nc.authenticated is None:
            raise ValueError("native_context.json has no authenticated principal")
        self.fixtures = fixtures
        self.x = x
        self.gs = gs
        self.auth = nc.authenticated
        cfg = x.config
        self.raw = json.loads((fixtures / x.path / "config.json").read_bytes())
        self.clk = FakeClock(at(cfg.now))
        self.cfg = validator_config(fixtures, cfg)
        self.signer = signer_for(keys, cfg.validator.key)
        self.reg = self._registry()
        self.holds = HoldStore(nc.security_holds)
        self.status = StatusChecker(nc.evidence_status, x.availability.sources)
        self.contexts = ContextMapper(
            self.cfg.realm, self.raw.get("reputation_context") or DEFAULT_REPUTATION_CONTEXT
        )
        gs.replay.set_mode(x.availability.replay_store)

    def _read(self, rel: str) -> bytes:
        b = self.x.decoded.get(rel)
        return b if b is not None else (self.fixtures / self.x.path / rel).read_bytes()

    def _registry(self) -> Registry:
        ap = self.x.config.active_policy
        sel = self.x.config.selection
        revs = (self.raw.get("active_policy") or {}).get("scoring_policy_revisions")
        conservative = ap.selected_set
        current = None
        checks: dict[str, list[str]] = {}
        if sel is not None:
            if sel.selector.order:
                conservative = sel.selector.order[0]
            if sel.current_snapshot is not None:
                current = decode_snapshot_value(self._read(sel.current_snapshot))
            checks = ((self.raw.get("selection") or {}).get("selector") or {}).get("checks") or {}
        active = validator.ActivePolicy(
            policy=contract.Policy(
                base_revision=ap.base_revision,
                learning_policy_digest=ap.learning_policy_digest,
                learning_artifact_digest=ap.learning_artifact_digest,
            ),
            conservative_set=conservative,
            scoring_policy_revisions=revs if revs is not None else ["finance-scoring-1"],
        )
        return Registry(active, sel, current, checks)

    def principal(self) -> Principal:
        """What authenticate_native established (native_context.json)."""
        return Principal(
            id=self.auth.principal_id,
            realm=Realm(
                tenant_id=self.auth.tenant_id,
                environment_id=self.x.config.gateway.environment_id,
            ),
            workload=WORKLOAD,
            mechanism="fixture",
            authenticated_at=at(self.auth.authenticated_at),
        )

    def prepare_submission(self, sub: Submission) -> None:
        """Set the clock to the submission's start, apply an eviction it asks for, and
        register its contract's nonce as the gateway's publisher did when it issued the
        contract."""
        self.clk.set(at(sub.evaluation.started_at))
        if sub.evict_replay_records:
            self.gs.replay.evict(self.clk.now())
        try:
            compact = self._text(sub.signed)
        except OSError:
            return
        c = embedded_contract(compact)
        if c is not None:
            self.gs.replay.register_contract(c)

    def _text(self, rel: str) -> str:
        return self._read(rel).decode().strip()

    def operation(self, rel: str) -> OperationContext:
        return strictjson.decode(self._read(rel), OperationContext)

    def validator_for(
        self, sub: Submission, cancel: threading.Event
    ) -> tuple[validator.Validator, validator.Request]:
        """The validator replica and the evaluate request of a submission; cancel is the
        requestor's cancellation of its evaluation."""
        compact = self._text(sub.signed)
        op = self.operation(sub.actual_operation)
        nat = TimedNative(self.native_adapter(op), self.clk, sub.evaluation, cancel)
        v = validator.Validator(
            config=self.cfg,
            native=nat,
            replay=self.gs.replay,
            receipts=self.gs.receipts,
            holds=self.holds,
            policies=self.reg,
            status=self.status,
            contexts=self.contexts,
            signer=self.signer,
            clock=self.clk,
        )
        req = validator.Request(
            presentation=compact,
            operation=op,
            principal=self.principal(),
            transport=sub.transport,
        )
        return v, req

    def submit(self, sub: Submission) -> tuple[validator.Result | None, str, Exception | None]:
        """Evaluate one submission and return its result, response line and error."""
        cancel = threading.Event()
        try:
            v, req = self.validator_for(sub, cancel)
        except (OSError, ValueError, strictjson.StrictJSONError) as e:
            return None, line(None, e, sub.jti), e
        try:
            res = v.evaluate(req, cancelled=cancel.is_set)
        except Exception as e:
            return getattr(e, "result", None), line(getattr(e, "result", None), e, sub.jti), e
        return res, line(res, None, sub.jti), None

    def handoff(self, h: HandoffAttempt, res: validator.Result | None) -> str:
        """Attempt the sidecar handoff of a submission's attestation (draft 11.5) and return
        its response line."""
        if res is None or not res.receipt:
            return line(None, RuntimeError("the presentation got no receipt"), h.presentation)
        try:
            op = self.operation(h.actual_operation)
            algs = self.cfg.algorithms
            ks = key_set(self.fixtures, algs, (self.x.config.validator.key,))
            hf = validator.Handoff(
                validators={self.cfg.issuer: ks},
                audience=self.cfg.audience,
                realm=self.cfg.realm,
                algorithms=algs,
                skew=self.cfg.skew,
                consumed=self.gs.consumed,
                holds=self.holds,
            )
            hf.accept(res.receipt, op, self.principal(), at(h.at))
        except Exception as e:
            return line(None, e, h.presentation)
        return '{"handoff":"accepted"}'

    # The native adapter.

    def native_adapter(self, op: OperationContext) -> memory.MemoryAdapter:
        """The in-memory adapter of the exchange's native state for a submission whose
        actual operation is op."""
        cfg, nc = self.x.config, self.x.native_context
        pr = self.principal()
        realm = memory.Realm(tenant_id=pr.realm.tenant_id, environment_id=pr.realm.environment_id)
        gw = memory.Gateway(
            tenant_id=cfg.gateway.tenant_id,
            environment_id=cfg.gateway.environment_id,
            origin=origin_of(op.target_uri),
        )
        unavailable: list[str] = []
        if self.x.availability.enrollment_source == "unavailable":
            unavailable.append(ENROLLMENT_SOURCE)
        approved = [m.native_path for m in cfg.native_mappings]
        claims = []
        for c in nc.native_claims:
            if c.native_path not in approved:
                approved.append(c.native_path)
            src = c.source_id
            if c.native_path in self.x.availability.sources:
                src = "fixture:unavailable:" + c.native_path
                unavailable.append(src)
            claims.append(
                memory.ClaimRecord(
                    realm=realm,
                    principal=pr.id,
                    path=c.native_path,
                    value=c.value,
                    observed_at=c.observed_at,
                    status_checked_at=c.status_checked_at,
                    source_id=src,
                )
            )
        intent = strictjson.decode(self.x.decoded["intent.json"], Intent)
        checks, unavailable = self.check_records(intent, op, unavailable)
        st = memory.State(
            model=memory.MODEL,
            gateway=gw,
            enrollments=tuple(self.enrollments(realm)),
            approved_paths=tuple(approved),
            claims=tuple(claims),
            checks=tuple(checks),
            unavailable_sources=tuple(unavailable),
        )
        return memory.new_adapter(st, self.clk)

    def enrollments(self, realm: memory.Realm) -> list[memory.Enrollment]:
        """native_context.json's authenticated binding as the records of the enrollment
        source (identity mapping IM-11, IM-19)."""
        a = self.auth
        profile = strictjson.decode(self.x.decoded["profile.json"], AgentProfile)

        def rec(wl: str, agent: str, operator: str, jkt: str, status: str) -> memory.Enrollment:
            return memory.Enrollment(
                realm=realm,
                workload=wl,
                agent_id=agent,
                operator_id=operator,
                holder_jkt=jkt,
                status=status,
                observed_at=a.authenticated_at,
                status_checked_at=a.authenticated_at,
                source_id=ENROLLMENT_SOURCE,
            )

        if a.binding_error == "UNSUPPORTED_REQUIREMENT":
            return [
                rec(WORKLOAD, AGENT1, profile.operator_id, profile.holder_jkt, "ACTIVE"),
                rec(WORKLOAD, AGENT2, profile.operator_id, profile.holder_jkt, "ACTIVE"),
            ]
        if a.binding_status == BINDING_UNKNOWN or a.agent_id is None or a.holder_jkt is None:
            if a.enrolled_elsewhere:
                return [
                    rec(
                        "fixture:other-workload",
                        profile.agent_id,
                        profile.operator_id,
                        profile.holder_jkt,
                        "ACTIVE",
                    )
                ]
            return []
        return [
            rec(WORKLOAD, a.agent_id, a.operator_id or "", a.holder_jkt, a.binding_status.upper())
        ]

    def check_age(self, id_: str) -> int:
        """The source age bound of an installed check: the field rule that maps its source,
        else check_freshness, else 30 seconds."""
        if id_ == "native-delegation-v1":
            try:
                c = strictjson.decode(self.x.decoded["contract.json"], RequirementContract)
            except (KeyError, strictjson.StrictJSONError):
                c = None
            if c is not None:
                for r in c.field_rules:
                    if r.path == DELEGATION_PATH and r.source == "native":
                        return r.max_age_seconds
        return self.x.config.check_freshness.get(id_, DEFAULT_CHECK_AGE)

    def check_records(
        self, intent: Intent, op: OperationContext, unavailable: list[str]
    ) -> tuple[list[memory.CheckRecord], list[str]]:
        """The native state of each installed check as the verdict the check's rules give it
        for this submission."""
        cfg, nc = self.x.config, self.x.native_context
        now = int(self.clk.now().timestamp())
        purposes = self.raw.get("purposes")
        if purposes is None:
            purposes = DEFAULT_PURPOSES
        out: list[memory.CheckRecord] = []
        for id_ in cfg.installed_checks:
            r = memory.CheckRecord(
                id=id_,
                source_id=cfg.validator.source_id,
                source_ref="configured-validation-record:" + id_,
                observed_at=now,
            )
            if id_ == "native-approval-v1":
                r = approval_record(r, nc.approval, intent, op, self.check_age(id_))
                if nc.approval is not None and nc.approval.state == "unavailable":
                    from dataclasses import replace

                    r = replace(r, source_id="fixture:unavailable:approval")
                    unavailable.append(r.source_id)
            elif id_ == "native-delegation-v1":
                r = delegation_record(
                    r, nc.delegation, intent, self.principal(), self.check_age(id_)
                )
            elif id_ == "execution-identity-v1":
                r = executor_record(r, nc.executor, cfg.executor_classes, intent, op)
            elif id_ == "purpose-operation-v1":
                r = purpose_record(r, purposes, intent, op)
            elif id_ == "security-hold-v1":
                from dataclasses import replace

                res, reason = verdict(Verdict.PASS)
                if nc.security_holds:
                    res, reason = verdict(Verdict.FAIL, "SECURITY_HOLD")
                r = replace(r, result=res, reason_code=reason)
            else:
                continue
            out.append(r)
        return out, unavailable


def line(res: validator.Result | None, err: BaseException | None, request_id: str) -> str:
    """The response line of a submission: its compact receipt, or the Problem of its
    rejection."""
    if res is not None and res.receipt:
        return res.receipt
    p = validator.problem_of(err, request_id)
    if p is None:
        return json.dumps(
            {
                "type": "about:blank",
                "title": "Dependency unavailable",
                "status": 503,
                "code": "DEPENDENCY_UNAVAILABLE",
                "request_id": request_id,
            }
        )
    return json.dumps(
        {
            "type": p.type,
            "title": p.title,
            "status": p.status,
            "code": p.code,
            "request_id": p.request_id,
        }
    )
