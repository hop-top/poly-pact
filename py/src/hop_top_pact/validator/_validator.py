"""The validator and the admission steps that come before an authenticated evaluation (draft
11.3 steps 1 to 4, 12.2)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from hop_top_pact import contract
from hop_top_pact.adapter import Code
from hop_top_pact.core import clock, digest, jws, limits, strictjson
from hop_top_pact.core.clock import Clock
from hop_top_pact.core.enums import CheckStatus, Mode
from hop_top_pact.core.jws import base64url
from hop_top_pact.core.types import Presentation
from hop_top_pact.validator import _exact
from hop_top_pact.validator._checks import run
from hop_top_pact.validator._config import (
    Config,
    ContextMapper,
    HoldStore,
    Native,
    PolicyRegistry,
    ReceiptStore,
    Request,
    Result,
    Signer,
    StatusChecker,
)
from hop_top_pact.validator._decide import (
    REASON_CONTEXT_MISMATCH,
    REASON_UNAVAILABLE,
    stale_contract,
)
from hop_top_pact.validator._eval import Evaluation
from hop_top_pact.validator._handoff import is_proof_failure
from hop_top_pact.validator._outcome import fail, unknown
from hop_top_pact.validator._outcome import ok as passed
from hop_top_pact.validator._problem import (
    CODE_CONTEXT_MISMATCH,
    CODE_INVALID_MESSAGE,
    CODE_INVALID_PROOF,
    Rejection,
    code_of,
    reject,
)
from hop_top_pact.validator._seal import seal
from hop_top_pact.validator._state import Event, Machine

__all__ = ["Validator"]

# The longest evaluation of draft 12.2 and 20.1.
MAX_EVALUATION: Final = timedelta(seconds=30)


@dataclass(slots=True, kw_only=True)
class Validator:
    """Evaluates presentations (draft 11.3) and seals each authenticated evaluation in a
    signed receipt (draft 12). Every store is an object the gateway implements; a store
    that cannot answer defers, never admits (draft 18). It is safe for concurrent use when
    its stores are: replicas of a gateway share one replay store and one receipt store.

    native is the gateway's native adapter (draft 17.1). replay consumes contract nonces
    atomically (draft 7.5). receipts records sealed receipts durably (draft 12.2). holds
    reports security holds, policies the active policy and selection, status the status
    of evidence (draft 18). contexts is the installed reputation context mapping; without
    it a presented snapshot's context cannot be checked, so the reputation-context check
    is UNKNOWN. signer signs the attestations; clock is the only source of time.
    """

    config: Config = field(default_factory=Config)
    native: Native | None = None
    replay: contract.ReplayStore | None = None
    receipts: ReceiptStore | None = None
    holds: HoldStore | None = None
    policies: PolicyRegistry | None = None
    status: StatusChecker | None = None
    contexts: ContextMapper | None = None
    signer: Signer | None = None
    clock: Clock | None = None

    def evaluate(self, req: Request, *, cancelled: Callable[[], bool] | None = None) -> Result:
        """Evaluate one presentation for the actual operation of req, at the instant the
        clock gives, and return the sealed receipt.

        A request rejected before an authenticated evaluation (draft 12.2) gets no
        receipt: the error is then a Rejection carrying the draft 13.4 code, which
        problem_of turns into a transport error. An authenticated evaluation always ends
        in a receipt, ADMISSIBLE only when every required check passed; when the receipt
        cannot be recorded durably, the error is a DEPENDENCY_UNAVAILABLE Rejection whose
        result attribute holds the DEFERRED receipt.

        cancelled is the requestor's cancellation through native session control (draft
        12.2): a predicate polled while the evaluation runs, in place of the Go context.
        Once it returns true the evaluation seals as CANCELLED; None never cancels. A
        predicate that raises is a caller bug and propagates. The evaluation deadline is
        driven by the clock alone.
        """
        self._ready()
        assert self.clock is not None
        e = Evaluation(v=self, req=req, m=Machine(), start=self.clock.now(), cancelled=cancelled)
        admit(e)
        e.m.fire(Event.PRESENTED)
        run(e)
        return seal(e)

    def _ready(self) -> None:
        """Raise ValueError for a configuration the validator cannot work with."""
        c = self.config
        if None in (
            self.native, self.replay, self.receipts, self.holds, self.policies, self.status,
            self.signer, self.clock,
        ):  # fmt: skip
            raise ValueError(
                "validator: native, replay, receipts, holds, policies, status, signer and clock "
                "are required"
            )
        if not (
            c.audience and c.issuer and c.source_id and c.realm.tenant_id and c.realm.environment_id
        ):
            raise ValueError("validator: Config needs audience, issuer, source_id and realm")
        if c.skew < timedelta(0) or c.skew > clock.BASELINE_SKEW:
            raise ValueError(f"validator: skew {c.skew} outside 0 to {clock.BASELINE_SKEW}")
        if c.evaluation_time < timedelta(0) or c.evaluation_time > MAX_EVALUATION:
            raise ValueError(
                f"validator: evaluation time {c.evaluation_time} outside 0 to {MAX_EVALUATION}"
            )
        try:
            limits.check(self.limits())
        except limits.LimitError as err:
            raise ValueError(str(err)) from err

    def limits(self) -> limits.Limits:
        return self.config.limits or limits.defaults()


class _HolderKeys:
    """The key resolver of a presentation: the expected holder_jkt comes from the agent
    binding, which the callback resolves."""

    def __init__(self, resolve: Callable[[jws.KeyRequest], str]) -> None:
        self._resolve = resolve

    def trusted_keys(self, req: jws.KeyRequest) -> jws.KeySet | None:
        raise LookupError("a presentation is holder-signed")

    def holder_jkt(self, req: jws.KeyRequest) -> str:
        return self._resolve(req)


def admit(e: Evaluation) -> None:
    """Run what comes before an authenticated evaluation (draft 11.3 steps 1 to 4, 12.2):
    native authentication, the presentation's form and signature, the agent binding, the
    contract's signature and validity window, the transport the contract names (draft
    13.3.1), the presentation's time bounds and the nonce. A failure is a transport
    rejection."""
    cfg, lim = e.v.config, e.v.limits()
    if not e.req.principal.id:
        raise reject(CODE_INVALID_PROOF, "no native authentication")
    refused: list[Rejection] = []

    def resolve(r: jws.KeyRequest) -> str:
        try:
            return prepare(e, r.payload)
        except Rejection as x:
            refused.append(x)
            raise

    try:
        parsed = jws.Verifier(
            keys=_HolderKeys(resolve),
            typ=jws.TYP_PRESENTATION,
            algorithms=cfg.algorithms,
            limits=limits.presentation_json(lim),
        ).verify(e.req.presentation)
    except jws.JWSError as err:
        if refused:
            raise refused[0] from err
        if is_proof_failure(err):
            raise reject(CODE_INVALID_PROOF, f"presentation signature: {err}") from err
        raise reject(CODE_INVALID_MESSAGE, f"presentation: {err}") from err
    if parsed.header.jwk is None:
        raise reject(CODE_INVALID_MESSAGE, "presentation carries no jwk")
    try:
        e.jkt = jws.thumbprint(parsed.header.jwk)
    except jws.JWSError as err:
        raise reject(CODE_INVALID_MESSAGE, f"presentation jwk: {err}") from err
    p, c = e.pres, e.con
    if e.jkt != p.profile.holder_jkt or e.jkt != c.claims.holder_jkt:
        raise reject(
            CODE_INVALID_PROOF, "presentation key is not the profile and contract holder_jkt"
        )
    named = c.transport()
    if c.claims.mode == Mode.ENFORCED and e.req.transport != named:
        raise reject(
            CODE_CONTEXT_MISMATCH,
            f'presentation arrived over transport "{e.req.transport}"; '
            f'the contract names "{named}"',
        )
    try:
        clock.check_presentation(p.iat, p.nbf, p.exp, e.start, cfg.skew)
    except clock.ClockError as err:
        if err.kind in (clock.ClockErrorKind.EXPIRED, clock.ClockErrorKind.TOO_OLD):
            raise reject(contract.CODE_EXPIRED, f"presentation: {err}") from err
        raise reject(CODE_INVALID_MESSAGE, f"presentation: {err}") from err
    try:
        limits.validate_operation(lim, e.req.operation)
    except limits.LimitError as err:
        raise reject(CODE_INVALID_MESSAGE, f"actual operation: {err}") from err
    if e.req.operation.principal_id != e.req.principal.id:
        raise reject(
            CODE_INVALID_MESSAGE,
            "actual operation names another principal than the authenticated one",
        )
    evaluation_time = cfg.evaluation_time or MAX_EVALUATION
    e.deadline = e.start + evaluation_time
    from datetime import UTC

    for exp in (c.claims.exp, p.exp):
        t = datetime.fromtimestamp(exp, UTC)
        if t < e.deadline:
            e.deadline = t
    consume_nonce(e)


def prepare(e: Evaluation, payload: bytes) -> str:
    """Decode the presentation payload, verify the embedded contract and resolve the agent
    binding, and return the holder_jkt the presentation key must have. It runs inside the
    JWS verification, after the structural checks and before the signature check; nothing
    in the payload is trusted until that check passes."""
    cfg, lim = e.v.config, e.v.limits()
    try:
        p = strictjson.decode(payload, Presentation, limits.presentation_json(lim))
        raw = _exact.raw_members(payload, limits.presentation_json(lim))
    except strictjson.StrictJSONError as err:
        raise reject(CODE_INVALID_MESSAGE, f"presentation payload: {err}") from err
    e.p = p
    e.profile_raw, e.intent_raw, e.op_raw = (
        raw.get("profile", ""),
        raw.get("intent", ""),
        raw.get("operation", ""),
    )
    try:
        limits.validate_presentation(lim, p, len(payload))
        limits.validate_profile_size(lim, len(e.profile_raw.encode("utf-8")))
    except limits.LimitError as err:
        raise reject(CODE_INVALID_MESSAGE, str(err)) from err
    if p.pact_version != "0.1" or p.iss != p.sub:
        raise reject(CODE_INVALID_MESSAGE, "presentation pact_version or iss and sub")
    try:
        e.profile = _exact.exact_value(e.profile_raw.encode("utf-8"))
    except (strictjson.StrictJSONError, ValueError) as err:
        raise reject(CODE_INVALID_MESSAGE, f"profile: {err}") from err
    try:
        c = contract.Verifier(
            publishers=cfg.publishers, algorithms=cfg.algorithms, skew=cfg.skew
        ).verify(p.contract, e.start)
    except contract.ContractError as err:
        raise reject(err.code, str(err)) from err
    try:
        limits.validate_contract(lim, c.claims)
    except limits.LimitError as err:
        raise reject(CODE_INVALID_MESSAGE, f"contract: {err}") from err
    e.c = c
    e.schemas = _schemas(c)
    return resolve_binding(e)


def _schemas(c: contract.Contract) -> dict[str, object]:
    """The exact field-rule schemas of the contract, by rule_id: its signed payload read again
    with numbers kept as written."""
    payload = base64url.decode(c.compact.split(".")[1])
    doc = _exact.exact_value(payload)
    return {r["rule_id"]: r["schema"] for r in doc["field_rules"]}


def resolve_binding(e: Evaluation) -> str:
    """Resolve the binding of the agent the presentation names to the authenticated workload
    (draft 6.1, 11.3 step 2, 17.1)."""
    pr = e.req.principal
    assert e.v.native is not None
    try:
        b = e.v.native.resolve_agent_binding(pr.realm, pr.workload, e.pres.sub)
    except Exception as err:
        code = code_of(err)
        if code in (
            str(Code.UNSUPPORTED_REQUIREMENT),
            CODE_INVALID_PROOF,
            CODE_CONTEXT_MISMATCH,
        ):
            raise reject(code, f"agent binding: {err}") from err
        # The enrollment source cannot answer: the evaluation proceeds and defers (draft 18);
        # the key must still be the one the publisher bound into the contract.
        return e.con.claims.holder_jkt
    from hop_top_pact.adapter import BindingStatus

    if b.status == BindingStatus.UNKNOWN:
        if b.enrolled_elsewhere:
            raise reject(CODE_CONTEXT_MISMATCH, "agent is enrolled for another workload")
        raise reject(CODE_INVALID_PROOF, "agent has no enrollment on the authenticated workload")
    if b.status in (BindingStatus.ACTIVE, BindingStatus.COMPROMISED):
        if b.agent_id != e.pres.sub:
            raise reject(CODE_INVALID_PROOF, "binding names another agent")
    else:
        raise reject(CODE_INVALID_PROOF, f"agent binding is {b.status}")
    e.binding, e.binding_known = b, True
    return b.holder_jkt


def consume_nonce(e: Evaluation) -> None:
    """Step 4 of draft 11.3: the nonce of the presentation is its contract's, consumed
    atomically, once."""
    p, c = e.pres, e.con
    if p.nonce != c.claims.nonce:
        e.nonce = fail(REASON_CONTEXT_MISMATCH)
        return
    until = clock.replay_retention(p.exp, p.iat, e.v.config.skew)
    from datetime import UTC

    t = datetime.fromtimestamp(c.claims.exp, UTC)
    if t > until:
        until = t
    assert e.v.replay is not None
    try:
        e.v.replay.consume(c.nonce_record(), e.start, until)
        e.nonce = passed()
    except contract.ContractError as err:
        if err.code == contract.CODE_REPLAY:
            if sealed_stale(e):
                raise reject(
                    contract.CODE_REQUIREMENTS_CHANGED,
                    "contract was sealed stale; obtain a new contract",
                ) from err
            raise reject(contract.CODE_REPLAY, "nonce already consumed") from err
        if err.code == CODE_CONTEXT_MISMATCH:
            e.nonce = fail(REASON_CONTEXT_MISMATCH)
        else:
            e.nonce = unknown(REASON_UNAVAILABLE)
    except Exception:
        e.nonce = unknown(REASON_UNAVAILABLE)
    e.nonce.observed = e.nonce.status = None


def sealed_stale(e: Evaluation) -> bool:
    """Report whether an evaluation of the contract sealed with a result that makes the
    contract stale: on reuse of such a contract the transport error is
    REQUIREMENTS_CHANGED (draft 11.3 step 9, 12.2)."""
    assert e.v.receipts is not None
    try:
        rs = e.v.receipts.by_contract(e.con.digest)
    except Exception:
        return False
    return any(
        c.result == CheckStatus.FAIL and stale_contract(c.reason_code)
        for r in rs
        for c in r.attestation.checks
    )


def object_digest(raw: str) -> str:
    """The object_digest of received JSON text (draft 7.4); empty when it has none."""
    try:
        return digest.object_digest(strictjson.parse(raw.encode("utf-8")))
    except (strictjson.StrictJSONError, ValueError, TypeError):
        return ""
