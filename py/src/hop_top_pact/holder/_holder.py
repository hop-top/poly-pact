"""The holder: negotiation, contract verification and presentations (draft 11.1 steps 2 to
5)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from hop_top_pact import contract
from hop_top_pact.adapter import Code, Realm
from hop_top_pact.contract import ContractError
from hop_top_pact.core import VERSION, clock, digest, jws, limits
from hop_top_pact.core.enums import JWSAlgorithm, Mode
from hop_top_pact.core.types import GatewayMetadata, Intent, OperationContext
from hop_top_pact.errors import PactError
from hop_top_pact.holder._artifact import peek, version_of
from hop_top_pact.holder._errors import CODE_EXPIRED, HolderError, unsupported_version
from hop_top_pact.holder._keysource import KeySource
from hop_top_pact.holder._present import present
from hop_top_pact.holder._types import Input, Presentation

__all__ = ["Holder", "HolderKey"]

_SECOND = timedelta(seconds=1)
# The codes of the contract package a holder passes on as its own.
_TRANSLATED = frozenset(
    {
        str(Code.INVALID_PROOF),
        str(Code.CONTEXT_MISMATCH),
        str(Code.UNSUPPORTED_REQUIREMENT),
        contract.CODE_EXPIRED,
        str(Code.DEPENDENCY_UNAVAILABLE),
    }
)


@dataclass(frozen=True, slots=True)
class HolderKey:
    """The key source's public key, checked, with its algorithm and RFC 7638 thumbprint."""

    jwk: jws.JWK
    alg: str
    jkt: str


@dataclass(slots=True, kw_only=True)
class Holder:
    """The agent side of one gateway: the enrolled agent, its key, the gateway it presents
    to and the requirement publishers it trusts.

    agent_id is the agent's agent_id (draft 6.1): the sub of its contracts and the iss
    and sub of its presentations. keys holds the enrolled holder key. gateway is the
    gateway's identifier: the aud of contracts and presentations, and the gateway_id of
    its metadata. realm is the gateway's tenant and environment. publishers maps the
    iss of each requirement publisher the holder trusts for this gateway to its keys
    (draft 7.3); they come from configuration, never from discovery (draft 13.1).
    algorithms are the negotiated JWS algorithms; empty is ES256 alone. extensions
    lists the contract extensions the holder supports; a contract with any other
    defers (draft 7.1, 21). skew is the allowed clock skew, 0 to 5 s (draft 7.5).
    lifetime is a presentation's exp - iat, whole seconds from 1 s to 60 s; zero is 60
    s (draft 7.5, 20.1). random is the source of presentation jti values, a function
    from a byte count to that many random bytes; None is the operating system's.
    transport is the transport profile the holder sends its presentations over:
    contract.TRANSPORT_HTTPS, the default when empty, or contract.TRANSPORT_STDIO_IPC
    (draft 13.3.1).
    """

    agent_id: str = ""
    keys: KeySource | None = None
    gateway: str = ""
    realm: Realm = field(default_factory=Realm)
    publishers: Mapping[str, jws.KeySet] = field(default_factory=dict)
    algorithms: jws.Algorithms = field(default_factory=jws.Algorithms)
    extensions: tuple[str, ...] = ()
    skew: timedelta = timedelta(0)
    lifetime: timedelta = timedelta(0)
    random: Callable[[int], bytes] | None = None
    transport: str = ""

    def check(self) -> tuple[int, KeySource]:
        """Validate the holder's configuration and return the presentation lifetime in
        seconds and the key source."""
        if not (
            self.agent_id and self.gateway and self.realm.tenant_id and self.realm.environment_id
        ):
            raise HolderError(Code.INVALID_MESSAGE, "agent_id, gateway and realm are required")
        if self.keys is None:
            raise HolderError(Code.INVALID_MESSAGE, "no key source")
        if self.skew < timedelta(0) or self.skew > clock.BASELINE_SKEW:
            raise HolderError(
                Code.INVALID_MESSAGE, f"skew {self.skew} outside 0 to {clock.BASELINE_SKEW}"
            )
        lifetime = self.lifetime or 60 * _SECOND
        if lifetime < _SECOND or lifetime > 60 * _SECOND or lifetime % _SECOND != timedelta(0):
            raise HolderError(
                Code.INVALID_MESSAGE,
                f"presentation lifetime {self.lifetime} is not 1 to 60 whole seconds",
            )
        return lifetime // _SECOND, self.keys

    def key(self, keys: KeySource) -> HolderKey:
        """The key source's public key. A key that is not a valid public key of an
        implemented algorithm is invalid; one whose algorithm is not negotiated is
        unsupported."""
        try:
            pub = keys.public_jwk()
        except Exception as e:
            raise HolderError(Code.DEPENDENCY_UNAVAILABLE, f"key source: {e}") from e
        # Only the members that identify the key are embedded (RFC 7638 section 3.2); kid,
        # alg and use play no part in a holder key's selection (draft 7.2).
        jwk = jws.JWK(kty=pub.kty, crv=pub.crv, x=pub.x, y=pub.y)
        try:
            alg = jwk.algorithm()
        except jws.JWSError as e:
            raise HolderError(Code.INVALID_PROOF, f"key source key: {e}") from e
        if not jws.Algorithms(self.algorithms).accepts(alg):
            raise HolderError(Code.UNSUPPORTED_REQUIREMENT, f"algorithm {alg} is not negotiated")
        try:
            jkt = jws.thumbprint(jwk)
        except jws.JWSError as e:
            raise HolderError(Code.INVALID_PROOF, f"key source key: {e}") from e
        return HolderKey(jwk, alg, jkt)

    def negotiate(self, md: GatewayMetadata) -> str:
        """Check the gateway metadata md (draft 13.1) and return the wire version to use:
        the gateway is self.gateway in self.realm's environment (CONTEXT_MISMATCH), it
        lists wire version 0.1, the only one this holder implements, compared exactly
        (INVALID_MESSAGE of kind unsupported-version; the holder never downgrades, draft
        21), and it lists the algorithm of the holder key, which self.algorithms also
        accepts (UNSUPPORTED_REQUIREMENT). The metadata establishes no trust: publisher
        keys come from self.publishers only."""
        _, keys = self.check()
        if md.gateway_id != self.gateway or md.environment_id != self.realm.environment_id:
            raise HolderError(
                Code.CONTEXT_MISMATCH,
                f"metadata of gateway {md.gateway_id!r} in {md.environment_id!r}",
            )
        if VERSION not in md.wire_versions:
            raise unsupported_version(
                f"gateway wire versions {list(md.wire_versions)!r}, holder {VERSION!r}"
            )
        k = self.key(keys)
        if JWSAlgorithm(k.alg) not in md.jws_algorithms:
            raise HolderError(Code.UNSUPPORTED_REQUIREMENT, f"gateway does not list {k.alg}")
        return VERSION

    def verify_contract(
        self, compact: str, intent: Intent, op: OperationContext, now: datetime
    ) -> contract.Contract:
        """Verify a received requirement contract for the intent and operation the agent is
        about to perform, at the holder time now:

        1. the publisher's signature under the keys self.publishers holds for its iss,
           the typ, the schema and the time rules of draft 7.5 with the 60-second
           lifetime (contract.Verifier.verify): INVALID_PROOF, INVALID_MESSAGE, an
           unsupported-version INVALID_MESSAGE for a pact_version other than 0.1, or
           EXPIRED at or after exp;
        2. sub, aud and realm are self.agent_id, self.gateway and self.realm
           (CONTEXT_MISMATCH), every extension is one of self.extensions
           (UNSUPPORTED_REQUIREMENT, which defers: draft 7.1, 21), and an enforced-mode
           contract names self.transport (Contract.transport; CONTEXT_MISMATCH, the
           downgrade rule of draft 13.3.1);
        3. holder_jkt is the thumbprint of the key source's key (INVALID_PROOF, draft
           6.2);
        4. intent_digest and operation_digest are the object_digest of intent and op
           (CONTEXT_MISMATCH): a contract for another intent or operation, or for one
           that changed since, does not apply (draft 10.3).

        It does not check whether the contract is still active at the gateway or consume
        its nonce; the validator does.
        """
        _, keys = self.check()
        return self.verified(compact, intent, op, self.key(keys), now)

    def verified(
        self, compact: str, intent: Intent, op: OperationContext, k: HolderKey, now: datetime
    ) -> contract.Contract:
        _check_input_limits(intent, op)
        _check_version(compact)
        v = contract.Verifier(
            publishers=self.publishers, algorithms=self.algorithms, skew=self.skew
        )
        try:
            c = v.verify(compact, now)
            c.check(
                contract.Expect(
                    agent_id=self.agent_id,
                    audience=self.gateway,
                    realm=self.realm,
                    supported_extensions=tuple(self.extensions),
                )
            )
        except ContractError as e:
            raise _translate(e) from e
        named = c.transport()
        if c.claims.mode == Mode.ENFORCED and named != self.transport_name():
            raise HolderError(
                Code.CONTEXT_MISMATCH,
                f"contract names transport {named!r}, holder sends over {self.transport_name()!r}",
            )
        if c.claims.holder_jkt != k.jkt:
            raise HolderError(
                Code.INVALID_PROOF, f"contract holder_jkt {c.claims.holder_jkt}, key source {k.jkt}"
            )
        intent_digest = _object_digest("intent", intent)
        op_digest = _object_digest("operation", op)
        if intent_digest != c.claims.intent_digest:
            raise HolderError(
                Code.CONTEXT_MISMATCH,
                f"intent digest {intent_digest}, contract binds {c.claims.intent_digest}",
            )
        if op_digest != c.claims.operation_digest:
            raise HolderError(
                Code.CONTEXT_MISMATCH,
                f"operation digest {op_digest}, contract binds {c.claims.operation_digest}",
            )
        return c

    def transport_name(self) -> str:
        """The transport the holder sends over."""
        return self.transport or contract.TRANSPORT_HTTPS

    def present(self, in_: Input, now: datetime) -> Presentation:
        """Build and sign the presentation of in_ at the holder time now (draft 11.1 steps
        4 and 5, 11.2):

        1. the contract, through verify_contract: publisher, freshness, agent, gateway,
           realm, extensions, holder key, intent and operation;
        2. the source profile names this agent, key and tenant and is current, its
           lifetime at most 24 hours (draft 8.1, Appendix A.2);
        3. the view discloses the core fields and, of the attributes, only the values the
           contract's field rules name, in rule order (draft 8.1, 9.2, 19). A native or
           self rule takes the profile's value. An evidence rule needs an applicable
           evidence claim on exactly its path, from an issuer the rule allows, for this
           agent, key, gateway and realm, valid now (draft 8.3, 8.4): every applicable
           claim must equal the profile's value or, when the profile has none, one
           another, and then supplies it. An evidence rule at or under
           /attributes/reputation takes the complete value of an applicable snapshot
           (draft 15.2). A rule the agent cannot satisfy fails with MISSING_FIELD, a value
           that disagrees with the evidence with CONFLICTING_EVIDENCE; nothing is
           self-asserted in place of an authoritative value (draft 8.6);
        4. the evidence that backs a rule is attached in input order, the snapshot only
           when a rule uses it, and the draft 20.1 limits hold (INVALID_MESSAGE: nothing
           is truncated or dropped to fit);
        5. the payload, iss and sub the agent, aud the gateway, a fresh 128-bit jti, iat
           and nbf now, exp iat plus self.lifetime, the contract's nonce, is RFC 8785
           canonical JSON, and the key source signs the protected header and payload. The
           holder verifies the result under the key's thumbprint before returning it
           (INVALID_PROOF).

        Malformed evidence or snapshots are INVALID_MESSAGE, or an unsupported-version
        INVALID_MESSAGE for another wire version. A key source or random source failure
        is DEPENDENCY_UNAVAILABLE.
        """
        return present(self, in_, now)


def _object_digest(name: str, value: object) -> str:
    try:
        return digest.object_digest(value)
    except (ValueError, TypeError, PactError) as e:
        raise HolderError(Code.INVALID_MESSAGE, f"{name}: {e}") from e


def _check_input_limits(intent: Intent, op: OperationContext) -> None:
    """Apply the draft 20.1 limits of the intent and the operation before anything is
    hashed or verified."""
    try:
        limits.validate_intent(limits.defaults(), intent)
        limits.validate_operation(limits.defaults(), op)
    except limits.LimitError as e:
        raise HolderError(Code.INVALID_MESSAGE, str(e)) from e


def _check_version(compact: str) -> None:
    """Report a contract whose payload names another wire version as unsupported, so that
    it is not mistaken for a malformed one. The payload is not authenticated yet;
    verify still checks it."""
    try:
        payload, _ = peek(compact)
    except ValueError:
        return  # verify reports the malformed JWS
    version_of(payload)


def _translate(err: ContractError) -> HolderError:
    """Map an error of package contract to the code it carries, keeping its text."""
    code = err.code if err.code in _TRANSLATED else str(Code.INVALID_MESSAGE)
    if code == contract.CODE_EXPIRED:
        code = CODE_EXPIRED
    return HolderError(code, str(err))
