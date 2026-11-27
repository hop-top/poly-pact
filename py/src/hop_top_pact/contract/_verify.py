"""Verifying received requirement contracts (draft 11.3 step 3)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Final

from hop_top_pact.adapter import Code
from hop_top_pact.contract._errors import CODE_EXPIRED, ContractError
from hop_top_pact.contract._types import Contract
from hop_top_pact.contract._validate import validate
from hop_top_pact.core import clock, digest, jws, strictjson
from hop_top_pact.core.clock import ClockError, ClockErrorKind
from hop_top_pact.core.jws import Algorithms, KeyRequest, KeySet, Reason
from hop_top_pact.core.types import RequirementContract

__all__ = ["Verifier"]

# The JWS failures that mean the publisher could not be authenticated; every other
# failure is a malformed message.
_SIGNATURE_REASONS: Final = frozenset(
    {Reason.SIGNATURE_INVALID, Reason.KID_UNKNOWN, Reason.KEY_UNAVAILABLE}
)


class _PublisherKeys:
    """Resolves the key set of the trust record that the payload's iss names. The payload
    is not authenticated yet: iss only selects which configured keys apply
    (jws.KeyRequest)."""

    def __init__(self, publishers: Mapping[str, KeySet]) -> None:
        self._publishers = publishers

    def trusted_keys(self, req: KeyRequest) -> KeySet | None:
        try:
            claims = json.loads(req.payload)
        except ValueError:
            return None
        iss = claims.get("iss") if isinstance(claims, dict) else None
        return self._publishers.get(iss) if isinstance(iss, str) else None

    def holder_jkt(self, req: KeyRequest) -> str:
        raise LookupError("a requirement contract is not holder-signed")


@dataclass(frozen=True, slots=True, kw_only=True)
class Verifier:
    """Verifies received contracts.

    publishers maps the iss of each gateway-authorized requirement publisher to the
    keys its trust record holds (draft 7.3: iss selects a trust record). A contract
    whose iss is not a key of the map has no trusted key. skew is the allowed clock
    skew, 0 to 5 s (draft 7.5); zero allows none. algorithms are the negotiated JWS
    algorithms; empty is ES256 alone.
    """

    publishers: Mapping[str, KeySet] = field(default_factory=dict)
    algorithms: Algorithms = field(default_factory=Algorithms)
    skew: timedelta = timedelta(0)

    def verify(self, compact: str, now: datetime) -> Contract:
        """Check compact at the verifier time now, in this order, and raise for the first
        failure:

        1. the JWS profile of draft 7.2 with typ pact-requirements+jwt, and the
           signature over the received signing input under a key of the trust record
           iss names: INVALID_MESSAGE for a malformed JWS or another typ,
           INVALID_PROOF when no trusted key of that publisher verifies it, which is
           the case for rules edited after signing;
        2. strict decoding into a RequirementContract and the schema and Appendix A.2
           rules: INVALID_MESSAGE;
        3. the time rules of draft 7.5 with self.skew: EXPIRED when now is at or after
           exp, INVALID_MESSAGE when iat or nbf is later than now plus the skew or
           exp - iat exceeds 60 seconds (draft 9.1, 20.1).

        A skew outside 0 to 5 s is a configuration error and raises ValueError.
        """
        if self.skew < timedelta(0) or self.skew > clock.BASELINE_SKEW:
            raise ValueError(f"contract: skew {self.skew} outside 0 to {clock.BASELINE_SKEW}")
        try:
            parsed = jws.Verifier(
                keys=_PublisherKeys(self.publishers),
                typ=jws.TYP_REQUIREMENTS,
                algorithms=self.algorithms,
            ).verify(compact)
        except jws.JWSError as e:
            code: str = Code.INVALID_PROOF
            if e.reason not in _SIGNATURE_REASONS:
                code = Code.INVALID_MESSAGE
            raise ContractError(code, str(e)) from e
        try:
            claims = strictjson.decode(parsed.payload, RequirementContract)
            raw = strictjson.parse(parsed.payload)
            validate(claims, raw if isinstance(raw, Mapping) else None)
        except (strictjson.StrictJSONError, ValueError) as e:
            raise ContractError(Code.INVALID_MESSAGE, str(e)) from e
        try:
            clock.check_window(claims.iat, claims.nbf, claims.exp, now, self.skew)
        except ClockError as e:
            expired: str = (
                CODE_EXPIRED if e.kind == ClockErrorKind.EXPIRED else Code.INVALID_MESSAGE
            )
            raise ContractError(expired, str(e)) from e
        try:
            clock.check_lifetime(clock.Artifact.CONTRACT, claims.iat, claims.exp)
        except ClockError as e:
            raise ContractError(Code.INVALID_MESSAGE, str(e)) from e
        try:
            artifact = digest.artifact_digest(compact)
        except ValueError as e:
            raise ContractError(Code.INVALID_MESSAGE, str(e)) from e
        return Contract(compact=compact, claims=claims, digest=artifact)
