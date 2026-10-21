"""record_outcome of the broken adapter, with its defects, and the signer of the
reports it leaks into (Go adapters/internal/broken, record.go)."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import replace
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from broken.defects import Defect
from broken.errors import BrokenError
from hop_top_pact.adapter import NoVisibility, Observation, Recorded, Signed
from hop_top_pact.core import jws
from hop_top_pact.core.enums import Dimension, EventKind, OutcomeResult

if TYPE_CHECKING:
    from broken.adapter import BrokenAdapter

__all__ = ["LeakySigner", "record_outcome"]

OUTCOME_TYP = "pact-outcome+jwt"


def _raw_url(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise BrokenError("broken: not base64url") from e


class LeakySigner:
    """Signs outcome reports with a key of its own, for the defect that signs text
    the memory adapter would have cleaned."""

    def __init__(self, kid: str) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.kid = kid

    def sign(self, report: dict[str, object]) -> str:
        payload = json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return jws.sign(jws.Header(typ=OUTCOME_TYP, kid=self.kid), payload, self.key)

    def verify(self, compact: str) -> None:
        """Raise BrokenError unless compact carries a signature of this signer."""
        parts = compact.split(".")
        if len(parts) != 3:
            raise BrokenError("broken: not a compact JWS")
        sig = _raw_url(parts[2])
        if len(sig) != 64:
            raise BrokenError("broken: malformed signature")
        r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
        try:
            self.key.public_key().verify(
                encode_dss_signature(r, s),
                (parts[0] + "." + parts[1]).encode("ascii", errors="replace"),
                ec.ECDSA(hashes.SHA256()),
            )
        except InvalidSignature:
            raise BrokenError("broken: the signature does not verify") from None


def _decode_report(compact: str) -> dict[str, object]:
    parts = compact.split(".")
    if len(parts) != 3:
        raise BrokenError("broken: not a compact JWS")
    rep = json.loads(_raw_url(parts[1]))
    if not isinstance(rep, dict):
        raise BrokenError("broken: the payload is not an object")
    return rep


def record_outcome(b: BrokenAdapter, o: Observation) -> Recorded:
    """The memory adapter's, with the recording defects."""
    visible = b.state().visibility == "execution"
    if b.has(Defect.NO_VISIBILITY_FOR_ADMISSION) and o.event_kind == EventKind.ADMISSION:
        return NoVisibility(reason="the adapter has no visibility")
    if (
        b.has(Defect.NO_VISIBILITY_DESPITE_VISIBILITY)
        and o.event_kind == EventKind.EXECUTION
        and visible
    ):
        return NoVisibility(reason="the adapter has no visibility")
    if (
        b.has(Defect.ASSUME_EXECUTION_SUCCESS)
        and o.event_kind == EventKind.EXECUTION
        and not visible
        and b.executing is not None
    ):
        # The adapter cannot see the execution and signs a success anyway.
        o = replace(o, result=OutcomeResult.SUCCESS, dimension=Dimension.RELIABILITY)
        return b.executing.record_outcome(o)
    rec = b.base.record_outcome(o)
    if not b.has(Defect.LEAK_DETAILS_IN_REPORT) or b.leaky is None:
        return rec
    if not isinstance(rec, Signed):
        return rec
    rep = _decode_report(rec.jws)
    rep["details"] = o.details
    rep["evidence_refs"] = list(o.evidence_refs)
    return Signed(jws=b.leaky.sign(rep))
