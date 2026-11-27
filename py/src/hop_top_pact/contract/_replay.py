"""The replay store (draft 7.5): the nonces of issued contracts, each consumed at
most once."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from hop_top_pact.adapter import Code
from hop_top_pact.contract._errors import CODE_REPLAY, ContractError
from hop_top_pact.contract._types import NonceRecord

__all__ = ["MemoryReplay", "ReplayStore"]


class ReplayStore(Protocol):
    """Keeps the nonces of issued contracts and consumes each at most once (draft 7.5).

    Replicas of a gateway share one store; consumption is atomic across them.
    A store that is full or cannot answer raises a ContractError with code
    DEPENDENCY_UNAVAILABLE, never succeeds. A record is kept at least until the
    latest until it was given, and never evicted earlier, under load or
    otherwise. The calls are synchronous and take no context argument.
    """

    def register(self, r: NonceRecord, now: datetime, until: datetime) -> None:
        """Record the nonce of a contract the publisher issued, not yet consumed, and
        keep it at least until until. A nonce the store already holds is REPLAY."""
        ...

    def consume(self, r: NonceRecord, now: datetime, until: datetime) -> None:
        """Atomically mark the registered nonce r.nonce consumed and keep it at least
        until until. A nonce consumed before, or never registered, is REPLAY; a
        record that differs from the registered one is CONTEXT_MISMATCH and consumes
        nothing."""
        ...


@dataclass(slots=True)
class _Entry:
    record: NonceRecord
    until: datetime
    consumed: bool = False


class MemoryReplay:
    """A ReplayStore in the memory of one process. It is safe for concurrent use.

    It holds at most max_records records; zero or less is no bound. A record whose
    retention bound has passed is removed when the store needs room. Replicas
    share one store, not one MemoryReplay.
    """

    def __init__(self, max_records: int = 0) -> None:
        self._lock = threading.Lock()
        self._max = max_records
        self._records: dict[str, _Entry] = {}

    def register(self, r: NonceRecord, now: datetime, until: datetime) -> None:
        """Record r.nonce, not yet consumed, until at least until."""
        with self._lock:
            self._evict(r.nonce, now)
            if r.nonce in self._records:
                raise ContractError(CODE_REPLAY, "nonce already registered")
            if self._max > 0 and len(self._records) >= self._max:
                self._sweep(now)
                if len(self._records) >= self._max:
                    raise ContractError(Code.DEPENDENCY_UNAVAILABLE, "replay store full")
            self._records[r.nonce] = _Entry(r, until)

    def consume(self, r: NonceRecord, now: datetime, until: datetime) -> None:
        """Consume r.nonce once; see ReplayStore.consume."""
        with self._lock:
            self._evict(r.nonce, now)
            e = self._records.get(r.nonce)
            if e is None:
                raise ContractError(CODE_REPLAY, "nonce not issued or no longer retained")
            if e.consumed:
                raise ContractError(CODE_REPLAY, "nonce already consumed")
            if e.record != r:
                raise ContractError(
                    Code.CONTEXT_MISMATCH,
                    "nonce bound to another agent, key, realm, operation or contract",
                )
            e.consumed = True
            if until > e.until:
                e.until = until

    def _evict(self, nonce: str, now: datetime) -> None:
        """Remove the record of nonce when its retention bound has passed."""
        e = self._records.get(nonce)
        if e is not None and now > e.until:
            del self._records[nonce]

    def _sweep(self, now: datetime) -> None:
        """Remove every record whose retention bound has passed."""
        for n in [n for n, e in self._records.items() if now > e.until]:
            del self._records[n]
