"""The error of the broken adapter that wraps another one (Go's fmt.Errorf with
%w)."""

from __future__ import annotations

from hop_top_pact.errors import PactError

__all__ = ["BrokenError"]


class BrokenError(PactError):
    """An error the broken adapter raises from another, which it wraps: the cause
    chain keeps the wrapped error and its code."""
