"""The root of the package's exception hierarchy.

Every error family of the Go library has one PactError subclass here, with a
kind, reason or code attribute holding the Go names: core.limits.LimitError,
core.clock.ClockError, and the families of the later modules.
"""

from __future__ import annotations

__all__ = ["PactError"]


class PactError(Exception):
    """Base class of every error the package raises for a protocol or limit violation."""
