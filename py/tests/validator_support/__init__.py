"""Test support: drives the reference validator over the evaluation cases of
spec/v1.0/fixtures. The port of go/validator/conformance: it reads a case with
hop_top_pact.conformance, builds the gateway the case describes over the in-memory adapter
of hop_top_pact.adapters.memory, and evaluates. It is not part of the package."""

from __future__ import annotations

from validator_support.run import Fixture, locate, prepare, run_case

__all__ = ["Fixture", "locate", "prepare", "run_case"]
