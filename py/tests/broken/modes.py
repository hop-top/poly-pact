"""The workload modes the proof runs the broken adapter in (Go
adapters/internal/broken, modes of broken_test.go): dedicated workloads, the
default of every profile, and workloads shared by several agents (identity
mapping IM-19). Each mode runs the cases that apply to it."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from broken.adapter import factory, shared_factory
from broken.defects import Defect
from hop_top_pact.adapter.adaptertest import Factory, Options

__all__ = ["MODES", "Mode"]


@dataclass(frozen=True, slots=True)
class Mode:
    """One workload mode: its name, the factory of the broken adapter with the given
    defects on, and the options the suite runs it with."""

    name: str
    factory: Callable[..., Factory]
    options: Options

    def build(self, *on: Defect) -> Factory:
        """The factory of the adapter with the defects on, in this mode."""
        f: Factory = self.factory(*on)
        return f


MODES: tuple[Mode, ...] = (
    Mode("dedicated", factory, Options()),
    Mode("shared", shared_factory, Options(shared_workloads=True)),
)
