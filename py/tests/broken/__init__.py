"""A deliberately wrong adapter: the memory adapter with switchable defects, each a
violation of draft 17.1 and of the invariants it cites that one common
conformance case exists to catch. Port of Go adapters/internal/broken.

The conformance suite is only evidence if it can fail. This package is the
proof: its test runs the suite against the adapter with each defect on and
requires the cases the defect targets to fail, against the adapter with all
defects on and requires every case to fail, and against the adapter with none
and requires every case to pass. A case that no defect targets fails a test of
its own, so a new case cannot land without a mutant that it catches.

It lives in the test tree and is never published. Do not use it as an example
of anything.
"""

from broken.adapter import BrokenAdapter, defects, factory, new_adapter, shared_factory
from broken.catalogue import CATALOGUE
from broken.defects import Defect, Spec
from broken.modes import MODES, Mode

__all__ = [
    "CATALOGUE",
    "MODES",
    "BrokenAdapter",
    "Defect",
    "Mode",
    "Spec",
    "defects",
    "factory",
    "new_adapter",
    "shared_factory",
]
