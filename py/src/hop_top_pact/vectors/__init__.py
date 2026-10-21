"""Shared-vector harness: ``python -m hop_top_pact.vectors [MANIFEST]``.

Prints one NDJSON line per manifest entry, ``{"id","kind","result"}``, and
nothing else on standard output. The counterpart of ``pactconf vectors
verify --ndjson``; the result grammar is in tools/parity/README.md of the
source repository (Result grammar).
"""

from __future__ import annotations

from typing import Final

# The manifest is read through hop_top_pact.runner.manifest, whose kinds(),
# scopes() and capabilities() are the closed sets an entry must stay within.

# The kinds the harness runs, in scope core and adapter. Every other entry,
# and every entry of scope runner, is skipped:out-of-scope.
RUN_KINDS: Final = ("vector", "key")

# The (kind, prefix) groups the harness runs. A run kind entry of scope core
# or adapter outside them fails the harness (unknown prefix). The prefix is
# the first segment of the id, or the first two under vectors/.
GROUPS: Final = (
    ("key", "keys"),
    ("vector", "vectors/binding"),
    ("vector", "vectors/digest"),
    ("vector", "vectors/jcs"),
    ("vector", "vectors/jws"),
    ("vector", "vectors/schema"),
    ("vector", "vectors/strictjson"),
)

# The optional capabilities this harness declares: none, so an entry that
# lists one is skipped:capability.
DECLARED_CAPABILITIES: Final[tuple[str, ...]] = ()

__all__ = ["DECLARED_CAPABILITIES", "GROUPS", "RUN_KINDS"]
