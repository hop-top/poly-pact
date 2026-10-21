"""The py column of the parity gates (docs/sdk/ports-plan.md section 5.3).

The harness exits 1 on a fail under a gate that is required for py; a fail
under a planned gate is printed and counted. The gates file sits at
tools/parity/gates.json of the repository whose spec/v1.0/fixtures holds the
manifest. Without it (a mirror checkout, a copy of the spec tree) no gate is
required.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hop_top_pact.vectors._common import HarnessError, parse_json

LANGUAGE = "py"
GATE_VALUES = ("required", "planned", "n/a")


@dataclass(frozen=True, slots=True)
class Gate:
    value: str
    exceptions: frozenset[str]


def gates_path(manifest: Path) -> Path | None:
    """tools/parity/gates.json of the repository of manifest.

    manifest is ROOT/spec/v1.0/fixtures/manifest.json: ROOT is its fourth parent.
    """
    parents = manifest.resolve().parents
    return parents[3] / "tools" / "parity" / "gates.json" if len(parents) > 3 else None


def load_gates(path: Path) -> dict[tuple[str, str, str], Gate]:
    """The py gate of every (scope, kind, prefix) row."""
    try:
        doc = parse_json(path.read_bytes())
    except (OSError, ValueError) as e:
        raise HarnessError(f"{path}: {e}") from e
    rows = doc.get("rows") if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        raise HarnessError(f"{path}: rows is not an array")
    out: dict[tuple[str, str, str], Gate] = {}
    for i, r in enumerate(rows):
        key = tuple(r.get(k) for k in ("scope", "kind", "prefix")) if isinstance(r, dict) else ()
        value = r.get(LANGUAGE) if isinstance(r, dict) else None
        exc = r.get("exceptions", []) if isinstance(r, dict) else None
        if (
            len(key) != 3
            or not all(isinstance(k, str) for k in key)
            or value not in GATE_VALUES
            or not isinstance(exc, list)
            or not all(isinstance(x, dict) and isinstance(x.get("id"), str) for x in exc)
        ):
            raise HarnessError(f"{path}: rows[{i}] is not a gate row with a {LANGUAGE} value")
        out[(str(key[0]), str(key[1]), str(key[2]))] = Gate(
            str(value), frozenset(str(x["id"]) for x in exc)
        )
    return out
