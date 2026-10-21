"""Manifest and fixture reading shared by the harness groups.

The manifest is read through hop_top_pact.runner.manifest: its strict parse,
then the rules of the members the harness reads (shape, id, duplicate id,
kind, scope, capabilities) as harness errors. The other field rules,
completeness and the spec-map checks belong to the manifest check (python -m
hop_top_pact.runner.manifest check). Fixture files are read as strict JSON
with the standard library (duplicate members and non-finite literals
refused), so that a fixture defect is told apart from a defect of the code
under test.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final, cast

from hop_top_pact.core.types import JSONValue
from hop_top_pact.runner import manifest
from hop_top_pact.runner.manifest import Entry as Entry
from hop_top_pact.vectors import GROUPS, RUN_KINDS

# The largest fixture file, the RFC 8785 number list, is under 1 MiB.
MAX_FIXTURE_BYTES = 4 << 20
# Reasons of a skipped result (tools/parity/README.md, Skipped reasons).
OUT_OF_SCOPE = "out-of-scope"
SPEC_DEFECT = "spec-defect"
CAPABILITY = "capability"


class HarnessError(Exception):
    """The run cannot start or cannot be trusted: exit status 2, nothing on standard output."""


class Fail(Exception):
    """The entry fails: its fixture or the code under test disagrees with the expectation."""


class Skipped(Exception):
    """Neither passed nor failed, for reason: out-of-scope, spec-defect or capability."""

    def __init__(
        self,
        reason: str,
        msg: str,
        defects: Sequence[Mapping[str, str]] = (),
        missing: Sequence[str] = (),
    ) -> None:
        super().__init__(msg)
        self.reason = reason
        self.defects = list(defects)
        self.missing = list(missing)


def prefix(e: Entry) -> str:
    """The gate prefix of an entry: the first segment, or the first two under vectors/,
    adapters/ and sources/."""
    segs = e.id.split("/")
    if segs[0] in ("vectors", "adapters", "sources") and len(segs) > 1:
        return "/".join(segs[:2])
    return segs[0]


def runs(e: Entry) -> bool:
    """Whether the harness runs the entry: a run kind outside scope runner."""
    return e.scope != manifest.Scope.RUNNER and e.kind in RUN_KINDS


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate member {k!r}")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def parse_json(data: bytes) -> Any:
    """Parse UTF-8 JSON text, refusing duplicate members and NaN or Infinity."""
    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_reject_duplicates,
        parse_constant=_reject_constant,
    )


def dump_json(value: Any) -> bytes:
    """Write value as compact UTF-8 JSON text."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def freeze(value: Any) -> JSONValue:
    """Return the parsed value with arrays as tuples, the shape of a parsed PACT tree."""
    if isinstance(value, dict):
        return {k: freeze(v) for k, v in value.items()}
    if isinstance(value, list):
        return tuple(freeze(v) for v in value)
    return cast(JSONValue, value)


# The rules of the members the harness reads: a manifest that breaks one cannot be run.
HARNESS_RULES: Final = frozenset(
    {
        manifest.RULE_SHAPE,
        manifest.RULE_ID,
        manifest.RULE_ID_DUPLICATE,
        manifest.RULE_KIND,
        manifest.RULE_SCOPE,
        manifest.RULE_CAPABILITIES,
    }
)


def load_manifest(path: Path) -> list[Entry]:
    """Read the manifest through runner.manifest and check what the harness relies on:
    the members it reads, and a known group for every entry it runs."""
    try:
        data = path.read_bytes()
    except OSError as err:
        raise HarnessError(f"{path}: {err.strerror or err}") from err
    try:
        m = manifest.parse(data)
    except manifest.Problems as err:
        raise HarnessError(f"{path}:\n{err}") from err
    found = [str(p) for p in m.validate() if p.rule in HARNESS_RULES]
    if found:
        raise HarnessError(f"{path}:\n" + "\n".join(found))
    for e in m.entries:
        if runs(e) and (e.kind, prefix(e)) not in GROUPS:
            groups = ", ".join(p for k, p in GROUPS if k == e.kind)
            raise HarnessError(
                f"entry {e.id}: unknown prefix {prefix(e)!r} for kind {e.kind} of scope"
                f" {e.scope} (groups: {groups})"
            )
    return list(m.entries)


_SEGMENT = re.compile(r"[^/\\]+")


def local_path(p: str) -> bool:
    """Whether p is a slash-separated relative path with no empty, '.' or '..' segment."""
    segs = p.split("/")
    return bool(p) and all(_SEGMENT.fullmatch(s) and s not in (".", "..") for s in segs)


def read_fixture(root: Path, rel: str) -> bytes:
    """Read the fixture file rel of the fixture directory root."""
    if not local_path(rel):
        raise Fail(f"path {rel!r} is not inside the fixture directory")
    try:
        data = (root / rel).read_bytes()
    except OSError as e:
        raise Fail(f"{rel}: {e.strerror or e}") from e
    if len(data) > MAX_FIXTURE_BYTES:
        raise Fail(f"{rel}: larger than {MAX_FIXTURE_BYTES} bytes")
    return data


def read_json(root: Path, rel: str) -> Any:
    """Read and parse the fixture file rel."""
    try:
        return parse_json(read_fixture(root, rel))
    except (UnicodeDecodeError, ValueError) as e:
        raise Fail(f"{rel}: {e}") from e


def single_file(e: Entry) -> None:
    """Require that the entry names one JSON file holding its own expectations."""
    if not e.path.endswith(".json") or e.expected != e.path:
        raise Fail(f"path {e.path!r} and expected {e.expected!r} must name the same JSON file")


def obj(
    v: Any, where: str, required: Sequence[str], optional: Sequence[str] = ()
) -> dict[str, Any]:
    """Require a JSON object with every required member and no member outside both lists."""
    if not isinstance(v, dict):
        raise Fail(f"{where}: not an object")
    missing = [k for k in required if k not in v]
    unknown = sorted(set(v) - set(required) - set(optional))
    if missing or unknown:
        raise Fail(
            f"{where}: members {sorted(v)}, want {sorted(required)} (optional {sorted(optional)})"
        )
    return v


def array(v: Any, where: str) -> list[Any]:
    """Require a non-empty JSON array."""
    if not isinstance(v, list) or not v:
        raise Fail(f"{where}: not a non-empty array")
    return v


def string(v: Any, where: str, *, null: bool = False) -> str:
    """Require a string (or null when null is set, returned as '')."""
    if v is None and null:
        return ""
    if not isinstance(v, str):
        raise Fail(f"{where}: not a string")
    return v


_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def b64url(s: str, where: str) -> bytes:
    """Decode unpadded base64url."""
    if not _B64URL.fullmatch(s) or len(s) % 4 == 1:
        raise Fail(f"{where}: not unpadded base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
