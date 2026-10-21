"""The cross-references with spec/v1.0/spec-map.md. Mirrors go/runner/manifest/specmap.go."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from hop_top_pact.runner.manifest.entry import Manifest
from hop_top_pact.runner.manifest.problem import (
    RULE_FIXTURE_MISSING,
    RULE_GROUP_LANDED,
    RULE_GROUP_PARTIAL_COMPLETE,
    RULE_GROUP_PARTIAL_EMPTY,
    RULE_GROUP_PLANNED,
    RULE_GROUP_UNLISTED,
    RULE_ROW_UNKNOWN,
    RULE_SPEC_MAP,
    Problems,
    _Collector,
)
from hop_top_pact.runner.manifest.rules import FILE_ID_RE, NEUTRAL_EXTENSIONS, go_quote, matches

# Group statuses of the spec map's Fixture groups table.
STATUS_PLANNED: Final = "planned"
"""No fixture of the group is committed. The ids the map lists for it are reserved, and
the manifest has no entry under it."""
STATUS_PARTIAL: Final = "partial"
"""Some fixtures of the group are committed. A listed id whose fixture exists is
registered; the others stay reserved. Once every listed id exists, the group is landed."""
STATUS_LANDED: Final = "landed"
"""Every id the map lists for the group exists and is registered."""

_STATUSES: Final = (STATUS_PLANNED, STATUS_PARTIAL, STATUS_LANDED)

_FENCE: Final = re.compile(r" {0,3}(`{3,}|~{3,})")
_SEPARATOR: Final = re.compile(r":?-+:?")
# Go's strings.TrimSpace set: Unicode White_Space.
_SPACE: Final = "".join(
    map(chr, (*range(0x09, 0x0E), 0x20, 0x85, 0xA0, 0x1680, *range(0x2000, 0x200B)))
) + "".join(map(chr, (0x2028, 0x2029, 0x202F, 0x205F, 0x3000)))


@dataclass(frozen=True, slots=True)
class Row:
    """One row of the spec map's Conformance map table."""

    id: str
    fixtures: tuple[str, ...] = ()
    """The ids of the Fixture(s) cell, in order."""


@dataclass(frozen=True, slots=True)
class SpecMap:
    """What the checks read from spec/v1.0/spec-map.md."""

    rows: tuple[Row, ...] = ()
    groups: dict[str, str] = field(default_factory=dict)
    """A group of the Fixture groups table and its status."""


def parse_spec_map(text: bytes) -> tuple[SpecMap | None, Problems]:
    """Read the Conformance map and Fixture groups tables of a spec map, as
    scripts/check-spec-map.py does. A missing section, table or column gives a None
    SpecMap; a malformed row, a duplicate row id or group, and a status other than planned,
    partial or landed are reported beside a usable SpecMap. Every problem has
    RULE_SPEC_MAP."""
    ps = _Collector()
    data = text.removeprefix(b"\xef\xbb\xbf").decode("utf-8", errors="surrogateescape")
    sections = _split_sections(data.replace("\r\n", "\n").replace("\r", "\n"))

    groups: dict[str, str] = {}
    header, rows, err = _table(sections, "Fixture groups")
    if not err:
        group_col, e1 = _column(header, "Group", prefix=False)
        status_col, e2 = _column(header, "Status", prefix=False)
        err = e1 + e2
        for cells in rows if not err else []:
            if len(cells) != len(header):
                first = cells[0] if cells else ""
                ps.add(
                    RULE_SPEC_MAP,
                    "Fixture groups",
                    f"row {go_quote(first)} has {len(cells)} cells, the header has {len(header)}",
                )
                continue
            group = cells[group_col].strip("` ")
            status = cells[status_col].strip("` ")
            if group in groups:
                ps.add(RULE_SPEC_MAP, group, "duplicate group in the Fixture groups table")
            elif status not in _STATUSES:
                ps.add(
                    RULE_SPEC_MAP,
                    group,
                    f"status {go_quote(status)} is not one of {', '.join(_STATUSES)}",
                )
            else:
                groups[group] = status
    if err:
        ps.add(RULE_SPEC_MAP, "Fixture groups", err)
        return None, ps.done()

    out: list[Row] = []
    header, rows, err = _table(sections, "Conformance map")
    if not err:
        id_col, e1 = _column(header, "ID", prefix=False)
        fix_col, e2 = _column(header, "Fixture(s)", prefix=True)
        err = e1 + e2
        seen: set[str] = set()
        for cells in rows if not err else []:
            if len(cells) != len(header):
                first = cells[0] if cells else ""
                ps.add(
                    RULE_SPEC_MAP,
                    first,
                    f"row has {len(cells)} cells, the header has {len(header)}",
                )
                continue
            rid = cells[id_col].strip("` ")
            if rid in seen:
                ps.add(RULE_SPEC_MAP, rid, "duplicate row id")
            seen.add(rid)
            fixtures = tuple(f for f in (x.strip(" `") for x in cells[fix_col].split(",")) if f)
            out.append(Row(rid, fixtures))
    if err:
        ps.add(RULE_SPEC_MAP, "Conformance map", err)
        return None, ps.done()
    return SpecMap(tuple(out), groups), ps.done()


def check_spec_map(root: str | os.PathLike[str], m: Manifest, sm: SpecMap) -> Problems:
    """Check the cross-references between m and sm. root is the fixture directory, where
    fixture_exists looks for the fixture of a listed id that has no entry.

    - RULE_ROW_UNKNOWN: an entry's spec_map_row is not a row of sm;
    - RULE_GROUP_UNLISTED: an entry or a row names a group that the Fixture groups table
      does not list. The ids of such a group are not checked further;
    - RULE_FIXTURE_MISSING: a fixture id of a row is not a manifest id, and its group is
      landed or its fixture exists;
    - RULE_GROUP_PLANNED: a planned group has manifest entries;
    - RULE_GROUP_PARTIAL_EMPTY: a partial group has none;
    - RULE_GROUP_PARTIAL_COMPLETE: the fixture of every id the rows list for a partial
      group exists, registered or not;
    - RULE_GROUP_LANDED: a landed group has no manifest entries.
    """
    ps = _Collector()
    row_ids = {r.id for r in sm.rows}
    ids: set[str] = set()
    by_group: dict[str, list[str]] = {}
    uncited: dict[str, list[str]] = {}
    for e in m.entries:
        if not e.id:
            continue
        ids.add(e.id)
        by_group.setdefault(_group_of(e.id), []).append(e.id)
        if e.spec_map_row and e.spec_map_row not in row_ids:
            uncited.setdefault(e.spec_map_row, []).append(e.id)
    for row in sorted(uncited):
        ps.add(
            RULE_ROW_UNKNOWN, row, f"not a row of the spec map, but cited by {_list(uncited[row])}"
        )

    order: list[str] = []
    cited_by: dict[str, list[str]] = {}
    listed: dict[str, list[str]] = {}
    for r in sm.rows:
        for f in r.fixtures:
            if f not in cited_by:
                cited_by[f] = []
                order.append(f)
                listed.setdefault(_group_of(f), []).append(f)
            if r.id not in cited_by[f]:
                cited_by[f].append(r.id)

    unlisted = {g for g in (*by_group, *listed) if g not in sm.groups}
    for g in sorted(unlisted):
        names = list(by_group.get(g, []))
        names += [f for f in listed.get(g, []) if f not in names]
        ps.add(
            RULE_GROUP_UNLISTED,
            g,
            f"named by {_list(names)}, but the Fixture groups table has no row for it",
        )

    exists: dict[str, bool] = {}
    for f in order:
        status = sm.groups.get(_group_of(f))
        if status is None:
            continue
        exists[f] = f in ids or fixture_exists(root, f)
        if f in ids:
            continue
        if status == STATUS_LANDED:
            ps.add(
                RULE_FIXTURE_MISSING,
                f,
                f"named by {', '.join(cited_by[f])} but not in the manifest: group"
                f" {_group_of(f)} is landed, so every id it lists is registered",
            )
        elif exists[f]:
            ps.add(
                RULE_FIXTURE_MISSING,
                f,
                f"named by {', '.join(cited_by[f])} and present in the fixture directory,"
                " but not in the manifest: register it",
            )

    for g in sorted(sm.groups):
        found = by_group.get(g, [])
        status = sm.groups[g]
        if status == STATUS_PLANNED:
            if found:
                ps.add(
                    RULE_GROUP_PLANNED,
                    g,
                    f"marked planned, but the manifest has entries: {_list(found)};"
                    " mark it partial",
                )
        elif status == STATUS_PARTIAL:
            if not found:
                ps.add(
                    RULE_GROUP_PARTIAL_EMPTY,
                    g,
                    "marked partial, but the manifest has no entries under it; mark it planned",
                )
            elif all(exists.get(f, False) for f in listed.get(g, [])):
                ps.add(
                    RULE_GROUP_PARTIAL_COMPLETE,
                    g,
                    f"marked partial, but every id the spec map lists for it exists"
                    f" ({len(listed.get(g, []))}); mark it landed",
                )
        elif status == STATUS_LANDED and not found:
            ps.add(RULE_GROUP_LANDED, g, "marked landed, but the manifest has no entries under it")
    return ps.done()


def fixture_exists(root: str | os.PathLike[str], id: str) -> bool:
    """Whether the fixture of id is in the fixture directory root: root/<id> is a file or
    a directory, or root/<id> followed by a neutral extension (.json, .yaml, .md, .jws) is
    a file. A case directory such as admission/valid, a single-file case such as
    parse/appendix-c-wrong-version.jws and an adapter case such as
    adapters/_common/common-03.fragment.json all exist this way. An id that does not have
    the id form exists only through its manifest entry, which this function does not
    consult."""
    if not matches(FILE_ID_RE, id):
        return False
    full = os.fspath(Path(root, *id.split("/")))
    try:
        os.stat(full)
        return True
    except OSError:
        pass
    for x in NEUTRAL_EXTENSIONS:
        try:
            if stat.S_ISREG(os.stat(full + x).st_mode):
                return True
        except OSError:
            continue
    return False


def _group_of(id: str) -> str:
    return id.split("/", 1)[0]


def _list(ids: list[str]) -> str:
    """A list of ids, shortened for a message."""
    if len(ids) > 5:
        return ", ".join(ids[:5]) + ", ..."
    return ", ".join(ids)


def _trim_space(s: str) -> str:
    return s.strip(_SPACE)


def _split_sections(text: str) -> dict[str, list[str]]:
    """Each H2 title and the lines under it that are outside fenced code blocks. An H2
    inside a fence starts no section."""
    sections: dict[str, list[str]] = {}
    current = ""
    fence = ""
    for line in text.split("\n"):
        if mark := _FENCE.match(line):
            tick = mark.group(1)
            if not fence:
                fence = tick
            elif tick[0] == fence[0] and len(tick) >= len(fence):
                fence = ""
            continue
        if fence:
            continue
        if line.startswith("## "):
            current = _trim_space(line[3:])
            sections[current] = []
            continue
        if current:
            sections[current].append(line)
    return sections


def _table(sections: dict[str, list[str]], name: str) -> tuple[list[str], list[list[str]], str]:
    """The header and rows of the first pipe table of a section, or why there is none."""
    if name not in sections:
        return [], [], f"the spec map has no '{name}' section"
    header: list[str] | None = None
    rows: list[list[str]] = []
    for line in sections[name]:
        if not line.lstrip(" \t").startswith("|"):
            if header is not None:
                break
            continue
        cells = _split_row(line)
        if cells is None:
            return [], [], "malformed table line: " + line
        if header is None:
            header = cells
        elif not all(_SEPARATOR.fullmatch(c) for c in cells):
            rows.append(cells)
    if header is None:
        return [], [], f"the '{name}' section has no table"
    return header, rows, ""


def _split_row(line: str) -> list[str] | None:
    """A table line split on the pipes not escaped with a backslash; None unless it starts
    and ends with a pipe."""
    line = _trim_space(line)
    cells: list[str] = []
    cell: list[str] = []
    i = 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            cell.append("|")
            i += 1
        elif c == "|":
            cells.append("".join(cell))
            cell = []
        else:
            cell.append(c)
        i += 1
    cells.append("".join(cell))
    if len(cells) < 2 or _trim_space(cells[0]) or _trim_space(cells[-1]):
        return None
    return [_trim_space(c) for c in cells[1:-1]]


def _column(header: list[str], label: str, *, prefix: bool) -> tuple[int, str]:
    """The index of a header cell, compared after trimming backticks and spaces; with
    prefix, a cell that starts with label matches too."""
    for i, c in enumerate(header):
        c = c.strip("` ")
        if c == label or (prefix and c.startswith(label)):
            return i, ""
    return 0, f"the table has no {label} column"
