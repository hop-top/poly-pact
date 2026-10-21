#!/usr/bin/env python3
"""Check spec/v1.0/spec-map.md against spec/v1.0/draft.md and spec/v1.0/fixtures/manifest.json.

While spec/v1.0/spec-map.md is absent the check prints a NOTICE and passes. Once
it exists, every item below must hold.

1. Draft pin. The first sha256 digest in the map's "Draft pin" section equals
   the sha256 of spec/v1.0/draft.md with the version number of each line that
   release-please rewrites replaced by X, so a release that only bumps the
   version keeps the pin. A stale pin means the refresh procedure in the map
   has not been run for the current draft. `--pin` prints the digest.
2. Row shape. The "Conformance map" table has the columns ID, Draft section
   and Fixture(s); row ids are unique; every row has the same number of cells
   as the header.
3. Draft sections. Every section cited in a Draft section cell resolves to a
   heading of spec/v1.0/draft.md. A cell is a list of section ids, a range such as
   `B.1 to B.12`, optional `step N` or `inv. N` qualifiers (not checked), and
   `;`-separated notes about the pinned draft:
   - `X is not a heading in the pinned draft` is a claim about the current
     draft too, so X must not resolve to a heading;
   - a note naming a backticked identifier and saying it is `not in the
     pinned draft` requires that identifier to be absent from the draft;
   - any other note of that kind is prose a script cannot test: it is printed
     as a NOTE and does not fail the check.
   Any other text in a cell fails the check, so a change in wording cannot
   switch the check off.
4. Fixture groups. The "Fixture groups" table gives each group, the first
   path segment of a fixture id, a Status: `planned`, `partial` or `landed`.
   A listed id is an id in a Fixture(s) cell; it is registered when it is the
   id of an entry of spec/v1.0/fixtures/manifest.json, and it exists when it is
   registered or when spec/v1.0/fixtures/<id> is a file or a directory, or
   spec/v1.0/fixtures/<id> followed by .json, .yaml, .md or .jws is a file (an id
   that does not have the manifest id form exists only by registration). The
   checks, the same as those of pactfix check manifest:
   - every group that a manifest entry or a listed id names has a row in the
     table (the ids of a group without one are not checked further);
   - a listed id that exists is registered, whatever its group's status;
   - `planned`: the manifest has no entry under the group; its listed ids
     are reserved;
   - `partial`: the manifest has at least one entry under the group, and at
     least one listed id of the group does not exist yet (it stays reserved);
     once every listed id exists the group is to be marked `landed`;
   - `landed`: every listed id of the group is registered, and the manifest
     has at least one entry under it.
   An absent manifest counts as one with no entries.
5. Cross-reference. Every `spec_map_row` of a manifest entry is the id of a
   row of the map.

Run it isolated, standard library only (Python 3.9 and later):

    python3 -I scripts/check-spec-map.py

Exit status: 0 clean or map absent; 1 problems listed on stderr; 2 cannot run.
"""

import hashlib
import importlib.util
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
MAP = "spec/v1.0/spec-map.md"
DRAFT = "spec/v1.0/draft.md"
FIXTURES = "spec/v1.0/fixtures"
MANIFEST = FIXTURES + "/manifest.json"
STATUSES = ("planned", "partial", "landed")
# The manifest id form and the neutral extensions, as in spec/v1.0/fixtures/README.md
# and go/runner/manifest.
_ID = re.compile(
    r"_?[a-z0-9]+(?:[-.][a-z0-9]+)*/_?[a-z0-9]+(?:[-.][a-z0-9]+)*(?:/_?[a-z0-9]+(?:[-.][a-z0-9]+)*)?"
)
NEUTRAL_EXTENSIONS = (".json", ".yaml", ".md", ".jws")


class CheckError(Exception):
    """The check cannot run; reported with exit status 2."""


def _load_sibling(name):
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True  # keep scripts/ free of __pycache__
    spec.loader.exec_module(module)
    return module


specjson = _load_sibling("specjson")

_FENCE = re.compile(r"^[ ]{0,3}(`{3,}|~{3,})")
_HEADING = re.compile(r"^#{1,6}[ \t]+(.+?)[ \t#]*$")
_NUMBERED = re.compile(r"^(\d+(?:\.\d+)*)\.?(?:\s|$)")
_APPENDIX = re.compile(r"^Appendix\s+([A-Z])(?:\W|$)")
_LETTERED = re.compile(r"^([A-Z](?:\.\d+)+)(?:\s|$)")
_DIGEST = re.compile(r"\b[0-9a-f]{64}\b")

_SECTION = r"(?:[A-Z]|\d+)(?:\.\d+)*"
_QUALIFIER = re.compile(r"\s+(?:step|inv\.)\s+\d+")
_REFS = re.compile(r"%s(?:\s*(?:,|\band\b|\bto\b)\s*%s)*" % (_SECTION, _SECTION))
_NOT_HEADING = re.compile(
    r"^(?:Section\s+)?(%s)\s+is not a heading in the pinned draft$" % _SECTION
)
_NOT_PRESENT = re.compile(r"\b(?:is|are) not in the pinned draft\b|\babsent from the pinned draft\b")
_BACKTICKED = re.compile(r"`([^`]+)`")


# Built in two parts: the version guard flags any line holding the whole marker.
_MARKER = b"x-release-please-" + b"version"
_VERSION = re.compile(rb"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?")


def pin_digest(draft_bytes):
    """sha256 of the draft with the release-managed version numbers masked."""
    lines = draft_bytes.split(b"\n")
    for i, line in enumerate(lines):
        if _MARKER in line:
            lines[i] = _VERSION.sub(b"X", line, count=1)
    return hashlib.sha256(b"\n".join(lines)).hexdigest()


def read_text(relative):
    path = os.path.join(ROOT, relative)
    try:
        with open(path, encoding="utf-8-sig") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise CheckError("%s: cannot read as UTF-8: %s" % (relative, exc))


def draft_headings(text):
    """Map a section id (`2.1`, `A`, `B.7`) to its heading text."""
    headings = {}
    fence = None
    for line in text.split("\n"):
        marker = _FENCE.match(line)
        if marker:
            if fence is None:
                fence = marker.group(1)
            elif marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        heading = _HEADING.match(line)
        if not heading:
            continue
        title = heading.group(1)
        for pattern in (_NUMBERED, _APPENDIX, _LETTERED):
            found = pattern.match(title)
            if found:
                headings.setdefault(found.group(1), title)
                break
    return headings


def split_sections(text):
    """Map an H2 title to the lines under it."""
    sections = {}
    current = None
    fence = None
    for line in text.split("\n"):
        marker = _FENCE.match(line)
        if marker:
            if fence is None:
                fence = marker.group(1)
            elif marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence):
                fence = None
        elif fence is None and line.startswith("## "):
            current = line[3:].strip()
            sections[current] = []
            continue
        if current is not None:
            sections[current].append(line)
    return sections


def split_row(line):
    cells = re.split(r"(?<!\\)\|", line.strip())
    if len(cells) < 2 or cells[0].strip() or cells[-1].strip():
        return None
    return [cell.replace("\\|", "|").strip() for cell in cells[1:-1]]


def parse_table(lines):
    """Return (header, rows) for the first pipe table in lines."""
    header = None
    rows = []
    for line in lines:
        if not line.lstrip().startswith("|"):
            if header is not None:
                break
            continue
        cells = split_row(line)
        if cells is None:
            raise CheckError("malformed table line: %s" % line[:80])
        if header is None:
            header = cells
        elif all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            continue
        else:
            rows.append(cells)
    return header, rows


def expand_range(start, end):
    """B.1 to B.12 names B.1 ... B.12 when both ends share a prefix."""
    first = re.fullmatch(r"(.*\.)(\d+)", start)
    last = re.fullmatch(r"(.*\.)(\d+)", end)
    if first and last and first.group(1) == last.group(1):
        low, high = int(first.group(2)), int(last.group(2))
        if low <= high and high - low < 1000:
            return [first.group(1) + str(n) for n in range(low, high + 1)]
    return [start, end]


def section_ids(clause):
    """Section ids named by a clause that is only a list of them, or None."""
    clause = _QUALIFIER.sub("", clause).strip()
    if not _REFS.fullmatch(clause):
        return None
    ids = []
    pieces = re.split(r"\s*(,|\band\b|\bto\b)\s*", clause)
    index = 0
    while index < len(pieces):
        item = pieces[index]
        if index + 2 < len(pieces) and pieces[index + 1] == "to":
            ids += expand_range(item, pieces[index + 2])
            index += 4
        else:
            ids.append(item)
            index += 2
    return ids


def check_draft_cell(row_id, cell, headings, draft_text, problems, notes):
    """Check one Draft section cell; return the number of sections it cites."""
    cited = 0
    if not cell:
        problems.append("%s: the Draft section cell is empty" % row_id)
        return cited
    for clause in (part.strip() for part in cell.split(";")):
        if not clause:
            continue
        if clause.startswith("current text:"):
            clause = clause[len("current text:"):].strip()
        negative = _NOT_HEADING.match(clause)
        if negative:
            section = negative.group(1)
            if section in headings:
                problems.append(
                    "%s: says %s is not a heading in the pinned draft, but the draft has "
                    "the heading %r" % (row_id, section, headings[section])
                )
            continue
        if _NOT_PRESENT.search(clause):
            names = _BACKTICKED.findall(clause)
            if not names:
                notes.append("%s: not machine-checkable: %r" % (row_id, clause))
            for name in names:
                if name in draft_text:
                    problems.append(
                        "%s: says `%s` is not in the pinned draft, but the draft contains it"
                        % (row_id, name)
                    )
            continue
        ids = section_ids(clause)
        if ids is None:
            problems.append("%s: cannot read the Draft section text %r" % (row_id, clause))
            continue
        for section in ids:
            cited += 1
            if section not in headings:
                problems.append(
                    "%s: cited section %s is not a heading of %s" % (row_id, section, DRAFT)
                )
    return cited


def column(header, label, startswith=False):
    for index, cell in enumerate(header):
        text = cell.strip("` ")
        if text == label or (startswith and text.startswith(label)):
            return index
    raise CheckError("the Conformance map table has no %r column" % label)


def group_of(fixture_id):
    return fixture_id.split("/")[0]


def fixture_exists(fixture_id):
    """Whether spec/v1.0/fixtures holds the fixture of an id, registered or not."""
    if not _ID.fullmatch(fixture_id):
        return False
    full = os.path.join(ROOT, FIXTURES, *fixture_id.split("/"))
    if os.path.exists(full):
        return True
    return any(os.path.isfile(full + ext) for ext in NEUTRAL_EXTENSIONS)


def shorten(ids):
    return ", ".join(ids[:5]) + (", ..." if len(ids) > 5 else "")


def parse_groups(lines, problems):
    """Map each group of the Fixture groups table to its status."""
    header, rows = parse_table(lines)
    if header is None:
        raise CheckError("the Fixture groups section has no table")
    group_col = column(header, "Group")
    status_col = column(header, "Status")
    groups = {}
    for cells in rows:
        if len(cells) != len(header):
            problems.append("Fixture groups row %r has the wrong number of cells" % cells[0][:40])
            continue
        group = cells[group_col].strip("` ")
        status = cells[status_col].strip("` ")
        if group in groups:
            problems.append("Fixture groups: duplicate group %s" % group)
        elif status not in STATUSES:
            problems.append(
                "Fixture groups: group %s has status %r, not one of %s"
                % (group, status, ", ".join(STATUSES))
            )
        else:
            groups[group] = status
    return groups


def run():
    map_path = os.path.join(ROOT, MAP)
    if not os.path.exists(map_path):
        print("NOTICE: check-spec-map: %s absent; nothing to check" % MAP, file=sys.stderr)
        return 0
    map_text = read_text(MAP)
    try:
        with open(os.path.join(ROOT, DRAFT), "rb") as handle:
            draft_bytes = handle.read()
    except OSError as exc:
        raise CheckError("%s: %s" % (DRAFT, exc))
    draft_text = draft_bytes.decode("utf-8", errors="replace")
    headings = draft_headings(draft_text)
    if not headings:
        raise CheckError("no numbered headings found in %s" % DRAFT)
    sections = split_sections(map_text)

    pin_problems = []
    table_problems = []
    section_problems = []
    fixture_problems = []
    group_problems = []
    xref_problems = []
    notes = []

    # 1. Draft pin.
    digest = pin_digest(draft_bytes)
    pin = _DIGEST.search("\n".join(sections.get("Draft pin", [])))
    if not pin:
        pin_problems.append("the Draft pin section of the map holds no sha256 digest")
    elif pin.group(0) != digest:
        pin_problems.append(
            "pinned %s, but sha256(%s) is %s; run the refresh procedure of the map"
            % (pin.group(0), DRAFT, digest)
        )

    # 2. Table.
    if "Conformance map" not in sections:
        raise CheckError("the map has no 'Conformance map' section")
    header, rows = parse_table(sections["Conformance map"])
    if header is None:
        raise CheckError("the Conformance map section has no table")
    id_col = column(header, "ID")
    section_col = column(header, "Draft section", startswith=True)
    fixture_col = column(header, "Fixture(s)", startswith=True)

    if "Fixture groups" not in sections:
        raise CheckError("the map has no 'Fixture groups' section")
    status = parse_groups(sections["Fixture groups"], table_problems)

    manifest = None
    manifest_ids = set()
    manifest_path = os.path.join(ROOT, MANIFEST)
    if os.path.exists(manifest_path):
        try:
            manifest = specjson.load(manifest_path)
        except specjson.StrictJSONError as exc:
            raise CheckError("%s: %s" % (MANIFEST, exc))
        entries = manifest.get("entries") if isinstance(manifest, dict) else None
        if not isinstance(entries, list) or not all(
            isinstance(e, dict) and isinstance(e.get("id"), str) for e in entries
        ):
            raise CheckError("%s: entries must be an array of objects with an id" % MANIFEST)
        manifest_ids = set(e["id"] for e in entries)
    else:
        notes.append("%s is absent; treated as a manifest with no entries" % MANIFEST)

    row_ids = []
    listed = []
    cited_by = {}
    cited = 0
    fixture_refs = 0
    for cells in rows:
        if len(cells) != len(header):
            table_problems.append(
                "row %r has %d cells, the header has %d" % (cells[0][:40], len(cells), len(header))
            )
            continue
        row_id = cells[id_col].strip("` ")
        if row_id in row_ids:
            table_problems.append("%s: duplicate row id" % row_id)
        row_ids.append(row_id)

        # 3. Draft sections.
        cited += check_draft_cell(
            row_id, cells[section_col], headings, draft_text, section_problems, notes
        )

        # 4. Fixture ids, gathered for the group checks below.
        for fixture in (part.strip(" `") for part in cells[fixture_col].split(",")):
            if not fixture:
                continue
            fixture_refs += 1
            if fixture not in cited_by:
                listed.append(fixture)
                cited_by[fixture] = []
            if row_id not in cited_by[fixture]:
                cited_by[fixture].append(row_id)

    # 4. Fixture groups against the manifest and the fixture directory.
    entries_by_group = {}
    for entry_id in sorted(manifest_ids):
        entries_by_group.setdefault(group_of(entry_id), []).append(entry_id)
    listed_by_group = {}
    for fixture in listed:
        listed_by_group.setdefault(group_of(fixture), []).append(fixture)
    for group in sorted((set(entries_by_group) | set(listed_by_group)) - set(status)):
        names = list(entries_by_group.get(group, []))
        names += [f for f in listed_by_group.get(group, []) if f not in names]
        group_problems.append(
            "group %s is named by %s, but the Fixture groups table has no row for it"
            % (group, shorten(names))
        )
    exists = {}
    for fixture in listed:
        group = group_of(fixture)
        if group not in status:
            continue
        registered = fixture in manifest_ids
        exists[fixture] = registered or fixture_exists(fixture)
        if registered:
            continue
        if status[group] == "landed":
            fixture_problems.append(
                "%s (named by %s): not in the manifest, but group %s is landed, so every id "
                "it lists is registered" % (fixture, ", ".join(cited_by[fixture]), group)
            )
        elif exists[fixture]:
            fixture_problems.append(
                "%s (named by %s): present in %s but not in the manifest; register it"
                % (fixture, ", ".join(cited_by[fixture]), FIXTURES)
            )
    for group in sorted(status):
        found = entries_by_group.get(group, [])
        if status[group] == "planned" and found:
            group_problems.append(
                "group %s is marked planned but the manifest has entries: %s; mark it partial"
                % (group, shorten(found))
            )
        elif status[group] == "partial" and not found:
            group_problems.append(
                "group %s is marked partial but the manifest has no entries under it; "
                "mark it planned" % group
            )
        elif status[group] == "partial" and all(
            exists[fixture] for fixture in listed_by_group.get(group, [])
        ):
            group_problems.append(
                "group %s is marked partial but every id the map lists for it exists (%d); "
                "mark it landed" % (group, len(listed_by_group.get(group, [])))
            )
        elif status[group] == "landed" and not found:
            group_problems.append(
                "group %s is marked landed but the manifest has no entries under it" % group
            )

    # 5. Every manifest entry cites a row of the map.
    if manifest is not None:
        uncited = {}
        for entry in manifest["entries"]:
            row = entry.get("spec_map_row")
            if row not in row_ids:
                uncited.setdefault(str(row), []).append(entry["id"])
        for row, ids in sorted(uncited.items()):
            xref_problems.append(
                "manifest entries cite row %s, which is not a row of the map: %s"
                % (row, ", ".join(ids))
            )

    for note in notes:
        print("NOTE %s" % note, file=sys.stderr)
    groups = (
        ("draft pin", pin_problems),
        ("map table", table_problems),
        ("draft sections", section_problems),
        ("fixture ids", fixture_problems),
        ("fixture groups", group_problems),
        ("manifest cross-reference", xref_problems),
    )
    total = sum(len(found) for _name, found in groups)
    if total:
        print(
            "check-spec-map: %d problem(s) (%s)"
            % (total, ", ".join("%s %d" % (name, len(found)) for name, found in groups if found)),
            file=sys.stderr,
        )
        for name, found in groups:
            for message in found:
                print("  [%s] %s" % (name, message), file=sys.stderr)
        return 1
    print(
        "check-spec-map: ok (%d rows, %d draft sections, %d fixture ids, pin %s)"
        % (len(row_ids), cited, fixture_refs, digest[:8])
    )
    return 0


def main():
    if sys.argv[1:] == ["--pin"]:
        with open(os.path.join(ROOT, DRAFT), "rb") as handle:
            print(pin_digest(handle.read()))
        return 0
    try:
        return run()
    except CheckError as exc:
        print("check-spec-map: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
