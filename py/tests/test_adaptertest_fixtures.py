"""The shipped common case files (port of
go/adapter/adaptertest/fixtures_test.go): they load, are registered in the
manifest, cite headings of the draft and keep the format language-neutral.
They fail when spec/ is absent under PACT_REQUIRE_VECTORS=1 (make py-test)
and skip otherwise."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from hop_top_pact.adapter.adaptertest.casefile import COMMON_DIR, accepted
from hop_top_pact.core import strictjson

REQUIRED_GROUPS = (
    "COMMON-01", "COMMON-02", "COMMON-03", "COMMON-04", "COMMON-05",
    "COMMON-06", "COMMON-07", "COMMON-08", "COMMON-09", "COMMON-10",
    "COMMON-11", "COMMON-12",
    "IDENT-01", "IDENT-02", "IDENT-03", "IDENT-04", "IDENT-05",
    "IDENT-06", "IDENT-07", "IDENT-08", "IDENT-09", "IDENT-10",
    "FRESH-01", "FRESH-02", "FRESH-03", "FRESH-04", "FRESH-05", "FRESH-06",
)  # fmt: skip
"""The common case groups of the suite, by id."""


def group_of(case_id: str) -> str:
    return case_id.split(".", 1)[0]


def test_common_case_files(at: Any) -> None:
    """Each shipped common case loads under the strict format, its file name is its
    lowercase id, and every group is present with at least one case."""
    root = at.repo_fixtures()
    cases = at.common_cases()
    files = sorted((root / COMMON_DIR).iterdir())
    for f in files:
        assert f.name.endswith(".json"), f"{COMMON_DIR}/{f.name} is not a case file"
    assert len(files) == len(cases), f"{len(files)} case files, {len(cases)} cases"
    groups: dict[str, int] = {}
    for c in cases:
        groups[group_of(c.id)] = groups.get(group_of(c.id), 0) + 1
        assert (root / COMMON_DIR / (c.id.lower() + ".json")).is_file(), (
            f"case {c.id} is not in a file named after its lowercase id"
        )
        assert c.draft, f"case {c.id} cites no draft section"
    for g in REQUIRED_GROUPS:
        assert groups.get(g), f"no case of group {g}"


def read_manifest(at: Any) -> Mapping[str, Any]:
    data = (at.repo_fixtures() / "manifest.json").read_bytes()
    m = strictjson.parse(data, strictjson.Limits(max_bytes=4 << 20, max_depth=8))
    assert isinstance(m, Mapping)
    return m


def manifest_outcome(outcome: str) -> str:
    """ACCEPTED when the case expects the adapter to let the stimulus through,
    REJECTED when it expects a refusal or a withheld result."""
    return "ACCEPTED" if accepted(outcome) else "REJECTED"


def test_case_files_are_registered(at: Any) -> None:
    """manifest.json lists every common case file, as an adapter-case entry that
    cites the group of the case, and lists no other."""
    cases = at.common_cases()
    m = read_manifest(at)
    assert m["manifest_version"] == 1
    ids = [e["id"] for e in m["entries"]]
    assert ids == sorted(ids), "manifest entries are not sorted by id"
    by_path = {
        e["path"]: e
        for e in m["entries"]
        if e["kind"] == "adapter-case" and e["path"].startswith(COMMON_DIR + "/")
    }
    for c in cases:
        file = f"{COMMON_DIR}/{c.id.lower()}.json"
        e = by_path.pop(file, None)
        assert e is not None, f"manifest.json does not list {file}"
        want = {
            "id": file.removesuffix(".json"),
            "kind": "adapter-case",
            "scope": "adapter",
            "path": file,
            "expected": file,
            "outcome": manifest_outcome(c.expect.outcome),
            "spec_map_row": group_of(c.id),
            "draft_section": e.get("draft_section"),
        }
        assert dict(e) == want, f"manifest entry of {c.id}"
        assert e["draft_section"] in c.draft, (
            f"manifest entry of {c.id} cites draft section {e['draft_section']!r},"
            " which the case does not"
        )
    assert not by_path, f"manifest.json lists {sorted(by_path)}, which are not case files"


def test_workload_modes_of_the_common_cases(at: Any) -> None:
    """IDENT-09 applies only to an adapter whose profile supports workloads shared by
    several agents, IDENT-10 only to one whose profile does not (draft 17.1,
    identity mapping IM-19); every other common case applies to both."""
    want = {"IDENT-09": "shared", "IDENT-10": "dedicated"}
    for c in at.common_cases():
        assert c.workloads == want.get(group_of(c.id), ""), f"case {c.id}"


def read_draft_headings(at: Any) -> set[str]:
    """The section numbers of the headings of the draft: "17.1" for "### 17.1
    Required adapter capabilities", and "19" for "## 19. ..."."""
    root = at.repo_fixtures()
    out: set[str] = set()
    for line in (root.parent / "draft.md").read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            continue
        fields = line.lstrip("#").split()
        if fields:
            out.add(fields[0].removesuffix("."))
    return out


def test_case_files_cite_the_draft(at: Any) -> None:
    """The draft section numbers of a case exist in spec/v1.0/draft.md as headings, so a
    renumbering of the draft cannot leave a case citing nothing."""
    draft = read_draft_headings(at)
    for c in at.common_cases():
        for s in c.draft:
            assert s in draft, f"case {c.id} cites draft section {s!r}, not a heading of the draft"


def test_case_files_are_json(at: Any) -> None:
    """The case files are valid JSON documents for any reader, not only for the
    strict decoder, and end with a newline."""
    for f in sorted((at.repo_fixtures() / COMMON_DIR).iterdir()):
        data = f.read_text(encoding="utf-8")
        json.loads(data)
        assert data.endswith("}\n"), f"{f.name} does not end with a newline"


def test_malformed_request_cases_pin_the_code(at: Any) -> None:
    """The common cases that show a request the baseline HTTP mapping forbids (draft
    10.2) expect map_operation to fail with INVALID_MESSAGE (draft 13.4). The case
    files name the code string and no identifier of an implementation."""
    root = at.repo_fixtures()
    by_id = {c.id: c for c in at.common_cases()}
    for cid in ("COMMON-03.fragment", "COMMON-03.userinfo", "COMMON-03.content-encoding"):
        c = by_id.get(cid)
        assert c is not None, f"no case {cid}"
        assert (c.expect.function, c.expect.outcome) == ("map_operation", "error"), cid
        assert c.expect.reason_code == "INVALID_MESSAGE", cid
        data = (root / COMMON_DIR / (cid.lower() + ".json")).read_text(encoding="utf-8")
        for name in ("adapter.", "ErrInvalidMessage", "InvalidMessage("):
            assert name not in data, f"{cid} names {name}; case files are language-neutral"


GROUP_ROW = re.compile(r"^\| `([A-Z][A-Z0-9]*-[0-9]{2,})` \|.*\| ([^|]+) \|$")


def test_readme_group_table_cites_the_cases(at: Any) -> None:
    """The Draft column of each group row of the common case table in
    adapters/README.md lists exactly the draft sections the cases of that group
    cite, and every group has a row."""
    cited: dict[str, set[str]] = {}
    for c in at.common_cases():
        cited.setdefault(group_of(c.id), set()).update(c.draft)
    readme = (at.repo_fixtures() / "adapters" / "README.md").read_text(encoding="utf-8")
    rows: set[str] = set()
    for line in readme.split("\n"):
        m = GROUP_ROW.match(line)
        if m is None:
            continue
        group = m.group(1)
        rows.add(group)
        listed = {s.strip() for s in m.group(2).split(",")}
        assert listed == cited.get(group, set()), (
            f"README row {group} lists draft {sorted(listed)}, its cases cite"
            f" {sorted(cited.get(group, set()))}"
        )
    for group in cited:
        assert group in rows, f"group {group} has no row in the common case table"
