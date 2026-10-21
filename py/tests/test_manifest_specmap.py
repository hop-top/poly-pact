"""runner.manifest: the spec-map checks and check. Port of
go/runner/manifest/specmap_test.go."""

from __future__ import annotations

import re
from typing import Any

import pytest

from hop_top_pact.runner import manifest


def parse_spec_map(text: str) -> manifest.SpecMap:
    sm, ps = manifest.parse_spec_map(text.encode("utf-8"))
    assert not ps, str(ps)
    assert sm is not None
    return sm


def test_parse_spec_map(mk: Any) -> None:
    sm = parse_spec_map(mk.BASE_SPEC_MAP)
    assert [r.id for r in sm.rows] == ["CL-11.3", "CL-C", "CL-17.3.1"]
    assert sm.rows[2].fixtures == ("approval/pending", "parse/alg-none")
    assert sm.groups == {
        "admission": "partial",
        "approval": "planned",
        "parse": "planned",
        "adapters": "landed",
        "keys": "landed",
        "vectors": "landed",
    }


def test_parse_spec_map_line_endings_and_bom(mk: Any) -> None:
    """A byte order mark is dropped and CRLF or CR line ends read as LF."""
    for text in (
        "﻿" + mk.BASE_SPEC_MAP,
        mk.BASE_SPEC_MAP.replace("\n", "\r\n"),
        mk.BASE_SPEC_MAP.replace("\n", "\r"),
    ):
        sm = parse_spec_map(text)
        assert [r.id for r in sm.rows] == ["CL-11.3", "CL-C", "CL-17.3.1"]
        assert len(sm.groups) == 6


def replace(base: str, old: str, new: str) -> str:
    assert old in base, old
    return base.replace(old, new, 1)


SPEC_MAP_PROBLEMS: dict[str, tuple[str, str]] = {
    "no conformance map": ("## Conformance map", "## Conformance table"),
    "no fixture groups": ("## Fixture groups", "## Groups"),
    "no ID column": ("| ID | Check |", "| Row | Check |"),
    "no Fixture(s) column": ("| Finding | Fixture(s) |", "| Finding | Cases |"),
    "no Status column": ("| Covers | Status |", "| Covers | State |"),
    "bad status": ("| Positive control | partial |", "| Positive control | done |"),
    "status in upper case": ("| Positive control | partial |", "| Positive control | Partial |"),
    "duplicate group": ("| approval | `fixtures/approval/`", "| admission | `fixtures/approval/`"),
    "duplicate row": ("| CL-C | Test keys", "| CL-11.3 | Test keys"),
    "row with a cell short": (
        "| CL-C | Test keys | C | G13 | keys/holder |",
        "| CL-C | Test keys | C | keys/holder |",
    ),
    "row without end pipe": (
        "| CL-C | Test keys | C | G13 | keys/holder |",
        "| CL-C | Test keys | C | G13 | keys/holder",
    ),
}


@pytest.mark.parametrize(("old", "new"), SPEC_MAP_PROBLEMS.values(), ids=SPEC_MAP_PROBLEMS)
def test_parse_spec_map_problems(mk: Any, old: str, new: str) -> None:
    _, ps = manifest.parse_spec_map(replace(mk.BASE_SPEC_MAP, old, new).encode("utf-8"))
    mk.want_rule(ps, manifest.RULE_SPEC_MAP)


def test_parse_spec_map_problems_fenced_table_only(mk: Any) -> None:
    text = replace(mk.BASE_SPEC_MAP, "## Conformance map\n\n", "## Conformance map\n\n```\n")
    sm, ps = manifest.parse_spec_map((text + "```\n").encode("utf-8"))
    assert sm is None
    mk.want_rule(ps, manifest.RULE_SPEC_MAP)


def test_check_spec_map_accepts_base(mk: Any) -> None:
    tr = mk.new_tree()
    mk.want_clean(manifest.check_spec_map(tr.root, tr.manifest(), parse_spec_map(mk.BASE_SPEC_MAP)))


def test_check_spec_map_row_unknown(mk: Any) -> None:
    """Every spec_map_row is a row of the map."""
    es = mk.base_entries()
    es[3]["spec_map_row"] = "CL-7.4"
    tr = mk.new_tree(es)
    ps = manifest.check_spec_map(tr.root, tr.manifest(), parse_spec_map(mk.BASE_SPEC_MAP))
    mk.want_rule(ps, manifest.RULE_ROW_UNKNOWN, "CL-7.4")
    mk.must_contain(str(ps), "vectors/jcs/arrays")


def with_fixtures(base: str, fixtures: str) -> str:
    """base with the Fixture(s) cell of row CL-C replaced."""
    return replace(
        base,
        "| CL-C | Test keys | C | G13 | keys/holder |",
        "| CL-C | Test keys | C | G13 | " + fixtures + " |",
    )


def with_status(text: str, group: str, status: str) -> str:
    """text with the status of group in the Fixture groups table set."""
    rx = re.compile(r"(?m)^(\| " + re.escape(group) + r" \|.*\| )[a-z]+( \|)$")
    assert rx.search(text), group
    return rx.sub(lambda m: m.group(1) + status + m.group(2), text)


def without_group(text: str, group: str) -> str:
    """text without the row of group in the Fixture groups table."""
    rx = re.compile(r"(?m)^\| " + re.escape(group) + r" \|.*\n")
    assert rx.search(text), group
    return rx.sub("", text)


FIXTURE_IDS: dict[str, tuple[str, list[str], str]] = {
    "landed group, id absent": ("keys/holder, keys/issuer", [], "keys/issuer"),
    "landed group, id on disk": ("keys/holder, keys/issuer", ["keys/issuer/"], "keys/issuer"),
    "partial group, id absent": ("", [], ""),
    "partial group, case directory": (
        "",
        ["admission/wrong-tenant/README.md"],
        "admission/wrong-tenant",
    ),
    "partial group, empty case directory": (
        "",
        ["admission/wrong-tenant/"],
        "admission/wrong-tenant",
    ),
    "partial group, case file": ("", ["admission/wrong-tenant.jws"], "admission/wrong-tenant"),
    "partial group, json case file": (
        "",
        ["admission/wrong-tenant.json"],
        "admission/wrong-tenant",
    ),
    "partial group, other extension": ("", ["admission/wrong-tenant.txt"], ""),
    "partial group, longer name": ("", ["admission/wrong-tenant-2.json"], ""),
    "planned group, no directory": ("keys/holder, approval/expired", [], ""),
    "planned group, directory exists": (
        "keys/holder, approval/expired",
        ["approval/README.md"],
        "",
    ),
    "planned group, case directory": (
        "keys/holder, approval/expired",
        ["approval/expired/"],
        "approval/expired",
    ),
    "planned group, three-part id on disk": (
        "keys/holder, approval/expired/old",
        ["approval/expired/old.json"],
        "approval/expired/old",
    ),
    "planned group, id with dots on disk": (
        "keys/holder, approval/_x/c-01.a",
        ["approval/_x/c-01.a.json"],
        "approval/_x/c-01.a",
    ),
    "id that is not an id form": ("keys/holder, admission/../keys", [], ""),
    "backticked id": ("keys/holder, `admission/valid`", [], ""),
}


@pytest.mark.parametrize(("fixtures", "create", "want"), FIXTURE_IDS.values(), ids=FIXTURE_IDS)
def test_check_spec_map_fixture_ids(mk: Any, fixtures: str, create: list[str], want: str) -> None:
    """An id a row lists is registered when its group is landed, and in any group once its
    fixture exists. A fixture exists when the fixture directory has a file or directory at
    the id, or a file at the id plus a neutral extension. Other ids are reserved."""
    text = with_fixtures(mk.BASE_SPEC_MAP, fixtures) if fixtures else mk.BASE_SPEC_MAP
    tr = mk.new_tree()
    for f in create:
        if f.endswith("/"):
            tr.mkdir(f.removesuffix("/"))
        else:
            tr.write(f, "{}")
    ps = manifest.check_spec_map(tr.root, tr.manifest(), parse_spec_map(text))
    if not want:
        mk.want_clean(ps)
        return
    mk.want_where(ps, manifest.RULE_FIXTURE_MISSING, want)
    for p in ps:
        assert not (p.rule == manifest.RULE_FIXTURE_MISSING and p.where != want), str(p)


PARSE_ENTRY = {
    "id": "parse/alg-none",
    "kind": "evaluate",
    "scope": "runner",
    "path": "parse/alg-none.jws",
    "expected": "expected/parse/alg-none/decision.json",
    "outcome": "REJECTED",
    "spec_map_row": "CL-17.3.1",
    "draft_section": "7.2",
}
PARSE_FILES = ["parse/alg-none.jws", "expected/parse/alg-none/decision.json"]


def with_entry(es: list[dict[str, Any]], e: dict[str, Any]) -> list[dict[str, Any]]:
    for i, x in enumerate(es):
        if x["id"] > e["id"]:
            return [*es[:i], dict(e), *es[i:]]
    return [*es, dict(e)]


def group_status_cases(base: str) -> dict[str, tuple[bool, str, list[str], str, str]]:
    only_valid = replace(base, "admission/valid, admission/wrong-tenant |", "admission/valid |")
    no_parse_id = replace(base, "approval/pending, parse/alg-none |", "approval/pending |")
    no_approval_id = replace(base, "approval/pending, parse/alg-none |", "parse/alg-none |")
    return {
        "planned group with an entry": (
            True,
            base,
            PARSE_FILES,
            manifest.RULE_GROUP_PLANNED,
            "parse",
        ),
        "planned group, entry no row lists": (
            True,
            no_parse_id,
            PARSE_FILES,
            manifest.RULE_GROUP_PLANNED,
            "parse",
        ),
        "partial group, its only id registered": (
            True,
            with_status(base, "parse", "partial"),
            PARSE_FILES,
            manifest.RULE_GROUP_PARTIAL_COMPLETE,
            "parse",
        ),
        "partial group without entries": (
            False,
            with_status(base, "approval", "partial"),
            [],
            manifest.RULE_GROUP_PARTIAL_EMPTY,
            "approval",
        ),
        "partial group, every id registered": (
            False,
            only_valid,
            [],
            manifest.RULE_GROUP_PARTIAL_COMPLETE,
            "admission",
        ),
        "partial group, no listed id": (
            False,
            with_status(base, "adapters", "partial"),
            [],
            manifest.RULE_GROUP_PARTIAL_COMPLETE,
            "adapters",
        ),
        "landed group without entries": (
            False,
            with_status(no_approval_id, "approval", "landed"),
            [],
            manifest.RULE_GROUP_LANDED,
            "approval",
        ),
        "landed group, no listed id": (False, base, [], "", ""),
        "landed group, every id registered": (
            False,
            with_status(only_valid, "admission", "landed"),
            [],
            "",
            "",
        ),
        "partial group, one id reserved": (False, base, [], "", ""),
    }


@pytest.mark.parametrize(
    "name",
    [
        "planned group with an entry",
        "planned group, entry no row lists",
        "partial group, its only id registered",
        "partial group without entries",
        "partial group, every id registered",
        "partial group, no listed id",
        "landed group without entries",
        "landed group, no listed id",
        "landed group, every id registered",
        "partial group, one id reserved",
    ],
)
def test_check_spec_map_group_status(mk: Any, name: str) -> None:
    """The three statuses of the Fixture groups table. planned: no manifest entry under the
    group. partial: at least one entry, and not every listed id exists yet. landed: at least
    one entry (and every listed id registered)."""
    add_parse, text, create, rule, where = group_status_cases(mk.BASE_SPEC_MAP)[name]
    es = mk.base_entries()
    tr = mk.new_tree(with_entry(es, PARSE_ENTRY) if add_parse else es)
    for f in create:
        tr.write(f, "{}")
    ps = manifest.check_spec_map(tr.root, tr.manifest(), parse_spec_map(text))
    if not rule:
        mk.want_clean(ps)
        return
    mk.want_rule(ps, rule, where)


def test_check_spec_map_group_status_partial_group_last_id_on_disk(mk: Any) -> None:
    """Every listed id of a partial group exists, one only on disk: the group is complete,
    and the unregistered fixture is missing from the manifest."""
    tr = mk.new_tree()
    tr.write("admission/wrong-tenant/README.md", "# x")
    ps = manifest.check_spec_map(tr.root, tr.manifest(), parse_spec_map(mk.BASE_SPEC_MAP))
    want = sorted([manifest.RULE_FIXTURE_MISSING, manifest.RULE_GROUP_PARTIAL_COMPLETE])
    assert mk.rules(ps) == want, str(ps)
    mk.want_where(ps, manifest.RULE_GROUP_PARTIAL_COMPLETE, "admission")


GROUP_UNLISTED = {
    "row names a group without a status": ("fixtures", "schema"),
    "manifest names a group without a status": ("drop", "vectors"),
    "both name a group without a status": ("drop", "keys"),
    "a group named only by a reserved id": ("drop", "approval"),
}


@pytest.mark.parametrize(("how", "group"), GROUP_UNLISTED.values(), ids=GROUP_UNLISTED)
def test_check_spec_map_group_unlisted(mk: Any, how: str, group: str) -> None:
    """Every group that a manifest entry or a row names has a status."""
    base = mk.BASE_SPEC_MAP
    if how == "fixtures":
        text = with_fixtures(base, "keys/holder, schema/appendix-b-valid")
    else:
        text = without_group(base, group)
    tr = mk.new_tree()
    ps = manifest.check_spec_map(tr.root, tr.manifest(), parse_spec_map(text))
    mk.want_rule(ps, manifest.RULE_GROUP_UNLISTED, group)
    assert len(ps) == 1, str(ps)


def test_check_spec_map_group_unlisted_named_once(mk: Any) -> None:
    """An id both registered and listed is named once."""
    tr = mk.new_tree()
    text = without_group(mk.BASE_SPEC_MAP, "keys")
    ps = manifest.check_spec_map(tr.root, tr.manifest(), parse_spec_map(text))
    assert str(ps).count("keys/holder") == 1, str(ps)


def test_check_spec_map_group_unlisted_listed_group_nothing_names(mk: Any) -> None:
    text = replace(
        mk.BASE_SPEC_MAP,
        "| vectors |",
        "| capacity | `fixtures/capacity/` | Limits | planned |\n| vectors |",
    )
    tr = mk.new_tree()
    mk.want_clean(manifest.check_spec_map(tr.root, tr.manifest(), parse_spec_map(text)))


def test_check(mk: Any) -> None:
    """Every rule over a tree on disk, as pactfix check manifest does."""
    tr = mk.new_tree()
    mk.want_clean(manifest.check(tr.root, tr.spec_map))

    tr.write("keys/issuer.jwk.json", "{}")
    tr.set_spec_map(
        replace(
            mk.BASE_SPEC_MAP,
            "| CL-C | Test keys | C | G13 | keys/holder |",
            "| CL-D | Test keys | C | G13 | keys/holder, keys/issuer |",
        )
    )
    got = mk.rules(manifest.check(tr.root, tr.spec_map))
    want = sorted(
        [manifest.RULE_UNCOVERED, manifest.RULE_FIXTURE_MISSING, manifest.RULE_ROW_UNKNOWN]
    )
    assert got == want

    tr.write("manifest.json", '{"manifest_version":1,"entries":[],"entries":[]}')
    mk.want_rule(manifest.check(tr.root, tr.spec_map), manifest.RULE_JSON, "manifest.json")

    tr.remove("manifest.json")
    mk.want_rule(manifest.check(tr.root, tr.spec_map), manifest.RULE_JSON, "manifest.json")

    tr.write("manifest.json", mk.encode(mk.base_entries()).decode("utf-8"))
    tr.remove("keys/issuer.jwk.json")
    tr.spec_map.unlink()
    mk.want_rule(manifest.check(tr.root, tr.spec_map), manifest.RULE_SPEC_MAP)
