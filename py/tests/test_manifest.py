"""runner.manifest: parse and the field rules. Port of go/runner/manifest/manifest_test.go."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from hop_top_pact.core.strictjson import StrictJSONError, StrictJSONErrorKind
from hop_top_pact.errors import PactError
from hop_top_pact.runner import manifest

Entries = list[dict[str, Any]]
Edit = Callable[[Entries], Entries]

EV = 1  # the evaluate entry of the base entries
KEY = 2  # the key entry


def test_parse_accepts_base(mk: Any) -> None:
    m = mk.parse(mk.encode(mk.base_entries()))
    mk.want_clean(m.validate())
    assert m.version == 1
    assert len(m.entries) == 4
    e = m.entries[1]
    assert e.id == "admission/valid"
    assert e.kind == manifest.Kind.EVALUATE
    assert e.scope == manifest.Scope.RUNNER
    assert e.path == "admission/valid"
    assert e.expected == "expected/admission/valid/decision.json"
    assert e.outcome == "ADMISSIBLE"
    assert e.spec_map_row == "CL-11.3"
    assert e.draft_section == "11.3"
    k = m.entries[2]
    assert k.expected is None
    assert k.outcome is None
    got = m.lookup("keys/holder")
    assert got is not None
    assert got.path == "keys/holder.jwk.json"
    assert m.lookup("keys/nobody") is None


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        pytest.param(
            b'{"manifest_version":1,"entries":[],"entries":[]}',
            StrictJSONErrorKind.DUPLICATE_KEY,
            id="duplicate member",
        ),
        pytest.param(
            b'{"manifest_version":1,"entries":[{"id":"a/b","id":"a/c"}]}',
            StrictJSONErrorKind.DUPLICATE_KEY,
            id="nested duplicate member",
        ),
        pytest.param(
            b'{"manifest_version":NaN,"entries":[]}',
            StrictJSONErrorKind.NON_FINITE,
            id="non-finite number",
        ),
        pytest.param(
            b'{"manifest_version":1,"entries":["\xff"]}',
            StrictJSONErrorKind.INVALID_UTF8,
            id="invalid UTF-8",
        ),
        pytest.param(
            b'{"manifest_version":1,"entries":["\\ud800"]}',
            StrictJSONErrorKind.LONE_SURROGATE,
            id="lone surrogate",
        ),
        pytest.param(
            b'\xef\xbb\xbf{"manifest_version":1,"entries":[]}',
            StrictJSONErrorKind.SYNTAX,
            id="byte order mark",
        ),
        pytest.param(
            b'{"manifest_version":1,"entries":[]} {}',
            StrictJSONErrorKind.TRAILING_DATA,
            id="trailing data",
        ),
        pytest.param(b"[]", None, id="not an object"),
    ],
)
def test_parse_is_strict(text: bytes, kind: StrictJSONErrorKind | None) -> None:
    """The manifest is read with the parse rules of draft Section 7.1, before any field rule."""
    with pytest.raises(manifest.Problems) as info:
        manifest.parse(text)
    ps = info.value
    assert issubclass(type(ps), PactError)
    assert len(ps) == 1
    assert ps[0].rule == manifest.RULE_JSON
    if kind is not None:
        assert isinstance(ps[0].err, StrictJSONError)
        assert ps[0].err.kind == kind
        assert ps.__cause__ is ps[0].err


def set_(i: int, k: str, v: Any) -> Edit:
    def edit(es: Entries) -> Entries:
        es[i][k] = v
        return es

    return edit


def drop(i: int, k: str) -> Edit:
    def edit(es: Entries) -> Entries:
        del es[i][k]
        return es

    return edit


def _underscore_unknown_kind(es: Entries) -> Entries:
    es[EV]["kind"] = "evaluation"
    es[EV]["id"] = "admission/_valid"
    return es


def _duplicate(es: Entries) -> Entries:
    return [*es[: KEY + 1], dict(es[KEY]), *es[KEY + 1 :]]


def _unsorted(es: Entries) -> Entries:
    es[0], es[1] = es[1], es[0]
    return es


VALIDATE_RULES: dict[str, tuple[str, str, Edit]] = {
    "missing id": (manifest.RULE_SHAPE, "entries[1]", drop(EV, "id")),
    "missing kind": (manifest.RULE_SHAPE, "admission/valid", drop(EV, "kind")),
    "missing scope": (manifest.RULE_SHAPE, "admission/valid", drop(EV, "scope")),
    "missing path": (manifest.RULE_SHAPE, "admission/valid", drop(EV, "path")),
    "missing expected": (manifest.RULE_SHAPE, "admission/valid", drop(EV, "expected")),
    "missing outcome": (manifest.RULE_SHAPE, "admission/valid", drop(EV, "outcome")),
    "missing spec_map_row": (manifest.RULE_SHAPE, "admission/valid", drop(EV, "spec_map_row")),
    "missing draft_section": (manifest.RULE_SHAPE, "admission/valid", drop(EV, "draft_section")),
    "unknown member": (manifest.RULE_SHAPE, "admission/valid", set_(EV, "note", "x")),
    "id not a string": (manifest.RULE_SHAPE, "entries[1]", set_(EV, "id", 7)),
    "kind not a string": (manifest.RULE_SHAPE, "admission/valid", set_(EV, "kind", True)),
    "path not a string": (manifest.RULE_SHAPE, "admission/valid", set_(EV, "path", ["a"])),
    "expected a number": (manifest.RULE_SHAPE, "admission/valid", set_(EV, "expected", 1)),
    "draft_section number": (
        manifest.RULE_SHAPE,
        "admission/valid",
        set_(EV, "draft_section", 11.3),
    ),
    "id one segment": (manifest.RULE_ID, "admission", set_(EV, "id", "admission")),
    "id four segments": (manifest.RULE_ID, "admission/b/c/d", set_(EV, "id", "admission/b/c/d")),
    "id upper case": (manifest.RULE_ID, "admission/Valid", set_(EV, "id", "admission/Valid")),
    "id underscore inside": (
        manifest.RULE_ID,
        "admission/va_lid",
        set_(EV, "id", "admission/va_lid"),
    ),
    "id trailing hyphen": (
        manifest.RULE_ID,
        "admission/valid-",
        set_(EV, "id", "admission/valid-"),
    ),
    "id empty segment": (manifest.RULE_ID, "admission//valid", set_(EV, "id", "admission//valid")),
    "id empty": (manifest.RULE_ID, "entries[1]", set_(EV, "id", "")),
    # Only adapter-case ids, which follow their file names, may start a
    # segment with "_" or have a "." in one.
    "id dot in a key": (manifest.RULE_ID, "keys/holder.v2", set_(KEY, "id", "keys/holder.v2")),
    "id leading underscore in a key": (
        manifest.RULE_ID,
        "keys/_holder",
        set_(KEY, "id", "keys/_holder"),
    ),
    "id leading underscore in a case": (
        manifest.RULE_ID,
        "admission/_valid",
        set_(EV, "id", "admission/_valid"),
    ),
    "id dot in an adapter asset": (
        manifest.RULE_ID,
        "adapters/db/schema.v2",
        set_(0, "id", "adapters/db/schema.v2"),
    ),
    "id underscore in an adapter asset": (
        manifest.RULE_ID,
        "adapters/_db/schema",
        set_(0, "id", "adapters/_db/schema"),
    ),
    # An unknown kind is reported once, by its own rule.
    "id underscore with an unknown kind": (
        manifest.RULE_KIND,
        "admission/_valid",
        _underscore_unknown_kind,
    ),
    "kind unknown": (manifest.RULE_KIND, "admission/valid", set_(EV, "kind", "evaluation")),
    "scope unknown": (manifest.RULE_SCOPE, "admission/valid", set_(EV, "scope", "sdk")),
    "path absolute": (manifest.RULE_PATH, "admission/valid", set_(EV, "path", "/admission/valid")),
    "path dot dot": (manifest.RULE_PATH, "admission/valid", set_(EV, "path", "admission/../keys")),
    "path dot": (manifest.RULE_PATH, "admission/valid", set_(EV, "path", "./admission/valid")),
    "path empty segment": (
        manifest.RULE_PATH,
        "admission/valid",
        set_(EV, "path", "admission//valid"),
    ),
    "path trailing slash": (
        manifest.RULE_PATH,
        "admission/valid",
        set_(EV, "path", "admission/valid/"),
    ),
    "path backslash": (manifest.RULE_PATH, "admission/valid", set_(EV, "path", "admission\\valid")),
    "path empty": (manifest.RULE_PATH, "admission/valid", set_(EV, "path", "")),
    "path hidden": (manifest.RULE_PATH, "admission/valid", set_(EV, "path", "admission/.valid")),
    "path space": (manifest.RULE_PATH, "admission/valid", set_(EV, "path", "admission/va lid")),
    "expected null for evaluate": (
        manifest.RULE_EXPECTED,
        "admission/valid",
        set_(EV, "expected", None),
    ),
    "expected set for key": (
        manifest.RULE_EXPECTED,
        "keys/holder",
        set_(KEY, "expected", "keys/holder.jwk.json"),
    ),
    "expected absolute": (
        manifest.RULE_EXPECTED,
        "admission/valid",
        set_(EV, "expected", "/expected/x.json"),
    ),
    "expected dot dot": (
        manifest.RULE_EXPECTED,
        "admission/valid",
        set_(EV, "expected", "../x.json"),
    ),
    "outcome null for evaluate": (
        manifest.RULE_OUTCOME,
        "admission/valid",
        set_(EV, "outcome", None),
    ),
    "outcome set for key": (manifest.RULE_OUTCOME, "keys/holder", set_(KEY, "outcome", "MATCH")),
    "outcome unknown token": (
        manifest.RULE_OUTCOME,
        "admission/valid",
        set_(EV, "outcome", "PASS"),
    ),
    "outcome lower case": (
        manifest.RULE_OUTCOME,
        "admission/valid",
        set_(EV, "outcome", "admissible"),
    ),
    "spec_map_row empty": (
        manifest.RULE_SPEC_MAP_ROW,
        "admission/valid",
        set_(EV, "spec_map_row", ""),
    ),
    "spec_map_row lower case": (
        manifest.RULE_SPEC_MAP_ROW,
        "admission/valid",
        set_(EV, "spec_map_row", "cl-11.3"),
    ),
    "draft_section trailing dot": (
        manifest.RULE_DRAFT_SECTION,
        "admission/valid",
        set_(EV, "draft_section", "11.3."),
    ),
    "draft_section lower letter": (
        manifest.RULE_DRAFT_SECTION,
        "admission/valid",
        set_(EV, "draft_section", "c"),
    ),
    "draft_section leading zero": (
        manifest.RULE_DRAFT_SECTION,
        "admission/valid",
        set_(EV, "draft_section", "011"),
    ),
    "draft_section empty": (
        manifest.RULE_DRAFT_SECTION,
        "admission/valid",
        set_(EV, "draft_section", ""),
    ),
    "draft_section with a prefix": (
        manifest.RULE_DRAFT_SECTION,
        "admission/valid",
        set_(EV, "draft_section", "Section 11.3"),
    ),
    "capabilities a string": (
        manifest.RULE_SHAPE,
        "admission/valid",
        set_(EV, "capabilities", "jws-ed25519"),
    ),
    "capabilities null": (manifest.RULE_SHAPE, "admission/valid", set_(EV, "capabilities", None)),
    "capability not a string": (
        manifest.RULE_SHAPE,
        "admission/valid",
        set_(EV, "capabilities", [1]),
    ),
    "capability null": (manifest.RULE_SHAPE, "admission/valid", set_(EV, "capabilities", [None])),
    "capabilities empty": (
        manifest.RULE_CAPABILITIES,
        "admission/valid",
        set_(EV, "capabilities", []),
    ),
    "capability unknown": (
        manifest.RULE_CAPABILITIES,
        "admission/valid",
        set_(EV, "capabilities", ["ed25519"]),
    ),
    "capability upper case": (
        manifest.RULE_CAPABILITIES,
        "admission/valid",
        set_(EV, "capabilities", ["JWS-ED25519"]),
    ),
    "capability repeated": (
        manifest.RULE_CAPABILITIES,
        "admission/valid",
        set_(EV, "capabilities", ["jws-ed25519", "jws-ed25519"]),
    ),
    "capability unknown on key": (
        manifest.RULE_CAPABILITIES,
        "keys/holder",
        set_(KEY, "capabilities", ["ES256"]),
    ),
    "duplicate id": (manifest.RULE_ID_DUPLICATE, "keys/holder", _duplicate),
    "unsorted": (manifest.RULE_ORDER, "adapters/db/schema", _unsorted),
}


@pytest.mark.parametrize(("rule", "where", "edit"), VALIDATE_RULES.values(), ids=VALIDATE_RULES)
def test_validate_rules(mk: Any, rule: str, where: str, edit: Edit) -> None:
    """Breaks one rule at a time and expects exactly that rule."""
    m = mk.parse(mk.encode(edit(mk.base_entries())))
    mk.want_rule(m.validate(), rule, where)


@pytest.mark.parametrize(
    ("eid", "kind", "path"),
    [
        ("admission/valid", "evaluate", "admission/valid"),
        (
            "outcomes/qualification/correction-recompute",
            "outcomes",
            "outcomes/qualification/correction-recompute",
        ),
        ("vectors/jws/es256-r-equals-n", "vector", "vectors/jws/es256-r-equals-n.json"),
        (
            "adapters/_common/common-03.fragment",
            "adapter-case",
            "adapters/_common/common-03.fragment.json",
        ),
        ("keys/reputation-service", "vector", "keys/reputation-service.jwk.json"),
    ],
)
def test_validate_accepts_existing_id_forms(mk: Any, eid: str, kind: str, path: str) -> None:
    es = [
        {
            "id": eid,
            "kind": kind,
            "scope": "core",
            "path": path,
            "expected": "a.json",
            "outcome": "MATCH",
            "spec_map_row": "CL-17.3.1",
            "draft_section": "B.7",
        }
    ]
    mk.want_clean(mk.parse(mk.encode(es)).validate())


def adapter_case(eid: str, path: str) -> dict[str, Any]:
    """An adapter-case entry with the given id and path."""
    return {
        "id": eid,
        "kind": "adapter-case",
        "scope": "adapter",
        "path": path,
        "expected": path,
        "outcome": "REJECTED",
        "spec_map_row": "COMMON-03",
        "draft_section": "10.2",
    }


@pytest.mark.parametrize(
    ("eid", "path"),
    [
        ("adapters/_common/common-03.fragment", "adapters/_common/common-03.fragment.json"),
        ("adapters/_common/fresh-02.at-limit", "adapters/_common/fresh-02.at-limit.json"),
        ("adapters/files/files-01.symlink", "adapters/files/files-01.symlink.json"),
        ("adapters/oauth/oauth-02", "adapters/oauth/oauth-02.json"),
    ],
)
def test_validate_adapter_case_layout_accepts(mk: Any, eid: str, path: str) -> None:
    """An adapter case is the file adapters/<adapter>/<case>.json with the id
    adapters/<adapter>/<case>, for adapters/_common and every adapter alike, with no
    cases/ subdirectory (spec/v1.0/fixtures/README.md, Manifest)."""
    mk.want_clean(mk.parse(mk.encode([adapter_case(eid, path)])).validate())


ADAPTER_CASE_LAYOUT = {
    "cases subdirectory": (
        "adapters/_common/common-03.fragment",
        "adapters/_common/cases/common-03.fragment.json",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    "path of another case": (
        "adapters/_common/common-03.fragment",
        "adapters/_common/common-03.headers.json",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    "path without .json": (
        "adapters/_common/common-03.fragment",
        "adapters/_common/common-03.fragment",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    "path with another extension": (
        "adapters/_common/common-03.fragment",
        "adapters/_common/common-03.fragment.yaml",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    "path the adapter directory": (
        "adapters/_common/common-03.fragment",
        "adapters/_common",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    "path in another adapter": (
        "adapters/_common/common-03.fragment",
        "adapters/files/common-03.fragment.json",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    "id outside adapters": (
        "vectors/zz-case",
        "vectors/zz-case.json",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    "id of two segments": (
        "adapters/zz-case",
        "adapters/zz-case.json",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    "id with an underscore group": (
        "_adapters/_common/zz-case",
        "_adapters/_common/zz-case.json",
        manifest.RULE_ADAPTER_CASE_PATH,
    ),
    # A malformed id or path is reported by its own rule only.
    "id upper case": (
        "adapters/_common/Common-03",
        "adapters/_common/Common-03.json",
        manifest.RULE_ID,
    ),
    "id of four segments": (
        "adapters/_common/cases/zz-case",
        "adapters/_common/cases/zz-case.json",
        manifest.RULE_ID,
    ),
    "path dot dot": ("adapters/_common/zz-case", "adapters/../zz-case.json", manifest.RULE_PATH),
}


@pytest.mark.parametrize(
    ("eid", "path", "rule"), ADAPTER_CASE_LAYOUT.values(), ids=ADAPTER_CASE_LAYOUT
)
def test_validate_adapter_case_layout(mk: Any, eid: str, path: str, rule: str) -> None:
    e = adapter_case(eid, path)
    if rule == manifest.RULE_PATH:
        e["expected"] = eid + ".json"  # so that only the path rule speaks
    mk.want_rule(mk.parse(mk.encode([e])).validate(), rule, eid)


def source_case(eid: str, path: str) -> dict[str, Any]:
    """A source-case entry: scope adapter, and neither an expected file nor an outcome."""
    return {
        "id": eid,
        "kind": "source-case",
        "scope": "adapter",
        "path": path,
        "expected": None,
        "outcome": None,
        "spec_map_row": "CL-17.2",
        "draft_section": "17.2",
    }


@pytest.mark.parametrize(
    ("eid", "path"),
    [
        ("sources/scim/scim-01.join", "sources/scim/scim-01.join.json"),
        ("sources/shared-signals/ssf-02", "sources/shared-signals/ssf-02.json"),
    ],
)
def test_validate_source_case_layout_accepts(mk: Any, eid: str, path: str) -> None:
    """A source case is the file sources/<source>/<case>.json with the id
    sources/<source>/<case>; its case segment may contain "." as an adapter case's does,
    and it has scope adapter and no expected file or outcome."""
    mk.want_clean(mk.parse(mk.encode([source_case(eid, path)])).validate())


SCIM = ("sources/scim/scim-01", "sources/scim/scim-01.json")
SOURCE_CASE_LAYOUT: dict[str, tuple[str, str, str, dict[str, Any]]] = {
    "cases subdirectory": (
        "sources/scim/scim-01.join",
        "sources/scim/cases/scim-01.join.json",
        manifest.RULE_SOURCE_CASE_PATH,
        {},
    ),
    "path without .json": (
        "sources/scim/scim-01.join",
        "sources/scim/scim-01.join",
        manifest.RULE_SOURCE_CASE_PATH,
        {},
    ),
    "path of another case": (
        "sources/scim/scim-01.join",
        "sources/scim/scim-02.json",
        manifest.RULE_SOURCE_CASE_PATH,
        {},
    ),
    "id outside sources": (
        "adapters/scim/scim-01",
        "adapters/scim/scim-01.json",
        manifest.RULE_SOURCE_CASE_PATH,
        {},
    ),
    "id of two segments": (
        "sources/scim-01",
        "sources/scim-01.json",
        manifest.RULE_SOURCE_CASE_PATH,
        {},
    ),
    "source with a dot": (
        "sources/sc.im/scim-01",
        "sources/sc.im/scim-01.json",
        manifest.RULE_SOURCE_CASE_PATH,
        {},
    ),
    "source with an underscore": (
        "sources/_scim/scim-01",
        "sources/_scim/scim-01.json",
        manifest.RULE_SOURCE_CASE_PATH,
        {},
    ),
    "case with an underscore": (
        "sources/scim/_scim-01",
        "sources/scim/_scim-01.json",
        manifest.RULE_SOURCE_CASE_PATH,
        {},
    ),
    "scope core": (*SCIM, manifest.RULE_SCOPE, {"scope": "core"}),
    "scope runner": (*SCIM, manifest.RULE_SCOPE, {"scope": "runner"}),
    "expected set": (*SCIM, manifest.RULE_EXPECTED, {"expected": "sources/scim/scim-01.json"}),
    "outcome set": (*SCIM, manifest.RULE_OUTCOME, {"outcome": "ACCEPTED"}),
    # A malformed id is reported by its own rule only.
    "id of four segments": (
        "sources/scim/cases/scim-01",
        "sources/scim/cases/scim-01.json",
        manifest.RULE_ID,
        {},
    ),
}


@pytest.mark.parametrize(
    ("eid", "path", "rule", "members"), SOURCE_CASE_LAYOUT.values(), ids=SOURCE_CASE_LAYOUT
)
def test_validate_source_case_layout(
    mk: Any, eid: str, path: str, rule: str, members: dict[str, Any]
) -> None:
    e = {**source_case(eid, path), **members}
    mk.want_rule(mk.parse(mk.encode([e])).validate(), rule, eid)


def test_validate_source_case_layout_id_dot_only_in_cases(mk: Any) -> None:
    """Only adapter-case and source-case ids may have a "." in a segment."""
    e = source_case("sources/scim/scim-01.join", "sources/scim/scim-01.join.json")
    e["kind"] = "vector"
    e["expected"], e["outcome"] = "sources/scim/scim-01.join.json", "MATCH"
    mk.want_rule(mk.parse(mk.encode([e])).validate(), manifest.RULE_ID, "sources/scim/scim-01.join")


@pytest.mark.parametrize(
    "outcome",
    [
        "ADMISSIBLE",
        "INADMISSIBLE",
        "DEFERRED",
        "ACCEPTED",
        "REJECTED",
        "QUALIFIED",
        "UNQUALIFIED",
        "DISPUTED",
        "MATCH",
    ],
)
def test_validate_accepts_every_outcome(mk: Any, outcome: str) -> None:
    """The outcome tokens of spec/v1.0/fixtures/README.md, the decisions of draft Section 11.4
    and the qualification results of draft Section 14.3 among them."""
    es = mk.base_entries()
    es[1]["outcome"] = outcome
    mk.want_clean(mk.parse(mk.encode(es)).validate())


@pytest.mark.parametrize(
    "text",
    [
        pytest.param('{"manifest_version":2,"entries":[]}', id="version 2"),
        pytest.param('{"manifest_version":"1","entries":[]}', id="version string"),
        pytest.param('{"manifest_version":1.0,"entries":[]}', id="version a fraction"),
        pytest.param('{"manifest_version":true,"entries":[]}', id="version true"),
        pytest.param('{"entries":[]}', id="version missing"),
        pytest.param('{"manifest_version":1}', id="entries missing"),
        pytest.param('{"manifest_version":1,"entries":{}}', id="entries an object"),
        pytest.param('{"manifest_version":1,"entries":null}', id="entries null"),
        pytest.param('{"manifest_version":1,"entries":[],"generated":true}', id="unknown member"),
        pytest.param('{"manifest_version":1,"entries":["admission/valid"]}', id="entry not object"),
    ],
)
def test_validate_top_level(mk: Any, text: str) -> None:
    mk.want_rule(mk.parse(text.encode()).validate(), manifest.RULE_SHAPE)


def test_problems_format(mk: Any) -> None:
    es = mk.base_entries()
    es[1]["kind"] = "evaluation"
    ps = mk.parse(mk.encode(es)).validate()
    assert ps.err() is ps
    mk.must_contain(str(ps), "[entry-kind]", "admission/valid", "evaluation")
    assert manifest.Problems().err() is None
    assert str(ps[0]).startswith("[entry-kind] admission/valid: ")
    assert isinstance(ps, PactError)


def test_validate_capabilities(mk: Any) -> None:
    """capabilities, the optional capabilities the entry tests (spec/v1.0/fixtures/README.md,
    Optional capabilities). An entry without it is mandatory."""
    assert manifest.capabilities() == [manifest.CAPABILITY_JWS_ED25519]
    assert manifest.CAPABILITY_JWS_ED25519 == "jws-ed25519"
    es = mk.base_entries()
    es[1]["capabilities"] = ["jws-ed25519"]
    m = mk.parse(mk.encode(es))
    mk.want_clean(m.validate())
    assert m.entries[1].capabilities == ("jws-ed25519",)
    for i, e in enumerate(m.entries):
        if i != 1:
            assert e.capabilities is None, e.id
    # A malformed member decodes as None, so a caller that skips validate never
    # reads it as a capability list.
    es[1]["capabilities"] = ["jws-ed25519", 1]
    assert mk.parse(mk.encode(es)).entries[1].capabilities is None


def test_encode_sorts_members(mk: Any) -> None:
    """The helper writes the members as Go's json.MarshalIndent writes a map: sorted."""
    doc = json.loads(mk.encode(mk.base_entries()))
    assert list(doc) == ["entries", "manifest_version"]
    assert list(doc["entries"][0]) == sorted(doc["entries"][0])
