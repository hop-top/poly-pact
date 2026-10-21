"""Entries, the manifest, load, parse and the field rules. Mirrors
go/runner/manifest/manifest.go."""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from hop_top_pact.core import strictjson
from hop_top_pact.core.types import JSONValue
from hop_top_pact.runner.manifest.problem import (
    RULE_ADAPTER_CASE_PATH,
    RULE_CAPABILITIES,
    RULE_CONFORMANCE_PROFILE,
    RULE_DRAFT_SECTION,
    RULE_EXPECTED,
    RULE_ID,
    RULE_ID_DUPLICATE,
    RULE_JSON,
    RULE_KIND,
    RULE_LAYER,
    RULE_ORDER,
    RULE_OUTCOME,
    RULE_PATH,
    RULE_SCOPE,
    RULE_SHAPE,
    RULE_SOURCE_CASE_PATH,
    RULE_SPEC_MAP_ROW,
    RULE_TRANSPORT,
    Problem,
    Problems,
    _Collector,
)
from hop_top_pact.runner.manifest.rules import (
    _CAPABILITIES,
    _CONFORMANCE_PROFILES,
    _LAYERS,
    _OUTCOMES,
    _TRANSPORTS,
    ADAPTER_CASE_ID_RE,
    DEFAULT_CONFORMANCE_PROFILE,
    DEFAULT_TRANSPORT,
    DRAFT_SECTION_RE,
    FILE_ID_RE,
    ID_RE,
    PATH_RE,
    SOURCE_CASE_ID_RE,
    SPEC_MAP_ROW_RE,
    TRANSPORT_STDIO_IPC,
    Kind,
    Scope,
    go_list,
    go_quote,
    kinds,
    matches,
    scopes,
)

# File names in the fixture directory, and the format version.
FILE_NAME: Final = "manifest.json"
SCHEMA_FILE_NAME: Final = "manifest.schema.json"
VERSION: Final = 1

# Bounds manifest.json. It is an index, not a protocol object, so the presentation limit
# of draft Section 20.1 does not apply.
_MAX_BYTES: Final = 16 << 20

# The members every entry has, all required, and those it may have.
_ENTRY_MEMBERS: Final = (
    "id",
    "kind",
    "scope",
    "path",
    "expected",
    "outcome",
    "spec_map_row",
    "draft_section",
)
_OPTIONAL_MEMBERS: Final = ("capabilities", "conformance_profile", "transport", "layer")


def json_type(v: JSONValue) -> str:
    """The JSON type of a parsed value."""
    if isinstance(v, dict):
        return "object"
    if isinstance(v, tuple):
        return "array"
    if isinstance(v, str):
        return "string"
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    return "number"


@dataclass(frozen=True, slots=True)
class Entry:
    """One fixture of the manifest.

    A member that is absent or has the wrong JSON type reads as "" (None for the members
    that may be null or absent); validate reports it.
    """

    id: str = ""
    kind: str = ""
    """A Kind value when it is one; as written otherwise."""
    scope: str = ""
    """A Scope value when it is one; as written otherwise."""
    path: str = ""
    """The case directory or single file, relative to the fixture directory."""
    expected: str | None = None
    """The expected-result file, None for key, adapter-asset and source-case entries."""
    outcome: str | None = None
    """The one-token result summary, None for key, adapter-asset and source-case entries."""
    spec_map_row: str = ""
    draft_section: str = ""
    capabilities: tuple[str, ...] | None = None
    """The optional capabilities the entry tests, None for an entry without the member,
    which every implementation must pass."""
    conformance_profile: tuple[str, ...] | None = None
    """The member conformance_profile as written, None when the entry has none;
    conformance_profiles applies the default."""
    transport: tuple[str, ...] | None = None
    """The member transport as written, None when the entry has none; transports applies
    the default."""
    layer: str = ""
    """The member layer, "" when the entry has none, which applies to every layer."""
    _raw: Mapping[str, JSONValue] | None = field(default=None, repr=False, compare=False)

    def conformance_profiles(self) -> list[str]:
        """The conformance profiles the entry runs under: its conformance_profile, or
        [DEFAULT_CONFORMANCE_PROFILE] when it has none."""
        if self.conformance_profile is None:
            return [DEFAULT_CONFORMANCE_PROFILE]
        return list(self.conformance_profile)

    def transports(self) -> list[str]:
        """The transports the entry exercises: its transport, or [DEFAULT_TRANSPORT] when
        it has none."""
        if self.transport is None:
            return [DEFAULT_TRANSPORT]
        return list(self.transport)


def _str(raw: Mapping[str, JSONValue], name: str) -> str:
    v = raw.get(name)
    return v if isinstance(v, str) else ""


def _opt_str(raw: Mapping[str, JSONValue], name: str) -> str | None:
    v = raw.get(name)
    return v if isinstance(v, str) else None


def _strs(raw: Mapping[str, JSONValue], name: str) -> tuple[str, ...] | None:
    """The member name when it is an array of strings, else None."""
    v = raw.get(name)
    if not isinstance(v, tuple) or not all(isinstance(x, str) for x in v):
        return None
    return tuple(str(x) for x in v)


def _token(cls: type[Kind] | type[Scope], s: str) -> str:
    return cls(s) if cls.known(s) else s


def _entry(el: JSONValue) -> Entry:
    if not isinstance(el, dict):
        return Entry()
    return Entry(
        id=_str(el, "id"),
        kind=_token(Kind, _str(el, "kind")),
        scope=_token(Scope, _str(el, "scope")),
        path=_str(el, "path"),
        expected=_opt_str(el, "expected"),
        outcome=_opt_str(el, "outcome"),
        spec_map_row=_str(el, "spec_map_row"),
        draft_section=_str(el, "draft_section"),
        capabilities=_strs(el, "capabilities"),
        conformance_profile=_strs(el, "conformance_profile"),
        transport=_strs(el, "transport"),
        layer=_str(el, "layer"),
        _raw=el,
    )


@dataclass(frozen=True, slots=True)
class Manifest:
    """A parsed manifest.json. Call validate before relying on it: parse accepts any
    strict JSON object, and a member that has the wrong JSON type reads as its zero
    value."""

    version: int = 0
    """manifest_version, 0 when it is absent or not an integer."""
    entries: tuple[Entry, ...] = ()
    """In file order, one per element of entries."""
    _top: Mapping[str, JSONValue] = field(default_factory=dict, repr=False, compare=False)

    def lookup(self, id: str) -> Entry | None:
        """The entry with the given id, or None."""
        return next((e for e in self.entries if e.id == id), None)

    def validate(self) -> Problems:
        """Apply the field rules of spec/v1.0/fixtures/README.md; every violation, in file
        order."""
        ps = _Collector()
        for k in sorted(self._top):
            if k not in ("manifest_version", "entries"):
                ps.add(RULE_SHAPE, FILE_NAME, f"unknown top-level member {go_quote(k)}")
        if "manifest_version" not in self._top:
            ps.add(RULE_SHAPE, FILE_NAME, "no manifest_version")
        else:
            v = self._top["manifest_version"]
            # Go compares the member's text with "1": only the integer literal 1.
            if not (type(v) is int and v == VERSION):
                ps.add(
                    RULE_SHAPE,
                    FILE_NAME,
                    f"manifest_version is {_text(v)}, want {VERSION}",
                )
        if "entries" not in self._top:
            ps.add(RULE_SHAPE, FILE_NAME, "no entries")
            return ps.done()
        if (t := json_type(self._top["entries"])) != "array":
            ps.add(RULE_SHAPE, FILE_NAME, f"entries is {t}, not an array")
            return ps.done()

        first: dict[str, int] = {}
        for i, e in enumerate(self.entries):
            _validate_entry(e, i, ps)
            if not e.id:
                continue
            if e.id in first:
                ps.add(
                    RULE_ID_DUPLICATE,
                    e.id,
                    f"entries[{i}] repeats the id of entries[{first[e.id]}]",
                )
            else:
                first[e.id] = i
            if i > 0 and self.entries[i - 1].id > e.id:
                ps.add(
                    RULE_ORDER,
                    e.id,
                    f"entries[{i}] sorts before entries[{i - 1}] {self.entries[i - 1].id};"
                    " sort the entries by id",
                )
        return ps.done()


def _text(v: JSONValue) -> str:
    """A parsed value written back as JSON text, for a message."""
    if isinstance(v, str):
        return go_quote(v)
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int | float):
        return repr(v)
    return json_type(v)


def load(root: str | os.PathLike[str]) -> Manifest:
    """Read and parse manifest.json in the fixture directory root; raise Problems with one
    RULE_JSON problem when it is unreadable or not strict JSON."""
    try:
        data = (Path(root) / FILE_NAME).read_bytes()
    except OSError as err:
        raise Problems([Problem(RULE_JSON, FILE_NAME, _os_message(err), err)]) from err
    return parse(data)


def _os_message(err: OSError) -> str:
    return f"{err.filename}: {err.strerror}" if err.strerror else str(err)


def parse(data: bytes) -> Manifest:
    """Read a manifest with the strict parse rules of draft Section 7.1: duplicate member
    names, non-finite numbers, invalid UTF-8, unpaired surrogates, a byte order mark and
    trailing data are errors, and the document must be an object. The error is Problems
    with one RULE_JSON problem whose err is the StrictJSONError."""
    try:
        top = strictjson.parse(data, strictjson.Limits(max_bytes=_MAX_BYTES))
        if not isinstance(top, dict):
            # As Go reports a value that does not fit its target: after the walk, at the
            # end of the value.
            raise strictjson.StrictJSONError(
                strictjson.StrictJSONErrorKind.TYPE,
                offset=len(data.rstrip(b" \t\r\n")),
                detail=f"{json_type(top)} does not fit an object",
            )
    except strictjson.StrictJSONError as err:
        raise Problems([Problem(RULE_JSON, FILE_NAME, str(err), err)]) from err
    v = top.get("manifest_version")
    version = v if type(v) is int else 0
    elems = top.get("entries")
    entries = tuple(_entry(el) for el in elems) if isinstance(elems, tuple) else ()
    return Manifest(version, entries, top)


def _validate_entry(e: Entry, i: int, ps: _Collector) -> None:
    where = e.id or f"entries[{i}]"
    raw = e._raw
    if raw is None:
        ps.add(RULE_SHAPE, where, "not an object")
        return
    for k in sorted(raw):
        if k not in _ENTRY_MEMBERS and k not in _OPTIONAL_MEMBERS:
            ps.add(RULE_SHAPE, where, f"unknown member {go_quote(k)}")
    for k in _ENTRY_MEMBERS:
        if k not in raw:
            ps.add(RULE_SHAPE, where, f"no {k}")

    known = Kind.known(e.kind)
    kind = Kind(e.kind) if known else None

    def check_id(v: str) -> str:
        if not matches(FILE_ID_RE, v):
            return "is not two or three id segments: lowercase letters, digits and hyphens"
        if kind not in (None, Kind.ADAPTER_CASE, Kind.SOURCE_CASE) and not matches(ID_RE, v):
            return (
                f"starts a segment with _ or has a . in one; only {Kind.ADAPTER_CASE.value}"
                f" and {Kind.SOURCE_CASE.value} ids may"
            )
        return ""

    def check_kind(v: str) -> str:
        return "" if Kind.known(v) else f"is not one of {go_list(kinds())}"

    def check_scope(v: str) -> str:
        if not Scope.known(v):
            return f"is not one of {go_list(scopes())}"
        want = kind.required_scope() if kind is not None else None
        if want is not None and v != want:
            return f"is not {want.value}, the scope of every {e.kind} entry"
        return ""

    def check_row(v: str) -> str:
        if not matches(SPEC_MAP_ROW_RE, v):
            return "is not a spec-map row id such as R01 or CL-11.3"
        return ""

    def check_section(v: str) -> str:
        if not matches(DRAFT_SECTION_RE, v):
            return 'is not a section number or appendix letter such as "11.3" or "C"'
        return ""

    _check(raw, ps, where, "id", RULE_ID, False, check_id)
    _check(raw, ps, where, "kind", RULE_KIND, False, check_kind)
    _check(raw, ps, where, "scope", RULE_SCOPE, False, check_scope)
    _check(raw, ps, where, "path", RULE_PATH, False, _path_problem)
    _check(raw, ps, where, "spec_map_row", RULE_SPEC_MAP_ROW, False, check_row)
    _check(raw, ps, where, "draft_section", RULE_DRAFT_SECTION, False, check_section)

    if kind is Kind.ADAPTER_CASE:
        form = "adapters/<adapter>/<case>"
        _check_case(e, ps, where, ADAPTER_CASE_ID_RE, RULE_ADAPTER_CASE_PATH, form)
    elif kind is Kind.SOURCE_CASE:
        form = "sources/<source>/<case>"
        _check_case(e, ps, where, SOURCE_CASE_ID_RE, RULE_SOURCE_CASE_PATH, form)
    _check_tokens(
        raw,
        ps,
        where,
        "capabilities",
        RULE_CAPABILITIES,
        _CAPABILITIES,
        "leave the member out for an entry every implementation must pass",
    )
    _check_tokens(
        raw,
        ps,
        where,
        "conformance_profile",
        RULE_CONFORMANCE_PROFILE,
        _CONFORMANCE_PROFILES,
        "leave the member out for an entry of the default profile " + DEFAULT_CONFORMANCE_PROFILE,
    )
    _check_tokens(
        raw,
        ps,
        where,
        "transport",
        RULE_TRANSPORT,
        _TRANSPORTS,
        "leave the member out for an entry of the default transport " + DEFAULT_TRANSPORT,
    )
    _check_layer(e, raw, ps, where, kind)

    # expected and outcome are null exactly for the kinds without them.
    def check_outcome(v: str) -> str:
        return "" if v in _OUTCOMES else f"is not one of {go_list(_OUTCOMES)}"

    _check(raw, ps, where, "expected", RULE_EXPECTED, True, _path_problem)
    _check(raw, ps, where, "outcome", RULE_OUTCOME, True, check_outcome)
    if kind is None:
        return
    needs = kind.has_expected()
    for name, rule, value in (
        ("expected", RULE_EXPECTED, e.expected),
        ("outcome", RULE_OUTCOME, e.outcome),
    ):
        if name not in raw or json_type(raw[name]) not in ("null", "string"):
            continue
        if needs and value is None:
            ps.add(rule, where, f"{name} is null, but kind {e.kind} needs one")
        elif not needs and value is not None:
            ps.add(
                rule, where, f"{name} is {go_quote(value)}, but kind {e.kind} has none: write null"
            )


def _check_case(
    e: Entry, ps: _Collector, where: str, rx: re.Pattern[str], rule: str, form: str
) -> None:
    """The adapter-case or source-case layout: the file <form>.json with the id <form>. An
    id or path that breaks its own field rule is left to that rule."""
    if not matches(FILE_ID_RE, e.id) or not matches(PATH_RE, e.path):
        return
    want = e.id + ".json"
    if not matches(rx, e.id):
        ps.add(
            rule,
            where,
            f"id {go_quote(e.id)} is not {form}, the id of the case file {form}.json",
        )
    elif e.path != want:
        ps.add(
            rule,
            where,
            f"path {go_quote(e.path)} is not the case file {go_quote(want)},"
            " the id followed by .json",
        )


def _check_tokens(
    raw: Mapping[str, JSONValue],
    ps: _Collector,
    where: str,
    name: str,
    rule: str,
    known: tuple[str, ...],
    empty: str,
) -> None:
    """rule over the optional member name: an array of one or more distinct tokens of
    known. A member of the wrong JSON type, or an item that is not a string, is a
    RULE_SHAPE problem; empty says what to write instead of an empty array."""
    if name not in raw:
        return
    items = raw[name]
    if not isinstance(items, tuple):
        ps.add(RULE_SHAPE, where, f"{name} is {json_type(items)}, not an array")
        return
    if not items:
        ps.add(rule, where, f"{name} is empty: {empty}")
        return
    seen: list[str] = []
    for i, item in enumerate(items):
        if not isinstance(item, str):
            ps.add(RULE_SHAPE, where, f"{name}[{i}] is {json_type(item)}, not a string")
            continue
        if item not in known:
            ps.add(rule, where, f"{name}[{i}] {go_quote(item)} is not one of {go_list(known)}")
        elif item in seen:
            ps.add(rule, where, f"{name}[{i}] {go_quote(item)} repeats a token")
        seen.append(item)


def _check_layer(
    e: Entry, raw: Mapping[str, JSONValue], ps: _Collector, where: str, kind: Kind | None
) -> None:
    """RULE_LAYER over the member layer: transcript or os, only on an entry whose
    transport, as written or by default, has stdio-ipc, and required on an entry of kind
    transport. A transport that breaks its own rule is left to that rule."""
    if "layer" not in raw and kind is Kind.TRANSPORT:
        ps.add(
            RULE_LAYER,
            where,
            f"names no layer: an entry of kind {Kind.TRANSPORT.value} says who executes it,"
            f" {go_list(_LAYERS)}",
        )

    def test(v: str) -> str:
        if v not in _LAYERS:
            return f"is not one of {go_list(_LAYERS)}"
        if "transport" in raw and e.transport is None:
            return ""  # a malformed transport is reported by its own rule
        if TRANSPORT_STDIO_IPC not in e.transports():
            return (
                f"is set, but transport {go_list(e.transports())} has no {TRANSPORT_STDIO_IPC}:"
                " a layer applies only to the local transport profile"
            )
        return ""

    _check(raw, ps, where, "layer", RULE_LAYER, False, test)


def _check(
    raw: Mapping[str, JSONValue],
    ps: _Collector,
    where: str,
    name: str,
    rule: str,
    nullable: bool,
    test: Callable[[str], str],
) -> None:
    """test over the string member name. A missing member is reported by the caller; a
    member of the wrong JSON type is a RULE_SHAPE problem; null is accepted only when
    nullable, and then not passed to test."""
    if name not in raw:
        return
    v = raw[name]
    t = json_type(v)
    if t == "null" and nullable:
        return
    if not isinstance(v, str):
        ps.add(RULE_SHAPE, where, f"{name} is {t}, not a string")
        return
    if msg := test(v):
        ps.add(rule, where, f"{name} {go_quote(v)} {msg}")


def _path_problem(v: str) -> str:
    if not matches(PATH_RE, v):
        return "is not a relative path: / separated ASCII segments, none empty or starting with ."
    return ""
