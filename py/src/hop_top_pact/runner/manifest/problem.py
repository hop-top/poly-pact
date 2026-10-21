"""The rule ids and the problem types. Mirrors go/runner/manifest/problem.go."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from collections.abc import Sequence as _Sequence
from dataclasses import dataclass
from typing import Final, overload

from hop_top_pact.errors import PactError

# Rules. A Problem names exactly one.

RULE_JSON: Final = "manifest-json"
"""manifest.json is unreadable or not strict JSON (draft 7.1)."""
RULE_SHAPE: Final = "manifest-shape"
"""A top-level member, an entry member or a JSON type is wrong or missing."""
RULE_ID: Final = "entry-id"
"""An id is not two or three id segments."""
RULE_ID_DUPLICATE: Final = "entry-id-duplicate"
"""Two entries share an id."""
RULE_ORDER: Final = "entry-order"
"""The entries are not sorted by id."""
RULE_KIND: Final = "entry-kind"
"""kind is not a known kind."""
RULE_SCOPE: Final = "entry-scope"
"""scope is not a known scope, or not the one scope of a kind that has one
(Kind.required_scope)."""
RULE_PATH: Final = "entry-path"
"""path is not a relative slash-separated path."""
RULE_EXPECTED: Final = "entry-expected"
"""expected is malformed, or null where a file is needed, or set where the kind has none."""
RULE_OUTCOME: Final = "entry-outcome"
"""outcome is not a known token, or null where one is needed, or set where the kind has
none."""
RULE_SPEC_MAP_ROW: Final = "entry-spec-map-row"
"""spec_map_row is not a row id."""
RULE_DRAFT_SECTION: Final = "entry-draft-section"
"""draft_section is not a section number or letter."""
RULE_CAPABILITIES: Final = "entry-capabilities"
"""capabilities is empty, or names a capability twice or one that is not a capability
token."""
RULE_CONFORMANCE_PROFILE: Final = "entry-conformance-profile"
"""conformance_profile is empty, or names a profile twice or one that is not a
conformance profile id."""
RULE_TRANSPORT: Final = "entry-transport"
"""transport is empty, or names a transport profile twice or one that is not https or
stdio-ipc."""
RULE_LAYER: Final = "entry-layer"
"""layer is not transcript or os, is set on an entry whose transport has no stdio-ipc, or
is absent from an entry of kind transport."""
RULE_ADAPTER_CASE_PATH: Final = "adapter-case-path"
"""An adapter-case entry is not the file adapters/<adapter>/<case>.json with the id
adapters/<adapter>/<case>."""
RULE_SOURCE_CASE_PATH: Final = "source-case-path"
"""A source-case entry is not the file sources/<source>/<case>.json with the id
sources/<source>/<case>."""
RULE_PATH_MISSING: Final = "path-missing"
"""An entry path does not exist, is a dangling symbolic link, or resolves outside the
fixture directory."""
RULE_EXPECTED_MISSING: Final = "expected-missing"
"""An expected file does not exist, resolves outside the fixture directory, or is not a
file."""
RULE_UNCOVERED: Final = "file-uncovered"
"""A fixture file is in no entry's path, is no entry's expected file, and is not under
expected/<id>/ for an entry's id."""
RULE_EXTENSION: Final = "file-extension"
"""A fixture file has an extension outside the neutral list, or a native-asset extension
outside an adapter-asset entry."""
RULE_ROW_UNKNOWN: Final = "row-unknown"
"""An entry cites a spec_map_row the spec map lacks."""
RULE_FIXTURE_MISSING: Final = "fixture-id-missing"
"""A fixture id named in the spec map is not in the manifest, although its group is landed
or its fixture exists."""
RULE_GROUP_PLANNED: Final = "group-planned-has-entries"
"""A group marked planned has manifest entries."""
RULE_GROUP_PARTIAL_EMPTY: Final = "group-partial-empty"
"""A group marked partial has no manifest entries."""
RULE_GROUP_PARTIAL_COMPLETE: Final = "group-partial-complete"
"""Every fixture id the spec map names in a group marked partial exists."""
RULE_GROUP_LANDED: Final = "group-landed-empty"
"""A group marked landed has no manifest entries."""
RULE_GROUP_UNLISTED: Final = "group-unlisted"
"""A manifest entry or a spec-map row names a group that has no row in the Fixture groups
table."""
RULE_SPEC_MAP: Final = "spec-map"
"""The spec map is unreadable or lacks a table, a column or a well-formed row the checks
read."""


@dataclass(frozen=True, slots=True)
class Problem:
    """One violation of a rule."""

    rule: str
    """One of the RULE_* ids."""
    where: str
    """The entry id (or entries[i] when the entry has no usable id), the fixture file, the
    spec-map row, group or fixture id, or the file name of manifest.json or the spec map."""
    msg: str
    """What is wrong."""
    err: BaseException | None = None
    """The underlying cause, or None."""

    def __str__(self) -> str:
        return f"[{self.rule}] {self.where}: {self.msg}"


class Problems(PactError, _Sequence[Problem]):
    """A list of problems, and the error load and parse raise.

    As an error it prints one problem per line. Its __cause__ is the underlying cause of
    the first problem that has one (Go: Unwrap).
    """

    def __init__(self, problems: Iterable[Problem] = ()) -> None:
        self._items: tuple[Problem, ...] = tuple(problems)
        super().__init__(str(self))
        self.__cause__ = next((p.err for p in self._items if p.err is not None), None)

    @overload
    def __getitem__(self, i: int) -> Problem: ...
    @overload
    def __getitem__(self, i: slice) -> Problems: ...
    def __getitem__(self, i: int | slice) -> Problem | Problems:
        if isinstance(i, slice):
            return Problems(self._items[i])
        return self._items[i]

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[Problem]:
        return iter(self._items)

    def __add__(self, other: Iterable[Problem]) -> Problems:
        return Problems((*self._items, *other))

    def __str__(self) -> str:
        return "\n".join(str(p) for p in self._items)

    def __repr__(self) -> str:
        return f"Problems({list(self._items)!r})"

    def err(self) -> Problems | None:
        """This list as an error, or None when it is empty."""
        return self if self._items else None


class _Collector(list[Problem]):
    """The problems a check gathers, in order."""

    def add(self, rule: str, where: str, msg: str, err: BaseException | None = None) -> None:
        self.append(Problem(rule, where, msg, err))

    def done(self) -> Problems:
        return Problems(self)
