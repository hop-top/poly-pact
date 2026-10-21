"""Patterns, vocabularies and file rules of the manifest format. Mirrors
go/runner/manifest/rules.go."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from enum import StrEnum
from typing import Final

# Patterns of the field rules. manifest.schema.json states the same ones. They are
# matched with re.fullmatch: Python's $ also matches before a final newline.

ID_PATTERN: Final = (
    r"^[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9]+(?:-[a-z0-9]+)*)?$"
)
"""The id of every entry that is not an adapter or source case, two or three segments. A
segment is lowercase letters and digits joined by hyphens."""
ADAPTER_CASE_ID_PATTERN: Final = (
    r"^adapters/_?[a-z0-9]+(?:[-.][a-z0-9]+)*/_?[a-z0-9]+(?:[-.][a-z0-9]+)*$"
)
"""The id of an adapter-case entry, adapters/<adapter>/<case>. It follows the file name
adapters/<adapter>/<case>.json, so its last two segments may also start with "_" and join
with ".", as in adapters/_common/common-03.fragment."""
SOURCE_CASE_ID_PATTERN: Final = r"^sources/[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:[-.][a-z0-9]+)*$"
"""The id of a source-case entry, sources/<source>/<case>. Its case segment may also join
with ".", as in sources/scim/scim-01.join; no segment starts with "_"."""
PATH_PATTERN: Final = r"^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$"
"""Relative and slash-separated; a segment is ASCII letters, digits, ".", "_" and "-", and
does not start with ".", so there is no leading "/", no empty segment and no "." or ".."
segment."""
SPEC_MAP_ROW_PATTERN: Final = r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+(?:\.[0-9]+)*)?$"
"""A row id of spec/v1.0/spec-map.md, such as R01, CL-11.3, CL-C or COMMON-01."""
DRAFT_SECTION_PATTERN: Final = r"^(?:[1-9][0-9]*|[A-Z])(?:\.[1-9][0-9]*)*$"
"""A section number such as 11.3, or an appendix letter with an optional subsection, such
as C or B.7."""

# Two or three segments that may each start with "_" and join with ".", the widest id
# form. An id of another form is malformed whatever the kind; a spec-map fixture id of
# this form can name a file.
_FILE_ID_PATTERN: Final = (
    r"^_?[a-z0-9]+(?:[-.][a-z0-9]+)*/_?[a-z0-9]+(?:[-.][a-z0-9]+)*"
    r"(?:/_?[a-z0-9]+(?:[-.][a-z0-9]+)*)?$"
)


def _matcher(pattern: str) -> re.Pattern[str]:
    # ASCII classes only, as Go's RE2 reads them.
    return re.compile(pattern, re.ASCII)


ID_RE: Final = _matcher(ID_PATTERN)
ADAPTER_CASE_ID_RE: Final = _matcher(ADAPTER_CASE_ID_PATTERN)
SOURCE_CASE_ID_RE: Final = _matcher(SOURCE_CASE_ID_PATTERN)
FILE_ID_RE: Final = _matcher(_FILE_ID_PATTERN)
PATH_RE: Final = _matcher(PATH_PATTERN)
SPEC_MAP_ROW_RE: Final = _matcher(SPEC_MAP_ROW_PATTERN)
DRAFT_SECTION_RE: Final = _matcher(DRAFT_SECTION_PATTERN)


def matches(rx: re.Pattern[str], s: str) -> bool:
    """Whether the whole of s matches rx."""
    return rx.fullmatch(s) is not None


class Scope(StrEnum):
    """Who must pass an entry."""

    CORE = "core"
    """Every language harness."""
    RUNNER = "runner"
    """Only the Go conformance runner."""
    ADAPTER = "adapter"
    """The adapter conformance harnesses."""

    @classmethod
    def known(cls, s: str) -> bool:
        """Whether s is a scope of the manifest format."""
        return s in cls._value2member_map_


class Kind(StrEnum):
    """What an entry is: the harness verb that runs it or the role of the asset."""

    KEY = "key"
    VECTOR = "vector"
    SCHEMA = "schema"
    EVALUATE = "evaluate"
    OUTCOMES = "outcomes"
    LEARNING = "learning"
    ADAPTER_CASE = "adapter-case"
    ADAPTER_ASSET = "adapter-asset"
    SOURCE_CASE = "source-case"
    """A case of a membership or status source that is not an adapter, scope adapter, with
    its expectations inline and neither an expected file nor an outcome."""
    PROFILE_INVALID = "profile-invalid"
    TRANSPORT = "transport"
    """A transport transcript, scope runner."""
    MCP = "mcp"
    """An MCP adapter vector or case, scope adapter."""
    PROFILE = "profile"
    """A conformance-profile case, scope runner."""

    @classmethod
    def known(cls, s: str) -> bool:
        """Whether s is a kind of the manifest format."""
        return s in cls._value2member_map_

    def has_expected(self) -> bool:
        """Whether entries of this kind name an expected file and an outcome. Key,
        adapter-asset and source-case entries have neither: both are null."""
        return self not in (Kind.KEY, Kind.ADAPTER_ASSET, Kind.SOURCE_CASE)

    def required_scope(self) -> Scope | None:
        """The one scope an entry of this kind must have, or None for a kind that takes
        any: runner for transport transcripts and conformance-profile cases, adapter for
        MCP vectors and cases and for source cases, never core, so that the harnesses that
        select entries by scope skip them alike."""
        if self in (Kind.TRANSPORT, Kind.PROFILE):
            return Scope.RUNNER
        if self in (Kind.MCP, Kind.SOURCE_CASE):
            return Scope.ADAPTER
        return None


def kinds() -> list[str]:
    """The kinds, in the order of the README."""
    return [k.value for k in Kind]


def scopes() -> list[str]:
    """The scopes, in the order of the README."""
    return [s.value for s in Scope]


# Conformance profiles: the entries of kind conformance in spec/v1.0/profiles/registry.json
# (draft Section 22.1). An entry runs under the profiles its conformance_profile member
# lists, DEFAULT_CONFORMANCE_PROFILE when it has none.
CONFORMANCE_PROFILE_FULL: Final = "full"
CONFORMANCE_PROFILE_SINGLE_OWNER: Final = "single-owner"
DEFAULT_CONFORMANCE_PROFILE: Final = CONFORMANCE_PROFILE_FULL
"""Applies to an entry without conformance_profile."""
_CONFORMANCE_PROFILES: Final = (CONFORMANCE_PROFILE_FULL, CONFORMANCE_PROFILE_SINGLE_OWNER)


def conformance_profiles() -> list[str]:
    """The conformance profile ids, in registry order."""
    return list(_CONFORMANCE_PROFILES)


# Transports: the transport profiles an entry exercises, by id as in claim.transport of
# spec/v1.0/profiles/integration-profile.schema.json (draft Section 21). https is the baseline
# HTTPS binding (draft Section 13), which has no registry entry; stdio-ipc is the local IPC
# and stdio profile of draft Section 13.3. An entry without transport exercises
# DEFAULT_TRANSPORT.
TRANSPORT_HTTPS: Final = "https"
TRANSPORT_STDIO_IPC: Final = "stdio-ipc"
DEFAULT_TRANSPORT: Final = TRANSPORT_HTTPS
"""Applies to an entry without transport."""
_TRANSPORTS: Final = (TRANSPORT_HTTPS, TRANSPORT_STDIO_IPC)


def transports() -> list[str]:
    """The transport profile ids, in the order of the README."""
    return list(_TRANSPORTS)


# Layers: how an entry over stdio-ipc is executed. An entry without layer applies to
# every layer. A transcript entry is a language-neutral frame sequence the runner
# executes; an os entry needs real operating-system facilities and is executed by a
# language-specific harness.
LAYER_TRANSCRIPT: Final = "transcript"
LAYER_OS: Final = "os"
_LAYERS: Final = (LAYER_TRANSCRIPT, LAYER_OS)


def layers() -> list[str]:
    """The layer tokens, in the order of the README."""
    return list(_LAYERS)


# Capabilities: the optional capabilities an entry may test, each a feature the draft
# makes optional (draft Sections 22.1 and 22.2); an entry that tests one applies only to
# an implementation that declares it.
CAPABILITY_JWS_ED25519: Final = "jws-ed25519"
"""Ed25519 (RFC 9864) negotiated explicitly for signed artifacts, with RFC 8037 keys
(draft Section 7.2, MAY)."""
_CAPABILITIES: Final = (CAPABILITY_JWS_ED25519,)


def capabilities() -> list[str]:
    """The capability tokens, in the order of the README."""
    return list(_CAPABILITIES)


# Outcome tokens: the decisions of draft Section 11.4, then the other one-token
# summaries, among them the qualification results of draft Section 14.3.
_OUTCOMES: Final = (
    "ADMISSIBLE",
    "INADMISSIBLE",
    "DEFERRED",
    "ACCEPTED",
    "REJECTED",
    "QUALIFIED",
    "UNQUALIFIED",
    "DISPUTED",
    "MATCH",
)


def outcomes() -> list[str]:
    """The outcome tokens, in the order of the README."""
    return list(_OUTCOMES)


# NEUTRAL_EXTENSIONS may appear anywhere under the fixture directory; NATIVE_EXTENSIONS
# only inside the path of an adapter-asset entry. Both are lowercase and compared as
# written: .JSON is on neither list.
NEUTRAL_EXTENSIONS: Final = (".json", ".yaml", ".md", ".jws")
NATIVE_EXTENSIONS: Final = (".sql", ".rego", ".fga", ".ldif")

TESTDATA_DIR: Final = "testdata"
"""Holds the test inputs of the manifest checks themselves, such as the test manifests of
testdata/manifest; they are not fixtures."""


def within(rel: str, p: str) -> bool:
    """Whether rel is p or lies inside the directory p."""
    return rel == p or rel.startswith(p + "/")


def base_name(rel: str) -> str:
    """The last element of a slash-separated path."""
    return rel.rsplit("/", 1)[-1]


def ext(rel: str) -> str:
    """The extension of a slash-separated path as Go's path.Ext reads it: from the last
    "." of the last element, "" when it has none (".json" is its own extension)."""
    name = base_name(rel)
    i = name.rfind(".")
    return name[i:] if i >= 0 else ""


def go_quote(s: str) -> str:
    """s in double quotes, as Go's %q writes a printable string."""
    return json.dumps(s, ensure_ascii=False)


def go_list(xs: Iterable[str]) -> str:
    """xs as Go's %v writes a []string."""
    return "[" + " ".join(xs) + "]"
