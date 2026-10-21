"""Fixture manifest reading and rules. Mirrors hop.top/pact-go/runner/manifest.

Reads and checks spec/v1.0/fixtures/manifest.json, the index of the language-neutral
conformance fixtures. The format is defined in spec/v1.0/fixtures/README.md;
spec/v1.0/fixtures/manifest.schema.json states the same field rules as a JSON Schema.

- load and parse read the manifest with the strict parse rules of draft Section
  7.1. Manifest.validate applies the field rules: the members of every entry,
  the id, path, kind, scope, expected, outcome, spec_map_row and draft_section
  forms, the optional members capabilities, conformance_profile, transport and
  layer, the scope of the kinds that have one, the layout of adapter and source
  cases, unique ids and order by id.
- completeness checks the manifest against the fixture directory: every path
  and expected file exists inside it, every file is covered by an entry
  (README.md files, files named LICENSE* and the files under testdata/ aside),
  and every file has a neutral extension, in lower case.
- parse_spec_map and check_spec_map check the cross-references with
  spec/v1.0/spec-map.md: every spec_map_row is a row, every group has a status in the
  Fixture groups table, and each status (planned, partial or landed) agrees
  with the manifest and with the fixtures that exist for the ids the rows list.

check runs all of them, as pactfix check manifest does; ``python -m
hop_top_pact.runner.manifest check ROOT SPECMAP`` runs it from the command
line. Every problem names its rule (the RULE_* constants).

Paths are slash-separated and relative to the directory that holds
manifest.json, so the same manifest resolves in the source repository and in
the spec mirror. Standard library and core.strictjson only.
"""

from __future__ import annotations

import os
from pathlib import Path

from hop_top_pact.runner.manifest.entry import (
    FILE_NAME,
    SCHEMA_FILE_NAME,
    VERSION,
    Entry,
    Manifest,
    load,
    parse,
)
from hop_top_pact.runner.manifest.files import completeness
from hop_top_pact.runner.manifest.problem import (
    RULE_ADAPTER_CASE_PATH,
    RULE_CAPABILITIES,
    RULE_CONFORMANCE_PROFILE,
    RULE_DRAFT_SECTION,
    RULE_EXPECTED,
    RULE_EXPECTED_MISSING,
    RULE_EXTENSION,
    RULE_FIXTURE_MISSING,
    RULE_GROUP_LANDED,
    RULE_GROUP_PARTIAL_COMPLETE,
    RULE_GROUP_PARTIAL_EMPTY,
    RULE_GROUP_PLANNED,
    RULE_GROUP_UNLISTED,
    RULE_ID,
    RULE_ID_DUPLICATE,
    RULE_JSON,
    RULE_KIND,
    RULE_LAYER,
    RULE_ORDER,
    RULE_OUTCOME,
    RULE_PATH,
    RULE_PATH_MISSING,
    RULE_ROW_UNKNOWN,
    RULE_SCOPE,
    RULE_SHAPE,
    RULE_SOURCE_CASE_PATH,
    RULE_SPEC_MAP,
    RULE_SPEC_MAP_ROW,
    RULE_TRANSPORT,
    RULE_UNCOVERED,
    Problem,
    Problems,
)
from hop_top_pact.runner.manifest.rules import (
    ADAPTER_CASE_ID_PATTERN,
    CAPABILITY_JWS_ED25519,
    CONFORMANCE_PROFILE_FULL,
    CONFORMANCE_PROFILE_SINGLE_OWNER,
    DEFAULT_CONFORMANCE_PROFILE,
    DEFAULT_TRANSPORT,
    DRAFT_SECTION_PATTERN,
    ID_PATTERN,
    LAYER_OS,
    LAYER_TRANSCRIPT,
    PATH_PATTERN,
    SOURCE_CASE_ID_PATTERN,
    SPEC_MAP_ROW_PATTERN,
    TESTDATA_DIR,
    TRANSPORT_HTTPS,
    TRANSPORT_STDIO_IPC,
    Kind,
    Scope,
    capabilities,
    conformance_profiles,
    kinds,
    layers,
    outcomes,
    scopes,
    transports,
)
from hop_top_pact.runner.manifest.specmap import (
    STATUS_LANDED,
    STATUS_PARTIAL,
    STATUS_PLANNED,
    Row,
    SpecMap,
    check_spec_map,
    fixture_exists,
    parse_spec_map,
)

__all__ = [
    "ADAPTER_CASE_ID_PATTERN",
    "CAPABILITY_JWS_ED25519",
    "CONFORMANCE_PROFILE_FULL",
    "CONFORMANCE_PROFILE_SINGLE_OWNER",
    "DEFAULT_CONFORMANCE_PROFILE",
    "DEFAULT_TRANSPORT",
    "DRAFT_SECTION_PATTERN",
    "FILE_NAME",
    "ID_PATTERN",
    "LAYER_OS",
    "LAYER_TRANSCRIPT",
    "PATH_PATTERN",
    "RULE_ADAPTER_CASE_PATH",
    "RULE_CAPABILITIES",
    "RULE_CONFORMANCE_PROFILE",
    "RULE_DRAFT_SECTION",
    "RULE_EXPECTED",
    "RULE_EXPECTED_MISSING",
    "RULE_EXTENSION",
    "RULE_FIXTURE_MISSING",
    "RULE_GROUP_LANDED",
    "RULE_GROUP_PARTIAL_COMPLETE",
    "RULE_GROUP_PARTIAL_EMPTY",
    "RULE_GROUP_PLANNED",
    "RULE_GROUP_UNLISTED",
    "RULE_ID",
    "RULE_ID_DUPLICATE",
    "RULE_JSON",
    "RULE_KIND",
    "RULE_LAYER",
    "RULE_ORDER",
    "RULE_OUTCOME",
    "RULE_PATH",
    "RULE_PATH_MISSING",
    "RULE_ROW_UNKNOWN",
    "RULE_SCOPE",
    "RULE_SHAPE",
    "RULE_SOURCE_CASE_PATH",
    "RULE_SPEC_MAP",
    "RULE_SPEC_MAP_ROW",
    "RULE_TRANSPORT",
    "RULE_UNCOVERED",
    "SCHEMA_FILE_NAME",
    "SOURCE_CASE_ID_PATTERN",
    "SPEC_MAP_ROW_PATTERN",
    "STATUS_LANDED",
    "STATUS_PARTIAL",
    "STATUS_PLANNED",
    "TESTDATA_DIR",
    "TRANSPORT_HTTPS",
    "TRANSPORT_STDIO_IPC",
    "VERSION",
    "Entry",
    "Kind",
    "Manifest",
    "Problem",
    "Problems",
    "Row",
    "Scope",
    "SpecMap",
    "capabilities",
    "check",
    "check_spec_map",
    "completeness",
    "conformance_profiles",
    "fixture_exists",
    "kinds",
    "layers",
    "load",
    "outcomes",
    "parse",
    "parse_spec_map",
    "scopes",
    "transports",
]


def check(root: str | os.PathLike[str], spec_map_path: str | os.PathLike[str]) -> Problems:
    """Run every check of pactfix check manifest over the fixture directory root and the
    spec map at spec_map_path: load, validate, completeness, parse_spec_map and
    check_spec_map. Return all problems; an unreadable or non-strict manifest stops it
    after the RULE_JSON problem."""
    try:
        m = load(root)
    except Problems as err:
        return err
    out = m.validate() + completeness(root, m)
    try:
        text = Path(spec_map_path).read_bytes()
    except OSError as err:
        msg = f"{err.filename}: {err.strerror}" if err.strerror else str(err)
        return Problems((*out, Problem(RULE_SPEC_MAP, os.path.basename(spec_map_path), msg, err)))
    sm, sps = parse_spec_map(text)
    out += sps
    if sm is not None:
        out += check_spec_map(root, m, sm)
    return out
