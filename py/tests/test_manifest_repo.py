"""runner.manifest against the committed spec tree. Port of
go/runner/manifest/repo_test.go, plus the whole check and the entry point."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import Any

from hop_top_pact.core import strictjson
from hop_top_pact.runner import manifest


def test_repo_manifest_validates(mk: Any) -> None:
    """Every committed entry follows the field rules."""
    m = manifest.load(mk.repo_fixtures())
    mk.want_clean(m.validate())


def test_repo_spec_map_parses(mk: Any) -> None:
    """The committed spec map has the tables the checks read."""
    mk.repo_fixtures()
    sm, ps = manifest.parse_spec_map(mk.REPO_SPEC_MAP.read_bytes())
    mk.want_clean(ps)
    assert sm is not None
    assert sm.rows
    assert sm.groups


def test_repo_check(mk: Any) -> None:
    """The committed tree passes every check, as pactfix check manifest requires."""
    mk.want_clean(manifest.check(mk.repo_fixtures(), mk.REPO_SPEC_MAP))


def schema(mk: Any) -> dict[str, Any]:
    data = (mk.repo_fixtures() / manifest.SCHEMA_FILE_NAME).read_bytes()
    doc = strictjson.parse(data, strictjson.Limits(max_depth=64))
    assert isinstance(doc, dict)
    return doc


def test_schema_matches_validator(mk: Any) -> None:
    """manifest.schema.json, read by non-Go consumers, states the same enums and patterns as
    the validator."""
    doc = schema(mk)
    assert doc["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert doc["properties"]["manifest_version"]["const"] == manifest.VERSION
    defs = doc["$defs"]
    for name, want in {
        "id": manifest.ID_PATTERN,
        "adapter_case_id": manifest.ADAPTER_CASE_ID_PATTERN,
        # The file of an adapter case: its id followed by .json.
        "adapter_case_path": manifest.ADAPTER_CASE_ID_PATTERN.removesuffix("$") + r"\.json$",
        "source_case_id": manifest.SOURCE_CASE_ID_PATTERN,
        # The file of a source case: its id followed by .json.
        "source_case_path": manifest.SOURCE_CASE_ID_PATTERN.removesuffix("$") + r"\.json$",
        "path": manifest.PATH_PATTERN,
        "spec_map_row": manifest.SPEC_MAP_ROW_PATTERN,
        "draft_section": manifest.DRAFT_SECTION_PATTERN,
    }.items():
        got = defs[name]["pattern"]
        assert got == want, name
        re.compile(got)
    for name, values in {
        "kind": manifest.kinds(),
        "scope": manifest.scopes(),
        "outcome": manifest.outcomes(),
        "capability": manifest.capabilities(),
        "conformance_profile_id": manifest.conformance_profiles(),
        "transport_name": manifest.transports(),
        "layer": manifest.layers(),
    }.items():
        assert list(defs[name]["enum"]) == values, name


def layout(c: Any, kind: str, id_ref: str, path_ref: str) -> Any:
    """Checks that the condition c applies to kind the id and path definitions of its then
    branch, and returns its else branch."""
    assert c is not None
    assert c["if"]["properties"]["kind"]["const"] == kind
    assert "kind" in c["if"]["required"], kind
    assert c["then"]["properties"]["id"]["$ref"] == id_ref, kind
    assert c["then"]["properties"]["path"]["$ref"] == path_ref, kind
    return c.get("else")


def test_schema_adapter_case_layout(mk: Any) -> None:
    """manifest.schema.json applies the adapter case id and path patterns to adapter-case
    entries, the source case ones to source-case entries and the plain id pattern to every
    other entry, as the validator does."""
    entry = schema(mk)["$defs"]["entry"]
    ids = [s["$ref"] for s in entry["properties"]["id"]["anyOf"]]
    assert ids == ["#/$defs/id", "#/$defs/adapter_case_id", "#/$defs/source_case_id"]
    found = False
    for c in entry["allOf"]:
        if c.get("if", {}).get("properties", {}).get("kind", {}).get("const") != "adapter-case":
            continue
        found = True
        other = layout(c, "adapter-case", "#/$defs/adapter_case_id", "#/$defs/adapter_case_path")
        other = layout(other, "source-case", "#/$defs/source_case_id", "#/$defs/source_case_path")
        assert other is not None
        assert other["properties"]["id"]["$ref"] == "#/$defs/id"
    assert found, "no allOf condition on kind adapter-case in $defs/entry"


def run_main(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "hop_top_pact.runner.manifest", *args],
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_main_check_repo(mk: Any) -> None:
    proc = run_main("check", str(mk.repo_fixtures()), str(mk.REPO_SPEC_MAP))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("manifest check: ok ("), proc.stdout


def test_main_check_problems(mk: Any) -> None:
    """Exit status 1 and one line per problem that starts with [rule-id], the contract of
    scripts/check-manifest-parity.py --checker."""
    tr = mk.new_tree()
    tr.write("keys/issuer.jwk.json", "{}")
    es = mk.base_entries()
    es[1]["kind"] = "evaluation"
    tr.write("manifest.json", mk.encode(es).decode("utf-8"))
    proc = run_main("check", str(tr.root), str(tr.spec_map))
    assert proc.returncode == 1, proc.stderr
    assert proc.stdout == ""
    lines = proc.stderr.splitlines()
    assert lines[0] == "manifest check: 2 problem(s)", proc.stderr
    assert lines[1:] == [
        '[entry-kind] admission/valid: kind "evaluation" is not one of [key vector schema'
        " evaluate outcomes learning adapter-case adapter-asset source-case profile-invalid"
        " transport mcp profile]",
        "[file-uncovered] keys/issuer.jwk.json: no manifest entry covers this file: add one,"
        " or put it inside an entry's path",
    ]


def test_main_usage(mk: Any) -> None:
    tr = mk.new_tree()
    for args in ((), ("check",), ("check", str(tr.root)), ("verify", str(tr.root), "x")):
        proc = run_main(*args)
        assert proc.returncode == 2, args
        assert proc.stdout == "", args
        assert "usage: python -m hop_top_pact.runner.manifest check ROOT SPECMAP" in proc.stderr
    proc = run_main("check", str(tr.root), str(tr.spec_map), "extra")
    assert proc.returncode == 2
