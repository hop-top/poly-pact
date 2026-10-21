"""The vectors entry point, ``python -m hop_top_pact.vectors``, as a process.

Against the repository manifest when it is present (required under
PACT_REQUIRE_VECTORS=1, as make py-test sets it), and against small
manifests for the entry handling and the failure paths. The groups the
harness runs are tested in-process in test_vectors_groups.py.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.vectors import RUN_KINDS

PY_ROOT = Path(__file__).resolve().parents[1]
REPO = PY_ROOT.parent
REPO_MANIFEST = REPO / "spec" / "v1.0" / "fixtures" / "manifest.json"
REPO_GATES = REPO / "tools" / "parity" / "gates.json"
RESULTS = {"pass", "fail", "skipped:out-of-scope", "skipped:spec-defect", "skipped:capability"}


def run(*args: str, cwd: Path = PY_ROOT, env: dict[str, str] | None = None) -> Any:
    return subprocess.run(
        [sys.executable, "-m", "hop_top_pact.vectors", *args],
        cwd=cwd,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        check=False,
    )


def write_manifest(path: Path, entries: list[dict[str, Any]]) -> Path:
    path.write_text(json.dumps({"manifest_version": 1, "entries": entries}), encoding="utf-8")
    return path


def entry(eid: str, kind: str = "evaluate", scope: str = "runner") -> dict[str, Any]:
    return {
        "id": eid,
        "kind": kind,
        "scope": scope,
        "path": eid,
        "expected": None,
        "outcome": None,
        "spec_map_row": "R01",
        "draft_section": "1",
    }


def prefix(eid: str) -> str:
    segs = eid.split("/")
    return "/".join(segs[:2]) if segs[0] in ("vectors", "adapters", "sources") else segs[0]


def repo_manifest() -> dict[str, Any]:
    if not REPO_MANIFEST.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{REPO_MANIFEST} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    doc: dict[str, Any] = json.loads(REPO_MANIFEST.read_text(encoding="utf-8"))
    return doc


def out_of_scope(e: dict[str, Any]) -> bool:
    """The entries the harness does not run, independently of the harness code. The
    common adapter cases run against the memory adapter."""
    if e["kind"] == "adapter-case" and e["scope"] == "adapter":
        return not e["id"].startswith("adapters/_common/")
    if e["scope"] == "runner" or e["kind"] not in ("vector", "key"):
        return True
    # The key rule leaves the Ed25519 key out: the algorithm is optional
    # (draft section 7.2).
    if e["kind"] == "key" and e["path"].endswith(".jwk.json"):
        jwk = json.loads((REPO_MANIFEST.parent / e["path"]).read_text(encoding="utf-8"))
        return bool(jwk.get("kty") == "OKP")
    return False


def test_run_kinds() -> None:
    assert RUN_KINDS == ("vector", "key")


def test_repository_manifest() -> None:
    manifest = repo_manifest()
    proc = run()
    assert proc.returncode in (0, 1), proc.stderr
    lines = [json.loads(line) for line in proc.stdout.splitlines()]
    assert [(x["id"], x["kind"]) for x in lines] == [
        (e["id"], e["kind"]) for e in manifest["entries"]
    ]
    for line, e in zip(lines, manifest["entries"], strict=True):
        assert line["result"] in RESULTS, line
        want = {"id", "kind", "result"}
        if line["result"] == "skipped:spec-defect":
            want.add("spec_defects")
        if line["result"] == "skipped:capability":
            want.add("missing_capabilities")
        assert set(line) == want, line
        if out_of_scope(e):
            assert line["result"] == "skipped:out-of-scope", line
        else:
            assert line["result"] != "skipped:out-of-scope", line
    in_scope = [e for e in manifest["entries"] if not out_of_scope(e)]
    # Every vector and key entry of scope core and adapter, binding included.
    assert {prefix(e["id"]) for e in in_scope} >= {"keys", "vectors/binding", "vectors/jws"}
    assert "summary:" not in proc.stdout
    assert proc.stderr.rstrip("\n").splitlines()[-1].startswith("vectors: ")


def test_repository_exit_status_follows_py_gates() -> None:
    """Status 1 exactly when a fail line sits under a gate required for py."""
    repo_manifest()
    if not REPO_GATES.exists():
        pytest.skip("no tools/parity/gates.json")
    gates = json.loads(REPO_GATES.read_text(encoding="utf-8"))
    required = {
        (r["scope"], r["kind"], r["prefix"]): {x["id"] for x in r.get("exceptions", [])}
        for r in gates["rows"]
        if r["py"] == "required"
    }
    scope = {e["id"]: e["scope"] for e in repo_manifest()["entries"]}
    proc = run()
    blocking = []
    for line in map(json.loads, proc.stdout.splitlines()):
        row = (scope[line["id"]], line["kind"], prefix(line["id"]))
        if line["result"] == "fail" and row in required and line["id"] not in required[row]:
            blocking.append(line["id"])
    assert proc.returncode == (1 if blocking else 0), proc.stderr


CORE_PRIMITIVES = ("vectors/strictjson", "vectors/jcs", "vectors/digest", "vectors/schema")


def test_repository_core_primitive_vectors_pass() -> None:
    """Every strictjson, jcs, digest and schema entry passes (none is flagged)."""
    manifest = repo_manifest()
    want = {e["id"] for e in manifest["entries"] if prefix(e["id"]) in CORE_PRIMITIVES}
    assert {prefix(i) for i in want} == set(CORE_PRIMITIVES)
    proc = run()
    got = {
        line["id"]: line["result"]
        for line in map(json.loads, proc.stdout.splitlines())
        if line["id"] in want
    }
    assert got == dict.fromkeys(want, "pass"), proc.stderr


def test_repository_jws_and_key_entries_pass() -> None:
    """Every vectors/jws and keys entry passes, except the Ed25519 key (out of scope)."""
    manifest = repo_manifest()
    want = {
        e["id"]: "skipped:out-of-scope" if out_of_scope(e) else "pass"
        for e in manifest["entries"]
        if prefix(e["id"]) in ("vectors/jws", "keys")
    }
    assert "keys/ed25519" in want
    assert want["keys/ed25519"] == "skipped:out-of-scope"
    proc = run()
    got = {
        line["id"]: line["result"]
        for line in map(json.loads, proc.stdout.splitlines())
        if line["id"] in want
    }
    assert got == want, proc.stderr


def test_out_of_scope_entries(tmp_path: Path) -> None:
    m = write_manifest(
        tmp_path / "m.json",
        [
            entry("admission/a"),
            entry("adapters/oauth/c", "adapter-case", "adapter"),
            entry("schema/s", "schema", "core"),
            entry("reputation/r", "vector", "runner"),
            {**entry("admission/e"), "capabilities": ["jws-ed25519"]},
        ],
    )
    proc = run(str(m))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [
        '{"id":"admission/a","kind":"evaluate","result":"skipped:out-of-scope"}',
        '{"id":"adapters/oauth/c","kind":"adapter-case","result":"skipped:out-of-scope"}',
        '{"id":"schema/s","kind":"schema","result":"skipped:out-of-scope"}',
        '{"id":"reputation/r","kind":"vector","result":"skipped:out-of-scope"}',
        '{"id":"admission/e","kind":"evaluate","result":"skipped:out-of-scope"}',
    ]
    assert "0 passed, 0 failed, 5 skipped (out-of-scope 5" in proc.stderr


@pytest.mark.parametrize(
    ("entries", "needle"),
    [
        ([entry("a/1", kind="vectors")], '[entry-kind] a/1: kind "vectors"'),
        ([entry("a/1", scope="sdk")], '[entry-scope] a/1: scope "sdk"'),
        ([entry("a/1", "transport", "core")], '[entry-scope] a/1: scope "core"'),
        ([entry("a/1"), entry("a/1")], "[entry-id-duplicate] a/1"),
        ([entry("A/1")], '[entry-id] A/1: id "A/1"'),
        ([{**entry("a/1"), "id": 1}], "[manifest-shape] entries[1]: id is number"),
        ([{k: v for k, v in entry("a/1").items() if k != "kind"}], "[manifest-shape] a/1: no kind"),
        ([entry("vectors/nope/x", "vector", "core")], "unknown prefix 'vectors/nope'"),
        ([entry("vectors/x", "vector", "core")], "unknown prefix 'vectors/x'"),
        ([entry("binding/x", "vector", "adapter")], "unknown prefix 'binding'"),
        ([entry("keyz/x", "key", "core")], "unknown prefix 'keyz'"),
        ([entry("vectors/jcs/x", "key", "core")], "unknown prefix 'vectors/jcs'"),
        (
            [{**entry("a/1"), "capabilities": ["jws-rsa"]}],
            '[entry-capabilities] a/1: capabilities[0] "jws-rsa"',
        ),
        (
            [{**entry("a/1"), "capabilities": "jws-ed25519"}],
            "[manifest-shape] a/1: capabilities is string",
        ),
        ([{**entry("a/1"), "path": 1}], "[manifest-shape] a/1: path is number"),
    ],
)
def test_harness_errors(tmp_path: Path, entries: list[dict[str, Any]], needle: str) -> None:
    m = write_manifest(tmp_path / "m.json", [entry("ok/0"), *entries])
    proc = run(str(m))
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert needle in proc.stderr


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        ('{"manifest_version": 1, "entries": [], "entries": []}', "[manifest-json] manifest.json"),
        ('{"manifest_version": 1, "entries": [], "x": NaN}', "[manifest-json] manifest.json"),
        ("[]", "[manifest-json] manifest.json"),
        ('{"manifest_version": 2, "entries": []}', "[manifest-shape] manifest.json"),
        ('{"manifest_version": 1, "entries": {}}', "[manifest-shape] manifest.json"),
    ],
)
def test_malformed_manifest(tmp_path: Path, text: str, needle: str) -> None:
    """The manifest is read through runner.manifest: its strict parse, then its shape."""
    m = tmp_path / "m.json"
    m.write_text(text, encoding="utf-8")
    proc = run(str(m))
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert needle in proc.stderr


def test_other_field_rules_are_not_harness_errors(tmp_path: Path) -> None:
    """Only the rules of the members the harness reads stop it; the order, path, row and
    section rules belong to the manifest check (make spec-manifest, pactfix check manifest)."""
    m = write_manifest(
        tmp_path / "m.json",
        [
            {**entry("z/1"), "draft_section": "x", "spec_map_row": "x"},
            {**entry("a/1"), "path": "../a"},
        ],
    )
    proc = run(str(m))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines() == [
        '{"id":"z/1","kind":"evaluate","result":"skipped:out-of-scope"}',
        '{"id":"a/1","kind":"evaluate","result":"skipped:out-of-scope"}',
    ]


def test_default_manifest_absent(tmp_path: Path) -> None:
    cwd = tmp_path / "py"
    cwd.mkdir()
    proc = run(cwd=cwd, env={"PACT_REQUIRE_VECTORS": ""})
    assert proc.returncode == 0
    assert proc.stdout == ""
    assert "NOTICE" in proc.stderr
    proc = run(cwd=cwd, env={"PACT_REQUIRE_VECTORS": "1"})
    assert proc.returncode == 2
    assert proc.stdout == ""


def test_explicit_manifest_absent(tmp_path: Path) -> None:
    proc = run(str(tmp_path / "missing.json"), env={"PACT_REQUIRE_VECTORS": ""})
    assert proc.returncode == 2
    assert proc.stdout == ""


def test_usage() -> None:
    assert run("a", "b").returncode == 2
    assert run("--ndjson").returncode == 2
