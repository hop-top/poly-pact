"""runner.manifest: the entry fields conformance_profile, transport and layer, and the
testdata manifests. Port of go/runner/manifest/fields_test.go."""

from __future__ import annotations

from typing import Any

import pytest

from hop_top_pact.core import strictjson
from hop_top_pact.runner import manifest

EV = 1  # the evaluate entry of the base entries
KEY = 2


def test_entry_field_vocabulary() -> None:
    """The tokens of the entry fields conformance_profile, transport and layer, and the
    kinds transport, mcp and profile (spec/v1.0/fixtures/README.md, Manifest entry fields)."""
    assert manifest.conformance_profiles() == ["full", "single-owner"]
    assert manifest.transports() == ["https", "stdio-ipc"]
    assert manifest.layers() == ["transcript", "os"]
    for k, want in {
        manifest.Kind.TRANSPORT: "transport",
        manifest.Kind.MCP: "mcp",
        manifest.Kind.PROFILE: "profile",
    }.items():
        assert k.value == want
        assert manifest.Kind.known(k)
        assert k.has_expected()
    # A source case carries its expectations inline and has no expected file or
    # outcome, as a key or an adapter asset; its scope is adapter.
    k = manifest.Kind.SOURCE_CASE
    assert k.value == "source-case"
    assert manifest.Kind.known(k)
    assert not k.has_expected()
    assert k.required_scope() == manifest.Scope.ADAPTER
    assert manifest.DEFAULT_CONFORMANCE_PROFILE == "full"
    assert manifest.DEFAULT_TRANSPORT == "https"


def registry(mk: Any) -> list[dict[str, Any]]:
    mk.repo_fixtures()
    data = (mk.REPO / "spec" / "v1.0" / "profiles" / "registry.json").read_bytes()
    reg = strictjson.parse(data)
    assert isinstance(reg, tuple)
    return [dict(e) for e in reg if isinstance(e, dict)]


def test_registry_conformance_profiles(mk: Any) -> None:
    """The conformance profile tokens are the entries of kind conformance in
    spec/v1.0/profiles/registry.json, in file order."""
    ids = [e["id"] for e in registry(mk) if e.get("kind") == "conformance"]
    assert manifest.conformance_profiles() == ids


def test_transport_profiles(mk: Any) -> None:
    """The transport tokens are the transport profile ids of claim.transport in
    spec/v1.0/profiles/integration-profile.schema.json, the baseline https and the entries of
    kind transport in spec/v1.0/profiles/registry.json (draft Section 21)."""
    mk.repo_fixtures()
    data = (mk.REPO / "spec" / "v1.0" / "profiles" / "integration-profile.schema.json").read_bytes()
    schema = strictjson.parse(data)
    assert isinstance(schema, dict)
    claim_enum: list[str] | None = None
    for d in schema["$defs"].values():
        tp = d.get("properties", {}).get("transport_profile")
        if tp is not None and "enum" in tp:
            claim_enum = list(tp["enum"])
    assert manifest.transports() == claim_enum
    want = [manifest.TRANSPORT_HTTPS]
    want += [e["id"] for e in registry(mk) if e.get("kind") == "transport"]
    assert manifest.transports() == want


def test_entry_field_defaults(mk: Any) -> None:
    """An absent conformance_profile means ["full"] and an absent transport ["https"]; the
    members as written are kept apart from the values that apply."""
    es = mk.base_entries()
    es[1]["conformance_profile"] = ["single-owner"]
    es[1]["transport"] = ["stdio-ipc", "https"]
    es[1]["layer"] = "transcript"
    m = mk.parse(mk.encode(es))
    mk.want_clean(m.validate())

    e = m.entries[1]
    assert e.conformance_profile == ("single-owner",)
    assert e.transport == ("stdio-ipc", "https")
    assert e.layer == "transcript"
    assert e.conformance_profiles() == ["single-owner"]
    assert e.transports() == ["stdio-ipc", "https"]

    d = m.entries[2]
    assert d.conformance_profile is None
    assert d.transport is None
    assert d.layer == ""
    assert d.conformance_profiles() == ["full"]
    assert d.transports() == ["https"]
    # The defaults are fresh lists: a caller cannot change them.
    d.conformance_profiles()[0] = "x"
    d.transports()[0] = "x"
    assert d.conformance_profiles()[0] == "full"
    assert d.transports()[0] == "https"
    # The vocabularies are fresh lists too.
    manifest.kinds()[0] = "x"
    manifest.outcomes()[0] = "x"
    assert manifest.kinds()[0] == "key"
    assert manifest.outcomes()[0] == "ADMISSIBLE"


def with_(i: int, **members: Any) -> dict[str, Any]:
    return {"i": i, "members": members}


ENTRY_FIELDS: dict[str, tuple[str, dict[str, Any]]] = {
    "profile a string": (manifest.RULE_SHAPE, with_(EV, conformance_profile="full")),
    "profile null": (manifest.RULE_SHAPE, with_(EV, conformance_profile=None)),
    "profile item a number": (manifest.RULE_SHAPE, with_(EV, conformance_profile=[1])),
    "profile empty": (manifest.RULE_CONFORMANCE_PROFILE, with_(EV, conformance_profile=[])),
    "profile lite": (manifest.RULE_CONFORMANCE_PROFILE, with_(EV, conformance_profile=["lite"])),
    "profile upper case": (
        manifest.RULE_CONFORMANCE_PROFILE,
        with_(EV, conformance_profile=["FULL"]),
    ),
    "profile repeated": (
        manifest.RULE_CONFORMANCE_PROFILE,
        with_(EV, conformance_profile=["full", "full"]),
    ),
    "profile on a key": (
        manifest.RULE_CONFORMANCE_PROFILE,
        with_(KEY, conformance_profile=["single_owner"]),
    ),
    "transport a string": (manifest.RULE_SHAPE, with_(EV, transport="https")),
    "transport item null": (manifest.RULE_SHAPE, with_(EV, transport=[None])),
    "transport empty": (manifest.RULE_TRANSPORT, with_(EV, transport=[])),
    "transport tcp": (manifest.RULE_TRANSPORT, with_(EV, transport=["tcp"])),
    # Channels are not transport profiles: no http, stdio or ipc.
    "transport http": (manifest.RULE_TRANSPORT, with_(EV, transport=["http"])),
    "transport stdio": (manifest.RULE_TRANSPORT, with_(EV, transport=["stdio"])),
    "transport ipc": (manifest.RULE_TRANSPORT, with_(EV, transport=["ipc"])),
    "transport upper case": (manifest.RULE_TRANSPORT, with_(EV, transport=["HTTPS"])),
    "transport with a version": (manifest.RULE_TRANSPORT, with_(EV, transport=["stdio-ipc/0.1"])),
    "transport repeated": (
        manifest.RULE_TRANSPORT,
        with_(EV, transport=["stdio-ipc", "stdio-ipc"]),
    ),
    "layer a number": (manifest.RULE_SHAPE, with_(EV, transport=["stdio-ipc"], layer=1)),
    "layer network": (manifest.RULE_LAYER, with_(EV, transport=["stdio-ipc"], layer="network")),
    "layer empty": (manifest.RULE_LAYER, with_(EV, transport=["stdio-ipc"], layer="")),
    "layer on https": (manifest.RULE_LAYER, with_(EV, transport=["https"], layer="transcript")),
    "layer without transport": (manifest.RULE_LAYER, with_(EV, layer="os")),
    "transport kind no layer": (
        manifest.RULE_LAYER,
        with_(EV, kind="transport", transport=["stdio-ipc"]),
    ),
    "transport kind on https": (manifest.RULE_LAYER, with_(EV, kind="transport")),
    "transport kind in core": (
        manifest.RULE_SCOPE,
        with_(EV, kind="transport", scope="core", transport=["stdio-ipc"], layer="os"),
    ),
    "transport kind adapter": (
        manifest.RULE_SCOPE,
        with_(EV, kind="transport", scope="adapter", transport=["stdio-ipc"], layer="os"),
    ),
    "profile kind in core": (manifest.RULE_SCOPE, with_(EV, kind="profile", scope="core")),
    "profile kind in adapter": (manifest.RULE_SCOPE, with_(EV, kind="profile", scope="adapter")),
    "mcp kind in core": (manifest.RULE_SCOPE, with_(EV, kind="mcp", scope="core")),
    "mcp kind in runner scope": (manifest.RULE_SCOPE, with_(EV, kind="mcp", scope="runner")),
}


@pytest.mark.parametrize(("rule", "edit"), ENTRY_FIELDS.values(), ids=ENTRY_FIELDS)
def test_validate_entry_fields(mk: Any, rule: str, edit: dict[str, Any]) -> None:
    """Breaks one field rule of conformance_profile, transport, layer or the scope of the
    new kinds at a time."""
    es = mk.base_entries()
    es[edit["i"]].update(edit["members"])
    where = "keys/holder" if edit["i"] == KEY else "admission/valid"
    mk.want_rule(mk.parse(mk.encode(es)).validate(), rule, where)


ACCEPTS_ENTRY_FIELDS: dict[str, dict[str, Any]] = {
    "full": {"conformance_profile": ["full"]},
    "single-owner": {"conformance_profile": ["single-owner"]},
    "both profiles": {"conformance_profile": ["single-owner", "full"]},
    "https": {"transport": ["https"]},
    "stdio-ipc": {"transport": ["stdio-ipc"]},
    "stdio-ipc os": {"transport": ["stdio-ipc"], "layer": "os"},
    "both, transcript": {"transport": ["https", "stdio-ipc"], "layer": "transcript"},
    "both, os": {"transport": ["stdio-ipc", "https"], "layer": "os"},
    "transport kind": {
        "kind": "transport",
        "scope": "runner",
        "transport": ["stdio-ipc"],
        "layer": "transcript",
    },
    "profile kind": {"kind": "profile", "scope": "runner", "conformance_profile": ["single-owner"]},
    "mcp kind": {"kind": "mcp", "scope": "adapter"},
    "stdio-ipc, no layer": {"transport": ["stdio-ipc"]},
    "every field at once": {
        "conformance_profile": ["full", "single-owner"],
        "transport": ["stdio-ipc"],
        "layer": "transcript",
        "capabilities": ["jws-ed25519"],
    },
}


@pytest.mark.parametrize("members", ACCEPTS_ENTRY_FIELDS.values(), ids=ACCEPTS_ENTRY_FIELDS)
def test_validate_accepts_entry_fields(mk: Any, members: dict[str, Any]) -> None:
    """Every token of each field, a layer on every entry whose transport has stdio-ipc, and
    each new kind in its scope."""
    es = mk.base_entries()
    es[1].update(members)
    mk.want_clean(mk.parse(mk.encode(es)).validate())


def test_testdata_manifests(mk: Any) -> None:
    """Each test manifest of spec/v1.0/fixtures/testdata/manifest breaks exactly the field rules
    its index case lists, and a valid one none."""
    d = mk.repo_fixtures() / "testdata" / "manifest"
    idx = strictjson.parse((d / "index.json").read_bytes())
    assert isinstance(idx, dict)
    assert set(idx) == {"description", "schema", "cases"}
    cases = idx["cases"]
    valid = invalid = 0
    files = set()
    for c in cases:
        assert set(c) <= {"file", "valid", "reason", "schema_errors", "rules"}, c
        files.add(c["file"])
        if c["valid"]:
            valid += 1
        else:
            invalid += 1
        m = manifest.parse((d / c["file"]).read_bytes())
        got = mk.rules(m.validate())
        want = sorted(c.get("rules") or [])
        assert got == want, f"{c['file']}: rules {got}, want {want} ({c.get('reason')})"
        assert c["valid"] == (not want and not c.get("schema_errors")), c["file"]
    assert (valid, invalid) == (4, 9)
    for f in d.iterdir():
        assert f.name == "index.json" or f.name in files, f"{f.name} is not in index.json"


def test_completeness_testdata(mk: Any) -> None:
    """Files under testdata/ at the top of the fixture directory are the test data of the
    checks, not fixtures, and need no entry; a testdata directory anywhere else does."""
    tr = mk.new_tree()
    tr.write("testdata/manifest/valid-defaults.json", "{}")
    tr.write("testdata/manifest/index.json", "{}")
    mk.want_clean(manifest.completeness(tr.root, tr.manifest()))

    tr.write("keys/testdata/x.json", "{}")
    mk.want_rule(
        manifest.completeness(tr.root, tr.manifest()),
        manifest.RULE_UNCOVERED,
        "keys/testdata/x.json",
    )

    tr = mk.new_tree()
    tr.write("testdata/manifest/notes.txt", "x")
    mk.want_rule(
        manifest.completeness(tr.root, tr.manifest()),
        manifest.RULE_EXTENSION,
        "testdata/manifest/notes.txt",
    )
