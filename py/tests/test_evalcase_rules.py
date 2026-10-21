"""The generator-contract rules of the evaluation-case loader: test keys, signing.json,
decoded files and presentations. Port of go/runner/evalcase/rules_test.go."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact import conformance
from hop_top_pact.core.jws import TYP_PRESENTATION, TYP_REQUIREMENTS

VALID = "admission/valid"
WEAKER = "selection/agent-requests-weaker-set"


def test_load_keys_checks_public_files(ec: Any) -> None:
    """A public JWK file that is not the public key of its role's private scalar stops
    load_keys."""
    keys = conformance.load_keys(ec.repo_fixtures())
    k = keys.get("issuer")
    assert k is not None
    assert k.role == "issuer"
    assert k.private is not None
    assert k.public.kid == "test-issuer-key-1"
    assert "ed25519" not in keys, "the Ed25519 pair is listed as an ES256 key"

    root = ec.copy_tree("keys")
    ec.write_file(
        ec.at(root, "keys/issuer.jwk.json"),
        ec.at(root, "keys/reputation-service.jwk.json").read_bytes(),
    )
    ec.fails(lambda: conformance.load_keys(root), "issuer.jwk.json", "role issuer")

    # The same kid on another public point is no better.
    root = ec.copy_tree("keys")
    other = (
        ec.at(root, "keys/reputation-service.jwk.json")
        .read_bytes()
        .replace(b"test-reputation-service-key-1", b"test-issuer-key-1", 1)
    )
    assert b"reputation" not in other, f"kid not replaced: {other!r}"
    ec.write_file(ec.at(root, "keys/issuer.jwk.json"), other)
    ec.fails(lambda: conformance.load_keys(root), "issuer.jwk.json", "role issuer")


def test_stale_carried_payload(ec: Any) -> None:
    """Under payload_signed the signature covers one file and the JWS carries another; a
    JWS whose carried payload is not the decoded file is stale although its signature
    still verifies over the covered file."""
    root = ec.case_tree(WEAKER)
    conformance.load(root, WEAKER)
    ec.edit_json(root, WEAKER + "/contract.json", lambda m: m.update(zz_extra=1))
    ec.fails(lambda: conformance.load(root, WEAKER), WEAKER, "signed/contract.jws", "stale")


def _artifact(i: int, **kv: Any) -> Callable[[dict[str, Any]], None]:
    return lambda s: s["artifacts"][i].update(kv)


def _presentation(i: int, **kv: Any) -> Callable[[dict[str, Any]], None]:
    return lambda s: s["presentations"][i].update(kv)


def _no_jti(s: dict[str, Any]) -> None:
    del s["presentations"][0]["jti"]


DIRS_RULES: list[tuple[str, Callable[[Any, Path], None], tuple[str, ...]]] = [
    (
        "signed files without signing.json",
        lambda ec, root: ec.remove_file(ec.at(root, VALID + "/signing.json")),
        (VALID, "holds signed files", "no signing.json"),
    ),
    (
        "signed file no entry names",
        lambda ec, root: ec.write_file(ec.at(root, VALID + "/signed/extra.jws"), "x"),
        ("signed/extra.jws", "named by no entry"),
    ),
    (
        "artifacts absent",
        lambda ec, root: ec.write_file(
            ec.at(root, VALID + "/signing.json"), '{"presentations":[]}'
        ),
        ("artifacts is required",),
    ),
    (
        "unknown member",
        lambda ec, root: ec.edit_json(
            root, VALID + "/signing.json", lambda s: s.update(artifact=[])
        ),
        ("signing.json",),
    ),
    (
        "path leaving the case",
        lambda ec, root: ec.edit_json(
            root, VALID + "/signing.json", _artifact(0, decoded="../contract.json")
        ),
        ("artifacts[0]", "not a relative path"),
    ),
    (
        "presentation typ for an artifact",
        lambda ec, root: ec.edit_json(
            root, VALID + "/signing.json", _artifact(0, typ="pact-presentation+jwt")
        ),
        ("artifacts[0]", "typ"),
    ),
    (
        "digests naming a later entry",
        lambda ec, root: ec.edit_json(
            root, VALID + "/signing.json", _artifact(0, digests={"/x": "signed/reputation.jws"})
        ),
        ("artifacts[0]", "not the signed file of an earlier entry"),
    ),
    (
        "signed file named twice",
        lambda ec, root: ec.edit_json(
            root, VALID + "/signing.json", _presentation(0, signed="signed/contract.jws")
        ),
        ("presentations[0]", "named twice"),
    ),
    (
        "presentation without jti",
        lambda ec, root: ec.edit_json(root, VALID + "/signing.json", _no_jti),
        ("presentations[0]", "required"),
    ),
]


@pytest.mark.parametrize(
    ("mutate", "want"), [r[1:] for r in DIRS_RULES], ids=[r[0] for r in DIRS_RULES]
)
def test_dirs_rules(ec: Any, mutate: Callable[[Any, Path], None], want: tuple[str, ...]) -> None:
    """The directory rules of the generator contract (README section Generator
    contract: signing.json)."""
    root = ec.case_tree(VALID)
    conformance.dirs(root)
    mutate(ec, root)
    ec.fails(lambda: conformance.dirs(root), *want)


@pytest.mark.parametrize(
    ("seq", "want"),
    [
        ('{"exchanges":[],"subject":"exchanges/1"}', "exchanges is empty"),
        ('{"exchanges":["../x"],"subject":"../x"}', "not a relative path"),
    ],
    ids=["no exchanges", "exchange outside the case"],
)
def test_dirs_rules_sequence(ec: Any, seq: str, want: str) -> None:
    multi = "approval/approved-fresh-exchange"
    root = ec.case_tree(multi)
    ec.write_file(ec.at(root, multi + "/sequence.json"), seq)
    ec.fails(lambda: conformance.dirs(root), multi, "sequence.json", want)


def _append_newline(ec: Any, root: Path) -> None:
    p = ec.at(root, VALID + "/contract.json")
    ec.write_file(p, p.read_bytes() + b"\n")


def _two_snapshots(s: dict[str, Any]) -> None:
    s["artifacts"][1]["typ"] = "pact-reputation+jwt"


WALK_RULES: list[tuple[str, Callable[[Any, Path], None], tuple[str, ...]]] = [
    ("decoded not canonical", _append_newline, ("contract.json", "RFC 8785 canonical")),
    (
        "jti not the fixed one",
        lambda ec, root: ec.edit_json(root, VALID + "/signing.json", _artifact(1, jti="other")),
        ("evidence/runtime.json", "jti"),
    ),
    (
        "iat not the fixed one",
        lambda ec, root: ec.edit_json(root, VALID + "/signing.json", _artifact(1, iat=1792080001)),
        ("evidence/runtime.json", "iat"),
    ),
    (
        "exp not the stated one",
        lambda ec, root: ec.edit_json(root, VALID + "/signing.json", _artifact(1, exp=1)),
        ("evidence/runtime.json", "exp"),
    ),
    (
        "null decoded artifact",
        lambda ec, root: ec.write_file(ec.at(root, VALID + "/reputation.json"), "null"),
        ("reputation.json is null",),
    ),
    (
        "no test key for the signer",
        lambda ec, root: ec.edit_json(root, VALID + "/signing.json", _artifact(0, signer="nobody")),
        ("contract.json", "no test key for role nobody"),
    ),
    (
        "two snapshots and no reputation named",
        lambda ec, root: ec.edit_json(root, VALID + "/signing.json", _two_snapshots),
        ("signed/presentation.jws", "2 snapshot artifacts"),
    ),
]


@pytest.mark.parametrize(
    ("mutate", "want"), [r[1:] for r in WALK_RULES], ids=[r[0] for r in WALK_RULES]
)
def test_walk_rules(ec: Any, mutate: Callable[[Any, Path], None], want: tuple[str, ...]) -> None:
    """The decoded-file and presentation rules of the generator contract, applied by
    walk whatever the signed files hold."""
    root = ec.case_tree(VALID)
    mutate(ec, root)
    keys = conformance.load_keys(root)
    d = conformance.dirs(root)[0]
    ec.fails(lambda: conformance.walk(root, d, keys, lambda f: f.sign()), *want)


def test_walk_files(ec: Any) -> None:
    """walk hands over each signed file with its typ, key, payload and signed bytes, and
    a fresh signature passes File.check."""
    fixtures = ec.repo_fixtures()
    keys = conformance.load_keys(fixtures)
    d = next((d for d in conformance.dirs(fixtures) if d.id == WEAKER), None)
    assert d is not None
    dir = ec.at(fixtures, d.path)
    seen: list[str] = []

    def sign(f: conformance.File) -> str:
        seen.append(f.signed)
        if f.signed == "signed/contract.jws":
            # payload_signed: the JWS carries contract.json, the signature covers the
            # file payload_signed names.
            assert (f.typ, f.key.role, f.decoded) == (TYP_REQUIREMENTS, "issuer", "contract.json")
            assert f.payload == (dir / "contract.json").read_bytes()
            assert f.over != f.payload
        elif f.signed == "signed/presentation.jws":
            assert (f.typ, f.key.role, f.decoded) == (TYP_PRESENTATION, "holder", "")
            assert f.over == f.payload
        f.check(f.sign())
        committed = str(ec.at(dir, f.signed).read_text(encoding="ascii"))
        f.check(committed)
        return committed

    conformance.walk(fixtures, d, keys, sign)
    assert len(seen) == len(d.signing.artifacts) + len(d.signing.presentations)


def _walk_payloads(root: Path, id: str) -> dict[str, bytes]:
    keys = conformance.load_keys(root)
    d = next((d for d in conformance.dirs(root) if d.id == id), None)
    assert d is not None, f"dirs lists no {id}"
    out: dict[str, bytes] = {}

    def sign(f: conformance.File) -> str:
        out[f.signed] = f.payload
        return f.sign()

    conformance.walk(root, d, keys, sign)
    return out


def _extra_evidence(name: str) -> dict[str, Any]:
    return {
        "decoded": f"evidence/{name}.json",
        "signed": f"signed/evidence/{name}.jws",
        "typ": "pact-evidence+jwt",
        "signer": "issuer",
        "jti": f"{name}-jti",
    }


def test_presentation_embeds_evidence_in_order(ec: Any) -> None:
    """Without an evidence member, the presentation embeds the compact evidence
    artifacts in signing.json order."""
    root = ec.case_tree(VALID)
    for name in ("extra-a", "extra-b"):
        ec.write_file(
            ec.at(root, f"{VALID}/evidence/{name}.json"),
            f'{{"iat":1792080000,"jti":"{name}-jti","nbf":1792080000}}',
        )
    ec.edit_json(
        root,
        VALID + "/signing.json",
        lambda s: s["artifacts"].extend([_extra_evidence("extra-a"), _extra_evidence("extra-b")]),
    )
    keys = conformance.load_keys(root)
    d = next(d for d in conformance.dirs(root) if d.id == VALID)
    signed: dict[str, str] = {}
    got: list[str] = []

    def sign(f: conformance.File) -> str:
        c = f.sign()
        signed[f.signed] = c
        if f.typ == TYP_PRESENTATION:
            got.extend(json.loads(f.payload)["evidence"])
        return c

    conformance.walk(root, d, keys, sign)
    assert got == [
        signed["signed/evidence/runtime.jws"],
        signed["signed/evidence/extra-a.jws"],
        signed["signed/evidence/extra-b.jws"],
    ], "presentation evidence is not the artifacts in signing.json order"


@pytest.mark.parametrize(
    ("ptr", "want"),
    [
        ("/extra", ""),
        ("/list/1", ""),
        ("/list/2", "no array element"),
        ("/list/01", "no array element"),
        ("/absent/x", "no member"),
        ("/name/x", "not an object or array"),
    ],
    ids=[
        "new member",
        "array element",
        "array element out of range",
        "array element with a leading zero",
        "missing step",
        "inside a string",
    ],
)
def test_digest_pointers(ec: Any, ptr: str, want: str) -> None:
    """The digests of an artifact entry set a member of an object or replace an element
    of an array, and name nothing else."""
    root = ec.case_tree(VALID)
    ec.write_file(
        ec.at(root, VALID + "/evidence/extra.json"),
        '{"iat":1792080000,"jti":"extra-jti","list":[1,2],"name":"n","nbf":1792080000}',
    )
    entry = _extra_evidence("extra") | {"digests": {ptr: "signed/contract.jws"}}
    ec.edit_json(root, VALID + "/signing.json", lambda s: s["artifacts"].append(entry))
    if want:
        ec.fails(lambda: _walk_payloads(root, VALID), "evidence/extra.json", ptr, want)
        return
    m = json.loads(_walk_payloads(root, VALID)["signed/evidence/extra.jws"])
    if ptr == "/extra":
        assert isinstance(m["extra"], str), m
        assert len(m["extra"]) == 43, m
    else:
        assert m["list"][0] == 1, m
        assert isinstance(m["list"][1], str), m
