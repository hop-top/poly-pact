"""The groups of the vectors harness, in-process, over small fixture trees.

Each test writes a manifest and its files under tmp_path/spec/v1.0/fixtures,
replaces the core functions the harness calls with fakes (RFC 8785 through
the rfc8785 oracle, SHA-256 digests through hashlib, keys through
cryptography) and checks the line the harness prints. With the stubs in
place (the groups whose package functions are not implemented yet, and the
implemented ones replaced by stubs) every run entry fails, and a stub's
NotImplementedError never counts as a rejection.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric import ec
from jsonschema import FormatChecker  # type: ignore[import-untyped]

from hop_top_pact.core import binding, digest, jcs, jws, limits, schema, strictjson
from hop_top_pact.core.types import JSONValue, OperationContext
from hop_top_pact.vectors.__main__ import main

# The P-256 base point (scalar 1), the holder key of draft Appendix C, and
# its RFC 7638 thumbprint, the Appendix C holder_jkt.
G_X = "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY"
G_Y = "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
HOLDER_JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
D1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"
EMPTY_DIGEST = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def sha(b: bytes) -> str:
    return b64u(hashlib.sha256(b).digest())


def oracle(data: bytes) -> bytes:
    return rfc8785.dumps(json.loads(data))


def oracle_digest(value: JSONValue) -> str:
    return sha(rfc8785.dumps(value))


def fake_parse_jwk(data: bytes) -> jws.JWK:
    m = json.loads(data)
    if "d" in m:
        raise jws.JWSError(jws.Reason.JWK_PRIVATE)
    names = ("kty", "crv", "x", "y", "kid", "alg", "use")
    return jws.JWK(**{k: m[k] for k in names if k in m})


def fake_public_jwk(key: ec.EllipticCurvePublicKey) -> jws.JWK:
    n = key.public_numbers()
    return jws.JWK(
        kty="EC", crv="P-256", x=b64u(n.x.to_bytes(32, "big")), y=b64u(n.y.to_bytes(32, "big"))
    )


def fake_thumbprint(k: jws.JWK) -> str:
    return sha(
        json.dumps({"crv": k.crv, "kty": k.kty, "x": k.x, "y": k.y}, separators=(",", ":")).encode()
    )


def fake_reason_of(err: BaseException | None) -> jws.Reason | None:
    return err.reason if isinstance(err, jws.JWSError) else None


@dataclass
class Run:
    code: int
    lines: list[dict[str, Any]]
    stderr: str

    def result(self, eid: str) -> str:
        return str(self.by_id(eid)["result"])

    def by_id(self, eid: str) -> dict[str, Any]:
        (line,) = [x for x in self.lines if x["id"] == eid]
        return line


@dataclass
class Tree:
    root: Path
    capsys: pytest.CaptureFixture[str]
    entries: list[dict[str, Any]] = field(default_factory=list)

    @property
    def fixtures(self) -> Path:
        return self.root / "spec" / "v1.0" / "fixtures"

    def file(self, rel: str, content: Any) -> str:
        p = self.fixtures / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        elif isinstance(content, str):
            p.write_text(content, encoding="utf-8")
        else:
            p.write_text(json.dumps(content, indent=2), encoding="utf-8")
        return rel

    def add(
        self,
        eid: str,
        kind: str,
        scope: str,
        path: str,
        expected: str | None,
        outcome: str | None,
        **extra: Any,
    ) -> str:
        self.entries.append(
            {
                "id": eid,
                "kind": kind,
                "scope": scope,
                "path": path,
                "expected": expected,
                "outcome": outcome,
                "spec_map_row": "X",
                "draft_section": "1",
                **extra,
            }
        )
        return eid

    def vector(self, eid: str, content: Any, outcome: str, scope: str = "core") -> str:
        rel = self.file(eid + ".json", content)
        return self.add(eid, "vector", scope, rel, rel, outcome)

    def gates(self, rows: list[dict[str, Any]]) -> None:
        p = self.root / "tools" / "parity" / "gates.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"gates_version": 1, "rows": rows}), encoding="utf-8")

    def run(self) -> Run:
        m = self.fixtures / "manifest.json"
        m.parent.mkdir(parents=True, exist_ok=True)
        m.write_text(json.dumps({"manifest_version": 1, "entries": self.entries}), encoding="utf-8")
        self.capsys.readouterr()
        code = main([str(m)])
        out, err = self.capsys.readouterr()
        return Run(code, [json.loads(line) for line in out.splitlines()], err)


@pytest.fixture
def tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Tree:
    return Tree(tmp_path, capsys)


# Vector documents, in the formats of spec/v1.0/fixtures/vectors/README.md.


def strictjson_vector(eid: str, text: str, expect: str) -> dict[str, Any]:
    return {"id": eid, "input_text": text, "expect": expect, "reason": "why"}


def binding_vector(eid: str, accept: bool, ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": eid,
        "description": "d",
        "config": {
            "origin": "https://gw.example",
            "header_allowlist": ["x-a"],
            "normalization_id": "n-1",
            "mapping_version": "m-1",
            "environment_id": "https://gw.example/env",
        },
        "request": {
            "method": "POST",
            "raw_request_uri": "/a?b=1",
            "headers": [{"name": "Host", "value": "gw.example"}, {"name": "X-A", "value": "1"}],
            "body_b64": base64.b64encode(b"{}").decode(),
        },
        "operation_id": "op-1",
        "principal_id": "https://id.example/p",
        "action": "a.write",
        "resources": ["https://r.example/1"],
        "expect": {"operation_context": ctx} if accept else {"reject_reason": "INVALID_MESSAGE"},
        "expect_operation_digest": oracle_digest(ctx) if accept and ctx is not None else None,
    }


def fragment_vector(eid: str) -> dict[str, Any]:
    v = binding_vector(eid, False)
    v["request"]["raw_request_uri"] = "/a#f"
    return v


def bound_context(principal_id: str = "https://id.example/p") -> dict[str, Any]:
    return {
        "operation_id": "op-1",
        "environment_id": "https://gw.example/env",
        "principal_id": principal_id,
        "action": "a.write",
        "resources": ["https://r.example/1"],
        "method": "POST",
        "target_uri": "https://gw.example/a?b=1",
        "body_digest": sha(b"{}"),
        "headers": {"x-a": "1"},
    }


def fake_from_request(
    cfg: binding.Config,
    req: binding.RawRequest,
    principal_id: str,
    action: str,
    resources: Sequence[str],
) -> OperationContext:
    if "#" in req.raw_request_uri:
        raise binding.RequestError(binding.Rule.FRAGMENT, "fragment")
    return OperationContext(
        operation_id="",
        environment_id="",
        principal_id=principal_id,
        action=action,
        resources=tuple(resources),
        method=req.method,
        target_uri=cfg.origin + req.raw_request_uri,
        body_digest=sha(req.body),
        headers={k.lower(): v for k, v in req.headers if k.lower() in cfg.header_allowlist},
    )


ISSUER_KEY = {"kty": "EC", "crv": "P-256", "x": G_X, "y": G_Y, "kid": "k1", "alg": "ES256"}


def jws_vector(eid: str, reason: str | None, payload: str | None = None) -> dict[str, Any]:
    return {
        "id": eid,
        "description": "d",
        "compact": "e30.e30.c2ln",
        "expected_typ": None,
        "trusted_keysets": {"issuer": [ISSUER_KEY]},
        "expected_holder_jkt": None,
        "decode_as": None,
        "expect": "reject" if reason else "accept",
        "reject_reason": reason,
        "signer_jwk": ISSUER_KEY,
        "signature_valid": True,
        "expected_payload": payload,
    }


def key_files(tree: Tree, x: str = G_X, scalar: str = "1") -> None:
    tree.file(
        "keys/test-private-scalars.json",
        {
            "label": "L",
            "warning": "W",
            "encoding": "E",
            "keys": [
                {
                    "role": "holder",
                    "kid": "h",
                    "alg": "ES256",
                    "kty": "EC",
                    "crv": "P-256",
                    "scalar": scalar,
                    "d": D1,
                    "public_jwk": "holder.jwk.json",
                },
                {
                    "role": "ed",
                    "kid": "e",
                    "alg": "Ed25519",
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "seed_hex": "00" * 32,
                    "d": b64u(bytes(32)),
                    "public_jwk": "ed25519.jwk.json",
                },
            ],
        },
    )
    tree.file("keys/holder.jwk.json", {"kty": "EC", "crv": "P-256", "x": x, "y": G_Y, "kid": "h"})
    tree.file("keys/ed25519.jwk.json", {"kty": "OKP", "crv": "Ed25519", "x": b64u(bytes(32))})


def key_entries(tree: Tree) -> None:
    for name in ("test-private-scalars.json", "holder.jwk.json", "ed25519.jwk.json"):
        eid = "keys/" + name.removesuffix(".json").removesuffix(".jwk")
        tree.add(eid, "key", "core", "keys/" + name, None, None)


def every_group(tree: Tree) -> list[str]:
    """One well-formed entry per group the harness runs; returns the run ids."""
    ids = [
        tree.vector(
            "vectors/strictjson/a",
            strictjson_vector("vectors/strictjson/a", "{}", "reject"),
            "REJECTED",
        ),
        tree.vector(
            "vectors/binding/a", fragment_vector("vectors/binding/a"), "REJECTED", "adapter"
        ),
        tree.vector("vectors/jws/a", jws_vector("vectors/jws/a", "kid-unknown"), "REJECTED"),
        tree.vector(
            "vectors/digest/a",
            [
                {
                    "id": "e",
                    "input_kind": "bytes",
                    "input": "",
                    "expected_digest": EMPTY_DIGEST,
                    "spec_defect": False,
                    "appendix_value": None,
                }
            ],
            "MATCH",
        ),
        tree.vector(
            "vectors/schema/uri-format",
            [
                {
                    "id": "u",
                    "input": "a:b",
                    "expect": "accept",
                    "reason": "r",
                    "ajv_formats_differs": False,
                }
            ],
            "MATCH",
        ),
    ]
    tree.file("vectors/jcs/input/a.json", '{"b":1,"a":2}')
    tree.file("vectors/jcs/output/a.json", '{"a":2,"b":1}')
    ids.append(
        tree.add(
            "vectors/jcs/a",
            "vector",
            "core",
            "vectors/jcs/input/a.json",
            "vectors/jcs/output/a.json",
            "MATCH",
        )
    )
    key_files(tree)
    key_entries(tree)
    ids += ["keys/test-private-scalars", "keys/holder"]
    return ids


def stub(name: str) -> Any:
    def f(*args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError(f"hop_top_pact.core.{name}")

    return f


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Put stubs back in place of the core functions that are implemented."""
    monkeypatch.setattr(strictjson, "decode", stub("strictjson.decode"))
    monkeypatch.setattr(jcs, "canonicalize", stub("jcs.canonicalize"))
    monkeypatch.setattr(digest, "object_digest", stub("digest.object_digest"))
    monkeypatch.setattr(digest, "artifact_digest", stub("digest.artifact_digest"))
    monkeypatch.setattr(digest, "bytes_digest", stub("digest.bytes_digest"))
    monkeypatch.setattr(schema, "format_checker", stub("schema.format_checker"))
    monkeypatch.setattr(jws, "parse_jwk", stub("jws.parse_jwk"))
    monkeypatch.setattr(jws, "public_jwk", stub("jws.public_jwk"))
    monkeypatch.setattr(jws, "thumbprint", stub("jws.thumbprint"))
    monkeypatch.setattr(jws, "new_key_set", stub("jws.new_key_set"))
    monkeypatch.setattr(jws.Verifier, "verify", stub("jws.Verifier.verify"))
    monkeypatch.setattr(binding, "from_request", stub("binding.from_request"))
    return monkeypatch


def test_stubs_fail_every_group(tree: Tree, stubs: pytest.MonkeyPatch) -> None:
    ids = every_group(tree)
    run = tree.run()
    assert run.code == 0, run.stderr
    for eid in ids:
        assert run.result(eid) == "fail", (eid, run.stderr)
        assert any(
            line.startswith(f"FAIL {eid}: ") and "not implemented: hop_top_pact.core." in line
            for line in run.stderr.splitlines()
        ), (eid, run.stderr)
    assert run.result("keys/ed25519") == "skipped:out-of-scope"
    assert f"vectors: 0 passed, {len(ids)} failed, 1 skipped (out-of-scope 1" in run.stderr


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Replace every core function the harness calls with a working fake."""
    monkeypatch.setattr(jcs, "canonicalize", oracle)
    monkeypatch.setattr(digest, "object_digest", oracle_digest)
    monkeypatch.setattr(digest, "artifact_digest", lambda s: sha(s.encode("ascii")))
    monkeypatch.setattr(digest, "bytes_digest", sha)
    monkeypatch.setattr(jws, "parse_jwk", fake_parse_jwk)
    monkeypatch.setattr(jws, "public_jwk", fake_public_jwk)
    monkeypatch.setattr(jws, "thumbprint", fake_thumbprint)
    monkeypatch.setattr(jws, "reason_of", fake_reason_of)
    monkeypatch.setattr(jws, "new_key_set", lambda *keys: jws.KeySet())
    monkeypatch.setattr(binding, "from_request", fake_from_request)
    return monkeypatch


def test_fakes_pass_every_group(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    ids = every_group(tree)

    def decode(data: bytes, cls: type[Any], lim: strictjson.Limits | None = None) -> Any:
        raise strictjson.StrictJSONError(strictjson.StrictJSONErrorKind.TYPE, "/operation_id")

    def verify(self: jws.Verifier, compact: str) -> jws.ParsedJWS:
        raise jws.JWSError(jws.Reason.KID_UNKNOWN)

    fakes.setattr(strictjson, "decode", decode)
    fakes.setattr(jws.Verifier, "verify", verify)
    checker = FormatChecker(formats=())
    checker.checks("uri")(lambda s: ":" in s)
    fakes.setattr(schema, "format_checker", lambda: checker)
    run = tree.run()
    assert run.code == 0, run.stderr
    assert {eid: run.result(eid) for eid in ids} == dict.fromkeys(ids, "pass"), run.stderr
    assert f"vectors: {len(ids)} passed, 0 failed, 1 skipped" in run.stderr


def test_jcs_pair(tree: Tree, monkeypatch: pytest.MonkeyPatch) -> None:
    tree.file("vectors/jcs/input/a.json", '{"b":1,"a":2}')
    tree.file("vectors/jcs/output/a.json", '{"a":2,"b":1}')
    tree.file("vectors/jcs/output/b.json", '{"b":1,"a":2}')
    tree.add(
        "vectors/jcs/a",
        "vector",
        "core",
        "vectors/jcs/input/a.json",
        "vectors/jcs/output/a.json",
        "MATCH",
    )
    tree.add(
        "vectors/jcs/b",
        "vector",
        "core",
        "vectors/jcs/input/a.json",
        "vectors/jcs/output/b.json",
        "MATCH",
    )
    monkeypatch.setattr(jcs, "canonicalize", oracle)
    run = tree.run()
    assert run.result("vectors/jcs/a") == "pass", run.stderr
    assert run.result("vectors/jcs/b") == "fail"
    monkeypatch.setattr(jcs, "canonicalize", lambda b: b)
    assert tree.run().result("vectors/jcs/a") == "fail"


def test_jcs_numbers(tree: Tree, monkeypatch: pytest.MonkeyPatch) -> None:
    # Each IEEE 754 value reaches canonicalize as the literal Go's
    # strconv.FormatFloat(f, 'e', -1, 64) writes.
    cases = [
        (1.0, "1e+00"),
        (-0.0, "-0e+00"),
        (0.0, "0e+00"),
        (5e-324, "5e-324"),
        (1e21, "1e+21"),
        (123.456, "1.23456e+02"),
        (-1.7976931348623157e308, "-1.7976931348623157e+308"),
        (1e-7, "1e-07"),
    ]
    rows = [
        {"ieee754_hex": struct.pack(">d", f).hex(), "expected": rfc8785.dumps(f).decode()}
        for f, _ in cases
    ]
    rel = tree.file("vectors/jcs/numbers.json", rows)
    tree.add("vectors/jcs/numbers", "vector", "core", rel, rel, "MATCH")
    seen: list[bytes] = []

    def record(data: bytes) -> bytes:
        seen.append(data)
        return oracle(data)

    monkeypatch.setattr(jcs, "canonicalize", record)
    run = tree.run()
    assert run.result("vectors/jcs/numbers") == "pass", run.stderr
    assert [s.decode() for s in seen] == [lit for _, lit in cases]
    rows[0]["expected"] = "1.0"
    tree.file(rel, rows)
    assert tree.run().result("vectors/jcs/numbers") == "fail"


def digest_rows(appendix: str | None, defect: bool) -> list[dict[str, Any]]:
    obj: JSONValue = {"b": (1, "x"), "a": None}
    return [
        {
            "id": "o",
            "input_kind": "object",
            "input": obj,
            "expected_digest": oracle_digest(obj),
            "spec_defect": False,
            "appendix_value": None,
        },
        {
            "id": "a",
            "input_kind": "artifact",
            "input": "e30.e30.c2ln",
            "expected_digest": sha(b"e30.e30.c2ln"),
            "spec_defect": defect,
            "appendix_value": appendix,
        },
        {
            "id": "b",
            "input_kind": "bytes",
            "input": "00ff",
            "expected_digest": sha(b"\x00\xff"),
            "spec_defect": False,
            "appendix_value": sha(b"\x00\xff"),
        },
    ]


def test_digest(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    tree.vector("vectors/digest/ok", digest_rows(None, False), "MATCH")
    tree.vector("vectors/digest/defect", digest_rows("printed-value", True), "MATCH")
    tree.vector("vectors/digest/unflagged", digest_rows("printed-value", False), "MATCH")
    tree.vector("vectors/digest/flag-matches", digest_rows(sha(b"e30.e30.c2ln"), True), "MATCH")
    run = tree.run()
    assert run.result("vectors/digest/ok") == "pass", run.stderr
    assert run.by_id("vectors/digest/defect") == {
        "id": "vectors/digest/defect",
        "kind": "vector",
        "result": "skipped:spec-defect",
        "spec_defects": [
            {
                "vector": "a",
                "appendix_value": "printed-value",
                "expected_digest": sha(b"e30.e30.c2ln"),
            }
        ],
    }
    assert run.result("vectors/digest/unflagged") == "fail"
    assert run.result("vectors/digest/flag-matches") == "fail"
    fakes.setattr(digest, "bytes_digest", lambda b: sha(b + b"x"))
    assert tree.run().result("vectors/digest/ok") == "fail"


def test_strictjson(tree: Tree, monkeypatch: pytest.MonkeyPatch) -> None:
    tree.vector(
        "vectors/strictjson/acc",
        strictjson_vector("vectors/strictjson/acc", '{"a":1}', "accept"),
        "ACCEPTED",
    )
    tree.vector(
        "vectors/strictjson/rej",
        strictjson_vector("vectors/strictjson/rej", '{"a":1,"a":2}', "reject"),
        "REJECTED",
    )
    b64 = {
        "id": "vectors/strictjson/b64",
        "input_b64": base64.b64encode(b"\xff").decode(),
        "expect": "reject",
        "reason": "r",
    }
    tree.vector("vectors/strictjson/b64", b64, "REJECTED")
    # The package decoder: {"a":1} is not an OperationContext.
    run = tree.run()
    assert [x["result"] for x in run.lines] == ["fail", "pass", "pass"], run.stderr
    monkeypatch.setattr(strictjson, "decode", stub("strictjson.decode"))
    run = tree.run()
    assert [x["result"] for x in run.lines] == ["fail", "fail", "fail"], run.stderr
    inputs: list[bytes] = []

    def decode(data: bytes, cls: type[Any], lim: strictjson.Limits | None = None) -> Any:
        assert cls is OperationContext
        inputs.append(data)
        if b'"a":2' in data or data == b"\xff":
            raise strictjson.StrictJSONError(strictjson.StrictJSONErrorKind.DUPLICATE_KEY)
        return object()

    monkeypatch.setattr(strictjson, "decode", decode)
    run = tree.run()
    assert [x["result"] for x in run.lines] == ["pass", "pass", "pass"], run.stderr
    assert inputs == [b'{"a":1}', b'{"a":1,"a":2}', b"\xff"]
    monkeypatch.setattr(strictjson, "decode", lambda data, cls, lim=None: object())
    assert [x["result"] for x in tree.run().lines] == ["pass", "fail", "fail"]


def test_strictjson_outcome_disagrees(tree: Tree) -> None:
    tree.vector(
        "vectors/strictjson/x",
        strictjson_vector("vectors/strictjson/x", "{}", "accept"),
        "REJECTED",
    )
    run = tree.run()
    assert run.result("vectors/strictjson/x") == "fail"
    assert "outcome" in run.stderr


def test_binding(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    tree.vector(
        "vectors/binding/acc",
        binding_vector("vectors/binding/acc", True, bound_context()),
        "ACCEPTED",
        "adapter",
    )
    other = binding_vector("vectors/binding/digest", True, bound_context())
    other["expect_operation_digest"] = EMPTY_DIGEST
    tree.vector("vectors/binding/digest", other, "ACCEPTED", "adapter")
    ctx = binding_vector("vectors/binding/ctx", True, bound_context("https://id.example/q"))
    ctx["expect_operation_digest"] = oracle_digest(bound_context())
    tree.vector("vectors/binding/ctx", ctx, "ACCEPTED", "adapter")
    rej = binding_vector("vectors/binding/rej", False)
    rej["request"]["raw_request_uri"] = "/a#f"
    tree.vector("vectors/binding/rej", rej, "REJECTED", "adapter")
    tree.vector(
        "vectors/binding/rej-bound",
        binding_vector("vectors/binding/rej-bound", False),
        "REJECTED",
        "adapter",
    )
    extra = {**binding_vector("vectors/binding/extra", False), "note": "n"}
    tree.vector("vectors/binding/extra", extra, "REJECTED", "adapter")
    seen: list[binding.RawRequest] = []

    def record(cfg: binding.Config, req: binding.RawRequest, *rest: Any) -> OperationContext:
        assert cfg.max_body > 0
        assert cfg.header_normalization_id == "n-1"
        seen.append(req)
        return fake_from_request(cfg, req, *rest)

    fakes.setattr(binding, "from_request", record)
    run = tree.run()
    assert run.result("vectors/binding/acc") == "pass", run.stderr
    assert run.result("vectors/binding/digest") == "fail"
    assert run.result("vectors/binding/ctx") == "fail"
    assert run.result("vectors/binding/rej") == "pass"
    assert run.result("vectors/binding/rej-bound") == "fail"
    assert run.result("vectors/binding/extra") == "fail"
    assert seen[0] == binding.RawRequest(
        method="POST",
        raw_request_uri="/a?b=1",
        headers=(("Host", "gw.example"), ("X-A", "1")),
        body=b"{}",
    )


def test_binding_config_error_is_not_a_refusal(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    # Only a refused request (kind INVALID_REQUEST) is INVALID_MESSAGE; an
    # unusable configuration or an unreadable body is a fail.
    for name in ("cfg", "body"):
        v = fragment_vector("vectors/binding/" + name)
        v["request"]["raw_request_uri"] = f"/{name}#f"
        tree.vector("vectors/binding/" + name, v, "REJECTED", "adapter")

    def broken(cfg: binding.Config, req: binding.RawRequest, *rest: Any) -> OperationContext:
        kind = binding.RequestErrorKind.BODY_READ
        if req.raw_request_uri.startswith("/cfg"):
            kind = binding.RequestErrorKind.INVALID_CONFIG
        raise binding.RequestError(None, "broken", kind)

    fakes.setattr(binding, "from_request", broken)
    run = tree.run()
    assert run.result("vectors/binding/cfg") == "fail"
    assert run.result("vectors/binding/body") == "fail"


def config_vector(eid: str, allow: list[str]) -> dict[str, Any]:
    v = binding_vector(eid, False)
    v["config"]["header_allowlist"] = allow
    v["expect"] = {"config_error": True}
    return v


def test_binding_config_error(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    # A config_error vector passes only when Config.validate fails with
    # INVALID_CONFIG; a usable configuration, or an expectation that does not
    # agree, is a fail.
    tree.vector(
        "vectors/binding/cfg",
        config_vector("vectors/binding/cfg", ["x-a", "host"]),
        "REJECTED",
        "adapter",
    )
    tree.vector(
        "vectors/binding/ok", config_vector("vectors/binding/ok", ["x-a"]), "REJECTED", "adapter"
    )
    tree.vector(
        "vectors/binding/acc", config_vector("vectors/binding/acc", ["host"]), "ACCEPTED", "adapter"
    )
    flag = config_vector("vectors/binding/flag", ["host"])
    flag["expect"] = {"config_error": False}
    tree.vector("vectors/binding/flag", flag, "REJECTED", "adapter")
    dig = config_vector("vectors/binding/dig", ["host"])
    dig["expect_operation_digest"] = sha(b"")
    tree.vector("vectors/binding/dig", dig, "REJECTED", "adapter")
    run = tree.run()
    assert run.result("vectors/binding/cfg") == "pass", run.stderr
    for name in ("ok", "acc", "flag", "dig"):
        assert run.result("vectors/binding/" + name) == "fail", (name, run.stderr)
    assert any(
        line.startswith("FAIL vectors/binding/ok: ") and "configuration accepted" in line
        for line in run.stderr.splitlines()
    ), run.stderr


def test_binding_config_error_needs_invalid_config(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    # A refused request is not a configuration error.
    tree.vector(
        "vectors/binding/cfg", config_vector("vectors/binding/cfg", ["host"]), "REJECTED", "adapter"
    )

    def refusing(self: binding.Config) -> None:
        raise binding.RequestError(binding.Rule.FRAGMENT, "refused")

    fakes.setattr(binding.Config, "validate", refusing)
    assert tree.run().result("vectors/binding/cfg") == "fail"


def test_binding_stub_is_not_a_refusal(tree: Tree) -> None:
    tree.vector(
        "vectors/binding/rej", binding_vector("vectors/binding/rej", False), "REJECTED", "adapter"
    )
    assert tree.run().result("vectors/binding/rej") == "fail"


def test_jws_verify(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    def vec(name: str, reason: str | None, payload: str | None = None, **extra: Any) -> None:
        eid = "vectors/jws/" + name
        v = {**jws_vector(eid, reason, payload), "compact": name, **extra}
        tree.vector(eid, v, "REJECTED" if reason else "ACCEPTED")

    vec("rej", "kid-unknown")
    vec("other", "typ-mismatch")
    vec("acc", None, '{"pact_version":"0.1"}')
    vec("payload", None, '{"x":1}')
    vec("v02", "payload-schema", decode_as="Evidence")
    vec("ev-ok", None, '{"pact_version":"0.1"}', decode_as="Evidence")
    vec("typ", "typ-mismatch", expected_typ="pact-evidence+jwt")
    vec("holder", "holder-jkt-mismatch", expected_holder_jkt=HOLDER_JKT)
    seen: dict[str, tuple[str | None, jws.StaticResolver]] = {}

    def verify(self: jws.Verifier, compact: str) -> jws.ParsedJWS:
        assert isinstance(self.keys, jws.StaticResolver)
        seen[compact] = (self.typ, self.keys)
        assert list(self.keys.key_sets) == ["issuer"]
        if self.typ is not None:
            raise jws.JWSError(jws.Reason.TYP_MISMATCH)
        if self.keys.expected_holder_jkt:
            raise jws.JWSError(jws.Reason.HOLDER_JKT_MISMATCH)
        if compact in ("rej", "other"):
            raise jws.JWSError(jws.Reason.KID_UNKNOWN)
        version = "0.2" if compact == "v02" else "0.1"
        return jws.ParsedJWS(
            compact=compact,
            header=jws.Header(),
            role=jws.Role.ISSUER,
            raw_header=b"{}",
            payload=f'{{"pact_version":"{version}"}}'.encode(),
            signing_input="",
            signature=b"",
            key=jws.JWK(),
            key_thumbprint="",
        )

    def decode(data: bytes, cls: type[Any], lim: strictjson.Limits | None = None) -> Any:
        assert lim == strictjson.Limits(max_bytes=7, max_depth=3)
        return SimpleNamespace(pact_version=json.loads(data)["pact_version"])

    fakes.setattr(limits, "defaults", lambda: limits.Limits(1, 7, 1, 1, 1, 3, 1, 1))
    fakes.setattr(
        limits,
        "artifact_json",
        lambda lim: strictjson.Limits(lim.artifact_payload_bytes, lim.depth),
    )
    fakes.setattr(strictjson, "decode", decode)
    fakes.setattr(jws.Verifier, "verify", verify)
    run = tree.run()
    assert {x["id"].removeprefix("vectors/jws/"): x["result"] for x in run.lines} == {
        "rej": "pass",
        "other": "fail",
        "acc": "pass",
        "payload": "fail",
        "v02": "pass",
        "ev-ok": "pass",
        "typ": "pass",
        "holder": "pass",
    }, run.stderr
    assert seen["typ"][0] == "pact-evidence+jwt"
    assert seen["rej"][0] is None
    assert seen["holder"][1].expected_holder_jkt == HOLDER_JKT
    assert seen["rej"][1].expected_holder_jkt == ""


def test_jws_error_without_reason_fails(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    tree.vector("vectors/jws/rej", jws_vector("vectors/jws/rej", "kid-unknown"), "REJECTED")

    def verify(self: jws.Verifier, compact: str) -> jws.ParsedJWS:
        raise ValueError("kid-unknown")

    fakes.setattr(jws.Verifier, "verify", verify)
    run = tree.run()
    assert run.result("vectors/jws/rej") == "fail"


def test_jws_arrays(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    holder = {"kty": "EC", "crv": "P-256", "x": G_X, "y": G_Y}
    rel = tree.file(
        "vectors/jws/thumbprint.json",
        [
            {
                "id": "h",
                "description": "d",
                "jwk": holder,
                "expected_thumbprint": HOLDER_JKT,
                "source": "s",
            }
        ],
    )
    tree.add("vectors/jws/thumbprint", "vector", "core", rel, rel, "ACCEPTED")
    rel = tree.file(
        "vectors/jws/jwk-reject.json",
        [
            {
                "id": "p",
                "description": "d",
                "jwk": {**holder, "d": D1},
                "reject_reason": "jwk-private",
            },
        ],
    )
    tree.add("vectors/jws/jwk-reject", "vector", "core", rel, rel, "REJECTED")
    rel = tree.file(
        "vectors/jws/appendix-c-keys.json",
        [
            {
                "id": "h",
                "description": "d",
                "d": D1,
                "expected_x": G_X,
                "expected_y": G_Y,
                "expected_thumbprint": HOLDER_JKT,
            }
        ],
    )
    tree.add("vectors/jws/appendix-c-keys", "vector", "core", rel, rel, "MATCH")
    run = tree.run()
    assert [x["result"] for x in run.lines] == ["pass", "pass", "pass"], run.stderr
    fakes.setattr(jws, "thumbprint", lambda k: HOLDER_JKT[::-1])
    fakes.setattr(jws, "parse_jwk", lambda b: jws.JWK(kty="EC", crv="P-256", x=G_X, y=G_Y))
    assert [x["result"] for x in tree.run().lines] == ["fail", "fail", "fail"]


def test_key_rule(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    key_files(tree)
    key_entries(tree)
    tree.file("keys/stray.jwk.json", {"kty": "EC", "crv": "P-256", "x": G_X, "y": G_Y})
    tree.add("keys/stray", "key", "core", "keys/stray.jwk.json", None, None)
    run = tree.run()
    assert run.result("keys/test-private-scalars") == "pass", run.stderr
    assert run.result("keys/holder") == "pass", run.stderr
    assert run.result("keys/ed25519") == "skipped:out-of-scope"
    assert run.result("keys/stray") == "fail"
    fakes.setattr(jws, "thumbprint", lambda k: "other")
    run = tree.run()
    assert run.result("keys/holder") == "fail"
    assert run.result("keys/test-private-scalars") == "fail"


@pytest.mark.parametrize(
    "files",
    [
        {"x": "fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg"},
        {"scalar": "2"},
        {"scalar": "-1"},
    ],
)
def test_key_rule_mismatch(tree: Tree, fakes: pytest.MonkeyPatch, files: dict[str, str]) -> None:
    key_files(tree, **files)
    key_entries(tree)
    run = tree.run()
    assert run.result("keys/holder") == "fail", run.stderr
    assert run.result("keys/test-private-scalars") == "fail"


def test_schema_uri(tree: Tree, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        {
            "id": "a",
            "input": "a:b",
            "expect": "accept",
            "reason": "r",
            "ajv_formats_differs": False,
        },
        {"id": "r", "input": "ab", "expect": "reject", "reason": "r", "ajv_formats_differs": True},
    ]
    tree.vector("vectors/schema/uri-format", rows, "MATCH")
    tree.vector("vectors/schema/other-format", rows, "MATCH")
    checker = FormatChecker(formats=())
    checker.checks("uri")(lambda s: ":" in s)
    monkeypatch.setattr(schema, "format_checker", lambda: checker)
    run = tree.run()
    assert run.result("vectors/schema/uri-format") == "pass", run.stderr
    assert run.result("vectors/schema/other-format") == "fail"
    monkeypatch.setattr(schema, "format_checker", lambda: FormatChecker(formats=()))
    assert tree.run().result("vectors/schema/uri-format") == "fail"


def test_capability_not_declared(tree: Tree, fakes: pytest.MonkeyPatch) -> None:
    v = jws_vector("vectors/jws/ed", "kid-unknown")
    rel = tree.file("vectors/jws/ed.json", v)
    tree.add("vectors/jws/ed", "vector", "core", rel, rel, "REJECTED", capabilities=["jws-ed25519"])
    tree.add(
        "admission/ed",
        "evaluate",
        "runner",
        "admission/ed",
        None,
        None,
        capabilities=["jws-ed25519"],
    )
    called: list[str] = []

    def verify(self: jws.Verifier, compact: str) -> jws.ParsedJWS:
        called.append(compact)
        raise jws.JWSError(jws.Reason.KID_UNKNOWN)

    fakes.setattr(jws.Verifier, "verify", verify)
    run = tree.run()
    assert run.by_id("vectors/jws/ed") == {
        "id": "vectors/jws/ed",
        "kind": "vector",
        "result": "skipped:capability",
        "missing_capabilities": ["jws-ed25519"],
    }
    assert run.result("admission/ed") == "skipped:out-of-scope"
    assert called == []
    assert "capability 1)" in run.stderr


def test_missing_fixture_fails(tree: Tree) -> None:
    tree.add(
        "vectors/strictjson/gone",
        "vector",
        "core",
        "vectors/strictjson/gone.json",
        "vectors/strictjson/gone.json",
        "REJECTED",
    )
    run = tree.run()
    assert run.code == 0
    assert run.result("vectors/strictjson/gone") == "fail"


def row(
    scope: str, kind: str, prefix: str, py: str, exceptions: Sequence[str] = ()
) -> dict[str, Any]:
    r: dict[str, Any] = {
        "scope": scope,
        "kind": kind,
        "prefix": prefix,
        "go": "required",
        "ts": "planned",
        "py": py,
        "rs": "n/a",
        "php": "n/a",
        "flipped_by": "x",
    }
    if exceptions:
        r["exceptions"] = [{"id": i, "reason": "r"} for i in exceptions]
    return r


@pytest.mark.parametrize(
    ("py", "exceptions", "code"),
    [
        ("required", (), 1),
        ("planned", (), 0),
        ("n/a", (), 0),
        ("required", ("vectors/strictjson/a",), 0),
    ],
)
def test_gates(tree: Tree, py: str, exceptions: Sequence[str], code: int) -> None:
    tree.vector(
        "vectors/strictjson/a",
        strictjson_vector("vectors/strictjson/a", '{"a":1,"a":2}', "accept"),
        "ACCEPTED",
    )
    tree.add("admission/x", "evaluate", "runner", "admission/x", None, None)
    tree.gates(
        [
            row("core", "vector", "vectors/strictjson", py, exceptions),
            row("runner", "evaluate", "admission", "required"),
        ]
    )
    run = tree.run()
    assert run.result("vectors/strictjson/a") == "fail"
    assert run.code == code, run.stderr


def test_gates_absent(tree: Tree) -> None:
    tree.vector(
        "vectors/strictjson/a",
        strictjson_vector("vectors/strictjson/a", "{}", "accept"),
        "ACCEPTED",
    )
    run = tree.run()
    assert run.code == 0
    assert "NOTICE" in run.stderr


@pytest.mark.parametrize(
    "gates", ['{"gates_version": 1}', "[]", '{"gates_version": 1, "rows": [{"py": 1}]}']
)
def test_gates_malformed(tree: Tree, gates: str) -> None:
    tree.vector(
        "vectors/strictjson/a",
        strictjson_vector("vectors/strictjson/a", "{}", "accept"),
        "ACCEPTED",
    )
    p = tree.root / "tools" / "parity" / "gates.json"
    p.parent.mkdir(parents=True)
    p.write_text(gates, encoding="utf-8")
    run = tree.run()
    assert run.code == 2
    assert run.lines == []
