"""The evaluation-case loader over the committed cases. Port of
go/runner/evalcase/evalcase_test.go."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact import conformance
from hop_top_pact.core.enums import Decision, Mode
from hop_top_pact.core.jws import (
    TYP_EVIDENCE,
    TYP_PRESENTATION,
    TYP_REPUTATION,
    TYP_REQUIREMENTS,
    Reason,
    Role,
    reason_of,
)
from hop_top_pact.runner import manifest

# The committed signed files that a case makes fail verification against its
# trust records on purpose, with the jws reason. An artifact entry with
# payload_signed must fail with signature-invalid (spec/v1.0/fixtures/README.md,
# Generator contract) and need not be listed. A new case whose artifact fails
# verification by design adds a row here.
DESIGNED_UNTRUSTED: dict[str, Reason] = {
    # The presentation is signed by a holder key other than the enrolled one
    # (native_context.json authenticated.holder_jkt).
    "admission/old-holder-key/signed/presentation.jws": Reason.HOLDER_JKT_MISMATCH,
    # The presentation is signed by the key that a rotation retired; the
    # enrollment names the key after the rotation.
    "admission/rotated-holder-key/signed/presentation.jws": Reason.HOLDER_JKT_MISMATCH,
    # The presented agent has no binding on the authenticated workload:
    # native_context.json authenticated.holder_jkt is null, so no enrolled key
    # exists to verify the presentation against.
    "admission/agent-of-other-workload/signed/presentation.jws": Reason.KEY_UNAVAILABLE,
    "admission/other-realm-agent-other-tenant/signed/presentation.jws": Reason.KEY_UNAVAILABLE,
    "admission/unenrolled-agent/signed/presentation.jws": Reason.KEY_UNAVAILABLE,
    "admission/workload-two-enrollments/signed/presentation.jws": Reason.KEY_UNAVAILABLE,
}

VALID = "admission/valid"


def evaluate_entries(fixtures: Path) -> list[manifest.Entry]:
    out = [e for e in manifest.load(fixtures).entries if e.kind == manifest.Kind.EVALUATE]
    assert out, "no evaluate entry in the manifest"
    return out


def test_loads_every_committed_case(ec: Any) -> None:
    """Every evaluate entry of the manifest loads, v1 and v2 alike; every signed file
    its signing.json names is read and verified, and verifies against the case's trust
    records unless the case makes it fail by design."""
    fixtures = ec.repo_fixtures()
    seen: set[str] = set()
    errors: list[str] = []
    for e in evaluate_entries(fixtures):
        try:
            c = conformance.load(fixtures, e.id)
        except conformance.CaseError as err:
            errors.append(f"{e.id}: {err}")
            continue
        if c.id != e.id or c.path != e.path or not c.exchanges:
            errors.append(f"case {c.id!r} path {c.path!r} with {len(c.exchanges)} exchanges")
            continue
        if (subj := c.exchanges[c.subject]).expected_path != e.expected:
            errors.append(
                f"{e.id}: subject expected file {subj.expected_path}, manifest {e.expected}"
            )
        for x in c.exchanges:
            if x.config.now == 0 or not x.config.trust or x.native_context.authenticated is None:
                errors.append(f"{x.path}: config or native context not read")
            n = len(x.signing.artifacts) + len(x.signing.presentations)
            if len(x.signed) != n or n == 0:
                errors.append(f"{x.path}: {len(x.signed)} signed files for {n} entries")
            if len(x.expected.expected_responses()) != len(x.submissions):
                errors.append(f"{x.path}: expected responses and submissions differ")
            tampered = {a.signed for a in x.signing.artifacts if a.payload_signed is not None}
            for s in x.signed:
                id = x.path + "/" + s.path
                want = DESIGNED_UNTRUSTED.get(id)
                if s.path in tampered:
                    want = Reason.SIGNATURE_INVALID
                seen.add(id)
                if want is not None and reason_of(s.trust) != want:
                    errors.append(f"{id}: trust {s.trust!r}, want reason {want} by design")
                elif want is None and s.trust is not None:
                    errors.append(f"{id}: does not verify against the trust records: {s.trust}")
    for id in DESIGNED_UNTRUSTED:
        if id not in seen:
            errors.append(f"DESIGNED_UNTRUSTED lists {id}, which no case signs")
    assert not errors, "\n".join(errors)


def test_verifies_every_signed_directory(ec: Any) -> None:
    """verify accepts every directory that dirs lists, outcome cases included, and
    returns one result per signed file found under it."""
    fixtures = ec.repo_fixtures()
    keys = conformance.load_keys(fixtures)
    total, groups = 0, set()
    for d in conformance.dirs(fixtures):
        signed = conformance.verify(fixtures, d, keys)
        groups.add(d.entry.split("/", 1)[0])
        root = ec.at(fixtures, d.path)
        files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.jws") if p.is_file())
        assert sorted(s.path for s in signed) == files, d.id
        total += len(signed)
    assert total > 0
    assert {"admission", "outcomes"} <= groups, groups


def test_valid_case(ec: Any) -> None:
    """admission/valid reads into the values of the README section admission/valid and
    the defaults of format v2 for a case without exchange.json."""
    fixtures = ec.repo_fixtures()
    c = conformance.load(fixtures, VALID)
    assert len(c.exchanges) == 1
    assert c.subject == 0
    x = c.exchanges[0]
    assert (x.name, x.path, x.expected_path) == (
        "",
        VALID,
        "expected/admission/valid/decision.json",
    )
    cfg = x.config
    assert (cfg.mode, cfg.now, cfg.clock_skew_seconds) == (Mode.ENFORCED, 1792080000, 5)
    assert cfg.gateway.gateway_id == "https://gateway.example/finance"
    assert cfg.gateway.tenant_id == "acme"
    assert len(cfg.trust) == 3
    assert cfg.trust[2].role == Role.REPUTATION_SERVICE
    assert tuple(cfg.trust[2].keys) == ("keys/reputation-service.jwk.json",)
    assert cfg.validator.key == "keys/validator.jwk.json"
    assert cfg.limits["evaluation_seconds"] == 30
    assert cfg.selection is None
    nc = x.native_context
    assert nc.authenticated is not None
    assert nc.authenticated.holder_jkt == "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"
    assert nc.authorize
    assert nc.approval is not None
    assert nc.approval.state == "approved"
    assert nc.delegation is not None
    assert nc.delegation.state == "active"
    assert len(x.submissions) == 1
    s = x.submissions[0]
    assert s == conformance.Submission(
        signed="signed/presentation.jws",
        jti="v6wxT-_cB0Ua8Xkqgcuu2g",
        replica="r1",
        concurrent=False,
        evict_replay_records=False,
        actual_operation="actual_operation.json",
        transport="https",
        evaluation=conformance.Evaluation(
            started_at=1792080000, native_reads_at=None, cancelled_at=None
        ),
    )
    assert x.availability.replay_store == "available"
    assert len(x.availability.sources) == 0
    assert len(x.handoff) == 0
    want = [
        ("signed/contract.jws", TYP_REQUIREMENTS, "zIMh1jdcSU0EP90CYPIbwA"),
        ("signed/evidence/runtime.jws", TYP_EVIDENCE, "7oJQ-3bglLNLRx8Tpz275Q"),
        ("signed/reputation.jws", TYP_REPUTATION, "VW7HSF227CWWBU7wN09Q5A"),
        ("signed/presentation.jws", TYP_PRESENTATION, "v6wxT-_cB0Ua8Xkqgcuu2g"),
    ]
    assert len(x.signed) == len(want)
    for got, (path, typ, jti) in zip(x.signed, want, strict=True):
        assert (got.path, got.typ, json.loads(got.payload)["jti"], got.trust) == (
            path,
            typ,
            jti,
            None,
        )
        raw = ec.at(fixtures, VALID + "/" + path).read_text(encoding="ascii")
        assert got.compact == raw, f"{path}: compact is not the committed file"
    assert x.signed[0].payload == x.decoded["contract.json"]
    for f in (
        "profile.json",
        "intent.json",
        "operation.json",
        "actual_operation.json",
        "contract.json",
        "evidence/runtime.json",
        "reputation.json",
    ):
        assert x.decoded.get(f), f"decoded {f} not read"
    for f in ("config.json", "native_context.json", "signing.json"):
        assert f not in x.decoded, f"control file {f} listed as a decoded object"
    rs = x.expected.expected_responses()
    assert len(rs) == 1
    assert rs[0].decision == Decision.ADMISSIBLE
    assert len(rs[0].checks) == 20
    assert rs[0].transport_code is None
    assert rs[0].receipt is not None
    assert rs[0].receipt.typ == "pact-admission+jwt"
    assert rs[0].receipt.signer == "keys/validator.jwk.json"


def test_exchange_defaults(ec: Any) -> None:
    """exchange.json members fill the submissions and handoff attempts with the
    defaults of README section exchange.json."""
    fixtures = ec.repo_fixtures()
    x = conformance.load(fixtures, "admission/attestation-reuse").exchanges[0]
    assert (len(x.submissions), len(x.handoff), len(x.expected.handoff)) == (1, 3, 3)
    first = x.submissions[0]
    for i, h in enumerate(x.handoff):
        op = "other_operation.json" if i == 0 else "actual_operation.json"
        assert h == conformance.HandoffAttempt(
            presentation=first.jti, actual_operation=op, at=first.evaluation.started_at
        ), i
    assert x.decoded.get("other_operation.json"), "other_operation.json not read"

    ss = conformance.load(fixtures, "admission/replay-same-nonce-two-replicas").exchanges[0]
    assert [(s.replica, s.concurrent) for s in ss.submissions] == [("r1", True), ("r2", True)]

    ss = conformance.load(fixtures, "admission/old-presentation-after-eviction").exchanges[0]
    assert [
        (s.replica, s.evict_replay_records, s.evaluation.started_at) for s in ss.submissions
    ] == [("r1", False, 1792080000), ("r1", True, 1792080070)]

    x = conformance.load(fixtures, "admission/replay-store-unavailable").exchanges[0]
    assert x.availability.replay_store == "unavailable"
    assert [s.signed for s in x.submissions] == ["signed/presentation.jws"]


def test_multi_exchange_case(ec: Any) -> None:
    """A sequence.json case loads each exchange directory in order, with the expected
    file under expected/<id>/<exchange>/, and the subject is the exchange sequence.json
    names."""
    id = "approval/approved-fresh-exchange"
    c = conformance.load(ec.repo_fixtures(), id)
    assert len(c.exchanges) == 2
    assert c.subject == 1
    for i, x in enumerate(c.exchanges):
        name = f"exchanges/{i + 1}"
        assert (x.name, x.path, x.expected_path) == (
            name,
            f"{id}/{name}",
            f"expected/{id}/{name}/decision.json",
        )
        assert x.signed


def _verify_dir(root: Path, id: str) -> list[conformance.Signed]:
    keys = conformance.load_keys(root)
    d = next((d for d in conformance.dirs(root) if d.id == id), None)
    assert d is not None, f"dirs lists no {id}"
    return list(conformance.verify(root, d, keys))


@pytest.mark.parametrize(
    ("name", "file"),
    [
        ("decoded edited", "signed/evidence/runtime.jws"),
        ("signature octet", "signed/contract.jws"),
        ("presentation input edited", "signed/presentation.jws"),
        ("signer changed", "signed/reputation.jws"),
    ],
)
def test_stale_signature_fails(ec: Any, name: str, file: str) -> None:
    """A signed file that is not what the generator would keep (spec/v1.0/fixtures/README.md,
    Signed artifacts) fails load and verify, naming the file."""
    root = ec.case_tree(VALID)
    conformance.load(root, VALID)
    if name == "decoded edited":
        ec.edit(root, VALID + "/evidence/runtime.json", "finance-agent-0001", "finance-agent-0009")
    elif name == "signature octet":
        ec.flip_signature(root, VALID + "/signed/contract.jws")
    elif name == "presentation input edited":
        ec.edit(root, VALID + "/intent.json", "invoice-summary", "invoice-summarx")
    else:

        def signer(s: dict[str, Any]) -> None:
            s["artifacts"][2]["signer"] = "issuer"

        ec.edit_json(root, VALID + "/signing.json", signer)
    ec.fails(lambda: conformance.load(root, VALID), VALID, file, "stale")
    ec.fails(lambda: _verify_dir(root, VALID), file, "stale")


def test_stale_digests_fail(ec: Any) -> None:
    """A decoded file whose digests member is not the artifact_digest of the signed file
    it names fails verify, as generate -check counts it as changed."""
    root = ec.case_tree(VALID)

    def digests(s: dict[str, Any]) -> None:
        s["artifacts"][1]["digests"] = {"/subject": "signed/contract.jws"}

    ec.edit_json(root, VALID + "/signing.json", digests)
    ec.fails(lambda: _verify_dir(root, VALID), "evidence/runtime.json", "digests")


def _drop_issuer(c: dict[str, Any], n: dict[str, Any]) -> None:
    c["trust"] = c["trust"][:2]


def _other_issuer(c: dict[str, Any], n: dict[str, Any]) -> None:
    c["trust"][2]["iss"] = "https://reputation.example/other"


def _other_role(c: dict[str, Any], n: dict[str, Any]) -> None:
    c["trust"][1]["role"] = "reputation-service"


def _other_key(c: dict[str, Any], n: dict[str, Any]) -> None:
    c["trust"][0]["keys"] = ["keys/reputation-service.jwk.json"]


def _other_holder(c: dict[str, Any], n: dict[str, Any]) -> None:
    n["authenticated"]["holder_jkt"] = "B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU"


@pytest.mark.parametrize(
    ("file", "want", "mutate"),
    [
        ("signed/reputation.jws", Reason.KID_UNKNOWN, _drop_issuer),
        ("signed/reputation.jws", Reason.KID_UNKNOWN, _other_issuer),
        ("signed/evidence/runtime.jws", Reason.KID_UNKNOWN, _other_role),
        ("signed/contract.jws", Reason.KID_UNKNOWN, _other_key),
        ("signed/presentation.jws", Reason.HOLDER_JKT_MISMATCH, _other_holder),
    ],
    ids=[
        "no record for the issuer",
        "record for another issuer",
        "record for another role",
        "record with another key",
        "other enrolled holder",
    ],
)
def test_trust_records(ec: Any, file: str, want: Reason, mutate: Any) -> None:
    """A signed file that verifies under its signing key but not against the trust
    records loads, with the reason in trust."""
    root = ec.case_tree(VALID)
    cfg = json.loads(ec.at(root, VALID + "/config.json").read_bytes())
    nc = json.loads(ec.at(root, VALID + "/native_context.json").read_bytes())
    mutate(cfg, nc)

    def put(src: dict[str, Any]) -> Any:
        def f(v: dict[str, Any]) -> None:
            v.clear()
            v.update(src)

        return f

    ec.edit_json(root, VALID + "/config.json", put(cfg))
    ec.edit_json(root, VALID + "/native_context.json", put(nc))
    for s in conformance.load(root, VALID).exchanges[0].signed:
        if s.path == file:
            assert reason_of(s.trust) == want, f"{s.path}: trust {s.trust!r}"
        else:
            assert s.trust is None, f"{s.path}: trust {s.trust!r}"


def _write(ec: Any, root: Path, rel: str, body: str) -> None:
    ec.write_file(ec.at(root, rel), body)


@pytest.mark.parametrize(
    "name",
    [
        "unknown config member",
        "no native context",
        "expected responses for a missing submission",
        "unknown exchange member",
        "unknown expected member",
    ],
)
def test_load_rejects(ec: Any, name: str) -> None:
    """load fails on a case it cannot read as the format defines it."""
    root = ec.case_tree(VALID)
    want: tuple[str, ...]
    if name == "unknown config member":
        ec.edit_json(root, VALID + "/config.json", lambda c: c.update(nowx=1))
        want = ("config.json",)
    elif name == "no native context":
        ec.remove_file(ec.at(root, VALID + "/native_context.json"))
        want = ("native_context.json",)
    elif name == "expected responses for a missing submission":
        p = '{"signed":"signed/presentation.jws","jti":"v6wxT-_cB0Ua8Xkqgcuu2g"}'
        _write(ec, root, VALID + "/exchange.json", '{"presentations":[' + p + "," + p + "]}")
        want = ("decision.json", "2 submissions")
    elif name == "unknown exchange member":
        _write(ec, root, VALID + "/exchange.json", '{"presentation":[]}')
        want = ("exchange.json",)
    else:
        ec.edit_json(
            root, "expected/" + VALID + "/decision.json", lambda d: d.update(decison="ADMISSIBLE")
        )
        want = ("decision.json",)
    ec.fails(lambda: conformance.load(root, VALID), *want)


def test_load_rejects_entries(ec: Any) -> None:
    """load names the id when the manifest has no evaluate entry for it."""
    fixtures = ec.repo_fixtures()
    id = "outcomes/qualification/correction-recompute"
    ec.fails(lambda: conformance.load(fixtures, id), id, "kind outcomes")
    id = "admission/no-such-case"
    ec.fails(lambda: conformance.load(fixtures, id), id, "no manifest entry")


def test_read(ec: Any) -> None:
    """read returns the case that load does, with no signed file verified: it needs no
    test keys, and a stale signed file is no error."""
    fixtures = ec.repo_fixtures()
    for e in evaluate_entries(fixtures):
        want = conformance.load(fixtures, e.id)
        got = conformance.read(fixtures, e.id)
        for x in got.exchanges:
            assert not x.signed, f"{e.id} {x.path}: read verified {len(x.signed)} signed files"
        stripped = dataclasses.replace(
            want, exchanges=tuple(dataclasses.replace(x, signed=()) for x in want.exchanges)
        )
        assert got == stripped, f"{e.id}: read and load differ beyond the signed files"


def test_read_no_keys(ec: Any) -> None:
    root = ec.case_tree(VALID)
    ec.remove_file(ec.at(root, "keys/test-private-scalars.json"))
    conformance.read(root, VALID)
    ec.fails(lambda: conformance.load(root, VALID), "test-private-scalars.json")


def test_read_stale_signed_file(ec: Any) -> None:
    root = ec.case_tree(VALID)
    ec.flip_signature(root, VALID + "/signed/contract.jws")
    conformance.read(root, VALID)
    ec.fails(lambda: conformance.load(root, VALID), "stale")


def test_read_structure(ec: Any) -> None:
    """read still checks the structure of the case."""
    root = ec.case_tree(VALID)
    ec.remove_file(ec.at(root, "expected/" + VALID + "/decision.json"))
    ec.fails(lambda: conformance.read(root, VALID), VALID, "decision.json")
    ec.fails(
        lambda: conformance.read(root, "admission/nope"), "admission/nope", "no manifest entry"
    )
    ec.fails(lambda: conformance.read(root, "keys/holder"), "keys/holder")
