"""The adaptertest case model frozen with the adapter contract.

The case model of go/adapter/adaptertest (casefile.go, harness.go and the
options of suite.go; tools/parity/README.md, Adapter contract), the
Hooks recorder, and the shared request decoder that fills RawRequest from a
case request. Every case file under spec/v1.0/fixtures/adapters strict-decodes
into Case: it fails when the fixtures are absent under PACT_REQUIRE_VECTORS=1
(make py-test) and skips otherwise.
"""

from __future__ import annotations

import dataclasses
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hop_top_pact.adapter import adaptertest
from hop_top_pact.adapter.adaptertest import (
    ABSENT,
    Case,
    Env,
    ExpectClaim,
    ExpectDecision,
    ExpectPrincipal,
    Hooks,
    Options,
    Replacement,
    Request,
    Subject,
    TLSPeer,
)
from hop_top_pact.core import binding, strictjson
from hop_top_pact.core.binding import RawRequest, RequestObjectError, decode_request
from hop_top_pact.core.binding._request import DecodedRequest, decode_request_object
from hop_top_pact.core.clock import FakeClock

REPO = Path(__file__).resolve().parents[2]
ADAPTERS = REPO / "spec" / "v1.0" / "fixtures" / "adapters"


def names(cls: type) -> list[str]:
    return [f.name for f in dataclasses.fields(cls)]


def annotation(cls: type, name: str) -> str:
    return str(next(f.type for f in dataclasses.fields(cls) if f.name == name))


def test_one_tls_peer_type() -> None:
    """The case model's TLSPeer is the RawRequest one, with the API names of the
    frozen contract; the case files spell the members the same way."""
    assert adaptertest.TLSPeer is binding.TLSPeer
    assert names(TLSPeer) == ["subject_cn", "issuer_cn", "dns_names", "uris"]
    assert annotation(Request, "tls_peer") == "TLSPeer | None"
    assert annotation(RawRequest, "tls_peer") == "TLSPeer | None"


def test_case_model_member_names() -> None:
    """The member names of the case file format (spec/v1.0/fixtures/adapters/README.md),
    as the Go json tags spell them."""
    want = {
        adaptertest.Case: [
            "case_version",
            "id",
            "title",
            "draft",
            "workloads",
            "now",
            "native_state",
            "request",
            "call",
            "expect",
        ],
        adaptertest.Request: [
            "method",
            "url",
            "headers",
            "body_b64",
            "tls_peer",
            "native_state_ref",
            "arrival",
        ],
        adaptertest.RealmJSON: ["tenant_id", "environment_id"],
        adaptertest.PrincipalJSON: [
            "id",
            "realm",
            "workload",
            "mechanism",
            "authenticated_at",
            "attributes",
        ],
        adaptertest.BindingJSON: ["agent_id", "operator_id", "holder_jkt", "status"],
        adaptertest.ObservationJSON: [
            "event_id",
            "event_kind",
            "context",
            "task_id",
            "operation_id",
            "admission_receipt_id",
            "observed_at",
            "result",
            "dimension",
            "severity",
            "evidence_refs",
            "attribution",
            "supersedes",
            "details",
        ],
        adaptertest.Call: [
            "realm",
            "workload",
            "agent_id",
            "mapping_version",
            "principal",
            "binding",
            "native_path",
            "check_id",
            "intent",
            "operation",
            "evidence_refs",
            "observation",
        ],
        adaptertest.Expect: [
            "function",
            "outcome",
            "reason_code",
            "must_not_call",
            "leak_scan",
            "principal",
            "binding",
            "operation",
            "claim",
            "decision",
        ],
        adaptertest.LeakScan: ["secrets"],
        adaptertest.ExpectPrincipal: ["id", "realm", "workload", "mechanism", "attributes"],
        adaptertest.ExpectBinding: [
            "agent_id",
            "operator_id",
            "holder_jkt",
            "status",
            "enrolled_elsewhere",
        ],
        adaptertest.ExpectOperation: [
            "environment_id",
            "principal_id",
            "action",
            "resources",
            "method",
            "target_uri",
            "body_digest",
            "headers",
        ],
        adaptertest.ExpectClaim: [
            "value",
            "observed_at",
            "status_checked_at",
            "source_id",
            "source_ref",
        ],
        adaptertest.ExpectDecision: [
            "obligations",
            "source_id",
            "source_ref",
            "decided_at",
            "policy_revision",
        ],
        adaptertest.ObligationJSON: ["id", "attributes"],
        adaptertest.Env: ["state", "clock", "hooks"],
        adaptertest.Subject: ["adapter", "arrive", "credential", "verify_outcome"],
        adaptertest.Options: ["fixtures", "adapter", "shared_workloads", "replaced"],
        adaptertest.Replacement: ["by", "reason"],
    }
    for cls, members in want.items():
        assert names(cls) == members, cls.__name__
    assert annotation(adaptertest.ExpectBinding, "enrolled_elsewhere") == "bool | None"


def test_hooks_records_the_hooks_that_ran_in_order() -> None:
    h = Hooks()
    assert h.fired() == []
    h.fire("execute")
    h.fire("notify")
    h.fire("execute")
    got = h.fired()
    assert got == ["execute", "notify", "execute"]
    got.append("tampered")
    assert h.fired() == ["execute", "notify", "execute"], "fired returns a copy"


def test_hooks_is_safe_for_concurrent_use() -> None:
    h = Hooks()
    barrier = threading.Barrier(8)

    def run() -> None:
        barrier.wait()
        for _ in range(200):
            h.fire("execute")

    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert h.fired() == ["execute"] * 1600


def test_request_decoder_reads_a_case_tls_peer_into_raw_request() -> None:
    d = decode_request_object(
        {
            "method": "GET",
            "url": "https://gw.example/x",
            "tls_peer": {
                "subject_cn": "svc-a",
                "issuer_cn": "Corp CA",
                "dns_names": ("a.example",),
                "uris": ("spiffe://example.org/a",),
            },
            "native_state_ref": "alice",
            "arrival": "direct",
        }
    )
    assert isinstance(d, DecodedRequest)
    assert d.request.tls_peer == TLSPeer(
        subject_cn="svc-a",
        issuer_cn="Corp CA",
        dns_names=("a.example",),
        uris=("spiffe://example.org/a",),
    )
    assert d.request.raw_request_uri == "https://gw.example/x"
    assert d.native_state_ref == "alice"
    assert d.arrival == "direct"


def test_request_decoder_defaults_and_arrival() -> None:
    d = decode_request_object({"method": "POST", "url": "/a", "body_b64": "aGk="})
    assert (d.native_state_ref, d.arrival) == ("", "")
    assert d.request == RawRequest(method="POST", raw_request_uri="/a", body=b"hi")
    assert decode_request({"method": "POST", "url": "/a", "body_b64": "aGk="}) == d.request
    assert decode_request_object(
        {"method": "GET", "url": "/", "arrival": "enforcement_point"}
    ).arrival == ("enforcement_point")
    for bad in ("gateway", "DIRECT"):
        with pytest.raises(RequestObjectError, match="arrival"):
            decode_request_object({"method": "GET", "url": "/", "arrival": bad})
    with pytest.raises(RequestObjectError):
        decode_request_object({"method": "GET", "url": "/", "native_state_ref": 7})


def test_absent_members_are_told_from_null() -> None:
    """A json.RawMessage member of Go tells an absent member from a JSON null:
    absent is not checked, null requires no value. Here absent is ABSENT."""
    claim = strictjson.decode(b'{"source_id": "dir"}', ExpectClaim)
    assert (claim.value, claim.observed_at, claim.status_checked_at) == (ABSENT, ABSENT, ABSENT)
    claim = strictjson.decode(
        b'{"value": null, "observed_at": null, "status_checked_at": 7}', ExpectClaim
    )
    assert (claim.value, claim.observed_at, claim.status_checked_at) == (None, None, 7)
    decision = strictjson.decode(b'{"source_ref": null}', ExpectDecision)
    assert (decision.source_ref, decision.decided_at) == (None, ABSENT)
    principal = strictjson.decode(b'{"id": "p"}', ExpectPrincipal)
    assert principal.attributes is ABSENT
    principal = strictjson.decode(b'{"attributes": {"groups": ["a"]}}', ExpectPrincipal)
    assert principal.attributes == {"groups": ("a",)}


def test_harness_values() -> None:
    o = Options()
    assert (o.fixtures, o.adapter, o.shared_workloads, dict(o.replaced)) == (None, "", False, {})
    r = Replacement(by="MTLS-01.direct", reason="the mechanism has no header form")
    o = Options(adapter="mtls", replaced={"COMMON-02.direct": r})
    assert o.replaced["COMMON-02.direct"].by == "MTLS-01.direct"
    env = Env(
        state={"model": "common/1"},
        clock=FakeClock(datetime(2026, 1, 1, tzinfo=UTC)),
        hooks=Hooks(),
    )
    assert env.hooks.fired() == []
    s = Subject(adapter=None, arrive=lambda req: req)  # type: ignore[arg-type]
    assert (s.credential, s.verify_outcome) == (None, None)


def case_files() -> list[Path]:
    if not ADAPTERS.is_dir():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{ADAPTERS} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    return sorted(p for d in ADAPTERS.iterdir() if d.is_dir() for p in d.glob("*.json"))


def test_every_case_file_decodes_into_the_model() -> None:
    """The model has a field for every member the case files use: a strict decode
    refuses an unknown member. A case request also goes through the shared
    request decoder."""
    files = case_files()
    common = [p for p in files if p.parent.name == "_common"]
    assert len(common) >= 84, f"{len(common)} common cases"
    for p in files:
        data = p.read_bytes()
        c = strictjson.decode(data, Case, strictjson.Limits(max_bytes=1 << 20))
        assert c.case_version == 1, p.name
        assert c.id, p.name
        assert c.expect.function, p.name
        tree = strictjson.parse(data)
        assert isinstance(tree, dict)
        if c.request is None:
            assert "request" not in tree, p.name
            continue
        d = decode_request_object(tree["request"])
        assert d.request.method == c.request.method, p.name
        assert d.request.raw_request_uri == c.request.url, p.name
        assert d.request.tls_peer == c.request.tls_peer, p.name
        assert d.native_state_ref == c.request.native_state_ref, p.name
        assert d.arrival == c.request.arrival, p.name
        assert list(d.request.headers) == list(c.request.headers.items()), p.name
