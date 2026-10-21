"""The suite's request builder, case harness and entry points.

Port of go/adapter/adaptertest/suite_test.go. Go's Run is split into
conformance_cases and run_case, Go's Evaluate is evaluate_conformance, and
Go's runCase, which both use, is suite.case_failures. A factory raises where
a Go factory returns an error or panics, and an adapter function that raises
an exception other than a PactError fails the case as a Go panic does.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.adapter import Decision, Effect, NativeDenial, Principal
from hop_top_pact.adapter.adaptertest import (
    CaseFailure,
    Env,
    LoadError,
    Options,
    Request,
    Subject,
    TLSPeer,
    conformance_cases,
    default_fixtures,
    evaluate_conformance,
    load_cases,
    run_case,
)
from hop_top_pact.adapter.adaptertest.request import build_request
from hop_top_pact.core.binding import RawRequest, RequestObjectError
from hop_top_pact.core.clock import FakeClock
from hop_top_pact.errors import PactError


def test_build_request() -> None:
    # url is kept as stated
    url = "https://svc:pw@internal.local:8443/a%2Fb/c?x=%2f&y=1#frag"
    r, body = build_request(
        Request(
            method="POST",
            url=url,
            headers={"X-One": "1", "host": "front.example"},
            body_b64="aGVsbG8=",
        )
    )
    assert r.method == "POST"
    # The request is the one a server took off the wire: its request-target
    # is the url, in absolute-form, octet for octet.
    assert r.raw_request_uri == url
    # The field lines in member order, names as stated; host stays a field
    # line, since RawRequest has no separate host.
    assert list(r.headers) == [("X-One", "1"), ("host", "front.example")]
    assert (r.body, body) == (b"hello", b"hello")

    # no body
    r, body = build_request(Request(method="GET", url="https://gateway.example/"))
    assert (r.body, body) == (b"", b"")
    assert r.tls_peer is None

    # tls peer
    peer = TLSPeer(
        subject_cn="alice",
        issuer_cn="Test CA",
        dns_names=("alice.example",),
        uris=("spiffe://example/alice",),
    )
    r, _ = build_request(Request(method="GET", url="https://gateway.example/", tls_peer=peer))
    assert r.tls_peer == peer

    # errors
    for name, req in {
        "bad body": Request(method="GET", url="https://x.example/", body_b64="***"),
        "bad url": Request(method="GET", url="https://x.example/%zz"),
        "bad method": Request(method="G ET", url="https://x.example/"),
        "bad peer": Request(
            method="GET", url="https://x.example/", tls_peer=TLSPeer(uris=("%zz",))
        ),
    }.items():
        with pytest.raises(RequestObjectError):
            build_request(req)
        assert issubclass(RequestObjectError, PactError), name


def auth_denied(at: Any) -> Any:
    """A case any denying fake passes."""
    return at.complete(at.auth_case("denied"))


def test_run_case_harness(at: Any) -> None:
    denial = NativeDenial("NO_CREDENTIAL")
    denying = at.auth_fake(Principal(), denial)

    # factory error
    def no_state(env: Env) -> Subject:
        raise at.Wrapped("no such state")

    at.want_fails(at.case_failures(no_state, auth_denied(at)), "factory: no such state")

    # factory panic: an exception other than a PactError
    def boom(env: Env) -> Subject:
        raise RuntimeError("boom")

    at.want_fails(at.case_failures(boom, auth_denied(at)), "factory raised RuntimeError: boom")

    # no adapter
    def no_adapter(env: Env) -> Any:
        return Subject(adapter=None, arrive=lambda r: r)  # type: ignore[arg-type]

    at.want_fails(at.case_failures(no_adapter, auth_denied(at)), "no adapter")

    # not a Subject
    at.want_fails(at.case_failures(lambda env: denying, auth_denied(at)), "want a Subject")

    # no arrive hook
    def no_arrive(env: Env) -> Any:
        return Subject(adapter=denying, arrive=None)  # type: ignore[arg-type]

    at.want_fails(at.case_failures(no_arrive, auth_denied(at)), "no arrive hook")

    # no credential hook
    def no_credential(env: Env) -> Subject:
        return Subject(adapter=denying, arrive=lambda r: r)

    at.want_fails(at.case_failures(no_credential, auth_denied(at)), "no credential hook", "'alice'")

    # credential error
    def bad_credential(r: RawRequest, ref: str) -> RawRequest:
        raise at.Wrapped("unknown ref")

    def credential_error(env: Env) -> Subject:
        return Subject(adapter=denying, arrive=lambda r: r, credential=bad_credential)

    at.want_fails(at.case_failures(credential_error, auth_denied(at)), "unknown ref")

    # arrive returns None
    def arrive_none(env: Env) -> Subject:
        return Subject(
            adapter=denying,
            arrive=lambda r: None,  # type: ignore[arg-type,return-value]
            credential=lambda r, ref: r,
        )

    at.want_fails(at.case_failures(arrive_none, auth_denied(at)), "arrive returned None")

    # adapter panic
    def nil_map(req: RawRequest) -> Principal:
        raise KeyError("nil map")

    at.want_fails(
        at.run_fake(at.FakeAdapter(auth=nil_map), at.auth_case("denied")),
        "authenticate_native raised KeyError: 'nil map'",
    )

    # arrive runs, unless the request is direct
    marked: list[bool] = []

    def auth(r: RawRequest) -> Principal:
        marked.append(("X-Arrived", "1") in r.headers)
        raise denial

    def marking(env: Env) -> Subject:
        return Subject(
            adapter=at.FakeAdapter(auth=auth),
            arrive=lambda r: replace(r, headers=(*r.headers, ("X-Arrived", "1"))),
            credential=lambda r, ref: r,
        )

    via = auth_denied(at)
    direct = replace(via, request=replace(via.request, arrival="direct"))
    for c in (via, direct):
        at.want_clean(at.case_failures(marking, c))
    assert marked == [True, False]

    # env: state, clock, hooks
    envs: list[Env] = []

    def keep(env: Env) -> Any:
        envs.append(env)
        return at.factory_for(denying)(env)

    c = replace(auth_denied(at), native_state={"model": "x"})
    at.want_clean(at.case_failures(keep, c))
    env = envs[-1]
    assert env.state == {"model": "x"}
    assert env.clock.now() == at.NOW, "the default now"
    assert env.hooks is not None
    c = replace(c, now=1_900_000_000)
    at.want_clean(at.case_failures(keep, c))
    assert envs[-1].clock.now() == at.EPOCH + timedelta(seconds=1_900_000_000)
    assert isinstance(envs[-1].clock, FakeClock), "a fake clock, not the wall clock"

    # each case gets a fresh adapter and fresh hooks
    seen: list[Any] = []

    def fire(env: Env) -> Any:
        seen.append(env.hooks)
        env.hooks.fire("execute")
        return at.factory_for(denying)(env)

    for _ in range(2):
        at.case_failures(fire, auth_denied(at))
    assert len(seen) == 2
    assert seen[0] is not seen[1]
    assert len(seen[1].fired()) == 1


def test_must_not_call(at: Any) -> None:
    deny = at.authz_fake(Decision(effect=Effect.DENY, source_id="policy-1"), None)

    def fires(*names: str) -> Any:
        def factory(env: Env) -> Any:
            for n in names:
                env.hooks.fire(n)
            return at.factory_for(deny)(env)

        return factory

    def case(*forbidden: str) -> Any:
        return at.complete(at.authz_case("DENY", must_not_call=forbidden))

    at.want_clean(at.case_failures(fires(), case("execute")))
    at.want_clean(at.case_failures(fires("audit"), case("execute")))
    at.want_clean(at.case_failures(fires("execute"), case()))
    at.want_fails(at.case_failures(fires("execute"), case("execute")), "hook 'execute' fired")
    at.want_fails(
        at.case_failures(fires("audit", "execute"), case("grant", "execute")),
        "hook 'execute' fired",
    )


def test_run_and_evaluate(at: Any) -> None:
    minimal = at.MINIMAL_CASE
    fixtures = at.tree_of(
        {
            "adapters/_common/a.json": minimal,
            "adapters/_common/b.json": minimal.replace("COMMON-01.one", "COMMON-01.two", 1).replace(
                '"denied"', '"error"', 1
            ),
        }
    )
    denying = at.auth_fake(Principal(), NativeDenial("NO_CREDENTIAL"))

    # evaluate
    res = evaluate_conformance(at.factory_for(denying), Options(fixtures=fixtures))
    assert len(res) == 2
    assert res[0].id == "COMMON-01.one"
    assert res[0].passed()
    res = evaluate_conformance(
        at.factory_for(at.auth_fake(at.good_principal(), None)), Options(fixtures=fixtures)
    )
    for r in res:
        assert not r.passed(), f"{r.id} passes against an adapter that authenticates everyone"

    # evaluate reports a load error
    with pytest.raises(LoadError):
        evaluate_conformance(at.factory_for(denying), Options(fixtures=at.tree_of({})))

    # run passes when the adapter does
    opts = Options(fixtures=at.tree_of({"adapters/_common/a.json": minimal}))
    cases, ids = conformance_cases(opts)
    assert ids == ["COMMON-01.one"]
    for c in cases:
        assert run_case(at.factory_for(denying), c, opts) == []

    # run fails when the adapter does: CaseFailure, an AssertionError
    everyone = at.factory_for(at.auth_fake(at.good_principal(), None))
    with pytest.raises(CaseFailure) as e:
        run_case(everyone, cases[0], opts)
    assert isinstance(e.value, AssertionError)
    assert isinstance(e.value, PactError)
    assert e.value.case_id == "COMMON-01.one"
    assert e.value.failures
    assert "COMMON-01.one" in str(e.value)


def test_workload_modes(at: Any) -> None:
    """A case marked "shared" runs only when the adapter's profile supports
    workloads shared by several agents, one marked "dedicated" only when it does
    not, and an unmarked case in both runs."""

    def mark(cid: str, mode: str, outcome: str) -> str:
        s = at.MINIMAL_CASE.replace("COMMON-01.one", cid, 1).replace(
            '"denied"', '"' + outcome + '"', 1
        )
        if mode:
            s = s.replace(
                '"title": "A case",', '"title": "A case", "workloads": "' + mode + '",', 1
            )
        return str(s)

    # The denying adapter fails the cases that expect an error, so a case that
    # runs in the wrong mode fails the run below.
    fixtures = at.tree_of(
        {
            "adapters/_common/a.json": mark("COMMON-01.both", "", "denied"),
            "adapters/_common/b.json": mark("COMMON-01.shared", "shared", "error"),
            "adapters/_common/c.json": mark("COMMON-01.dedicated", "dedicated", "error"),
            "adapters/_common/d.json": mark("COMMON-01.shared-denied", "shared", "denied"),
            "adapters/_common/e.json": mark("COMMON-01.dedicated-denied", "dedicated", "denied"),
        }
    )
    denying = at.auth_fake(Principal(), NativeDenial("NO_CREDENTIAL"))
    for shared, want in (
        (False, ["COMMON-01.both", "COMMON-01.dedicated", "COMMON-01.dedicated-denied"]),
        (True, ["COMMON-01.both", "COMMON-01.shared", "COMMON-01.shared-denied"]),
    ):
        opts = Options(fixtures=fixtures, shared_workloads=shared)
        res = evaluate_conformance(at.factory_for(denying), opts)
        assert sorted(r.id for r in res) == want
        _, ids = conformance_cases(opts)
        assert sorted(ids) == want

    # run skips the cases of the other mode
    only = at.tree_of(
        {
            "adapters/_common/a.json": mark("COMMON-01.both", "", "denied"),
            "adapters/_common/b.json": mark("COMMON-01.shared", "shared", "error"),
            "adapters/_common/d.json": mark("COMMON-01.dedicated-denied", "dedicated", "denied"),
        }
    )
    opts = Options(fixtures=only)
    for c in conformance_cases(opts)[0]:
        run_case(at.factory_for(denying), c, opts)
    only = at.tree_of(
        {
            "adapters/_common/a.json": mark("COMMON-01.both", "", "denied"),
            "adapters/_common/c.json": mark("COMMON-01.dedicated", "dedicated", "error"),
            "adapters/_common/e.json": mark("COMMON-01.shared-denied", "shared", "denied"),
        }
    )
    opts = Options(fixtures=only, shared_workloads=True)
    for c in conformance_cases(opts)[0]:
        run_case(at.factory_for(denying), c, opts)


def test_default_fixtures(at: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = at.repo_fixtures()
    monkeypatch.chdir(at.REPO / "py" / "tests")
    fsys = default_fixtures()
    assert fsys.resolve() == root.resolve()
    assert load_cases(fsys), "the default fixture tree has no common cases"
    # Outside the source repository there is none.
    monkeypatch.chdir(tmp_path)
    with pytest.raises(LoadError, match=r"set Options\.fixtures"):
        default_fixtures()
