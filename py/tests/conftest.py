"""Shared helpers of the runner.manifest tests, as the fixture ``mk``.

The port of go/runner/manifest/helpers_test.go: a valid base manifest with
one entry of each shape the tests need, its files, a spec map that cites it,
and a scratch fixture tree on disk. The tests take them through the fixture
``mk`` (a ManifestKit), since a test module cannot import a sibling module.
"""

from __future__ import annotations

import base64
import copy
import json
import os
from collections.abc import Callable, Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact.adapter import (
    AgentBinding,
    BindingStatus,
    CheckOutcome,
    Decision,
    Descriptor,
    NativeClaim,
    Principal,
    Realm,
)
from hop_top_pact.adapter.adaptertest import RealmJSON
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.clock import FakeClock
from hop_top_pact.core.enums import CausalAssessment, Dimension, EventKind, OutcomeResult, Severity
from hop_top_pact.core.types import Attribution, OperationContext, ReputationContext
from hop_top_pact.errors import PactError
from hop_top_pact.runner import manifest

PY_ROOT = Path(__file__).resolve().parents[1]
REPO = PY_ROOT.parent

Entry = dict[str, Any]

# The base manifest: one entry of each shape the tests need, sorted by id.
_BASE_ENTRIES: list[Entry] = [
    {
        "id": "adapters/db/schema",
        "kind": "adapter-asset",
        "scope": "adapter",
        "path": "adapters/db/assets",
        "expected": None,
        "outcome": None,
        "spec_map_row": "CL-C",
        "draft_section": "17.1",
    },
    {
        "id": "admission/valid",
        "kind": "evaluate",
        "scope": "runner",
        "path": "admission/valid",
        "expected": "expected/admission/valid/decision.json",
        "outcome": "ADMISSIBLE",
        "spec_map_row": "CL-11.3",
        "draft_section": "11.3",
    },
    {
        "id": "keys/holder",
        "kind": "key",
        "scope": "core",
        "path": "keys/holder.jwk.json",
        "expected": None,
        "outcome": None,
        "spec_map_row": "CL-C",
        "draft_section": "C",
    },
    {
        "id": "vectors/jcs/arrays",
        "kind": "vector",
        "scope": "core",
        "path": "vectors/jcs/input/arrays.json",
        "expected": "vectors/jcs/output/arrays.json",
        "outcome": "ACCEPTED",
        "spec_map_row": "CL-C",
        "draft_section": "7.4",
    },
]

# The files of the base tree, other than manifest.json.
BASE_FILES = (
    "README.md",
    "manifest.schema.json",
    "adapters/README.md",
    "adapters/db/assets/schema.sql",
    "admission/valid/config.json",
    "admission/valid/signed/contract.jws",
    "expected/admission/valid/decision.json",
    "keys/README.md",
    "keys/holder.jwk.json",
    "vectors/jcs/input/arrays.json",
    "vectors/jcs/output/arrays.json",
)

# Cites every base entry's row. Every group of the base entries and rows has a
# status: admission is partial (admission/valid is registered,
# admission/wrong-tenant is reserved), approval and parse are planned, and
# adapters, keys and vectors are landed.
BASE_SPEC_MAP = (
    "# Spec map\n\n"
    "## Fixture groups\n\n"
    "| Group | Directory | Covers | Status |\n"
    "|---|---|---|---|\n"
    "| admission | `fixtures/admission/` | Positive control | partial |\n"
    "| approval | `fixtures/approval/` | Approval states | planned |\n"
    "| parse | `fixtures/parse/` | Strict parse \\| JWS | planned |\n"
    "| adapters | `fixtures/adapters/` | Adapter cases | landed |\n"
    "| keys | `fixtures/keys/` | Test keys | landed |\n"
    "| vectors | `fixtures/vectors/` | Vectors | landed |\n\n"
    "## Conformance map\n\n"
    "| ID | Check | Draft section | Finding | Fixture(s) |\n"
    "|----|-------|---------------|---------|------------|\n"
    "| CL-11.3 | Positive control | 11.3 | G13 | admission/valid, admission/wrong-tenant |\n"
    "| CL-C | Test keys | C | G13 | keys/holder |\n"
    "| CL-17.3.1 | Approval | 17.3 | G06 | approval/pending, parse/alg-none |\n\n"
    "```\n## Not a section\n```\n"
)


class Tree:
    """A scratch fixture directory, fixtures/, with spec-map.md beside it."""

    def __init__(self, dir: Path, entries: list[Entry]) -> None:
        self.dir = dir
        self.root = dir / "fixtures"
        self.spec_map = dir / "spec-map.md"
        for f in BASE_FILES:
            self.write(f, "{}")
        self.write("manifest.json", encode(entries).decode("utf-8"))
        self.spec_map.write_text(BASE_SPEC_MAP, encoding="utf-8", newline="")

    def write(self, rel: str, content: str) -> None:
        full = self.root / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content, encoding="utf-8", newline="")

    def mkdir(self, rel: str) -> None:
        (self.root / rel).mkdir(parents=True, exist_ok=True)

    def remove(self, rel: str) -> None:
        full = self.root / rel
        if full.is_dir() and not full.is_symlink():
            for sub, dirs, files in os.walk(full, topdown=False):
                for name in files:
                    os.remove(os.path.join(sub, name))
                for name in dirs:
                    os.rmdir(os.path.join(sub, name))
            full.rmdir()
        elif os.path.lexists(full):
            full.unlink()

    def set_spec_map(self, text: str) -> None:
        self.spec_map.write_text(text, encoding="utf-8", newline="")

    def manifest(self) -> manifest.Manifest:
        return manifest.load(self.root)


def base_entries() -> list[Entry]:
    """A fresh copy of the base manifest's entries."""
    return copy.deepcopy(_BASE_ENTRIES)


def encode(entries: list[Entry]) -> bytes:
    """entries as a manifest document, written as Go's json.MarshalIndent writes a map."""
    doc = {"manifest_version": 1, "entries": entries}
    return json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")


def parse(data: bytes) -> manifest.Manifest:
    return manifest.parse(data)


def rules(ps: manifest.Problems) -> list[str]:
    """The distinct rules of ps, sorted."""
    return sorted({p.rule for p in ps})


def want_rule(ps: manifest.Problems, rule: str, where: str = "") -> None:
    """ps has a problem of rule at where (anywhere when where is empty), and no other rule."""
    others = [str(p) for p in ps if p.rule != rule]
    assert not others, "unexpected problems:\n" + "\n".join(others)
    found = any(not where or p.where == where for p in ps)
    assert found, f"no {rule} problem at {where!r}; got:\n{ps}"


def want_clean(ps: manifest.Problems) -> None:
    assert len(ps) == 0, f"want no problems, got:\n{ps}"


def want_where(ps: manifest.Problems, rule: str, where: str) -> None:
    assert any(p.rule == rule and p.where == where for p in ps), (
        f"no {rule} problem at {where}:\n{ps}"
    )


def must_contain(s: str, *parts: str) -> None:
    for p in parts:
        assert p in s, f"{s!r} does not contain {p!r}"


class ManifestKit:
    """The helpers, bound to a scratch directory factory."""

    REPO = REPO
    REPO_FIXTURES = REPO / "spec" / "v1.0" / "fixtures"
    REPO_SPEC_MAP = REPO / "spec" / "v1.0" / "spec-map.md"
    BASE_SPEC_MAP = BASE_SPEC_MAP
    base_entries = staticmethod(base_entries)
    encode = staticmethod(encode)
    parse = staticmethod(parse)
    rules = staticmethod(rules)
    want_rule = staticmethod(want_rule)
    want_clean = staticmethod(want_clean)
    want_where = staticmethod(want_where)
    must_contain = staticmethod(must_contain)

    def __init__(self, mktemp: Callable[[], Path]) -> None:
        self._mktemp = mktemp

    def new_tree(self, entries: list[Entry] | None = None) -> Tree:
        return Tree(self._mktemp(), base_entries() if entries is None else entries)

    def tmp(self) -> Path:
        return self._mktemp()

    def repo_fixtures(self) -> Path:
        """spec/v1.0/fixtures of the repository; absent in a mirror or mutation copy."""
        if not (self.REPO_FIXTURES / "manifest.json").exists():
            if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
                pytest.fail(f"{self.REPO_FIXTURES} absent under PACT_REQUIRE_VECTORS=1")
            pytest.skip("no spec/ tree (mirror checkout)")
        return self.REPO_FIXTURES

    def repo_file(self, *parts: str) -> Path:
        """A repository file outside py/ and spec/: skipped when absent."""
        path = self.REPO.joinpath(*parts)
        if not path.exists():
            pytest.skip(f"{'/'.join(parts)} absent")
        return path


@pytest.fixture
def mk(tmp_path_factory: pytest.TempPathFactory) -> ManifestKit:
    return ManifestKit(lambda: tmp_path_factory.mktemp("manifest"))


# The adaptertest helpers: the port of go/adapter/adaptertest/fake_test.go and
# of the case builders of its test files, as the fixture ``at``. The suite's
# own modules are imported inside the functions that use them, so that a
# missing suite fails the adaptertest tests and nothing else.

AT_NOW_SEC = 1_792_080_000
AT_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
AT_NOW = AT_EPOCH + timedelta(seconds=AT_NOW_SEC)
AT_ACME = Realm(tenant_id="acme", environment_id="https://gateway.example/environments/finance")
AT_ACME_JS = RealmJSON(
    tenant_id="acme", environment_id="https://gateway.example/environments/finance"
)

MINIMAL_CASE = """{
  "case_version": 1,
  "id": "COMMON-01.one",
  "title": "A case",
  "draft": ["17.1"],
  "native_state": {"model": "common/1"},
  "request": {"method": "GET", "url": "https://gateway.example/x"},
  "expect": {"function": "authenticate_native", "outcome": "denied"}
}"""


class Wrapped(PactError):
    """A PactError that wraps another, as fmt.Errorf with %w does."""


def wrap(msg: str, cause: BaseException) -> Wrapped:
    e = Wrapped(msg)
    e.__cause__ = cause
    return e


def result_of(value: Any, err: BaseException | None) -> Callable[..., Any]:
    """A function that raises err when it is set and returns value otherwise."""

    def f(*_: Any) -> Any:
        if err is not None:
            raise err
        return value

    return f


class FakeAdapter:
    """An adapter whose behavior each test scripts. A function that is not set
    returns the zero value, which the suite treats as a wrong answer."""

    def __init__(
        self,
        *,
        auth: Callable[..., Any] | None = None,
        bind: Callable[..., Any] | None = None,
        map_op: Callable[..., Any] | None = None,
        claim: Callable[..., Any] | None = None,
        check: Callable[..., Any] | None = None,
        authz: Callable[..., Any] | None = None,
        record: Callable[..., Any] | None = None,
    ) -> None:
        self.auth, self.bind, self.map_op, self.claim = auth, bind, map_op, claim
        self.check, self.authz, self.record = check, authz, record

    def describe(self) -> Descriptor:
        return Descriptor(protocol="fake")

    def authenticate_native(self, req: RawRequest) -> Any:
        return Principal() if self.auth is None else self.auth(req)

    def resolve_agent_binding(self, realm: Realm, workload: str, agent: str) -> Any:
        return AgentBinding() if self.bind is None else self.bind(realm, workload, agent)

    def map_operation(self, req: RawRequest, p: Principal, version: str) -> Any:
        if self.map_op is None:
            return zero_op()
        return self.map_op(req, p, version)

    def read_native_claim(self, path: str, c: Any) -> Any:
        return NativeClaim() if self.claim is None else self.claim(path, c)

    def check_context(self, check_id: str, inp: Any) -> Any:
        return CheckOutcome() if self.check is None else self.check(check_id, inp)

    def authorize_native(self, p: Principal, op: OperationContext) -> Any:
        return Decision() if self.authz is None else self.authz(p, op)

    def record_outcome(self, o: Any) -> Any:
        return None if self.record is None else self.record(o)


def zero_op() -> OperationContext:
    return OperationContext(
        operation_id="",
        environment_id="",
        principal_id="",
        action="",
        resources=(),
        method="",
        target_uri="",
        body_digest="",
        headers={},
    )


def factory_for(fake: Any) -> Callable[[Any], Any]:
    """A Factory that hands out fake with an arrive hook that marks nothing and a
    credential hook that adds a bearer token."""
    from hop_top_pact.adapter.adaptertest import Subject

    def credential(r: RawRequest, ref: str) -> RawRequest:
        return replace(r, headers=(*r.headers, ("Authorization", "Bearer tok-" + ref)))

    def factory(env: Any) -> Any:
        return Subject(adapter=fake, arrive=lambda r: r, credential=credential)

    return factory


def case_failures(factory: Any, c: Any) -> list[str]:
    from hop_top_pact.adapter.adaptertest.suite import case_failures as run

    return run(factory, c)


def complete(c: Any) -> Any:
    """c with the id and native state a case file needs."""
    if c.native_state is None:
        c = replace(c, native_state={})
    if not c.id:
        c = replace(c, id="T-01")
    return c


def run_fake(fake: Any, c: Any) -> list[str]:
    """Run one case against fake and return the failures."""
    return case_failures(factory_for(fake), complete(c))


def want_no_failures(fails: list[str]) -> None:
    assert not fails, f"unexpected failures: {fails}"


def want_fails(fails: list[str], *subs: str) -> None:
    """Some failure contains each substring, and there is a failure at all."""
    assert fails, f"the case passed, want failures containing {subs}"
    for s in subs:
        assert any(s in f for f in fails), f"no failure contains {s!r}; failures: {fails}"


def run_rows(rows: list[tuple[str, Any, Any, tuple[str, ...]]]) -> None:
    """Run each row, a name, a fake, a case and the failures expected (none for a
    pass), and report every row whose result differs."""
    bad: list[str] = []
    for name, fake, c, fails in rows:
        got = run_fake(fake, c)
        if not fails and got:
            bad.append(f"{name}: unexpected failures: {got}")
        elif fails and not got:
            bad.append(f"{name}: the case passed, want failures containing {fails}")
        else:
            bad.extend(
                f"{name}: no failure contains {s!r}; failures: {got}"
                for s in fails
                if not any(s in f for f in got)
            )
    assert not bad, "\n".join(bad)


def tree_of(files: dict[str, str]) -> FixtureTree:
    return FixtureTree(files)


def good_principal() -> Principal:
    """An authenticated principal that satisfies every invariant."""
    return Principal(
        id="https://idp.example/alice",
        realm=AT_ACME,
        workload="w-1",
        mechanism="bearer",
        authenticated_at=AT_NOW,
    )


def good_op() -> OperationContext:
    """An operation context that satisfies every invariant."""
    return OperationContext(
        operation_id="op-1",
        environment_id=AT_ACME.environment_id,
        principal_id="https://idp.example/alice",
        action="invoice.read",
        resources=("https://invoices.example/invoices/1",),
        method="GET",
        target_uri="https://gateway.example/invoices/1",
        body_digest="47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
        headers={},
    )


def good_binding() -> AgentBinding:
    return AgentBinding(
        agent_id="https://identity.example/agents/a",
        operator_id="https://identity.example/operators/o",
        holder_jkt="xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
        status=BindingStatus.ACTIVE,
        observed_at=AT_NOW - timedelta(hours=1),
        status_checked_at=AT_NOW - timedelta(minutes=1),
        source_id="registry",
    )


def good_claim() -> NativeClaim:
    return NativeClaim(
        value=("approver",),
        observed_at=AT_NOW - timedelta(hours=1),
        status_checked_at=AT_NOW - timedelta(seconds=30),
        source_id="directory-1",
        source_ref="entry-17",
    )


def _expect(function: str, outcome: str, kw: dict[str, Any]) -> Any:
    from hop_top_pact.adapter.adaptertest import Expect

    return Expect(function=function, outcome=outcome, **kw)


def _principal_json() -> Any:
    from hop_top_pact.adapter.adaptertest import PrincipalJSON

    return PrincipalJSON(id=good_principal().id, realm=AT_ACME_JS, workload="w-1")


def auth_case(outcome: str, **expect: Any) -> Any:
    from hop_top_pact.adapter.adaptertest import Case, Request

    return Case(
        request=Request(
            method="GET", url="https://gateway.example/invoices/1", native_state_ref="alice"
        ),
        expect=_expect("authenticate_native", outcome, expect),
    )


def auth_fake(p: Any, err: BaseException | None) -> FakeAdapter:
    return FakeAdapter(auth=result_of(p, err))


def bind_case(outcome: str, **expect: Any) -> Any:
    from hop_top_pact.adapter.adaptertest import Call, Case

    return Case(
        call=Call(realm=AT_ACME_JS, workload="w-1", agent_id="https://identity.example/agents/a"),
        expect=_expect("resolve_agent_binding", outcome, expect),
    )


def bind_fake(b: Any, err: BaseException | None) -> FakeAdapter:
    return FakeAdapter(bind=result_of(b, err))


def map_case(outcome: str, request: Any = None, **expect: Any) -> Any:
    from hop_top_pact.adapter.adaptertest import Call, Case, Request

    req = request if request is not None else Request()
    req = replace(
        req,
        method=req.method or "GET",
        url=req.url or "https://gateway.example/invoices/1",
    )
    return Case(
        request=req,
        call=Call(mapping_version="map-1", principal=_principal_json()),
        expect=_expect("map_operation", outcome, expect),
    )


def map_fake(op: Any, err: BaseException | None) -> FakeAdapter:
    return FakeAdapter(map_op=result_of(op, err))


def claim_case(outcome: str, **expect: Any) -> Any:
    from hop_top_pact.adapter.adaptertest import Call, Case

    return Case(
        call=Call(native_path="/attributes/environment/roles", principal=_principal_json()),
        expect=_expect("read_native_claim", outcome, expect),
    )


def claim_fake(c: Any, err: BaseException | None) -> FakeAdapter:
    return FakeAdapter(claim=result_of(c, err))


def check_case(check_id: str, outcome: str, **expect: Any) -> Any:
    from hop_top_pact.adapter.adaptertest import Call, Case

    return Case(
        call=Call(check_id=check_id, principal=_principal_json(), operation=good_op()),
        expect=_expect("check_context", outcome, expect),
    )


def check_fake(out: Any) -> FakeAdapter:
    return FakeAdapter(check=result_of(out, None))


def authz_case(outcome: str, **expect: Any) -> Any:
    from hop_top_pact.adapter.adaptertest import Call, Case

    return Case(
        call=Call(principal=_principal_json(), operation=good_op()),
        expect=_expect("authorize_native", outcome, expect),
    )


def authz_fake(d: Any, err: BaseException | None) -> FakeAdapter:
    return FakeAdapter(authz=result_of(d, err))


def record_case(outcome: str, kind: EventKind, result: OutcomeResult, **expect: Any) -> Any:
    from hop_top_pact.adapter.adaptertest import Call, Case, ObservationJSON

    return Case(
        call=Call(
            observation=ObservationJSON(
                event_id="event-1",
                event_kind=kind,
                context=ReputationContext(
                    tenant_id="acme",
                    environment_id=AT_ACME.environment_id,
                    agent_id="https://identity.example/agents/a",
                    purpose_id="p",
                    action_class="a",
                    resource_class="r",
                    runtime_class="managed",
                ),
                task_id="task-1",
                operation_id="op-1",
                observed_at=AT_NOW_SEC - 5,
                result=result,
                dimension=Dimension.RELIABILITY,
                severity=Severity.INFO,
                evidence_refs=("native-record:1",),
                supersedes=(),
                attribution=Attribution(
                    native_task_ref="task-1",
                    independence_group="g",
                    causal_assessment=CausalAssessment.UNKNOWN,
                    assessment_ref=None,
                ),
            )
        ),
        expect=_expect("record_outcome", outcome, expect),
    )


def report_of(o: Any) -> dict[str, Any]:
    """The outcome report of the observation o, as the JSON object a recorder signs."""
    sec = (o.observed_at - AT_EPOCH) // timedelta(seconds=1)
    return {
        "pact_version": "0.1",
        "iss": "https://gateway.example/reporters/finance",
        "sub": o.context.agent_id,
        "aud": "https://reputation.example/service",
        "jti": "AAAAAAAAAAAAAAAAAAAAAA",
        "iat": AT_NOW_SEC,
        "nbf": AT_NOW_SEC,
        "exp": AT_NOW_SEC + 300,
        "tenant_id": o.context.tenant_id,
        "event_id": o.event_id,
        "environment_id": o.context.environment_id,
        "task_id": o.task_id,
        "operation_id": o.operation_id,
        "admission_receipt_id": o.admission_receipt_id,
        "observed_at": sec,
        "reporter_role": "executor",
        "context": {
            "tenant_id": o.context.tenant_id,
            "environment_id": o.context.environment_id,
            "agent_id": o.context.agent_id,
            "purpose_id": o.context.purpose_id,
            "action_class": o.context.action_class,
            "resource_class": o.context.resource_class,
            "runtime_class": o.context.runtime_class,
        },
        "event_kind": str(o.event_kind),
        "result": str(o.result),
        "dimension": str(o.dimension),
        "severity": str(o.severity),
        "evidence_refs": list(o.evidence_refs),
        "attribution": {
            "native_task_ref": o.attribution.native_task_ref,
            "independence_group": o.attribution.independence_group,
            "causal_assessment": str(o.attribution.causal_assessment),
            "assessment_ref": o.attribution.assessment_ref,
        },
        "supersedes": list(o.supersedes),
        "details": o.details,
    }


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class Parts:
    """The pieces of a signed outcome that a test changes before they are put
    together: the header, the report, and a payload that replaces the report."""

    def __init__(self, hdr: dict[str, Any], rep: dict[str, Any]) -> None:
        self.hdr = hdr
        self.rep = rep
        self.payload: bytes | None = None

    def jws(self) -> str:
        payload = self.payload
        if payload is None:
            payload = json.dumps(self.rep).encode("utf-8")
        return (
            b64url(json.dumps(self.hdr).encode("utf-8"))
            + "."
            + b64url(payload)
            + "."
            + b64url(b"signature")
        )


def signed_fake(mod: Callable[[Parts], None] | None = None) -> FakeAdapter:
    """A fake that signs the observation it gets, after mod has changed the pieces."""
    from hop_top_pact.adapter import Signed

    def rec(o: Any) -> Any:
        p = Parts(
            {"alg": "ES256", "kid": "reporter-key-1", "typ": "pact-outcome+jwt"}, report_of(o)
        )
        if mod is not None:
            mod(p)
        return Signed(jws=p.jws())

    return FakeAdapter(record=rec)


def record_fake(rec: Any, err: BaseException | None) -> FakeAdapter:
    return FakeAdapter(record=result_of(rec, err))


class AdapterTestKit:
    """The adaptertest helpers, as attributes of one fixture value."""

    NOW_SEC = AT_NOW_SEC
    NOW = AT_NOW
    EPOCH = AT_EPOCH
    ACME = AT_ACME
    ACME_JS = AT_ACME_JS
    MINIMAL_CASE = MINIMAL_CASE
    REPO = REPO
    FakeAdapter = FakeAdapter
    Parts = Parts
    Wrapped = Wrapped
    wrap = staticmethod(wrap)
    result_of = staticmethod(result_of)
    zero_op = staticmethod(zero_op)
    factory_for = staticmethod(factory_for)
    case_failures = staticmethod(case_failures)
    complete = staticmethod(complete)
    run_fake = staticmethod(run_fake)
    want_clean = staticmethod(want_no_failures)
    want_fails = staticmethod(want_fails)
    run_rows = staticmethod(run_rows)
    tree_of = staticmethod(tree_of)
    good_principal = staticmethod(good_principal)
    good_op = staticmethod(good_op)
    good_binding = staticmethod(good_binding)
    good_claim = staticmethod(good_claim)
    auth_case = staticmethod(auth_case)
    auth_fake = staticmethod(auth_fake)
    bind_case = staticmethod(bind_case)
    bind_fake = staticmethod(bind_fake)
    map_case = staticmethod(map_case)
    map_fake = staticmethod(map_fake)
    claim_case = staticmethod(claim_case)
    claim_fake = staticmethod(claim_fake)
    check_case = staticmethod(check_case)
    check_fake = staticmethod(check_fake)
    authz_case = staticmethod(authz_case)
    authz_fake = staticmethod(authz_fake)
    record_case = staticmethod(record_case)
    report_of = staticmethod(report_of)
    b64url = staticmethod(b64url)
    signed_fake = staticmethod(signed_fake)
    record_fake = staticmethod(record_fake)

    def repo_fixtures(self) -> Path:
        """spec/v1.0/fixtures of the repository: a failure under PACT_REQUIRE_VECTORS=1
        when it is absent, a skip otherwise."""
        root = REPO / "spec" / "v1.0" / "fixtures"
        if not (root / "manifest.json").exists():
            if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
                pytest.fail(f"{root} absent under PACT_REQUIRE_VECTORS=1")
            pytest.skip("no spec/ tree (mirror checkout)")
        return root

    def common_cases(self) -> list[Any]:
        """The common cases of the repository's fixture tree."""
        from hop_top_pact.adapter.adaptertest import load_cases

        return load_cases(self.repo_fixtures(), "")


class FixtureTree:
    """An in-memory fixture tree, Go's fstest.MapFS: a Traversable over files given
    as {"adapters/_common/a.json": text}."""

    def __init__(self, files: dict[str, str], path: str = "") -> None:
        self._files = files
        self._path = path

    @property
    def name(self) -> str:
        return self._path.rsplit("/", 1)[-1]

    def joinpath(self, *descendants: str) -> FixtureTree:
        parts = [p for p in (self._path, *descendants) if p]
        return FixtureTree(self._files, "/".join(parts))

    def __truediv__(self, child: str) -> FixtureTree:
        return self.joinpath(child)

    def is_file(self) -> bool:
        return self._path in self._files

    def is_dir(self) -> bool:
        prefix = self._path + "/" if self._path else ""
        return not self.is_file() and any(f.startswith(prefix) for f in self._files)

    def iterdir(self) -> Iterator[FixtureTree]:
        prefix = self._path + "/" if self._path else ""
        names = {f[len(prefix) :].split("/", 1)[0] for f in self._files if f.startswith(prefix)}
        return iter([self.joinpath(n) for n in sorted(names)])

    def read_bytes(self) -> bytes:
        if not self.is_file():
            raise FileNotFoundError(self._path)
        return self._files[self._path].encode("utf-8")

    def read_text(self, encoding: str | None = None) -> str:
        return self.read_bytes().decode(encoding or "utf-8")

    def open(self, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("FixtureTree.open")


@pytest.fixture
def at() -> AdapterTestKit:
    return AdapterTestKit()


# The memory adapter helpers: the port of the helpers of
# go/adapters/memory/memory_unit_test.go, as the fixture ``mem``.

MEM_ENV = "https://gateway.example/environments/finance"


def _mem_state() -> Any:
    """A state with two identities, one mapping, one approved claim path and one
    installed check; reporting configured and execution visible."""
    from hop_top_pact.adapters import memory as m

    realm = m.Realm(tenant_id="acme", environment_id=MEM_ENV)
    return m.State(
        model=m.MODEL,
        gateway=m.Gateway(
            tenant_id="acme",
            environment_id=MEM_ENV,
            origin="https://gateway.example",
            header_allowlist=("x-request-kind",),
        ),
        mappings=(
            m.Mapping(
                version="map-1",
                routes=(
                    m.Route(
                        method="GET",
                        path="/invoices/{id}",
                        action="invoice.read",
                        resource="https://invoices.example/invoices/{id}",
                    ),
                ),
            ),
        ),
        identities=(
            m.Identity(
                ref="alice",
                id="https://idp.example/alice",
                realm=realm,
                workload="w-alice",
                secret="tok-alice-secret-1",  # noqa: S106
            ),
            m.Identity(
                ref="bob",
                id="https://idp.example/bob",
                realm=realm,
                workload="w-bob",
                secret="tok-bob-secret-2",  # noqa: S106
            ),
        ),
        approved_paths=("/roles",),
        claims=(
            m.ClaimRecord(
                realm=realm,
                principal="https://idp.example/alice",
                path="/roles",
                value=("approver",),
                source_id="directory",
            ),
        ),
        checks=(
            m.CheckRecord(
                id="approval-v1",
                result="PASS",
                reason_code="REQUIREMENT_SATISFIED",
                source_id="approvals",
            ),
        ),
        reporting=m.Reporting(
            issuer="https://gateway.example/reporters/finance",
            audience="https://reputation.example/",
            kid="k1",
        ),
        visibility="execution",
    )


class MemoryTestKit:
    """The memory adapter test helpers, as attributes of one fixture value."""

    T0_SEC = AT_NOW_SEC
    T0 = AT_NOW
    ENV = MEM_ENV
    EPOCH = AT_EPOCH

    @staticmethod
    def state() -> Any:
        return _mem_state()

    @staticmethod
    def new_adapter(*mutate: Callable[[Any], Any], shared: bool = False) -> tuple[Any, FakeClock]:
        """An adapter over the base state with each mutation applied in turn, and its
        clock, held at T0. Its workloads are dedicated unless shared is set."""
        from hop_top_pact.adapters import memory as m

        st = _mem_state()
        for f in mutate:
            st = f(st)
        clk = FakeClock(AT_NOW)
        opts = (m.with_shared_workloads(),) if shared else ()
        return m.new_adapter(st, clk, *opts), clk

    @staticmethod
    def at(d: int) -> int:
        """The Unix seconds d seconds after T0."""
        return AT_NOW_SEC + d

    @staticmethod
    def alice() -> Principal:
        return Principal(
            id="https://idp.example/alice",
            workload="w-alice",
            mechanism="bearer",
            realm=Realm(tenant_id="acme", environment_id=MEM_ENV),
        )

    @staticmethod
    def received(
        method: str,
        target: str,
        body: bytes = b"",
        headers: tuple[tuple[str, str], ...] = (),
    ) -> RawRequest:
        """The request a server takes off the wire for the request-target target,
        octet for octet. An origin-form target comes with the Host line of the
        configured origin, as an HTTP/1.1 request carries it (RFC 9112 3.2,
        request-binding.md RB-66)."""
        if target.startswith("/"):
            headers = (("Host", "gateway.example"), *headers)
        return RawRequest(method=method, raw_request_uri=target, headers=headers, body=body)

    @staticmethod
    def get(target: str, *headers: tuple[str, str]) -> RawRequest:
        return MemoryTestKit.received("GET", target, headers=headers)


@pytest.fixture
def mem() -> MemoryTestKit:
    return MemoryTestKit()


class EvalCaseKit:
    """The helpers of the conformance case-loader tests, as the fixture ``ec``.

    The port of go/runner/evalcase/helpers_test.go: copies of the committed
    fixture tree in scratch directories, and the edits the tests make to them.
    """

    REPO_FIXTURES = REPO / "spec" / "v1.0" / "fixtures"

    def __init__(self, mktemp: Callable[[], Path]) -> None:
        self._mktemp = mktemp

    def repo_fixtures(self) -> Path:
        """spec/v1.0/fixtures of the repository; absent in a mirror or mutation copy."""
        if not (self.REPO_FIXTURES / "manifest.json").exists():
            if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
                pytest.fail(f"{self.REPO_FIXTURES} absent under PACT_REQUIRE_VECTORS=1")
            pytest.skip("no spec/ tree (mirror checkout)")
        return self.REPO_FIXTURES

    @staticmethod
    def at(root: Path, rel: str) -> Path:
        """The slash-separated fixture path rel under root."""
        return root.joinpath(*rel.split("/"))

    @staticmethod
    def read_file(path: Path) -> bytes:
        return path.read_bytes()

    @staticmethod
    def write_file(path: Path, data: bytes | str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)

    @staticmethod
    def remove_file(path: Path) -> None:
        path.unlink()

    def copy_tree(self, *rels: str) -> Path:
        """Copy the regular files under the fixture paths rels (files or directories,
        slash-separated) into a fresh directory and return it."""
        src_root = self.repo_fixtures()
        root = self._mktemp()
        for rel in rels:
            src = self.at(src_root, rel)
            files = [src] if src.is_file() else sorted(p for p in src.rglob("*") if p.is_file())
            for p in files:
                self.write_file(root / p.relative_to(src_root), p.read_bytes())
        return root

    def case_tree(self, *ids: str) -> Path:
        """Copy the manifest, the test keys, and the case and expected directories of
        the manifest ids."""
        rels = ["manifest.json", "keys"]
        for id in ids:
            rels += [id, "expected/" + id]
        return self.copy_tree(*rels)

    def edit(self, root: Path, rel: str, old: str, repl: str) -> None:
        """Replace old by repl, once, in the file rel of the tree root."""
        p = self.at(root, rel)
        b = p.read_bytes()
        n = b.count(old.encode("utf-8"))
        assert n == 1, f"{rel} holds {old!r} {n} times, want once"
        self.write_file(p, b.replace(old.encode("utf-8"), repl.encode("utf-8"), 1))

    def edit_json(self, root: Path, rel: str, f: Callable[[dict[str, Any]], None]) -> None:
        """Rewrite the JSON file rel of the tree root through f, in RFC 8785 canonical
        form (the manifest, which is no signed artifact, compactly encoded)."""
        from hop_top_pact.core import jcs

        p = self.at(root, rel)
        v = json.loads(p.read_bytes())
        f(v)
        if rel == "manifest.json":
            b = json.dumps(v, sort_keys=True, separators=(",", ":")).encode("utf-8")
        else:
            b = jcs.canonicalize_value(v)
        self.write_file(p, b)

    def flip_signature(self, root: Path, rel: str) -> None:
        """Change one octet of the signature of the compact JWS file rel of the tree
        root, keeping it canonical base64url."""
        from hop_top_pact.core.jws import base64url

        p = self.at(root, rel)
        seg = p.read_text(encoding="ascii").split(".")
        sig = bytearray(base64url.decode(seg[2]))
        sig[10] ^= 0x01
        seg[2] = base64url.encode(bytes(sig))
        self.write_file(p, ".".join(seg))

    @staticmethod
    def want_err(err: BaseException | None, *parts: str) -> None:
        """err is an error whose text mentions every part."""
        assert err is not None, f"no error, want one mentioning {parts!r}"
        for s in parts:
            assert s in str(err), f"error {str(err)!r}, want one mentioning {s!r}"

    def fails(self, f: Callable[[], object], *parts: str) -> BaseException:
        """f raises a conformance CaseError whose text mentions every part."""
        from hop_top_pact.conformance import CaseError

        try:
            f()
        except CaseError as e:
            self.want_err(e, *parts)
            return e
        pytest.fail(f"no error, want one mentioning {parts!r}")


@pytest.fixture
def ec(tmp_path_factory: pytest.TempPathFactory) -> EvalCaseKit:
    return EvalCaseKit(lambda: tmp_path_factory.mktemp("evalcase"))
