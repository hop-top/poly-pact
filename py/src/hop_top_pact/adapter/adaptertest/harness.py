"""What the conformance suite and an adapter under test exchange (Go adaptertest,
harness.go and the options of suite.go)."""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from importlib.resources.abc import Traversable
from types import MappingProxyType
from typing import TypeAlias

from hop_top_pact.adapter._contract import Adapter
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.clock import Clock
from hop_top_pact.core.types import JSONValue

__all__ = ["Env", "Factory", "Hooks", "Options", "Replacement", "Subject"]


class Hooks:
    """Records the native hooks an adapter fired during a case. It is safe for
    concurrent use."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fired: list[str] = []

    def fire(self, name: str) -> None:
        """Record that the hook named name ran."""
        with self._lock:
            self._fired.append(name)

    def fired(self) -> list[str]:
        """The names of the hooks that ran, in order: a new list."""
        with self._lock:
            return list(self._fired)


@dataclass(frozen=True, slots=True, kw_only=True)
class Env:
    """What the suite hands a Factory.

    state is the native_state member of the case file, as parsed JSON. clock is
    the adapter's only source of the current time: the suite holds it at the
    case's now, so an adapter that reads the wall clock instead is caught by
    every time assertion. hooks records the calls the adapter makes into native
    execution hooks: an adapter wired to a downstream executor calls
    hooks.fire("execute") where it would run the protected operation, and cases
    then assert, with expect.must_not_call, that a denial ran nothing.
    """

    state: JSONValue
    clock: Clock
    hooks: Hooks


@dataclass(frozen=True, slots=True, kw_only=True)
class Subject:
    """The adapter under test with the few hooks that depend on the native mechanism
    and that the suite cannot supply itself.

    arrive marks a request as having reached the adapter through the enforcement
    point, in the way the adapter's mechanism recognizes, and returns the request
    to use from then on. A request the suite does not pass through it is a
    direct request that bypassed the enforcement point; the adapter must not
    authenticate it. Required.

    credential returns the request with the credential of the native identity
    that ref names in the case's native state, in the form the adapter's
    mechanism reads: a header, a cookie, a peer certificate. It raises when ref
    is unknown. Required by cases that set request.native_state_ref.

    verify_outcome, when set, verifies the signature of a compact JWS that
    record_outcome returned, and raises when it does not verify.
    """

    adapter: Adapter
    arrive: Callable[[RawRequest], RawRequest]
    credential: Callable[[RawRequest, str], RawRequest] | None = None
    verify_outcome: Callable[[str], None] | None = None


Factory: TypeAlias = Callable[[Env], Subject]
"""Builds the adapter under test for one case. The suite calls it once per case,
so every case starts from the native state it declares and from nothing else.

A Factory reads env.state, the case's native_state member, and builds the
adapter's native systems from it: the identity store, the enrollment source,
the claim sources, the policy and the installed checks. The common cases in
spec/v1.0/fixtures/adapters/_common state it in the neutral "common/1" model that
the fixture README defines, and an adapter's own cases state it in whatever
shape its Factory reads. The suite never looks inside. A Factory that cannot
build the adapter raises; the case fails with that exception. Go's testing.TB
argument, for cleanup only, has no counterpart: the suite imports no test
framework."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Replacement:
    """The adapter's own case that stands in for a common case the adapter's
    mechanism cannot realize. Draft 22.2 lets a conformance claim replace a
    required test by one that is no weaker than the original intent. by is the
    id of the adapter's own case; reason says why the mechanism cannot realize
    the common case."""

    by: str
    reason: str


def _no_replacements() -> Mapping[str, Replacement]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True, kw_only=True)
class Options:
    """How the suite runs.

    fixtures is the fixture tree, rooted at spec/v1.0/fixtures, such as a
    pathlib.Path; None uses the spec/v1.0/fixtures directory of the source
    repository. adapter names the adapter's own cases, the case files directly
    in adapters/<adapter>, run after the common cases; "" runs the common cases
    only. shared_workloads says that the adapter's profile supports workloads
    shared by several agents (spec/v1.0/profiles/identity-mapping.md, IM-19): the
    suite then runs the cases whose workloads member is "shared" instead of
    those whose member is "dedicated"; cases without the member run either way.
    replaced maps the id of a common authenticate_native or authorize_native
    case to the adapter's own case for the same function with the same outcome
    class that replaces it; a replaced case is still run and must fail.
    """

    fixtures: Traversable | None = None
    adapter: str = ""
    shared_workloads: bool = False
    replaced: Mapping[str, Replacement] = field(default_factory=_no_replacements)
