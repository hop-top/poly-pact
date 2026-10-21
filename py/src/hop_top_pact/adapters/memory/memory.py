"""The memory adapter itself (Go adapters/memory, memory.go): construction, the
arrival mark, the credential hook, and the helpers the seven functions share.
The functions live in identity, operation, native and outcome."""

from __future__ import annotations

import hmac
import json
from collections.abc import Callable
from dataclasses import fields
from datetime import datetime
from typing import Final, TypeAlias

from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Decision,
    DependencyUnavailable,
    Descriptor,
    NativeClaim,
    Observation,
    Principal,
    Realm,
    Recorded,
    Workload,
)
from hop_top_pact.adapter import freshness as fr
from hop_top_pact.adapters.memory import identity, native, operation, outcome
from hop_top_pact.adapters.memory.freshness import new_guard
from hop_top_pact.adapters.memory.identity import arrive, arrived, header
from hop_top_pact.adapters.memory.state import (
    Identity,
    Mapping,
    MemoryAdapterError,
    State,
    parse_state,
)
from hop_top_pact.core.binding import Config, RawRequest, RequestError
from hop_top_pact.core.clock import BASELINE_SKEW, Clock
from hop_top_pact.core.types import JSONValue, OperationContext

__all__ = [
    "MemoryAdapter",
    "Option",
    "arrive",
    "arrived",
    "from_json",
    "new_adapter",
    "with_shared_workloads",
]

MAX_BODY: Final = 8 << 20
"""The largest request body the adapter reads to digest it."""

HEADER_NORMALIZATION_ID: Final = "memory-header-normalization-1"
"""The header normalization of the baseline HTTP mapping, which core.binding
applies."""

Option: TypeAlias = Callable[["MemoryAdapter"], None]
"""Configures a MemoryAdapter as new_adapter builds it."""


def with_shared_workloads() -> Option:
    """Make the adapter that of a profile that supports workloads shared by several
    agents (spec/v1.0/profiles/identity-mapping.md, IM-19): resolve_agent_binding
    selects among the records of a workload by the agent ID alone, however many
    of them are in force. Without it, the default of every profile, a workload
    serves one agent, and a workload with more than one enrollment in force is a
    configuration error."""

    def opt(a: MemoryAdapter) -> None:
        a.shared = True

    return opt


class MemoryAdapter:
    """The in-memory reference adapter: the seven functions of draft 17.1 over a
    State, keeping nothing outside memory.

    It never reads the wall clock; the clock passed to new_adapter is its only
    source of the current time. It is safe for concurrent use: after
    construction it only reads its state, and the guard against re-stamping
    locks itself.
    """

    def __init__(self, st: State, clock: Clock | None, *opts: Option) -> None:
        if clock is None:
            raise MemoryAdapterError("memory: no clock")
        try:
            st.validate()
        except MemoryAdapterError as e:
            raise MemoryAdapterError(f"memory: state: {e}") from e
        self.st = st
        self.clock: Clock = clock
        self.shared = False
        for o in opts:
            o(self)
        self.mappings: dict[str, Mapping] = {}
        for m in st.mappings:
            # map_operation applies the baseline HTTP mapping under each
            # installed version; its configuration must be usable before any
            # request.
            try:
                self.binding_config(m.version).validate()
            except RequestError as e:
                raise MemoryAdapterError(f"memory: mapping {m.version!r}: {e}") from e
            self.mappings[m.version] = m
        self.guard: fr.Monotonic = new_guard(st.sightings)
        self.key: ec.EllipticCurvePrivateKey | None = (
            ec.generate_private_key(ec.SECP256R1()) if st.reporting is not None else None
        )

    def state(self) -> State:
        """The adapter's state."""
        return self.st

    def describe(self) -> Descriptor:
        """The descriptor of the memory mechanism."""
        return Descriptor(protocol="memory", version="1", mapping_revision="memory-map-1")

    def realm(self) -> Realm:
        """The realm of the gateway the adapter serves."""
        g = self.st.gateway
        return Realm(tenant_id=g.tenant_id, environment_id=g.environment_id)

    def binding_config(self, mapping_version: str) -> Config:
        """The baseline HTTP mapping of the gateway under one installed version."""
        g = self.st.gateway
        return Config(
            origin=g.origin,
            header_allowlist=g.header_allowlist,
            header_normalization_id=HEADER_NORMALIZATION_ID,
            mapping_version=mapping_version,
            max_body=MAX_BODY,
        )

    def credential(self, r: RawRequest, ref: str) -> RawRequest:
        """r with the bearer token of the identity named ref, unless r already carries
        an Authorization header. Raises MemoryAdapterError for an unknown ref."""
        for i in self.st.identities:
            if i.ref != ref:
                continue
            if header(r, "Authorization"):
                return r
            return type(r)(
                **{
                    **{f.name: getattr(r, f.name) for f in fields(RawRequest)},
                    "headers": (*r.headers, ("Authorization", "Bearer " + i.secret)),
                }
            )
        raise MemoryAdapterError(f"memory: no identity {ref!r}")

    def identity_by_secret(self, token: str) -> Identity | None:
        """The identity that token authenticates. It compares against every identity,
        so that the time taken does not depend on which one matches."""
        found: Identity | None = None
        for i in self.st.identities:
            if hmac.compare_digest(i.secret.encode(), token.encode()) and token:
                found = i
        return found

    def unavailable(self, source_id: str) -> bool:
        """Whether the source named source_id cannot currently answer."""
        return source_id in self.st.unavailable_sources

    def check_source_times(self, observed: datetime | None, checked: datetime | None) -> None:
        """Refuse times the adapter cannot pass on. No source observation or
        status-check time may be later than now plus the skew (draft A.2): such a
        time did not happen yet and the source is not trustworthy at this moment,
        so the dependency cannot be relied on, which defers the decision
        (freshness profile, section 3.2). Raises DependencyUnavailable."""
        limit = self.clock.now() + BASELINE_SKEW
        if observed is not None and observed > limit:
            raise DependencyUnavailable(
                "memory: the source reports an observation later than now plus the skew"
            )
        if checked is not None and checked > limit:
            raise DependencyUnavailable(
                "memory: the source reports a status check later than now plus the skew"
            )

    # The seven functions of draft 17.1.

    def authenticate_native(self, req: RawRequest) -> Principal:
        return identity.authenticate_native(self, req)

    def resolve_agent_binding(
        self, realm: Realm, workload: Workload, agent: AgentID
    ) -> AgentBinding:
        return identity.resolve_agent_binding(self, realm, workload, agent)

    def map_operation(
        self, req: RawRequest, p: Principal, mapping_version: str
    ) -> OperationContext:
        return operation.map_operation(self, req, p, mapping_version)

    def read_native_claim(self, native_path: str, c: ClaimContext) -> NativeClaim:
        return native.read_native_claim(self, native_path, c)

    def check_context(self, check_id: str, input: CheckInput) -> CheckOutcome:
        return native.check_context(self, check_id, input)

    def authorize_native(self, p: Principal, op: OperationContext) -> Decision:
        return native.authorize_native(self, p, op)

    def record_outcome(self, o: Observation) -> Recorded:
        return outcome.record_outcome(self, o)

    def verify_outcome(self, jws: str) -> None:
        """Verify the ES256 signature of a compact JWS this adapter signed; raise
        MemoryAdapterError when it does not verify."""
        outcome.verify_outcome(self, jws)


def new_adapter(st: State, clock: Clock | None, *opts: Option) -> MemoryAdapter:
    """An adapter over st, reading the current time from clock. It validates st and
    raises MemoryAdapterError for a state it cannot use."""
    return MemoryAdapter(st, clock, *opts)


def from_json(raw: bytes, clock: Clock | None, *opts: Option) -> MemoryAdapter:
    """Parse a state document with parse_state and call new_adapter."""
    return new_adapter(parse_state(raw), clock, *opts)


def state_bytes(state: JSONValue) -> bytes:
    """A parsed state document as JSON text again, for from_json."""
    return json.dumps(state, ensure_ascii=False).encode("utf-8")
