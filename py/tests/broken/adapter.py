"""The broken adapter itself (Go adapters/internal/broken, broken.go): the memory
adapter it wraps, the defects that are on, and its factories."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import datetime

from broken import identity, native, operation, record
from broken.catalogue import CATALOGUE
from broken.defects import Defect
from broken.freshness import freshness_state
from hop_top_pact.adapter import (
    AgentBinding,
    AgentID,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Decision,
    Descriptor,
    NativeClaim,
    Observation,
    Principal,
    Realm,
    Recorded,
    Workload,
)
from hop_top_pact.adapter.adaptertest import Env, Factory, Hooks, Subject
from hop_top_pact.adapters import memory
from hop_top_pact.adapters.memory.memory import state_bytes
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.clock import Clock
from hop_top_pact.core.types import OperationContext
from hop_top_pact.errors import PactError

__all__ = ["BrokenAdapter", "defects", "factory", "new_adapter", "shared_factory"]


class BrokenAdapter:
    """The memory adapter with the defects that are switched on.

    base is the memory adapter the defects wrap, over the state as the freshness
    defects make it look. shared says that the adapter's workloads may be shared by
    several agents, as for memory.with_shared_workloads. executing is a memory
    adapter with execution visibility, whose reports stand in for the success that
    ASSUME_EXECUTION_SUCCESS invents, and leaky signs reports with the unredacted
    text of the observation; both are None without reporting.
    """

    def __init__(
        self, st: memory.State, clock: Clock, hooks: Hooks, shared: bool, *on: Defect
    ) -> None:
        opts = (
            [memory.with_shared_workloads()]
            if shared or Defect.SELECT_DESPITE_DEDICATED in on
            else []
        )
        self.on = frozenset(on)
        self.base = memory.new_adapter(freshness_state(st, self.on), clock, *opts)
        self.shared = shared
        self.clock = clock
        self.hooks = hooks
        self.executing: memory.MemoryAdapter | None = None
        self.leaky: record.LeakySigner | None = None
        if st.reporting is not None:
            self.executing = memory.new_adapter(replace(st, visibility="execution"), clock, *opts)
            self.leaky = record.LeakySigner(st.reporting.kid)

    def has(self, d: Defect) -> bool:
        """Whether the defect d is on."""
        return d in self.on

    def state(self) -> memory.State:
        """The state of the memory adapter."""
        return self.base.state()

    def now(self) -> datetime:
        """The current time."""
        return self.clock.now()

    def fire(self, name: str) -> None:
        """Record that the native hook name ran."""
        self.hooks.fire(name)

    def describe(self) -> Descriptor:
        """A descriptor that says what this is."""
        return Descriptor(protocol="broken", version="0", mapping_revision="broken-map-0")

    def credential(self, r: RawRequest, ref: str) -> RawRequest:
        """The credential hook of the memory adapter."""
        return self.base.credential(r, ref)

    def verify_outcome(self, jws: str) -> None:
        """Verify a report signed by the adapter, by the adapter that stands in for a
        visible execution, or by the leaky signer; raise the error of the adapter's
        own verification when none verifies it."""
        try:
            self.base.verify_outcome(jws)
        except PactError:
            if self.executing is not None and _verifies(self.executing.verify_outcome, jws):
                return
            if self.leaky is not None and _verifies(self.leaky.verify, jws):
                return
            raise

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
        return record.record_outcome(self, o)


def _verifies(verify: Callable[[str], None], jws: str) -> bool:
    try:
        verify(jws)
    except PactError:
        return False
    return True


def new_adapter(
    st: memory.State, clock: Clock, hooks: Hooks, shared: bool, *on: Defect
) -> BrokenAdapter:
    """The memory adapter over st with the defects on switched on, with workloads
    that several agents may share when shared is true and dedicated ones
    otherwise. hooks receives the execution hook calls of the defects that make
    them. Raises MemoryAdapterError for a state the memory adapter cannot use."""
    return BrokenAdapter(st, clock, hooks, shared, *on)


def factory(*on: Defect) -> Factory:
    """The adaptertest Factory of the adapter with the defects on and dedicated
    workloads, the default."""
    return _factory(False, on)


def shared_factory(*on: Defect) -> Factory:
    """factory for the adapter whose workloads several agents may share. The suite
    runs it with Options.shared_workloads set."""
    return _factory(True, on)


def _factory(shared: bool, on: tuple[Defect, ...]) -> Factory:
    def build(env: Env) -> Subject:
        st = memory.parse_state(state_bytes(env.state))
        b = new_adapter(st, env.clock, env.hooks, shared, *on)
        return Subject(
            adapter=b,
            arrive=memory.arrive,
            credential=b.credential,
            verify_outcome=b.verify_outcome,
        )

    return build


def defects() -> list[Defect]:
    """Every defect of the catalogue, in catalogue order."""
    return [s.defect for s in CATALOGUE]
