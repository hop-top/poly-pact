"""The adaptertest Factory of the memory adapter (Go adapters/memory, factory.go)."""

from __future__ import annotations

from hop_top_pact.adapter.adaptertest import Env, Factory, Subject
from hop_top_pact.adapters.memory.identity import arrive
from hop_top_pact.adapters.memory.memory import MemoryAdapter, Option, from_json, state_bytes

__all__ = ["factory", "factory_with", "subject_of"]


def factory(env: Env) -> Subject:
    """The adaptertest Factory of the memory adapter: it builds the adapter from the
    common/1 native state of a case, with the clock of the suite. Its workloads
    are dedicated, the default."""
    return factory_with()(env)


def factory_with(*opts: Option) -> Factory:
    """The adaptertest Factory of the memory adapter built with opts. The suite runs
    the adapter built with with_shared_workloads with Options.shared_workloads
    set."""

    def build(env: Env) -> Subject:
        return subject_of(from_json(state_bytes(env.state), env.clock, *opts))

    return build


def subject_of(a: MemoryAdapter) -> Subject:
    """The adapter with the hooks the suite needs."""
    return Subject(
        adapter=a, arrive=arrive, credential=a.credential, verify_outcome=a.verify_outcome
    )
