"""The in-memory reference adapter. Mirrors hop.top/pact-go/adapters/memory.

The seven functions of draft 17.1 over native stores that live in process
memory and are built from a document, with no network and no files. It is
the baseline of the conformance suite in hop_top_pact.adapter.adaptertest: it
passes every common case, and it is written from the draft and the
invariants the draft cites, not from the cases.

Native state
------------

An adapter is built from a State, the neutral "common/1" model that the
common cases state their native state in: the gateway's trusted
configuration, the installed operation mappings, an identity store of bearer
tokens, an enrollment source, approved claim paths and their values,
installed checks with their verdicts, an authorization policy, and the signer
of outcome reports. parse_state reads it strictly from JSON and new_adapter
builds the adapter over it. The clock passed to new_adapter is the adapter's
only source of the current time.

What it does
------------

- authenticate_native: the bearer token of the Authorization header decides.
  Identity headers such as X-User are ignored, and a request that did not
  pass through the enforcement point, marked with arrive, is refused.
- resolve_agent_binding: looked up by realm, workload and agent ID together,
  so the agent ID selects among the records of the workload only. A binding
  that is revoked or compromised is returned as that status, with the agent,
  operator and holder key of the record and no error (identity mapping
  IM-11); an agent with no record on the workload in the realm has status
  UNKNOWN, whatever other agents share the workload, and enrolled_elsewhere
  says whether it has a record on another workload of the realm (draft
  17.1). By default a workload serves one agent, and a workload with more
  than one enrollment in force is a configuration error,
  UNSUPPORTED_REQUIREMENT with no binding, whichever agent the request names
  (identity mapping IM-19); with_shared_workloads builds the adapter of a
  profile whose workloads several agents may share.
- map_operation: the baseline HTTP mapping of draft 10.2, by core.binding. A
  request it refuses, such as one with a fragment, userinfo, a content
  encoding or an ambiguous encoding, raises InvalidMessage.
- read_native_claim: only approved paths, per realm and principal, with the
  times the source gives and never the time of the read. A fact of a
  resource is read only for a resource of the operation in the claim
  context, and a fact of a task only for the task of its intent.
- check_context: an exact match on the check id; anything else is UNKNOWN
  with UNSUPPORTED_REQUIREMENT. A record that names a principal or an agent
  applies only in a call from that principal and that agent's binding (draft
  17.1); an installed check that no record applies to, such as one called
  with no binding for an agent, is FAIL with APPROVAL_SCOPE_MISMATCH. A check
  with freshness limits evaluates the record it consults with
  adapter.freshness, with the baseline skew and a guard against re-stamping
  that starts with the sightings of the state: CLOCK_AHEAD, RESTAMPED and
  STALE_EVIDENCE are FAIL. A check pinned to a revision of its source fails
  with REQUIREMENTS_CHANGED when the source reports another.
- authorize_native: the policy decides for the original principal, a deny
  wins, and no rule is a deny. The decision carries the provenance of the
  rule that decided, and always names a policy source.
- record_outcome: signs outcome reports with ES256 under a P-256 key made for
  each adapter, declares no visibility for executions it does not observe,
  and removes credentials from free text and references.

A source that the state lists as unavailable is not read: a binding or a
claim from it raises DependencyUnavailable and a check of it is UNKNOWN with
DEPENDENCY_UNAVAILABLE. The adapter keeps no copy to fall back on. It has no
execution path, so it never runs the execution hook.

An error without a draft 13.4 code is a MemoryAdapterError, a PactError.
"""

from hop_top_pact.adapters.memory.factory import factory, factory_with, subject_of
from hop_top_pact.adapters.memory.freshness import (
    CODE_APPROVAL_SCOPE_MISMATCH,
    CODE_REQUIREMENTS_CHANGED,
)
from hop_top_pact.adapters.memory.identity import arrive, arrived
from hop_top_pact.adapters.memory.memory import (
    MemoryAdapter,
    Option,
    from_json,
    new_adapter,
    with_shared_workloads,
)
from hop_top_pact.adapters.memory.native import POLICY_SOURCE_ID
from hop_top_pact.adapters.memory.state import (
    MODEL,
    CheckFreshness,
    CheckRecord,
    ClaimRecord,
    Enrollment,
    Gateway,
    Identity,
    Mapping,
    MemoryAdapterError,
    Obligation,
    PolicyRule,
    Realm,
    Reporting,
    Route,
    Sighting,
    State,
    normalize_origin,
    parse_state,
)

__all__ = [
    "CODE_APPROVAL_SCOPE_MISMATCH",
    "CODE_REQUIREMENTS_CHANGED",
    "MODEL",
    "POLICY_SOURCE_ID",
    "CheckFreshness",
    "CheckRecord",
    "ClaimRecord",
    "Enrollment",
    "Gateway",
    "Identity",
    "Mapping",
    "MemoryAdapter",
    "MemoryAdapterError",
    "Obligation",
    "Option",
    "PolicyRule",
    "Realm",
    "Reporting",
    "Route",
    "Sighting",
    "State",
    "arrive",
    "arrived",
    "factory",
    "factory_with",
    "from_json",
    "new_adapter",
    "normalize_origin",
    "parse_state",
    "subject_of",
    "with_shared_workloads",
]
