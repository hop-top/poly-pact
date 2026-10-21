"""Native adapter contract (draft section 17.1). Mirrors hop.top/pact-go/adapter.

The seven logical functions an enforced gateway adapter exposes, the value
types they exchange, and the errors they report. The package holds
Protocols, types and errors only; an implementation lives in its own
package, and the validator and the conformance suite are written against the
Protocols here. The contracts are behavioral, not new REST APIs (draft
17.1): an existing gateway plugin, policy hook, middleware, directory lookup
or native claim can satisfy them. The calls are synchronous and take no
context argument; the request is a core.binding.RawRequest.

The seven functions
-------------------

One Protocol per row of the draft 17.1 table, and the composite Adapter that
inherits all seven. Each row below gives the draft function name, the Python
Protocol and method, and the draft's own Input and Output / requirement
cells.

authenticate_native    NativeAuthenticator.authenticate_native
    Input:  Actual request
    Output: Authenticated principal and workload context, or native denial.

resolve_agent_binding  BindingResolver.resolve_agent_binding
    Input:  Realm, authenticated workload, and the agent ID the request names
    Output: The enrolled binding of that agent ID to that workload in that
            realm: operator binding, holder key, and current binding status;
            `UNKNOWN` when no such enrollment exists, together with whether
            that agent ID is enrolled for another workload of the realm.

map_operation          OperationMapper.map_operation
    Input:  Actual request and mapping version
    Output: Authoritative `OperationContext`; all consequential request data
            is covered.

read_native_claim      ClaimReader.read_native_claim
    Input:  Approved native path and context
    Output: Authoritative value, original observation time, status time, and
            source ID.

check_context          ContextChecker.check_context
    Input:  Installed check ID; the authenticated principal and workload
            context that `authenticate_native` returned, with its
            authenticated attributes; the agent binding that
            `resolve_agent_binding` returned; intent; operation; evidence
            references
    Output: `PASS`, `FAIL`, or `UNKNOWN`, with a reason.

authorize_native       NativeAuthorizer.authorize_native
    Input:  Original principal and actual operation
    Output: Existing policy decision; PACT cannot rewrite a denial.

record_outcome         OutcomeRecorder.record_outcome
    Input:  Attributable decision/execution observation
    Output: Signed outcome or declared absence of execution visibility.

Invariants
----------

Every implementation holds two invariants, whatever the native system:

1. Values come only from authenticated context or configured authoritative
   lookups. A client-supplied header, profile text, URL parameter or model
   output is never native context, and identities keep their issuer and
   tenant namespace so that similarly named users or roles are not conflated
   (draft 8.5, 17.2).
2. observed_at is the original source observation. An adapter never
   refreshes a stale upstream fact by stamping it with the time of the read,
   and it never reports a check or a freshness it did not perform (draft 8.3,
   17.2). None means the source gives no such time; the validator cannot
   establish freshness from it.

Errors
------

Every error is an AdapterError, a PactError, whose code is one of the draft
13.4 table; code_of recovers the code from an exception chain:

    InvalidMessage          INVALID_MESSAGE
    InvalidProof            INVALID_PROOF
    ContextMismatch         CONTEXT_MISMATCH
    DependencyUnavailable   DEPENDENCY_UNAVAILABLE
    UnsupportedRequirement  UNSUPPORTED_REQUIREMENT
    UnsupportedPurpose      UNSUPPORTED_PURPOSE
    MissingField            MISSING_FIELD

NativeDenial is an InvalidProof. A function that cannot reach its source
raises DependencyUnavailable; the validator records the affected check as
UNKNOWN and the admission decision as DEFERRED (draft 11.4, 17.3.1).
check_context raises nothing: it reports the same conditions as a
CheckOutcome with the verdict UNKNOWN and the code as reason_code.

Times
-----

Instants are aware datetimes with microsecond precision. On the wire they are
integer Unix seconds; a conversion truncates to the second and maps None to
an absent (null) member.

The Protocols are the contract that implementations and the conformance
suite share, frozen with the Go package (tools/parity/README.md
in the source repository, Adapter contract): a change to a signature or to a type's fields
breaks every implementation.
"""

from hop_top_pact.adapter._contract import (
    Adapter,
    BindingResolver,
    ClaimReader,
    ContextChecker,
    MultiDescriber,
    NativeAuthenticator,
    NativeAuthorizer,
    OperationMapper,
    OutcomeRecorder,
    descriptors_of,
)
from hop_top_pact.adapter._errors import (
    AdapterError,
    Code,
    ContextMismatch,
    DenialReason,
    DependencyUnavailable,
    InvalidMessage,
    InvalidProof,
    MissingField,
    NativeDenial,
    UnsupportedPurpose,
    UnsupportedRequirement,
    code_of,
)
from hop_top_pact.adapter._types import (
    AgentBinding,
    AgentID,
    BindingStatus,
    CheckInput,
    CheckOutcome,
    ClaimContext,
    Decision,
    Descriptor,
    Effect,
    Mechanism,
    NativeClaim,
    NoVisibility,
    Obligation,
    Observation,
    Principal,
    Realm,
    Recorded,
    Signed,
    Verdict,
    Workload,
)

__all__ = [
    "Adapter",
    "AdapterError",
    "AgentBinding",
    "AgentID",
    "BindingResolver",
    "BindingStatus",
    "CheckInput",
    "CheckOutcome",
    "ClaimContext",
    "ClaimReader",
    "Code",
    "ContextChecker",
    "ContextMismatch",
    "Decision",
    "DenialReason",
    "DependencyUnavailable",
    "Descriptor",
    "Effect",
    "InvalidMessage",
    "InvalidProof",
    "Mechanism",
    "MissingField",
    "MultiDescriber",
    "NativeAuthenticator",
    "NativeAuthorizer",
    "NativeClaim",
    "NativeDenial",
    "NoVisibility",
    "Obligation",
    "Observation",
    "OperationMapper",
    "OutcomeRecorder",
    "Principal",
    "Realm",
    "Recorded",
    "Signed",
    "UnsupportedPurpose",
    "UnsupportedRequirement",
    "Verdict",
    "Workload",
    "code_of",
    "descriptors_of",
]
