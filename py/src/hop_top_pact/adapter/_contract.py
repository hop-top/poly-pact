"""The seven functions of draft 17.1 as Protocols, and the composite Adapter."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from hop_top_pact.adapter._types import (
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
from hop_top_pact.core.binding import RawRequest
from hop_top_pact.core.types import OperationContext


@runtime_checkable
class NativeAuthenticator(Protocol):
    """The draft 17.1 function authenticate_native."""

    def authenticate_native(self, req: RawRequest) -> Principal:
        """Authenticate the actual request with the environment's existing identity
        system and return the principal and workload context.

        Raises NativeDenial when authentication was evaluated and failed, and
        DependencyUnavailable when it could not be evaluated. It never returns
        an empty Principal.
        """
        ...


@runtime_checkable
class BindingResolver(Protocol):
    """The draft 17.1 function resolve_agent_binding."""

    def resolve_agent_binding(
        self, realm: Realm, workload: Workload, agent: AgentID
    ) -> AgentBinding:
        """Return the enrolled binding of agent to the authenticated workload in the
        realm, from the configured enrollment source. The realm and workload are
        those of the authenticated Principal; agent is the agent ID the request
        names.

        The agent ID only selects among the enrollments of the workload: it
        never selects an enrollment of another workload, and a workload alone
        never names an agent. The holder-key proof then binds the request to
        the selected enrollment (draft 6.2). When the profile in use does not
        support workloads shared by several agents, a workload with more than
        one enrollment in force is a configuration error: the function returns
        no binding and raises UnsupportedRequirement, whichever agent ID it is
        given. An enrollment is in force unless it is revoked; a compromised
        one is in force (spec/v1.0/profiles/identity-mapping.md, IM-18, IM-19).

        A binding the source holds as revoked or compromised is returned with
        status REVOKED or COMPROMISED and the agent_id, operator_id and
        holder_jkt of its record, so that a caller can state the reason
        (identity mapping IM-11); it is never reported as active. A source that
        cannot answer raises DependencyUnavailable. A source that answers that
        no such enrollment exists returns status UNKNOWN, not an error, with
        enrolled_elsewhere set when the agent ID is enrolled for another
        workload of the realm.
        """
        ...


@runtime_checkable
class OperationMapper(Protocol):
    """The draft 17.1 function map_operation."""

    def map_operation(
        self, req: RawRequest, p: Principal, mapping_version: str
    ) -> OperationContext:
        """Derive the authoritative OperationContext from the actual authenticated
        request and the installed mapping named by mapping_version (draft 10.2).
        Action, resources and principal come from the request and p, never from
        a client-supplied resource list, and every consequential part of the
        request (path, query, body, headers) is covered.

        Raises InvalidMessage when req violates a rule of the baseline HTTP
        mapping (draft 10.2, 13.4), such as a fragment or userinfo in the
        target, an ambiguous encoding as draft 10.2 defines and lists them, or
        an HTTP content encoding; UnsupportedRequirement when mapping_version is
        not installed; ContextMismatch when the request and p disagree; and
        DependencyUnavailable when a lookup the mapping needs cannot be
        completed.
        """
        ...


@runtime_checkable
class ClaimReader(Protocol):
    """The draft 17.1 function read_native_claim."""

    def read_native_claim(self, native_path: str, c: ClaimContext) -> NativeClaim:
        """Read the value at native_path in the context c from the configured
        authoritative source. native_path is a path an administrator approved in
        the versioned mapping (draft 17.2); any other path raises
        UnsupportedRequirement. A fact of a resource is read only for a resource
        that c.operation lists, and a fact of a task only for the task of
        c.intent.

        The adapter reports the timestamps the source gives and no others: it
        does not claim a freshness it cannot establish, and it does not restamp
        a cached snapshot with the time of the read (draft 8.3, 17.2). A source
        that cannot be reached raises DependencyUnavailable, which the validator
        maps to DEFERRED.
        """
        ...


@runtime_checkable
class ContextChecker(Protocol):
    """The draft 17.1 function check_context."""

    def check_context(self, check_id: str, input: CheckInput) -> CheckOutcome:
        """Run the installed, versioned check named by check_id on input: the
        authenticated principal, the agent binding, the declared intent, the
        actual operation and the evidence references, the inputs draft 17.1
        lists. A check compares an agent or a principal against input.binding
        and input.principal, never against a value the presentation, the
        profile or an evidence artifact carries; a check that needs neither
        ignores them.

        It raises nothing. A check it did not perform returns UNKNOWN, never
        PASS (draft 17.2): an unknown check_id with reason_code
        UNSUPPORTED_REQUIREMENT, a source that cannot answer with reason_code
        DEPENDENCY_UNAVAILABLE. The validator records UNKNOWN as DEFERRED.
        """
        ...


@runtime_checkable
class NativeAuthorizer(Protocol):
    """The draft 17.1 function authorize_native."""

    def authorize_native(self, p: Principal, op: OperationContext) -> Decision:
        """Return the environment's existing policy decision for the original
        authenticated principal p and the actual operation. It never substitutes
        a connector or service identity for p (draft 4.3). A native exception
        changes only this result (draft 17.3); PACT evidence of an exception
        neither grants nor implies one.

        Native authorization never sees the PACT contract: draft 17.1 gives it
        the original principal and the actual operation only. A caller whose
        contract pins a policy version compares Decision.policy_revision with
        the installed check version the contract names; on a mismatch it does
        not use the decision and answers REQUIREMENTS_CHANGED (draft 13.4), so
        that a new contract is obtained.

        A policy that cannot decide raises DependencyUnavailable, or returns a
        Decision with effect UNKNOWN.
        """
        ...


@runtime_checkable
class OutcomeRecorder(Protocol):
    """The draft 17.1 function record_outcome."""

    def record_outcome(self, o: Observation) -> Recorded:
        """Record the observation as a signed OutcomeReport and return Signed, or
        return NoVisibility when the adapter has no visibility of the event.
        Missing visibility is declared, never assumed to be success (draft
        14.1). A recorder that cannot reach its signer or store raises
        DependencyUnavailable.
        """
        ...


@runtime_checkable
class Adapter(
    NativeAuthenticator,
    BindingResolver,
    OperationMapper,
    ClaimReader,
    ContextChecker,
    NativeAuthorizer,
    OutcomeRecorder,
    Protocol,
):
    """The composite an enforced adapter implements: the seven draft 17.1
    functions and its descriptor."""

    def describe(self) -> Descriptor:
        """The adapter's descriptor; for a MultiDescriber, the primary form."""
        ...


@runtime_checkable
class MultiDescriber(Protocol):
    """Implemented by an adapter that serves more than one native protocol form and
    publishes one GatewayMetadata.adapters entry per form (draft 13.3); describe
    then returns the primary form."""

    def descriptors(self) -> list[Descriptor]:
        """One descriptor per form, the primary form first."""
        ...


def descriptors_of(a: Adapter) -> list[Descriptor]:
    """Every descriptor an adapter publishes: descriptors() of a MultiDescriber,
    otherwise the one describe() returns. The result is the caller's to change."""
    if isinstance(a, MultiDescriber):
        return list(a.descriptors())
    return [a.describe()]
