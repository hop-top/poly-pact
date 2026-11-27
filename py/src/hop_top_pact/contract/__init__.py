"""Requirement contract issuance and verification (draft sections 9.1 to 9.4, typ
pact-requirements+jwt). Mirrors hop.top/pact-go/contract.

A requirement contract is the signed answer to "for this agent and this
operation, which fields must be defined, what must their values satisfy, and who
must establish their truth".

Issuing
-------

A Publisher turns a core.types.ContractRequest into a signed contract
(Publisher.issue). It requires the native context that step 1 of draft 11.1
established (Authenticated: the principal authenticate_native returned and the
binding resolve_agent_binding returned), because a gateway MUST obtain native
authentication and a trustworthy agent/key binding before it issues a
personalized contract (draft 9.1). The contract binds:

- sub, the agent; aud, the gateway; iss, the publisher; tenant_id and
  environment_id, the realm;
- holder_jkt, the enrolled key, and the object_digest of the request's operation
  and intent (draft 7.4, Appendix A.2);
- the effective Requirements: base_revision, selected_set, the complete
  field_rules and context_checks (draft 9.4), the learning_policy_digest and
  learning_artifact_digest, and mode;
- a fresh jti and a one-use nonce of 128 random bits (Appendix A.2), and an expiry
  at most 60 seconds after iat (draft 9.1, 20.1).

The payload is signed through a Signer (ES256Signer for an in-process key) and the
nonce is registered in a ReplayStore before the contract is returned. A store
that is full or unavailable fails the issuance with DEPENDENCY_UNAVAILABLE: no
contract leaves without its nonce record (draft 7.5). The payload is the RFC 8785
canonical form of the claims.

Verifying
---------

Step 3 of the validator algorithm (draft 11.3) is three calls, so that a validator
can record each check on its own:

- Verifier.verify: the publisher's signature over the received signing input, under
  the keys of the trust record that iss names; the typ; the strict decoding; the
  RequirementContract schema and the rules of Appendix A.2; and the time rules of
  draft 7.5 with the 60-second contract lifetime. A failure here is a transport
  error: INVALID_PROOF, INVALID_MESSAGE or EXPIRED (draft 12.2, 13.4). Rules edited
  after signing fail the signature.
- Contract.check: subject, audience and realm, and the contract's extensions (the
  contract-validity check): CONTEXT_MISMATCH or UNSUPPORTED_REQUIREMENT.
- Contract.check_active: the base revision and learning versions the contract pins
  against the active Policy (the active-policy check): REQUIREMENTS_CHANGED.

holder_jkt, operation_digest and intent_digest are compared by the checks of steps
2 and 5, which have the presentation and the actual operation.

Nonces
------

Contract.nonce_record is the binding of the nonce to the agent, holder key, realm,
operation digest and requirements digest (draft 7.5). ReplayStore.consume consumes
it atomically: a second consumption, or a nonce that was never registered, is
REPLAY. MemoryReplay is a replay store for one process; replicas share one store.

Errors
------

Every error is a ContractError whose code is the draft 13.4 code. The calls are
synchronous and take no context argument; instants are aware datetimes and the
publisher's lifetime and the verifier's skew are timedeltas, with microsecond
precision where Go has nanoseconds. A misconfigured Publisher or Verifier raises
ValueError, not a ContractError.
"""

from __future__ import annotations

from hop_top_pact.contract._errors import (
    CODE_EXPIRED,
    CODE_REPLAY,
    CODE_REQUIREMENTS_CHANGED,
    CODE_SECURITY_HOLD,
    ContractError,
)
from hop_top_pact.contract._publish import ES256Signer, Publisher, Signer
from hop_top_pact.contract._replay import MemoryReplay, ReplayStore
from hop_top_pact.contract._transport import (
    EXTENSION_TRANSPORT_PROFILE,
    TRANSPORT_HTTPS,
    TRANSPORT_STDIO_IPC,
)
from hop_top_pact.contract._types import (
    SELECTION_CONSISTENCY_CHECK,
    Authenticated,
    Contract,
    Expect,
    NonceRecord,
    Policy,
    Requirements,
    ThresholdRule,
)
from hop_top_pact.contract._verify import Verifier

__all__ = [
    "CODE_EXPIRED",
    "CODE_REPLAY",
    "CODE_REQUIREMENTS_CHANGED",
    "CODE_SECURITY_HOLD",
    "EXTENSION_TRANSPORT_PROFILE",
    "SELECTION_CONSISTENCY_CHECK",
    "TRANSPORT_HTTPS",
    "TRANSPORT_STDIO_IPC",
    "Authenticated",
    "Contract",
    "ContractError",
    "ES256Signer",
    "Expect",
    "MemoryReplay",
    "NonceRecord",
    "Policy",
    "Publisher",
    "ReplayStore",
    "Requirements",
    "Signer",
    "ThresholdRule",
    "Verifier",
]
