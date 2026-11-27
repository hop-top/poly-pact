"""The PACT admission validator: the algorithm of draft Section 11.3, the decisions of
Section 11.4 and the receipts and state machine of Section 12, for a gateway that
evaluates in its own request path or as a trusted sidecar (draft 4.4). Mirrors
hop.top/pact-go/validator.

Validator.evaluate takes the signed presentation, the actual operation the gateway mapped
from the request and the principal native authentication established (draft 13.2, 17.1).
Before an authenticated evaluation it applies, as transport checks that give no receipt
(draft 12.2): native authentication; the presentation's size, strict parsing, typ and
signature; the enrolled agent/key binding; the publisher's signature and validity window of
the embedded contract; the transport the contract names; the presentation's time bounds; and
the atomic consumption of the contract's nonce. The error is then a Rejection carrying the
draft 13.4 code, which problem_of turns into the RFC 9457 transport error.

An authenticated evaluation records every check in a CheckResult, in the order of the table
of draft 12.1, then each field rule by its rule_id and each of the contract's context_checks,
in contract order, each exactly once. A check that was not performed is never PASS: it is
UNKNOWN with NOT_EVALUATED. decide is draft 11.4; a store that cannot answer makes the
check that needs it UNKNOWN, which defers; it never admits (draft 18). A receipt is recorded
before it is returned: one that cannot be recorded is DEFERRED with the check receipt-store
UNKNOWN, and the raised error carries it as its result attribute.

Time is the injected clock alone. The evaluation deadline is the earliest of the contract's
and the presentation's exp and the start plus Config.evaluation_time, at most 30 seconds
(draft 12.2). evaluate also takes a keyword-only cancelled predicate, the requestor's
cancellation through native session control: it is polled while the evaluation runs, and
once it returns true the evaluation seals DEFERRED with terminal reason CANCELLED. The calls
take no context argument.

Every other error is the draft 13.4 code the error carries; ValidatorError carries the two
failures that have none. Handoff is the gateway's check of a sidecar validator's attestation
(draft 11.5).
"""

from __future__ import annotations

from typing import Final

from hop_top_pact.contract import SELECTION_CONSISTENCY_CHECK
from hop_top_pact.validator._config import (
    ActivePolicy,
    Config,
    ContextMapper,
    EvidenceStatus,
    HoldStore,
    Issuer,
    Native,
    NativeMapping,
    PolicyRegistry,
    ReceiptStore,
    Request,
    Result,
    Selection,
    SelectionInput,
    Selector,
    Signer,
    SourceCapability,
    StatusChecker,
)
from hop_top_pact.validator._decide import decide
from hop_top_pact.validator._errors import ValidatorError, ValidatorErrorKind
from hop_top_pact.validator._handoff import AttestationStore, Handoff, MemoryAttestations
from hop_top_pact.validator._problem import problem_of
from hop_top_pact.validator._receipt import Ed25519Signer, ES256Signer, MemoryReceipts
from hop_top_pact.validator._state import Event, State, next
from hop_top_pact.validator._validator import Validator

# The check identifiers of the mandatory protocol checks of draft 9.3, 11.3 and 12.1, in the
# order a receipt lists them (the table of draft 12.1), and of the two baseline installed
# checks the validator evaluates itself (draft 9.4, 17.5). A receipt then lists the field
# rules by rule_id and the contract's context_checks, each in contract order.
CHECK_NATIVE_AUTHENTICATION: Final = "native-authentication"
CHECK_AGENT_HOLDER_BINDING: Final = "agent-holder-binding"
CHECK_CONTRACT_VALIDITY: Final = "contract-validity"
CHECK_NONCE: Final = "nonce"
CHECK_OPERATION_BINDING: Final = "operation-binding"
CHECK_INTENT_BINDING: Final = "intent-binding"
CHECK_PROFILE_VALIDITY: Final = "profile-validity"
CHECK_EVIDENCE_VALIDITY: Final = "evidence-validity"
CHECK_REPUTATION_CONTEXT: Final = "reputation-context"
CHECK_SECURITY_HOLD: Final = "security-hold"
CHECK_ACTIVE_POLICY: Final = "active-policy"
CHECK_RECEIPT_STORE: Final = "receipt-store"
CHECK_NATIVE_PRINCIPAL_BINDING: Final = "native-principal-binding-v1"
CHECK_SELECTION_CONSISTENCY: Final = SELECTION_CONSISTENCY_CHECK

__all__ = [
    "CHECK_ACTIVE_POLICY",
    "CHECK_AGENT_HOLDER_BINDING",
    "CHECK_CONTRACT_VALIDITY",
    "CHECK_EVIDENCE_VALIDITY",
    "CHECK_INTENT_BINDING",
    "CHECK_NATIVE_AUTHENTICATION",
    "CHECK_NATIVE_PRINCIPAL_BINDING",
    "CHECK_NONCE",
    "CHECK_OPERATION_BINDING",
    "CHECK_PROFILE_VALIDITY",
    "CHECK_RECEIPT_STORE",
    "CHECK_REPUTATION_CONTEXT",
    "CHECK_SECURITY_HOLD",
    "CHECK_SELECTION_CONSISTENCY",
    "ActivePolicy",
    "AttestationStore",
    "Config",
    "ContextMapper",
    "ES256Signer",
    "Ed25519Signer",
    "Event",
    "EvidenceStatus",
    "Handoff",
    "HoldStore",
    "Issuer",
    "MemoryAttestations",
    "MemoryReceipts",
    "Native",
    "NativeMapping",
    "PolicyRegistry",
    "ReceiptStore",
    "Request",
    "Result",
    "Selection",
    "SelectionInput",
    "Selector",
    "Signer",
    "SourceCapability",
    "State",
    "StatusChecker",
    "Validator",
    "ValidatorError",
    "ValidatorErrorKind",
    "decide",
    "next",
    "problem_of",
]
