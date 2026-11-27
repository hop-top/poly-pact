"""The PACT admission validator: the algorithm of draft Section 11.3, the decisions of
Section 11.4 and the receipts and state machine of Section 12, for a gateway that
evaluates in its own request path or as a trusted sidecar (draft 4.4). Mirrors
hop.top/pact-go/validator.

This module holds, so far, the pieces that need no evaluation: the check identifiers, the
decision table (decide), the state machine (State, Event, next) and the transport errors
(problem_of). Every error code is the draft 13.4 code; ValidatorError carries the two
failures that have none.
"""

from __future__ import annotations

from typing import Final

from hop_top_pact.contract import SELECTION_CONSISTENCY_CHECK
from hop_top_pact.validator._decide import decide
from hop_top_pact.validator._errors import ValidatorError, ValidatorErrorKind
from hop_top_pact.validator._problem import problem_of
from hop_top_pact.validator._state import Event, State, next

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
    "Event",
    "State",
    "ValidatorError",
    "ValidatorErrorKind",
    "decide",
    "next",
    "problem_of",
]
