"""The agent side of a PACT admission exchange, the PACT Holder 0.1 role of draft section
22.1: strict version negotiation, contract verification, requirement-driven profile
disclosure, evidence handling, request binding and key proof (draft 11.1 steps 2 to 5).
Mirrors hop.top/pact-go/holder.

Flow
----

1. Holder.negotiate checks the gateway metadata (draft 13.1): wire version 0.1, compared
   exactly and never downgraded (draft 21), and the holder key's algorithm.
2. operation_from_request maps the HTTP request the agent is about to send to its
   operation context with the gateway's baseline mapping (core.binding, draft 10.2), for
   the contract request.
3. Holder.verify_contract verifies the returned requirement contract with the contract
   package: the publisher's signature under configured keys, freshness, agent, gateway,
   realm, extensions, the holder key, and the object_digest of the intent and operation
   the agent will perform (draft 9.1, 10.3).
4. Holder.present discloses the profile view the contract asks for, attaches the
   evidence and reputation snapshot its rules use, binds the intent, operation, contract
   and nonce, and has the KeySource sign the presentation (draft 8, 11.2).

Disclosure
----------

The view keeps the source profile's core fields and discloses, of its attributes, only
the values at the paths the contract's field rules name (draft 8.1, 19). A native or
self rule takes the agent's value. An evidence rule needs applicable evidence: an issuer
the rule allows, a claim on exactly the rule's path, and the agent, holder key, gateway
and realm of this exchange, valid now (draft 8.3, 8.4). A reputation rule takes the
complete value of an applicable snapshot at /attributes/reputation (draft 15.2, Appendix
A.2). The holder never replaces a missing authoritative value with a self-asserted one
(draft 8.6): such a rule fails with MISSING_FIELD. Evidence and snapshots are read, not
verified: their issuers' authority is the gateway's check (draft 11.2).

Keys
----

The holder key stays in its KeySource: the holder asks it for the public key and for a
signature over the JWS signing input, so that an OS keychain, a hardware key or a signing
service can hold it (draft 6.4). MemoryKey is an in-memory key source for tests and
examples. The presentation embeds the public key (draft 7.2), and the holder verifies
each signature under the key's thumbprint before it returns the presentation.

Errors
------

Every error is a HolderError whose code is the draft 13.4 code. The calls are synchronous
and take no context argument; instants are aware datetimes and the holder's skew and
lifetime are timedeltas, with microsecond precision where Go has nanoseconds.
"""

from __future__ import annotations

from hop_top_pact.holder._errors import CODE_CONFLICTING_EVIDENCE, CODE_EXPIRED, HolderError
from hop_top_pact.holder._holder import Holder
from hop_top_pact.holder._keysource import KeySource, MemoryKey
from hop_top_pact.holder._operation import operation_from_request
from hop_top_pact.holder._types import Input, Presentation

__all__ = [
    "CODE_CONFLICTING_EVIDENCE",
    "CODE_EXPIRED",
    "Holder",
    "HolderError",
    "Input",
    "KeySource",
    "MemoryKey",
    "Presentation",
    "operation_from_request",
]
