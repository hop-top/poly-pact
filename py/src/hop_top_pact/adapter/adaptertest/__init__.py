"""Adapter conformance suite. Mirrors hop.top/pact-go/adapter/adaptertest.

The case model, frozen with the adapter contract; what the suite and an
adapter under test exchange; the case loader; and the suite entry points:
conformance_cases and run_case, the two halves of Go's Run, and
evaluate_conformance, Go's Evaluate.

An adapter function reports an error by raising a PactError, the AdapterError
of the draft 13.4 code where it has one, as a Go adapter returns an error.
Any other exception is a defect of the adapter, as a Go panic is: the case
fails whatever outcome it expects. A Python call either returns or raises,
so the Go checks of a value returned together with an error have no
counterpart.

No module of this package imports a test framework.
"""

from hop_top_pact.adapter.adaptertest.casefile import (
    ABSENT,
    BindingJSON,
    Call,
    Case,
    Expect,
    ExpectBinding,
    ExpectClaim,
    ExpectDecision,
    ExpectOperation,
    ExpectPrincipal,
    LeakScan,
    LoadError,
    ObligationJSON,
    ObservationJSON,
    PrincipalJSON,
    RealmJSON,
    Request,
    TLSPeer,
    load_cases,
)
from hop_top_pact.adapter.adaptertest.harness import (
    Env,
    Factory,
    Hooks,
    Options,
    Replacement,
    Subject,
)
from hop_top_pact.adapter.adaptertest.suite import (
    DEFAULT_NOW,
    CaseFailure,
    Result,
    conformance_cases,
    default_fixtures,
    evaluate_conformance,
    run_case,
)

__all__ = [
    "ABSENT",
    "DEFAULT_NOW",
    "BindingJSON",
    "Call",
    "Case",
    "CaseFailure",
    "Env",
    "Expect",
    "ExpectBinding",
    "ExpectClaim",
    "ExpectDecision",
    "ExpectOperation",
    "ExpectPrincipal",
    "Factory",
    "Hooks",
    "LeakScan",
    "LoadError",
    "ObligationJSON",
    "ObservationJSON",
    "Options",
    "PrincipalJSON",
    "RealmJSON",
    "Replacement",
    "Request",
    "Result",
    "Subject",
    "TLSPeer",
    "conformance_cases",
    "default_fixtures",
    "evaluate_conformance",
    "load_cases",
    "run_case",
]
