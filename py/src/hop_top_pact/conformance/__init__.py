"""Evaluation-case loading for an implementation under test. Mirrors
hop.top/pact-go/runner/evalcase.

Reads the evaluation cases of spec/v1.0/fixtures and checks their signed files. The
format is spec/v1.0/fixtures/README.md, sections Evaluation cases, Signed artifacts and
Format v2. Standard library, cryptography and the package's own modules only;
distinct from the adapter case files that adapter.adaptertest reads.

Evaluation cases: load reads a manifest entry of kind evaluate into a Case: one
Exchange for a case directory, or one per exchange directory of a multi-exchange
case's sequence.json, in order. An Exchange holds config.json, native_context.json,
signing.json and exchange.json as typed values, exchange.json with its defaults
applied, every other JSON file of the directory as bytes, the committed signed files,
and the expected decision.json, whether at expected/<id>/decision.json or, for an
exchange, at expected/<id>/<exchange>/decision.json. v1 cases read the same under
format v2, since every v2 member has a default. read reads a case without verifying
its signed files, for a consumer that judges an implementation against it.

Signed files: the generator contract of signing.json is applied by walk, which
verify drives to check: dirs lists the signed directories, load_keys the test keys
of KEYS_FILE, and each File says what a signed file must carry. verify, and so load,
fails on a stale signed file, one the generator would sign again. Each Signed also
carries the result of verifying it against the directory's trust records
(config.json trust and the authenticated holder_jkt), which a case may make fail by
design.

Not ported: the outcomes and learning case readers of the Go package
(ReadOutcomes, ReadLearning), which build on its reputation package. dirs and verify
cover the signed directories of outcomes and learning cases all the same. Trust keys
are read with core.jws.parse_jwk, which accepts ES256 keys only: a trust record
naming an Ed25519 key fails here where Go verifies it.

Errors are CaseError, a PactError. Paths are slash-separated and relative to the
fixture directory, the directory of manifest.json, or to a case directory where a
field says so.

``python -m hop_top_pact.conformance evaluate DIR [STATE]`` is the evaluate skeleton
of the conformance runner (see __main__).
"""

from __future__ import annotations

from hop_top_pact.conformance.case import Case, Exchange, load, read
from hop_top_pact.conformance.dirs import Dir, dirs
from hop_top_pact.conformance.errors import CaseError
from hop_top_pact.conformance.keys import KEYS_FILE, Key, load_keys
from hop_top_pact.conformance.signing import (
    ABSENT,
    FIXED_TIME,
    PRESENTATION_LIFETIME,
    Artifact,
    Presentation,
    Signing,
)
from hop_top_pact.conformance.types import (
    BINDING_ACTIVE,
    BINDING_COMPROMISED,
    BINDING_REVOKED,
    BINDING_UNKNOWN,
    ActivePolicy,
    Amount,
    Approval,
    ApproverAuthority,
    Authenticated,
    Availability,
    Config,
    Decision,
    Delegation,
    Evaluation,
    EvidenceStatus,
    Executor,
    ExecutorClass,
    ExpectedCheck,
    Gateway,
    Handoff,
    HandoffAttempt,
    Minimums,
    NativeClaim,
    NativeContext,
    NativeMapping,
    NativeSource,
    Receipt,
    Response,
    Selection,
    SelectionRecord,
    Selector,
    Submission,
    Threshold,
    TrustRecord,
    Validator,
)
from hop_top_pact.conformance.verify import Signed, verify
from hop_top_pact.conformance.walk import File, read_decoded, walk

__all__ = [
    "ABSENT",
    "BINDING_ACTIVE",
    "BINDING_COMPROMISED",
    "BINDING_REVOKED",
    "BINDING_UNKNOWN",
    "FIXED_TIME",
    "KEYS_FILE",
    "PRESENTATION_LIFETIME",
    "ActivePolicy",
    "Amount",
    "Approval",
    "ApproverAuthority",
    "Artifact",
    "Authenticated",
    "Availability",
    "Case",
    "CaseError",
    "Config",
    "Decision",
    "Delegation",
    "Dir",
    "Evaluation",
    "EvidenceStatus",
    "Exchange",
    "Executor",
    "ExecutorClass",
    "ExpectedCheck",
    "File",
    "Gateway",
    "Handoff",
    "HandoffAttempt",
    "Key",
    "Minimums",
    "NativeClaim",
    "NativeContext",
    "NativeMapping",
    "NativeSource",
    "Presentation",
    "Receipt",
    "Response",
    "Selection",
    "SelectionRecord",
    "Selector",
    "Signed",
    "Signing",
    "Submission",
    "Threshold",
    "TrustRecord",
    "Validator",
    "dirs",
    "load",
    "load_keys",
    "read",
    "read_decoded",
    "verify",
    "walk",
]
