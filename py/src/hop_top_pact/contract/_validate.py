"""The RequirementContract schema rules that strict decoding does not enforce, and the
source-specific rules of Appendix A.2 and draft 9.2."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Final

from hop_top_pact.core import VERSION, Digest
from hop_top_pact.core.enums import Comparison, Mode, RuleSource
from hop_top_pact.core.schema import URI_EXPRESSION
from hop_top_pact.core.types import FieldRule, JSONValue, RequirementContract

__all__ = [
    "DELEGATION_PREFIX",
    "PRINCIPAL_PATH",
    "REPUTATION_PREFIX",
    "bounded",
    "validate",
    "within",
]

# Bounds of the RequirementContract and FieldRule schema (Appendix A.3).
_MAX_STRING: Final = 1024
_MAX_FIELD_RULES: Final = 128
_MAX_CHECKS: Final = 128
_MAX_ISSUERS: Final = 32
_MAX_EXTENSIONS: Final = 128
_MAX_CORE_INTEGER: Final = (1 << 53) - 1

# The jti and nonce form: at least 128 bits of base64url (Appendix A.2, A.3).
_RANDOM: Final = re.compile(r"[A-Za-z0-9_-]{22,128}")
# The schema pattern of path and native_path: a non-empty RFC 6901 JSON Pointer.
_POINTER: Final = re.compile(r"(?:/(?:[^~/]|~[01])*)+")
_URI: Final = re.compile(URI_EXPRESSION)

# The profile paths a self rule can never decide (draft 9.2, Appendix A.2): the
# principal, and the delegation and reputation prefixes with their descendants.
PRINCIPAL_PATH: Final = "/attributes/environment/principal_id"
DELEGATION_PREFIX: Final = "/attributes/delegation"
REPUTATION_PREFIX: Final = "/attributes/reputation"


def validate(c: RequirementContract, raw: Mapping[str, JSONValue] | None = None) -> None:
    """Apply the RequirementContract schema of Appendix A.3 that strict decoding does not
    enforce, and the source-specific rules of Appendix A.2 and draft 9.2; raise
    ValueError naming the first rule broken.

    It does not check the time window, the context or the field-rule schemas'
    keywords: an unsupported keyword makes the rule UNKNOWN, not the contract
    invalid (Appendix A.1). raw is the payload as strictjson.parse read it, when
    there is one: strict decoding gives an absent array the value of an empty
    one, and the schema requires field_rules and each rule's allowed_issuers.
    """
    if c.pact_version != VERSION:
        raise ValueError(f"pact_version {c.pact_version!r}")
    if not all(_uri(s) for s in (c.iss, c.sub, c.aud, c.environment_id)):
        raise ValueError(
            "iss, sub, aud and environment_id are absolute URIs of at most 1024 characters"
        )
    if not bounded(c.tenant_id, c.contract_id, c.base_revision, c.selected_set):
        raise ValueError(
            "tenant_id, contract_id, base_revision and selected_set are 1 to 1024 characters"
        )
    if not (_RANDOM.fullmatch(c.jti) and _RANDOM.fullmatch(c.nonce)):
        raise ValueError("jti and nonce are 22 to 128 base64url characters")
    if not all(_integer(n) for n in (c.iat, c.nbf, c.exp)):
        raise ValueError("iat, nbf and exp are integers in 0..2^53-1")
    if c.iat >= c.exp or c.nbf >= c.exp:
        raise ValueError("iat and nbf are before exp")
    if not Mode.is_valid(c.mode):
        raise ValueError(f"mode {c.mode!r}")
    if len(c.extensions or ()) > _MAX_EXTENSIONS:
        raise ValueError("more than 128 extensions")
    for name, d in (
        ("holder_jkt", c.holder_jkt),
        ("operation_digest", c.operation_digest),
        ("intent_digest", c.intent_digest),
        ("learning_policy_digest", c.learning_policy_digest),
        ("learning_artifact_digest", c.learning_artifact_digest),
    ):
        try:
            Digest(d).validate()
        except ValueError as e:
            raise ValueError(f"{name}: {e}") from e
    checks = c.context_checks
    if not checks or len(checks) > _MAX_CHECKS or not _unique(checks) or not bounded(*checks):
        raise ValueError("context_checks holds 1 to 128 distinct identifiers")
    if (raw is not None and not isinstance(raw.get("field_rules"), tuple)) or (
        len(c.field_rules) > _MAX_FIELD_RULES
    ):
        raise ValueError("field_rules is an array of at most 128 rules")
    raw_rules: Sequence[JSONValue] = ()
    if raw is not None:
        rules = raw["field_rules"]
        assert isinstance(rules, tuple)
        raw_rules = rules
    ids: set[str] = set()
    for i, r in enumerate(c.field_rules):
        member = raw_rules[i] if i < len(raw_rules) else None
        try:
            _validate_rule(r, raw is not None and not _has_issuers(member))
        except ValueError as e:
            raise ValueError(f"field_rules[{i}]: {e}") from e
        if r.rule_id in ids:
            raise ValueError(f"field_rules[{i}]: rule_id {r.rule_id!r} is not unique")
        ids.add(r.rule_id)


def _has_issuers(rule: JSONValue) -> bool:
    return isinstance(rule, Mapping) and isinstance(rule.get("allowed_issuers"), tuple)


def _validate_rule(r: FieldRule, issuers_absent: bool) -> None:
    """Apply the FieldRule schema and the source rules of Appendix A.2."""
    if not bounded(r.rule_id):
        raise ValueError("rule_id is 1 to 1024 characters")
    if not _pointer(r.path):
        raise ValueError(f"path {r.path!r} is not a JSON Pointer")
    if not isinstance(r.schema, bool | Mapping):
        raise ValueError("schema is an object or a boolean")
    if not RuleSource.is_valid(r.source) or not Comparison.is_valid(r.comparison):
        raise ValueError(f"source {r.source!r} or comparison {r.comparison!r}")
    if issuers_absent or len(r.allowed_issuers) > _MAX_ISSUERS or not _unique(r.allowed_issuers):
        raise ValueError("allowed_issuers is an array of at most 32 distinct URIs")
    if r.native_path is not None and not _pointer(r.native_path):
        raise ValueError(f"native_path {r.native_path!r} is not a JSON Pointer")
    if not _integer(r.max_age_seconds) or not _integer(r.status_max_age_seconds):
        raise ValueError("max_age_seconds and status_max_age_seconds are integers in 0..2^53-1")
    if len(r.extensions or ()) > _MAX_EXTENSIONS:
        raise ValueError("more than 128 extensions")
    for iss in r.allowed_issuers:
        if not _uri(iss):
            raise ValueError(f"allowed issuer {iss!r} is not an absolute URI")
    if r.source == RuleSource.SELF:
        if (
            r.allowed_issuers
            or r.native_path is not None
            or r.comparison != Comparison.EQUAL
            or r.max_age_seconds != 0
            or r.status_max_age_seconds != 0
        ):
            raise ValueError(
                "a self rule has no issuers, native_path null, comparison equal and both ages zero"
            )
        if (
            r.path == PRINCIPAL_PATH
            or within(r.path, DELEGATION_PREFIX)
            or within(r.path, REPUTATION_PREFIX)
        ):
            raise ValueError(f"a self rule cannot decide {r.path} (draft 9.2)")
    elif r.source == RuleSource.EVIDENCE:
        if not r.allowed_issuers or r.native_path is not None:
            raise ValueError(
                "an evidence rule has at least one allowed issuer and native_path null"
            )
    elif r.allowed_issuers or r.native_path is None:
        raise ValueError("a native rule has no issuers and a native_path")


def within(path: str, prefix: str) -> bool:
    """Report whether the JSON Pointer path is prefix or a descendant of it."""
    return path == prefix or path.startswith(prefix + "/")


def _octets(s: str) -> int:
    return len(s) if s.isascii() else len(s.encode("utf-8", "surrogatepass"))


def bounded(*ss: str) -> bool:
    """Report whether every s is 1 to 1024 octets of UTF-8."""
    return all(s and _octets(s) <= _MAX_STRING for s in ss)


def _uri(s: str) -> bool:
    """Whether s is an absolute URI (the schema's format uri) of at most 1024 octets."""
    return bounded(s) and _URI.fullmatch(s) is not None


def _pointer(s: str) -> bool:
    return _octets(s) <= _MAX_STRING and _POINTER.fullmatch(s) is not None


def _integer(n: int) -> bool:
    return 0 <= n <= _MAX_CORE_INTEGER


def _unique(ss: Sequence[str]) -> bool:
    return len(set(ss)) == len(ss)
