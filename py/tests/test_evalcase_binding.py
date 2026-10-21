"""The binding results of native_context.json and the enrollment source of
exchange.json. Port of go/runner/evalcase/binding_test.go."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact import conformance

VALID = "admission/valid"
AGENT = "https://identity.example/agents/invoice-assistant"
OPERATOR = "https://identity.example/operators/acme"
JKT = "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M"


def unknown_binding(a: dict[str, Any]) -> None:
    """The result of resolve_agent_binding for an agent with no record on the
    authenticated workload (identity mapping IM-11): binding_status unknown and no
    agent, operator or key."""
    a["binding_status"] = "unknown"
    a["agent_id"] = a["operator_id"] = a["holder_jkt"] = None


def edit_authenticated(ec: Any, root: Path, f: Callable[[dict[str, Any]], None]) -> None:
    ec.edit_json(root, VALID + "/native_context.json", lambda n: f(n["authenticated"]))


def then(*fs: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
    def run(a: dict[str, Any]) -> None:
        for f in fs:
            f(a)

    return run


def put(**kv: Any) -> Callable[[dict[str, Any]], None]:
    return lambda a: a.update(kv)


def test_binding_result_defaults(ec: Any) -> None:
    """native_context.json's authenticated member carries the binding results of
    identity mapping section 8 (spec/v1.0/fixtures/README.md, native_context.json), with
    the defaults of enrolled_elsewhere and binding_error."""
    c = conformance.load(ec.repo_fixtures(), VALID)
    a = c.exchanges[0].native_context.authenticated
    assert a is not None
    assert (a.agent_id, a.operator_id, a.holder_jkt) == (AGENT, OPERATOR, JKT)
    assert (a.binding_status, a.enrolled_elsewhere, a.binding_error) == ("active", False, None)
    assert c.exchanges[0].availability.enrollment_source == "available"


ACCEPTED: dict[str, tuple[Callable[[dict[str, Any]], None], dict[str, Any]]] = {
    "unknown, not enrolled elsewhere": (
        unknown_binding,
        {
            "agent_id": None,
            "operator_id": None,
            "holder_jkt": None,
            "enrolled_elsewhere": False,
            "binding_error": None,
        },
    ),
    "unknown, enrolled elsewhere": (
        then(unknown_binding, put(enrolled_elsewhere=True)),
        {"enrolled_elsewhere": True},
    ),
    "unknown, two enrollments": (
        then(unknown_binding, put(binding_error="UNSUPPORTED_REQUIREMENT")),
        {"binding_error": "UNSUPPORTED_REQUIREMENT"},
    ),
    "explicit defaults": (
        put(enrolled_elsewhere=False, binding_error=None),
        {"enrolled_elsewhere": False, "binding_error": None, "agent_id": AGENT},
    ),
    "compromised": (
        put(binding_status="compromised"),
        {"binding_status": "compromised", "holder_jkt": JKT},
    ),
    "revoked": (put(binding_status="revoked"), {"binding_status": "revoked"}),
}


@pytest.mark.parametrize(("edit", "want"), list(ACCEPTED.values()), ids=list(ACCEPTED))
def test_binding_result_accepts(
    ec: Any, edit: Callable[[dict[str, Any]], None], want: dict[str, Any]
) -> None:
    root = ec.case_tree(VALID)
    edit_authenticated(ec, root, edit)
    a = conformance.load(root, VALID).exchanges[0].native_context.authenticated
    assert a is not None
    assert {k: getattr(a, k) for k in want} == want


REJECTED: dict[str, tuple[Callable[[dict[str, Any]], None], str]] = {
    "a status outside the four": (put(binding_status="suspended"), "binding_status"),
    "an upper-case status": (put(binding_status="ACTIVE"), "binding_status"),
    "unknown with an agent": (then(unknown_binding, put(agent_id=AGENT)), "agent_id"),
    "unknown with an operator": (then(unknown_binding, put(operator_id=OPERATOR)), "operator_id"),
    "unknown with a key": (then(unknown_binding, put(holder_jkt=JKT)), "holder_jkt"),
    "active with no agent": (put(agent_id=None), "agent_id"),
    "active with no operator": (put(operator_id=None), "operator_id"),
    "compromised with no key": (put(binding_status="compromised", holder_jkt=None), "holder_jkt"),
    "active with an empty agent": (put(agent_id=""), "agent_id"),
    "enrolled elsewhere with an active binding": (
        put(enrolled_elsewhere=True),
        "enrolled_elsewhere",
    ),
    "enrolled elsewhere null": (
        then(unknown_binding, put(enrolled_elsewhere=None)),
        "enrolled_elsewhere",
    ),
    "binding error with an active binding": (
        put(binding_error="UNSUPPORTED_REQUIREMENT"),
        "binding_error",
    ),
    "binding error of another code": (
        then(unknown_binding, put(binding_error="CONTEXT_MISMATCH")),
        "binding_error",
    ),
    "a renamed member": (
        then(unknown_binding, put(enrolled_for_another_workload=True)),
        "enrolled_for_another_workload",
    ),
}


@pytest.mark.parametrize(("edit", "want"), list(REJECTED.values()), ids=list(REJECTED))
def test_binding_result_rejects(ec: Any, edit: Callable[[dict[str, Any]], None], want: str) -> None:
    root = ec.case_tree(VALID)
    edit_authenticated(ec, root, edit)
    ec.fails(lambda: conformance.load(root, VALID), "native_context.json", want)
    ec.fails(lambda: conformance.read(root, VALID), "native_context.json", want)


@pytest.mark.parametrize(
    ("body", "want"),
    [
        ('{"availability":{"enrollment_source":"unavailable"}}', "unavailable"),
        ('{"availability":{"enrollment_source":"available"}}', "available"),
        ('{"availability":{"replay_store":"unavailable"}}', "available"),
        ('{"availability":{}}', "available"),
    ],
)
def test_enrollment_source(ec: Any, body: str, want: str) -> None:
    """exchange.json's availability.enrollment_source is available or unavailable
    (spec/v1.0/fixtures/README.md, availability)."""
    root = ec.case_tree(VALID)
    ec.write_file(ec.at(root, VALID + "/exchange.json"), body)
    assert conformance.load(root, VALID).exchanges[0].availability.enrollment_source == want


@pytest.mark.parametrize(
    "body",
    [
        '{"availability":{"enrollment_source":"down"}}',
        '{"availability":{"enrollment_source":"full"}}',
    ],
)
def test_enrollment_source_rejects(ec: Any, body: str) -> None:
    root = ec.case_tree(VALID)
    ec.write_file(ec.at(root, VALID + "/exchange.json"), body)
    ec.fails(lambda: conformance.load(root, VALID), "exchange.json", "enrollment_source")
