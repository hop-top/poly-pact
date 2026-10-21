"""The case loader and the rules of the case file format.

Port of go/adapter/adaptertest/casefile_test.go: Load becomes load_cases over a
Traversable fixture tree (the in-memory FixtureTree of the at fixture, Go's
fstest.MapFS), and an error is a LoadError that names the file.
"""

from __future__ import annotations

from typing import Any

import pytest

from hop_top_pact.adapter.adaptertest import LoadError, load_cases
from hop_top_pact.errors import PactError


def test_load(at: Any) -> None:
    minimal = at.MINIMAL_CASE

    # common cases
    cases = load_cases(
        at.tree_of(
            {
                "adapters/_common/a.json": minimal,
                "adapters/_common/b.json": minimal.replace("COMMON-01.one", "COMMON-01.two", 1),
                "adapters/_common/notes.txt": "ignored",
            }
        )
    )
    assert [c.id for c in cases] == ["COMMON-01.one", "COMMON-01.two"]

    # adapter cases follow the common cases
    cases = load_cases(
        at.tree_of(
            {
                "adapters/_common/a.json": minimal,
                "adapters/basic/basic-01.json": minimal.replace("COMMON-01.one", "BASIC-01", 1),
                "adapters/basic/basic-02.json": minimal.replace("COMMON-01.one", "BASIC-02", 1),
                "adapters/other/other-01.json": minimal.replace("COMMON-01.one", "OTHER-01", 1),
                "adapters/basic/notes/x.json": minimal.replace("COMMON-01.one", "BASIC-99", 1),
                "adapters/basic/cases/old.json": minimal.replace("COMMON-01.one", "BASIC-98", 1),
            }
        ),
        "basic",
    )
    assert [c.id for c in cases] == ["COMMON-01.one", "BASIC-01", "BASIC-02"], (
        "the adapter's cases are the files of adapters/<name>, with no subdirectory"
    )

    # adapter name without cases
    for name, tree in {
        "no directory": {"adapters/_common/a.json": minimal},
        "only a cases subdirectory": {
            "adapters/_common/a.json": minimal,
            "adapters/basic/cases/own.json": minimal.replace("COMMON-01.one", "BASIC-01", 1),
        },
    }.items():
        with pytest.raises(LoadError) as e:
            load_cases(at.tree_of(tree), "basic")
        assert "adapters/basic" in str(e.value), name
        assert "adapters/basic/cases" not in str(e.value), name

    # bad adapter name
    for bad in ("../x", "Basic", "a/b", "-x"):
        with pytest.raises(LoadError, match="adapter name"):
            load_cases(at.tree_of({"adapters/_common/a.json": minimal}), bad)

    # no common cases
    with pytest.raises(LoadError):
        load_cases(at.tree_of({"adapters/_common/readme.txt": "x"}))
    with pytest.raises(LoadError):
        load_cases(at.tree_of({"other/a.json": minimal}))

    # duplicate id across directories
    with pytest.raises(LoadError, match="used twice"):
        load_cases(
            at.tree_of(
                {"adapters/_common/a.json": minimal, "adapters/basic/basic-01.json": minimal}
            ),
            "basic",
        )

    # the error is a PactError
    assert issubclass(LoadError, PactError)


def _case_file_rules(minimal: str) -> list[tuple[str, str, str]]:
    def sub(old: str, new: str) -> str:
        assert old in minimal, f"the minimal case lacks {old!r}"
        return minimal.replace(old, new, 1)

    claim = (
        minimal.replace("authenticate_native", "read_native_claim")
        .replace('"denied"', '"bounded"')
        .replace(
            '"request": {"method": "GET", "url": "https://gateway.example/x"},',
            '"call": {"principal": {"id": "p", "realm": {"tenant_id": "t",'
            ' "environment_id": "e"}}, "native_path": "/x"},',
        )
    )
    request = '"request": {"method": "GET", "url": "https://gateway.example/x"},'
    return [
        (
            "unknown member",
            sub('"title": "A case",', '"title": "A case", "surprise": 1,'),
            "surprise",
        ),
        (
            "duplicate member",
            sub('"title": "A case",', '"title": "A case", "title": "B",'),
            "duplicate",
        ),
        ("case version", sub('"case_version": 1', '"case_version": 2'), "case_version"),
        ("id shape", sub("COMMON-01.one", "common-01"), "does not match"),
        ("id suffix shape", sub("COMMON-01.one", "COMMON-01.One"), "does not match"),
        ("empty title", sub('"A case"', '" "'), "title is empty"),
        ("native state is not an object", sub('{"model": "common/1"}', "[1]"), "native_state"),
        ("native state missing", sub('"native_state": {"model": "common/1"},', ""), "native_state"),
        ("negative now", sub('"title"', '"now": -1, "title"'), "now"),
        ("unknown function", sub("authenticate_native", "authenticate"), "seven functions"),
        (
            "outcome of another function",
            sub('"denied"', '"mapped"'),
            "not defined for authenticate_native",
        ),
        # A clock-ahead claim is refused (freshness profile); no outcome accepts
        # a claim with its times clamped instead.
        (
            "retired bounded outcome",
            claim,
            "outcome 'bounded' is not defined for read_native_claim",
        ),
        (
            "authenticated without a principal",
            sub('"denied"', '"authenticated"'),
            "needs expect.principal",
        ),
        ("missing request", sub(request, ""), "needs a request"),
        (
            "request without a url",
            sub('"url": "https://gateway.example/x"', '"url": ""'),
            "method and a url",
        ),
        (
            "bad arrival",
            sub('"method": "GET"', '"method": "GET", "arrival": "sideways"'),
            "arrival",
        ),
        (
            "bad header name",
            sub('"method": "GET"', '"method": "GET", "headers": {"X Bad": "1"}'),
            "header name",
        ),
        ("bad body", sub('"method": "GET"', '"method": "GET", "body_b64": "***"'), "base64"),
        (
            "call argument that does not apply",
            sub('"expect"', '"call": {"native_path": "/x"}, "expect"'),
            "not an argument of authenticate_native",
        ),
        (
            "expectation that does not apply",
            sub('"outcome": "denied"', '"outcome": "denied", "claim": {}'),
            "does not apply",
        ),
        (
            "empty hook name",
            sub('"outcome": "denied"', '"outcome": "denied", "must_not_call": [" "]'),
            "empty hook name",
        ),
        (
            "unknown workload mode",
            sub('"title": "A case",', '"title": "A case", "workloads": "Shared",'),
            "workloads",
        ),
        (
            "workload mode of no profile",
            sub('"title": "A case",', '"title": "A case", "workloads": "any",'),
            "workloads",
        ),
        ("not json", "{", "strictjson"),
    ]


def test_case_file_rules(at: Any) -> None:
    """Each mutation of the minimal case breaks one rule of the format, and
    load_cases names it and the file."""
    for name, body, want in _case_file_rules(at.MINIMAL_CASE):
        with pytest.raises(LoadError) as e:
            load_cases(at.tree_of({"adapters/_common/a.json": body}))
        assert want in str(e.value), f"{name}: {e.value}"
        assert "adapters/_common/a.json" in str(e.value), f"{name}: {e.value}"


def test_workloads_member(at: Any) -> None:
    """A case may say which adapters it applies to, by whether the adapter's profile
    supports workloads shared by several agents. "shared" and "dedicated" are the
    two values; absent, the case applies to every adapter."""
    for member, want in (
        ("", ""),
        ('"workloads": "shared",', "shared"),
        ('"workloads": "dedicated",', "dedicated"),
    ):
        body = at.MINIMAL_CASE.replace('"title": "A case",', '"title": "A case", ' + member, 1)
        cases = load_cases(at.tree_of({"adapters/_common/a.json": body}))
        assert cases[0].workloads == want, member


def _load_body(at: Any, body: str, want: str, name: str) -> None:
    tree = at.tree_of({"adapters/_common/a.json": body})
    if not want:
        try:
            load_cases(tree)
        except LoadError as e:
            pytest.fail(f"{name}: load_cases rejected a valid case: {e}")
        return
    with pytest.raises(LoadError) as err:
        load_cases(tree)
    assert want in str(err.value), f"{name}: {err.value}"


def test_enrolled_elsewhere_expectation(at: Any) -> None:
    """expect.binding.enrolled_elsewhere may be true only for the outcome unknown,
    which accepts no other binding member."""
    record = (
        '"agent_id": "https://a.example/a", "operator_id": "https://o.example/o",'
        ' "holder_jkt": "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M", "status": "ACTIVE"'
    )
    for outcome, binding, want in (
        ("unknown", '"enrolled_elsewhere": true', ""),
        ("unknown", '"enrolled_elsewhere": false', ""),
        (
            "unknown",
            '"enrolled_elsewhere": true, "agent_id": "https://a.example/a"',
            "only enrolled_elsewhere",
        ),
        ("unknown", '"status": "UNKNOWN"', "only enrolled_elsewhere"),
        ("bound", record + ', "enrolled_elsewhere": false', ""),
        ("bound", record + ', "enrolled_elsewhere": true', "enrolled_elsewhere true"),
        ("unusable", record + ', "enrolled_elsewhere": true', "enrolled_elsewhere true"),
        ("error", '"enrolled_elsewhere": true', "enrolled_elsewhere true"),
    ):
        body = (
            '{"case_version": 1, "id": "CASE-01", "title": "t", "native_state": {}, '
            '"call": {"realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w",'
            ' "agent_id": "https://a.example/a"}, '
            '"expect": {"function": "resolve_agent_binding", "outcome": "'
            + outcome
            + '", "binding": {'
            + binding
            + "}}}"
        )
        _load_body(at, body, want, f"{outcome}/{binding}")


REALM = '"realm": {"tenant_id": "t", "environment_id": "e"}'
PRIN = (
    '"principal": {"id": "p", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}'
)
OP = (
    '"operation": {"operation_id": "o", "environment_id": "e", "principal_id": "p", "action": "a",'
    ' "resources": [], "method": "GET", "target_uri": "https://x.example/", "body_digest": "",'
    ' "headers": {}}'
)
BINDING = (
    '"binding": {"agent_id": "https://a.example/a", "operator_id": "https://o.example/o",'
    ' "holder_jkt": "k"}'
)
OTHER_PRIN = (
    '"principal": {"id": "q", "realm": {"tenant_id": "t", "environment_id": "e"}, "workload": "w"}'
)
OBS = (
    '"observation": {"event_id": "e", "event_kind": "ADMISSION", "task_id": "t",'
    ' "operation_id": "o", "observed_at": 1}'
)
INTENT = '"intent": {"intent_id": "i", "purpose_id": "p", "description": "", "task_id": "t"}'
AGENT = '"agent_id": "https://a.example/a"'

CALL_ARGUMENTS: list[tuple[str, str, str, bool, str]] = [
    ("resolve_agent_binding", "unknown", REALM + ', "workload": "w", ' + AGENT, False, ""),
    ("resolve_agent_binding", "unknown", REALM + ", " + AGENT, False, "call.workload is required"),
    (
        "resolve_agent_binding",
        "unknown",
        REALM + ', "workload": "w"',
        False,
        "call.agent_id is required",
    ),
    (
        "resolve_agent_binding",
        "unknown",
        '"workload": "w", ' + AGENT,
        False,
        "call.realm is required",
    ),
    (
        "resolve_agent_binding",
        "unknown",
        REALM + ', "workload": "w", ' + AGENT + ', "native_path": "/x"',
        False,
        "not an argument",
    ),
    (
        "resolve_agent_binding",
        "unusable",
        REALM + ', "workload": "w", ' + AGENT,
        False,
        "needs expect.binding",
    ),
    ("map_operation", "error", PRIN + ', "mapping_version": "m"', True, ""),
    ("map_operation", "error", PRIN, True, "call.mapping_version is required"),
    (
        "map_operation",
        "error",
        PRIN + ', "mapping_version": "m", ' + AGENT,
        True,
        "not an argument",
    ),
    ("map_operation", "error", PRIN + ', "mapping_version": "m"', False, "needs a request"),
    ("read_native_claim", "error", PRIN + ', "native_path": "/x"', False, ""),
    ("read_native_claim", "error", PRIN + ', "native_path": "/x"', True, "takes no request"),
    ("read_native_claim", "error", PRIN + ', "native_path": "/x", ' + OP, False, ""),
    ("read_native_claim", "error", PRIN + ', "native_path": "/x", ' + INTENT, False, ""),
    (
        "read_native_claim",
        "error",
        PRIN + ', "native_path": "/x", ' + INTENT + ", " + OP,
        False,
        "",
    ),
    (
        "read_native_claim",
        "error",
        '"native_path": "/x", ' + OP,
        False,
        "call.principal is required",
    ),
    (
        "read_native_claim",
        "error",
        PRIN + ', "native_path": "/x", "evidence_refs": ["r"]',
        False,
        "not an argument",
    ),
    (
        "read_native_claim",
        "error",
        PRIN + ', "native_path": "/x", "check_id": "c"',
        False,
        "not an argument",
    ),
    ("check_context", "UNKNOWN", PRIN + ", " + OP + ', "check_id": ""', False, ""),
    ("check_context", "UNKNOWN", PRIN + ", " + OP, False, "call.check_id is required"),
    ("check_context", "UNKNOWN", '"check_id": "c", ' + OP, False, "call.principal is required"),
    ("check_context", "UNKNOWN", '"check_id": "c", ' + PRIN, False, "call.operation is required"),
    (
        "check_context",
        "UNKNOWN",
        '"check_id": "c", ' + PRIN + ", " + OP + ', "evidence_refs": ["r"]',
        False,
        "",
    ),
    (
        "check_context",
        "UNKNOWN",
        '"check_id": "c", ' + PRIN + ", " + OP + ", " + BINDING,
        False,
        "",
    ),
    (
        "check_context",
        "UNKNOWN",
        '"check_id": "c", ' + PRIN + ", " + OP + ', "binding": {' + AGENT + ', "status": "ACTIVE"}',
        False,
        "",
    ),
    (
        "check_context",
        "UNKNOWN",
        '"check_id": "c", ' + PRIN + ", " + OP + ', "binding": {' + AGENT + ', "status": "LIVE"}',
        False,
        "not a binding status",
    ),
    (
        "check_context",
        "UNKNOWN",
        '"check_id": "c", ' + OTHER_PRIN + ", " + OP,
        False,
        "is not call.operation.principal_id",
    ),
    (
        "read_native_claim",
        "error",
        PRIN + ', "native_path": "/x", ' + BINDING,
        False,
        "call.binding is not an argument",
    ),
    (
        "authorize_native",
        "DENY",
        PRIN + ", " + OP + ", " + BINDING,
        False,
        "call.binding is not an argument",
    ),
    (
        "resolve_agent_binding",
        "unknown",
        REALM + ', "workload": "w", ' + AGENT + ", " + BINDING,
        False,
        "call.binding is not an argument",
    ),
    (
        "map_operation",
        "error",
        PRIN + ', "mapping_version": "m", ' + BINDING,
        True,
        "call.binding is not an argument",
    ),
    ("authorize_native", "DENY", PRIN + ", " + OP, False, ""),
    ("authorize_native", "DENY", PRIN, False, "call.operation is required"),
    ("record_outcome", "error", OBS, False, ""),
    ("record_outcome", "error", "", False, "call.observation is required"),
]


def test_call_arguments_per_function(at: Any) -> None:
    """Each function requires its arguments and rejects the others."""
    for fn, outcome, call, request, want in CALL_ARGUMENTS:
        req = '"request": {"method": "GET", "url": "https://gateway.example/x"},' if request else ""
        members = '"call": {' + call + "}," if call else ""
        body = (
            '{"case_version": 1, "id": "T-01", "title": "t", "native_state": {}, '
            + req
            + members
            + '"expect": {"function": "'
            + fn
            + '", "outcome": "'
            + outcome
            + '"}}'
        )
        _load_body(at, body, want, f"{fn}/{want}")
