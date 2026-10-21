"""A submission's transport. Port of go/runner/evalcase/transport_test.go."""

from __future__ import annotations

from typing import Any

import pytest

from hop_top_pact import conformance

VALID = "admission/valid"
PRES = '"signed":"signed/presentation.jws","jti":"v6wxT-_cB0Ua8Xkqgcuu2g"'


@pytest.mark.parametrize(
    ("body", "want"),
    [
        ("", "https"),
        ('{"presentations":[{' + PRES + "}]}", "https"),
        ('{"presentations":[{' + PRES + ',"transport":"https"}]}', "https"),
        ('{"presentations":[{' + PRES + ',"transport":"stdio-ipc"}]}', "stdio-ipc"),
    ],
)
def test_submission_transport(ec: Any, body: str, want: str) -> None:
    """A submission's transport is the transport profile the presentation arrives
    over, https or stdio-ipc, by default https (spec/v1.0/fixtures/README.md,
    exchange.json; draft 13.3.1)."""
    root = ec.case_tree(VALID)
    if body:
        ec.write_file(ec.at(root, VALID + "/exchange.json"), body)
    assert conformance.load(root, VALID).exchanges[0].submissions[0].transport == want


@pytest.mark.parametrize(
    "body",
    [
        '{"presentations":[{' + PRES + ',"transport":"http"}]}',
        '{"presentations":[{' + PRES + ',"transport":""}]}',
        '{"presentations":[{' + PRES + ',"transport":"HTTPS"}]}',
    ],
)
def test_submission_transport_rejects(ec: Any, body: str) -> None:
    root = ec.case_tree(VALID)
    ec.write_file(ec.at(root, VALID + "/exchange.json"), body)
    ec.fails(lambda: conformance.load(root, VALID), "exchange.json", "transport")


@pytest.mark.parametrize(
    ("id", "want"),
    [
        ("transport/https-contract-over-stdio-ipc", "stdio-ipc"),
        ("transport/stdio-ipc-contract-over-https", "https"),
    ],
)
def test_transport_cases(ec: Any, id: str, want: str) -> None:
    assert conformance.load(ec.repo_fixtures(), id).exchanges[0].submissions[0].transport == want
