"""The schema module's format checker: format uri per RFC 3986.

The vectors are spec/v1.0/fixtures/vectors/schema/uri-format.json of the source
repository (fails when absent under PACT_REQUIRE_VECTORS=1, skips
otherwise); their verdicts come from the RFC 3986 grammar.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from hop_top_pact.core import schema

VECTORS = Path(__file__).resolve().parents[2] / "spec" / "v1.0" / "fixtures" / "vectors" / "schema"


def uri_vectors() -> list[dict[str, Any]]:
    path = VECTORS / "uri-format.json"
    if not path.exists():
        if os.environ.get("PACT_REQUIRE_VECTORS") == "1":
            pytest.fail(f"{path} absent under PACT_REQUIRE_VECTORS=1")
        pytest.skip("no spec/ tree (mirror checkout)")
    rows: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    return rows


def validator() -> Any:
    return Draft202012Validator(
        {"type": "string", "format": "uri"}, format_checker=schema.format_checker()
    )


def test_uri_vectors() -> None:
    v = validator()
    rows = uri_vectors()
    assert len(rows) >= 50
    wrong = [
        r["id"] for r in rows if ("accept" if v.is_valid(r["input"]) else "reject") != r["expect"]
    ]
    assert wrong == []


def test_uri_expression_is_the_shared_one() -> None:
    readme = (VECTORS / "README.md").read_text(encoding="utf-8") if VECTORS.exists() else None
    if readme is None:
        uri_vectors()  # fails or skips as the vectors do
        return
    start = readme.index("```text\n") + len("```text\n")
    shared = readme[start : readme.index("\n```", start)]
    assert shared == schema.URI_EXPRESSION


def test_only_uri_is_checked() -> None:
    checker = schema.format_checker()
    assert set(checker.checkers) == {"uri"}
    # Other formats are annotations only.
    v = Draft202012Validator(
        {"type": "string", "format": "email"}, format_checker=schema.format_checker()
    )
    assert v.is_valid("not an email")


def test_uri_matches_the_whole_string() -> None:
    v = validator()
    assert v.is_valid("https://example.com/a")
    assert not v.is_valid("https://example.com/a\n")
    assert not v.is_valid("x https://example.com/a")
    assert v.is_valid("https:")


def test_uri_format_ignores_non_strings() -> None:
    v = Draft202012Validator({"format": "uri"}, format_checker=schema.format_checker())
    assert v.is_valid(5)
    assert v.is_valid(None)


def test_format_checker_is_fresh() -> None:
    a, b = schema.format_checker(), schema.format_checker()
    assert a is not b
