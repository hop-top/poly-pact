"""config.json native_mappings[].source of the evaluation-case loader. Port of
go/runner/evalcase/source_test.go."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from hop_top_pact import conformance

VALID = "admission/valid"


def roles_source() -> dict[str, Any]:
    """A declared capability for the roles mapping of admission/valid, whose native
    claim names configured-finance-validator-v1."""
    return {
        "source_id": "configured-finance-validator-v1",
        "best_max_age_seconds": 60,
        "best_status_max_age_seconds": 30,
        "live_check": False,
        "change_feed": "poll_delta",
    }


def with_source(ec: Any, root: Path, f: Callable[[dict[str, Any]], Any]) -> None:
    """Set the source of the roles mapping of admission/valid, native_mappings[1],
    through f."""

    def edit(c: dict[str, Any]) -> None:
        c["native_mappings"][1]["source"] = f(roles_source())

    ec.edit_json(root, VALID + "/config.json", edit)


def test_native_mapping_source(ec: Any) -> None:
    """native_mappings[].source is optional, null or an object with exactly its five
    members (spec/v1.0/fixtures/README.md, config.json additions), parsed strictly."""
    c = conformance.load(ec.repo_fixtures(), VALID)
    for m in c.exchanges[0].config.native_mappings:
        assert m.source is None, f"{m.native_path}: source {m.source!r}, want none"

    root = ec.case_tree(VALID)
    with_source(ec, root, lambda src: src)
    got = conformance.load(root, VALID).exchanges[0].config.native_mappings[1].source
    assert got == conformance.NativeSource(
        source_id="configured-finance-validator-v1",
        best_max_age_seconds=60,
        best_status_max_age_seconds=30,
        live_check=False,
        change_feed="poll_delta",
    )

    root = ec.case_tree(VALID)
    with_source(ec, root, lambda src: None)
    assert conformance.load(root, VALID).exchanges[0].config.native_mappings[1].source is None


def _set(**kv: Any) -> Callable[[dict[str, Any]], Any]:
    return lambda s: s | kv


def _drop(name: str) -> Callable[[dict[str, Any]], Any]:
    return lambda s: {k: v for k, v in s.items() if k != name}


REJECTED: dict[str, tuple[Callable[[dict[str, Any]], Any], str]] = {
    "unknown member": (_set(cache_seconds=1), "config.json"),
    "no source_id": (_drop("source_id"), "source_id"),
    "empty source_id": (_set(source_id=""), "source_id"),
    "no best_max_age": (_drop("best_max_age_seconds"), "best_max_age_seconds"),
    "no best_status": (_drop("best_status_max_age_seconds"), "best_status_max_age_seconds"),
    "no live_check": (_drop("live_check"), "live_check"),
    "no change_feed": (_drop("change_feed"), "change_feed"),
    "negative bound": (_set(best_max_age_seconds=-1), "best_max_age_seconds"),
    "unknown change feed": (_set(change_feed="webhook"), "change_feed"),
    "live_check a string": (_set(live_check="false"), "config.json"),
    "no live check, bound 0": (_set(best_status_max_age_seconds=0), "at least 1"),
    "other source_id": (_set(source_id="scim-northstar"), "source_id"),
    "an array": (lambda s: [s], "config.json"),
}


@pytest.mark.parametrize(("edit", "want"), list(REJECTED.values()), ids=list(REJECTED))
def test_native_mapping_source_rejects(
    ec: Any, edit: Callable[[dict[str, Any]], Any], want: str
) -> None:
    root = ec.case_tree(VALID)
    with_source(ec, root, edit)
    ec.fails(lambda: conformance.load(root, VALID), want)


def test_native_mapping_source_live_bound_zero(ec: Any) -> None:
    """A live source may declare a status bound of zero."""
    root = ec.case_tree(VALID)
    with_source(ec, root, _set(live_check=True, best_status_max_age_seconds=0))
    conformance.load(root, VALID)


def test_gateway_algorithms(ec: Any) -> None:
    """config.json gateway.jws_algorithms has the type of GatewayMetadata.jws_algorithms
    (draft 13.1, A.3): absent for the baseline ES256 alone (draft 7.2), else one or two
    distinct algorithms out of ES256 and Ed25519."""
    fixtures = ec.repo_fixtures()
    gw = conformance.load(fixtures, VALID).exchanges[0].config.gateway
    assert gw.jws_algorithms is None
    assert tuple(gw.algorithms()) == ("ES256",)
    gw = conformance.load(fixtures, "admission/valid-ed25519").exchanges[0].config.gateway
    assert tuple(gw.algorithms()) == ("ES256", "Ed25519")

    def algs(v: Any) -> Callable[[dict[str, Any]], None]:
        return lambda c: c["gateway"].update(jws_algorithms=v)

    for v, want in (
        ([], "jws_algorithms is empty"),
        (["EdDSA"], "jws_algorithms[0]"),
        (["ES256", "none"], "jws_algorithms[1]"),
        (["ES256", "ES256"], "repeats"),
        (None, "config.json"),
    ):
        root = ec.case_tree(VALID)
        ec.edit_json(root, VALID + "/config.json", algs(v))
        ec.fails(lambda root=root: conformance.load(root, VALID), "config.json", want)
