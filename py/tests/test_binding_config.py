"""Configuration checks. Port of go/core/binding/config_test.go."""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from hop_top_pact.core import binding
from hop_top_pact.core.binding import RawRequest, RequestError, RequestErrorKind
from hop_top_pact.errors import PactError

ORIGIN = "https://gateway.example"
GET = RawRequest(method="GET", raw_request_uri="/x", headers=(("Host", "gateway.example"),))


def config(**changes: Any) -> binding.Config:
    cfg = binding.Config(
        origin=ORIGIN,
        header_allowlist=("if-match", "x-dry-run"),
        header_normalization_id="finance-header-normalization-1",
        mapping_version="finance-http-1",
        max_body=1 << 20,
    )
    return dataclasses.replace(cfg, **changes)


MANY_63 = tuple(f"x-h{i}" for i in range(63))
MANY_64 = tuple(f"x-h{i}" for i in range(64))

VALID: list[tuple[str, dict[str, Any]]] = [
    ("appendix B", {}),
    ("no allowlist", {"header_allowlist": ()}),
    ("token characters", {"header_allowlist": ("x-a!#$%&'*+.^_`|~1",)}),
    ("63 names plus content-type", {"header_allowlist": MANY_63}),
    ("64 names with content-type", {"header_allowlist": (*MANY_63, "content-type")}),
    ("zero max_body", {"max_body": 0}),
    (
        "1024 character identifiers",
        {"mapping_version": "m" * 1024, "header_normalization_id": "n" * 1024},
    ),
    ("1024 non-ASCII characters", {"mapping_version": "\u00e9" * 1024}),
]


@pytest.mark.parametrize("changes", [v[1] for v in VALID], ids=[v[0] for v in VALID])
def test_config_valid(changes: dict[str, Any]) -> None:
    # The Appendix B configuration and its variants pass.
    cfg = config(**changes)
    cfg.validate()
    binding.from_request(cfg, GET, "p", "a", [])


ORIGINS = [
    ("empty", ""),
    ("http scheme", "http://gateway.example"),
    ("no scheme", "gateway.example"),
    ("trailing slash", "https://gateway.example/"),
    ("path", "https://gateway.example/base"),
    ("query", "https://gateway.example?x"),
    ("fragment", "https://gateway.example#f"),
    ("userinfo", "https://u@gateway.example"),
    ("non-ASCII host", "https://b\u00fccher.example"),
    ("percent-encoded host", "https://b%C3%BCcher.example"),
    ("empty host", "https://"),
    ("empty host with port", "https://:443"),
    ("space in host", "https://gate way.example"),
    ("port not a number", "https://gateway.example:abc"),
    ("port with leading zero", "https://gateway.example:0443"),
    ("port zero", "https://gateway.example:0"),
    ("port too large", "https://gateway.example:65536"),
    ("port with sign", "https://gateway.example:+443"),
    ("port with non-ASCII digit", "https://gateway.example:\u0664\u0664\u0663"),
    ("IPv6 zone", "https://[fe80::1%25en0]"),
    ("IPvFuture", "https://[v1.x]"),
    ("IPv4 in brackets", "https://[192.0.2.1]"),
    ("unclosed bracket", "https://[::1"),
    ("text after bracket", "https://[::1]x"),
]

ALLOWLISTS = [
    ("authorization", ("authorization",)),
    ("authorization any case", ("Authorization",)),
    ("cookie", ("cookie",)),
    ("set-cookie", ("set-cookie",)),
    ("pact-presentation", ("pact-presentation",)),
    ("pact-admission any case", ("PACT-Admission",)),
    ("any pact- name", ("pact-anything",)),
    ("connection", ("connection",)),
    ("keep-alive", ("keep-alive",)),
    ("te", ("te",)),
    ("transfer-encoding", ("transfer-encoding",)),
    ("upgrade", ("upgrade",)),
    ("proxy-authorization", ("proxy-authorization",)),
    ("proxy-connection", ("proxy-connection",)),
    ("any proxy- name", ("proxy-anything",)),
    ("signature", ("signature",)),
    ("signature-input", ("signature-input",)),
    ("host", ("host",)),
    ("host any case", ("Host",)),
    ("empty name", ("",)),
    ("space in name", ("x dry",)),
    ("colon in name", ("x:y",)),
    ("non-ASCII name", ("x-caf\u00e9",)),
    ("duplicate", ("x-a", "X-A")),
    ("65 names with content-type", MANY_64),
]

REJECT: list[tuple[str, dict[str, Any]]] = [
    ("empty mapping version", {"mapping_version": ""}),
    ("long mapping version", {"mapping_version": "m" * 1025}),
    ("mapping version not UTF-8", {"mapping_version": "m\udcff"}),
    ("empty header normalization id", {"header_normalization_id": ""}),
    ("long header normalization id", {"header_normalization_id": "n" * 1025}),
    ("negative max_body", {"max_body": -1}),
    *[("origin/" + n, {"origin": o}) for n, o in ORIGINS],
    *[("allowlist/" + n, {"header_allowlist": a}) for n, a in ALLOWLISTS],
]


@pytest.mark.parametrize("changes", [r[1] for r in REJECT], ids=[r[0] for r in REJECT])
def test_reject_config(changes: dict[str, Any]) -> None:
    # Each configuration rule has a failing input. from_request refuses an
    # invalid configuration as INVALID_CONFIG, not as a refused request.
    cfg = config(**changes)
    with pytest.raises(RequestError) as info:
        cfg.validate()
    assert info.value.kind is RequestErrorKind.INVALID_CONFIG, str(info.value)
    assert info.value.rule is None
    with pytest.raises(RequestError) as info:
        binding.from_request(cfg, GET, "p", "a", [])
    assert info.value.kind is RequestErrorKind.INVALID_CONFIG, str(info.value)
    assert isinstance(info.value, PactError)


def test_reject_config_non_ascii_host() -> None:
    # A non-ASCII or percent-encoded host in the origin is reported as such (RFC
    # 3986 3.2.2), not as a stray character.
    for o in ("https://b\u00fccher.example", "https://b%C3%BCcher.example"):
        with pytest.raises(RequestError, match="non-ASCII host") as info:
            config(origin=o).validate()
        assert info.value.kind is RequestErrorKind.INVALID_CONFIG
    config(origin="https://xn--bcher-kva.example").validate()


def test_request_error_kinds() -> None:
    # A refused request names a rule; the other kinds name none.
    with pytest.raises(ValueError, match="names a rule"):
        RequestError(None, "x")
    with pytest.raises(ValueError, match="names a rule"):
        RequestError(binding.Rule.METHOD, "x", RequestErrorKind.INVALID_CONFIG)
    e = RequestError(binding.Rule.METHOD, "empty method")
    assert str(e) == "binding: request refused (method): empty method"
    assert issubclass(RequestError, PactError)
    assert len(binding.Rule) == 23
