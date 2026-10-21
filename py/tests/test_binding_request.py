"""The shared decoder of JSON request objects: the binding vectors' request
(spec/v1.0/fixtures/vectors/README.md) and the adapter case files' request
(go/adapter/adaptertest/casefile.go, Request and TLSPeer).
"""

from __future__ import annotations

from typing import Any

import pytest

from hop_top_pact.core import binding, strictjson
from hop_top_pact.core.binding import RawRequest, RequestObjectError, TLSPeer
from hop_top_pact.errors import PactError


def test_vector_request() -> None:
    obj: Any = strictjson.parse(
        b'{"method":"POST","raw_request_uri":"/a?b=1",'
        b'"headers":[{"name":"Host","value":"gw.example"},{"name":"X-A","value":"1"},'
        b'{"name":"x-a","value":"2"}],"body_b64":"e30="}'
    )
    assert binding.decode_request(obj) == RawRequest(
        method="POST",
        raw_request_uri="/a?b=1",
        headers=(("Host", "gw.example"), ("X-A", "1"), ("x-a", "2")),
        body=b"{}",
    )


def test_vector_request_lists() -> None:
    # A parser that gives lists rather than tuples is read the same way.
    obj: dict[str, Any] = {
        "method": "GET",
        "raw_request_uri": "/",
        "headers": [{"name": "A", "value": "1"}],
        "body_b64": "",
    }
    assert binding.decode_request(obj).headers == (("A", "1"),)


def test_case_file_request() -> None:
    # The adapter case form: the target as url (absolute-form, kept octet for
    # octet), headers as an object in member order, tls_peer, and the members
    # the suite reads itself (native_state_ref, arrival).
    obj: Any = strictjson.parse(
        b'{"method":"GET","url":"https://gw.example/a#f","headers":{"Host":"gw.example",'
        b'"Accept":"*/*"},"native_state_ref":"alice","arrival":"direct",'
        b'"tls_peer":{"subject_cn":"svc","issuer_cn":"ca","dns_names":["svc.example"],'
        b'"uris":["spiffe://example/svc"]}}'
    )
    assert binding.decode_request(obj) == RawRequest(
        method="GET",
        raw_request_uri="https://gw.example/a#f",
        headers=(("Host", "gw.example"), ("Accept", "*/*")),
        body=b"",
        tls_peer=TLSPeer(
            subject_cn="svc",
            issuer_cn="ca",
            dns_names=("svc.example",),
            uris=("spiffe://example/svc",),
        ),
    )


def test_case_file_request_minimal() -> None:
    obj = {"method": "GET", "url": "https://gw.example/", "headers": None, "tls_peer": None}
    assert binding.decode_request(obj) == RawRequest(
        method="GET", raw_request_uri="https://gw.example/"
    )
    assert (
        binding.decode_request({"method": "GET", "url": "/", "tls_peer": {}}).tls_peer == TLSPeer()
    )


@pytest.mark.parametrize(
    "obj",
    [
        {},
        {"raw_request_uri": "/"},
        {"method": 1, "raw_request_uri": "/"},
        {"method": "GET"},
        {"method": "GET", "raw_request_uri": "/", "url": "/"},
        {"method": "GET", "raw_request_uri": 1},
        {"method": "GET", "raw_request_uri": "/", "note": "x"},
        {"method": "GET", "raw_request_uri": "/", "headers": "A: 1"},
        {"method": "GET", "raw_request_uri": "/", "headers": [{"name": "A"}]},
        {"method": "GET", "raw_request_uri": "/", "headers": [{"name": "A", "value": 1}]},
        {"method": "GET", "raw_request_uri": "/", "headers": [{"name": "A", "value": "1", "x": 1}]},
        {"method": "GET", "raw_request_uri": "/", "headers": [["A", "1"]]},
        {"method": "GET", "raw_request_uri": "/", "headers": {"A": 1}},
        {"method": "GET", "raw_request_uri": "/", "body_b64": "e30"},
        {"method": "GET", "raw_request_uri": "/", "body_b64": "e3 0="},
        {"method": "GET", "raw_request_uri": "/", "body_b64": "e3-_"},
        {"method": "GET", "raw_request_uri": "/", "body_b64": None},
        {"method": "GET", "url": "/", "tls_peer": {"subject": "x"}},
        {"method": "GET", "url": "/", "tls_peer": {"dns_names": "a"}},
        {"method": "GET", "url": "/", "tls_peer": {"uris": [1]}},
        {"method": "GET", "url": "/", "tls_peer": []},
        {"method": "GET", "url": "/", "arrival": 1},
        {"method": "GET", "url": "/", "native_state_ref": None},
    ],
)
def test_reject_malformed_request_object(obj: dict[str, Any]) -> None:
    with pytest.raises(RequestObjectError):
        binding.decode_request(obj)


def test_request_object_error_is_a_pact_error() -> None:
    assert issubclass(RequestObjectError, PactError)
    assert issubclass(RequestObjectError, ValueError)
    with pytest.raises(RequestObjectError):
        binding.decode_request([])  # type: ignore[arg-type]
