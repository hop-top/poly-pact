"""Header names of a case request (port of go/adapter/adaptertest/fold_test.go).

Field names are ASCII and compared without regard to ASCII case only (RFC
9110 5.1). Go moves a host member into Request.Host and must not take a name
spelled with U+017F LATIN SMALL LETTER LONG S in place of the s, which
strings.EqualFold folds to "s", for it. RawRequest has no separate host: every member stays a field
line with its name as the case spells it, so no folding happens at all.
"""

from __future__ import annotations

from hop_top_pact.adapter.adaptertest import Request
from hop_top_pact.adapter.adaptertest.request import build_request

LONG_S_HOST = "Ho" + chr(0x17F) + "t"


def test_build_request_host_fold_ascii() -> None:
    req, _ = build_request(
        Request(method="GET", url="https://gw.example/x", headers={LONG_S_HOST: "other.example"})
    )
    assert list(req.headers) == [(LONG_S_HOST, "other.example")]
    assert req.raw_request_uri == "https://gw.example/x"
    req, _ = build_request(
        Request(method="GET", url="https://gw.example/x", headers={"HOST": "other.example"})
    )
    assert list(req.headers) == [("HOST", "other.example")]
