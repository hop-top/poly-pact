"""Hosts of the origin (port of go/adapters/memory/fold_test.go).

Hosts are compared without regard to ASCII case only (RFC 3986 3.2.2; a
reg-name is ASCII). A Unicode lowercase maps two non-ASCII characters to ASCII
letters, U+212A KELVIN SIGN to "k" and U+0130 LATIN CAPITAL LETTER I WITH DOT
ABOVE to "i" and a combining dot, so an origin naming either is another
origin, never the ASCII one it lowercases to.
"""

from __future__ import annotations

from hop_top_pact.adapters import memory


def test_normalize_origin_fold_ascii() -> None:
    for host, ascii_origin in (
        ("pac" + chr(0x212A) + ".example", "https://pack.example"),
        (chr(0x130) + "dp.example", "https://idp.example"),
    ):
        try:
            got = memory.normalize_origin("https://" + host)
        except memory.MemoryAdapterError:
            continue
        assert got != ascii_origin, f"normalize_origin({host!r}) = the ASCII origin"
    assert memory.normalize_origin("https://PACK.Example") == "https://pack.example"
