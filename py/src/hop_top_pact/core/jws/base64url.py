"""RFC 7515 base64url: the URL-safe alphabet without padding (RFC 7515 section 2).

decode accepts only the canonical encoding of its octets. The standard
library decoders do not: urlsafe_b64decode skips newlines, and
b64decode(validate=True) and a2b_base64(strict_mode=True) accept non-zero
spare bits (``AB==``). So the four rules are checked first, then the padded
text is decoded with validate=True.
"""

from __future__ import annotations

import base64
from typing import Final

__all__ = ["decode", "encode"]

_ALPHABET: Final = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
# The 6-bit value of each character (RFC 4648 section 5, Table 2).
_VALUE: Final = {c: i for i, c in enumerate(_ALPHABET)}


def encode(b: bytes) -> str:
    """Return the unpadded base64url of b."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def decode(s: str) -> bytes:
    """Decode the canonical unpadded base64url s; raise ValueError otherwise.

    The rules, in order: only the 64 characters of the URL-safe alphabet (no
    padding, white space or line breaks); a length that is not 1 mod 4; zero
    spare bits in the last character.
    """
    for i, c in enumerate(s):
        if c not in _VALUE:
            raise ValueError(f"base64url: character {c!r} at offset {i} is not base64url")
    if len(s) % 4 == 1:
        raise ValueError(f"base64url: length {len(s)} is 1 mod 4")
    spare = {2: 0x0F, 3: 0x03}.get(len(s) % 4, 0)
    if spare and _VALUE[s[-1]] & spare:
        raise ValueError(f"base64url: non-zero spare bits in {s[-1]!r} at offset {len(s) - 1}")
    return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
