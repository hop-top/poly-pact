"""Ed25519 public key validation and verification. Mirrors go/core/jws/ed25519point.go.

x of an OKP Ed25519 key (RFC 8037 section 2) must decode as a point of edwards25519
under RFC 8032 section 5.1.3, and be of the prime order L of the base point: a key
generated under RFC 8032 section 5.1.5 is [s]B, so a point of small order, or of
mixed order, is no generated key and binds a signature to no private key.
"""

from __future__ import annotations

from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

__all__ = ["check_ed25519_point", "verify_ed25519"]

# edwards25519 (RFC 8032 section 5.1, RFC 7748 section 4.1): p = 2^255 - 19 and
# d = -121665/121666 mod p. The curve is -x^2 + y^2 = 1 + d x^2 y^2.
_P: Final = (1 << 255) - 19
_D: Final = (-121665 * pow(121666, -1, _P)) % _P
# 2^((p-1)/4) mod p, a square root of -1.
_SQRT_M1: Final = pow(2, (_P - 1) >> 2, _P)
# (p-5)/8, the exponent of the candidate root of step 2.
_EXP: Final = (_P - 5) >> 3
# L = 2^252 + 27742317777372353535851937790883648493, the prime order of the base point.
_L: Final = (1 << 252) + 27742317777372353535851937790883648493
# 2d mod p, a constant of the addition formulas of RFC 8032 section 5.1.4.
_2D: Final = (2 * _D) % _P

_Extended = tuple[int, int, int, int]


def check_ed25519_point(b: bytes) -> None:
    """Decode the 32-octet public key b as RFC 8032 section 5.1.3 does and raise ValueError
    when decoding fails (y is p or more, there is no x for that y, or x is 0 with the sign
    bit set), when the point is of small order ([8]P is the identity), or when it is
    outside the subgroup of prime order L ([L]A is not the identity)."""
    if len(b) != 32:
        raise ValueError("not 32 octets")
    x0 = b[31] >> 7
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError(
            "not an edwards25519 point: y is not below p (RFC 8032 section 5.1.3, step 1)"
        )
    x = recover_x(y)
    if x is None:
        raise ValueError(
            "not an edwards25519 point: no x for its y (RFC 8032 section 5.1.3, step 3)"
        )
    if x == 0 and x0 == 1:
        raise ValueError(
            "not an edwards25519 point encoding: x = 0 with the sign bit set "
            "(RFC 8032 section 5.1.3, step 4)"
        )
    # Step 4 then picks x or p - x by x_0. Both points have the same order, so the order
    # checks below do not depend on the choice.
    px, py = x, y
    for _ in range(3):
        px, py = ed_add(px, py, px, py)
    if px == 0 and py == 1:
        raise ValueError(
            "an edwards25519 point of small order, which key generation never yields "
            "(RFC 8032 section 5.1.5)"
        )
    if not ed_identity(ed_mul(_L, x, y)):
        raise ValueError(
            "an edwards25519 point outside the subgroup of prime order L: [L]A is not the "
            "identity, and key generation yields only [s]B (RFC 8032 section 5.1.5)"
        )


def ed_mul(k: int, x: int, y: int) -> _Extended:
    """Return [k](x, y) by double and add with the addition formulas of RFC 8032 section
    5.1.4, which are complete, so they also double. The coordinates stay projective."""
    q: _Extended = (0, 1, 1, 0)
    pt: _Extended = (x, y, 1, x * y % _P)
    for i in range(k.bit_length() - 1, -1, -1):
        q = _add_ext(q, q)
        if (k >> i) & 1:
            q = _add_ext(q, pt)
    return q


def _add_ext(p1: _Extended, p2: _Extended) -> _Extended:
    """Add two points in extended coordinates (RFC 8032 section 5.1.4)."""
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * _2D % _P * t2 % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def ed_identity(q: _Extended) -> bool:
    """Report whether q is the neutral element (0, 1): X = 0 and Y = Z mod p."""
    return q[0] % _P == 0 and (q[1] - q[2]) % _P == 0


def recover_x(y: int) -> int | None:
    """Return a square root of (y^2 - 1) / (d y^2 + 1) mod p (RFC 8032 section 5.1.3,
    steps 2 and 3), or None when there is none."""
    yy = y * y
    u = (yy - 1) % _P
    v = (_D * yy + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P) % _P, _EXP, _P) % _P
    vxx = x * x * v % _P
    if vxx == u:
        return x
    if vxx == (-u) % _P:
        return x * _SQRT_M1 % _P
    return None


def ed_add(x1: int, y1: int, x2: int, y2: int) -> tuple[int, int]:
    """Add two points of edwards25519 in affine coordinates (RFC 8032 section 3, a = -1).
    The formulas are complete, so the denominators are never zero."""
    t = x1 * x2 * y1 * y2 * _D % _P
    nx = (x1 * y2 + x2 * y1) * pow(1 + t, -1, _P) % _P
    ny = (y1 * y2 + x1 * x2) * pow(1 - t, -1, _P) % _P
    return nx, ny


def verify_ed25519(pub: Ed25519PublicKey, signing_input: str, sig: bytes) -> bool:
    """Verify a 64-octet Ed25519 signature (RFC 8032 section 5.1.7) over the signing input."""
    if len(sig) != 64:
        return False
    try:
        pub.verify(sig, signing_input.encode("ascii"))
    except InvalidSignature:
        return False
    return True
