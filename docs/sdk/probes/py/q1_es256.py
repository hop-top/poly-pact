# Q1: ES256 with cryptography: DER <-> 64-byte r||s, round trip, tamper and length rejects, RFC 7515 A.3 vector.
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature as dec, encode_dss_signature as enc
u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
A, C = ec.ECDSA(hashes.SHA256()), ec.SECP256R1()
pub = lambda x, y: ec.EllipticCurvePublicNumbers(int.from_bytes(u(x), "big"), int.from_bytes(u(y), "big"), C).public_key()
def ok(p, sig, m):
    if len(sig) != 64: return False
    try: p.verify(enc(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), m, A); return True
    except InvalidSignature: return False
k = ec.generate_private_key(C); m = b"hdr.payload"; ders = [k.sign(m, A) for _ in range(5000)]
raw = [b"".join(v.to_bytes(32, "big") for v in dec(d)) for d in ders]
print("round trip", all(ok(k.public_key(), s, m) for s in raw), "raw lens", {len(s) for s in raw}, "DER lens", sorted({len(d) for d in ders}))
print("tampered msg", ok(k.public_key(), raw[0], b"hdr.payloaX"), "63 bytes", ok(k.public_key(), raw[0][:63], m), "65 bytes", ok(k.public_key(), raw[0] + b"\0", m))
a3 = pub("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
si, sg = b"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", u("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q")
print("RFC 7515 A.3 verifies", ok(a3, sg, si), "sig bytes", len(sg), "tampered input", ok(a3, sg, si + b"x"))
