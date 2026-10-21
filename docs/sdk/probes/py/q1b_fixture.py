# Q1 (fixture): Appendix C compact JWS verifies under issuer.jwk.json; off-curve JWK point rejected on load.
import base64, json, pathlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature as enc
u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def pub(j): return ec.EllipticCurvePublicNumbers(int.from_bytes(u(j["x"]), "big"), int.from_bytes(u(j["y"]), "big"), ec.SECP256R1()).public_key()
R = pathlib.Path(__file__).resolve().parents[4] / "spec" / "v1.0"
issuer = json.loads((R / "fixtures/keys/issuer.jwk.json").read_text())
h, p, s = (R / "fixtures/parse/appendix-c-wrong-version.jws").read_text().strip().split(".")
sig = u(s)
def check(key, msg):
    try: key.verify(enc(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), msg, ec.ECDSA(hashes.SHA256())); return True
    except InvalidSignature: return False
print("header", u(h), "sig bytes", len(sig), "verifies", check(pub(issuer), (h + "." + p).encode()), "other payload", check(pub(issuer), (h + ".e30").encode()))
bad = dict(issuer, y=json.loads((R / "fixtures/keys/holder.jwk.json").read_text())["y"])
try: pub(bad); print("off-curve point accepted")
except ValueError as e: print("off-curve point rejected:", e)
