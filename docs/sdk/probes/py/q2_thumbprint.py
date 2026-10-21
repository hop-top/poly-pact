# Q2: RFC 7638 SHA-256 JWK thumbprint with stdlib only: holder fixture and the RFC 7638 section 3.1 example.
import base64, hashlib, json, pathlib
REQ = {"EC": ("crv", "kty", "x", "y"), "RSA": ("e", "kty", "n"), "OKP": ("crv", "kty", "x")}
def jkt(jwk):
    members = {k: jwk[k] for k in REQ[jwk["kty"]]}
    raw = json.dumps(members, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode("ascii")
keys = pathlib.Path(__file__).resolve().parents[4] / "spec/v1.0/fixtures/keys"
load = lambda name: json.loads((keys / name).read_text())
holder = load("holder.jwk.json")
print("holder", jkt(holder), "== expected:", jkt(holder) == "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M")
print("kid/alg/use ignored:", jkt({k: holder[k] for k in REQ["EC"]}) == jkt(holder), "| extra member ignored:", jkt(dict(holder, foo="bar")) == jkt(holder))
n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
rsa = {"kty": "RSA", "n": n, "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}
print("RFC 7638 3.1", jkt(rsa), "== expected:", jkt(rsa) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
for p in sorted(keys.glob("*.jwk.json")):
    if "private" not in p.name: print(" ", p.name, jkt(json.loads(p.read_text())))
try: jkt({"kty": "EC", "crv": "P-256", "x": "AA"})
except KeyError as e: print("missing required member y ->", type(e).__name__, e)
print("RFC 8037 A.3 Ed25519 thumbprint matches:", jkt(load("ed25519.jwk.json")) == "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k")
