# Q1 and Q5 (stdlib): does the Python 3.11 stdlib expose ECDSA, JSON Schema validation or RFC 3986 URI validation?
import hashlib, ssl, sys
from urllib.parse import urlsplit
keys = ("ecdsa", "ecdh", "sign", "jws", "jose", "pkcs", "crypto", "curve", "secp", "schema", "validat")
print("python", sys.version.split()[0], "| openssl", ssl.OPENSSL_VERSION)
print("stdlib modules matching:", sorted(m for m in sys.stdlib_module_names if any(k in m.lower() for k in keys)))
print("hashlib names/attrs matching:", sorted(a for a in set(hashlib.algorithms_available) | set(dir(hashlib)) if any(k in a.lower() for k in keys)))
print("ssl attrs matching:", sorted(a for a in dir(ssl) if any(k in a.lower() for k in keys)))
print("ssl.SSLContext attrs matching:", sorted(a for a in dir(ssl.SSLContext) if any(k in a.lower() for k in keys)))
for s in ("not a uri", "http://a b/c d", "urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60", "https://trust.example/issuers/finance"):
    try: print(f"urlsplit({s!r}) -> scheme={urlsplit(s).scheme!r} netloc={urlsplit(s).netloc!r}, no exception")
    except ValueError as e: print(f"urlsplit({s!r}) -> ValueError {e}")
