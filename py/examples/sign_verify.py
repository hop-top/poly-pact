from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric import ec

from hop_top_pact.core.digest import object_digest
from hop_top_pact.core.jws import (
    TYP_REQUIREMENTS,
    Header,
    Role,
    StaticResolver,
    new_key_set,
    public_jwk,
    sign,
    verify,
)

# A requirement publisher signs a payload with its P-256 key (ES256).
key = ec.generate_private_key(ec.SECP256R1())
payload = b'{"pact_version":"0.1","jti":"contract-1"}'
compact = sign(Header(typ=TYP_REQUIREMENTS, kid="publisher-1"), payload, key)

# A gateway that trusts the publisher's public key verifies the compact JWS.
publisher = replace(public_jwk(key.public_key()), kid="publisher-1")
trusted = StaticResolver(key_sets={Role.REQUIREMENT_PUBLISHER: new_key_set(publisher)})
parsed = verify(compact, trusted)
print(parsed.role, parsed.header.kid, parsed.payload.decode())

# Object digest: unpadded base64url SHA-256 of the RFC 8785 canonical form.
print(object_digest({"jti": "contract-1", "pact_version": "0.1"}))
