// Q1: ES256 JWS with node:crypto: 64-byte r||s signature, round trip, RFC 7515 A.3 vector (public RFC test key).
import { generateKeyPairSync, createPublicKey, createPrivateKey, sign, verify } from 'node:crypto';
const P = { dsaEncoding: 'ieee-p1363' }, d = Buffer.from('abc');
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const lens = (o) => [...new Set(Array.from({ length: 2000 }, () => sign('sha256', d, { key: privateKey, ...o }).length))].sort();
const s = sign('sha256', d, { key: privateKey, ...P }), ok = (sig) => verify('sha256', d, { key: publicKey, ...P }, sig);
console.log('lengths over 2000 signs: p1363', lens(P), 'default', lens({}), 'p1363 round trip', ok(s));
console.log('DER sig read as p1363:', ok(sign('sha256', d, privateKey)), '| 63-byte:', ok(s.subarray(1)), '| 65-byte:', ok(Buffer.concat([s, d])));
const x = 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y = 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0';
const pub = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x, y }, format: 'jwk' });
const prv = createPrivateKey({ key: { kty: 'EC', crv: 'P-256', x, y, d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI' }, format: 'jwk' });
const jws = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
  + '.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
const [h, p, sg] = jws.split('.'), input = Buffer.from(`${h}.${p}`), rfc = Buffer.from(sg, 'base64url');
const v = (sig, key = pub) => verify('sha256', input, { key, ...P }, sig);
console.log('A.3 signature bytes:', rfc.length, '| verifies:', v(rfc));
const mine = sign('sha256', input, { key: prv, ...P });
console.log('own signature with A.3 d: bytes', mine.length, 'verifies', v(mine), '| equals RFC bytes', mine.equals(rfc));
rfc[0] ^= 1;
console.log('A.3 signature with one bit flipped verifies:', v(rfc));
