// Q2: JWK import/export member sets and RFC 7638 thumbprints (RFC 7638 3.1 RSA example, spec/v1.0/fixtures/keys).
import { createPublicKey, createHash, generateKeyPairSync } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
const REQ = { EC: ['crv', 'kty', 'x', 'y'], RSA: ['e', 'kty', 'n'], OKP: ['crv', 'kty', 'x'] }; // RFC 7638 3.2, sorted
const jkt = (j) => createHash('sha256').update(JSON.stringify(Object.fromEntries(REQ[j.kty].map((k) => [k, j[k]])))).digest('base64url');
const exp = (j) => createPublicKey({ key: j, format: 'jwk' }).export({ format: 'jwk' });
const dir = new URL('../../../../spec/v1.0/fixtures/keys/', import.meta.url);
const rsa = { kty: 'RSA', n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw', e: 'AQAB', alg: 'RS256', kid: '2011-04-29' };
console.log('RFC 7638 3.1 RSA', Object.keys(rsa).join(), '| exported', Object.keys(exp(rsa)).join(), '|', jkt(rsa), '| known:', jkt(rsa) === 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
for (const f of readdirSync(dir).filter((f) => f.endsWith('.jwk.json')).sort()) {
  const j = JSON.parse(readFileSync(new URL(f, dir)));
  const want = { 'holder.jwk.json': 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M', 'ed25519.jwk.json': 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k' }[f]; // draft Appendix C, RFC 8037 A.3
  console.log(f.padEnd(30), Object.keys(j).join(), '| exported', Object.keys(exp(j)).join(), '|', jkt(j), '| known:', want ? jkt(j) === want : 'n/a', '| same from export:', jkt(j) === jkt(exp(j)));
}
let lead = 0, bad = 0; // does export pad x/y to 32 bytes when a coordinate starts with 0x00? (RFC 7518 6.2.1.2)
for (let i = 0; i < 4000; i++) {
  const j = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
  for (const b of [j.x, j.y].map((c) => Buffer.from(c, 'base64url'))) { lead += b[0] === 0; bad += b.length !== 32; }
}
console.log('4000 generated keys: coordinates with leading 0x00:', lead, '| coordinates not 32 bytes:', bad);
