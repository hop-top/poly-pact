// Q1 (fixture): verify the Appendix C JWS in spec/v1.0/fixtures/parse under spec/v1.0/fixtures/keys/issuer.jwk.json with node:crypto.
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
const read = (p) => readFileSync(new URL('../../../../spec/v1.0/fixtures/' + p, import.meta.url), 'utf8');
const pub = (name) => createPublicKey({ key: JSON.parse(read(`keys/${name}.jwk.json`)), format: 'jwk' });
const [h, p, s] = read('parse/appendix-c-wrong-version.jws').trim().split('.'), sig = Buffer.from(s, 'base64url');
const ok = (key, input) => verify('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }, sig);
console.log('header:', Buffer.from(h, 'base64url').toString(), '| signature bytes:', sig.length);
console.log('verifies under issuer:', ok(pub('issuer'), `${h}.${p}`), '| under holder:', ok(pub('holder'), `${h}.${p}`));
console.log('signing input with one byte appended, under issuer:', ok(pub('issuer'), `${h}.${p}x`));
