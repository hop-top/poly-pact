// Port of go/core/jws/rfc7515_internal_test.go: RFC 7515 Appendix A.3,
// ES256 over P-256. The compact serialization, the public key and the R and
// S octets are copied from the RFC text.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { decodeSegment } from '../src/core/jws/base64url.ts';
import { verifyES256 } from '../src/core/jws/es256.ts';
import { publicKeyOf, Reason, StaticResolver, verify } from '../src/core/jws/index.ts';
import { wantReason } from './support/jws.ts';

const A3_COMPACT =
  'eyJhbGciOiJFUzI1NiJ9' +
  '.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ' +
  '.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
const A3_X = 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU';
const A3_Y = 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0';
const A3_R = [
  14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3, 58, 249, 124,
  126, 23, 129, 154, 195, 22, 158, 166, 101,
];
const A3_S = [
  197, 10, 7, 211, 140, 60, 112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242,
  147, 80, 154, 143, 63, 127, 138, 131, 163, 84, 213,
];
// UTF-8 of the protected header {"alg":"ES256"}.
const A3_HEADER = [123, 34, 97, 108, 103, 34, 58, 34, 69, 83, 50, 53, 54, 34, 125];

test('TestRFC7515A3', () => {
  const [h, p, s] = A3_COMPACT.split('.') as [string, string, string];
  assert.deepEqual([...decodeSegment(h)], A3_HEADER);
  const sig = decodeSegment(s);
  assert.deepEqual([...sig], [...A3_R, ...A3_S], 'signature is R || S of the RFC');
  const pub = publicKeyOf({ kty: 'EC', crv: 'P-256', x: A3_X, y: A3_Y });
  const signingInput = `${h}.${p}`;
  assert.equal(verifyES256(pub, signingInput, sig), true, 'RFC 7515 A.3 signature verifies');
  assert.equal(verifyES256(pub, `${signingInput}A`, sig), false, 'over a changed signing input');
  // A PACT verifier still rejects the JWS: its header has no typ.
  wantReason(() => verify(A3_COMPACT, new StaticResolver()), Reason.TYP_UNSUPPORTED);
});

test('decodeSegment is canonical unpadded base64url', () => {
  assert.deepEqual([...decodeSegment('')], []);
  assert.deepEqual([...decodeSegment('AQ')], [1]);
  assert.deepEqual([...decodeSegment('-_8')], [0xfb, 0xff]);
  // Node's decoder accepts each of these (docs/sdk/probes/ts.md, P6 fact 1).
  for (const s of ['AQ==', 'AQ=', 'AR', 'A Q', 'AQ\n', '+/8', 'A', 'AQ\r', 'é']) {
    assert.throws(() => decodeSegment(s), JSON.stringify(s));
  }
});
