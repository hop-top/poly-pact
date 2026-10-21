/**
 * The test keys of the fixture tree (Go hop.top/pact-go/runner/evalcase,
 * keys.go).
 *
 * @module
 */
import { createECDH, createPrivateKey, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { decodeSegment, encodeSegment } from '../core/jws/base64url.ts';
import { type JWK, parseJWK, publicJWK } from '../core/jws/jwk.ts';
import { ALG_ES256 } from '../core/jws/typ.ts';
import { decodeAs } from './decode.ts';
import { under } from './dirs.ts';
import { CaseError, wrap } from './errors.ts';

/** The file of the private test values, relative to the fixture directory. */
export const KEYS_FILE = 'keys/test-private-scalars.json';

/** An ES256 test key: its role, its private key, and its public JWK file, whose kid signed files carry. */
export interface Key {
  readonly role: string;
  readonly private: KeyObject;
  readonly public: JWK;
}

interface KeysFile {
  readonly keys: readonly {
    readonly role: string;
    readonly kid: string;
    readonly alg: string;
    readonly d: string;
    readonly public_jwk: string;
  }[];
}

// The P-256 private key of the 32-octet big-endian scalar d.
function privateKey(d: Uint8Array): KeyObject {
  if (d.length !== 32) throw new Error(`a P-256 private scalar has 32 octets, not ${d.length}`);
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey();
  return createPrivateKey({
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: encodeSegment(pub.subarray(1, 33)),
      y: encodeSegment(pub.subarray(33)),
      d: encodeSegment(d),
    },
    format: 'jwk',
  });
}

/**
 * Reads the ES256 test keys of {@link KEYS_FILE} under the fixture
 * directory, by role, and checks each against its public JWK file: the
 * public point and the kid must match. The Ed25519 pair is not listed.
 * Throws a {@link CaseError}, or the file system error when the file is
 * missing.
 */
export function loadKeys(fixtures: string): Map<string, Key> {
  const file = KEYS_FILE;
  const b = new Uint8Array(readFileSync(under(fixtures, file)));
  let scalars: KeysFile;
  try {
    scalars = decodeAs<KeysFile>(b, 'KeysFile');
  } catch (err) {
    throw wrap(file, err);
  }
  const out = new Map<string, Key>();
  for (const k of scalars.keys) {
    if (k.alg !== ALG_ES256) continue; // the Ed25519 pair is not an ES256 key
    let d: Uint8Array;
    try {
      d = decodeSegment(k.d);
    } catch (err) {
      throw wrap(`${file}: role ${k.role}: d`, err);
    }
    let priv: KeyObject;
    let pb: Uint8Array;
    try {
      priv = privateKey(d);
      pb = new Uint8Array(readFileSync(under(under(fixtures, 'keys'), k.public_jwk)));
    } catch (err) {
      throw wrap(`${file}: role ${k.role}`, err);
    }
    let jwk: JWK;
    try {
      jwk = parseJWK(pb);
    } catch (err) {
      throw wrap(`keys/${k.public_jwk}`, err);
    }
    const own = publicJWK(priv);
    if (own.x !== jwk.x || own.y !== jwk.y || jwk.kid !== k.kid) {
      throw new CaseError(
        `keys/${k.public_jwk} is not the public key of role ${k.role} (kid ${k.kid})`,
      );
    }
    out.set(k.role, { role: k.role, private: priv, public: jwk });
  }
  return out;
}
