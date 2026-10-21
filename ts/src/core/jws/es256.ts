/**
 * ES256 (RFC 7518 section 3.4) over `node:crypto`: ECDSA P-256 with
 * SHA-256, the signature the 64 octets R || S (`dsaEncoding:
 * 'ieee-p1363'`).
 *
 * @module
 */
import { type KeyObject, sign, verify } from 'node:crypto';

/** The order n of the P-256 base point (SEC 2 section 2.4.2). */
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_N = N >> 1n;

function int(b: Uint8Array): bigint {
  return BigInt(`0x${Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('hex')}`);
}

function octets32(n: bigint): Buffer {
  return Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
}

/**
 * Whether `sig` is a valid ES256 signature of `signingInput` under the P-256
 * public `key`. R and S outside [1, n-1] fail before the platform call. A
 * high S is accepted, as Go does: the verification equation holds for S and
 * n-S alike, and neither RFC 7518 nor the draft adds a low-S rule.
 */
export function verifyES256(key: KeyObject, signingInput: string, sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  const r = int(sig.subarray(0, 32));
  const s = int(sig.subarray(32));
  if (r === 0n || r >= N || s === 0n || s >= N) return false;
  try {
    return verify(
      'sha256',
      Buffer.from(signingInput, 'utf8'),
      { key, dsaEncoding: 'ieee-p1363' },
      sig,
    );
  } catch {
    return false;
  }
}

/**
 * The ES256 signature of `signingInput` under the P-256 private `key`. ECDSA
 * signing is randomized; S is always the low value of the pair (S, n-S), as
 * Go writes it: Node's signer writes a high S about half the time
 * (docs/sdk/probes/ts.md).
 */
export function signES256(key: KeyObject, signingInput: string): Uint8Array {
  const sig = sign('sha256', Buffer.from(signingInput, 'utf8'), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  const s = int(sig.subarray(32));
  if (s > HALF_N) octets32(N - s).copy(sig, 32);
  return new Uint8Array(sig.buffer, sig.byteOffset, sig.byteLength);
}
