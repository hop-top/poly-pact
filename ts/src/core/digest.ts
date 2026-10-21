/**
 * The three digests of draft section 7.4 (Go package hop.top/pact-go/core/digest):
 * SHA-256 written as base64url without padding, a {@link Digest} of 43
 * characters.
 *
 * - {@link objectDigest} hashes the RFC 8785 form of a JSON object
 *   (`jcs.canonicalize`), so the strict checks of section 7.1 and the
 *   presentation size and depth baselines of section 20.1 apply to it;
 * - {@link artifactDigest} hashes the ASCII bytes of the exact compact JWS;
 * - {@link bytesDigest} hashes raw bytes.
 *
 * Received JSON is digested from its bytes (a `Uint8Array`, or a
 * {@link RawJSON}), never from a value decoded and re-encoded.
 *
 * @module
 */
import { createHash } from 'node:crypto';
import { encode } from '../internal/encode.ts';
import { canonicalize } from './jcs.ts';
import { type Digest, RawJSON } from './values.ts';

/** The value given to {@link objectDigest} is not a JSON object (Go `ErrNotObject`). */
export class NotObjectError extends Error {
  constructor(detail: string) {
    super(`digest: not a JSON object: ${detail}`);
    this.name = 'NotObjectError';
  }
}

function describe(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'an array';
  return `a ${typeof v}`;
}

/**
 * The object_digest of a JSON object: the digest of its RFC 8785 form.
 * `value` is the received JSON text (a `Uint8Array` or a {@link RawJSON}),
 * or an object as `strictjson` decodes it: plain objects, arrays, JSON
 * scalars, `bigint` integers and {@link RawJSON} members. Any other JSON
 * value is a {@link NotObjectError}; a text the strict parse refuses, a
 * `StrictJSONError`.
 */
export function objectDigest(value: unknown): Digest {
  let text: Uint8Array | string;
  if (value instanceof Uint8Array) text = value;
  else if (value instanceof RawJSON) text = value.text;
  else if (typeof value === 'object' && value !== null && !Array.isArray(value))
    text = encode(value);
  else throw new NotObjectError(describe(value));
  const canonical = canonicalize(text);
  // The canonical form has no white space: its first byte tells the type.
  if (canonical[0] !== 0x7b) throw new NotObjectError('the JSON text is not an object');
  return bytesDigest(canonical);
}

/**
 * The artifact_digest of a compact JWS: the digest of its ASCII bytes,
 * exactly as given. A character outside ASCII throws.
 */
export function artifactDigest(compact: string): Digest {
  for (let i = 0; i < compact.length; i++) {
    const c = compact.charCodeAt(i);
    if (c > 0x7f) {
      throw new Error(
        `digest: artifact has non-ASCII character U+${c.toString(16).toUpperCase().padStart(4, '0')} at offset ${i}`,
      );
    }
  }
  return bytesDigest(Buffer.from(compact, 'latin1'));
}

/** The digest of raw bytes. */
export function bytesDigest(bytes: Uint8Array): Digest {
  return createHash('sha256').update(bytes).digest('base64url') as Digest;
}
