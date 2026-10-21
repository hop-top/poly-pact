/**
 * RFC 7515 base64url segments (Go go/core/jws/base64url.go): the URL-safe
 * alphabet, no padding, no line breaks, white space or other characters
 * (RFC 7515 sections 2 and 5.2), and only the canonical encoding of the
 * octets (RFC 4648 section 3.5: the spare bits of the last character are
 * zero, and the length is not 1 mod 4). `Buffer.from(s, 'base64url')` alone
 * accepts padding, spare bits, white space and the standard alphabet
 * (docs/sdk/probes/ts.md), so the alphabet is scanned first and the octets
 * must encode back to `s`.
 *
 * @module
 */

/** The octets of a canonical unpadded base64url segment; an `Error` otherwise. */
export function decodeSegment(s: string): Uint8Array {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ok =
      (c >= 0x41 && c <= 0x5a) || // A-Z
      (c >= 0x61 && c <= 0x7a) || // a-z
      (c >= 0x30 && c <= 0x39) || // 0-9
      c === 0x2d || // -
      c === 0x5f; // _
    if (!ok) {
      throw new Error(`character ${JSON.stringify(s.charAt(i))} at offset ${i} is not base64url`);
    }
  }
  const b = Buffer.from(s, 'base64url');
  if (b.toString('base64url') !== s) {
    throw new Error(
      s.length % 4 === 1
        ? `length ${s.length} is 1 mod 4`
        : 'not the canonical encoding: non-zero spare bits',
    );
  }
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}

/** The unpadded base64url text of `b`. */
export function encodeSegment(b: Uint8Array): string {
  return Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString('base64url');
}
