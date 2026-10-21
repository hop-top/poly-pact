/**
 * The value types the wire interfaces share (Go package hop.top/pact-go/core:
 * Digest, DigestLen, Object).
 *
 * @module
 */

/** The length of a base64url SHA-256 value without padding. */
export const DIGEST_LEN = 43;

declare const digestBrand: unique symbol;

/**
 * A base64url (RFC 4648, no padding) SHA-256 value, such as an object digest
 * or a JWK thumbprint. The schema pattern is `^[A-Za-z0-9_-]{43}$`.
 */
export type Digest = string & { readonly [digestBrand]: true };

/** Operations on {@link Digest} values. */
export const Digest = Object.freeze({
  /** Throws a `TypeError` unless `d` is exactly 43 base64url characters. */
  validate(d: string): asserts d is Digest {
    if (typeof d !== 'string') throw new TypeError(`core: digest is a ${typeof d}, want a string`);
    if (d.length !== DIGEST_LEN) {
      throw new TypeError(`core: digest has ${d.length} characters, want ${DIGEST_LEN}`);
    }
    for (let i = 0; i < d.length; i++) {
      const c = d.charCodeAt(i);
      const ok =
        (c >= 0x41 && c <= 0x5a) || // A-Z
        (c >= 0x61 && c <= 0x7a) || // a-z
        (c >= 0x30 && c <= 0x39) || // 0-9
        c === 0x2d || // -
        c === 0x5f; // _
      if (!ok) {
        throw new TypeError(
          `core: digest has invalid character ${JSON.stringify(d.charAt(i))} at offset ${i}`,
        );
      }
    }
  },
});

/**
 * The text of one JSON value as received (Go `json.RawMessage`). The strict
 * decoder makes one for each `raw` member and each member of an open
 * object; the serializer writes `text` as it is.
 */
export class RawJSON {
  readonly #text: string;

  /** Wraps `text`, which must be one JSON value. */
  constructor(text: string) {
    this.#text = text;
    Object.freeze(this);
  }

  /** The JSON text of the value. */
  get text(): string {
    return this.#text;
  }
}

/**
 * An open JSON object, the `attributes` and `extensions` members, where the
 * schema allows any member. Member values stay raw so that decoding and
 * encoding do not alter them.
 */
export type PactObject = Readonly<Record<string, RawJSON>>;
