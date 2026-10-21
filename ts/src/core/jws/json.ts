/**
 * Strict JSON objects and the header writer of the package, the
 * counterparts of Go's strictjson.Unmarshal into a map[string]json.RawMessage
 * and of encoding/json with SetEscapeHTML(false).
 *
 * @module
 */
import type { Shape } from '../shapes.ts';
import { decode, type Limits, parse } from '../strictjson.ts';
import { RawJSON } from '../values.ts';

const NO_MEMBERS: Shape = Object.freeze({ required: [], optional: [], members: {} });

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Strictly parses `input` as a JSON object and returns its members; throws
 * a `StrictJSONError`. Any other JSON value is the error Go's map target
 * gives: `NULL` for null, `TYPE` for an array, a string, a number or a
 * boolean.
 */
export function strictObject(input: Uint8Array | string, limits?: Limits): Record<string, unknown> {
  const v = parse(input, limits);
  if (isObject(v)) return v;
  // A member-less shape refuses a value that is not an object with the
  // decoder's own error, and accepts nothing here: v is not an object.
  decode(input, NO_MEMBERS, limits);
  throw new TypeError('jws: unreachable: a non-object decoded as an object');
}

/**
 * The text of member `name` of the strict JSON object `input`, as received
 * (Go json.RawMessage). `members` are the object's members, as
 * {@link strictObject} returns them.
 */
export function rawMember(
  input: Uint8Array | string,
  limits: Limits | undefined,
  members: Readonly<Record<string, unknown>>,
  name: string,
): string {
  const names = Object.keys(members);
  const shape: Shape = {
    required: [],
    optional: names,
    members: Object.fromEntries(names.map((n) => [n, { type: 'raw' }])),
  };
  const raw = decode<Record<string, unknown>>(input, shape, limits)[name];
  if (!(raw instanceof RawJSON)) throw new TypeError(`jws: member ${name} is absent`);
  return raw.text;
}

/**
 * The JSON string of `s` as Go's encoder writes it with SetEscapeHTML(false):
 * `"` and `\` escaped, control characters as `\b`, `\f`, `\n`, `\r`, `\t`
 * or `\u00XX`, U+2028 and U+2029 escaped, `<`, `>` and `&` as they are, and
 * a lone surrogate (invalid UTF-8 in Go) as `�`.
 */
export function jsonString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        out += s.slice(i, i + 2);
        i++;
      } else {
        out += '\\ufffd';
      }
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      out += '\\ufffd';
    } else if (c === 0x2028 || c === 0x2029) {
      out += `\\u${c.toString(16)}`;
    } else if (c < 0x20 || c === 0x22 || c === 0x5c) {
      out += JSON.stringify(s.charAt(i)).slice(1, -1);
    } else {
      out += s.charAt(i);
    }
  }
  return `${out}"`;
}
