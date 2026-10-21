/**
 * The compact JSON writer of the package, the counterpart of the strict
 * decoder: it writes what `strictjson.decode` and `strictjson.parse` return.
 *
 * - `null`, booleans, strings (`JSON.stringify`), finite numbers in the
 *   RFC 8785 form and `bigint` integers as decimal literals;
 * - a {@link RawJSON} as its text without insignificant white space, as
 *   Go's encoder writes a json.RawMessage;
 * - arrays, and plain objects (prototype `Object.prototype` or `null`) with
 *   their own enumerable members in order, a member whose value is
 *   `undefined` left out.
 *
 * Anything else is a `TypeError`, a non-finite number a `RangeError`, and
 * nesting deeper than `maxDepth` (a cycle included) a `StrictJSONError` of
 * kind `DEPTH`, as the decoder would refuse it. The writer does not check
 * the limits the decoder applies to the text: a reader parses it strictly.
 *
 * @module
 */
import { DEFAULT_MAX_DEPTH, StrictJSONError } from '../core/strictjson.ts';
import { RawJSON } from '../core/values.ts';
import { numberText } from './numbers.ts';

/** The compact JSON text of `value`. */
export function encode(value: unknown, maxDepth = DEFAULT_MAX_DEPTH): string {
  const out: string[] = [];
  const path: string[] = [];
  let size = 0;
  const put = (s: string) => {
    out.push(s);
    size += s.length;
  };
  const where = () => path.map((p) => `/${p.replaceAll('~', '~0').replaceAll('/', '~1')}`).join('');
  const write = (v: unknown, depth: number): void => {
    switch (typeof v) {
      case 'string':
        put(JSON.stringify(v));
        return;
      case 'number':
        put(numberText(v));
        return;
      case 'bigint':
        put(v.toString());
        return;
      case 'boolean':
        put(v ? 'true' : 'false');
        return;
      case 'object':
        break;
      default:
        throw new TypeError(`encode: a ${typeof v} at ${where() || '/'} is not a JSON value`);
    }
    if (v === null) {
      put('null');
      return;
    }
    if (v instanceof RawJSON) {
      put(compact(v.text));
      return;
    }
    if (depth + 1 > maxDepth) {
      throw new StrictJSONError(
        'DEPTH',
        where(),
        size,
        `depth ${depth + 1} exceeds the limit of ${maxDepth}`,
      );
    }
    if (Array.isArray(v)) {
      put('[');
      for (let i = 0; i < v.length; i++) {
        if (i > 0) put(',');
        path.push(String(i));
        if (v[i] === undefined) throw new TypeError(`encode: undefined at ${where()}`);
        write(v[i], depth + 1);
        path.pop();
      }
      put(']');
      return;
    }
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) {
      const name = (proto as { constructor?: { name?: string } }).constructor?.name ?? 'object';
      throw new TypeError(`encode: a ${name} at ${where() || '/'} is not a plain object`);
    }
    put('{');
    let first = true;
    for (const key of Object.keys(v)) {
      const e = (v as Record<string, unknown>)[key];
      if (e === undefined) continue;
      if (!first) put(',');
      first = false;
      put(JSON.stringify(key));
      put(':');
      path.push(key);
      write(e, depth + 1);
      path.pop();
    }
    put('}');
  };
  write(value, 0);
  return out.join('');
}

// The JSON text t without white space outside strings.
function compact(t: string): string {
  let out = '';
  let run = 0;
  let inString = false;
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++;
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) {
      inString = true;
    } else if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
      out += t.slice(run, i);
      run = i + 1;
    }
  }
  return out + t.slice(run);
}
