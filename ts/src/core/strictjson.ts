/**
 * Strict JSON decoding (Go package hop.top/pact-go/core/strictjson): the checks
 * of draft section 7.1 that `JSON.parse` does not make.
 *
 * {@link parse} and {@link decode} read the input with an in-house
 * tokenizer and reject, in this order:
 *
 * - input over `maxBytes` (`SIZE`), then invalid UTF-8 (`INVALID_UTF8`);
 * - in document order: invalid JSON, empty input and text after the value
 *   (`SYNTAX`, `TRAILING_DATA`); nesting deeper than `maxDepth` (`DEPTH`,
 *   the outermost object or array has depth 1); duplicate member names,
 *   compared after unescaping, in any object (`DUPLICATE_KEY`); member names
 *   that are not an exact, case-sensitive member of the shape
 *   (`UNKNOWN_FIELD`); NaN, Infinity and literals that overflow binary64
 *   (`NON_FINITE`); integer literals outside ±(2^53-1) anywhere, and
 *   negative or non-integer numbers for an `integer` member (`INTEGER`);
 *   null for a member that cannot hold it (`NULL`);
 * - then unpaired surrogate escapes (`LONE_SURROGATE`);
 * - then a value of the wrong JSON type for its member (`TYPE`).
 *
 * The decoder checks syntax and shape. It does not apply the schema's
 * patterns, lengths, enum sets or required members; a schema validator does.
 *
 * @module
 */
import { type Member, type Shape, shapes } from './shapes.ts';
import { RawJSON } from './values.ts';

/** The largest integer a value may carry: 2^53-1 (draft section 7.1). */
export const MAX_SAFE_INTEGER = 9007199254740991;

/** The size bound of a decode without `maxBytes`: the section 20.1 presentation baseline. */
export const DEFAULT_MAX_BYTES = 262144;

/** The nesting bound of a decode without `maxDepth`: the section 20.1 baseline. */
export const DEFAULT_MAX_DEPTH = 16;

/** Size and nesting bounds of one decode; an absent, zero or negative member takes the default. */
export interface Limits {
  readonly maxBytes?: number;
  readonly maxDepth?: number;
}

/** The kinds of a strict decode failure, one per Go sentinel error. */
export type StrictJSONErrorKind =
  | 'TARGET'
  | 'SIZE'
  | 'SYNTAX'
  | 'INVALID_UTF8'
  | 'LONE_SURROGATE'
  | 'DEPTH'
  | 'DUPLICATE_KEY'
  | 'UNKNOWN_FIELD'
  | 'NON_FINITE'
  | 'INTEGER'
  | 'NULL'
  | 'TRAILING_DATA'
  | 'TYPE';

/**
 * A strict decode failure: its kind, RFC 6901 path ("" for the document
 * root), byte offset and detail. The message names the path unless it is the
 * root, as Go's `Error.Error` does.
 */
export class StrictJSONError extends Error {
  readonly kind: StrictJSONErrorKind;
  readonly path: string;
  readonly offset: number;
  readonly detail: string;

  constructor(kind: StrictJSONErrorKind, path: string, offset: number, detail: string) {
    // The root's pointer is "" (RFC 6901); "/" is the member named "".
    super(`strictjson: ${kind}${path === '' ? '' : ` at ${path}`} (offset ${offset}): ${detail}`);
    this.name = 'StrictJSONError';
    this.kind = kind;
    this.path = path;
    this.offset = offset;
    this.detail = detail;
  }
}

/**
 * Strictly decodes `input` as an object of `shape`; throws a
 * {@link StrictJSONError}. A `shape` member names an entry of `defs`, the
 * generated shapes by default. The result holds the members present in the
 * input, in input order: strings, numbers and booleans as such, `raw`
 * members and the members of `object` members as {@link RawJSON} with the
 * text as received.
 */
export function decode<T = unknown>(
  input: Uint8Array | string,
  shape: Shape,
  limits?: Limits,
  defs: Readonly<Record<string, Shape>> = shapes,
): T {
  checkShapes(shape, defs);
  return new Walker(bytesOf(input, limits), limits, defs).document(shape) as T;
}

/**
 * Strictly parses `input` as one JSON value of any shape; throws a
 * {@link StrictJSONError}. Objects are plain objects with their members in
 * input order, numbers are `number`.
 */
export function parse(input: Uint8Array | string, limits?: Limits): unknown {
  return new Walker(bytesOf(input, limits), limits, shapes).document(FREE);
}

// Targets of the walk besides a member: a free-form value, built as plain
// JSON values, and a value that is only checked (the text of a raw member,
// or a subtree under a member of another JSON type).
const FREE = 0;
const CHECK = 1;
type Target = Member | Shape | typeof FREE | typeof CHECK;

// The member type of the values of an open object.
const RAW: Member = Object.freeze({ type: 'raw' });

const utf8 = new TextEncoder();
const text = new TextDecoder('utf-8', { ignoreBOM: true });

function maxBytesOf(limits: Limits | undefined): number {
  const n = limits?.maxBytes ?? 0;
  return n > 0 ? n : DEFAULT_MAX_BYTES;
}

function sizeError(max: number): StrictJSONError {
  return new StrictJSONError('SIZE', '', max, `limit is ${max} bytes`);
}

// The input as UTF-8 bytes, after the size and encoding checks.
function bytesOf(input: Uint8Array | string, limits: Limits | undefined): Uint8Array {
  const max = maxBytesOf(limits);
  let b: Uint8Array;
  if (typeof input === 'string') {
    // Every UTF-16 code unit is at least one UTF-8 byte.
    if (input.length > max) throw sizeError(max);
    b = utf8.encode(input);
    if (b.length > max) throw sizeError(max);
    if (!input.isWellFormed()) {
      let i = 0;
      while (input.slice(0, i + 1).isWellFormed()) i++;
      throw new StrictJSONError(
        'INVALID_UTF8',
        '',
        utf8.encode(input.slice(0, i)).length,
        'unpaired surrogate code unit',
      );
    }
    return b;
  }
  if (!(input instanceof Uint8Array)) {
    throw new TypeError(`strictjson: input is ${typeof input}, want a Uint8Array or a string`);
  }
  if (input.length > max) throw sizeError(max);
  const bad = firstInvalidUTF8(input);
  if (bad >= 0) throw new StrictJSONError('INVALID_UTF8', '', bad, 'invalid UTF-8');
  return input;
}

// The offset of the first byte that does not start a valid UTF-8 sequence
// (Go utf8.Valid: no overlong forms, surrogates or values above U+10FFFF),
// or -1.
function firstInvalidUTF8(b: Uint8Array): number {
  const n = b.length;
  let i = 0;
  while (i < n) {
    const c = b[i] as number;
    if (c < 0x80) {
      i++;
      continue;
    }
    let size: number;
    let lo = 0x80;
    let hi = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) size = 2;
    else if (c >= 0xe0 && c <= 0xef) {
      size = 3;
      if (c === 0xe0) lo = 0xa0;
      else if (c === 0xed) hi = 0x9f;
    } else if (c >= 0xf0 && c <= 0xf4) {
      size = 4;
      if (c === 0xf0) lo = 0x90;
      else if (c === 0xf4) hi = 0x8f;
    } else return i;
    if (i + size > n) return i;
    const c1 = b[i + 1] as number;
    if (c1 < lo || c1 > hi) return i;
    for (let k = 2; k < size; k++) {
      const ck = b[i + k] as number;
      if (ck < 0x80 || ck > 0xbf) return i;
    }
    i += size;
  }
  return -1;
}

const MEMBER_TYPES: ReadonlySet<string> = new Set([
  'string',
  'digest',
  'enum',
  'integer',
  'number',
  'boolean',
  'raw',
  'object',
  'shape',
  'array',
  'map',
  'nullable',
]);

function targetError(detail: string): StrictJSONError {
  return new StrictJSONError('TARGET', '', 0, detail);
}

const checked = new WeakMap<object, WeakSet<object>>();

// Fails with TARGET unless shape and every shape it reaches are well formed.
function checkShapes(shape: Shape, defs: Readonly<Record<string, Shape>>): void {
  if (typeof defs !== 'object' || defs === null) throw targetError('defs is not an object');
  let done = checked.get(defs);
  if (done?.has(shape as object)) return;
  const seen = new Set<object>();
  const visitShape = (s: unknown, what: string): void => {
    if (typeof s !== 'object' || s === null || Array.isArray(s)) {
      throw targetError(`${what} is not a shape`);
    }
    if (seen.has(s)) return;
    seen.add(s);
    const members = (s as { members?: unknown }).members;
    if (typeof members !== 'object' || members === null || Array.isArray(members)) {
      throw targetError(`${what} has no members table`);
    }
    for (const [name, m] of Object.entries(members)) visitMember(m, `${what}.${name}`);
  };
  const visitMember = (m: unknown, what: string): void => {
    const type = typeof m === 'object' && m !== null ? (m as { type?: unknown }).type : undefined;
    if (typeof type !== 'string' || !MEMBER_TYPES.has(type)) {
      throw targetError(`${what} has no member type`);
    }
    const x = m as Record<string, unknown>;
    switch (type) {
      case 'enum':
        if (typeof x.name !== 'string') throw targetError(`${what} names no enum`);
        return;
      case 'shape': {
        const name = x.name;
        if (typeof name !== 'string' || !Object.hasOwn(defs, name)) {
          throw targetError(`${what} names no shape of defs: ${JSON.stringify(name)}`);
        }
        visitShape(defs[name], name);
        return;
      }
      case 'array':
        visitMember(x.items, `${what}[]`);
        return;
      case 'map':
        visitMember(x.values, `${what}{}`);
        return;
      case 'nullable':
        visitMember(x.of, what);
        return;
    }
  };
  visitShape(shape, 'shape');
  if (done === undefined) {
    done = new WeakSet();
    checked.set(defs, done);
  }
  done.add(shape as object);
}

// A JSON Pointer (RFC 6901) of path segments.
function pointer(path: readonly string[]): string {
  let p = '';
  for (const seg of path) p += `/${seg.replaceAll('~', '~0').replaceAll('/', '~1')}`;
  return p;
}

// Sets own member key of o, "__proto__" included.
function setMember(o: Record<string, unknown>, key: string, v: unknown): void {
  if (key === '__proto__') {
    Object.defineProperty(o, key, {
      value: v,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  } else {
    o[key] = v;
  }
}

function isWS(c: number | undefined): boolean {
  return c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d;
}

function isDigit(c: number | undefined): boolean {
  return c !== undefined && c >= 0x30 && c <= 0x39;
}

function hexValue(c: number | undefined): number {
  if (c === undefined) return -1;
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x61 && c <= 0x66) return c - 0x57;
  if (c >= 0x41 && c <= 0x46) return c - 0x37;
  return -1;
}

const NON_FINITE_WORDS = ['NaN', 'Infinity', '-Infinity', '+Infinity'];

const ESCAPES: Readonly<Record<number, string>> = {
  34: '"',
  92: '\\',
  47: '/',
  98: '\b',
  102: '\f',
  110: '\n',
  114: '\r',
  116: '\t',
};

function quoteByte(c: number): string {
  return c >= 0x20 && c < 0x7f
    ? `'${String.fromCharCode(c)}'`
    : `0x${c.toString(16).padStart(2, '0')}`;
}

// One pass over the input in step with the target: the checks that fail at
// once, and the first unpaired surrogate and the first type mismatch, which
// fail after the whole walk, in that order.
class Walker {
  private readonly b: Uint8Array;
  private readonly maxDepth: number;
  private readonly defs: Readonly<Record<string, Shape>>;
  private pos = 0;
  private depth = 0;
  private readonly path: string[] = [];
  private surrogate: StrictJSONError | undefined;
  private mismatch: StrictJSONError | undefined;

  constructor(b: Uint8Array, limits: Limits | undefined, defs: Readonly<Record<string, Shape>>) {
    this.b = b;
    const d = limits?.maxDepth ?? 0;
    this.maxDepth = d > 0 ? d : DEFAULT_MAX_DEPTH;
    this.defs = defs;
  }

  document(t: Target): unknown {
    this.ws();
    const scalar = this.b[this.pos] !== 0x7b && this.b[this.pos] !== 0x5b;
    const v = this.value(t);
    if (scalar && this.pos < this.b.length && !isWS(this.b[this.pos])) {
      throw this.error(
        'SYNTAX',
        `invalid character ${quoteByte(this.b[this.pos] as number)} after top-level value`,
      );
    }
    this.ws();
    if (this.pos < this.b.length) throw this.error('TRAILING_DATA', 'data after the JSON value');
    if (this.surrogate) throw this.surrogate;
    if (this.mismatch) throw this.mismatch;
    return v;
  }

  private error(kind: StrictJSONErrorKind, detail: string, at = this.pos): StrictJSONError {
    return new StrictJSONError(kind, pointer(this.path), at, detail);
  }

  // A syntax error at offset at, or NON_FINITE when the text there is NaN or
  // an infinity, which JSON does not have.
  private syntax(at: number, detail: string): StrictJSONError {
    let i = at;
    while (isWS(this.b[i])) i++;
    for (const w of NON_FINITE_WORDS) {
      let k = 0;
      while (k < w.length && this.b[i + k] === w.charCodeAt(k)) k++;
      if (k === w.length) return this.error('NON_FINITE', `${w} is not a JSON number`, i);
    }
    if (at >= this.b.length) return this.error('SYNTAX', 'unexpected end of input', at);
    return this.error('SYNTAX', detail, at);
  }

  private unexpected(what: string): StrictJSONError {
    const c = this.b[this.pos];
    return this.syntax(
      this.pos,
      c === undefined ? 'unexpected end of input' : `invalid character ${quoteByte(c)} ${what}`,
    );
  }

  private ws(): void {
    while (isWS(this.b[this.pos])) this.pos++;
  }

  private mismatched(start: number, got: string, m: Member | Shape): void {
    const want = 'members' in m ? 'object' : m.type;
    this.mismatch ??= this.error('TYPE', `${got} does not fit a ${want} member`, start);
  }

  private value(t: Target): unknown {
    this.ws();
    const start = this.pos;
    let m = t;
    let nullable = t === FREE || t === CHECK;
    while (typeof m === 'object' && 'type' in m && m.type === 'nullable') {
      nullable = true;
      m = m.of;
    }
    if (typeof m === 'object' && 'type' in m && m.type === 'raw') {
      this.value(CHECK);
      return new RawJSON(text.decode(this.b.subarray(start, this.pos)));
    }
    const c = this.b[start];
    switch (c) {
      case 0x7b:
        return this.object(m, start);
      case 0x5b:
        return this.array(m, start);
      case 0x22: {
        const s = this.string();
        if (m === FREE) return s;
        if (m === CHECK) return undefined;
        if ('type' in m && (m.type === 'string' || m.type === 'digest' || m.type === 'enum'))
          return s;
        this.mismatched(start, 'a string', m);
        return undefined;
      }
      case 0x74:
      case 0x66: {
        const v = c === 0x74;
        this.literal(v ? 'true' : 'false');
        if (m === FREE) return v;
        if (m === CHECK) return undefined;
        if ('type' in m && m.type === 'boolean') return v;
        this.mismatched(start, 'a boolean', m);
        return undefined;
      }
      case 0x6e:
        this.literal('null');
        if (!nullable) {
          const want = typeof m === 'object' && 'type' in m ? `a ${m.type} member` : 'an object';
          throw this.error('NULL', `${want} cannot hold null`, start);
        }
        return m === CHECK ? undefined : null;
      default:
        if (c === 0x2d || isDigit(c)) return this.number(m, start);
        throw this.unexpected('looking for beginning of value');
    }
  }

  private literal(word: string): void {
    for (let k = 0; k < word.length; k++) {
      if (this.b[this.pos] !== word.charCodeAt(k)) {
        throw this.unexpected(`in literal ${word}`);
      }
      this.pos++;
    }
  }

  private enter(): void {
    this.depth++;
    if (this.depth > this.maxDepth) {
      throw this.error('DEPTH', `depth ${this.depth} exceeds the limit of ${this.maxDepth}`);
    }
  }

  private object(m: Target, start: number): unknown {
    this.enter();
    this.pos++;
    // What the members are: checked against a shape, values of one type,
    // raw values, plain values, or only checked.
    let shape: Shape | undefined;
    let child: Target = CHECK;
    let out: Record<string, unknown> | undefined;
    if (m === FREE) {
      child = FREE;
      out = {};
    } else if (m !== CHECK) {
      const s: Shape | undefined =
        'members' in m ? m : m.type === 'shape' ? this.defs[m.name] : undefined;
      if (s !== undefined) {
        shape = s;
        out = {};
      } else if ('type' in m && m.type === 'map') {
        child = m.values;
        out = {};
      } else if ('type' in m && m.type === 'object') {
        child = RAW;
        out = {};
      } else {
        this.mismatched(start, 'an object', m);
      }
    }
    const seen = new Set<string>();
    this.ws();
    if (this.b[this.pos] === 0x7d) {
      this.pos++;
      this.depth--;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.b[this.pos] !== 0x22)
        throw this.unexpected('looking for beginning of object key string');
      const key = this.string();
      this.path.push(key);
      // Lone surrogates compare as U+FFFD, as Go decodes them.
      const name = key.isWellFormed() ? key : key.toWellFormed();
      if (seen.has(name)) throw this.error('DUPLICATE_KEY', JSON.stringify(key));
      seen.add(name);
      let target = child;
      if (shape !== undefined) {
        if (!Object.hasOwn(shape.members, key)) {
          throw this.error('UNKNOWN_FIELD', `${JSON.stringify(key)} is not a member of the shape`);
        }
        target = shape.members[key] as Member;
      }
      this.ws();
      if (this.b[this.pos] !== 0x3a) throw this.unexpected('after object key');
      this.pos++;
      const v = this.value(target);
      if (out !== undefined) setMember(out, key, v);
      this.path.pop();
      this.ws();
      const c = this.b[this.pos];
      if (c === 0x2c) {
        this.pos++;
        continue;
      }
      if (c === 0x7d) {
        this.pos++;
        break;
      }
      throw this.unexpected('after object key:value pair');
    }
    this.depth--;
    return out;
  }

  private array(m: Target, start: number): unknown {
    this.enter();
    this.pos++;
    let child: Target = CHECK;
    let out: unknown[] | undefined;
    if (m === FREE) {
      child = FREE;
      out = [];
    } else if (m !== CHECK) {
      if ('type' in m && m.type === 'array') {
        child = m.items;
        out = [];
      } else {
        this.mismatched(start, 'an array', m);
      }
    }
    this.ws();
    if (this.b[this.pos] === 0x5d) {
      this.pos++;
      this.depth--;
      return out;
    }
    for (let i = 0; ; i++) {
      this.path.push(String(i));
      const v = this.value(child);
      out?.push(v);
      this.path.pop();
      this.ws();
      const c = this.b[this.pos];
      if (c === 0x2c) {
        this.pos++;
        continue;
      }
      if (c === 0x5d) {
        this.pos++;
        break;
      }
      throw this.unexpected('after array element');
    }
    this.depth--;
    return out;
  }

  // The string token at pos, unescaped. The first escape of an unpaired
  // surrogate is recorded, not thrown.
  private string(): string {
    const b = this.b;
    let i = this.pos + 1;
    let s = '';
    let run = i;
    for (;;) {
      const c = b[i];
      if (c === undefined) {
        this.pos = i;
        throw this.error('SYNTAX', 'unexpected end of input');
      }
      if (c === 0x22) break;
      if (c < 0x20) {
        this.pos = i;
        throw this.error('SYNTAX', `invalid character ${quoteByte(c)} in string literal`);
      }
      if (c !== 0x5c) {
        i++;
        continue;
      }
      if (run < i) s += text.decode(b.subarray(run, i));
      const e = b[i + 1];
      const short = e === undefined ? undefined : ESCAPES[e];
      if (short !== undefined) {
        s += short;
        i += 2;
      } else if (e === 0x75) {
        const u = this.hex4(i + 2);
        if (u < 0) {
          this.pos = i;
          throw this.error('SYNTAX', 'invalid \\u escape in string literal');
        }
        if (u >= 0xdc00 && u <= 0xdfff) {
          this.surrogate ??= this.error(
            'LONE_SURROGATE',
            `low surrogate \\u${u.toString(16).padStart(4, '0')} without a high surrogate before it`,
            i,
          );
        } else if (u >= 0xd800 && u <= 0xdbff) {
          const next = b[i + 6] === 0x5c && b[i + 7] === 0x75 ? this.hex4(i + 8) : -1;
          if (next >= 0xdc00 && next <= 0xdfff) {
            // A pair: both escapes, one code point.
            s += String.fromCharCode(u, next);
            i += 12;
            run = i;
            continue;
          }
          this.surrogate ??= this.error(
            'LONE_SURROGATE',
            `high surrogate \\u${u.toString(16).padStart(4, '0')} without a low surrogate after it`,
            i,
          );
        }
        s += String.fromCharCode(u);
        i += 6;
      } else {
        this.pos = i;
        throw this.error('SYNTAX', 'invalid escape in string literal');
      }
      run = i;
    }
    if (run < i) s += text.decode(b.subarray(run, i));
    this.pos = i + 1;
    return s;
  }

  private hex4(at: number): number {
    let u = 0;
    for (let k = 0; k < 4; k++) {
      const h = hexValue(this.b[at + k]);
      if (h < 0) return -1;
      u = (u << 4) | h;
    }
    return u;
  }

  private number(m: Target, start: number): unknown {
    const b = this.b;
    let i = start;
    if (b[i] === 0x2d) i++;
    if (b[i] === 0x30) {
      i++;
    } else if (isDigit(b[i])) {
      while (isDigit(b[i])) i++;
    } else {
      this.pos = i;
      throw this.syntax(start, 'invalid number literal');
    }
    let integer = true;
    if (b[i] === 0x2e) {
      integer = false;
      i++;
      if (!isDigit(b[i])) {
        this.pos = i;
        throw this.unexpected('after decimal point in numeric literal');
      }
      while (isDigit(b[i])) i++;
    }
    if (b[i] === 0x65 || b[i] === 0x45) {
      integer = false;
      i++;
      if (b[i] === 0x2b || b[i] === 0x2d) i++;
      if (!isDigit(b[i])) {
        this.pos = i;
        throw this.unexpected('in exponent of numeric literal');
      }
      while (isDigit(b[i])) i++;
    }
    const literal = text.decode(b.subarray(start, i));
    this.pos = i;
    const intTarget = typeof m === 'object' && 'type' in m && m.type === 'integer';
    const f = Number(literal);
    if (!integer) {
      if (intTarget) throw this.error('INTEGER', `${literal} is not an integer`, start);
      if (!Number.isFinite(f))
        throw this.error('NON_FINITE', `${literal} does not fit binary64`, start);
    } else {
      // The double nearest an integer literal exceeds 2^53-1 exactly when the
      // literal does.
      if (Math.abs(f) > MAX_SAFE_INTEGER) {
        throw this.error('INTEGER', `${literal} is outside ±${MAX_SAFE_INTEGER}`, start);
      }
      if (intTarget && f < 0) throw this.error('INTEGER', `${literal} is negative`, start);
    }
    if (m === FREE) return f;
    if (m === CHECK) return undefined;
    if (intTarget) return f === 0 ? 0 : f;
    if ('type' in m && m.type === 'number') return f;
    this.mismatched(start, 'a number', m);
    return undefined;
  }
}
