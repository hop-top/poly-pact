/**
 * The vectors/jcs, vectors/digest, vectors/strictjson and vectors/schema
 * groups of the harness, after the Go runners of cli/pactconf
 * (vectors_core.go, vectors_schema.go) and the formats of
 * spec/v1.0/fixtures/vectors/<group>/README.md.
 *
 * @module
 */
import { StrictJSONError } from '../core/strictjson.ts';
import type { Core } from './core.ts';
import {
  base64Std,
  bytes,
  equal,
  exactMembers,
  isObject,
  messageOf,
  nullableStringOf,
  onlyMembers,
  readFixture,
  readJSON,
  rethrowStub,
  Skipped,
  type SpecDefect,
  singleFile,
  str,
  stringOf,
} from './fixture.ts';
import type { Entry } from './manifest.ts';

/**
 * vectors/jcs: an input and output pair, whose canonical form is the output
 * byte for byte, or the number list, each IEEE 754 value written as an
 * exponent literal and canonicalized.
 */
export function runJCS(root: string, e: Entry, core: Core): void {
  if (e.expected === null) throw new Error('expected is null');
  if (e.path === e.expected) {
    runJCSNumbers(root, e.path, core);
    return;
  }
  const input = readFixture(root, e.path);
  const want = readFixture(root, e.expected);
  let got: Uint8Array;
  try {
    got = core.canonicalize(input);
  } catch (err) {
    rethrowStub(err);
    throw new Error(`canonicalize the input: ${messageOf(err)}`);
  }
  if (!equal(got, want)) {
    throw new Error(
      `canonical form ${JSON.stringify(str(got))}, want ${JSON.stringify(str(want))}`,
    );
  }
  if (!equal(core.canonicalize(want), want))
    throw new Error('the expected output is not canonical');
}

/** The shortest exponent literal of an IEEE 754 double, sign of zero kept. */
function exponentLiteral(bits: bigint): string {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, bits);
  const f = view.getFloat64(0);
  return (Object.is(f, -0) ? '-' : '') + f.toExponential();
}

function runJCSNumbers(root: string, rel: string, core: Core): void {
  const vs = readJSON(root, rel);
  if (!Array.isArray(vs) || vs.length === 0) throw new Error(`${rel} has no numbers`);
  for (const [i, v] of vs.entries()) {
    const hex = isObject(v) ? v.ieee754_hex : undefined;
    const want = isObject(v) ? v.expected : undefined;
    if (
      typeof hex !== 'string' ||
      !/^[0-9A-Fa-f]{16}$/.test(hex) ||
      typeof want !== 'string' ||
      want === ''
    ) {
      throw new Error(`number ${i} is malformed`);
    }
    const literal = exponentLiteral(BigInt(`0x${hex}`));
    let got: string;
    try {
      got = str(core.canonicalize(bytes(literal)));
    } catch (err) {
      rethrowStub(err);
      throw new Error(
        `${hex}: canonicalize ${literal}: ${messageOf(err)}, want ${JSON.stringify(want)}`,
      );
    }
    if (got !== want)
      throw new Error(
        `${hex}: canonical form ${JSON.stringify(got)}, want ${JSON.stringify(want)}`,
      );
  }
}

const DIGEST_MEMBERS = [
  'appendix_value',
  'expected_digest',
  'id',
  'input',
  'input_kind',
  'spec_defect',
];

/**
 * vectors/digest: every vector's digest equals expected_digest, and a value
 * the draft prints equals it too unless the vector marks a spec defect,
 * which is skipped:spec-defect with both values.
 */
export function runDigest(root: string, e: Entry, core: Core): void {
  singleFile(e);
  const vs = readJSON(root, e.path);
  if (!Array.isArray(vs) || vs.length === 0) throw new Error(`${e.path} has no vectors`);
  const defects: SpecDefect[] = [];
  const seen = new Set<string>();
  for (const [i, raw] of vs.entries()) {
    let v: Record<string, unknown>;
    try {
      v = exactMembers(raw, ...DIGEST_MEMBERS);
    } catch (err) {
      throw new Error(`vector ${i}: ${messageOf(err)}`);
    }
    const id = v.id;
    if (typeof id !== 'string' || id === '' || seen.has(id)) {
      throw new Error(`vector ${i}: id ${JSON.stringify(id)} is empty or repeated`);
    }
    seen.add(id);
    const want = stringOf(v.expected_digest, `${id}: expected_digest`);
    const appendix = nullableStringOf(v.appendix_value, `${id}: appendix_value`);
    if (typeof v.spec_defect !== 'boolean') throw new Error(`${id}: spec_defect is not a boolean`);
    const got = computeDigest(id, v, core);
    if (got !== want) throw new Error(`${id}: digest ${got}, want expected_digest ${want}`);
    if (appendix === null) {
      if (v.spec_defect) throw new Error(`${id}: spec_defect is set but appendix_value is null`);
    } else if (appendix === got) {
      if (v.spec_defect) throw new Error(`${id}: spec_defect is set but appendix_value matches`);
    } else if (v.spec_defect) {
      defects.push({ vector: id, appendix_value: appendix, expected_digest: got });
    } else {
      throw new Error(
        `${id}: appendix_value ${appendix} differs from ${got} and spec_defect is not set`,
      );
    }
  }
  if (defects.length > 0) {
    const what = defects.map(
      (d) => `${d.vector}: the draft states ${d.appendix_value}, computed ${d.expected_digest}`,
    );
    throw new Skipped('spec-defect', `spec defect: ${what.join('; ')}`, defects);
  }
}

function computeDigest(id: string, v: Record<string, unknown>, core: Core): string {
  switch (v.input_kind) {
    case 'object':
      return core.objectDigest(v.input);
    case 'artifact':
      return core.artifactDigest(stringOf(v.input, `${id}: input`));
    case 'bytes': {
      const hex = stringOf(v.input, `${id}: input`);
      if (!/^(?:[0-9a-f]{2})*$/.test(hex))
        throw new Error(`${id}: input ${JSON.stringify(hex)} is not lowercase hex`);
      return core.bytesDigest(new Uint8Array(Buffer.from(hex, 'hex')));
    }
    default:
      throw new Error(
        `${id}: input_kind ${JSON.stringify(v.input_kind)} is not object, artifact or bytes`,
      );
  }
}

const OUTCOME_OF_EXPECT: Readonly<Record<string, string>> = {
  accept: 'ACCEPTED',
  reject: 'REJECTED',
};

/**
 * vectors/strictjson: the input is decoded as an OperationContext and
 * accepted, or refused with a StrictJSONError, as expect says.
 */
export function runStrictJSON(root: string, e: Entry, core: Core): void {
  singleFile(e);
  const v = onlyMembers(
    readJSON(root, e.path),
    'id',
    'input_text',
    'input_b64',
    'expect',
    'reason',
  );
  if (v.id !== e.id || typeof v.reason !== 'string' || v.reason === '') {
    throw new Error(
      `vector id ${JSON.stringify(v.id)} (manifest ${JSON.stringify(e.id)}) or empty reason`,
    );
  }
  const text = v.input_text === undefined ? '' : stringOf(v.input_text, 'input_text');
  const b64 = v.input_b64 === undefined ? '' : stringOf(v.input_b64, 'input_b64');
  let input: Uint8Array;
  if (text !== '' && b64 !== '') throw new Error('both input_text and input_b64 are set');
  else if (b64 !== '') input = base64Std(b64, 'input_b64');
  else if (text !== '') input = bytes(text);
  else throw new Error('no input');
  const expect = typeof v.expect === 'string' ? v.expect : '';
  const want = OUTCOME_OF_EXPECT[expect];
  if (want === undefined || want !== e.outcome) {
    throw new Error(
      `expect ${JSON.stringify(v.expect)} does not agree with outcome ${JSON.stringify(e.outcome)}`,
    );
  }
  let refusal: unknown;
  try {
    core.decodeOperationContext(input);
  } catch (err) {
    rethrowStub(err);
    refusal = err;
  }
  if (expect === 'accept' && refusal !== undefined)
    throw new Error(`rejected (${messageOf(refusal)}), want accept`);
  if (expect === 'reject') {
    if (refusal === undefined) throw new Error('accepted, want reject');
    if (!(refusal instanceof StrictJSONError)) {
      throw new Error(`refused with ${messageOf(refusal)}, not a StrictJSONError`);
    }
  }
}

/** The format each vectors/schema entry tests. */
const SCHEMA_FORMATS: Readonly<Record<string, string>> = { 'vectors/schema/uri-format': 'uri' };

const SCHEMA_MEMBERS = ['ajv_formats_differs', 'expect', 'id', 'input', 'reason'];

/**
 * vectors/schema: each string gets the vector's verdict under the shared
 * checker of the entry's format.
 */
export function runSchema(root: string, e: Entry, core: Core): void {
  singleFile(e);
  const format = SCHEMA_FORMATS[e.id];
  if (format === undefined) throw new Error(`no format for ${e.id}`);
  if (e.outcome !== 'MATCH') throw new Error(`outcome ${JSON.stringify(e.outcome)}, want MATCH`);
  const vs = readJSON(root, e.path);
  if (!Array.isArray(vs) || vs.length === 0) throw new Error(`${e.path} has no vectors`);
  const check = { uri: (s: string) => core.uriFormat(s) }[format];
  if (check === undefined) throw new Error(`no checker for format ${format}`);
  const wrong: string[] = [];
  const seen = new Set<string>();
  for (const [i, raw] of vs.entries()) {
    let v: Record<string, unknown>;
    try {
      v = exactMembers(raw, ...SCHEMA_MEMBERS);
    } catch (err) {
      throw new Error(`vector ${i}: ${messageOf(err)}`);
    }
    const id = v.id;
    if (typeof id !== 'string' || id === '' || seen.has(id)) {
      throw new Error(`vector ${i}: id ${JSON.stringify(id)} is empty or repeated`);
    }
    seen.add(id);
    if (v.expect !== 'accept' && v.expect !== 'reject') {
      throw new Error(`${id}: expect ${JSON.stringify(v.expect)}, want accept or reject`);
    }
    const got = check(stringOf(v.input, `${id}: input`)) ? 'accept' : 'reject';
    if (got !== v.expect) wrong.push(`${id}: ${got}ed, want ${v.expect}`);
  }
  if (wrong.length > 0) throw new Error(`format ${format}: ${wrong.join('; ')}`);
}
