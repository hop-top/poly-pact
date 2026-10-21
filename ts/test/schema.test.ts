// The schema module, an SDK extra (docs/sdk/parity-ledger.md, SDK extras):
// the shared RFC 3986 `uri` matcher against spec/v1.0/fixtures/vectors/schema,
// checked against ajv-formats 3.0.1 as published (development oracle), and
// definition validation over the vendored schema with the matcher
// registered (spec/v1.0/fixtures/schema/README.md, steps 3 and 4).

import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import Ajv2020Mod from 'ajv/dist/2020.js';
import addFormatsMod from 'ajv-formats';
import { SchemaError, uriFormat, validate } from '../src/core/schema.ts';
import { StrictJSONError } from '../src/core/strictjson.ts';
import { URI_PATTERN } from '../src/core/uri.ts';
import { fixturesPresent, manifestEntries, readFixtureJSON } from './support/fixtures.ts';
import { REPO, specText } from './support/repo.ts';

const Ajv2020 = Ajv2020Mod.default;
const addFormats = addFormatsMod.default;

interface UriVector {
  id: string;
  input: string;
  expect: 'accept' | 'reject';
  reason: string;
  ajv_formats_differs: boolean;
}

function uriVectors(): UriVector[] {
  const e = manifestEntries('vectors/schema/').find((x) => x.id === 'vectors/schema/uri-format');
  assert.ok(e, 'manifest lacks vectors/schema/uri-format');
  assert.equal(e.outcome, 'MATCH');
  const vs = readFixtureJSON(e.path) as UriVector[];
  assert.ok(Array.isArray(vs) && vs.length > 0);
  return vs;
}

test('the uri matcher gives every vector its verdict', (t) => {
  if (!fixturesPresent(t)) return;
  const wrong = uriVectors()
    .filter((v) => (uriFormat(v.input) ? 'accept' : 'reject') !== v.expect)
    .map((v) => `${v.id}: ${JSON.stringify(v.input)} want ${v.expect}`);
  assert.deepEqual(wrong, []);
});

// The README of the vectors: the matcher and ajv-formats 3.0.1 as published
// disagree on exactly the rows marked ajv_formats_differs.
test('the uri matcher agrees with ajv-formats except on the marked rows', (t) => {
  if (!fixturesPresent(t)) return;
  const ajv = new Ajv2020({ strict: true });
  addFormats(ajv, ['uri']);
  const oracle = ajv.compile({ type: 'string', format: 'uri' });
  const vs = uriVectors();
  const wrong = vs
    .filter((v) => (uriFormat(v.input) === oracle(v.input)) === v.ajv_formats_differs)
    .map((v) => `${v.id}: matcher ${uriFormat(v.input)}, ajv-formats ${oracle(v.input)}`);
  assert.deepEqual(wrong, []);
  assert.equal(vs.filter((v) => v.ajv_formats_differs).length, 3);
});

test('the registered uri format is the matcher, in definition validation', (t) => {
  if (!fixturesPresent(t)) return;
  const problem = (type: string) =>
    JSON.stringify({ type, title: 't', status: 400, code: 'c', request_id: 'r' });
  const wrong: string[] = [];
  for (const v of uriVectors()) {
    if (v.input.length < 1 || v.input.length > 1024) continue; // Problem.type length bounds
    let verdict = 'accept';
    try {
      validate('Problem', problem(v.input));
    } catch (err) {
      assert.ok(err instanceof SchemaError, String(err));
      verdict = 'reject';
    }
    if (verdict !== v.expect) wrong.push(`${v.id}: ${verdict}ed, want ${v.expect}`);
  }
  assert.deepEqual(wrong, []);
});

test('the uri expression is the one of the vectors README', (t) => {
  const readme = specText(
    t,
    join(REPO, 'spec', 'v1.0', 'fixtures', 'vectors', 'schema', 'README.md'),
  );
  if (readme === undefined) return;
  const m = /```text\n(\^.*?\$)\n```/s.exec(readme);
  assert.ok(m?.[1] !== undefined, 'README has no expression block');
  assert.equal(URI_PATTERN.source, m[1]);
  assert.equal(URI_PATTERN.flags, '');
});

test('uriFormat matches the whole string, ASCII only', () => {
  for (const s of ['https://example.com/', 'https:', 'urn:x', 'https://[::1]:8080/a?b#c']) {
    assert.equal(uriFormat(s), true, s);
  }
  for (const s of [
    '',
    'https://example.com/\n',
    'x https://example.com/',
    'https://example.com/a b',
    'https://example.com/K',
    'https://example.com:8١/',
    '//example.com/',
  ]) {
    assert.equal(uriFormat(s), false, JSON.stringify(s));
  }
});

const ACK = { request_id: 'r-1', status: 'ACCEPTED', artifact_id: 'a-1', received_at: 1 };

test('validate returns the strictly parsed document of a valid object', () => {
  assert.deepEqual(validate('Acknowledgment', JSON.stringify(ACK)), ACK);
  assert.deepEqual(validate('Acknowledgment', new TextEncoder().encode(JSON.stringify(ACK))), ACK);
});

test('validate refuses a schema failure with every issue', () => {
  const err = (() => {
    try {
      validate('Acknowledgment', JSON.stringify({ ...ACK, status: 'OK', bogus: 1 }));
    } catch (e) {
      return e;
    }
    return undefined;
  })();
  assert.ok(err instanceof SchemaError, String(err));
  assert.equal(err.def, 'Acknowledgment');
  const keywords = err.issues.map((i) => i.keyword).sort();
  assert.deepEqual(keywords, ['additionalProperties', 'enum']);
  assert.ok(err.issues.some((i) => i.instancePath === '/status'));
});

test('validate applies the strict parse first', () => {
  for (const [input, kind] of [
    ['{"request_id":"r","request_id":"s"}', 'DUPLICATE_KEY'],
    [JSON.stringify({ ...ACK, received_at: 2 ** 53 }), 'INTEGER'],
    ['{"a":NaN}', 'NON_FINITE'],
  ] as const) {
    assert.throws(
      () => validate('Acknowledgment', input),
      (e) => e instanceof StrictJSONError && e.kind === kind,
      input,
    );
  }
  assert.throws(
    () => validate('Acknowledgment', '{}', { maxBytes: 1 }),
    (e) => e instanceof StrictJSONError && e.kind === 'SIZE',
  );
});

test('validate refuses a name that is not a $defs entry', () => {
  for (const name of ['', 'Nope', 'GatewayEndpoints', '__proto__', '#']) {
    assert.throws(() => validate(name, '{}'), RangeError, name);
  }
});

// spec/v1.0/fixtures/schema/README.md, definition selection: typ of draft 7.3.
const DEF_OF_TYP: Readonly<Record<string, string>> = {
  'pact-requirements+jwt': 'RequirementContract',
  'pact-evidence+jwt': 'Evidence',
  'pact-presentation+jwt': 'Presentation',
  'pact-admission+jwt': 'AdmissionAttestation',
  'pact-outcome+jwt': 'OutcomeReport',
  'pact-reputation+jwt': 'ReputationSnapshot',
  'pact-learning-policy+jwt': 'LearningPolicy',
  'pact-learning-artifact+jwt': 'LearningArtifact',
  'pact-learning-event+jwt': 'LearningEvent',
};

test('every Appendix B object validates against its definition', (t) => {
  if (!fixturesPresent(t)) return;
  const list = readFixtureJSON('schema/appendix-b-valid.json') as {
    objects: { section: string; typ?: string; def?: string; object: unknown }[];
  };
  assert.equal(list.objects.length, 12);
  for (const o of list.objects) {
    const def = o.def ?? DEF_OF_TYP[o.typ ?? ''];
    assert.ok(def !== undefined, `${o.section}: no definition`);
    validate(def, JSON.stringify(o.object));
  }
});
