// Port of go/core/limits_test.go. The baselines below are written out from
// the second table of draft section 20.1, not derived from defaultLimits.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  artifactJSON,
  checkLimits,
  defaultLimits,
  LimitError,
  type LimitErrorKind,
  type Limits,
  presentationJSON,
  profileJSON,
  validateArtifactSize,
  validateContract,
  validateIntent,
  validateOperation,
  validatePresentation,
  validateProfileSize,
} from '../src/core/limits.ts';
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_DEPTH,
  type Limits as JSONLimits,
  parse,
  StrictJSONError,
} from '../src/core/strictjson.ts';
import type {
  Intent,
  OperationContext,
  Presentation,
  RequirementContract,
} from '../src/core/types.ts';
import { DRAFT, specText } from './support/repo.ts';

type Field = keyof Limits;

const limitFields: readonly { key: string; baseline: number; field: Field }[] = [
  { key: 'max_presentation_bytes', baseline: 262144, field: 'presentationBytes' },
  { key: 'max_artifact_payload_bytes', baseline: 32768, field: 'artifactPayloadBytes' },
  { key: 'max_profile_bytes', baseline: 32768, field: 'profileBytes' },
  { key: 'max_evidence_artifacts', baseline: 32, field: 'evidenceArtifacts' },
  { key: 'max_field_rules', baseline: 128, field: 'fieldRules' },
  { key: 'max_json_depth', baseline: 16, field: 'depth' },
  { key: 'max_resources', baseline: 256, field: 'resources' },
  { key: 'max_description_bytes', baseline: 4096, field: 'descriptionBytes' },
];

function withField(l: Limits, field: Field, value: number): Limits {
  return { ...l, [field]: value };
}

/** The error `fn` throws, or undefined when it returns. */
function thrown(fn: () => void): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return undefined;
}

function assertLimitError(err: unknown, kind: LimitErrorKind, what: string): LimitError {
  assert.ok(err instanceof LimitError, `${what}: got ${String(err)}, want a LimitError ${kind}`);
  assert.equal(err.kind, kind, `${what}: ${err.message}`);
  return err;
}

const zeroLimits: Limits = {
  presentationBytes: 0,
  artifactPayloadBytes: 0,
  profileBytes: 0,
  evidenceArtifacts: 0,
  fieldRules: 0,
  depth: 0,
  resources: 0,
  descriptionBytes: 0,
};

// The members validatePresentation reads, the rest of the object left out.
function presentation(p: {
  evidence?: number;
  resources?: number;
  description?: string;
}): Presentation {
  return {
    evidence: Array.from({ length: p.evidence ?? 0 }, () => ''),
    operation: { resources: Array.from({ length: p.resources ?? 0 }, () => '') },
    intent: { description: p.description ?? '' },
  } as unknown as Presentation;
}

function operation(resources: number): OperationContext {
  return { resources: Array.from({ length: resources }, () => '') } as unknown as OperationContext;
}

function contract(rules: number): RequirementContract {
  return {
    field_rules: Array.from({ length: rules }, () => ({})),
  } as unknown as RequirementContract;
}

function intent(description: string): Intent {
  return { description } as unknown as Intent;
}

test('TestDefaults', () => {
  const d = defaultLimits();
  for (const f of limitFields) {
    assert.equal(d[f.field], f.baseline, `defaultLimits().${f.field} (${f.key})`);
  }
  checkLimits(d);
});

// Reads the second table of section 20.1, so a change to a baseline value in
// the draft fails here.
test('TestDefaultsMatchTheDraft', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const d = defaultLimits();
  for (const f of limitFields) {
    const m = new RegExp(`^\\| \`${f.key}\` \\| (\\d+) \\|`, 'm').exec(draft);
    assert.ok(m, `draft 20.1 has no row for ${f.key}`);
    assert.equal(d[f.field], Number(m[1]), `defaultLimits().${f.field}, draft 20.1 ${f.key}`);
  }
});

test('TestCheck', async (t) => {
  for (const f of limitFields) {
    await t.test(f.key, () => {
      for (const v of [1, f.baseline - 1, f.baseline]) {
        checkLimits(withField(defaultLimits(), f.field, v));
      }
      for (const v of [f.baseline + 1, 2 * f.baseline, 0, -1]) {
        const err = thrown(() => checkLimits(withField(defaultLimits(), f.field, v)));
        const le = assertLimitError(err, 'LIMITS_INVALID', `${f.key} = ${v}`);
        assert.equal(le.key, f.key, `${f.key} = ${v}: error does not name the key`);
      }
    });
  }
  assertLimitError(
    thrown(() => checkLimits(zeroLimits)),
    'LIMITS_INVALID',
    'zero Limits',
  );
});

// How to build an object that holds exactly n units of one limited quantity
// and validate it.
const boundaries: readonly { key: string; run: (l: Limits, n: number) => void }[] = [
  { key: 'max_presentation_bytes', run: (l, n) => validatePresentation(l, presentation({}), n) },
  { key: 'max_artifact_payload_bytes', run: (l, n) => validateArtifactSize(l, n) },
  { key: 'max_profile_bytes', run: (l, n) => validateProfileSize(l, n) },
  {
    key: 'max_evidence_artifacts',
    run: (l, n) => validatePresentation(l, presentation({ evidence: n }), 0),
  },
  { key: 'max_field_rules', run: (l, n) => validateContract(l, contract(n)) },
  { key: 'max_resources', run: (l, n) => validateOperation(l, operation(n)) },
  {
    key: 'max_resources',
    run: (l, n) => validatePresentation(l, presentation({ resources: n }), 0),
  },
  { key: 'max_description_bytes', run: (l, n) => validateIntent(l, intent('a'.repeat(n))) },
  {
    key: 'max_description_bytes',
    run: (l, n) => validatePresentation(l, presentation({ description: 'a'.repeat(n) }), 0),
  },
];

function baselineOf(key: string): { baseline: number; field: Field } {
  const f = limitFields.find((x) => x.key === key);
  assert.ok(f, `no limit field for key ${key}`);
  return f;
}

test('TestBoundaries', async (t) => {
  for (const [i, b] of boundaries.entries()) {
    await t.test(`${b.key}/${i}`, () => {
      const { baseline, field } = baselineOf(b.key);
      const d = defaultLimits();

      // Equal passes, plus one fails.
      b.run(d, baseline);
      b.run(d, 0);
      const err = thrown(() => b.run(d, baseline + 1));
      const le = assertLimitError(err, 'LIMIT_EXCEEDED', `${baseline + 1}`);
      assert.deepEqual(
        { key: le.key, max: le.max, got: le.got },
        { key: b.key, max: baseline, got: baseline + 1 },
      );
      assert.ok(le.message.includes(b.key), `message ${le.message} does not name ${b.key}`);

      // A tighter configured limit moves the boundary down.
      const tight = withField(defaultLimits(), field, baseline - 1);
      b.run(tight, baseline - 1);
      assertLimitError(
        thrown(() => b.run(tight, baseline)),
        'LIMIT_EXCEEDED',
        `tightened, ${baseline}`,
      );
    });
  }
});

test('TestEachLimitIsIndependent', () => {
  // Lowering one limit must not affect the others.
  for (const f of limitFields) {
    const l = withField(defaultLimits(), f.field, 1);
    for (const b of boundaries) {
      if (b.key === f.key) continue;
      const { baseline } = baselineOf(b.key);
      const err = thrown(() => b.run(l, baseline));
      assert.equal(err, undefined, `limiting ${f.key} to 1 broke ${b.key} at ${baseline}`);
    }
  }
});

test('TestDescriptionLimitCountsBytesNotCharacters', () => {
  const d = defaultLimits();
  const tests: readonly { name: string; desc: string; ok: boolean }[] = [
    { name: '2048 two-byte characters are 4096 bytes', desc: 'é'.repeat(2048), ok: true },
    { name: '2049 two-byte characters are 4098 bytes', desc: 'é'.repeat(2049), ok: false },
    { name: '1024 four-byte characters are 4096 bytes', desc: '😀'.repeat(1024), ok: true },
    { name: '1025 four-byte characters are 4100 bytes', desc: '😀'.repeat(1025), ok: false },
    {
      name: '4095 ASCII plus one two-byte character is 4097 bytes',
      desc: `${'a'.repeat(4095)}é`,
      ok: false,
    },
    // UTF-16 code units are not bytes either: 1366 three-byte characters are
    // 1366 code units and 4098 bytes.
    { name: '1366 three-byte characters are 4098 bytes', desc: '€'.repeat(1366), ok: false },
  ];
  for (const tc of tests) {
    const err = thrown(() => validateIntent(d, intent(tc.desc)));
    if (tc.ok) assert.equal(err, undefined, `${tc.name}: ${String(err)}`);
    else assertLimitError(err, 'LIMIT_EXCEEDED', tc.name);
  }
});

test('TestValidateRejectsNil', () => {
  const d = defaultLimits();
  const cases: Record<string, () => void> = {
    presentation: () => validatePresentation(d, null, 0),
    contract: () => validateContract(d, null),
    operation: () => validateOperation(d, undefined),
    intent: () => validateIntent(d, null),
  };
  for (const [name, fn] of Object.entries(cases)) {
    assertLimitError(thrown(fn), 'NIL_OBJECT', name);
  }
});

test('TestValidateOnTheZeroLimitsFailsClosed', () => {
  assertLimitError(
    thrown(() => validateContract(zeroLimits, contract(1))),
    'LIMIT_EXCEEDED',
    'zero Limits accepted a field rule',
  );
  assertLimitError(
    thrown(() => validateArtifactSize(zeroLimits, 1)),
    'LIMIT_EXCEEDED',
    'zero Limits accepted a payload',
  );
});

// A JSON object of exactly n bytes.
function docOfSize(n: number): string {
  const overhead = '{"a":""}'.length;
  return `{"a":"${'x'.repeat(n - overhead)}"}`;
}

// A JSON document whose nesting depth is exactly d.
function docOfDepth(d: number): string {
  return `{"a":${'['.repeat(d - 1)}${']'.repeat(d - 1)}}`;
}

/** Strictly parses `input` under `lim` (Go: into an open Object) and returns the error, or undefined. */
function decodeErr(input: string, lim: JSONLimits): unknown {
  try {
    parse(input, lim);
  } catch (err) {
    return err;
  }
  return undefined;
}

function assertJSONKind(err: unknown, kind: string, what: string): void {
  assert.ok(err instanceof StrictJSONError, `${what}: got ${String(err)}, want ${kind}`);
  assert.equal(err.kind, kind, `${what}: ${err.message}`);
}

test('TestStrictJSONLimits', async (t) => {
  const forms: readonly {
    name: string;
    lim: (l: Limits) => JSONLimits;
    key: string;
    baseline: number;
  }[] = [
    {
      name: 'presentation',
      lim: presentationJSON,
      key: 'max_presentation_bytes',
      baseline: 262144,
    },
    { name: 'artifact', lim: artifactJSON, key: 'max_artifact_payload_bytes', baseline: 32768 },
    { name: 'profile', lim: profileJSON, key: 'max_profile_bytes', baseline: 32768 },
  ];
  for (const f of forms) {
    await t.test(f.name, () => {
      const lim = f.lim(defaultLimits());
      assert.deepEqual(lim, { maxBytes: f.baseline, maxDepth: 16 });
      const { field } = baselineOf(f.key);
      const tight = f.lim(withField(defaultLimits(), field, 1000));
      assert.deepEqual(tight, { maxBytes: 1000, maxDepth: 16 });

      const ok = decodeErr(docOfSize(f.baseline), lim);
      assert.equal(ok, undefined, `${f.baseline} bytes: ${String(ok)}`);
      assertJSONKind(decodeErr(docOfSize(f.baseline + 1), lim), 'SIZE', `${f.baseline + 1}`);
      assert.equal(decodeErr(docOfSize(1000), tight), undefined, 'tightened, 1000 bytes');
      assertJSONKind(decodeErr(docOfSize(1001), tight), 'SIZE', 'tightened, 1001 bytes');
    });
  }
});

test('TestStrictJSONDepthComesFromLimitsDepth', async (t) => {
  const forms: Record<string, (l: Limits) => JSONLimits> = {
    presentation: presentationJSON,
    artifact: artifactJSON,
    profile: profileJSON,
  };
  for (const [name, lim] of Object.entries(forms)) {
    await t.test(name, () => {
      const tight = withField(defaultLimits(), 'depth', 3);
      assert.equal(lim(tight).maxDepth, 3);

      const ok = decodeErr(docOfDepth(16), lim(defaultLimits()));
      assert.equal(ok, undefined, `depth 16: ${String(ok)}`);
      assertJSONKind(decodeErr(docOfDepth(17), lim(defaultLimits())), 'DEPTH', 'depth 17');
      assert.equal(decodeErr(docOfDepth(3), lim(tight)), undefined, 'Depth 3, depth 3');
      assertJSONKind(decodeErr(docOfDepth(4), lim(tight)), 'DEPTH', 'Depth 3, depth 4');
    });
  }
});

// Keeps the decoder's own defaults, used when a caller passes no limits,
// equal to the baseline.
test('TestStrictJSONDefaultsAgree', () => {
  const d = defaultLimits();
  assert.equal(DEFAULT_MAX_DEPTH, d.depth);
  assert.equal(DEFAULT_MAX_BYTES, d.presentationBytes);
});
