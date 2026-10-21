// Port of go/core/roundtrip_test.go over the Appendix B examples of
// spec/v1.0/draft.md: each example strictly decodes into its $defs shape, and
// strict decode, serialize, strict decode gives the same JSON value (the
// RFC 8785 forms of the draft text and of both re-encodings are equal).

import assert from 'node:assert/strict';
import { type TestContext, test } from 'node:test';
import { isMode, Mode } from '../src/core/enums.ts';
import { canonicalize } from '../src/core/jcs.ts';
import { type Shape, shapes } from '../src/core/shapes.ts';
import { decode, StrictJSONError } from '../src/core/strictjson.ts';
import { Digest, RawJSON } from '../src/core/values.ts';
import { encode } from '../src/internal/encode.ts';
import { str } from './support/fixtures.ts';
import { DRAFT, specText } from './support/repo.ts';

// The first json fence under the Appendix B heading "### <section> ".
function draftBlock(t: TestContext, section: string): string | undefined {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return undefined;
  const esc = section.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(
    `^### ${esc} [^\\n]*\\n(?:[^\\n#][^\\n]*\\n|\\n)*?\`\`\`json\\n([\\s\\S]*?)\\n\`\`\`\\n`,
    'm',
  );
  const m = re.exec(draft);
  assert.ok(m?.[1] !== undefined, `draft has no json block under ${section}`);
  return m[1];
}

// The JSON text src without insignificant white space.
function compact(src: string): string {
  let out = '';
  let inString = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i] as string;
    if (inString) {
      out += c;
      if (c === '\\') out += src[++i];
      else if (c === '"') inString = false;
    } else if (c === '"') {
      inString = true;
      out += c;
    } else if (!' \t\r\n'.includes(c)) out += c;
  }
  return out;
}

const jcs = (text: string) => str(canonicalize(text));

test('TestRoundTripByteStable', async (t) => {
  for (const [section, shape] of [
    ['B.3', shapes.OperationContext],
    ['B.4', shapes.RequirementContract],
  ] as const) {
    await t.test(section, (t) => {
      const src = draftBlock(t, section);
      if (src === undefined) return;
      assert.equal(encode(decode(src, shape)), compact(src));
    });
  }
});

const APPENDIX_B: readonly [string, Shape][] = [
  ['B.1', shapes.AgentProfile],
  ['B.2', shapes.Intent],
  ['B.3', shapes.OperationContext],
  ['B.4', shapes.RequirementContract],
  ['B.5', shapes.Evidence],
  ['B.6', shapes.ReputationSnapshot],
  ['B.7', shapes.AdmissionAttestation],
  ['B.8', shapes.OutcomeReport],
  ['B.9', shapes.LearningPolicy],
  ['B.10', shapes.LearningArtifact],
  ['B.11', shapes.LearningEvent],
  ['B.13', shapes.GatewayMetadata],
];

test('TestAppendixBDecodes', async (t) => {
  for (const [section, shape] of APPENDIX_B) {
    await t.test(section, (t) => {
      const src = draftBlock(t, section);
      if (src === undefined) return;
      const first = encode(decode(src, shape));
      const second = encode(decode(first, shape));
      const want = jcs(src);
      assert.equal(jcs(first), want, 're-encoded value differs from the draft');
      assert.equal(jcs(second), want, 'second round differs from the draft');
      assert.equal(second, first, 'serialization is not stable');
    });
  }
});

test('TestDraftDigestsValidate', (t) => {
  const src = draftBlock(t, 'B.4');
  if (src === undefined) return;
  const c = decode<Record<string, unknown>>(src, shapes.RequirementContract);
  for (const name of [
    'holder_jkt',
    'operation_digest',
    'intent_digest',
    'learning_policy_digest',
    'learning_artifact_digest',
  ]) {
    assert.doesNotThrow(() => Digest.validate(c[name] as string), name);
  }
  assert.equal(c.mode, Mode.ENFORCED);
  assert.ok(isMode(c.mode));
});

test('TestDuplicateKeyRejected', (t) => {
  const block = draftBlock(t, 'B.3');
  if (block === undefined) return;
  const src = block.replace(
    '"action": "invoice.read",',
    '"action": "invoice.read", "action": "invoice.write",',
  );
  assert.ok(src.includes('"invoice.write"'), 'could not build the duplicate-key input');
  assert.throws(
    () => decode(src, shapes.OperationContext),
    (err) => err instanceof StrictJSONError && err.kind === 'DUPLICATE_KEY',
  );
});

test('TestCoreIntegersAreRangeChecked', () => {
  const profile = (revision: string) =>
    `{"profile_id":"p","revision":${revision},"agent_id":"https://a.example/x","operator_id":"https://o.example/x",` +
    `"tenant_id":"t","holder_jkt":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","created_at":1,"expires_at":2,"attributes":{}}`;
  for (const ok of ['1', '0', '9007199254740991']) {
    const p = decode<{ revision: number }>(profile(ok), shapes.AgentProfile);
    assert.equal(p.revision, Number(ok));
  }
  for (const bad of ['-1', '9007199254740992', '1.5', '1e3', 'null', '"1"']) {
    assert.throws(() => decode(profile(bad), shapes.AgentProfile), StrictJSONError, bad);
  }
});

test('TestOpenMapsAcceptAdditionalMembers', () => {
  const src =
    '{"operation_id":"o","environment_id":"https://e.example/x","principal_id":"https://p.example/x","action":"a",' +
    '"resources":["https://r.example/x"],"method":"GET","target_uri":"https://t.example/x",' +
    '"body_digest":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","headers":{"x-extra":"1"},"extensions":{"https://x.example/ext":{"k":[1,2]}}}';
  type Op = { headers: Record<string, string>; extensions?: Record<string, RawJSON> };
  const op = decode<Op>(src, shapes.OperationContext);
  assert.equal(op.headers['x-extra'], '1');
  const ext = op.extensions?.['https://x.example/ext'];
  assert.ok(ext instanceof RawJSON);
  assert.equal(ext.text, '{"k":[1,2]}');
  const bare = src.replace(',"extensions":{"https://x.example/ext":{"k":[1,2]}}', '');
  const op2 = decode<Op>(bare, shapes.OperationContext);
  assert.ok(!('extensions' in op2), 'absent extensions decoded');
  assert.ok(encode(op).includes('"extensions"'));
  assert.ok(!encode(op2).includes('"extensions"'));
});
