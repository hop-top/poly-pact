// Port of go/core/digest_test.go.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DIGEST_LEN, Digest } from '../src/core/values.ts';

test('TestDigestValidate', () => {
  assert.equal(DIGEST_LEN, 43);
  const valid = [
    '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU',
    'A'.repeat(43),
    '-'.repeat(43),
    '_'.repeat(43),
    '0'.repeat(43),
  ];
  for (const d of valid) {
    assert.doesNotThrow(() => Digest.validate(d), `validate(${JSON.stringify(d)})`);
  }

  const invalid: Record<string, string> = {
    empty: '',
    '42 chars': 'A'.repeat(42),
    '44 chars': 'A'.repeat(44),
    padded: `${'A'.repeat(42)}=`,
    'standard plus': `${'A'.repeat(42)}+`,
    'standard slash': `${'A'.repeat(42)}/`,
    space: `${'A'.repeat(42)} `,
    'newline suffix': `${'A'.repeat(43)}\n`,
    'newline in place': `${'A'.repeat(42)}\n`,
    'non-ascii': `${'A'.repeat(42)}é`,
    '43 bytes unicode': `${'A'.repeat(41)}é`,
    nul: `${'A'.repeat(42)}\x00`,
    'astral character': `${'A'.repeat(41)}😀`,
  };
  for (const [name, d] of Object.entries(invalid)) {
    assert.throws(() => Digest.validate(d), Error, `${name}: validate(${JSON.stringify(d)})`);
  }
  assert.throws(() => Digest.validate(42 as unknown as string), Error, 'not a string');
});
