// Q6: does `node --test` run a .ts file directly (type stripping) on the pinned Node, without vitest or a build step?
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type { Hash } from 'node:crypto';

interface Vector { input: string; sha256: string }
const vectors: Vector[] = [{ input: 'abc', sha256: 'ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0' }];

test('sha256("abc") base64url equals the FIPS 180-2 vector', () => {
  for (const v of vectors) assert.equal(createHash('sha256').update(v.input).digest('base64url'), v.sha256);
});

test('annotations, generics and `as` casts are erased at load', () => {
  const h: Hash | null = null as Hash | null;
  const id = <T,>(x: T): T => x;
  assert.equal(id<number>(h === null ? 1 : 0), 1);
  assert.equal(process.features.typescript, 'strip');
});
