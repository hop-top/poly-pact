// Helpers of the vectors harness tests: scratch fixture trees, manifest
// entries and fake cores. Not a test file (the test glob is *.test.ts).

import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { JWK } from '../../src/core/jws/index.ts';
import { NotImplementedError } from '../../src/internal/notimplemented.ts';
import { type Core, defaultCore } from '../../src/vectors/core.ts';
import type { Entry } from '../../src/vectors/manifest.ts';

const roots: string[] = [];

/** Removes every tree made by {@link tree}; call it from an after hook. */
export function cleanup(): void {
  for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
}

/**
 * Writes files under a new scratch fixture directory and returns it. A string
 * or Uint8Array is written as is, anything else as indented JSON.
 */
export function tree(files: Readonly<Record<string, unknown>>): string {
  const root = mkdtempSync(join(tmpdir(), 'pact-vectors-tree-'));
  roots.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const p = join(root, ...rel.split('/'));
    mkdirSync(dirname(p), { recursive: true });
    const data =
      typeof content === 'string' || content instanceof Uint8Array
        ? content
        : `${JSON.stringify(content, null, 2)}\n`;
    writeFileSync(p, data);
  }
  return root;
}

/** A manifest entry; expected defaults to path, as for a single-file vector. */
export function entry(
  id: string,
  kind: string,
  scope: string,
  path: string,
  more: Partial<Entry> = {},
): Entry {
  return {
    id,
    kind,
    scope,
    path,
    expected: path,
    outcome: 'ACCEPTED',
    capabilities: [],
    ...more,
  };
}

/**
 * A core whose every function is a stub of a module not ported: it throws
 * {@link NotImplementedError}, as each module did before its port.
 */
export const stubbed: Core = Object.fromEntries(
  Object.keys(defaultCore).map((k) => [
    k,
    () => {
      throw new NotImplementedError(`vectors.${k}`);
    },
  ]),
) as unknown as Core;

/** The stubbed core with some functions replaced. */
export function fake(overrides: Partial<Core>): Core {
  return { ...stubbed, ...overrides };
}

/** Thrown by {@link poisoned}: a core function was called. */
export class Called extends Error {}

/** A core whose every function throws {@link Called}. */
export const poisoned: Core = Object.fromEntries(
  Object.keys(defaultCore).map((k) => [
    k,
    () => {
      throw new Called(k);
    },
  ]),
) as unknown as Core;

const utf8 = new TextEncoder();
const text = new TextDecoder();

export function bytes(s: string): Uint8Array {
  return utf8.encode(s);
}

export function str(b: Uint8Array): string {
  return text.decode(b);
}

function sorted(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sorted);
  if (typeof v === 'object' && v !== null) {
    const o = v as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(o)
        .sort()
        .map((k) => [k, sorted(o[k])]),
    );
  }
  return v;
}

/** A toy canonicalizer, enough for the small inputs of these tests. */
export function toyCanonicalize(input: Uint8Array): Uint8Array {
  return bytes(JSON.stringify(sorted(JSON.parse(str(input)))));
}

/** RFC 7638 thumbprint of a P-256 JWK, written out independently of the SDK. */
export function rfc7638(jwk: JWK): string {
  const members = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y ?? ''}"}`;
  return createHash('sha256').update(members).digest('base64url');
}
