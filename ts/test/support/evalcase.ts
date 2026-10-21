// Helpers of the conformance case-loader tests, ported from
// go/runner/evalcase/helpers_test.go: copies of the committed fixture tree
// and the edits the tests make to them. Not a test file (the test glob is
// *.test.ts).

import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { TestContext } from 'node:test';
import { canonicalize } from '../../src/core/jcs.ts';
import { decodeSegment, encodeSegment } from '../../src/core/jws/base64url.ts';
import { FIXTURES } from './fixtures.ts';

/** spec/v1.0/fixtures of the source repository. */
export const REPO_FIXTURES = FIXTURES;

/** The path of the slash-separated fixture path rel under root. */
export function at(root: string, rel: string): string {
  return join(root, ...rel.split('/'));
}

export function readFile(path: string): Uint8Array {
  return new Uint8Array(readFileSync(path));
}

export function writeFile(path: string, data: Uint8Array | string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, data);
}

export function removeFile(path: string): void {
  rmSync(path);
}

/**
 * Copies the files under the fixture paths rels (files or directories,
 * slash-separated) into a fresh directory, removed after the test, and
 * returns it.
 */
export function copyTree(t: TestContext, ...rels: string[]): string {
  const root = mkdtempSync(join(tmpdir(), 'pact-evalcase-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const rel of rels) cpSync(at(REPO_FIXTURES, rel), at(root, rel), { recursive: true });
  return root;
}

/** Copies the manifest, the test keys, and the case and expected directories of the ids. */
export function caseTree(t: TestContext, ...ids: string[]): string {
  const rels = ['manifest.json', 'keys'];
  for (const id of ids) rels.push(id, `expected/${id}`);
  return copyTree(t, ...rels);
}

function count(s: string, sub: string): number {
  return s.split(sub).length - 1;
}

/** Replaces old by repl, once, in the file rel of the tree root. */
export function edit(root: string, rel: string, old: string, repl: string): void {
  const p = at(root, rel);
  const s = readFileSync(p, 'utf8');
  const n = count(s, old);
  assert.equal(n, 1, `${rel} holds ${JSON.stringify(old)} ${n} times, want once`);
  writeFile(p, s.replace(old, repl));
}

/** A JSON object as the tests edit it. */
// biome-ignore lint/suspicious/noExplicitAny: the edits reach into arbitrary JSON
export type JSONObject = Record<string, any>;

/**
 * Rewrites the JSON file rel of the tree root through f, in RFC 8785
 * canonical form. The manifest is no signed artifact and outgrows the input
 * limit of jcs; it is written as encoded.
 */
export function editJSON(root: string, rel: string, f: (v: JSONObject) => void): void {
  const p = at(root, rel);
  const v = JSON.parse(readFileSync(p, 'utf8')) as JSONObject;
  f(v);
  const text = JSON.stringify(v);
  writeFile(p, rel === 'manifest.json' ? text : canonicalize(text));
}

/** Changes one octet of the signature of the compact JWS file rel of the tree root. */
export function flipSignature(root: string, rel: string): void {
  const p = at(root, rel);
  const seg = readFileSync(p, 'utf8').split('.');
  const sig = decodeSegment(seg[2] ?? '');
  sig[10] = (sig[10] ?? 0) ^ 0x01;
  seg[2] = encodeSegment(sig);
  writeFile(p, seg.join('.'));
}

/** Asserts that f throws an error whose message mentions every part. */
export function wantThrows(f: () => unknown, ...parts: string[]): void {
  let err: unknown;
  try {
    f();
  } catch (e) {
    err = e;
  }
  assert.ok(err !== undefined, `no error, want one mentioning ${JSON.stringify(parts)}`);
  const msg = err instanceof Error ? err.message : String(err);
  for (const s of parts) {
    assert.ok(
      msg.includes(s),
      `error ${JSON.stringify(msg)}, want one mentioning ${JSON.stringify(s)}`,
    );
  }
}

const text = new TextDecoder();

/** The members of a JSON object payload. */
export function payloadOf(b: Uint8Array): JSONObject {
  return JSON.parse(text.decode(b)) as JSONObject;
}
