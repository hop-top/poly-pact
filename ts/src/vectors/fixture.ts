/**
 * Fixture reading and checks shared by the vector groups of the harness.
 * A group runner returns on a pass, throws {@link Skipped} on a skip and
 * any other error on a failure.
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { NotImplementedError } from '../internal/notimplemented.ts';
import type { Entry } from './manifest.ts';

/** A digest the draft prints that differs from the one its algorithm gives. */
export interface SpecDefect {
  readonly vector: string;
  readonly appendix_value: string;
  readonly expected_digest: string;
}

/** A skipped result: its reason of the result grammar and what the line carries. */
export class Skipped extends Error {
  readonly reason: 'out-of-scope' | 'spec-defect' | 'capability';
  readonly specDefects: readonly SpecDefect[];

  constructor(
    reason: 'out-of-scope' | 'spec-defect' | 'capability',
    message: string,
    specDefects: readonly SpecDefect[] = [],
  ) {
    super(message);
    this.name = 'Skipped';
    this.reason = reason;
    this.specDefects = specDefects;
  }
}

/**
 * Rethrows a {@link NotImplementedError}, so that a stub never counts as the
 * refusal a vector expects. Call it first in every catch that inspects an
 * error of the module under test.
 */
export function rethrowStub(err: unknown): void {
  if (err instanceof NotImplementedError) throw err;
}

/** The message of a thrown value. */
export function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

const utf8 = new TextEncoder();
const text = new TextDecoder();

export function bytes(s: string): Uint8Array {
  return utf8.encode(s);
}

export function str(b: Uint8Array): string {
  return text.decode(b);
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

export function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Whether p is a slash-separated relative path with no empty, "." or ".." segment. */
export function localPath(p: string): boolean {
  if (p === '' || p.startsWith('/') || p.includes('\\')) return false;
  return p.split('/').every((s) => s !== '' && s !== '.' && s !== '..');
}

/** The bytes of a fixture file named relative to the fixture directory root. */
export function readFixture(root: string, rel: string): Uint8Array {
  if (!localPath(rel))
    throw new Error(`path ${JSON.stringify(rel)} is not inside the fixture directory`);
  return readFileSync(join(root, ...rel.split('/')));
}

/** A fixture file parsed as JSON. */
export function readJSON(root: string, rel: string): unknown {
  const b = readFixture(root, rel);
  try {
    return JSON.parse(str(b));
  } catch (err) {
    throw new Error(`${rel}: ${messageOf(err)}`);
  }
}

/** Checks that an entry names one JSON file that holds its own expectations. */
export function singleFile(e: Entry): void {
  if (!e.path.endsWith('.json') || e.expected !== e.path) {
    throw new Error(
      `path ${JSON.stringify(e.path)} and expected ${JSON.stringify(e.expected)} must name the same JSON file`,
    );
  }
}

/** Checks that v is an object whose members are exactly want. */
export function exactMembers(v: unknown, ...want: string[]): Record<string, unknown> {
  if (!isObject(v)) throw new Error('not a JSON object');
  const got = Object.keys(v).sort();
  const w = [...want].sort();
  if (got.join() !== w.join())
    throw new Error(`members ${JSON.stringify(got)}, want exactly ${JSON.stringify(w)}`);
  return v;
}

/** Checks that v is an object with no member outside allowed. */
export function onlyMembers(v: unknown, ...allowed: string[]): Record<string, unknown> {
  if (!isObject(v)) throw new Error('not a JSON object');
  const extra = Object.keys(v).filter((k) => !allowed.includes(k));
  if (extra.length > 0) throw new Error(`unknown members ${JSON.stringify(extra)}`);
  return v;
}

export function stringOf(v: unknown, name: string): string {
  if (typeof v !== 'string') throw new Error(`${name} is not a string`);
  return v;
}

export function nullableStringOf(v: unknown, name: string): string | null {
  if (v !== null && typeof v !== 'string') throw new Error(`${name} is neither a string nor null`);
  return v;
}

export function stringsOf(v: unknown, name: string): string[] {
  if (!Array.isArray(v) || !v.every((s) => typeof s === 'string')) {
    throw new Error(`${name} is not an array of strings`);
  }
  return v;
}

/** Decodes canonical padded base64 (RFC 4648 section 4), as Go StdEncoding does. */
export function base64Std(s: string, name: string): Uint8Array {
  const b = Buffer.from(s, 'base64');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || b.toString('base64') !== s) {
    throw new Error(`${name} is not canonical base64`);
  }
  return new Uint8Array(b);
}

/** Decodes canonical unpadded base64url (RFC 4648 section 5). */
export function base64URL(s: string, name: string): Uint8Array {
  const b = Buffer.from(s, 'base64url');
  if (!/^[A-Za-z0-9_-]*$/.test(s) || b.toString('base64url') !== s) {
    throw new Error(`${name} is not canonical base64url`);
  }
  return new Uint8Array(b);
}
