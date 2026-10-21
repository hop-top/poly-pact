/**
 * The signed directories of the fixture tree (Go hop.top/pact-go/runner/evalcase,
 * dirs.go): the case directories, or exchange directories, that hold a
 * signing.json, and the rules for the signed files under them.
 *
 * @module
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  type Entry,
  Kind,
  load as loadManifest,
  FILE_NAME as MANIFEST,
} from '../runner/manifest/index.ts';
import { decodeAs } from './decode.ts';
import { CaseError, notExist, q, wrap } from './errors.ts';
import { parseSigning, relPath, type Signing } from './signing.ts';

/** One directory the generator signs: a case directory, or an exchange directory of a multi-exchange case. */
export interface Dir {
  /** The manifest id. */
  readonly entry: string;
  /** The directory: the entry id or, for an exchange, the entry id and the exchange path. */
  readonly id: string;
  /** The directory, slash-separated, relative to the fixture directory. */
  readonly path: string;
  /** The directory's signing.json. */
  readonly signing: Signing;
}

// The manifest kinds whose case directories are signed.
const SIGNED_KINDS: readonly string[] = [Kind.EVALUATE, Kind.OUTCOMES, Kind.LEARNING];

/** The path of the slash-separated fixture path rel under root. */
export function under(root: string, rel: string): string {
  return rel === '' ? root : join(root, ...rel.split('/'));
}

/** Reports whether p is a directory. */
export function isDir(p: string): boolean {
  try {
    return statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** Reads the manifest of the fixture directory; throws a {@link CaseError}. */
export function manifestEntries(fixtures: string): readonly Entry[] {
  try {
    return loadManifest(fixtures).entries;
  } catch (err) {
    throw wrap(MANIFEST, err);
  }
}

/**
 * Walks the manifest of the fixture directory and returns, in manifest
 * order, every directory with a signing.json: the case directory of each
 * entry of kind evaluate, outcomes or learning, or each exchange directory
 * its sequence.json names. A directory that holds a signed file (a .jws
 * file) but no signing.json, or a signed file its signing.json does not
 * name, is an error. An entry whose path is not a directory is left to the
 * manifest check. Throws a {@link CaseError}.
 */
export function dirs(fixtures: string): Dir[] {
  const out: Dir[] = [];
  for (const e of manifestEntries(fixtures)) {
    if (SIGNED_KINDS.includes(e.kind)) out.push(...entryDirs(fixtures, e));
  }
  return out;
}

function entryDirs(fixtures: string, e: Entry): Dir[] {
  const dir = under(fixtures, e.path);
  if (!isDir(dir)) return []; // not a case directory: the manifest check reports it
  let seq: Sequence | undefined;
  try {
    seq = readSequence(dir);
  } catch (err) {
    throw wrap(e.id, err);
  }
  if (seq === undefined) {
    const d = loadDir(fixtures, e.id, e.id, e.path, []);
    return d === undefined ? [] : [d];
  }
  noSignedFiles(fixtures, e.path, seq.exchanges);
  const out: Dir[] = [];
  for (const x of seq.exchanges) {
    const d = loadDir(fixtures, e.id, `${e.id}/${x}`, `${e.path}/${x}`, []);
    if (d !== undefined) out.push(d);
  }
  return out;
}

/** sequence.json of a multi-exchange case. */
export interface Sequence {
  readonly exchanges: readonly string[];
  readonly subject: string;
}

/** Reads sequence.json of the case directory dir; undefined when there is none. */
export function readSequence(dir: string): Sequence | undefined {
  let b: Uint8Array;
  try {
    b = new Uint8Array(readFileSync(join(dir, 'sequence.json')));
  } catch (err) {
    if (notExist(err)) return undefined;
    throw err;
  }
  let seq: Sequence;
  try {
    seq = decodeAs<Sequence>(b, 'Sequence');
  } catch (err) {
    throw wrap('sequence.json', err);
  }
  if (seq.exchanges.length === 0) throw new CaseError('sequence.json: exchanges is empty');
  for (const x of seq.exchanges) {
    if (!relPath(x)) throw new CaseError(`sequence.json: exchange ${q(x)} is not a relative path`);
  }
  return seq;
}

/**
 * Reads signing.json of the directory rel. Undefined when there is none and
 * the directory holds no signed file outside skip.
 */
export function loadDir(
  fixtures: string,
  entry: string,
  id: string,
  rel: string,
  skip: readonly string[],
): Dir | undefined {
  let b: Uint8Array;
  try {
    b = new Uint8Array(readFileSync(join(under(fixtures, rel), 'signing.json')));
  } catch (err) {
    if (!notExist(err)) throw err;
    noSignedFiles(fixtures, rel, skip);
    return undefined;
  }
  let signing: Signing;
  try {
    signing = parseSigning(b);
  } catch (err) {
    throw wrap(`${id}/signing.json`, err);
  }
  const named = new Set([...signing.artifacts, ...signing.presentations].map((a) => a.signed));
  for (const f of signedFilesUnder(fixtures, rel, skip)) {
    if (!named.has(f)) {
      throw new CaseError(`${id}: signed file ${f} is named by no entry of signing.json`);
    }
  }
  return { entry, id, path: rel, signing };
}

/** Fails when the directory rel holds a signed file outside the subdirectories skip, since nothing names it. */
export function noSignedFiles(fixtures: string, rel: string, skip: readonly string[]): void {
  const files = signedFilesUnder(fixtures, rel, skip);
  if (files.length > 0) {
    throw new CaseError(`${rel}: holds signed files (${files.join(', ')}) but no signing.json`);
  }
}

/**
 * The .jws files under the directory rel, as paths relative to it, in
 * lexical order, leaving out the subdirectories skip. Symbolic links are
 * not followed.
 */
function signedFilesUnder(fixtures: string, rel: string, skip: readonly string[]): string[] {
  const out: string[] = [];
  const visit = (dir: string, prefix: string) => {
    const names = readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const d of names) {
      const r = prefix === '' ? d.name : `${prefix}/${d.name}`;
      if (d.isDirectory()) {
        if (!skip.includes(r)) visit(join(dir, d.name), r);
      } else if (d.name.endsWith('.jws')) {
        out.push(r);
      }
    }
  };
  visit(under(fixtures, rel), '');
  return out;
}

/** Every JSON file under dir, as slash-separated paths relative to it, in lexical order. */
export function jsonFilesUnder(dir: string): string[] {
  const out: string[] = [];
  const visit = (d: string, prefix: string) => {
    const names = readdirSync(d, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
    );
    for (const e of names) {
      const r = prefix === '' ? e.name : `${prefix}/${e.name}`;
      if (e.isDirectory()) visit(join(d, e.name), r);
      else if (e.name.endsWith('.json')) out.push(r);
    }
  };
  visit(dir, '');
  return out;
}
