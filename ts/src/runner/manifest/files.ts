/**
 * The manifest against the fixture directory (Go runner/manifest files.go).
 *
 * @module
 */
import { type Dirent, lstatSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { basename, dirname, join, sep } from 'node:path';
import { FILE_NAME, type Manifest, SCHEMA_FILE_NAME } from './manifest.ts';
import {
  add,
  Problems,
  RULE_EXPECTED_MISSING,
  RULE_EXTENSION,
  RULE_PATH_MISSING,
  RULE_UNCOVERED,
} from './problem.ts';
import {
  baseName,
  compareCodePoints,
  extName,
  Kind,
  NATIVE_EXTENSIONS,
  NEUTRAL_EXTENSIONS,
  pathRE,
  TESTDATA_DIR,
  within,
} from './rules.ts';

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

// The fixture file rel needs no covering entry: manifest.json and
// manifest.schema.json at the top, files under testdata/ at the top, files
// named README.md, and files whose name starts with LICENSE.
function exempt(rel: string): boolean {
  if (rel === FILE_NAME || rel === SCHEMA_FILE_NAME || within(rel, TESTDATA_DIR)) return true;
  const name = baseName(rel);
  return name === 'README.md' || name.startsWith('LICENSE');
}

/**
 * Checks `m` against the fixture directory `root`:
 *
 * - every entry path exists, is not a dangling symbolic link and resolves
 *   inside root (`path-missing`);
 * - every expected file does too, and is a file (`expected-missing`);
 * - every file under root, except manifest.json, manifest.schema.json,
 *   README.md files, files whose name starts with LICENSE and the files
 *   under testdata/ at the top, is inside an entry's path, is an entry's
 *   expected file, or is under expected/<id>/ for the id of an entry
 *   (`file-uncovered`; fixture format v2);
 * - every file has a neutral extension, or a native-asset extension inside
 *   the path of an adapter-asset entry, written in lower case
 *   (`file-extension`).
 *
 * The root is resolved once: a root that is itself a symbolic link is
 * followed, as a POSIX utility follows a link named on its command line
 * (find -H). Symbolic links inside the tree are not followed. Entries whose
 * path or expected file breaks a field rule are skipped here;
 * {@link Manifest.validate} reports them.
 */
export function completeness(root: string, m: Manifest): Problems {
  const ps = new Problems();
  let realRoot: string;
  try {
    realRoot = realpathSync.native(root);
  } catch (err) {
    add(ps, RULE_PATH_MISSING, '.', `fixture directory: ${messageOf(err)}`, asError(err));
    return ps;
  }

  const paths = new Set<string>();
  const assets = new Set<string>();
  const expected = new Set<string>();
  const dirs = new Map<string, string>();
  for (const [i, e] of m.entries.entries()) {
    const where = e.id === '' ? `entries[${i}]` : e.id;
    // Format v2: every file under expected/<id>/ belongs to the entry.
    const dir = `expected/${e.id}`;
    if (e.id !== '' && pathRE.test(dir)) paths.add(dir);
    if (pathRE.test(e.path)) {
      const msg = locate(root, realRoot, e.path, dirs);
      if (msg !== '') add(ps, RULE_PATH_MISSING, where, `path ${JSON.stringify(e.path)} ${msg}`);
      paths.add(e.path);
      if (e.kind === Kind.ADAPTER_ASSET) assets.add(e.path);
    }
    if (e.expected !== null && pathRE.test(e.expected)) {
      const x = e.expected;
      let msg = locate(root, realRoot, x, dirs);
      if (msg === '') {
        const info = statSync(join(root, ...x.split('/')), { throwIfNoEntry: false });
        if (info !== undefined && !info.isFile()) msg = 'is not a file';
      }
      if (msg !== '') add(ps, RULE_EXPECTED_MISSING, where, `expected ${JSON.stringify(x)} ${msg}`);
      expected.add(x);
    }
  }

  const visit = (rel: string): void => {
    const inAsset = withinAny(rel, assets);
    const ext = extName(rel);
    if (NEUTRAL_EXTENSIONS.includes(ext)) {
      // allowed anywhere
    } else if (NATIVE_EXTENSIONS.includes(ext) && inAsset) {
      // allowed inside an adapter asset
    } else if (NATIVE_EXTENSIONS.includes(ext)) {
      add(
        ps,
        RULE_EXTENSION,
        rel,
        `extension ${ext} is allowed only inside the path of an ${Kind.ADAPTER_ASSET} entry`,
      );
    } else {
      add(
        ps,
        RULE_EXTENSION,
        rel,
        `extension ${JSON.stringify(ext)} is not language-neutral; allowed: ${NEUTRAL_EXTENSIONS.join(' ')}, and ${NATIVE_EXTENSIONS.join(' ')} inside an ${Kind.ADAPTER_ASSET} entry`,
      );
    }
    if (exempt(rel) || expected.has(rel) || withinAny(rel, paths)) return;
    add(
      ps,
      RULE_UNCOVERED,
      rel,
      "no manifest entry covers this file: add one, or put it inside an entry's path",
    );
  };
  try {
    walk(realRoot, '', visit);
  } catch (err) {
    add(ps, RULE_PATH_MISSING, '.', `walk: ${messageOf(err)}`, asError(err));
  }
  return ps;
}

// Whether rel is one of paths or lies inside one: one of its ancestors at a
// segment boundary, or rel itself, is in the set.
function withinAny(rel: string, paths: ReadonlySet<string>): boolean {
  for (let i = rel.indexOf('/'); i >= 0; i = rel.indexOf('/', i + 1)) {
    if (paths.has(rel.slice(0, i))) return true;
  }
  return paths.has(rel);
}

// Calls visit with the slash-separated path, relative to the walk's root, of
// every entry under dir that is not a directory, in lexical order (Go
// filepath.WalkDir). Symbolic links are not followed.
function walk(dir: string, prefix: string, visit: (rel: string) => void): void {
  const entries: Dirent[] = readdirSync(dir, { withFileTypes: true });
  entries.sort((a, b) => compareCodePoints(a.name, b.name));
  for (const d of entries) {
    const rel = prefix === '' ? d.name : `${prefix}/${d.name}`;
    if (d.isDirectory()) walk(join(dir, d.name), rel, visit);
    else visit(rel);
  }
}

// Why rel is not an existing path inside root, or '' when it is. realRoot
// is root with symbolic links resolved; dirs caches the resolved
// directories.
function locate(root: string, realRoot: string, rel: string, dirs: Map<string, string>): string {
  const full = join(root, ...rel.split('/'));
  let info: ReturnType<typeof lstatSync>;
  try {
    info = lstatSync(full);
  } catch {
    return 'does not exist';
  }
  let real: string;
  try {
    // A path that is not a symbolic link resolves to its resolved directory
    // and its own name.
    real = info.isSymbolicLink()
      ? realpathSync.native(full)
      : join(resolvedDir(dirname(full), dirs), basename(full));
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return 'is a dangling symbolic link';
    return `cannot be resolved: ${messageOf(err)}`;
  }
  if (!real.startsWith(realRoot + sep)) return 'resolves outside the fixture directory';
  return '';
}

function resolvedDir(dir: string, dirs: Map<string, string>): string {
  let real = dirs.get(dir);
  if (real === undefined) {
    real = realpathSync.native(dir);
    dirs.set(dir, real);
  }
  return real;
}
