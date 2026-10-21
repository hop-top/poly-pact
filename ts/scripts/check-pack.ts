/**
 * Checks the file list of the npm package (`npm pack --dry-run --json`) after
 * a build: only dist/**, schema/pact.schema.json, README.md, LICENSE and
 * package.json, and every target of the exports map among them.
 *
 * @module
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const FIXED = ['LICENSE', 'README.md', 'package.json', 'schema/pact.schema.json'];

interface PackResult {
  readonly files: readonly { readonly path: string }[];
}

function exportTargets(exports: unknown): string[] {
  if (typeof exports === 'string') return [exports.replace(/^\.\//, '')];
  if (typeof exports !== 'object' || exports === null) return [];
  return Object.values(exports).flatMap(exportTargets);
}

function main(): number {
  const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: ROOT,
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  const [result] = JSON.parse(out) as PackResult[];
  if (result === undefined) throw new Error('npm pack printed no result');
  const files = new Set(result.files.map((f) => f.path));
  const problems: string[] = [];
  for (const f of files) {
    if (!FIXED.includes(f) && !f.startsWith('dist/')) problems.push(`unexpected file ${f}`);
  }
  for (const f of FIXED) {
    if (!files.has(f)) problems.push(`missing file ${f}`);
  }
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  for (const target of exportTargets(pkg.exports)) {
    if (!files.has(target)) problems.push(`exports target ${target} is not in the package`);
  }
  for (const p of problems) process.stderr.write(`check-pack: ${p}\n`);
  return problems.length === 0 ? 0 : 1;
}

process.exitCode = main();
