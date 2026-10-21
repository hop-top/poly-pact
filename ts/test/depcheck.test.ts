// Dependency guard of the package (Go counterpart: internal/depcheck). The
// vetted sets below are the pins recorded in docs/sdk/deps-ts.md of the
// source repository; a dependency joins them only after that vet.

import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SRC = join(ROOT, 'src');

const RUNTIME: Readonly<Record<string, string>> = { ajv: '8.20.0' };
const DEVELOPMENT: Readonly<Record<string, string>> = {
  '@biomejs/biome': '2.5.15',
  '@types/node': '22.20.5',
  'ajv-formats': '3.0.1',
  typescript: '7.0.2',
};

interface PackageJSON {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  bundleDependencies?: unknown;
  bundledDependencies?: unknown;
}

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as PackageJSON;

test('dependencies are exactly the vetted runtime set', () => {
  assert.deepEqual(pkg.dependencies ?? {}, RUNTIME);
});

test('devDependencies are exactly the vetted development set', () => {
  assert.deepEqual(pkg.devDependencies ?? {}, DEVELOPMENT);
});

test('no peer, optional or bundled dependencies', () => {
  assert.deepEqual(pkg.peerDependencies ?? {}, {});
  assert.deepEqual(pkg.optionalDependencies ?? {}, {});
  assert.equal(pkg.bundleDependencies, undefined);
  assert.equal(pkg.bundledDependencies, undefined);
});

// Module specifiers of static imports and re-exports, side-effect imports,
// dynamic imports and require calls. Over-matching (a specifier quoted in a
// comment) can only make the guard stricter.
const SPECIFIER = [
  /\b(?:import|export)\s+(?:type\s+)?[\w$*{}\s,]*?\bfrom\s*['"]([^'"]+)['"]/g,
  /\bimport\s*['"]([^'"]+)['"]/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
];

export function specifiers(source: string): string[] {
  return SPECIFIER.flatMap((re) => [...source.matchAll(re)].map((m) => m[1] ?? ''));
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((d) => d.isFile() && /\.(?:[cm]?ts|[cm]?js)$/.test(d.name))
    .map((d) => join(d.parentPath, d.name))
    .sort();
}

function packageName(spec: string): string {
  const parts = spec.split('/');
  return spec.startsWith('@') ? parts.slice(0, 2).join('/') : (parts[0] ?? spec);
}

// checkImports returns one problem per import under root that is not
// relative and inside root, not a node: builtin, and not a vetted runtime
// package.
export function checkImports(root: string, runtime: Readonly<Record<string, string>>): string[] {
  const problems: string[] = [];
  for (const file of sourceFiles(root)) {
    const where = relative(root, file);
    for (const spec of specifiers(readFileSync(file, 'utf8'))) {
      if (spec.startsWith('./') || spec.startsWith('../')) {
        const target = resolve(dirname(file), spec);
        if (target !== root && !target.startsWith(root + sep)) {
          problems.push(`${where}: ${spec} leaves ${relative(ROOT, root) || '.'}`);
        }
      } else if (spec.startsWith('node:')) {
        // builtin
      } else if (!Object.hasOwn(runtime, packageName(spec))) {
        problems.push(`${where}: ${spec} is neither relative, node: nor a vetted runtime package`);
      }
    }
  }
  return problems;
}

test('every import under src is relative, node: or a vetted runtime package', () => {
  assert.deepEqual(checkImports(SRC, RUNTIME), []);
});

test('negative control: the guard reports bad imports in a copy of src', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pact-depcheck-'));
  try {
    const copy = join(dir, 'src');
    cpSync(SRC, copy, { recursive: true });
    assert.deepEqual(checkImports(copy, RUNTIME), [], 'the unmodified copy is clean');
    const bad: Record<string, string> = {
      'bare-builtin.ts': "import { readFileSync } from 'fs';\n",
      'unvetted.ts': "import leftPad from 'left-pad';\n",
      'dev-only.ts': "import addFormats from 'ajv-formats';\n",
      'scoped.ts': "export type { T } from '@scope/pkg/sub';\n",
      'side-effect.ts': "import 'polyfill';\n",
      'dynamic.ts': "const m = await import('chalk');\n",
      'escape.ts': "import schema from '../../schema/pact.schema.json' with { type: 'json' };\n",
    };
    for (const [name, text] of Object.entries(bad)) writeFileSync(join(copy, name), text);
    const problems = checkImports(copy, RUNTIME);
    for (const name of Object.keys(bad)) {
      assert.ok(
        problems.some((p) => p.startsWith(`${name}:`)),
        `${name} is reported: ${problems.join('; ')}`,
      );
    }
    assert.equal(problems.length, Object.keys(bad).length);
    writeFileSync(join(copy, 'vetted.ts'), "import Ajv2020Mod from 'ajv/dist/2020.js';\n");
    assert.equal(checkImports(copy, RUNTIME).length, Object.keys(bad).length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
