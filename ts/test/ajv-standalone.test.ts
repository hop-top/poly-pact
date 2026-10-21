// Guard of the require-from-string exception in docs/sdk/deps-ts.md of the
// source repository: ajv loads require-from-string (archived upstream) only
// from ajv/dist/standalone, so no file under src may import or require
// either. Then the package is installed but never loaded.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const SRC = fileURLToPath(new URL('../src', import.meta.url));

const SPECIFIER = [
  /\b(?:import|export)\s+(?:type\s+)?[\w$*{}\s,]*?\bfrom\s*['"]([^'"]+)['"]/g,
  /\bimport\s*['"]([^'"]+)['"]/g,
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  /\brequire\.resolve\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
];

// ajv/dist/standalone and ajv/lib/standalone with any subpath or extension,
// and require-from-string itself.
const FORBIDDEN = /^(?:ajv\/(?:dist|lib)\/standalone(?:[/.]|$)|require-from-string(?:\/|$))/;

function forbidden(source: string): string[] {
  return SPECIFIER.flatMap((re) => [...source.matchAll(re)].map((m) => m[1] ?? '')).filter((s) =>
    FORBIDDEN.test(s),
  );
}

test('the forbidden patterns match every form of the two imports', () => {
  const bad = [
    "import standaloneCode from 'ajv/dist/standalone';",
    "import standaloneCode from 'ajv/dist/standalone/index.js';",
    "import x from 'ajv/dist/standalone.js';",
    "export * from 'ajv/dist/standalone/instance.js';",
    "import 'ajv/lib/standalone';",
    "const m = await import('ajv/dist/standalone');",
    "const r = require('require-from-string');",
    "import requireFromString from 'require-from-string';",
  ];
  for (const line of bad) assert.equal(forbidden(line).length, 1, line);
  const good = [
    "import Ajv2020Mod from 'ajv/dist/2020.js';",
    "import type { ErrorObject } from 'ajv';",
    "import { x } from './standalone.ts';",
    "import y from 'ajv/dist/standalonex';",
  ];
  for (const line of good) assert.deepEqual(forbidden(line), [], line);
});

test('no file under src imports ajv/dist/standalone or require-from-string', () => {
  const problems = readdirSync(SRC, { withFileTypes: true, recursive: true })
    .filter((d) => d.isFile() && /\.(?:[cm]?ts|[cm]?js)$/.test(d.name))
    .flatMap((d) => {
      const file = join(d.parentPath, d.name);
      return forbidden(readFileSync(file, 'utf8')).map((s) => `${relative(SRC, file)}: ${s}`);
    });
  assert.deepEqual(problems, []);
});
