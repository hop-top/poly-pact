// The Usage example of README.md is test/readme-example.ts with the package
// specifiers in place of the source paths. This test runs the file, compares
// its output with the output block of README.md, and checks that the README
// code is the file with each specifier mapped through the exports map.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const EXAMPLE = fileURLToPath(new URL('readme-example.ts', import.meta.url));
const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const PKG = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

function usageBlocks(): { code: string; output: string } {
  const start = README.indexOf('\n## Usage\n');
  assert.notEqual(start, -1, 'README.md has no Usage section');
  const next = README.indexOf('\n## ', start + 1);
  const section = README.slice(start, next === -1 ? undefined : next);
  const code = /```ts\n([\s\S]*?)```/.exec(section)?.[1];
  const output = /```text\n([\s\S]*?)```/.exec(section)?.[1];
  assert.ok(code !== undefined, 'Usage has no ts block');
  assert.ok(output !== undefined, 'Usage has no text block');
  return { code, output };
}

// '@hop-top/pact/core/jws' -> '../src/core/jws/index.ts', from the exports map.
function sourcePath(specifier: string): string {
  const sub = `.${specifier.slice('@hop-top/pact'.length)}`;
  const target = PKG.exports[sub]?.default;
  assert.equal(typeof target, 'string', `${specifier} is not an export of the package`);
  return target.replace(/^\.\/dist\//, '../src/').replace(/\.js$/, '.ts');
}

test('README usage example matches test/readme-example.ts', () => {
  const { code } = usageBlocks();
  const mapped = code.replace(/'(@hop-top\/pact(?:\/[^']*)?)'/g, (_, s) => `'${sourcePath(s)}'`);
  assert.equal(mapped, readFileSync(EXAMPLE, 'utf8'));
});

test('README usage output is what test/readme-example.ts prints', () => {
  const { output } = usageBlocks();
  const out = execFileSync(process.execPath, [EXAMPLE], { encoding: 'utf8' });
  assert.equal(out, output);
});
