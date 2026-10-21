// Paths of the source repository around the package, and the rule for a
// file there that may be absent: spec/ is required in the source
// repository (PACT_REQUIRE_VECTORS=1) and a NOTICE skip in the package
// mirror; a Go source is a skip wherever it is absent (package mirror,
// mutation copy).

import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { TestContext } from 'node:test';
import { fileURLToPath } from 'node:url';

export const REPO = fileURLToPath(new URL('../../..', import.meta.url));
export const PACKAGE = fileURLToPath(new URL('../..', import.meta.url));
export const DRAFT = join(REPO, 'spec', 'v1.0', 'draft.md');
export const SCHEMA = join(PACKAGE, 'schema', 'pact.schema.json');

/** The text of a spec/ file, or undefined after a NOTICE skip in the mirror. */
export function specText(t: TestContext, path: string): string | undefined {
  if (existsSync(path)) return readFileSync(path, 'utf8');
  if (process.env.PACT_REQUIRE_VECTORS === '1')
    assert.fail(`PACT_REQUIRE_VECTORS=1 and ${path} is absent`);
  t.skip(`NOTICE: ${path} absent (package mirror)`);
  return undefined;
}

/** The text of a Go source of the repository, or undefined after a skip. */
export function goSource(t: TestContext, path: string): string | undefined {
  if (existsSync(path)) return readFileSync(path, 'utf8');
  t.skip(`${path} absent`);
  return undefined;
}
