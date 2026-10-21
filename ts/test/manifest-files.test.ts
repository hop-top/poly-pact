// Port of go/runner/manifest/files_test.go: the manifest against the
// fixture directory (spec/v1.0/fixtures/README.md, Completeness).

import assert from 'node:assert/strict';
import { symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  completeness,
  RULE_EXPECTED_MISSING,
  RULE_EXTENSION,
  RULE_PATH_MISSING,
  RULE_UNCOVERED,
} from '../src/runner/manifest/index.ts';
import {
  baseEntries,
  type RawEntry,
  rules,
  Tree,
  wantClean,
  wantRule,
  wantWhere,
} from './support/manifest.ts';

// Symbolic links need privileges on Windows.
const NO_SYMLINKS =
  process.platform === 'win32' ? 'symbolic links need privileges on windows' : false;

test('TestCompletenessAcceptsBase', () => {
  const tr = new Tree(baseEntries());
  wantClean(completeness(tr.root, tr.manifest()));
});

test('TestCompletenessPathMissing', () => {
  const tr = new Tree(baseEntries());
  tr.remove('keys/holder.jwk.json');
  wantRule(completeness(tr.root, tr.manifest()), RULE_PATH_MISSING, 'keys/holder');
});

test('TestCompletenessExpectedMissing', () => {
  const tr = new Tree(baseEntries());
  tr.remove('expected/admission/valid/decision.json');
  wantRule(completeness(tr.root, tr.manifest()), RULE_EXPECTED_MISSING, 'admission/valid');
});

// An expected result is a file, never a directory.
test('TestCompletenessExpectedIsAFile', () => {
  let es = baseEntries();
  (es[1] as RawEntry).expected = 'expected/admission/valid';
  let tr = new Tree(es);
  let ps = completeness(tr.root, tr.manifest());
  wantWhere(ps, RULE_EXPECTED_MISSING, 'admission/valid');

  // A directory named as expected covers nothing inside it. (A file under
  // expected/<id>/ is covered by the entry <id> whatever its expected names,
  // so the directory here is outside that tree.)
  es = baseEntries();
  (es[1] as RawEntry).expected = 'admission/valid-results';
  tr = new Tree(es);
  tr.write('admission/valid-results/decision.json', '{}');
  ps = completeness(tr.root, tr.manifest());
  wantWhere(ps, RULE_EXPECTED_MISSING, 'admission/valid');
  wantWhere(ps, RULE_UNCOVERED, 'admission/valid-results/decision.json');
});

test('TestCompletenessSymlinks', { skip: NO_SYMLINKS }, async (t) => {
  await t.test('escapes the fixtures directory', () => {
    const tr = new Tree(baseEntries());
    const outside = join(tr.dir, 'outside.json');
    writeFileSync(outside, '{}');
    tr.remove('keys/holder.jwk.json');
    symlinkSync(outside, join(tr.root, 'keys', 'holder.jwk.json'));
    wantRule(completeness(tr.root, tr.manifest()), RULE_PATH_MISSING, 'keys/holder');
  });
  await t.test('dangling', () => {
    const tr = new Tree(baseEntries());
    tr.remove('keys/holder.jwk.json');
    symlinkSync('nowhere.json', join(tr.root, 'keys', 'holder.jwk.json'));
    wantRule(completeness(tr.root, tr.manifest()), RULE_PATH_MISSING, 'keys/holder');
  });
});

// A fixture directory given as a symbolic link to a directory is followed,
// as a POSIX utility follows a link named on its command line (find -H): the
// walk covers the files of the directory it resolves to, so the result is
// the one for the directory itself. Links inside the tree are not followed.
test('TestCompletenessSymlinkedRoot', { skip: NO_SYMLINKS }, async (t) => {
  const link = (tr: Tree): string => {
    const l = join(tr.dir, 'fixtures-link');
    symlinkSync(tr.root, l);
    return l;
  };
  await t.test('clean tree', () => {
    const tr = new Tree(baseEntries());
    wantClean(completeness(link(tr), tr.manifest()));
  });
  await t.test('uncovered file', () => {
    const tr = new Tree(baseEntries());
    tr.write('keys/issuer.jwk.json', '{}');
    wantRule(completeness(link(tr), tr.manifest()), RULE_UNCOVERED, 'keys/issuer.jwk.json');
  });
  await t.test('extension', () => {
    const tr = new Tree(baseEntries());
    tr.write('admission/valid/run.sh', 'x');
    wantRule(completeness(link(tr), tr.manifest()), RULE_EXTENSION, 'admission/valid/run.sh');
  });
  await t.test('missing path', () => {
    const tr = new Tree(baseEntries());
    tr.remove('keys/holder.jwk.json');
    wantRule(completeness(link(tr), tr.manifest()), RULE_PATH_MISSING, 'keys/holder');
  });
});

test('TestCompletenessUncovered', async (t) => {
  const cases: Record<string, string> = {
    'file in no entry': 'keys/issuer.jwk.json',
    'file beside a file path': 'vectors/jcs/input/french.json',
    'expected tree of no entry': 'expected/admission/other/decision.json',
    'expected tree of a group': 'expected/admission/decision.json',
    'beside an expected tree': 'expected/admission/valid-2/decision.json',
    'nested manifest.json': 'keys/manifest.json',
    'nested manifest.schema.json': 'vectors/manifest.schema.json',
    'other markdown': 'vectors/jcs/NOTES.md',
    'LICENSE inside a name': 'vectors/jcs/MY-LICENSE.md',
    'lower-case license': 'vectors/jcs/license.md',
    'directory named LICENSE': 'vectors/LICENSE/notes.json',
    'prefix but not inside': 'admission/valid-2/config.json',
  };
  for (const [name, file] of Object.entries(cases)) {
    await t.test(name, () => {
      const tr = new Tree(baseEntries());
      tr.write(file, '{}');
      wantRule(completeness(tr.root, tr.manifest()), RULE_UNCOVERED, file);
    });
  }
});

// A file inside a directory path, a single-file path, an expected file, a
// file under expected/<id>/ of an entry <id>, a README.md anywhere and a
// file whose name starts with LICENSE are covered.
test('TestCompletenessCovered', () => {
  const tr = new Tree(baseEntries());
  tr.write('expected/admission/valid/snapshot.json', '{}');
  tr.write('expected/admission/valid/exchanges/1/decision.json', '{}');
  tr.write('expected/vectors/jcs/arrays/extra.json', '{}');
  tr.write('admission/valid/evidence/runtime.json', '{}');
  tr.write('admission/valid/signed/evidence/runtime.jws', 'e30.e30.e30');
  tr.write('vectors/jcs/README.md', '# x');
  tr.write('expected/README.md', '# x');
  tr.write('vectors/jcs/LICENSE-NOTE.md', '# x');
  tr.write('LICENSE.md', '# x');
  tr.write('keys/LICENSE.json', '{}');
  wantClean(completeness(tr.root, tr.manifest()));
});

test('TestCompletenessExtensions', async (t) => {
  const cases: Record<string, [string, string[]]> = {
    'go source inside a case': ['admission/valid/gen.go', [RULE_EXTENSION]],
    'shell script inside a case': ['admission/valid/run.sh', [RULE_EXTENSION]],
    'no extension': ['admission/valid/LICENSE', [RULE_EXTENSION]],
    'LICENSE outside every entry': ['vectors/LICENSE', [RULE_EXTENSION]],
    'yml is not in the neutral list': ['admission/valid/case.yml', [RULE_EXTENSION]],
    'txt is not in the neutral list': ['admission/valid/notes.txt', [RULE_EXTENSION]],
    'sql outside an asset entry': ['admission/valid/seed.sql', [RULE_EXTENSION]],
    'rego outside an asset entry': ['admission/valid/policy.rego', [RULE_EXTENSION]],
    'fga outside an asset entry': ['admission/valid/model.fga', [RULE_EXTENSION]],
    'ldif outside an asset entry': ['admission/valid/tree.ldif', [RULE_EXTENSION]],
    'uncovered sql': ['adapters/db/other.sql', [RULE_EXTENSION, RULE_UNCOVERED]],
    // Extensions are lowercase, as listed.
    'upper-case json': ['admission/valid/E.JSON', [RULE_EXTENSION]],
    'mixed-case yaml': ['admission/valid/case.Yaml', [RULE_EXTENSION]],
    'upper-case jws': ['admission/valid/signed/x.JWS', [RULE_EXTENSION]],
    'upper-case md': ['admission/valid/NOTES.MD', [RULE_EXTENSION]],
    'upper-case sql inside an asset': ['adapters/db/assets/seed.SQL', [RULE_EXTENSION]],
  };
  for (const [name, [file, want]] of Object.entries(cases)) {
    await t.test(name, () => {
      const tr = new Tree(baseEntries());
      tr.write(file, 'x');
      const ps = completeness(tr.root, tr.manifest());
      assert.equal(
        rules(ps).length,
        want.length,
        `rules ${rules(ps)}, want ${want}:\n${ps.message}`,
      );
      for (const r of want) wantWhere(ps, r, file);
    });
  }
});

test('TestCompletenessAllowedExtensions', () => {
  const tr = new Tree(baseEntries());
  for (const f of [
    'admission/valid/a.json',
    'admission/valid/b.yaml',
    'admission/valid/c.md',
    'admission/valid/d.jws',
    'admission/valid/E.json',
    'adapters/db/assets/policy.rego',
    'adapters/db/assets/model.fga',
    'adapters/db/assets/tree.ldif',
  ]) {
    tr.write(f, 'x');
  }
  wantClean(completeness(tr.root, tr.manifest()));
});

// An entry whose path breaks a field rule is reported by validate, not
// looked up on disk.
test('TestCompletenessSkipsMalformedEntries', () => {
  const es = baseEntries();
  (es[2] as RawEntry).path = '../outside.json';
  const tr = new Tree(es);
  for (const p of completeness(tr.root, tr.manifest())) {
    assert.ok(
      p.rule === RULE_UNCOVERED && p.where === 'keys/holder.jwk.json',
      `unexpected problem ${p}`,
    );
  }
});
