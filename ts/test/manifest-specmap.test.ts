// Port of go/runner/manifest/specmap_test.go: the cross-references between
// the manifest and spec/v1.0/spec-map.md, and check over a tree on disk.

import assert from 'node:assert/strict';
import { mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import {
  check,
  checkSpecMap,
  parseSpecMap,
  RULE_FIXTURE_MISSING,
  RULE_GROUP_LANDED,
  RULE_GROUP_PARTIAL_COMPLETE,
  RULE_GROUP_PARTIAL_EMPTY,
  RULE_GROUP_PLANNED,
  RULE_GROUP_UNLISTED,
  RULE_JSON,
  RULE_ROW_UNKNOWN,
  RULE_SPEC_MAP,
  RULE_UNCOVERED,
  type SpecMap,
} from '../src/runner/manifest/index.ts';
import {
  BASE_SPEC_MAP,
  baseEntries,
  encode,
  mustContain,
  type RawEntry,
  rules,
  Tree,
  wantClean,
  wantRule,
  wantWhere,
} from './support/manifest.ts';

function parseMap(text: string): SpecMap {
  const [sm, ps] = parseSpecMap(text);
  assert.equal(ps.length, 0, `parseSpecMap: ${ps.message}`);
  assert.ok(sm);
  return sm;
}

test('TestParseSpecMap', () => {
  const sm = parseMap(BASE_SPEC_MAP);
  assert.deepEqual(
    sm.rows.map((r) => r.id),
    ['CL-11.3', 'CL-C', 'CL-17.3.1'],
  );
  assert.deepEqual(sm.rows[2]?.fixtures, ['approval/pending', 'parse/alg-none']);
  assert.deepEqual(Object.fromEntries(sm.groups), {
    admission: 'partial',
    approval: 'planned',
    parse: 'planned',
    adapters: 'landed',
    keys: 'landed',
    vectors: 'landed',
  });
});

function replace(old: string, repl: string): string {
  assert.ok(BASE_SPEC_MAP.includes(old), old);
  return BASE_SPEC_MAP.replace(old, repl);
}

test('TestParseSpecMapProblems', async (t) => {
  const cases: Record<string, string> = {
    'no conformance map': replace('## Conformance map', '## Conformance table'),
    'no fixture groups': replace('## Fixture groups', '## Groups'),
    'no ID column': replace('| ID | Check |', '| Row | Check |'),
    'no Fixture(s) column': replace('| Finding | Fixture(s) |', '| Finding | Cases |'),
    'no Status column': replace('| Covers | Status |', '| Covers | State |'),
    'bad status': replace('| Positive control | partial |', '| Positive control | done |'),
    'status in upper case': replace(
      '| Positive control | partial |',
      '| Positive control | Partial |',
    ),
    'duplicate group': replace(
      '| approval | `fixtures/approval/`',
      '| admission | `fixtures/approval/`',
    ),
    'duplicate row': replace('| CL-C | Test keys', '| CL-11.3 | Test keys'),
    'row with a cell short': replace(
      '| CL-C | Test keys | C | G13 | keys/holder |',
      '| CL-C | Test keys | C | keys/holder |',
    ),
    'row without end pipe': replace(
      '| CL-C | Test keys | C | G13 | keys/holder |',
      '| CL-C | Test keys | C | G13 | keys/holder',
    ),
    'fenced table only': `${replace('## Conformance map\n\n', '## Conformance map\n\n```\n')}\`\`\`\n`,
  };
  for (const [name, text] of Object.entries(cases)) {
    await t.test(name, () => {
      const [, ps] = parseSpecMap(text);
      wantRule(ps, RULE_SPEC_MAP, '');
    });
  }
});

test('TestCheckSpecMapAcceptsBase', () => {
  const tr = new Tree(baseEntries());
  wantClean(checkSpecMap(tr.root, tr.manifest(), parseMap(BASE_SPEC_MAP)));
});

// Every spec_map_row is a row of the map.
test('TestCheckSpecMapRowUnknown', () => {
  const es = baseEntries();
  (es[3] as RawEntry).spec_map_row = 'CL-7.4';
  const tr = new Tree(es);
  const ps = checkSpecMap(tr.root, tr.manifest(), parseMap(BASE_SPEC_MAP));
  wantRule(ps, RULE_ROW_UNKNOWN, 'CL-7.4');
  mustContain(ps.message, 'vectors/jcs/arrays');
});

// Replaces the Fixture(s) cell of row CL-C.
function withFixtures(fixtures: string): string {
  return BASE_SPEC_MAP.replace(
    '| CL-C | Test keys | C | G13 | keys/holder |',
    `| CL-C | Test keys | C | G13 | ${fixtures} |`,
  );
}

function escapeRE(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Sets the status of group in the Fixture groups table.
function withStatus(text: string, group: string, status: string): string {
  const re = new RegExp(`^(\\| ${escapeRE(group)} \\|.*\\| )[a-z]+( \\|)$`, 'm');
  assert.ok(re.test(text), group);
  return text.replace(re, `$1${status}$2`);
}

// Drops the row of group from the Fixture groups table.
function withoutGroup(text: string, group: string): string {
  const re = new RegExp(`^\\| ${escapeRE(group)} \\|.*\\n`, 'm');
  assert.ok(re.test(text), group);
  return text.replace(re, '');
}

// An id a row lists is registered when its group is landed, and in any group
// once its fixture exists. A fixture exists when the fixture directory has a
// file or directory at the id, or a file at the id plus a neutral extension.
// Other ids are reserved.
test('TestCheckSpecMapFixtureIDs', async (t) => {
  // specMap, files to write (a name ending in / is a directory), the id
  // reported missing ('' for none).
  const cases: Record<string, [string, string[], string]> = {
    'landed group, id absent': [withFixtures('keys/holder, keys/issuer'), [], 'keys/issuer'],
    'landed group, id on disk': [
      withFixtures('keys/holder, keys/issuer'),
      ['keys/issuer/'],
      'keys/issuer',
    ],
    'partial group, id absent': [BASE_SPEC_MAP, [], ''],
    'partial group, case directory': [
      BASE_SPEC_MAP,
      ['admission/wrong-tenant/README.md'],
      'admission/wrong-tenant',
    ],
    'partial group, empty case directory': [
      BASE_SPEC_MAP,
      ['admission/wrong-tenant/'],
      'admission/wrong-tenant',
    ],
    'partial group, case file': [
      BASE_SPEC_MAP,
      ['admission/wrong-tenant.jws'],
      'admission/wrong-tenant',
    ],
    'partial group, json case file': [
      BASE_SPEC_MAP,
      ['admission/wrong-tenant.json'],
      'admission/wrong-tenant',
    ],
    'partial group, other extension': [BASE_SPEC_MAP, ['admission/wrong-tenant.txt'], ''],
    'partial group, longer name': [BASE_SPEC_MAP, ['admission/wrong-tenant-2.json'], ''],
    'planned group, no directory': [withFixtures('keys/holder, approval/expired'), [], ''],
    'planned group, directory exists': [
      withFixtures('keys/holder, approval/expired'),
      ['approval/README.md'],
      '',
    ],
    'planned group, case directory': [
      withFixtures('keys/holder, approval/expired'),
      ['approval/expired/'],
      'approval/expired',
    ],
    'planned group, three-part id on disk': [
      withFixtures('keys/holder, approval/expired/old'),
      ['approval/expired/old.json'],
      'approval/expired/old',
    ],
    'planned group, id with dots on disk': [
      withFixtures('keys/holder, approval/_x/c-01.a'),
      ['approval/_x/c-01.a.json'],
      'approval/_x/c-01.a',
    ],
    'id that is not an id form': [withFixtures('keys/holder, admission/../keys'), [], ''],
    'backticked id': [withFixtures('keys/holder, `admission/valid`'), [], ''],
  };
  for (const [name, [specMap, create, want]] of Object.entries(cases)) {
    await t.test(name, () => {
      const tr = new Tree(baseEntries());
      for (const f of create) {
        if (f.endsWith('/'))
          mkdirSync(join(tr.root, ...f.slice(0, -1).split('/')), { recursive: true });
        else tr.write(f, '{}');
      }
      const ps = checkSpecMap(tr.root, tr.manifest(), parseMap(specMap));
      if (want === '') {
        wantClean(ps);
        return;
      }
      wantWhere(ps, RULE_FIXTURE_MISSING, want);
      for (const p of ps) {
        assert.ok(p.rule !== RULE_FIXTURE_MISSING || p.where === want, `unexpected problem ${p}`);
      }
    });
  }
});

// The three statuses of the Fixture groups table. planned: no manifest entry
// under the group. partial: at least one entry, and not every listed id
// exists yet. landed: at least one entry (and every listed id registered).
test('TestCheckSpecMapGroupStatus', async (t) => {
  const withEntry = (e: RawEntry): RawEntry[] => {
    const es = baseEntries();
    const i = es.findIndex((x) => (x.id as string) > (e.id as string));
    return i < 0 ? [...es, e] : [...es.slice(0, i), e, ...es.slice(i)];
  };
  const parseEntry: RawEntry = {
    id: 'parse/alg-none',
    kind: 'evaluate',
    scope: 'runner',
    path: 'parse/alg-none.jws',
    expected: 'expected/parse/alg-none/decision.json',
    outcome: 'REJECTED',
    spec_map_row: 'CL-17.3.1',
    draft_section: '7.2',
  };
  const parseFiles = ['parse/alg-none.jws', 'expected/parse/alg-none/decision.json'];
  const onlyValid = BASE_SPEC_MAP.replace(
    'admission/valid, admission/wrong-tenant |',
    'admission/valid |',
  );
  const noParseID = BASE_SPEC_MAP.replace(
    'approval/pending, parse/alg-none |',
    'approval/pending |',
  );
  const noApprovalID = BASE_SPEC_MAP.replace(
    'approval/pending, parse/alg-none |',
    'parse/alg-none |',
  );
  // entries, spec map, files to write, the rule ('' for a clean result), where.
  const cases: Record<string, [RawEntry[], string, string[], string, string]> = {
    'planned group with an entry': [
      withEntry(parseEntry),
      BASE_SPEC_MAP,
      parseFiles,
      RULE_GROUP_PLANNED,
      'parse',
    ],
    'planned group, entry no row lists': [
      withEntry(parseEntry),
      noParseID,
      parseFiles,
      RULE_GROUP_PLANNED,
      'parse',
    ],
    'partial group, its only id registered': [
      withEntry(parseEntry),
      withStatus(BASE_SPEC_MAP, 'parse', 'partial'),
      parseFiles,
      RULE_GROUP_PARTIAL_COMPLETE,
      'parse',
    ],
    'partial group without entries': [
      baseEntries(),
      withStatus(BASE_SPEC_MAP, 'approval', 'partial'),
      [],
      RULE_GROUP_PARTIAL_EMPTY,
      'approval',
    ],
    'partial group, every id registered': [
      baseEntries(),
      onlyValid,
      [],
      RULE_GROUP_PARTIAL_COMPLETE,
      'admission',
    ],
    'partial group, no listed id': [
      baseEntries(),
      withStatus(BASE_SPEC_MAP, 'adapters', 'partial'),
      [],
      RULE_GROUP_PARTIAL_COMPLETE,
      'adapters',
    ],
    'landed group without entries': [
      baseEntries(),
      withStatus(noApprovalID, 'approval', 'landed'),
      [],
      RULE_GROUP_LANDED,
      'approval',
    ],
    'landed group, no listed id': [baseEntries(), BASE_SPEC_MAP, [], '', ''],
    'landed group, every id registered': [
      baseEntries(),
      withStatus(onlyValid, 'admission', 'landed'),
      [],
      '',
      '',
    ],
    'partial group, one id reserved': [baseEntries(), BASE_SPEC_MAP, [], '', ''],
  };
  for (const [name, [entries, specMap, create, rule, where]] of Object.entries(cases)) {
    await t.test(name, () => {
      const tr = new Tree(entries);
      for (const f of create) tr.write(f, '{}');
      const ps = checkSpecMap(tr.root, tr.manifest(), parseMap(specMap));
      if (rule === '') {
        wantClean(ps);
        return;
      }
      wantRule(ps, rule, where);
    });
  }

  // Every listed id of a partial group exists, one only on disk: the group
  // is complete, and the unregistered fixture is missing from the manifest.
  await t.test('partial group, last id on disk', () => {
    const tr = new Tree(baseEntries());
    tr.write('admission/wrong-tenant/README.md', '# x');
    const ps = checkSpecMap(tr.root, tr.manifest(), parseMap(BASE_SPEC_MAP));
    assert.deepEqual(rules(ps), [RULE_FIXTURE_MISSING, RULE_GROUP_PARTIAL_COMPLETE].sort());
    wantWhere(ps, RULE_GROUP_PARTIAL_COMPLETE, 'admission');
  });
});

// Every group that a manifest entry or a row names has a status.
test('TestCheckSpecMapGroupUnlisted', async (t) => {
  const cases: Record<string, [string, string]> = {
    'row names a group without a status': [
      withFixtures('keys/holder, schema/appendix-b-valid'),
      'schema',
    ],
    'manifest names a group without a status': [withoutGroup(BASE_SPEC_MAP, 'vectors'), 'vectors'],
    'both name a group without a status': [withoutGroup(BASE_SPEC_MAP, 'keys'), 'keys'],
    'a group named only by a reserved id': [withoutGroup(BASE_SPEC_MAP, 'approval'), 'approval'],
  };
  for (const [name, [specMap, where]] of Object.entries(cases)) {
    await t.test(name, () => {
      const tr = new Tree(baseEntries());
      const ps = checkSpecMap(tr.root, tr.manifest(), parseMap(specMap));
      wantRule(ps, RULE_GROUP_UNLISTED, where);
      assert.equal(ps.length, 1, `want one problem, got:\n${ps.message}`);
    });
  }
  await t.test('an id both registered and listed is named once', () => {
    const tr = new Tree(baseEntries());
    const ps = checkSpecMap(tr.root, tr.manifest(), parseMap(withoutGroup(BASE_SPEC_MAP, 'keys')));
    assert.equal(ps.message.split('keys/holder').length - 1, 1, ps.message);
  });
  await t.test('a listed group nothing names', () => {
    const text = BASE_SPEC_MAP.replace(
      '| vectors |',
      '| capacity | `fixtures/capacity/` | Limits | planned |\n| vectors |',
    );
    const tr = new Tree(baseEntries());
    wantClean(checkSpecMap(tr.root, tr.manifest(), parseMap(text)));
  });
});

// Runs every rule over a tree on disk, as pactfix check manifest does.
test('TestCheck', () => {
  const tr = new Tree(baseEntries());
  wantClean(check(tr.root, tr.specMap));

  tr.write('keys/issuer.jwk.json', '{}');
  tr.setSpecMap(
    BASE_SPEC_MAP.replace(
      '| CL-C | Test keys | C | G13 | keys/holder |',
      '| CL-D | Test keys | C | G13 | keys/holder, keys/issuer |',
    ),
  );
  assert.deepEqual(
    rules(check(tr.root, tr.specMap)),
    [RULE_UNCOVERED, RULE_FIXTURE_MISSING, RULE_ROW_UNKNOWN].sort(),
  );

  tr.write('manifest.json', '{"manifest_version":1,"entries":[],"entries":[]}');
  wantRule(check(tr.root, tr.specMap), RULE_JSON, 'manifest.json');

  tr.remove('manifest.json');
  wantRule(check(tr.root, tr.specMap), RULE_JSON, 'manifest.json');

  tr.write('manifest.json', encode(baseEntries()));
  tr.remove('keys/issuer.jwk.json');
  rmSync(tr.specMap);
  wantRule(check(tr.root, tr.specMap), RULE_SPEC_MAP, '');
});
