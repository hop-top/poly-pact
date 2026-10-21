// Port of go/adapter/adaptertest/fixtures_test.go and
// freshness_cases_test.go: the shipped common case files load, are named
// after their ids, are registered in the manifest, cite headings of the
// draft, and pin what the draft and the freshness profile require. Absent
// in the package mirror: a NOTICE skip there, a failure under
// PACT_REQUIRE_VECTORS=1.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { type TestContext, test } from 'node:test';
import { type Case, defaultFixtures, loadCases } from '../src/adapter/adaptertest/index.ts';
import { ReasonCode } from '../src/adapter/freshness.ts';
import { Code } from '../src/adapter/index.ts';
import {
  FIXTURES,
  fixturesPresent,
  type ManifestEntry,
  readFixtureJSON,
} from './support/fixtures.ts';
import { DRAFT, specText } from './support/repo.ts';

const COMMON_DIR = 'adapters/_common';
const DEFAULT_NOW = 1792080000;
// The baseline clock skew of draft 7.5, in seconds.
const SKEW = 5;
// The lifetime of a requirement contract, draft 20.1, in seconds.
const CONTRACT_LIFETIME = 60;

function commonCases(t: TestContext): Case[] | undefined {
  if (!fixturesPresent(t)) return undefined;
  return loadCases(defaultFixtures());
}

const groupOf = (id: string): string => id.split('.')[0] as string;

// The common case groups of the suite, by id.
const REQUIRED_GROUPS = [
  'COMMON-01',
  'COMMON-02',
  'COMMON-03',
  'COMMON-04',
  'COMMON-05',
  'COMMON-06',
  'COMMON-07',
  'COMMON-08',
  'COMMON-09',
  'COMMON-10',
  'COMMON-11',
  'COMMON-12',
  'IDENT-01',
  'IDENT-02',
  'IDENT-03',
  'IDENT-04',
  'IDENT-05',
  'IDENT-06',
  'IDENT-07',
  'IDENT-08',
  'IDENT-09',
  'IDENT-10',
  'FRESH-01',
  'FRESH-02',
  'FRESH-03',
  'FRESH-04',
  'FRESH-05',
  'FRESH-06',
];

// Each shipped common case loads under the strict format, its file name is
// its lowercase id, and every group is present with at least one case.
test('TestCommonCaseFiles', (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const files = readdirSync(join(FIXTURES, COMMON_DIR));
  for (const f of files) assert.ok(f.endsWith('.json'), `${COMMON_DIR}/${f} is not a case file`);
  assert.equal(files.length, cases.length, 'one case per case file');
  const groups = new Map<string, number>();
  for (const c of cases) {
    groups.set(groupOf(c.id), (groups.get(groupOf(c.id)) ?? 0) + 1);
    assert.ok(
      files.includes(`${c.id.toLowerCase()}.json`),
      `case ${c.id} is not in a file named after its lowercase id`,
    );
    assert.ok(c.draft.length > 0, `case ${c.id} cites no draft section`);
  }
  for (const g of REQUIRED_GROUPS) assert.ok((groups.get(g) ?? 0) > 0, `no case of group ${g}`);
});

// The manifest's outcome class of a case.
function manifestOutcome(c: Case): string {
  const yes = ['authenticated', 'bound', 'mapped', 'claim', 'signed', 'ALLOW', 'PASS'];
  return yes.includes(c.expect.outcome) ? 'ACCEPTED' : 'REJECTED';
}

// manifest.json lists every common case file, as an adapter-case entry that
// cites the group of the case, and lists no other.
test('TestCaseFilesAreRegistered', (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const m = readFixtureJSON('manifest.json') as {
    manifest_version: number;
    entries: ManifestEntry[];
  };
  assert.equal(m.manifest_version, 1);
  const ids = m.entries.map((e) => e.id);
  assert.deepEqual(ids, [...ids].sort(), 'manifest entries are sorted by id');
  const byPath = new Map<string, ManifestEntry>();
  for (const e of m.entries) {
    if (e.kind === 'adapter-case' && e.path.startsWith(`${COMMON_DIR}/`)) byPath.set(e.path, e);
  }
  for (const c of cases) {
    const file = `${COMMON_DIR}/${c.id.toLowerCase()}.json`;
    const e = byPath.get(file);
    assert.ok(e !== undefined, `manifest.json does not list ${file}`);
    byPath.delete(file);
    assert.deepEqual(
      {
        id: e.id,
        kind: e.kind,
        scope: e.scope,
        path: e.path,
        expected: e.expected,
        outcome: e.outcome,
        spec_map_row: e.spec_map_row,
        capabilities: e.capabilities ?? [],
      },
      {
        id: file.replace(/\.json$/, ''),
        kind: 'adapter-case',
        scope: 'adapter',
        path: file,
        expected: file,
        outcome: manifestOutcome(c),
        spec_map_row: groupOf(c.id),
        capabilities: [],
      },
      `manifest entry of ${c.id}`,
    );
    assert.ok(
      c.draft.includes(e.draft_section),
      `manifest entry of ${c.id} cites draft section ${e.draft_section}, which the case does not`,
    );
  }
  assert.deepEqual(
    [...byPath.keys()],
    [],
    `manifest.json lists files that are not case files of ${COMMON_DIR}`,
  );
});

// IDENT-09, selection among the agents of a shared workload, applies only to
// an adapter whose profile supports workloads shared by several agents, and
// IDENT-10, the configuration error of a workload with more than one
// enrollment in force, only to one whose profile does not (draft 17.1,
// identity mapping IM-19). Every other common case applies to both.
test('TestWorkloadModesOfTheCommonCases', (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const want: Record<string, string> = { 'IDENT-09': 'shared', 'IDENT-10': 'dedicated' };
  for (const c of cases) {
    assert.equal(c.workloads, want[groupOf(c.id)] ?? '', `case ${c.id}`);
  }
});

// The section numbers of the headings of the draft: "17.1" for
// "### 17.1 Required adapter capabilities", and "19" for "## 19. ...".
function draftHeadings(text: string): Set<string> {
  const out = new Set<string>();
  for (const line of text.split('\n')) {
    if (!line.startsWith('#')) continue;
    const first = line.replace(/^#+/, '').trim().split(/\s+/)[0];
    if (first) out.add(first.replace(/\.$/, ''));
  }
  return out;
}

// The draft section numbers of a case exist in spec/v1.0/draft.md as headings, so
// a renumbering of the draft cannot leave a case citing nothing.
test('TestCaseFilesCiteTheDraft', (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const text = specText(t, DRAFT);
  if (text === undefined) return;
  const headings = draftHeadings(text);
  for (const c of cases) {
    for (const s of c.draft) {
      assert.ok(
        headings.has(s),
        `case ${c.id} cites draft section ${s}, which is not a heading of spec/v1.0/draft.md`,
      );
    }
  }
});

// The case files are valid JSON documents for any reader, not only for the
// strict decoder, and end with a newline.
test('TestCaseFilesAreJSON', (t) => {
  if (!fixturesPresent(t)) return;
  for (const f of readdirSync(join(FIXTURES, COMMON_DIR))) {
    const data = readFileSync(join(FIXTURES, COMMON_DIR, f), 'utf8');
    assert.doesNotThrow(() => JSON.parse(data), f);
    assert.ok(data.endsWith('}\n'), `${f} does not end with a newline`);
  }
});

// The common cases that show a request the baseline HTTP mapping forbids
// (draft 10.2) expect map_operation to fail with INVALID_MESSAGE (draft
// 13.4), by the code string and no language identifier.
test('TestMalformedRequestCasesPinTheCode', async (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const byId = new Map(cases.map((c) => [c.id, c]));
  for (const id of ['COMMON-03.fragment', 'COMMON-03.userinfo', 'COMMON-03.content-encoding']) {
    await t.test(id, () => {
      const c = byId.get(id);
      assert.ok(c !== undefined, `no case ${id}`);
      assert.equal(c.expect.function, 'map_operation');
      assert.equal(c.expect.outcome, 'error');
      assert.equal(c.expect.reason_code, 'INVALID_MESSAGE');
      const data = readFileSync(join(FIXTURES, COMMON_DIR, `${id.toLowerCase()}.json`), 'utf8');
      assert.ok(
        !data.includes('adapter.') && !data.includes('ErrInvalidMessage'),
        `${id} names a Go identifier`,
      );
    });
  }
});

// A row of the common case table of adapters/README.md: the group id in the
// first column, the draft sections in the last.
const GROUP_ROW = /^\| `([A-Z][A-Z0-9]*-[0-9]{2,})` \|.*\| ([^|]+) \|$/;

// The Draft column of each group row of the common case table lists exactly
// the draft sections the cases of that group cite, and every group has a row.
test('TestReadmeGroupTableCitesTheCases', (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const cited = new Map<string, Set<string>>();
  for (const c of cases) {
    const g = groupOf(c.id);
    const set = cited.get(g) ?? new Set<string>();
    for (const s of c.draft) set.add(s);
    cited.set(g, set);
  }
  const readme = readFileSync(join(FIXTURES, 'adapters', 'README.md'), 'utf8');
  const rows = new Set<string>();
  for (const line of readme.split('\n')) {
    const m = GROUP_ROW.exec(line);
    if (m === null) continue;
    const g = m[1] as string;
    rows.add(g);
    const listed = (m[2] as string)
      .split(',')
      .map((s) => s.trim())
      .sort();
    assert.deepEqual(listed, [...(cited.get(g) ?? [])].sort(), `README row ${g}`);
  }
  for (const g of cited.keys())
    assert.ok(rows.has(g), `group ${g} has no row in the common case table of adapters/README.md`);
});

function byId(cases: readonly Case[]): Map<string, Case> {
  return new Map(cases.map((c) => [c.id, c]));
}

// The FRESH cases expect what the freshness profile (spec/v1.0/profiles/
// freshness.md, sections 3.2, 5 and 6) and the draft require. CLOCK_AHEAD and
// RESTAMPED are check-specific codes with no draft 13.4 row, so they are
// pinned as check_context reason codes.
test('TestFreshnessCasesPinTheProfile', async (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const m = byId(cases);
  const want: [string, string, string, string][] = [
    ['FRESH-01.revoked-after-issuance', 'resolve_agent_binding', 'unusable', ''],
    ['FRESH-02.stale-snapshot', 'check_context', 'FAIL', 'STALE_EVIDENCE'],
    ['FRESH-02.at-limit', 'check_context', 'PASS', 'REQUIREMENT_SATISFIED'],
    ['FRESH-03.observed-ahead', 'check_context', 'FAIL', 'CLOCK_AHEAD'],
    ['FRESH-03.at-skew', 'check_context', 'PASS', 'REQUIREMENT_SATISFIED'],
    ['FRESH-04.pinned-revision-changed', 'check_context', 'FAIL', 'REQUIREMENTS_CHANGED'],
    ['FRESH-05.binding-source-down', 'resolve_agent_binding', 'error', 'DEPENDENCY_UNAVAILABLE'],
    ['FRESH-05.claim-source-down', 'read_native_claim', 'error', 'DEPENDENCY_UNAVAILABLE'],
    ['FRESH-05.check-source-down', 'check_context', 'UNKNOWN', 'DEPENDENCY_UNAVAILABLE'],
    ['FRESH-06.restamped', 'check_context', 'FAIL', 'RESTAMPED'],
  ];
  for (const [id, fn, outcome, code] of want) {
    await t.test(id, () => {
      const c = m.get(id);
      assert.ok(c !== undefined, `no case ${id}`);
      assert.deepEqual(
        [c.expect.function, c.expect.outcome, c.expect.reason_code],
        [fn, outcome, code],
      );
      assert.notEqual(c.now, null, 'a freshness case fixes the clock');
    });
  }
  for (const [code, impl] of Object.entries({
    STALE_EVIDENCE: ReasonCode.STALE_EVIDENCE,
    CLOCK_AHEAD: ReasonCode.CLOCK_AHEAD,
    RESTAMPED: ReasonCode.RESTAMPED,
    REQUIREMENT_SATISFIED: ReasonCode.SATISFIED,
    DEPENDENCY_UNAVAILABLE: ReasonCode.DEPENDENCY_UNAVAILABLE,
  })) {
    assert.equal(impl, code, `module freshness spells ${code} as ${impl}`);
  }
});

interface FreshState {
  checks?: { observed_at?: number }[];
  enrollments?: { status_checked_at?: number }[];
  claims?: { status_checked_at?: number }[];
}

const stateOf = (c: Case): FreshState => JSON.parse(c.native_state.text) as FreshState;

// The times of the FRESH cases sit where the draft's bounds put them: one
// second past the 5-second skew and exactly at it (draft 7.5), and a
// revocation inside the 60-second lifetime of a contract issued before it
// (draft 9.1, 20.1).
test('TestFreshnessCaseTimes', (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const m = byId(cases);
  const read = (id: string): [number, FreshState] => {
    const c = m.get(id);
    assert.ok(c !== undefined && c.now !== null, `no case ${id} with a now`);
    return [c.now, stateOf(c)];
  };
  let [now, st] = read('FRESH-03.observed-ahead');
  assert.equal(st.checks?.length, 1);
  assert.equal(
    st.checks?.[0]?.observed_at,
    now + SKEW + 1,
    'observed_at is now plus the skew plus one second',
  );
  [now, st] = read('FRESH-03.at-skew');
  assert.equal(st.checks?.length, 1);
  assert.equal(st.checks?.[0]?.observed_at, now + SKEW, 'observed_at is now plus the skew');
  [now, st] = read('FRESH-01.revoked-after-issuance');
  assert.equal(st.enrollments?.length, 1, 'want one enrollment');
  const age = now - (st.enrollments?.[0]?.status_checked_at ?? 0);
  assert.ok(
    age > 0 && age < CONTRACT_LIFETIME,
    `the revocation is ${age} s old, want inside a contract lifetime`,
  );
});

// The COMMON-04 status-check cases sit at the bound of draft A.2: exactly at
// now plus the 5-second skew for the control, and one second past it for the
// case that must not be passed on.
test('TestStatusCheckCaseTimes', (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const m = byId(cases);
  for (const [id, ahead, outcome] of [
    ['COMMON-04.status-checked-at-skew', SKEW, 'claim'],
    ['COMMON-04.future-status-checked', SKEW + 1, 'error'],
  ] as const) {
    const c = m.get(id);
    assert.ok(c !== undefined, `no case ${id}`);
    const st = stateOf(c);
    assert.equal(st.claims?.length, 1, `${id}: want one claim record`);
    assert.equal((st.claims?.[0]?.status_checked_at ?? 0) - (c.now ?? DEFAULT_NOW), ahead, id);
    assert.equal(c.expect.outcome, outcome, id);
  }
});

// A read_native_claim whose source time is later than now plus the skew is
// refused with DEPENDENCY_UNAVAILABLE (freshness profile, section 3; draft
// A.2, 13.4).
test('TestClaimClockAheadCasesRequireRefusal', (t) => {
  const cases = commonCases(t);
  if (cases === undefined) return;
  const m = byId(cases);
  for (const id of ['COMMON-04.future-observed-at', 'COMMON-04.future-status-checked']) {
    const c = m.get(id);
    assert.ok(c !== undefined, `no case ${id}`);
    assert.deepEqual(
      [c.expect.function, c.expect.outcome, c.expect.reason_code],
      ['read_native_claim', 'error', Code.DEPENDENCY_UNAVAILABLE],
      id,
    );
  }
});
