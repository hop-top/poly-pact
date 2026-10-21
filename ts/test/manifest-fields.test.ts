// Port of go/runner/manifest/fields_test.go: the entry fields
// conformance_profile, transport and layer, the kinds transport, mcp,
// profile and source-case, and the test manifests of
// spec/v1.0/fixtures/testdata/manifest.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { parse as strictParse } from '../src/core/strictjson.ts';
import {
  completeness,
  conformanceProfiles,
  DEFAULT_CONFORMANCE_PROFILE,
  DEFAULT_TRANSPORT,
  Kind,
  layers,
  parse,
  RULE_CONFORMANCE_PROFILE,
  RULE_EXTENSION,
  RULE_LAYER,
  RULE_SCOPE,
  RULE_SHAPE,
  RULE_TRANSPORT,
  RULE_UNCOVERED,
  Scope,
  TRANSPORT_HTTPS,
  transports,
} from '../src/runner/manifest/index.ts';
import {
  baseEntries,
  encode,
  type RawEntry,
  REPO_FIXTURES,
  rules,
  Tree,
  wantClean,
  wantRule,
} from './support/manifest.ts';
import { specText } from './support/repo.ts';

// The tokens of the entry fields conformance_profile, transport and layer,
// and the kinds transport, mcp and profile (spec/v1.0/fixtures/README.md,
// Manifest entry fields).
test('TestEntryFieldVocabulary', () => {
  assert.deepEqual(conformanceProfiles(), ['full', 'single-owner']);
  assert.deepEqual(transports(), ['https', 'stdio-ipc']);
  assert.deepEqual(layers(), ['transcript', 'os']);
  for (const [k, want] of [
    [Kind.TRANSPORT, 'transport'],
    [Kind.MCP, 'mcp'],
    [Kind.PROFILE, 'profile'],
  ] as const) {
    assert.equal(k, want);
    assert.ok(Kind.known(k), `${k} known`);
    assert.ok(Kind.hasExpected(k), `${k} has an expected result`);
  }
  // A source case carries its expectations inline and has no expected file
  // or outcome, as a key or an adapter asset; its scope is adapter.
  assert.equal(Kind.SOURCE_CASE, 'source-case');
  assert.ok(Kind.known(Kind.SOURCE_CASE));
  assert.ok(!Kind.hasExpected(Kind.SOURCE_CASE));
  assert.equal(Kind.requiredScope(Kind.SOURCE_CASE), Scope.ADAPTER);
  assert.equal(DEFAULT_CONFORMANCE_PROFILE, 'full');
  assert.equal(DEFAULT_TRANSPORT, 'https');
});

interface RegistryEntry {
  kind?: unknown;
  id?: unknown;
}

function registryIds(text: string, kind: string): string[] {
  const reg = strictParse(text) as RegistryEntry[];
  return reg.filter((e) => e.kind === kind).map((e) => (typeof e.id === 'string' ? e.id : ''));
}

// The conformance profile tokens are the entries of kind conformance in
// spec/v1.0/profiles/registry.json, in file order.
test('TestRegistryConformanceProfiles', (t) => {
  const text = specText(t, join(REPO_FIXTURES, '..', 'profiles', 'registry.json'));
  if (text === undefined) return;
  assert.deepEqual(conformanceProfiles(), registryIds(text, 'conformance'));
});

// The transport tokens are the transport profile ids of claim.transport in
// spec/v1.0/profiles/integration-profile.schema.json, the baseline https and the
// entries of kind transport in spec/v1.0/profiles/registry.json (draft section
// 21: a profile is identified by kind, id and version).
test('TestTransportProfiles', (t) => {
  const profiles = join(REPO_FIXTURES, '..', 'profiles');
  const schemaText = specText(t, join(profiles, 'integration-profile.schema.json'));
  if (schemaText === undefined) return;
  const schema = JSON.parse(schemaText) as {
    $defs: Record<string, { properties?: Record<string, { enum?: string[] }> }>;
  };
  let claimEnum: string[] | undefined;
  for (const d of Object.values(schema.$defs)) {
    const e = d.properties?.transport_profile?.enum;
    if (e !== undefined) claimEnum = e;
  }
  assert.deepEqual(transports(), claimEnum);
  const regText = specText(t, join(profiles, 'registry.json'));
  if (regText === undefined) return;
  assert.deepEqual(transports(), [TRANSPORT_HTTPS, ...registryIds(regText, 'transport')]);
});

// An absent conformance_profile means ["full"] and an absent transport
// ["https"]; the members as written are kept apart from the values that
// apply.
test('TestEntryFieldDefaults', () => {
  const es = baseEntries();
  const ev = es[1] as RawEntry;
  ev.conformance_profile = ['single-owner'];
  ev.transport = ['stdio-ipc', 'https'];
  ev.layer = 'transcript';
  const m = parse(encode(es));
  wantClean(m.validate());

  const e = m.entries[1];
  assert.ok(e);
  assert.deepEqual(e.conformanceProfile, ['single-owner']);
  assert.deepEqual(e.transport, ['stdio-ipc', 'https']);
  assert.equal(e.layer, 'transcript');
  assert.deepEqual(e.conformanceProfiles(), ['single-owner']);
  assert.deepEqual(e.transports(), ['stdio-ipc', 'https']);

  const d = m.entries[2];
  assert.ok(d);
  assert.equal(d.conformanceProfile, null);
  assert.equal(d.transport, null);
  assert.equal(d.layer, '');
  assert.deepEqual(d.conformanceProfiles(), ['full']);
  assert.deepEqual(d.transports(), ['https']);
  // The defaults are fresh arrays: a caller cannot change them.
  d.conformanceProfiles()[0] = 'x';
  d.transports()[0] = 'x';
  assert.equal(d.conformanceProfiles()[0], 'full');
  assert.equal(d.transports()[0], 'https');
});

// Breaks one field rule of conformance_profile, transport, layer or the
// scope of the new kinds at a time.
test('TestValidateEntryFields', async (t) => {
  const ev = 1; // the evaluate entry of baseEntries
  const key = 2;
  const withMembers =
    (i: number, ...kv: unknown[]) =>
    (es: RawEntry[]): RawEntry[] => {
      for (let j = 0; j < kv.length; j += 2) (es[i] as RawEntry)[kv[j] as string] = kv[j + 1];
      return es;
    };
  const cases: Record<string, [string, (es: RawEntry[]) => RawEntry[]]> = {
    'profile a string': [RULE_SHAPE, withMembers(ev, 'conformance_profile', 'full')],
    'profile null': [RULE_SHAPE, withMembers(ev, 'conformance_profile', null)],
    'profile item a number': [RULE_SHAPE, withMembers(ev, 'conformance_profile', [1])],
    'profile empty': [RULE_CONFORMANCE_PROFILE, withMembers(ev, 'conformance_profile', [])],
    'profile lite': [RULE_CONFORMANCE_PROFILE, withMembers(ev, 'conformance_profile', ['lite'])],
    'profile upper case': [
      RULE_CONFORMANCE_PROFILE,
      withMembers(ev, 'conformance_profile', ['FULL']),
    ],
    'profile repeated': [
      RULE_CONFORMANCE_PROFILE,
      withMembers(ev, 'conformance_profile', ['full', 'full']),
    ],
    'profile on a key': [
      RULE_CONFORMANCE_PROFILE,
      withMembers(key, 'conformance_profile', ['single_owner']),
    ],

    'transport a string': [RULE_SHAPE, withMembers(ev, 'transport', 'https')],
    'transport item null': [RULE_SHAPE, withMembers(ev, 'transport', [null])],
    'transport empty': [RULE_TRANSPORT, withMembers(ev, 'transport', [])],
    'transport tcp': [RULE_TRANSPORT, withMembers(ev, 'transport', ['tcp'])],
    // Channels are not transport profiles: no http, stdio or ipc.
    'transport http': [RULE_TRANSPORT, withMembers(ev, 'transport', ['http'])],
    'transport stdio': [RULE_TRANSPORT, withMembers(ev, 'transport', ['stdio'])],
    'transport ipc': [RULE_TRANSPORT, withMembers(ev, 'transport', ['ipc'])],
    'transport upper case': [RULE_TRANSPORT, withMembers(ev, 'transport', ['HTTPS'])],
    'transport with a version': [RULE_TRANSPORT, withMembers(ev, 'transport', ['stdio-ipc/0.1'])],
    'transport repeated': [
      RULE_TRANSPORT,
      withMembers(ev, 'transport', ['stdio-ipc', 'stdio-ipc']),
    ],

    'layer a number': [RULE_SHAPE, withMembers(ev, 'transport', ['stdio-ipc'], 'layer', 1)],
    'layer network': [RULE_LAYER, withMembers(ev, 'transport', ['stdio-ipc'], 'layer', 'network')],
    'layer empty': [RULE_LAYER, withMembers(ev, 'transport', ['stdio-ipc'], 'layer', '')],
    'layer on https': [RULE_LAYER, withMembers(ev, 'transport', ['https'], 'layer', 'transcript')],
    'layer without transport': [RULE_LAYER, withMembers(ev, 'layer', 'os')],
    'transport kind no layer': [
      RULE_LAYER,
      withMembers(ev, 'kind', 'transport', 'transport', ['stdio-ipc']),
    ],
    'transport kind on https': [RULE_LAYER, withMembers(ev, 'kind', 'transport')],

    'transport kind in core': [
      RULE_SCOPE,
      withMembers(
        ev,
        'kind',
        'transport',
        'scope',
        'core',
        'transport',
        ['stdio-ipc'],
        'layer',
        'os',
      ),
    ],
    'transport kind adapter': [
      RULE_SCOPE,
      withMembers(
        ev,
        'kind',
        'transport',
        'scope',
        'adapter',
        'transport',
        ['stdio-ipc'],
        'layer',
        'os',
      ),
    ],
    'profile kind in core': [RULE_SCOPE, withMembers(ev, 'kind', 'profile', 'scope', 'core')],
    'profile kind in adapter': [RULE_SCOPE, withMembers(ev, 'kind', 'profile', 'scope', 'adapter')],
    'mcp kind in core': [RULE_SCOPE, withMembers(ev, 'kind', 'mcp', 'scope', 'core')],
    'mcp kind in runner scope': [RULE_SCOPE, withMembers(ev, 'kind', 'mcp', 'scope', 'runner')],
  };
  for (const [name, [rule, edit]] of Object.entries(cases)) {
    await t.test(name, () => {
      const m = parse(encode(edit(baseEntries())));
      const where = name === 'profile on a key' ? 'keys/holder' : 'admission/valid';
      wantRule(m.validate(), rule, where);
    });
  }
});

// Every token of each field, a layer on every entry whose transport has
// stdio-ipc, and each new kind in its scope.
test('TestValidateAcceptsEntryFields', async (t) => {
  const cases: Record<string, RawEntry> = {
    full: { conformance_profile: ['full'] },
    'single-owner': { conformance_profile: ['single-owner'] },
    'both profiles': { conformance_profile: ['single-owner', 'full'] },
    https: { transport: ['https'] },
    'stdio-ipc': { transport: ['stdio-ipc'] },
    'stdio-ipc os': { transport: ['stdio-ipc'], layer: 'os' },
    'both, transcript': { transport: ['https', 'stdio-ipc'], layer: 'transcript' },
    'both, os': { transport: ['stdio-ipc', 'https'], layer: 'os' },
    'transport kind': {
      kind: 'transport',
      scope: 'runner',
      transport: ['stdio-ipc'],
      layer: 'transcript',
    },
    'profile kind': { kind: 'profile', scope: 'runner', conformance_profile: ['single-owner'] },
    'mcp kind': { kind: 'mcp', scope: 'adapter' },
    'stdio-ipc, no layer': { transport: ['stdio-ipc'] },
    'every field at once': {
      conformance_profile: ['full', 'single-owner'],
      transport: ['stdio-ipc'],
      layer: 'transcript',
      capabilities: ['jws-ed25519'],
    },
  };
  for (const [name, members] of Object.entries(cases)) {
    await t.test(name, () => {
      const es = baseEntries();
      Object.assign(es[1] as RawEntry, members);
      wantClean(parse(encode(es)).validate());
    });
  }
});

// One case of spec/v1.0/fixtures/testdata/manifest/index.json.
interface ManifestCase {
  file: string;
  valid: boolean;
  reason: string;
  // Checked against manifest.schema.json by the schema test of cli/pactconf.
  schema_errors?: unknown[];
  rules?: string[];
}

// Each test manifest of spec/v1.0/fixtures/testdata/manifest breaks exactly the
// field rules its index case lists, and a valid one none.
test('TestTestdataManifests', async (t) => {
  const dir = join(REPO_FIXTURES, 'testdata', 'manifest');
  const text = specText(t, join(dir, 'index.json'));
  if (text === undefined) return;
  const idx = strictParse(text) as { cases: ManifestCase[] };
  let valid = 0;
  let invalid = 0;
  for (const c of idx.cases) {
    if (c.valid) valid++;
    else invalid++;
    await t.test(c.file, () => {
      const m = parse(readFileSync(join(dir, c.file)));
      const got = rules(m.validate());
      const want = [...(c.rules ?? [])].sort();
      assert.deepEqual(got, want, c.reason);
      assert.equal(
        c.valid,
        want.length === 0 && (c.schema_errors ?? []).length === 0,
        `valid = ${c.valid}, but the case lists rules ${want} and schema errors ${(c.schema_errors ?? []).length}`,
      );
    });
  }
  assert.deepEqual([valid, invalid], [4, 9], 'valid and invalid cases');
  for (const f of readdirSync(dir)) {
    if (f !== 'index.json') {
      assert.ok(
        idx.cases.some((c) => c.file === f),
        `${f} is not in index.json`,
      );
    }
  }
});

// Files under testdata/ at the top of the fixture directory are the test
// data of the checks, not fixtures, and need no entry; a testdata directory
// anywhere else does.
test('TestCompletenessTestdata', () => {
  let tr = new Tree(baseEntries());
  tr.write('testdata/manifest/valid-defaults.json', '{}');
  tr.write('testdata/manifest/index.json', '{}');
  wantClean(completeness(tr.root, tr.manifest()));

  tr.write('keys/testdata/x.json', '{}');
  wantRule(completeness(tr.root, tr.manifest()), RULE_UNCOVERED, 'keys/testdata/x.json');

  tr = new Tree(baseEntries());
  tr.write('testdata/manifest/notes.txt', 'x');
  wantRule(completeness(tr.root, tr.manifest()), RULE_EXTENSION, 'testdata/manifest/notes.txt');
});
