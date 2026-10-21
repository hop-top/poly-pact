// Port of go/runner/manifest/manifest_test.go. Expected rules come from the
// field rules of spec/v1.0/fixtures/README.md (Manifest) and draft section 7.1.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { StrictJSONError } from '../src/core/strictjson.ts';
import {
  CAPABILITY_JWS_ED25519,
  capabilities,
  Kind,
  Problems,
  parse,
  RULE_CAPABILITIES,
  RULE_DRAFT_SECTION,
  RULE_EXPECTED,
  RULE_ID,
  RULE_ID_DUPLICATE,
  RULE_JSON,
  RULE_KIND,
  RULE_ORDER,
  RULE_OUTCOME,
  RULE_PATH,
  RULE_SCOPE,
  RULE_SHAPE,
  RULE_SPEC_MAP_ROW,
  Scope,
} from '../src/runner/manifest/index.ts';
import {
  baseEntries,
  encode,
  mustContain,
  type RawEntry,
  wantClean,
  wantRule,
} from './support/manifest.ts';

test('TestParseAcceptsBase', () => {
  const m = parse(encode(baseEntries()));
  wantClean(m.validate());
  assert.equal(m.version, 1);
  assert.equal(m.entries.length, 4);
  const e = m.entries[1];
  assert.ok(e);
  assert.equal(e.id, 'admission/valid');
  assert.equal(e.kind, Kind.EVALUATE);
  assert.equal(e.scope, Scope.RUNNER);
  assert.equal(e.path, 'admission/valid');
  assert.equal(e.expected, 'expected/admission/valid/decision.json');
  assert.equal(e.outcome, 'ADMISSIBLE');
  assert.equal(e.specMapRow, 'CL-11.3');
  assert.equal(e.draftSection, '11.3');
  const k = m.entries[2];
  assert.equal(k?.expected, null);
  assert.equal(k?.outcome, null);
  assert.equal(m.lookup('keys/holder')?.path, 'keys/holder.jwk.json');
  assert.equal(m.lookup('keys/nobody'), undefined);
});

// The manifest is read with the parse rules of draft section 7.1, before any
// field rule.
test('TestParseIsStrict', async (t) => {
  const cases: Record<string, [string, string | undefined]> = {
    'duplicate member': ['{"manifest_version":1,"entries":[],"entries":[]}', 'DUPLICATE_KEY'],
    'nested duplicate member': [
      '{"manifest_version":1,"entries":[{"id":"a/b","id":"a/c"}]}',
      'DUPLICATE_KEY',
    ],
    'non-finite number': ['{"manifest_version":NaN,"entries":[]}', 'NON_FINITE'],
    'invalid UTF-8': ['', 'INVALID_UTF8'],
    'lone surrogate': ['{"manifest_version":1,"entries":["\\ud800"]}', 'LONE_SURROGATE'],
    'byte order mark': ['﻿{"manifest_version":1,"entries":[]}', 'SYNTAX'],
    'trailing data': ['{"manifest_version":1,"entries":[]} {}', 'TRAILING_DATA'],
    'not an object': ['[]', undefined],
  };
  const invalidUTF8 = Uint8Array.from([
    ...new TextEncoder().encode('{"manifest_version":1,"entries":["'),
    0xff,
    ...new TextEncoder().encode('"]}'),
  ]);
  for (const [name, [text, kind]] of Object.entries(cases)) {
    await t.test(name, () => {
      const input = name === 'invalid UTF-8' ? invalidUTF8 : text;
      let thrown: unknown;
      try {
        parse(input);
      } catch (err) {
        thrown = err;
      }
      assert.ok(thrown !== undefined, 'parse accepted it');
      assert.ok(thrown instanceof Problems, `error ${String(thrown)}, want Problems`);
      assert.equal(thrown.length, 1);
      assert.equal(thrown[0]?.rule, RULE_JSON);
      if (kind !== undefined) {
        const cause = thrown.cause[0];
        assert.ok(cause instanceof StrictJSONError, `cause ${String(cause)}`);
        assert.equal(cause.kind, kind);
      }
    });
  }
});

// Breaks one rule at a time and expects exactly that rule.
test('TestValidateRules', async (t) => {
  type Edit = (es: RawEntry[]) => RawEntry[];
  const set =
    (i: number, k: string, v: unknown): Edit =>
    (es) => {
      (es[i] as RawEntry)[k] = v;
      return es;
    };
  const drop =
    (i: number, k: string): Edit =>
    (es) => {
      delete (es[i] as RawEntry)[k];
      return es;
    };
  const ev = 1; // index of the evaluate entry in baseEntries
  const key = 2;
  const cases: Record<string, [string, string, Edit]> = {
    'missing id': [RULE_SHAPE, 'entries[1]', drop(ev, 'id')],
    'missing kind': [RULE_SHAPE, 'admission/valid', drop(ev, 'kind')],
    'missing scope': [RULE_SHAPE, 'admission/valid', drop(ev, 'scope')],
    'missing path': [RULE_SHAPE, 'admission/valid', drop(ev, 'path')],
    'missing expected': [RULE_SHAPE, 'admission/valid', drop(ev, 'expected')],
    'missing outcome': [RULE_SHAPE, 'admission/valid', drop(ev, 'outcome')],
    'missing spec_map_row': [RULE_SHAPE, 'admission/valid', drop(ev, 'spec_map_row')],
    'missing draft_section': [RULE_SHAPE, 'admission/valid', drop(ev, 'draft_section')],
    'unknown member': [RULE_SHAPE, 'admission/valid', set(ev, 'note', 'x')],
    'id not a string': [RULE_SHAPE, 'entries[1]', set(ev, 'id', 7)],
    'kind not a string': [RULE_SHAPE, 'admission/valid', set(ev, 'kind', true)],
    'path not a string': [RULE_SHAPE, 'admission/valid', set(ev, 'path', ['a'])],
    'expected a number': [RULE_SHAPE, 'admission/valid', set(ev, 'expected', 1)],
    'draft_section number': [RULE_SHAPE, 'admission/valid', set(ev, 'draft_section', 11.3)],

    'id one segment': [RULE_ID, 'admission', set(ev, 'id', 'admission')],
    'id four segments': [RULE_ID, 'admission/b/c/d', set(ev, 'id', 'admission/b/c/d')],
    'id upper case': [RULE_ID, 'admission/Valid', set(ev, 'id', 'admission/Valid')],
    'id underscore inside': [RULE_ID, 'admission/va_lid', set(ev, 'id', 'admission/va_lid')],
    'id trailing hyphen': [RULE_ID, 'admission/valid-', set(ev, 'id', 'admission/valid-')],
    'id empty segment': [RULE_ID, 'admission//valid', set(ev, 'id', 'admission//valid')],
    'id empty': [RULE_ID, 'entries[1]', set(ev, 'id', '')],

    // Only adapter-case ids, which follow their file names, may start a
    // segment with "_" or have a "." in one.
    'id dot in a key': [RULE_ID, 'keys/holder.v2', set(key, 'id', 'keys/holder.v2')],
    'id leading underscore in a key': [RULE_ID, 'keys/_holder', set(key, 'id', 'keys/_holder')],
    'id leading underscore in a case': [
      RULE_ID,
      'admission/_valid',
      set(ev, 'id', 'admission/_valid'),
    ],
    'id dot in an adapter asset': [
      RULE_ID,
      'adapters/db/schema.v2',
      set(0, 'id', 'adapters/db/schema.v2'),
    ],
    'id underscore in an adapter asset': [
      RULE_ID,
      'adapters/_db/schema',
      set(0, 'id', 'adapters/_db/schema'),
    ],
    // An unknown kind is reported once, by its own rule.
    'id underscore with an unknown kind': [
      RULE_KIND,
      'admission/_valid',
      (es) => {
        (es[ev] as RawEntry).kind = 'evaluation';
        (es[ev] as RawEntry).id = 'admission/_valid';
        return es;
      },
    ],

    'kind unknown': [RULE_KIND, 'admission/valid', set(ev, 'kind', 'evaluation')],
    'scope unknown': [RULE_SCOPE, 'admission/valid', set(ev, 'scope', 'sdk')],

    'path absolute': [RULE_PATH, 'admission/valid', set(ev, 'path', '/admission/valid')],
    'path dot dot': [RULE_PATH, 'admission/valid', set(ev, 'path', 'admission/../keys')],
    'path dot': [RULE_PATH, 'admission/valid', set(ev, 'path', './admission/valid')],
    'path empty segment': [RULE_PATH, 'admission/valid', set(ev, 'path', 'admission//valid')],
    'path trailing slash': [RULE_PATH, 'admission/valid', set(ev, 'path', 'admission/valid/')],
    'path backslash': [RULE_PATH, 'admission/valid', set(ev, 'path', 'admission\\valid')],
    'path empty': [RULE_PATH, 'admission/valid', set(ev, 'path', '')],
    'path hidden': [RULE_PATH, 'admission/valid', set(ev, 'path', 'admission/.valid')],
    'path space': [RULE_PATH, 'admission/valid', set(ev, 'path', 'admission/va lid')],

    'expected null for evaluate': [RULE_EXPECTED, 'admission/valid', set(ev, 'expected', null)],
    'expected set for key': [
      RULE_EXPECTED,
      'keys/holder',
      set(key, 'expected', 'keys/holder.jwk.json'),
    ],
    'expected absolute': [
      RULE_EXPECTED,
      'admission/valid',
      set(ev, 'expected', '/expected/x.json'),
    ],
    'expected dot dot': [RULE_EXPECTED, 'admission/valid', set(ev, 'expected', '../x.json')],
    'outcome null for evaluate': [RULE_OUTCOME, 'admission/valid', set(ev, 'outcome', null)],
    'outcome set for key': [RULE_OUTCOME, 'keys/holder', set(key, 'outcome', 'MATCH')],
    'outcome unknown token': [RULE_OUTCOME, 'admission/valid', set(ev, 'outcome', 'PASS')],
    'outcome lower case': [RULE_OUTCOME, 'admission/valid', set(ev, 'outcome', 'admissible')],
    'spec_map_row empty': [RULE_SPEC_MAP_ROW, 'admission/valid', set(ev, 'spec_map_row', '')],
    'spec_map_row lower case': [
      RULE_SPEC_MAP_ROW,
      'admission/valid',
      set(ev, 'spec_map_row', 'cl-11.3'),
    ],
    'draft_section trailing dot': [
      RULE_DRAFT_SECTION,
      'admission/valid',
      set(ev, 'draft_section', '11.3.'),
    ],
    'draft_section lower letter': [
      RULE_DRAFT_SECTION,
      'admission/valid',
      set(ev, 'draft_section', 'c'),
    ],
    'draft_section leading zero': [
      RULE_DRAFT_SECTION,
      'admission/valid',
      set(ev, 'draft_section', '011'),
    ],
    'draft_section empty': [RULE_DRAFT_SECTION, 'admission/valid', set(ev, 'draft_section', '')],
    'draft_section with a prefix': [
      RULE_DRAFT_SECTION,
      'admission/valid',
      set(ev, 'draft_section', 'Section 11.3'),
    ],

    'capabilities a string': [
      RULE_SHAPE,
      'admission/valid',
      set(ev, 'capabilities', 'jws-ed25519'),
    ],
    'capabilities null': [RULE_SHAPE, 'admission/valid', set(ev, 'capabilities', null)],
    'capability not a string': [RULE_SHAPE, 'admission/valid', set(ev, 'capabilities', [1])],
    'capability null': [RULE_SHAPE, 'admission/valid', set(ev, 'capabilities', [null])],
    'capabilities empty': [RULE_CAPABILITIES, 'admission/valid', set(ev, 'capabilities', [])],
    'capability unknown': [
      RULE_CAPABILITIES,
      'admission/valid',
      set(ev, 'capabilities', ['ed25519']),
    ],
    'capability upper case': [
      RULE_CAPABILITIES,
      'admission/valid',
      set(ev, 'capabilities', ['JWS-ED25519']),
    ],
    'capability repeated': [
      RULE_CAPABILITIES,
      'admission/valid',
      set(ev, 'capabilities', ['jws-ed25519', 'jws-ed25519']),
    ],
    'capability unknown on key': [
      RULE_CAPABILITIES,
      'keys/holder',
      set(key, 'capabilities', ['ES256']),
    ],

    'duplicate id': [
      RULE_ID_DUPLICATE,
      'keys/holder',
      (es) => [...es.slice(0, key + 1), { ...es[key] }, ...es.slice(key + 1)],
    ],
    unsorted: [
      RULE_ORDER,
      'adapters/db/schema',
      (es) => [es[1] as RawEntry, es[0] as RawEntry, ...es.slice(2)],
    ],
  };
  for (const [name, [rule, where, edit]] of Object.entries(cases)) {
    await t.test(name, () => {
      const m = parse(encode(edit(baseEntries())));
      wantRule(m.validate(), rule, where);
    });
  }
});

test('TestValidateAcceptsExistingIDForms', () => {
  for (const [id, kind, path] of [
    ['admission/valid', 'evaluate', 'admission/valid'],
    [
      'outcomes/qualification/correction-recompute',
      'outcomes',
      'outcomes/qualification/correction-recompute',
    ],
    ['vectors/jws/es256-r-equals-n', 'vector', 'vectors/jws/es256-r-equals-n.json'],
    [
      'adapters/_common/common-03.fragment',
      'adapter-case',
      'adapters/_common/common-03.fragment.json',
    ],
    ['keys/reputation-service', 'vector', 'keys/reputation-service.jwk.json'],
  ]) {
    const es = [
      {
        id,
        kind,
        scope: 'core',
        path,
        expected: 'a.json',
        outcome: 'MATCH',
        spec_map_row: 'CL-17.3.1',
        draft_section: 'B.7',
      },
    ];
    wantClean(parse(encode(es)).validate());
  }
});

// The outcome tokens of spec/v1.0/fixtures/README.md, the decisions of draft
// section 11.4 and the qualification results of draft section 14.3 among
// them.
test('TestValidateAcceptsEveryOutcome', () => {
  for (const outcome of [
    'ADMISSIBLE',
    'INADMISSIBLE',
    'DEFERRED',
    'ACCEPTED',
    'REJECTED',
    'QUALIFIED',
    'UNQUALIFIED',
    'DISPUTED',
    'MATCH',
  ]) {
    const es = baseEntries();
    (es[1] as RawEntry).outcome = outcome;
    wantClean(parse(encode(es)).validate());
  }
});

test('TestValidateTopLevel', async (t) => {
  const cases: Record<string, string> = {
    'version 2': '{"manifest_version":2,"entries":[]}',
    'version string': '{"manifest_version":"1","entries":[]}',
    'version missing': '{"entries":[]}',
    'entries missing': '{"manifest_version":1}',
    'entries an object': '{"manifest_version":1,"entries":{}}',
    'entries null': '{"manifest_version":1,"entries":null}',
    'unknown member': '{"manifest_version":1,"entries":[],"generated":true}',
    'entry not object': '{"manifest_version":1,"entries":["admission/valid"]}',
  };
  for (const [name, text] of Object.entries(cases)) {
    await t.test(name, () => {
      wantRule(parse(text).validate(), RULE_SHAPE, '');
    });
  }
});

test('TestProblemsFormat', () => {
  const es = baseEntries();
  (es[1] as RawEntry).kind = 'evaluation';
  const ps = parse(encode(es)).validate();
  assert.ok(ps.err() !== undefined, 'err() is undefined');
  mustContain(ps.message, '[entry-kind]', 'admission/valid', 'evaluation');
  assert.equal(new Problems().err(), undefined, 'empty Problems has an error');
  assert.ok(String(ps[0]).startsWith('[entry-kind] admission/valid: '), `toString() = ${ps[0]}`);
});

// capabilities is an optional member of an entry, the optional capabilities
// the entry tests (spec/v1.0/fixtures/README.md, Optional capabilities). An entry
// without it is mandatory.
test('TestValidateCapabilities', () => {
  assert.deepEqual(capabilities(), [CAPABILITY_JWS_ED25519]);
  assert.equal(CAPABILITY_JWS_ED25519, 'jws-ed25519');
  const es = baseEntries();
  (es[1] as RawEntry).capabilities = ['jws-ed25519'];
  const m = parse(encode(es));
  wantClean(m.validate());
  assert.deepEqual(m.entries[1]?.capabilities, ['jws-ed25519']);
  for (const [i, e] of m.entries.entries()) {
    if (i !== 1) assert.equal(e.capabilities, null, `${e.id}: capabilities, want null`);
  }
  // A malformed member decodes as null, so a caller that skips validate
  // never reads it as a capability list.
  (es[1] as RawEntry).capabilities = ['jws-ed25519', 1];
  assert.equal(parse(encode(es)).entries[1]?.capabilities, null);
});
