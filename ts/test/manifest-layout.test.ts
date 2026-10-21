// Port of the case-layout tests of go/runner/manifest/manifest_test.go:
// adapter-case and source-case entries (spec/v1.0/fixtures/README.md, Manifest).

import { test } from 'node:test';
import {
  parse,
  RULE_ADAPTER_CASE_PATH,
  RULE_EXPECTED,
  RULE_ID,
  RULE_OUTCOME,
  RULE_PATH,
  RULE_SCOPE,
  RULE_SOURCE_CASE_PATH,
} from '../src/runner/manifest/index.ts';
import { encode, type RawEntry, wantClean, wantRule } from './support/manifest.ts';

// An adapter-case entry with the given id and path.
function adapterCase(id: string, path: string): RawEntry {
  return {
    id,
    kind: 'adapter-case',
    scope: 'adapter',
    path,
    expected: path,
    outcome: 'REJECTED',
    spec_map_row: 'COMMON-03',
    draft_section: '10.2',
  };
}

// An adapter case is the file adapters/<adapter>/<case>.json with the id
// adapters/<adapter>/<case>, for adapters/_common and every adapter alike,
// with no cases/ subdirectory (spec/v1.0/fixtures/README.md, Manifest).
test('TestValidateAdapterCaseLayout', async (t) => {
  for (const [id, path] of [
    ['adapters/_common/common-03.fragment', 'adapters/_common/common-03.fragment.json'],
    ['adapters/_common/fresh-02.at-limit', 'adapters/_common/fresh-02.at-limit.json'],
    ['adapters/files/files-01.symlink', 'adapters/files/files-01.symlink.json'],
    ['adapters/oauth/oauth-02', 'adapters/oauth/oauth-02.json'],
  ] as const) {
    await t.test(id, () => {
      wantClean(parse(encode([adapterCase(id, path)])).validate());
    });
  }

  const cases: Record<string, [string, string, string]> = {
    'cases subdirectory': [
      'adapters/_common/common-03.fragment',
      'adapters/_common/cases/common-03.fragment.json',
      RULE_ADAPTER_CASE_PATH,
    ],
    'path of another case': [
      'adapters/_common/common-03.fragment',
      'adapters/_common/common-03.headers.json',
      RULE_ADAPTER_CASE_PATH,
    ],
    'path without .json': [
      'adapters/_common/common-03.fragment',
      'adapters/_common/common-03.fragment',
      RULE_ADAPTER_CASE_PATH,
    ],
    'path with another extension': [
      'adapters/_common/common-03.fragment',
      'adapters/_common/common-03.fragment.yaml',
      RULE_ADAPTER_CASE_PATH,
    ],
    'path the adapter directory': [
      'adapters/_common/common-03.fragment',
      'adapters/_common',
      RULE_ADAPTER_CASE_PATH,
    ],
    'path in another adapter': [
      'adapters/_common/common-03.fragment',
      'adapters/files/common-03.fragment.json',
      RULE_ADAPTER_CASE_PATH,
    ],
    'id outside adapters': ['vectors/zz-case', 'vectors/zz-case.json', RULE_ADAPTER_CASE_PATH],
    'id of two segments': ['adapters/zz-case', 'adapters/zz-case.json', RULE_ADAPTER_CASE_PATH],
    'id with an underscore group': [
      '_adapters/_common/zz-case',
      '_adapters/_common/zz-case.json',
      RULE_ADAPTER_CASE_PATH,
    ],
    // A malformed id or path is reported by its own rule only.
    'id upper case': ['adapters/_common/Common-03', 'adapters/_common/Common-03.json', RULE_ID],
    'id of four segments': [
      'adapters/_common/cases/zz-case',
      'adapters/_common/cases/zz-case.json',
      RULE_ID,
    ],
    'path dot dot': ['adapters/_common/zz-case', 'adapters/../zz-case.json', RULE_PATH],
  };
  for (const [name, [id, path, rule]] of Object.entries(cases)) {
    await t.test(name, () => {
      const e = adapterCase(id, path);
      if (rule === RULE_PATH) e.expected = `${id}.json`; // so that only the path rule speaks
      wantRule(parse(encode([e])).validate(), rule, id);
    });
  }
});

// A source-case entry with the given id and path: scope adapter, and neither
// an expected file nor an outcome.
function sourceCase(id: string, path: string): RawEntry {
  return {
    id,
    kind: 'source-case',
    scope: 'adapter',
    path,
    expected: null,
    outcome: null,
    spec_map_row: 'CL-17.2',
    draft_section: '17.2',
  };
}

// A source case is the file sources/<source>/<case>.json with the id
// sources/<source>/<case>; its case segment may contain "." as an adapter
// case's does, and it has scope adapter and no expected file or outcome
// (spec/v1.0/fixtures/README.md, Manifest).
test('TestValidateSourceCaseLayout', async (t) => {
  for (const [id, path] of [
    ['sources/scim/scim-01.join', 'sources/scim/scim-01.join.json'],
    ['sources/shared-signals/ssf-02', 'sources/shared-signals/ssf-02.json'],
  ] as const) {
    await t.test(id, () => {
      wantClean(parse(encode([sourceCase(id, path)])).validate());
    });
  }

  type Edit = ((e: RawEntry) => void) | undefined;
  const cases: Record<string, [string, string, string, Edit]> = {
    'cases subdirectory': [
      'sources/scim/scim-01.join',
      'sources/scim/cases/scim-01.join.json',
      RULE_SOURCE_CASE_PATH,
      undefined,
    ],
    'path without .json': [
      'sources/scim/scim-01.join',
      'sources/scim/scim-01.join',
      RULE_SOURCE_CASE_PATH,
      undefined,
    ],
    'path of another case': [
      'sources/scim/scim-01.join',
      'sources/scim/scim-02.json',
      RULE_SOURCE_CASE_PATH,
      undefined,
    ],
    'id outside sources': [
      'adapters/scim/scim-01',
      'adapters/scim/scim-01.json',
      RULE_SOURCE_CASE_PATH,
      undefined,
    ],
    'id of two segments': [
      'sources/scim-01',
      'sources/scim-01.json',
      RULE_SOURCE_CASE_PATH,
      undefined,
    ],
    'source with a dot': [
      'sources/sc.im/scim-01',
      'sources/sc.im/scim-01.json',
      RULE_SOURCE_CASE_PATH,
      undefined,
    ],
    'source with an underscore': [
      'sources/_scim/scim-01',
      'sources/_scim/scim-01.json',
      RULE_SOURCE_CASE_PATH,
      undefined,
    ],
    'case with an underscore': [
      'sources/scim/_scim-01',
      'sources/scim/_scim-01.json',
      RULE_SOURCE_CASE_PATH,
      undefined,
    ],
    'scope core': [
      'sources/scim/scim-01',
      'sources/scim/scim-01.json',
      RULE_SCOPE,
      (e) => {
        e.scope = 'core';
      },
    ],
    'scope runner': [
      'sources/scim/scim-01',
      'sources/scim/scim-01.json',
      RULE_SCOPE,
      (e) => {
        e.scope = 'runner';
      },
    ],
    'expected set': [
      'sources/scim/scim-01',
      'sources/scim/scim-01.json',
      RULE_EXPECTED,
      (e) => {
        e.expected = 'sources/scim/scim-01.json';
      },
    ],
    'outcome set': [
      'sources/scim/scim-01',
      'sources/scim/scim-01.json',
      RULE_OUTCOME,
      (e) => {
        e.outcome = 'ACCEPTED';
      },
    ],
    // A malformed id is reported by its own rule only.
    'id of four segments': [
      'sources/scim/cases/scim-01',
      'sources/scim/cases/scim-01.json',
      RULE_ID,
      undefined,
    ],
  };
  for (const [name, [id, path, rule, edit]] of Object.entries(cases)) {
    await t.test(name, () => {
      const e = sourceCase(id, path);
      edit?.(e);
      wantRule(parse(encode([e])).validate(), rule, id);
    });
  }

  // Only adapter-case and source-case ids may have a "." in a segment.
  const e = sourceCase('sources/scim/scim-01.join', 'sources/scim/scim-01.join.json');
  e.kind = 'vector';
  e.expected = 'sources/scim/scim-01.join.json';
  e.outcome = 'MATCH';
  wantRule(parse(encode([e])).validate(), RULE_ID, 'sources/scim/scim-01.join');
});
