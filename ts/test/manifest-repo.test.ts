// Port of go/runner/manifest/repo_test.go: the committed manifest, spec map
// and manifest.schema.json against the module.

import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import { parse as strictParse } from '../src/core/strictjson.ts';
import {
  ADAPTER_CASE_ID_PATTERN,
  capabilities,
  conformanceProfiles,
  DRAFT_SECTION_PATTERN,
  ID_PATTERN,
  Kind,
  kinds,
  layers,
  outcomes,
  PATH_PATTERN,
  parse,
  parseSpecMap,
  SCHEMA_FILE_NAME,
  SOURCE_CASE_ID_PATTERN,
  SPEC_MAP_ROW_PATTERN,
  scopes,
  transports,
  VERSION,
} from '../src/runner/manifest/index.ts';
import { REPO_FIXTURES, REPO_SPEC_MAP, wantClean } from './support/manifest.ts';
import { specText } from './support/repo.ts';

// Every committed entry follows the field rules.
test('TestRepoManifestValidates', (t) => {
  const text = specText(t, join(REPO_FIXTURES, 'manifest.json'));
  if (text === undefined) return;
  wantClean(parse(text).validate());
});

// The committed spec map has the tables the checks read.
test('TestRepoSpecMapParses', (t) => {
  const text = specText(t, REPO_SPEC_MAP);
  if (text === undefined) return;
  const [sm, ps] = parseSpecMap(text);
  wantClean(ps);
  assert.ok(sm !== undefined && sm.rows.length > 0 && sm.groups.size > 0, 'spec map parsed empty');
});

interface Def {
  pattern?: string;
  enum?: string[];
}

// manifest.schema.json, read by consumers in other languages, states the
// same enums and patterns as the module.
test('TestSchemaMatchesValidator', (t) => {
  const text = specText(t, join(REPO_FIXTURES, SCHEMA_FILE_NAME));
  if (text === undefined) return;
  // The schema is strict JSON.
  const schema = strictParse(text) as {
    $schema: string;
    $defs: Record<string, Def>;
    properties: { manifest_version: { const: number } };
  };
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.properties.manifest_version.const, VERSION);
  const patterns: Record<string, string> = {
    id: ID_PATTERN,
    adapter_case_id: ADAPTER_CASE_ID_PATTERN,
    // The file of an adapter case: its id followed by .json.
    adapter_case_path: `${ADAPTER_CASE_ID_PATTERN.replace(/\$$/, '')}\\.json$`,
    source_case_id: SOURCE_CASE_ID_PATTERN,
    // The file of a source case: its id followed by .json.
    source_case_path: `${SOURCE_CASE_ID_PATTERN.replace(/\$$/, '')}\\.json$`,
    path: PATH_PATTERN,
    spec_map_row: SPEC_MAP_ROW_PATTERN,
    draft_section: DRAFT_SECTION_PATTERN,
  };
  for (const [def, want] of Object.entries(patterns)) {
    const got = schema.$defs[def]?.pattern;
    assert.equal(got, want, `$defs/${def} pattern`);
    assert.doesNotThrow(() => new RegExp(got ?? ''), `$defs/${def} pattern compiles`);
  }
  const enums: Record<string, string[]> = {
    kind: kinds(),
    scope: scopes(),
    outcome: outcomes(),
    capability: capabilities(),
    conformance_profile_id: conformanceProfiles(),
    transport_name: transports(),
    layer: layers(),
  };
  for (const [def, want] of Object.entries(enums)) {
    assert.deepEqual(schema.$defs[def]?.enum, want, `$defs/${def} enum`);
  }
});

interface Cond {
  properties?: Record<string, { $ref?: string; const?: string }>;
  required?: string[];
  if?: Cond;
  then?: Cond;
  else?: Cond;
}

// manifest.schema.json applies the adapter case id and path patterns to
// adapter-case entries, the source case id and path patterns to source-case
// entries and the plain id pattern to every other entry, as the module does.
// The rule that the path is the id followed by .json is not expressible in
// JSON Schema.
test('TestSchemaAdapterCaseLayout', (t) => {
  const text = specText(t, join(REPO_FIXTURES, SCHEMA_FILE_NAME));
  if (text === undefined) return;
  const schema = JSON.parse(text) as {
    $defs: {
      entry: { properties: Record<string, { anyOf?: { $ref: string }[] }>; allOf: Cond[] };
    };
  };
  const entry = schema.$defs.entry;
  assert.deepEqual(
    (entry.properties.id?.anyOf ?? []).map((s) => s.$ref),
    ['#/$defs/id', '#/$defs/adapter_case_id', '#/$defs/source_case_id'],
  );
  // Checks that c applies to kind the id and path definitions of its then
  // branch and returns its else branch.
  const layout = (
    c: Cond | undefined,
    kind: string,
    id: string,
    path: string,
  ): Cond | undefined => {
    assert.ok(c?.if && c.then, `no condition on kind ${kind}`);
    assert.equal(c.if.properties?.kind?.const, kind);
    assert.ok(c.if.required?.includes('kind'), `the ${kind} condition does not require kind`);
    assert.equal(c.then.properties?.id?.$ref, id, `${kind} id`);
    assert.equal(c.then.properties?.path?.$ref, path, `${kind} path`);
    return c.else;
  };
  let found = false;
  for (const c of entry.allOf) {
    if (c.if?.properties?.kind?.const !== Kind.ADAPTER_CASE) continue;
    found = true;
    let other = layout(
      c,
      Kind.ADAPTER_CASE,
      '#/$defs/adapter_case_id',
      '#/$defs/adapter_case_path',
    );
    other = layout(other, Kind.SOURCE_CASE, '#/$defs/source_case_id', '#/$defs/source_case_path');
    assert.equal(other?.properties?.id?.$ref, '#/$defs/id', 'the id of other kinds');
  }
  assert.ok(found, 'no allOf condition on kind adapter-case in $defs/entry');
});
