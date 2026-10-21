// Port of go/core/schema_drift_test.go: the generated tables of
// src/core/shapes.ts, src/core/types.ts and src/core/enums.ts against the
// vendored schema, schema/pact.schema.json (make ts-check-schema keeps that
// equal to spec/v1.0/schemas/pact.schema.json), and the enum values against
// go/core/enums.go where the Go sources are present.
//
// The expected member descriptors and TypeScript types are derived here from
// the schema, independently of scripts/gen-types.ts.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { VERSION } from '../src/core/limits.ts';
import { shapes } from '../src/core/shapes.ts';
import { ENUM_NAMES, enumOf } from './support/enums.ts';
import { goSource, PACKAGE, REPO, SCHEMA } from './support/repo.ts';

const DIGEST_PATTERN = '^[A-Za-z0-9_-]{43}$';
const TYPES = join(PACKAGE, 'src', 'core', 'types.ts');
const GO_ENUMS = join(REPO, 'go', 'core', 'enums.go');

// Every $defs entry; the test fails when the schema gains or loses an entry
// that this table does not follow.
const DEF_NAMES: readonly string[] = [
  'AgentProfile',
  'Intent',
  'OperationContext',
  'FieldRule',
  'RequirementContract',
  'Claim',
  'Evidence',
  'Presentation',
  'CheckResult',
  'AdmissionAttestation',
  'ReputationContext',
  'DimensionStats',
  'ReputationValue',
  'ReputationSnapshot',
  'Attribution',
  'OutcomeReport',
  'AdaptiveControl',
  'DataPolicy',
  'MetricBound',
  'EvaluationPolicy',
  'LearningPolicy',
  'LearningArtifact',
  'LearningEvent',
  'ContractRequest',
  'EvaluationRequest',
  'ReputationQuery',
  'ReceiptQuery',
  'Acknowledgment',
  'NativeAdapter',
  'GatewayMetadata',
  'Problem',
];

// The payload-only $defs entries: payload schemas of extension values, not in
// the root oneOf and reached by no wire object, with no shape (go/core
// payloadOnly).
const PAYLOAD_ONLY: readonly string[] = ['ConformanceDeclaration', 'TransportDeclaration'];

// The inline objects that have a shape of their own (Go helper structs).
const INLINE: Readonly<Record<string, string>> = {
  'GatewayMetadata.endpoints': 'GatewayEndpoints',
  'ReputationValue.dimensions': 'ReputationDimensions',
};

type Schema = Readonly<Record<string, unknown>>;

interface ShapeTable {
  readonly required: readonly string[];
  readonly optional: readonly string[];
  readonly members?: Readonly<Record<string, unknown>>;
}

const schema = JSON.parse(readFileSync(SCHEMA, 'utf8')) as {
  oneOf: unknown;
  $defs: Record<string, Schema>;
};
const defs = schema.$defs;
const table = shapes as unknown as Readonly<Record<string, ShapeTable>>;

function asSchema(v: unknown): Schema {
  return typeof v === 'object' && v !== null ? (v as Schema) : {};
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  return JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
}

/** Collects problems and the facts later checks need, like Go's drift. */
class Drift {
  readonly problems: string[] = [];
  readonly shapesReached = new Set<string>();
  readonly enums = new Map<string, readonly string[]>();
  /** The expected TypeScript type of each member, by `Shape.member`. */
  readonly tsTypes = new Map<string, string>();

  fail(msg: string): void {
    this.problems.push(msg);
  }

  checkShape(path: string, name: string, sch: Schema): void {
    const got = table[name];
    if (got === undefined) {
      this.fail(`${path}: no shape ${name}`);
      return;
    }
    this.shapesReached.add(name);
    if (sch.type !== 'object')
      this.fail(`${path}: schema type is ${String(sch.type)}, want object`);
    if (sch.additionalProperties !== false) {
      this.fail(
        `${path}: additionalProperties is not false (unknown core fields must stay rejected)`,
      );
    }
    const props = asSchema(sch.properties);
    const names = Object.keys(props);
    const required = (sch.required ?? []) as readonly string[];
    for (const r of required) {
      if (!names.includes(r)) this.fail(`${path}: required ${r} is not a property`);
    }
    const wantRequired = names.filter((n) => required.includes(n));
    const wantOptional = names.filter((n) => !required.includes(n));
    if (JSON.stringify(got.required) !== JSON.stringify(wantRequired)) {
      this.fail(
        `${path}: required is ${JSON.stringify(got.required)}, schema ${JSON.stringify(wantRequired)}`,
      );
    }
    if (JSON.stringify(got.optional) !== JSON.stringify(wantOptional)) {
      this.fail(
        `${path}: optional is ${JSON.stringify(got.optional)}, schema ${JSON.stringify(wantOptional)}`,
      );
    }
    const members = got.members ?? {};
    if (JSON.stringify(Object.keys(members)) !== JSON.stringify(names)) {
      this.fail(
        `${path}: members are ${JSON.stringify(Object.keys(members))}, schema properties ${JSON.stringify(names)}`,
      );
    }
    for (const n of names) {
      const ts = this.checkMember(`${path}.${n}`, `${name}.${n}`, asSchema(props[n]), members[n]);
      this.tsTypes.set(`${name}.${n}`, ts);
    }
  }

  /** Checks one member descriptor and returns the TypeScript type the schema gives it. */
  checkMember(path: string, key: string, sch: Schema, got: unknown): string {
    const want = (d: Readonly<Record<string, unknown>>, ts: string): string => {
      if (JSON.stringify(got) !== JSON.stringify(d)) {
        this.fail(
          `${path}: descriptor is ${JSON.stringify(got)}, schema wants ${JSON.stringify(d)}`,
        );
      }
      return ts;
    };
    const g = asSchema(got);
    // An anyOf beside a type only constrains values of that type (the
    // URI-or-token items of GatewayMetadata.extensions_supported).
    if (Array.isArray(sch.anyOf) && sch.type === undefined) {
      const opts = sch.anyOf as readonly unknown[];
      if (opts.length === 2 && JSON.stringify(opts[1]) === '{"type":"null"}') {
        if (g.type !== 'nullable') {
          this.fail(`${path}: schema allows null, descriptor is ${JSON.stringify(got)}`);
          return '?';
        }
        const inner = this.checkMember(path, key, asSchema(opts[0]), g.of);
        return `${inner} | null`;
      }
      // object-or-boolean: free-form JSON.
      return want({ type: 'raw' }, 'RawJSON');
    }
    if (typeof sch.$ref === 'string') {
      const name = sch.$ref.replace(/^#\/\$defs\//, '');
      if (!DEF_NAMES.includes(name)) this.fail(`${path}: $ref to unknown def ${name}`);
      return want({ type: 'shape', name }, name);
    }
    if (Array.isArray(sch.enum)) {
      const vals = sch.enum as readonly string[];
      const name = typeof g.name === 'string' ? g.name : '';
      if (g.type !== 'enum' || !ENUM_NAMES.includes(name)) {
        this.fail(
          `${path}: schema enum ${JSON.stringify(vals)} needs a registered enum, descriptor is ${JSON.stringify(got)}`,
        );
        return '?';
      }
      want({ type: 'enum', name }, name);
      const set = enumOf(name).values;
      if (!sameSet(set, vals))
        this.fail(
          `${path}: enum ${name} is ${JSON.stringify(set)}, schema lists ${JSON.stringify(vals)}`,
        );
      const prev = this.enums.get(name);
      if (prev !== undefined && !sameSet(prev, vals))
        this.fail(`${path}: enum ${name} is used for two different schema enums`);
      this.enums.set(name, vals);
      return name;
    }
    if (sch.const !== undefined) {
      if (typeof sch.const === 'string') return want({ type: 'string' }, 'string');
      if (typeof sch.const === 'number') return want({ type: 'integer' }, 'number');
      this.fail(`${path}: unhandled const ${JSON.stringify(sch.const)}`);
      return '?';
    }
    switch (sch.type) {
      case undefined:
        return want({ type: 'raw' }, 'RawJSON'); // {} accepts any JSON value
      case 'string':
        return sch.pattern === DIGEST_PATTERN
          ? want({ type: 'digest' }, 'Digest')
          : want({ type: 'string' }, 'string');
      case 'integer':
        return want({ type: 'integer' }, 'number');
      case 'number':
        return want({ type: 'number' }, 'number');
      case 'boolean':
        return want({ type: 'boolean' }, 'boolean');
      case 'array': {
        if (g.type !== 'array') {
          this.fail(`${path}: schema array, descriptor is ${JSON.stringify(got)}`);
          return '?';
        }
        const items = this.checkMember(`${path}[]`, key, asSchema(sch.items), g.items);
        return `readonly ${items.includes(' ') ? `(${items})` : items}[]`;
      }
      case 'object': {
        if (sch.properties !== undefined) {
          const name = INLINE[key];
          if (name === undefined) {
            this.fail(`${path}: inline object has no shape name`);
            return '?';
          }
          want({ type: 'shape', name }, name);
          this.checkShape(path, name, sch);
          return name;
        }
        if (typeof sch.additionalProperties === 'object' && sch.additionalProperties !== null) {
          if (g.type !== 'map') {
            this.fail(`${path}: schema map, descriptor is ${JSON.stringify(got)}`);
            return '?';
          }
          const v = this.checkMember(
            `${path}{}`,
            key,
            asSchema(sch.additionalProperties),
            g.values,
          );
          return `Readonly<Record<string, ${v}>>`;
        }
        return want({ type: 'object' }, 'PactObject'); // open object (attributes, extensions)
      }
    }
    this.fail(`${path}: unhandled schema shape ${JSON.stringify(sch)}`);
    return '?';
  }
}

/** The interfaces of src/core/types.ts: name to member lines `name`, `name?` with their types. */
function interfaces(source: string): Map<string, [string, string][]> {
  const out = new Map<string, [string, string][]>();
  for (const m of source.matchAll(/^export interface (\w+) \{\n([\s\S]*?)^\}/gm)) {
    const members: [string, string][] = [];
    for (const line of (m[2] ?? '').split('\n')) {
      const mm = /^ {2}readonly (\w+)(\??): (.+);$/.exec(line);
      if (mm) members.push([`${mm[1]}${mm[2]}`, mm[3] ?? '']);
    }
    out.set(m[1] ?? '', members);
  }
  return out;
}

/** Adds the local $ref targets in v to out. */
function refs(v: unknown, out: Set<string>): void {
  if (Array.isArray(v)) {
    for (const e of v) refs(e, out);
  } else if (typeof v === 'object' && v !== null) {
    for (const [k, e] of Object.entries(v)) {
      if (k === '$ref' && typeof e === 'string') out.add(e.replace(/^#\/\$defs\//, ''));
      else refs(e, out);
    }
  }
}

/** The $defs entries reachable from the root oneOf. */
function reachable(): Set<string> {
  const seen = new Set<string>();
  let todo = new Set<string>();
  refs(schema.oneOf, todo);
  while (todo.size > 0) {
    const next = new Set<string>();
    for (const name of todo) {
      if (seen.has(name)) continue;
      seen.add(name);
      refs(defs[name], next);
    }
    todo = next;
  }
  return seen;
}

function memberKey(name: string): string {
  return name.toUpperCase().replaceAll('-', '_');
}

test('TestSchemaDrift', (t) => {
  assert.equal(Object.keys(defs).length, 33, 'schema $defs entries');
  assert.equal(DEF_NAMES.length, 31, 'DEF_NAMES entries');
  assert.equal(ENUM_NAMES.length, 22, 'ENUM_NAMES entries (go/core enumSets)');

  const d = new Drift();
  const wire = reachable();
  for (const name of PAYLOAD_ONLY) {
    if (defs[name] === undefined) d.fail(`payload-only ${name} has no $defs entry`);
  }
  for (const name of Object.keys(defs).sort()) {
    if (PAYLOAD_ONLY.includes(name)) {
      if (wire.has(name))
        d.fail(`$defs/${name} is listed payload-only but a wire object reaches it`);
      continue;
    }
    if (!wire.has(name)) {
      d.fail(`$defs/${name} is not reachable from the root oneOf and not listed payload-only`);
    }
    if (!DEF_NAMES.includes(name)) {
      d.fail(`$defs/${name} has no shape`);
      continue;
    }
    d.checkShape(name, name, asSchema(defs[name]));
  }
  for (const name of DEF_NAMES) {
    if (defs[name] === undefined) d.fail(`shape ${name} has no $defs entry`);
  }

  // No shape without a schema counterpart.
  for (const name of Object.keys(table)) {
    if (!d.shapesReached.has(name)) d.fail(`shape ${name} is not reachable from the schema`);
  }

  // Each enum is used, has the schema's values, and names its members by
  // value (docs/sdk/parity-ledger.md, naming rules).
  for (const name of ENUM_NAMES) {
    const vals = d.enums.get(name);
    if (vals === undefined) {
      d.fail(`enum ${name} is not used by any schema enum property`);
      continue;
    }
    const e = enumOf(name);
    if (e.values.length !== vals.length)
      d.fail(`enum ${name} has ${e.values.length} values, schema ${vals.length}`);
    for (const [k, v] of Object.entries(e.members)) {
      if (k !== memberKey(v)) d.fail(`enum ${name}: member ${k} holds ${v}, want ${memberKey(v)}`);
    }
    if (!Object.isFrozen(e.members)) d.fail(`enum ${name} is not frozen`);
  }

  // The interfaces of types.ts: one per shape, same members, the optional
  // split, and the TypeScript type of each member.
  const ifaces = interfaces(readFileSync(TYPES, 'utf8'));
  if (!sameSet([...ifaces.keys()], Object.keys(table))) {
    d.fail(
      `types.ts interfaces ${JSON.stringify([...ifaces.keys()])}, shapes ${JSON.stringify(Object.keys(table))}`,
    );
  }
  for (const [name, members] of ifaces) {
    const shape = table[name];
    if (shape === undefined) continue;
    const want = Object.keys(asSchema(shape.members)).map((m) => [
      shape.optional.includes(m) ? `${m}?` : m,
      d.tsTypes.get(`${name}.${m}`) ?? '?',
    ]);
    if (JSON.stringify(members) !== JSON.stringify(want)) {
      d.fail(
        `types.ts ${name}: members ${JSON.stringify(members)}, schema ${JSON.stringify(want)}`,
      );
    }
  }

  for (const p of d.problems) t.diagnostic(p);
  assert.deepEqual(d.problems, []);
});

// The source-level half of the Go test: the typed string constants of
// go/core/enums.go per enum type equal the generated values.
test('TestSchemaDrift/go enums', (t) => {
  const src = goSource(t, GO_ENUMS);
  if (src === undefined) return;
  const goTypes = [...src.matchAll(/^type (\w+) string$/gm)].map((m) => m[1] ?? '');
  assert.deepEqual(goTypes, [...ENUM_NAMES], 'Go enum types, in declaration order');
  for (const name of ENUM_NAMES) {
    const re = new RegExp(`^\\s*\\w+\\s+${name}\\s*=\\s*"([^"]+)"`, 'gm');
    const goValues: string[] = [...src.matchAll(re)].map((m) => m[1] ?? '');
    assert.deepEqual(enumOf(name).values, goValues, `enum ${name}, in Go order`);
  }
  const version = /^const Version = "([^"]+)"$/m.exec(src);
  assert.ok(version, 'go/core/enums.go declares no Version');
  assert.equal(VERSION, version[1], 'VERSION, Go core.Version');
});
