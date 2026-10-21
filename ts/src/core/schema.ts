/**
 * JSON Schema validation of PACT objects, an SDK extra with no Go library
 * counterpart: the definitions of the vendored Appendix A.3 schema
 * (schema/pact.schema.json), JSON Schema Draft 2020-12, with format `uri`
 * asserted by the RFC 3986 matcher every PACT SDK shares.
 *
 * The validator only ever sees what the strict parser returns: {@link validate}
 * takes JSON text, applies `strictjson.parse` first and then the schema.
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import Ajv2020Mod from 'ajv/dist/2020.js';
import { type Limits, parse } from './strictjson.ts';
import { uriFormat } from './uri.ts';

export { uriFormat };

// ajv is CommonJS; under NodeNext its constructor is the default export's
// `default` (a plain default import fails tsc with TS2351).
const Ajv2020 = Ajv2020Mod.default;

/** One schema failure of a document. */
export interface SchemaIssue {
  /** The JSON Pointer (RFC 6901) of the failing value. */
  readonly instancePath: string;
  /** The schema keyword that failed. */
  readonly keyword: string;
  readonly message: string;
}

/** A document that is strict JSON but fails its definition. */
export class SchemaError extends Error {
  /** The `$defs` name the document was validated against. */
  readonly def: string;
  readonly issues: readonly SchemaIssue[];

  constructor(def: string, issues: readonly SchemaIssue[]) {
    super(
      `schema: ${def}: ${issues.map((i) => `${i.instancePath || '/'} ${i.message}`).join('; ')}`,
    );
    this.name = 'SchemaError';
    this.def = def;
    this.issues = issues;
  }
}

type Check = ((value: unknown) => boolean) & {
  errors?: readonly { instancePath: string; keyword: string; message?: string }[] | null;
};

interface Compiled {
  readonly defs: ReadonlySet<string>;
  readonly get: (def: string) => Check;
}

let compiled: Compiled | undefined;

// The vendored schema, compiled on first use: strict mode, every error, and
// the `uri` format registered before anything compiles.
function schema(): Compiled {
  if (compiled !== undefined) return compiled;
  const doc = parse(readFileSync(new URL('../../schema/pact.schema.json', import.meta.url)), {
    maxBytes: 1 << 22,
    maxDepth: 64,
  }) as { $id: string; $defs: Record<string, unknown> };
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  ajv.addFormat('uri', uriFormat);
  ajv.addSchema(doc);
  const cache = new Map<string, Check>();
  compiled = {
    defs: new Set(Object.keys(doc.$defs)),
    get: (def) => {
      let check = cache.get(def);
      if (check === undefined) {
        const fn = ajv.getSchema(`${doc.$id}#/$defs/${def}`);
        if (fn === undefined) throw new Error(`schema: no compiled definition ${def}`);
        check = fn as Check;
        cache.set(def, check);
      }
      return check;
    },
  };
  return compiled;
}

/**
 * Strictly parses `input` (`strictjson.parse` under `limits`) and validates
 * the value against the `$defs` entry `def`. Returns the parsed value; throws
 * a `StrictJSONError` for a document that is not strict JSON, a
 * {@link SchemaError} for one that fails the definition, and a `RangeError`
 * for a `def` that the schema does not define.
 */
export function validate(def: string, input: Uint8Array | string, limits?: Limits): unknown {
  const s = schema();
  if (typeof def !== 'string' || !s.defs.has(def)) {
    throw new RangeError(`schema: ${JSON.stringify(def)} is not a $defs entry of the schema`);
  }
  const value = parse(input, limits);
  const check = s.get(def);
  if (!check(value)) {
    throw new SchemaError(
      def,
      (check.errors ?? []).map((e) => ({
        instancePath: e.instancePath,
        keyword: e.keyword,
        message: e.message ?? e.keyword,
      })),
    );
  }
  return value;
}
