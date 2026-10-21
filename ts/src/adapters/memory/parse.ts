/**
 * The strict decode of a state document of the memory adapter (Go
 * hop.top/pact-go/adapters/memory, ParseState and the json tags of State and
 * the records it holds).
 *
 * @module
 */
import { type Member, type Shape, shapes } from '../../core/shapes.ts';
import { decode } from '../../core/strictjson.ts';
import { RawJSON } from '../../core/values.ts';
import { State } from './state.ts';

/** The bound of a state document. */
const MAX_STATE_BYTES = 1 << 20;

// The member tables of a state document. A Go pointer is nullable; a Go
// slice or map is not.
const str: Member = { type: 'string' };
const strs: Member = { type: 'array', items: str };
const time: Member = { type: 'nullable', of: { type: 'number' } };
const ref = (name: string): Member => ({ type: 'shape', name });
const list = (name: string): Member => ({ type: 'array', items: ref(name) });
const attrs: Member = { type: 'map', values: { type: 'raw' } };
const shapeOf = (members: Record<string, Member>): Shape => ({
  required: [],
  optional: Object.keys(members),
  members,
});

const DEFS: Readonly<Record<string, Shape>> = {
  ...shapes,
  State: shapeOf({
    model: str,
    gateway: ref('Gateway'),
    mappings: list('Mapping'),
    identities: list('Identity'),
    enrollments: list('Enrollment'),
    approved_paths: strs,
    claims: list('ClaimRecord'),
    checks: list('CheckRecord'),
    policy: list('PolicyRule'),
    visibility: str,
    reporting: { type: 'nullable', of: ref('Reporting') },
    sightings: list('Sighting'),
    unavailable_sources: strs,
  }),
  Realm: shapeOf({ tenant_id: str, environment_id: str }),
  Gateway: shapeOf({ tenant_id: str, environment_id: str, origin: str, header_allowlist: strs }),
  Mapping: shapeOf({ version: str, routes: list('Route') }),
  Route: shapeOf({ method: str, path: str, action: str, resource: str }),
  Identity: shapeOf({
    ref: str,
    id: str,
    realm: ref('Realm'),
    workload: str,
    secret: str,
    attributes: attrs,
  }),
  Enrollment: shapeOf({
    realm: ref('Realm'),
    workload: str,
    agent_id: str,
    operator_id: str,
    holder_jkt: str,
    status: str,
    observed_at: time,
    status_checked_at: time,
    source_id: str,
    source_ref: str,
  }),
  ClaimRecord: shapeOf({
    realm: ref('Realm'),
    principal: str,
    path: str,
    resource: str,
    task_id: str,
    value: { type: 'raw' },
    observed_at: time,
    status_checked_at: time,
    source_id: str,
    source_ref: str,
  }),
  CheckFreshness: shapeOf({ max_age_seconds: time, status_max_age_seconds: time }),
  CheckRecord: shapeOf({
    id: str,
    principal: str,
    agent_id: str,
    result: str,
    reason_code: str,
    source_id: str,
    source_ref: str,
    observed_at: time,
    status_checked_at: time,
    freshness: { type: 'nullable', of: ref('CheckFreshness') },
    pinned_revision: str,
    revision: str,
  }),
  Obligation: shapeOf({ id: str, attributes: attrs }),
  PolicyRule: shapeOf({
    realm: ref('Realm'),
    principal: str,
    action: str,
    resource: str,
    effect: str,
    obligations: list('Obligation'),
    reason: str,
    source_id: str,
    source_ref: str,
    decided_at: time,
    policy_revision: str,
  }),
  Reporting: shapeOf({ issuer: str, audience: str, kid: str }),
  Sighting: shapeOf({ source_id: str, source_ref: str, observed_at: time }),
};

type Obj = Record<string, unknown>;

// The decoded value of a member as the State type has it: the defaults of
// absent members (Go zero values), raw attribute members as JSON data, and
// time members checked to be integers, as a Go int64 is.
function complete(v: unknown, shapeName: string, path: string): unknown {
  const s = DEFS[shapeName] as Shape;
  const o = (v ?? {}) as Obj;
  const out: Obj = {};
  for (const [name, m] of Object.entries(s.members)) {
    out[name] = member(o[name], m, `${path}/${name}`);
  }
  return Object.freeze(out);
}

function member(v: unknown, m: Member, path: string): unknown {
  switch (m.type) {
    case 'string':
      return v ?? '';
    case 'raw':
      return v ?? null;
    case 'nullable':
      if (v === undefined || v === null) return null;
      if (m.of.type === 'number') {
        if (!Number.isSafeInteger(v)) throw new Error(`${path} is not an integer`);
        return v;
      }
      return member(v, m.of, path);
    case 'shape':
      return complete(v, m.name, path);
    case 'array':
      return Object.freeze(
        ((v ?? []) as unknown[]).map((x, i) => member(x, m.items, `${path}/${i}`)),
      );
    case 'map': {
      if (v === undefined) return null;
      const out: Obj = {};
      for (const [k, x] of Object.entries(v as Obj)) {
        out[k] = x instanceof RawJSON ? (JSON.parse(x.text) as unknown) : x;
      }
      return out;
    }
    default:
      return v;
  }
}

/** Strictly decodes a state document and validates it; throws an `Error`. */
export function parseState(raw: Uint8Array | string): State {
  let st: State;
  try {
    const v = decode(raw, DEFS.State as Shape, { maxBytes: MAX_STATE_BYTES }, DEFS);
    st = complete(v, 'State', '') as State;
  } catch (err) {
    throw new Error(`memory: state: ${(err as Error).message}`, { cause: err });
  }
  try {
    State.validate(st);
  } catch (err) {
    throw new Error(`memory: state: ${(err as Error).message}`, { cause: err });
  }
  return st;
}
