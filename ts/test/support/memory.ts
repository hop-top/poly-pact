// The fixture of the ported go/adapters/memory unit tests
// (memory_unit_test.go, freshness_unit_test.go): a state with two
// identities, one mapping, one approved claim path and one installed check,
// the adapter over it with a fake clock, and requests as a gateway receives
// them.

import type { Principal } from '../../src/adapter/index.ts';
import {
  MemoryAdapter,
  MODEL,
  type Option,
  type State,
  withSharedWorkloads,
} from '../../src/adapters/memory/index.ts';
import type { RawRequest } from '../../src/core/binding/index.ts';
import { FakeClock } from '../../src/core/clock.ts';
import { RawJSON } from '../../src/core/values.ts';

/** The now of the fixture, 2026-10-15T16:00:00Z, in milliseconds. */
export const T0 = 1792080000 * 1000;
export const SEC = T0 / 1000;
export const ENV = 'https://gateway.example/environments/finance';

export type DeepMutable<T> = T extends RawJSON
  ? T
  : T extends readonly (infer E)[]
    ? DeepMutable<E>[]
    : T extends object
      ? { -readonly [K in keyof T]: DeepMutable<T[K]> }
      : T;

/** A state whose members a test may change. */
export type MState = DeepMutable<State>;

const realm = () => ({ tenant_id: 'acme', environment_id: ENV });

/** Unix seconds `d` seconds after the fixture's now (Go `at`). */
export function at(d: number): number {
  return SEC + d;
}

export function baseState(): MState {
  return {
    model: MODEL,
    gateway: {
      tenant_id: 'acme',
      environment_id: ENV,
      origin: 'https://gateway.example',
      header_allowlist: ['x-request-kind'],
    },
    mappings: [
      {
        version: 'map-1',
        routes: [
          {
            method: 'GET',
            path: '/invoices/{id}',
            action: 'invoice.read',
            resource: 'https://invoices.example/invoices/{id}',
          },
        ],
      },
    ],
    identities: [
      identity('alice', 'https://idp.example/alice', 'w-alice', 'tok-alice-secret-1'),
      identity('bob', 'https://idp.example/bob', 'w-bob', 'tok-bob-secret-2'),
    ],
    enrollments: [],
    approved_paths: ['/roles'],
    claims: [claim({ path: '/roles', value: new RawJSON('["approver"]'), source_id: 'directory' })],
    checks: [
      check({
        id: 'approval-v1',
        result: 'PASS',
        reason_code: 'REQUIREMENT_SATISFIED',
        source_id: 'approvals',
      }),
    ],
    policy: [],
    visibility: 'execution',
    reporting: {
      issuer: 'https://gateway.example/reporters/finance',
      audience: 'https://reputation.example/',
      kid: 'k1',
    },
    sightings: [],
    unavailable_sources: [],
  };
}

export function identity(ref: string, id: string, workload: string, secret: string) {
  return { ref, id, realm: realm(), workload, secret, attributes: null };
}

type Rec<T> = Partial<DeepMutable<T>>;

export function enrollment(m: Rec<State['enrollments'][number]>): MState['enrollments'][number] {
  return {
    realm: realm(),
    workload: '',
    agent_id: '',
    operator_id: '',
    holder_jkt: '',
    status: 'ACTIVE',
    observed_at: null,
    status_checked_at: null,
    source_id: 'registry',
    source_ref: '',
    ...m,
  };
}

export function claim(m: Rec<State['claims'][number]>): MState['claims'][number] {
  return {
    realm: realm(),
    principal: 'https://idp.example/alice',
    path: '',
    resource: '',
    task_id: '',
    value: null,
    observed_at: null,
    status_checked_at: null,
    source_id: '',
    source_ref: '',
    ...m,
  };
}

export function check(m: Rec<State['checks'][number]>): MState['checks'][number] {
  return {
    id: '',
    principal: '',
    agent_id: '',
    result: '',
    reason_code: '',
    source_id: '',
    source_ref: '',
    observed_at: null,
    status_checked_at: null,
    freshness: null,
    pinned_revision: '',
    revision: '',
    ...m,
  };
}

export function rule(m: Rec<State['policy'][number]>): MState['policy'][number] {
  return {
    realm: realm(),
    principal: '',
    action: '',
    resource: '',
    effect: '',
    obligations: [],
    reason: '',
    source_id: '',
    source_ref: '',
    decided_at: null,
    policy_revision: '',
    ...m,
  };
}

/** The age limits of a bounded check (Go `limits`). */
export function limits(maxAge: number, statusMaxAge: number) {
  return { max_age_seconds: maxAge, status_max_age_seconds: statusMaxAge };
}

function build(opts: Option[], mutate: ((st: MState) => void)[]) {
  const st = baseState();
  for (const m of mutate) m(st);
  const clock = new FakeClock(T0);
  return { a: new MemoryAdapter(st as State, clock, ...opts), clock, st };
}

/** The adapter over the fixture state, changed by mutate; its workloads are dedicated. */
export function newAdapter(...mutate: ((st: MState) => void)[]) {
  return build([], mutate);
}

/** newAdapter with workloads that several agents may share. */
export function newSharedAdapter(...mutate: ((st: MState) => void)[]) {
  return build([withSharedWorkloads()], mutate);
}

export function alice(): Principal {
  return {
    id: 'https://idp.example/alice',
    workload: 'w-alice',
    mechanism: 'bearer',
    realm: { tenantId: 'acme', environmentId: ENV },
    authenticatedAt: null,
    attributes: {},
  };
}

/**
 * The request a server takes off the wire for the request-target `target`.
 * An origin-form target comes with the Host line of the configured origin,
 * as an HTTP/1.1 request carries it (RFC 9112 3.2, request-binding.md RB-66).
 */
export function received(method: string, target: string, body = new Uint8Array(0)): RawRequest {
  const headers: [string, string][] = target.startsWith('/') ? [['Host', 'gateway.example']] : [];
  return { method, rawRequestURI: target, headers, body };
}

export function get(target: string): RawRequest {
  return received('GET', target);
}

/** `req` with one more field line. */
export function addHeader(req: RawRequest, name: string, value: string): RawRequest {
  return { ...req, headers: [...req.headers, [name, value]] };
}

/** `req` with the field `name` set to `value`, any line of that name replaced. */
export function setHeader(req: RawRequest, name: string, value: string): RawRequest {
  const rest = req.headers.filter(([n]) => n.toLowerCase() !== name.toLowerCase());
  return { ...req, headers: [...rest, [name, value]] };
}
