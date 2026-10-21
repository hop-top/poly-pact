/**
 * One case against a fresh adapter (Go hop.top/pact-go/adapter/adaptertest:
 * runCase and the run state of suite.go, compare.go, the scans of
 * leak.go).
 *
 * An adapter function settles in one of three ways. It resolves, which is
 * its answer; it rejects, which is its error (Go: the returned error); or it
 * throws before returning a promise, which breaks the contract of a function
 * that returns a promise and fails the case as a panic does in Go.
 *
 * @module
 */

import type { RawRequest } from '../../core/binding/index.ts';
import { BASELINE_SKEW_MS, FakeClock } from '../../core/clock.ts';
import { canonicalize } from '../../core/jcs.ts';
import { decodeSegment } from '../../core/jws/base64url.ts';
import { Digest } from '../../core/values.ts';
import { codeOf } from '../errors.ts';
import type { Principal } from '../types.ts';
import type { Case } from './casefile.ts';
import { authenticate, binding } from './checks-identity.ts';
import { authorize, check, claim } from './checks-native.ts';
import { mapOperation } from './checks-operation.ts';
import { record } from './checks-record.ts';
import { type Factory, Hooks, type Subject } from './harness.ts';
import { errorText, findCredentials, jsonText } from './leak.ts';
import { ARRIVAL_DIRECT, FN } from './load.ts';
import { buildRequest } from './request.ts';

/**
 * The current time of a case that states none, in Unix seconds:
 * 2026-10-15T16:00:00Z, the timestamp of the draft's worked example.
 */
export const DEFAULT_NOW = 1792080000;

/** The bound of each adapter call, in milliseconds. */
export const CALL_TIMEOUT_MS = 10_000;

/**
 * The clock skew the suite allows between an adapter's timestamps and the
 * case's now: the baseline of draft 7.5. An adapter configured with a
 * tighter skew passes; one that needs a larger skew does not.
 */
export const SKEW_MS = BASELINE_SKEW_MS;

/** How an adapter call settled. */
export type Settled<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: unknown };

const TIMEOUT = Symbol('timeout');

/** Whole Unix seconds of an instant in milliseconds, as Go's `Time.Unix`. */
export function sec(ms: number): number {
  return Math.floor(ms / 1000);
}

/**
 * Whether `a` and `b`, two JSON texts, are the same JSON data: object
 * member order is ignored, array order is significant (draft 8.4). Both are
 * put into RFC 8785 canonical form and compared. Throws when either is not
 * strict JSON, naming which.
 */
export function jsonEqual(a: string | Uint8Array, b: string | Uint8Array): boolean {
  let ca: Uint8Array;
  let cb: Uint8Array;
  try {
    ca = canonicalize(a);
  } catch (err) {
    throw new Error(`expected value: ${(err as Error).message}`);
  }
  try {
    cb = canonicalize(b);
  } catch (err) {
    throw new Error(`returned value: ${(err as Error).message}`);
  }
  return Buffer.from(ca).equals(Buffer.from(cb));
}

/** Why `d` is not a digest (`Digest.validate`), or `undefined` when it is one. */
export function digestProblem(d: unknown): string | undefined {
  const validate: (d: string) => void = Digest.validate;
  try {
    validate(d as string);
    return undefined;
  } catch (err) {
    return (err as Error).message;
  }
}

/** The state of one case. */
export class Run {
  readonly c: Case;
  /** The case's now in milliseconds. */
  readonly now: number;
  readonly hooks = new Hooks();
  readonly fails: string[] = [];
  /** Aborts every call of the case after {@link CALL_TIMEOUT_MS}. */
  readonly signal: AbortSignal = AbortSignal.timeout(CALL_TIMEOUT_MS);
  subj!: Subject;

  constructor(c: Case) {
    this.c = c;
    this.now = (c.now ?? DEFAULT_NOW) * 1000;
  }

  failf(msg: string): void {
    this.fails.push(msg);
  }

  /**
   * Calls `f`, an adapter function, and returns how it settled, or
   * `undefined` after recording a failure: it threw instead of returning a
   * promise (`<step> panicked`), or it did not settle in time.
   */
  async call<T>(step: string, f: () => Promise<T> | T): Promise<Settled<T> | undefined> {
    let p: Promise<T> | T;
    try {
      p = f();
    } catch (err) {
      this.failf(`${step} panicked: ${errorText(err)}`);
      return undefined;
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const late = new Promise<typeof TIMEOUT>((resolve) => {
      timer = setTimeout(() => resolve(TIMEOUT), CALL_TIMEOUT_MS);
    });
    try {
      const settled = await Promise.race([
        Promise.resolve(p).then(
          (value): Settled<T> => ({ ok: true, value }),
          (error: unknown): Settled<T> => ({ ok: false, error }),
        ),
        late,
      ]);
      if (settled === TIMEOUT) {
        this.failf(`${step} did not settle within ${CALL_TIMEOUT_MS / 1000} s`);
        return undefined;
      }
      return settled;
    } finally {
      clearTimeout(timer);
    }
  }

  /** The case's request with its credential and its arrival; `undefined` after a failure. */
  request(): { req: RawRequest; body: Uint8Array } | undefined {
    const cr = this.c.request;
    if (cr === null) {
      this.failf('the case has no request');
      return undefined;
    }
    let built: { req: RawRequest; body: Uint8Array };
    try {
      built = buildRequest(cr);
    } catch (err) {
      this.failf(errorText(err));
      return undefined;
    }
    let req = built.req;
    if (cr.native_state_ref !== '') {
      const credential = this.subj.credential;
      if (typeof credential !== 'function') {
        this.failf(
          `factory returned no credential hook, and the case presents native identity ${JSON.stringify(cr.native_state_ref)}`,
        );
        return undefined;
      }
      try {
        req = credential(req, cr.native_state_ref);
      } catch (err) {
        this.failf(
          `credential for native identity ${JSON.stringify(cr.native_state_ref)}: ${errorText(err)}`,
        );
        return undefined;
      }
      if (req === null || typeof req !== 'object') {
        this.failf('the credential hook returned no request');
        return undefined;
      }
    }
    if (cr.arrival !== ARRIVAL_DIRECT) {
      req = this.subj.arrive(req);
      if (req === null || req === undefined) {
        this.failf('the arrive hook returned no request');
        return undefined;
      }
    }
    return { req, body: built.body };
  }

  /** The case's principal argument as the adapter type. */
  principal(): Principal {
    const p = this.c.call.principal;
    return Object.freeze({
      id: p?.id ?? '',
      realm: Object.freeze({
        tenantId: p?.realm.tenant_id ?? '',
        environmentId: p?.realm.environment_id ?? '',
      }),
      workload: p?.workload ?? '',
      mechanism: p === null || p.mechanism === '' ? 'test' : p.mechanism,
      authenticatedAt:
        p === null || p.authenticated_at === null ? this.now : p.authenticated_at * 1000,
      attributes: Object.freeze({ ...(p?.attributes ?? {}) }),
    });
  }

  /** Fails the case for each credential in `text`, when the case asks for the scan. */
  scanText(what: string, text: string): void {
    const ls = this.c.expect.leak_scan;
    if (ls === null) return;
    for (const f of findCredentials(text, ls.secrets)) {
      this.failf(`${what} carries a credential: ${f}`);
    }
  }

  /** Scans the JSON form of a returned value. */
  scanValue(what: string, v: unknown): void {
    if (this.c.expect.leak_scan === null) return;
    this.scanText(what, jsonText(v));
  }

  /** Scans an error's text, which includes the text of everything it wraps. */
  scanError(what: string, err: unknown): void {
    if (this.c.expect.leak_scan === null) return;
    this.scanText(`${what} error`, errorText(err));
  }

  /**
   * Scans a compact JWS: the string as returned, for the literal secrets
   * only (the patterns would match the JWS itself), and its header and
   * payload decoded, since a credential inside the payload is base64url text
   * in the string.
   */
  scanJWS(what: string, jws: string): void {
    const ls = this.c.expect.leak_scan;
    if (ls === null) return;
    for (const s of ls.secrets) {
      if (s !== '' && jws.includes(s)) {
        this.failf(`${what} carries a credential: secret ${JSON.stringify(s)}`);
      }
    }
    for (const [i, seg] of jws.split('.').slice(0, 2).entries()) {
      let raw: Uint8Array;
      try {
        raw = decodeSegment(seg);
      } catch {
        continue;
      }
      this.scanText(`${what} segment ${i}`, Buffer.from(raw).toString('utf8'));
    }
  }

  /**
   * Checks the draft 13.4 code an error carries against the case's
   * reason_code, when the case names one. A code is carried by an
   * `AdapterError` in the error's `cause` chain (`codeOf`).
   */
  wantReason(step: string, err: unknown): void {
    const want = this.c.expect.reason_code;
    if (want === '') return;
    const got = codeOf(err);
    if (got === '') {
      this.failf(`${step} error carries no draft 13.4 code, want ${want}: ${errorText(err)}`);
    } else if (got !== want) {
      this.failf(`${step} error code is ${got}, want ${want}: ${errorText(err)}`);
    }
  }

  /**
   * Checks a time against an expected member of the case: absent is not
   * checked, JSON null requires no time, a number requires those Unix
   * seconds.
   */
  wantTime(what: string, want: { readonly text: string } | null, got: number | null): void {
    if (want === null) return;
    const text = want.text.trim();
    if (text === 'null') {
      if (got !== null) {
        this.failf(
          `${what} is ${sec(got)}, want none: the source gives none and the adapter must not supply one`,
        );
      }
      return;
    }
    const n = Number(text);
    if (!/^-?[0-9]+$/.test(text) || !Number.isSafeInteger(n)) {
      this.failf(`${what}: expected value ${text} is not an integer`);
      return;
    }
    if (got === null) {
      this.failf(`${what} is none, want ${n}`);
    } else if (sec(got) !== n) {
      this.failf(
        `${what} is ${sec(got)}, want ${n} (the time the source gave, not the time of the read)`,
      );
    }
  }

  /** Fails when `t` is later than `limit`. No time passes: the source gives none. */
  notAfter(what: string, t: number | null | undefined, limit: number): void {
    if (typeof t === 'number' && t > limit) {
      this.failf(`${what} is ${sec(t)}, later than the allowed ${sec(limit)}`);
    }
  }
}

async function execute(r: Run): Promise<void> {
  switch (r.c.expect.function) {
    case FN.authenticate:
      return authenticate(r);
    case FN.binding:
      return binding(r);
    case FN.mapOperation:
      return mapOperation(r);
    case FN.claim:
      return claim(r);
    case FN.check:
      return check(r);
    case FN.authorize:
      return authorize(r);
    case FN.record:
      return record(r);
  }
}

/** Runs one case against a fresh adapter and returns its failures. */
export async function runCase(factory: Factory, c: Case): Promise<string[]> {
  const r = new Run(c);
  const env = Object.freeze({ state: c.native_state, clock: new FakeClock(r.now), hooks: r.hooks });
  let made: Subject | Promise<Subject>;
  try {
    made = factory(env);
  } catch (err) {
    r.failf(`factory panicked: ${errorText(err)}`);
    return r.fails;
  }
  let subj: Subject;
  try {
    subj = await made;
  } catch (err) {
    r.failf(`factory: ${errorText(err)}`);
    return r.fails;
  }
  if (subj === null || typeof subj !== 'object' || subj.adapter == null) {
    r.failf('factory returned no adapter');
    return r.fails;
  }
  if (typeof subj.arrive !== 'function') {
    r.failf(
      'factory returned no arrive hook: the suite cannot tell a request through the enforcement point from a bypass',
    );
    return r.fails;
  }
  r.subj = subj;
  await execute(r);
  const fired = r.hooks.fired();
  for (const name of c.expect.must_not_call) {
    if (fired.includes(name)) {
      r.failf(`hook ${JSON.stringify(name)} fired; it must not (fired: [${fired.join(' ')}])`);
    }
  }
  return r.fails;
}
