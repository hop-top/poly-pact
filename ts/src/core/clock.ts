/**
 * Time windows and lifetimes (Go package hop.top/pact-go/core/clock): the time
 * rules of draft section 7.5 and the baseline lifetimes of section 20.1.
 *
 * Protocol timestamps (iat, nbf, exp, created_at, expires_at) are integer
 * Unix seconds in the range 0..2^53-1. Instants, such as the current time a
 * {@link Clock} reports, are Unix milliseconds, and durations are
 * milliseconds. A validator reads the current time from a Clock so that tests
 * control it, then applies:
 *
 * - {@link checkWindow}: nbf <= now + skew, iat <= now + skew and now < exp,
 *   with no grace period after exp;
 * - {@link checkLifetime}: the longest span from iat to exp an artifact type
 *   may claim;
 * - {@link checkPresentation}: the window and lifetime checks plus
 *   now - iat <= 60 s for an agent presentation;
 * - {@link replayRetention}: how long a replay record must be kept.
 *
 * Comparisons are exact. The current time is split once into whole seconds
 * (floor) and a sub-second remainder, and a wire integer is compared against
 * that pair; a wire value is never scaled to milliseconds for a comparison
 * (2^53-1 seconds is beyond 2^53-1 milliseconds), so a fractional now is not
 * rounded in the artifact's favour.
 *
 * The checks throw a {@link ClockError}.
 *
 * @module
 */

/** The largest clock skew a validator may allow, in ms (sections 7.5, 20.1). There is no expiry grace period in addition to it. */
export const BASELINE_SKEW_MS = 5000;

// The largest value of a core integer field: 2^53-1 (section 7.1).
const MAX_TIMESTAMP = Number.MAX_SAFE_INTEGER;

// The last whole second whose instant, in ms, is at most 2^53-1.
const MAX_INSTANT_SECOND = Math.floor(Number.MAX_SAFE_INTEGER / 1000);

// The longest presentation lifetime, and the 60 of the replay retention
// formula of section 7.5, in seconds.
const PRESENTATION_VALIDITY = 60;

/** Reports the current time as Unix milliseconds. */
export interface Clock {
  now(): number;
}

/** The clock of the host: `Date.now()`. */
export class SystemClock implements Clock {
  now(): number {
    return Date.now();
  }
}

/** A clock that only moves when told to. */
export class FakeClock implements Clock {
  #now: number;

  /** A clock that reads `startMs` until it is moved. */
  constructor(startMs: number) {
    this.#now = startMs;
  }

  /** The instant the clock was last set or advanced to. */
  now(): number {
    return this.#now;
  }

  /** Moves the clock to `ms`. */
  set(ms: number): void {
    this.#now = ms;
  }

  /** Moves the clock by `ms`, which may be negative. */
  advance(ms: number): void {
    this.#now += ms;
  }
}

/** The kinds of a time check failure, one per Go sentinel error. */
export type ClockErrorKind =
  | 'SKEW'
  | 'TIMESTAMP'
  | 'NOT_YET_VALID'
  | 'ISSUED_IN_FUTURE'
  | 'EXPIRED'
  | 'LIFETIME'
  | 'TOO_OLD'
  | 'UNKNOWN_ARTIFACT';

/**
 * A time check failure:
 *
 * - `SKEW`: the skew passed to a check is negative or above {@link BASELINE_SKEW_MS};
 * - `TIMESTAMP`: a timestamp is not an integer in 0..2^53-1;
 * - `NOT_YET_VALID`: nbf is later than now + skew;
 * - `ISSUED_IN_FUTURE`: iat is later than now + skew;
 * - `EXPIRED`: now is at or after exp;
 * - `LIFETIME`: exp is not after iat, or exp - iat is longer than the artifact type allows;
 * - `TOO_OLD`: a presentation was issued more than 60 seconds before now;
 * - `UNKNOWN_ARTIFACT`: the value names no artifact type.
 */
export class ClockError extends Error {
  readonly kind: ClockErrorKind;

  constructor(kind: ClockErrorKind, detail: string) {
    super(`clock: ${detail}`);
    this.name = 'ClockError';
    this.kind = kind;
  }
}

// The lifetime in seconds of each artifact type.
const LIFETIMES = new Map<unknown, number>();

/** An artifact type that section 20.1 gives a lifetime. */
export class Artifact {
  static readonly PRESENTATION = new Artifact(1, 'presentation', 60);
  static readonly CONTRACT = new Artifact(2, 'requirement contract', 60);
  static readonly EVIDENCE = new Artifact(3, 'evidence', 3600);
  static readonly SNAPSHOT = new Artifact(4, 'reputation snapshot', 300);
  static readonly OUTCOME = new Artifact(5, 'outcome report', 300);
  static readonly PROFILE = new Artifact(6, 'profile', 86400);

  /** The Go `Artifact` value. */
  readonly code: number;
  readonly #name: string;

  private constructor(code: number, name: string, lifetimeSeconds: number) {
    this.code = code;
    this.#name = name;
    LIFETIMES.set(this, lifetimeSeconds);
    Object.freeze(this);
  }

  toString(): string {
    return this.#name;
  }
}

// The lifetime in seconds of a, or a ClockError when a is not one of the
// artifact types.
function lifetimeOf(a: Artifact): number {
  const s = LIFETIMES.get(a);
  if (s === undefined) {
    throw new ClockError('UNKNOWN_ARTIFACT', `unknown artifact type: ${String(a)}`);
  }
  return s;
}

/**
 * The longest lifetime of an artifact of type `a`, in ms, measured from iat
 * to exp (from created_at to expires_at for a profile). Section 20.1:
 * presentation 60 s, contract 60 s, evidence 1 h, reputation snapshot 300 s,
 * outcome report 300 s, profile 24 h.
 */
export function maxLifetime(a: Artifact): number {
  return lifetimeOf(a) * 1000;
}

function checkSkew(skewMs: number): void {
  if (!(skewMs >= 0 && skewMs <= BASELINE_SKEW_MS)) {
    throw new ClockError('SKEW', `skew must be between 0 and 5s: got ${skewMs} ms`);
  }
}

function checkRange(name: string, sec: number): void {
  if (!Number.isInteger(sec) || sec < 0 || sec > MAX_TIMESTAMP) {
    throw new ClockError('TIMESTAMP', `timestamp outside 0..9007199254740991: ${name} is ${sec}`);
  }
}

/** An instant split once into whole seconds (floor) and the remainder in ms, 0 <= ms < 1000. */
function split(instantMs: number): readonly [sec: number, ms: number] {
  let sec = Math.floor(instantMs / 1000);
  let ms = instantMs - sec * 1000;
  if (ms < 0) {
    sec -= 1;
    ms += 1000;
  } else if (ms >= 1000) {
    sec += 1;
    ms -= 1000;
  }
  return [sec, ms];
}

/**
 * Applies section 7.5 to an artifact's claims at `now` (ms):
 *
 *     nbf <= now + skew
 *     iat <= now + skew
 *     now < exp
 *
 * There is no grace period: an artifact whose exp is at or before now is
 * expired, however small the skew. `skewMs` must lie in
 * 0..{@link BASELINE_SKEW_MS}; a deployment that tightens the baseline passes
 * its own smaller value. The checks run in the order skew, range, nbf, iat,
 * exp, and the first failure is thrown.
 *
 * For an agent profile call `checkWindow(createdAt, createdAt, expiresAt, ...)`.
 */
export function checkWindow(
  iat: number,
  nbf: number,
  exp: number,
  now: number,
  skewMs: number,
): void {
  checkSkew(skewMs);
  checkRange('iat', iat);
  checkRange('nbf', nbf);
  checkRange('exp', exp);
  const [sec, ms] = split(now);
  // now + skew is latest + a fraction of a second; an integer claim is
  // later than it exactly when it is later than latest.
  const latest = sec + Math.floor((ms + skewMs) / 1000);
  if (!(nbf <= latest)) {
    throw new ClockError(
      'NOT_YET_VALID',
      `not yet valid (nbf is in the future): nbf ${nbf}, now ${sec}, skew ${skewMs} ms`,
    );
  }
  if (!(iat <= latest)) {
    throw new ClockError(
      'ISSUED_IN_FUTURE',
      `issued in the future (iat is later than now plus skew): iat ${iat}, now ${sec}, skew ${skewMs} ms`,
    );
  }
  // now = sec + a fraction below 1, so now < exp exactly when sec < exp.
  if (!(sec < exp)) {
    throw new ClockError('EXPIRED', `expired: exp ${exp}, now ${sec}`);
  }
}

/**
 * Checks that exp - iat is positive (Appendix A.2: iat < exp) and no longer
 * than {@link maxLifetime} of `a`. It compares the claims alone and does not
 * need the current time. A claim that is not an integer is a `TIMESTAMP`
 * error.
 */
export function checkLifetime(a: Artifact, iat: number, exp: number): void {
  const max = lifetimeOf(a);
  for (const [name, sec] of [
    ['iat', iat],
    ['exp', exp],
  ] as const) {
    if (!Number.isInteger(sec)) {
      throw new ClockError('TIMESTAMP', `timestamp is not an integer: ${name} is ${sec}`);
    }
  }
  if (!(exp > iat)) {
    throw new ClockError('LIFETIME', `invalid lifetime: ${a} exp ${exp} is not after iat ${iat}`);
  }
  if (!(exp - iat <= max)) {
    throw new ClockError(
      'LIFETIME',
      `invalid lifetime: ${a} lives ${exp - iat} s, at most ${max} s`,
    );
  }
}

/**
 * Checks that a presentation issued at `iat` is at most 60 seconds old at
 * `now` (ms): now - iat <= 60 s (section 7.5). A presentation issued ahead
 * of now is not too old; {@link checkWindow} bounds that case.
 */
export function checkPresentationAge(iat: number, now: number): void {
  checkRange('iat', iat);
  const [sec, ms] = split(now);
  // Both are integers below 2^53 in magnitude, so the difference is exact.
  const age = sec - iat;
  if (!(age < PRESENTATION_VALIDITY || (age === PRESENTATION_VALIDITY && ms === 0))) {
    throw new ClockError(
      'TOO_OLD',
      `presentation issued more than 60s ago: iat ${iat}, now ${sec}`,
    );
  }
}

/**
 * Applies every time rule of section 7.5 to an agent presentation:
 * {@link checkWindow}, then exp - iat <= 60 s, then now - iat <= 60 s. The
 * first failure is thrown. Claims that pass the first two checks always pass
 * the third (now < exp <= iat + 60); it stays so that each rule is enforced
 * by name and survives a change to either bound.
 */
export function checkPresentation(
  iat: number,
  nbf: number,
  exp: number,
  now: number,
  skewMs: number,
): void {
  checkWindow(iat, nbf, exp, now, skewMs);
  checkLifetime(Artifact.PRESENTATION, iat, exp);
  checkPresentationAge(iat, now);
}

// The instant in ms that is sec seconds plus extraMs after the epoch, or
// Infinity when it is later than 2^53-1 ms and so has no exact value.
function instant(sec: number, extraMs: number): number {
  if (sec > MAX_INSTANT_SECOND) return Number.POSITIVE_INFINITY;
  const ms = sec * 1000 + extraMs;
  return ms <= Number.MAX_SAFE_INTEGER ? ms : Number.POSITIVE_INFINITY;
}

// A claim clamped into 0..2^53-1; a value that is no number at all is
// clamped up, which can only lengthen a retention.
function clamp(sec: number): number {
  if (Number.isNaN(sec)) return MAX_TIMESTAMP;
  return Math.min(Math.max(Math.ceil(sec), 0), MAX_TIMESTAMP);
}

/**
 * The instant (ms) before which a replay record must not be evicted: the
 * later of the artifact expiry and iat + 60 s + skew (section 7.5). Evicting
 * earlier, even under load, lets a presentation be replayed.
 *
 * A negative skew counts as zero. Claims outside 0..2^53-1 are clamped into
 * that range, which can only lengthen the retention of a valid claim; such
 * claims fail {@link checkWindow} before a record is written. A retention
 * later than 2^53-1 ms is `Infinity`: it is never shortened by rounding, and
 * no clock reading reaches it.
 */
export function replayRetention(exp: number, iat: number, skewMs: number): number {
  const skew = skewMs > 0 ? skewMs : 0;
  const expiry = instant(clamp(exp), 0);
  const horizon = instant(clamp(iat), PRESENTATION_VALIDITY * 1000 + skew);
  return Math.max(expiry, horizon);
}
