/**
 * record_outcome of the broken adapter, with its defects, and the signer of
 * the defect that signs text the memory adapter would have cleaned (Go
 * hop.top/pact-go/adapters/internal/broken, record.go).
 *
 * @module
 */
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { NoVisibility, type Observation, type Recorded, Signed } from '../../src/adapter/types.ts';
import type { State } from '../../src/adapters/memory/index.ts';
import { Dimension, EventKind, OutcomeResult } from '../../src/core/enums.ts';
import { decodeSegment, encodeSegment } from '../../src/core/jws/base64url.ts';
import { signES256, verifyES256 } from '../../src/core/jws/es256.ts';
import type { OutcomeReport } from '../../src/core/types.ts';
import { encode } from '../../src/internal/encode.ts';
import type { Adapter } from './broken.ts';
import { Defect } from './defects.ts';

const utf8 = new TextEncoder();

/** Signs outcome reports with a key of its own. */
export class LeakySigner {
  readonly #key: KeyObject;
  readonly #publicKey: KeyObject;
  readonly #kid: string;

  /** A signer under a new P-256 key, with the kid of the state's reporting. */
  constructor(st: State) {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.#key = pair.privateKey;
    this.#publicKey = pair.publicKey;
    this.#kid = st.reporting?.kid ?? '';
  }

  /** The report as a compact JWS signed with ES256. */
  sign(rep: OutcomeReport): string {
    const hdr = JSON.stringify({ alg: 'ES256', kid: this.#kid, typ: 'pact-outcome+jwt' });
    const input = `${encodeSegment(utf8.encode(hdr))}.${encodeSegment(utf8.encode(encode(rep)))}`;
    return `${input}.${encodeSegment(signES256(this.#key, input))}`;
  }

  /** Throws when `jws` is not a compact JWS this signer signed. */
  verify(jws: string): void {
    const parts = jws.split('.');
    if (parts.length !== 3) throw new Error('not a compact JWS');
    let sig: Uint8Array;
    try {
      sig = decodeSegment(parts[2] as string);
    } catch {
      throw new Error('malformed signature');
    }
    if (sig.length !== 64) throw new Error('malformed signature');
    if (!verifyES256(this.#publicKey, `${parts[0]}.${parts[1]}`, sig)) {
      throw new Error('signature does not verify');
    }
  }
}

/** recordOutcome of the memory adapter, with the recording defects. */
export async function recordOutcome(
  b: Adapter,
  o: Observation,
  signal?: AbortSignal,
): Promise<Recorded> {
  const visible = b.state().visibility === 'execution';
  if (b.has(Defect.NO_VISIBILITY_FOR_ADMISSION) && o.eventKind === EventKind.ADMISSION) {
    return new NoVisibility('the adapter has no visibility');
  }
  if (
    b.has(Defect.NO_VISIBILITY_DESPITE_VISIBILITY) &&
    o.eventKind === EventKind.EXECUTION &&
    visible
  ) {
    return new NoVisibility('the adapter has no visibility');
  }
  if (
    b.has(Defect.ASSUME_EXECUTION_SUCCESS) &&
    o.eventKind === EventKind.EXECUTION &&
    !visible &&
    b.executing !== null
  ) {
    // The adapter cannot see the execution and signs a success anyway.
    return b.executing.recordOutcome(
      { ...o, result: OutcomeResult.SUCCESS, dimension: Dimension.RELIABILITY },
      signal,
    );
  }
  const rec = await b.base.recordOutcome(o, signal);
  if (!b.has(Defect.LEAK_DETAILS_IN_REPORT) || b.leaky === null || !(rec instanceof Signed)) {
    return rec;
  }
  const rep = decodeReport(rec.jws);
  return new Signed(
    b.leaky.sign({ ...rep, details: o.details, evidence_refs: [...o.evidenceRefs] }),
  );
}

function decodeReport(jws: string): OutcomeReport {
  const parts = jws.split('.');
  if (parts.length !== 3) throw new Error('not a compact JWS');
  return JSON.parse(Buffer.from(decodeSegment(parts[1] as string)).toString('utf8'));
}
