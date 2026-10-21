/**
 * Evaluation-case loader (Go package hop.top/pact-go/runner/evalcase): reads
 * the evaluation cases of spec/v1.0/fixtures and checks their signed files. It
 * uses `node:` builtins and the package's own modules only, and is distinct
 * from the adapter case files that `adaptertest` reads. The format is
 * spec/v1.0/fixtures/README.md, sections Evaluation cases, Signed artifacts and
 * Format v2.
 *
 * ## Evaluation cases
 *
 * {@link load} reads a manifest entry of kind evaluate into a {@link Case}:
 * one {@link Exchange} for a case directory, or one per exchange directory
 * of a multi-exchange case's sequence.json, in order. An exchange holds
 * config.json, native_context.json, signing.json and exchange.json as typed
 * values, exchange.json with its defaults applied, every other JSON file of
 * the directory as bytes, the committed signed files, and the expected
 * decision.json, whether at expected/<id>/decision.json or, for an
 * exchange, at expected/<id>/<exchange>/decision.json. v1 cases read the
 * same under format v2, since every v2 member has a default.
 *
 * ## Signed files
 *
 * The generator contract of signing.json is applied by {@link walk}:
 * {@link dirs} lists the directories to sign, {@link loadKeys} the test keys
 * of {@link KEYS_FILE}, and each {@link File} says what a signed file must
 * carry. {@link verify}, and so {@link load}, fails on a stale signed file,
 * one the generator would sign again. Each returned {@link Signed} also
 * carries the result of verifying it against the directory's trust records
 * (config.json trust and the authenticated holder_jkt), which a case may
 * make fail by design.
 *
 * Paths are slash-separated and relative to the fixture directory, the
 * directory of manifest.json, or to a case directory where a field says so.
 * Every failure is a {@link CaseError} whose message names the case and the
 * file, as Go's errors do; a missing test-keys file is the file system
 * error.
 *
 * The readers of outcomes and learning cases of the Go package are not
 * ported.
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import { Kind } from '../runner/manifest/index.ts';
import { checkAlgorithms, checkAuthenticated, checkSources, readAs, readConfig } from './decode.ts';
import {
  type Dir,
  isDir,
  jsonFilesUnder,
  loadDir,
  manifestEntries,
  noSignedFiles,
  readSequence,
  type Sequence,
  under,
} from './dirs.ts';
import { CaseError, notExist, q, wrap } from './errors.ts';
import { type Key, loadKeys } from './keys.ts';
import type { Signing } from './signing.ts';
import {
  type Availability,
  type Config,
  Decision,
  type HandoffAttempt,
  type NativeContext,
  type Submission,
} from './types.ts';
import { type Signed, verifyDir } from './verify.ts';

export { type Dir, dirs, type Sequence } from './dirs.ts';
export { CaseError } from './errors.ts';
export { KEYS_FILE, type Key, loadKeys } from './keys.ts';
export {
  type Artifact,
  FIXED_TIME,
  PRESENTATION_LIFETIME,
  type Presentation,
  type Signing,
} from './signing.ts';
export * from './types.ts';
export { type Signed, verify } from './verify.ts';
export { File, type FileInit, readDecoded, walk } from './walk.ts';

/**
 * An evaluation case: a manifest entry of kind evaluate, read with every
 * file of its directory, or of each exchange directory of a multi-exchange
 * case.
 */
export interface Case {
  /** The manifest id. */
  readonly id: string;
  /** The case directory, relative to the fixture directory. */
  readonly path: string;
  /** The case's one exchange, or the exchanges of its sequence.json in order. */
  readonly exchanges: readonly Exchange[];
  /** The index in exchanges of the exchange whose expected file is the manifest entry's expected file. */
  readonly subject: number;
}

/** One admission exchange: a case directory, or an exchange directory of a multi-exchange case. */
export interface Exchange {
  /** The exchange path sequence.json names, such as "exchanges/1", or '' for a case of one exchange. */
  readonly name: string;
  /** The directory, relative to the fixture directory. */
  readonly path: string;
  readonly config: Config;
  readonly nativeContext: NativeContext;
  /** signing.json; empty when the directory has none. */
  readonly signing: Signing;
  /**
   * exchange.json with its defaults: without the file, one submission of
   * signed/presentation.jws, everything available and no handoff.
   */
  readonly submissions: readonly Submission[];
  readonly availability: Availability;
  readonly handoff: readonly HandoffAttempt[];
  /**
   * The bytes of every other JSON file of the directory, by path relative to
   * it, in lexical order: the decoded artifacts, the profile, intent and
   * operations. They are kept as bytes since a case may hold an object that
   * a validator must reject.
   */
  readonly decoded: ReadonlyMap<string, Uint8Array>;
  /** The committed signed files, verified ({@link verify}); empty after {@link read}. */
  readonly signed: readonly Signed[];
  /** The expected file at {@link Exchange.expectedPath}, relative to the fixture directory. */
  readonly expected: Decision;
  readonly expectedPath: string;
}

// The files of a case directory that are not decoded objects.
const CONTROL_FILES = [
  'config.json',
  'native_context.json',
  'signing.json',
  'exchange.json',
  'sequence.json',
];

const DEFAULT_OPERATION = 'actual_operation.json';
const DEFAULT_TRANSPORT = 'https';
const DEFAULT_PRESENTATION = 'signed/presentation.jws';

/**
 * Reads the evaluation case id of the fixture directory fixtures (the
 * directory of manifest.json) and verifies its signed files. Throws a
 * {@link CaseError} when the manifest does not list id as an entry of kind
 * evaluate, when a file is missing or is not strict JSON of its format, when
 * the expected file does not have one response per submission and one entry
 * per handoff attempt, or when a signed file is stale ({@link verify}). A
 * signed file that fails its trust records is not an error: its
 * `Signed.trust` says why.
 */
export function load(fixtures: string, id: string): Case {
  return loadCase(fixtures, id, true);
}

/**
 * Reads the evaluation case id as {@link load} does but does not verify the
 * signed files: it loads no test key, so a fixture directory without the
 * private values of {@link KEYS_FILE} reads, and a stale signed file is not
 * an error. The signed list of each exchange is empty. A consumer that
 * judges an implementation against the case, not the case itself, reads
 * with read; the generator and its checks use load.
 */
export function read(fixtures: string, id: string): Case {
  return loadCase(fixtures, id, false);
}

function loadCase(fixtures: string, id: string, check: boolean): Case {
  const e = manifestEntries(fixtures).find((e) => e.id === id);
  if (e === undefined) throw new CaseError(`${id}: no manifest entry`);
  if (e.kind !== Kind.EVALUATE) {
    throw new CaseError(`${id}: manifest kind ${e.kind}, not ${Kind.EVALUATE}`);
  }
  if (e.expected === null) throw new CaseError(`${id}: the manifest entry names no expected file`);
  const keys = check ? loadKeys(fixtures) : undefined;
  if (!isDir(under(fixtures, e.path))) {
    throw new CaseError(`${id}: path ${e.path} is not a case directory`);
  }
  let seq: Sequence | undefined;
  try {
    seq = readSequence(under(fixtures, e.path));
  } catch (err) {
    throw wrap(id, err);
  }
  if (seq === undefined) {
    const x = loadExchange(fixtures, keys, e.id, '', e.path, e.expected);
    return { id, path: e.path, exchanges: [x], subject: 0 };
  }
  noSignedFiles(fixtures, e.path, seq.exchanges);
  const subject = seq.exchanges.indexOf(seq.subject);
  if (subject < 0) {
    throw new CaseError(
      `${id}/sequence.json: subject ${q(seq.subject)} is not one of its exchanges`,
    );
  }
  const exchanges: Exchange[] = [];
  for (const name of seq.exchanges) {
    const exp = `expected/${id}/${name}/decision.json`;
    if (name === seq.subject && exp !== e.expected) {
      throw new CaseError(
        `${id}: manifest expected ${e.expected} is not ${exp}, the expected file of the subject exchange`,
      );
    }
    exchanges.push(loadExchange(fixtures, keys, e.id, name, `${e.path}/${name}`, exp));
  }
  return { id, path: e.path, exchanges, subject };
}

// Reads the exchange directory rel of the entry; keys is undefined when the
// signed files are not verified.
function loadExchange(
  fixtures: string,
  keys: ReadonlyMap<string, Key> | undefined,
  entry: string,
  name: string,
  rel: string,
  expectedPath: string,
): Exchange {
  const id = name === '' ? entry : `${entry}/${name}`;
  const dir = under(fixtures, rel);
  if (!isDir(dir)) throw new CaseError(`${id}: not a directory of the case`);
  let config: Config;
  let nativeContext: NativeContext;
  try {
    config = readConfig(under(dir, 'config.json'));
  } catch (err) {
    throw wrap(`${id}/config.json`, err);
  }
  try {
    nativeContext = readAs<NativeContext>(under(dir, 'native_context.json'), 'NativeContext');
  } catch (err) {
    throw wrap(`${id}/native_context.json`, err);
  }
  try {
    checkAlgorithms(config.gateway);
  } catch (err) {
    throw wrap(`${id}/config.json`, err);
  }
  try {
    checkAuthenticated(nativeContext.authenticated);
  } catch (err) {
    throw wrap(`${id}/native_context.json`, err);
  }
  try {
    checkSources(config, nativeContext);
  } catch (err) {
    throw wrap(`${id}/config.json`, err);
  }
  const d: Dir | undefined = loadDir(fixtures, entry, id, rel, []);
  const signing: Signing = d?.signing ?? { artifacts: [], presentations: [] };
  let signed: Signed[] = [];
  if (d !== undefined && keys !== undefined) {
    signed = verifyDir(
      fixtures,
      d,
      keys,
      config.trust,
      nativeContext.authenticated?.holder_jkt ?? '',
    );
  }
  let ex: ReturnType<typeof readExchange>;
  try {
    ex = readExchange(dir, config, signing);
  } catch (err) {
    throw wrap(`${id}/exchange.json`, err);
  }
  let decoded: Map<string, Uint8Array>;
  try {
    decoded = readDecodedFiles(dir);
  } catch (err) {
    throw wrap(id, err);
  }
  let expected: Decision;
  try {
    expected = readAs<Decision>(under(fixtures, expectedPath), 'Decision');
  } catch (err) {
    throw wrap(`${id}: expected file ${expectedPath}`, err);
  }
  const n = Decision.expectedResponses(expected).length;
  if (n !== ex.submissions.length) {
    throw new CaseError(
      `${id}: expected file ${expectedPath}: ${n} expected responses for ${ex.submissions.length} submissions`,
    );
  }
  if (expected.handoff.length !== ex.handoff.length) {
    throw new CaseError(
      `${id}: expected file ${expectedPath}: ${expected.handoff.length} expected handoff results for ${ex.handoff.length} handoff attempts`,
    );
  }
  return {
    name,
    path: rel,
    config,
    nativeContext,
    signing,
    submissions: ex.submissions,
    availability: ex.availability,
    handoff: ex.handoff,
    decoded,
    signed,
    expected,
    expectedPath,
  };
}

interface ExchangeFile {
  readonly presentations:
    | readonly {
        readonly signed: string;
        readonly jti: string;
        readonly replica: string | null;
        readonly concurrent: boolean | null;
        readonly evict_replay_records: boolean | null;
        readonly actual_operation: string | null;
        readonly transport: string | null;
        readonly evaluation: {
          readonly started_at: number | null;
          readonly native_reads_at: number | null;
          readonly cancelled_at: number | null;
        } | null;
      }[]
    | null;
  readonly availability: {
    readonly sources: readonly string[];
    readonly replay_store: string | null;
    readonly enrollment_source: string | null;
  } | null;
  readonly handoff: readonly {
    readonly presentation: string | null;
    readonly actual_operation: string | null;
    readonly at: number | null;
  }[];
}

// Reads exchange.json, when there is one, and applies the defaults of
// README section exchange.json.
function readExchange(
  dir: string,
  config: Config,
  signing: Signing,
): { submissions: Submission[]; availability: Availability; handoff: HandoffAttempt[] } {
  let f: ExchangeFile = { presentations: null, availability: null, handoff: [] };
  try {
    f = readAs<ExchangeFile>(under(dir, 'exchange.json'), 'ExchangeFile');
  } catch (err) {
    if (!notExist(err)) throw err;
  }
  const submissions: Submission[] = [];
  if (f.presentations === null) {
    const p = signing.presentations.find((p) => p.signed === DEFAULT_PRESENTATION);
    submissions.push({
      signed: DEFAULT_PRESENTATION,
      jti: p?.jti ?? '',
      replica: 'r1',
      concurrent: false,
      evictReplayRecords: false,
      actualOperation: DEFAULT_OPERATION,
      transport: DEFAULT_TRANSPORT,
      evaluation: { startedAt: config.now, nativeReadsAt: null, cancelledAt: null },
    });
  } else if (f.presentations.length === 0) {
    throw new CaseError('presentations is empty');
  }
  for (const [i, p] of (f.presentations ?? []).entries()) {
    if (p.signed === '' || p.jti === '') {
      throw new CaseError(`presentations[${i}]: signed and jti are required`);
    }
    const transport = p.transport ?? DEFAULT_TRANSPORT;
    if (transport !== 'https' && transport !== 'stdio-ipc') {
      throw new CaseError(
        `presentations[${i}]: transport ${q(transport)} is not https or stdio-ipc`,
      );
    }
    submissions.push({
      signed: p.signed,
      jti: p.jti,
      replica: p.replica ?? 'r1',
      concurrent: p.concurrent === true,
      evictReplayRecords: p.evict_replay_records === true,
      actualOperation: p.actual_operation ?? DEFAULT_OPERATION,
      transport,
      evaluation: {
        startedAt: p.evaluation?.started_at ?? config.now,
        nativeReadsAt: p.evaluation?.native_reads_at ?? null,
        cancelledAt: p.evaluation?.cancelled_at ?? null,
      },
    });
  }
  let availability: Availability = {
    sources: [],
    replayStore: 'available',
    enrollmentSource: 'available',
  };
  const a = f.availability;
  if (a !== null) {
    availability = {
      sources: a.sources,
      replayStore: a.replay_store ?? 'available',
      enrollmentSource: a.enrollment_source ?? 'available',
    };
    const s = availability.enrollmentSource;
    if (s !== 'available' && s !== 'unavailable') {
      throw new CaseError(`availability.enrollment_source ${q(s)} is not available or unavailable`);
    }
  }
  const handoff: HandoffAttempt[] = [];
  for (const [i, h] of f.handoff.entries()) {
    // The attempt's submission: the one its presentation jti names, by
    // default the first.
    let s = submissions[0] as Submission;
    if (h.presentation !== null) {
      const j = submissions.findIndex((s) => s.jti === h.presentation);
      if (j < 0) {
        throw new CaseError(
          `handoff[${i}]: presentation ${q(h.presentation)} is the jti of no submission`,
        );
      }
      s = submissions[j] as Submission;
    }
    handoff.push({
      presentation: s.jti,
      actualOperation: h.actual_operation ?? DEFAULT_OPERATION,
      at: h.at ?? s.evaluation.startedAt,
    });
  }
  return { submissions, availability, handoff };
}

// Every JSON file under dir other than the control files at its top level.
function readDecodedFiles(dir: string): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const r of jsonFilesUnder(dir)) {
    if (!r.includes('/') && CONTROL_FILES.includes(r)) continue;
    out.set(r, new Uint8Array(readFileSync(under(dir, r))));
  }
  return out;
}
