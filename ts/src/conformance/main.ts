/**
 * Evaluate skeleton: the `tool evaluate {dir} {state}` command of the
 * conformance runner's adapter contract (go/runner package documentation),
 * for a validator not yet written in this language. It reads the case with
 * the case loader ({@link read}: no private test key needed) and prints, for
 * each exchange in order, one line per submission and one per handoff
 * attempt: an RFC 9457 Problem (draft 13.4) with the code
 * UNSUPPORTED_REQUIREMENT and status 422. pactc therefore judges every
 * admission case FAIL, line by line, and never sees a crash.
 *
 * Usage: `node src/conformance/main.ts evaluate DIR [STATE]`. Plain argv, no
 * command-line framework. DIR is the case directory, inside the fixture
 * directory that holds manifest.json; STATE, the scratch path of the
 * runner, is accepted and unused.
 *
 * With make, from the repository root:
 *
 * ```sh
 * make conformance PACTC_ARGS='--fixture admission/ --evaluate-cmd "node ts/src/conformance/main.ts evaluate {dir} {state}"'
 * ```
 *
 * Exit status: 0 after printing the lines; 2 on a usage error or a directory
 * that is not an evaluate case, with the reason on standard error and
 * nothing on standard output.
 *
 * @module
 */
import { existsSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import process from 'node:process';
import type { Problem } from '../core/types.ts';
import { Kind } from '../runner/manifest/index.ts';
import { read } from './case.ts';
import { manifestEntries } from './dirs.ts';
import { messageOf } from './errors.ts';

const EXIT_USAGE = 2;
const USAGE = 'usage: node src/conformance/main.ts evaluate DIR [STATE]\n';

/** The Problem of every line: the skeleton supports no requirement. */
function problem(n: number): Problem {
  return {
    type: 'about:blank',
    title: 'Unsupported requirement',
    status: 422,
    code: 'UNSUPPORTED_REQUIREMENT',
    request_id: `skeleton-${n}`,
  };
}

// The fixture directory holding dir and the entry id of dir in its manifest.
function locate(dir: string): { fixtures: string; id: string } {
  let fixtures = dir;
  while (!existsSync(join(fixtures, 'manifest.json'))) {
    const up = dirname(fixtures);
    if (up === fixtures) throw new Error(`${dir}: no manifest.json in it or above it`);
    fixtures = up;
  }
  const rel = relative(fixtures, dir).split(sep).join('/');
  const e = manifestEntries(fixtures).find((e) => e.kind === Kind.EVALUATE && e.path === rel);
  if (e === undefined) {
    throw new Error(
      `${dir}: no evaluate entry of ${join(fixtures, 'manifest.json')} has path ${rel}`,
    );
  }
  return { fixtures, id: e.id };
}

function main(argv: readonly string[]): number {
  if (argv[0] !== 'evaluate' || argv.length < 2 || argv.length > 3) {
    process.stderr.write(USAGE);
    return EXIT_USAGE;
  }
  let lines: string[];
  try {
    const { fixtures, id } = locate(resolve(argv[1] as string));
    lines = [];
    for (const x of read(fixtures, id).exchanges) {
      for (let i = 0; i < x.submissions.length + x.handoff.length; i++) {
        lines.push(JSON.stringify(problem(lines.length + 1)));
      }
    }
  } catch (err) {
    process.stderr.write(`evaluate: ${messageOf(err)}\n`);
    return EXIT_USAGE;
  }
  process.stdout.write(lines.map((l) => `${l}\n`).join(''));
  return 0;
}

process.exitCode = main(process.argv.slice(2));
