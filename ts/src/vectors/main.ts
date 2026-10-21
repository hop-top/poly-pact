/**
 * Vectors harness entry, run by `make ts-vectors`: prints one NDJSON line,
 * `{"id","kind","result"}`, per entry of the fixture manifest named on the
 * command line, and nothing else on standard output. The common adapter
 * cases of the manifest's fixture tree run against the memory adapter first. Every row that is not
 * a pass, with its detail, and a summary line go to standard error.
 *
 * Usage: `node src/vectors/main.ts [--gates FILE] [--capability NAME]... MANIFEST`.
 * Plain argv, no command-line framework. `--gates` names the gates file
 * (tools/parity/gates.json); `--capability` declares an optional capability
 * of the fixtures (jws-ed25519).
 *
 * Exit status: 0 when no entry fails, or when every failing entry is under a
 * gate that is planned for ts; 1 when an entry fails under any other gate
 * (every gate counts as required without `--gates`); 2 on a harness error
 * (usage, an unreadable or malformed manifest or gates file, an unknown
 * kind, scope, capability or in-scope prefix), which prints nothing on
 * standard output. An absent manifest (a package mirror has no fixtures) is
 * a NOTICE on standard error and exit 0, unless `PACT_REQUIRE_VECTORS=1`,
 * which makes it a harness error.
 *
 * @module
 */
import { existsSync } from 'node:fs';
import { dirname } from 'node:path';
import process from 'node:process';
import { type Gates, loadGates } from './gates.ts';
import { runManifest } from './harness.ts';
import { HarnessError } from './manifest.ts';
import { evaluateAdapterCases } from './run-adapter-cases.ts';

const EXIT_HARNESS_ERROR = 2;
const USAGE = 'usage: node src/vectors/main.ts [--gates FILE] [--capability NAME]... MANIFEST\n';

interface Args {
  manifest: string;
  gates?: string;
  capabilities: string[];
}

function parseArgs(argv: readonly string[]): Args | undefined {
  const capabilities: string[] = [];
  let gates: string | undefined;
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? '';
    if (a === '--gates' || a === '--capability') {
      const v = argv[i + 1];
      if (v === undefined) return undefined;
      i += 1;
      if (a === '--gates') gates = v;
      else capabilities.push(v);
    } else if (a.startsWith('-')) {
      return undefined;
    } else {
      rest.push(a);
    }
  }
  const manifest = rest[0];
  if (rest.length !== 1 || manifest === undefined) return undefined;
  return { manifest, gates, capabilities };
}

async function main(argv: readonly string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args === undefined) {
    process.stderr.write(USAGE);
    return EXIT_HARNESS_ERROR;
  }
  if (!existsSync(args.manifest)) {
    if (process.env.PACT_REQUIRE_VECTORS === '1') {
      process.stderr.write(`vectors: PACT_REQUIRE_VECTORS=1 and ${args.manifest} is absent\n`);
      return EXIT_HARNESS_ERROR;
    }
    process.stderr.write(`NOTICE: vectors skipped: ${args.manifest} absent\n`);
    return 0;
  }
  try {
    const gates: Gates | undefined = args.gates === undefined ? undefined : loadGates(args.gates);
    const adapterCases = await evaluateAdapterCases(dirname(args.manifest));
    const run = runManifest(args.manifest, {
      capabilities: args.capabilities,
      gates,
      adapterCases,
    });
    process.stdout.write(run.lines.map((l) => `${JSON.stringify(l)}\n`).join(''));
    process.stderr.write([...run.details, run.summary].map((l) => `${l}\n`).join(''));
    return run.status;
  } catch (err) {
    if (!(err instanceof HarnessError)) throw err;
    process.stderr.write(`vectors: ${err.message}\n`);
    return EXIT_HARNESS_ERROR;
  }
}

process.exitCode = await main(process.argv.slice(2));
