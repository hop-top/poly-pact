// The body that TestRunFailsEveryCase of broken.test.ts runs as a
// subprocess (Go TestRunAgainstBroken): the public entry point,
// runConformance, against the adapter with every defect on, in each mode. It
// fails, by design, and only runs when the parent test asks for it. The name
// keeps it out of the test glob.

import { test } from 'node:test';
import { runConformance } from '../../src/adapter/adaptertest/index.ts';
import { defects } from './broken.ts';
import { MODES } from './modes.ts';

for (const m of MODES) {
  test(m.name, { skip: process.env.PACT_RUN_BROKEN !== '1' }, (t) =>
    runConformance(t, m.factory(...defects()), m.options),
  );
}
