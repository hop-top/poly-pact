// Port of go/adapters/memory/memory_test.go: the conformance suite against
// the reference adapter in both workload modes. By default its workloads are
// dedicated, the default of every profile; with withSharedWorkloads they may
// be shared by several agents (identity mapping IM-19), and the suite then
// runs the shared-workload cases, IDENT-09 among them.

import { test } from 'node:test';
import { runConformance } from '../src/adapter/adaptertest/index.ts';
import { factory, factoryWith, withSharedWorkloads } from '../src/adapters/memory/index.ts';
import { fixturesPresent } from './support/fixtures.ts';

test('TestSuite', async (t) => {
  if (!fixturesPresent(t)) return;
  await t.test('dedicated', (t) => runConformance(t, factory));
  await t.test('shared', (t) =>
    runConformance(t, factoryWith(withSharedWorkloads()), { sharedWorkloads: true }),
  );
});
