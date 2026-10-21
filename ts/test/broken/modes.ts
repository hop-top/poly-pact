/**
 * The workload modes the proof runs the broken adapter in (Go
 * hop.top/pact-go/adapters/internal/broken, `modes` of broken_test.go):
 * dedicated workloads, the default of every profile, and workloads shared by
 * several agents (identity mapping IM-19). Each mode runs the cases that
 * apply to it.
 *
 * @module
 */
import type { Factory, Options } from '../../src/adapter/adaptertest/index.ts';
import { factory, sharedFactory } from './broken.ts';
import type { Defect } from './defects.ts';

/** One workload mode. */
export interface Mode {
  readonly name: string;
  readonly factory: (...defects: Defect[]) => Factory;
  readonly options: Options;
}

export const MODES: readonly Mode[] = Object.freeze([
  { name: 'dedicated', factory, options: {} },
  { name: 'shared', factory: sharedFactory, options: { sharedWorkloads: true } },
]);
