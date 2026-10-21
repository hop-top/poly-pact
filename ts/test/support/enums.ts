// The 22 string enums of Go core (go/core/schema_drift_test.go enumSets),
// written out here, and access to their generated tables in
// src/core/enums.ts by name.

import assert from 'node:assert/strict';
import * as enums from '../../src/core/enums.ts';

export const ENUM_NAMES: readonly string[] = [
  'RuleSource',
  'Comparison',
  'Mode',
  'EvidenceKind',
  'CheckStatus',
  'Decision',
  'TerminalReason',
  'SecurityStatus',
  'CausalAssessment',
  'ReporterRole',
  'EventKind',
  'OutcomeResult',
  'Dimension',
  'Severity',
  'BoundDirection',
  'LearningMode',
  'ArtifactType',
  'Transition',
  'LifecycleState',
  'AckStatus',
  'JWSAlgorithm',
  'PresentationTransport',
];

export interface EnumTable {
  /** The const object: member name to value. */
  readonly members: Readonly<Record<string, string>>;
  /** Its values, in declaration order. */
  readonly values: readonly string[];
  /** The `is<Name>` guard. */
  readonly guard: (x: unknown) => boolean;
}

export function enumOf(name: string): EnumTable {
  const exports = enums as unknown as Record<string, unknown>;
  const members = exports[name];
  const guard = exports[`is${name}`];
  assert.ok(
    typeof members === 'object' && members !== null,
    `src/core/enums.ts exports no const ${name}`,
  );
  assert.equal(typeof guard, 'function', `src/core/enums.ts exports no is${name}`);
  const table = members as Record<string, string>;
  return {
    members: table,
    values: Object.values(table),
    guard: guard as (x: unknown) => boolean,
  };
}
