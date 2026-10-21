/**
 * Fixture manifest reading and checks (Go package hop.top/pact-go/runner/manifest).
 *
 * @module
 */
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { completeness } from './files.ts';
import { load } from './manifest.ts';
import { add, Problems, RULE_SPEC_MAP } from './problem.ts';
import { checkSpecMap, parseSpecMap } from './specmap.ts';

export { completeness } from './files.ts';
export {
  Entry,
  FILE_NAME,
  load,
  Manifest,
  parse,
  SCHEMA_FILE_NAME,
  VERSION,
} from './manifest.ts';
export {
  Problem,
  Problems,
  RULE_ADAPTER_CASE_PATH,
  RULE_CAPABILITIES,
  RULE_CONFORMANCE_PROFILE,
  RULE_DRAFT_SECTION,
  RULE_EXPECTED,
  RULE_EXPECTED_MISSING,
  RULE_EXTENSION,
  RULE_FIXTURE_MISSING,
  RULE_GROUP_LANDED,
  RULE_GROUP_PARTIAL_COMPLETE,
  RULE_GROUP_PARTIAL_EMPTY,
  RULE_GROUP_PLANNED,
  RULE_GROUP_UNLISTED,
  RULE_ID,
  RULE_ID_DUPLICATE,
  RULE_JSON,
  RULE_KIND,
  RULE_LAYER,
  RULE_ORDER,
  RULE_OUTCOME,
  RULE_PATH,
  RULE_PATH_MISSING,
  RULE_ROW_UNKNOWN,
  RULE_SCOPE,
  RULE_SHAPE,
  RULE_SOURCE_CASE_PATH,
  RULE_SPEC_MAP,
  RULE_SPEC_MAP_ROW,
  RULE_TRANSPORT,
  RULE_UNCOVERED,
} from './problem.ts';
export {
  ADAPTER_CASE_ID_PATTERN,
  CAPABILITY_JWS_ED25519,
  CONFORMANCE_PROFILE_FULL,
  CONFORMANCE_PROFILE_SINGLE_OWNER,
  capabilities,
  conformanceProfiles,
  DEFAULT_CONFORMANCE_PROFILE,
  DEFAULT_TRANSPORT,
  DRAFT_SECTION_PATTERN,
  ID_PATTERN,
  Kind,
  kinds,
  LAYER_OS,
  LAYER_TRANSCRIPT,
  layers,
  outcomes,
  PATH_PATTERN,
  Scope,
  SOURCE_CASE_ID_PATTERN,
  SPEC_MAP_ROW_PATTERN,
  scopes,
  TESTDATA_DIR,
  TRANSPORT_HTTPS,
  TRANSPORT_STDIO_IPC,
  transports,
} from './rules.ts';
export {
  checkSpecMap,
  fixtureExists,
  parseSpecMap,
  type Row,
  type SpecMap,
  STATUS_LANDED,
  STATUS_PARTIAL,
  STATUS_PLANNED,
} from './specmap.ts';

/**
 * Runs every check of the manifest over the fixture directory `root` and
 * the spec map at `specMapPath`: load, validate, completeness, parseSpecMap
 * and checkSpecMap. An unreadable or non-strict manifest stops it after the
 * {@link RULE_JSON} problem.
 */
export function check(root: string, specMapPath: string): Problems {
  let m: ReturnType<typeof load>;
  try {
    m = load(root);
  } catch (err) {
    if (err instanceof Problems) return err;
    throw err;
  }
  const ps = m.validate();
  ps.push(...completeness(root, m));
  let text: Uint8Array;
  try {
    text = readFileSync(specMapPath);
  } catch (err) {
    const e = err instanceof Error ? err : new Error(String(err));
    add(ps, RULE_SPEC_MAP, basename(specMapPath), e.message, e);
    return ps;
  }
  const [sm, sps] = parseSpecMap(text);
  ps.push(...sps);
  if (sm !== undefined) ps.push(...checkSpecMap(root, m, sm));
  return ps;
}
