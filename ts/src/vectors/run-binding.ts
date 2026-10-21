/**
 * The vectors/binding group of the harness, after cli/pactconf
 * vectors_core.go and spec/v1.0/fixtures/vectors/binding/README.md. The vector's
 * request object is the literal wire form of a RawRequest, so the request
 * is bound once, as received.
 *
 * @module
 */
import { type Config, RequestError } from '../core/binding/index.ts';
import { decodeRequest } from '../internal/request.ts';
import type { Core } from './core.ts';
import {
  bytes,
  equal,
  exactMembers,
  isObject,
  messageOf,
  onlyMembers,
  readJSON,
  rethrowStub,
  singleFile,
  str,
  stringOf,
  stringsOf,
} from './fixture.ts';
import type { Entry } from './manifest.ts';

const MEMBERS = [
  'action',
  'config',
  'description',
  'expect',
  'expect_operation_digest',
  'id',
  'operation_id',
  'principal_id',
  'request',
  'resources',
];

/** The body limit the harness configures; no vector tests a limit. */
export const BINDING_MAX_BODY = 1 << 20;

/**
 * vectors/binding: the request is bound under the vector's configuration;
 * an accepted one, completed with the vector's operation_id and the
 * configuration's environment_id, has the expected canonical context and
 * object_digest; a refused one is a RequestError of kind INVALID_REQUEST; a
 * configuration error is a RequestError of kind INVALID_CONFIG from the
 * configuration check, and no request is bound.
 */
export function runBinding(root: string, e: Entry, core: Core): void {
  singleFile(e);
  const v = exactMembers(readJSON(root, e.path), ...MEMBERS);
  if (v.id !== e.id)
    throw new Error(`vector id ${JSON.stringify(v.id)}, manifest id ${JSON.stringify(e.id)}`);
  const expect = onlyMembers(v.expect, 'operation_context', 'reject_reason', 'config_error');
  const accept = expect.operation_context !== undefined;
  const configError = expect.config_error !== undefined;
  const digest = v.expect_operation_digest;
  const agree = accept
    ? isObject(expect.operation_context) &&
      expect.reject_reason === undefined &&
      !configError &&
      e.outcome === 'ACCEPTED' &&
      typeof digest === 'string'
    : configError
      ? expect.config_error === true &&
        expect.reject_reason === undefined &&
        e.outcome === 'REJECTED' &&
        digest === null
      : expect.reject_reason === 'INVALID_MESSAGE' && e.outcome === 'REJECTED' && digest === null;
  if (!agree) {
    throw new Error(
      `expect, expect_operation_digest and outcome ${JSON.stringify(e.outcome)} do not agree`,
    );
  }

  const c = onlyMembers(
    v.config,
    'origin',
    'header_allowlist',
    'normalization_id',
    'mapping_version',
    'environment_id',
  );
  const cfg: Config = {
    origin: stringOf(c.origin, 'config.origin'),
    headerAllowlist: stringsOf(c.header_allowlist, 'config.header_allowlist'),
    headerNormalizationId: stringOf(c.normalization_id, 'config.normalization_id'),
    mappingVersion: stringOf(c.mapping_version, 'config.mapping_version'),
    maxBody: BINDING_MAX_BODY,
  };
  const environmentId = stringOf(c.environment_id, 'config.environment_id');
  if (configError) {
    try {
      core.validateConfig(cfg);
    } catch (err) {
      rethrowStub(err);
      if (err instanceof RequestError && err.kind === 'INVALID_CONFIG') return;
      throw new Error(`got ${messageOf(err)}, want a RequestError INVALID_CONFIG`);
    }
    throw new Error('configuration accepted, want a configuration error');
  }
  // Every member is present in every file (vectors README).
  exactMembers(v.request, 'method', 'raw_request_uri', 'headers', 'body_b64');
  const req = decodeRequest(v.request).request;
  const principalId = stringOf(v.principal_id, 'principal_id');
  const action = stringOf(v.action, 'action');
  const resources = stringsOf(v.resources, 'resources');

  let op: Record<string, unknown>;
  try {
    op = core.fromRequest(cfg, req, principalId, action, resources);
  } catch (err) {
    rethrowStub(err);
    if (accept) throw new Error(`refused (${messageOf(err)}), want an operation context`);
    if (err instanceof RequestError && err.kind === 'INVALID_REQUEST') return;
    throw new Error(`got ${messageOf(err)}, want a RequestError INVALID_REQUEST (INVALID_MESSAGE)`);
  }
  if (!accept) throw new Error('got an operation context, want a refusal (INVALID_MESSAGE)');
  const completed = {
    ...op,
    operation_id: stringOf(v.operation_id, 'operation_id'),
    environment_id: environmentId,
  };
  const got = core.canonicalize(bytes(JSON.stringify(completed)));
  const want = core.canonicalize(bytes(JSON.stringify(expect.operation_context)));
  if (!equal(got, want)) throw new Error(`operation context: got ${str(got)}, want ${str(want)}`);
  const d = core.objectDigest(completed);
  if (d !== digest) throw new Error(`object_digest ${d}, want ${String(digest)}`);
}
