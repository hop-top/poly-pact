/**
 * map_operation of the memory adapter (Go hop.top/pact-go/adapters/memory,
 * operation.go).
 *
 * @module
 */
import { createHash } from 'node:crypto';
import { AdapterError } from '../../adapter/errors.ts';
import type { Principal } from '../../adapter/types.ts';
import {
  type Config,
  fromRequest,
  type RawRequest,
  RequestError,
} from '../../core/binding/index.ts';
import type { OperationContext } from '../../core/types.ts';
import { type Core, live, realmOf } from './core.ts';
import { bearerToken, identityBySecret } from './identity.ts';
import type { Gateway, Mapping } from './state.ts';

/** The largest request body the adapter reads to digest it. */
const MAX_BODY = 8 << 20;

/** The header normalization of the baseline HTTP mapping, which the binding applies. */
const HEADER_NORMALIZATION_ID = 'memory-header-normalization-1';

/** The baseline HTTP mapping of the gateway under one installed mapping version. */
export function bindingConfig(gateway: Gateway, mappingVersion: string): Config {
  return {
    origin: gateway.origin,
    headerAllowlist: gateway.header_allowlist,
    headerNormalizationId: HEADER_NORMALIZATION_ID,
    mappingVersion,
    maxBody: MAX_BODY,
  };
}

/**
 * map_operation: the operation context of draft 10.2 from the request, the
 * authenticated principal and the installed mapping.
 *
 * The baseline HTTP mapping is the binding's `fromRequest`: method,
 * target_uri from the configured origin and the exact path and query of the
 * request-target, body_digest of the exact body, and the allowlisted
 * headers. A Host, Forwarded or X-Forwarded-* header cannot choose the
 * target. The adapter adds what the binding leaves to it: action and
 * resources from the installed route that matches the method and the bound
 * path, never from a list the client supplied; principal_id, the
 * authenticated principal; environment_id, from the gateway configuration;
 * and operation_id.
 *
 * A request the baseline mapping refuses, such as one with a fragment,
 * userinfo, a content encoding or an ambiguous encoding, rejects with an
 * INVALID_MESSAGE error whose cause is the binding's `RequestError`, which
 * names the rule.
 */
export function mapOperation(
  c: Core,
  req: RawRequest | null | undefined,
  p: Principal,
  mappingVersion: string,
  signal?: AbortSignal,
): OperationContext {
  live('map operation', signal);
  if (req === null || req === undefined || typeof req !== 'object') {
    throw AdapterError.invalidMessage('memory: no request');
  }
  const m = c.mappings.get(mappingVersion);
  if (m === undefined) {
    throw AdapterError.unsupportedRequirement(
      `memory: mapping version ${JSON.stringify(mappingVersion)} is not installed`,
    );
  }
  const realm = realmOf(c);
  if (
    p.id === '' ||
    p.realm.tenantId !== realm.tenantId ||
    p.realm.environmentId !== realm.environmentId
  ) {
    throw AdapterError.contextMismatch(
      "memory: the principal does not belong to this gateway's realm",
    );
  }
  matchCredential(c, req, p);

  let op: OperationContext;
  try {
    op = fromRequest(bindingConfig(c.st.gateway, mappingVersion), req, p.id, '', []);
  } catch (err) {
    if (err instanceof RequestError && err.kind === 'INVALID_REQUEST') {
      throw AdapterError.invalidMessage(`memory: ${err.message}`, { cause: err });
    }
    if (err instanceof RequestError && err.kind === 'BODY_READ') {
      throw AdapterError.dependencyUnavailable(`memory: ${err.message}`, { cause: err });
    }
    // The constructor validated the configuration of every installed
    // mapping, so this is not reached; an unusable mapping is not supported.
    throw AdapterError.unsupportedRequirement(
      `memory: mapping ${JSON.stringify(mappingVersion)}: ${(err as Error).message}`,
      { cause: err },
    );
  }

  const path = boundPath(op.target_uri);
  const route = matchRoute(m, op.method, path);
  if (route === undefined) {
    throw AdapterError.unsupportedRequirement(
      `memory: mapping ${JSON.stringify(mappingVersion)} has no route for ${op.method} ${path}`,
    );
  }
  return {
    ...op,
    operation_id: operationId(p.id, op.method, op.target_uri, op.body_digest, mappingVersion),
    environment_id: c.st.gateway.environment_id,
    action: route.action,
    resources: [route.resource],
  };
}

// The path of a target URI that the binding built: what follows the origin,
// up to the query. The origin has no "/" and the path starts with one.
function boundPath(target: string): string {
  const rest = target.startsWith('https://') ? target.slice('https://'.length) : target;
  const fromPath = rest.slice(rest.indexOf('/'));
  const q = fromPath.indexOf('?');
  return q < 0 ? fromPath : fromPath.slice(0, q);
}

// Refuses a request whose bearer token authenticates somebody other than p.
// A token the identity store does not know says nothing about who sent the
// request, so it is not a mismatch.
function matchCredential(c: Core, req: RawRequest, p: Principal): void {
  const token = bearerToken(req);
  if (token === '') return;
  const id = identityBySecret(c, token);
  if (
    id !== undefined &&
    (id.id !== p.id ||
      id.realm.tenant_id !== p.realm.tenantId ||
      id.realm.environment_id !== p.realm.environmentId)
  ) {
    throw AdapterError.contextMismatch(
      'memory: the request authenticates a different principal than the one given',
    );
  }
}

// The route for method and path, with its resource's placeholders filled in.
// path is the path as sent, so a segment with an escape matches no
// placeholder.
function matchRoute(
  m: Mapping,
  method: string,
  path: string,
): { action: string; resource: string } | undefined {
  const segs = path.split('/');
  for (const rt of m.routes) {
    if (rt.method !== method) continue;
    const vars = matchPath(rt.path.split('/'), segs);
    if (vars === undefined) continue;
    let res = rt.resource;
    for (const [k, v] of vars) res = res.replaceAll(`{${k}}`, v);
    return { action: rt.action, resource: res };
  }
  return undefined;
}

// Matches the segments of a request path against a template. A {name}
// segment matches one non-empty segment of unreserved characters.
function matchPath(
  tmpl: readonly string[],
  segs: readonly string[],
): Map<string, string> | undefined {
  if (tmpl.length !== segs.length) return undefined;
  const vars = new Map<string, string>();
  for (const [i, t] of tmpl.entries()) {
    const s = segs[i] as string;
    if (t.startsWith('{') && t.endsWith('}')) {
      if (!/^[A-Za-z0-9._~-]+$/.test(s)) return undefined;
      vars.set(t.slice(1, -1), s);
      continue;
    }
    if (t !== s) return undefined;
  }
  return vars;
}

/**
 * A stable correlation identifier: the same request of the same principal
 * under the same mapping has the same id.
 */
function operationId(
  principal: string,
  method: string,
  target: string,
  digest: string,
  mapping: string,
): string {
  const h = createHash('sha256');
  for (const part of [principal, method, target, digest, mapping]) {
    h.update(part, 'utf8');
    h.update(new Uint8Array([0]));
  }
  return `op-${h.digest('base64url').slice(0, 22)}`;
}
