/**
 * The map_operation checks of the suite (Go
 * hop.top/pact-go/adapter/adaptertest, checks_operation.go).
 *
 * @module
 */
import type { RawRequest } from '../../core/binding/index.ts';
import type { OperationContext } from '../../core/types.ts';
import type { ExpectOperation } from './casefile.ts';
import { errorText } from './leak.ts';
import { OUT } from './load.ts';
import { digestProblem, type Run } from './run.ts';

/** Whether an operation context carries nothing a caller could act on. */
export function operationEmpty(op: Partial<OperationContext> | null | undefined): boolean {
  return (
    (op?.operation_id ?? '') === '' &&
    (op?.principal_id ?? '') === '' &&
    (op?.action ?? '') === '' &&
    (op?.target_uri ?? '') === '' &&
    (op?.body_digest ?? '') === '' &&
    (op?.resources?.length ?? 0) === 0
  );
}

/** Whether two string lists are equal, in order. */
export function equalStrings(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/** Whether two string maps are equal. */
export function equalMaps(
  a: Readonly<Record<string, string>>,
  b: Readonly<Record<string, string>>,
): boolean {
  const ka = Object.keys(a);
  return (
    ka.length === Object.keys(b).length && ka.every((k) => Object.hasOwn(b, k) && a[k] === b[k])
  );
}

/** A header map with sorted names, for messages. */
export function formatMap(m: Readonly<Record<string, string>>): string {
  const parts = Object.keys(m)
    .sort()
    .map((k) => `${JSON.stringify(k)}: ${JSON.stringify(m[k])}`);
  return `{${parts.join(', ')}}`;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Runs a map_operation case. */
export async function mapOperation(r: Run): Promise<void> {
  const built = r.request();
  if (built === undefined) return;
  const p = r.principal();
  const s = await r.call('mapOperation', () =>
    r.subj.adapter.mapOperation(built.req, p, r.c.call.mapping_version, r.signal),
  );
  if (s === undefined) return;
  checkBodyLeft(r, built.req, built.body);
  const err = s.ok ? undefined : s.error;
  const op = s.ok ? s.value : undefined;
  if (!s.ok) r.scanError('mapOperation', err);
  else r.scanValue('mapOperation operation', op);

  const e = r.c.expect;
  switch (e.outcome) {
    case OUT.mapped:
      if (!s.ok) {
        r.failf(`mapOperation rejected with ${errorText(err)}, want an operation context`);
        return;
      }
      checkOperation(r, op as OperationContext, p.id, e.operation);
      break;
    case OUT.error:
      if (s.ok) {
        r.failf(
          `mapOperation mapped the request to ${op?.method} ${op?.target_uri}, want an error`,
        );
        return;
      }
      r.wantReason('mapOperation', err);
      break;
  }
}

// Fails when the adapter changed the body of the request it was handed: the
// digest covers the exact bytes, and the request must still be forwardable
// (draft 10.2). A RawRequest is a value, so a reader only changes it by
// writing into its body.
function checkBodyLeft(r: Run, req: RawRequest, body: Uint8Array): void {
  if (body.length === 0) return;
  const got = req.body;
  if (!(got instanceof Uint8Array)) {
    r.failf('mapOperation left the request without a body; it must leave what it reads');
    return;
  }
  if (!Buffer.from(got).equals(Buffer.from(body))) {
    r.failf(
      `mapOperation left ${got.length} body bytes that differ from the original ${body.length}; it must leave what it reads`,
    );
  }
}

// A mapped operation against the invariants of the baseline HTTP mapping
// (draft 10.2) and the case.
function checkOperation(
  r: Run,
  op: OperationContext,
  principalId: string,
  want: ExpectOperation | null,
): void {
  const o = (op ?? {}) as Partial<OperationContext>;
  if ((o.operation_id ?? '') === '') r.failf('operation_id is empty');
  if (o.principal_id !== principalId) {
    r.failf(
      `principal_id is ${JSON.stringify(o.principal_id)}, want the authenticated principal ${JSON.stringify(principalId)}: the principal comes from native authentication, never from the request`,
    );
  }
  const method = o.method ?? '';
  if (method !== method.toUpperCase()) r.failf(`method ${JSON.stringify(method)} is not uppercase`);
  const target = o.target_uri ?? '';
  if (!target.startsWith('https://')) {
    r.failf(`target_uri ${JSON.stringify(target)} is not an https URI`);
  }
  if (target.includes('#')) r.failf(`target_uri ${JSON.stringify(target)} carries a fragment`);
  const bad = digestProblem(o.body_digest);
  if (bad !== undefined) r.failf(`body_digest: ${bad}`);
  // The wire form has an array and an object here.
  if (!Array.isArray(o.resources)) {
    r.failf(`resources is ${String(o.resources)}, not an array; it must be an array`);
  }
  if (!isPlainObject(o.headers)) {
    r.failf(`headers is ${String(o.headers)}, not an object; it must be an object`);
  } else {
    for (const name of Object.keys(o.headers)) {
      if (name !== name.toLowerCase())
        r.failf(`header name ${JSON.stringify(name)} is not lowercase`);
    }
  }
  if (want === null) return;
  const q = JSON.stringify;
  if (want.environment_id !== '' && o.environment_id !== want.environment_id) {
    r.failf(`environment_id is ${q(o.environment_id)}, want ${q(want.environment_id)}`);
  }
  if (want.principal_id !== '' && o.principal_id !== want.principal_id) {
    r.failf(`principal_id is ${q(o.principal_id)}, want ${q(want.principal_id)}`);
  }
  if (want.action !== '' && o.action !== want.action) {
    r.failf(`action is ${q(o.action)}, want ${q(want.action)}`);
  }
  if (want.resources !== null && !equalStrings(o.resources ?? [], want.resources)) {
    r.failf(
      `resources are ${q(o.resources)}, want ${q(want.resources)}: the resources come from the request and the installed mapping, never from a client-supplied list`,
    );
  }
  if (want.method !== '' && o.method !== want.method) {
    r.failf(`method is ${q(o.method)}, want ${q(want.method)}`);
  }
  if (want.target_uri !== '' && o.target_uri !== want.target_uri) {
    r.failf(`target_uri is ${q(o.target_uri)}, want ${q(want.target_uri)}`);
  }
  if (want.body_digest !== '' && o.body_digest !== want.body_digest) {
    r.failf(`body_digest is ${q(o.body_digest)}, want ${q(want.body_digest)}`);
  }
  if (
    want.headers !== null &&
    !equalMaps(isPlainObject(o.headers) ? (o.headers as Record<string, string>) : {}, want.headers)
  ) {
    r.failf(
      `headers are ${formatMap(isPlainObject(o.headers) ? (o.headers as Record<string, string>) : {})}, want ${formatMap(want.headers)}`,
    );
  }
}
