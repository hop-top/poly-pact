// The adaptertest case model frozen with the adapter contract
// (tools/parity/README.md, Adapter contract): the hooks recorder of
// go/adapter/adaptertest/harness.go, and the request types the shared
// request decoder fills.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  type BindingJSON,
  type Case,
  type ExpectBinding,
  Hooks,
  type Request,
  type TLSPeer,
} from '../src/adapter/adaptertest/index.ts';
import type { TLSPeer as BindingTLSPeer, RawRequest } from '../src/core/binding/index.ts';
import { decodeRequest } from '../src/internal/request.ts';
import { assertType, type Equal } from './support/types.ts';

// One TLS peer type: the case model's is the RawRequest one, with the API
// names of the frozen contract; the case files spell the members in snake case.
assertType<Equal<TLSPeer, BindingTLSPeer>>();
assertType<Equal<Request['tlsPeer'], TLSPeer | null>>();
assertType<Equal<NonNullable<RawRequest['tlsPeer']>, TLSPeer>>();
assertType<Equal<keyof TLSPeer, 'subjectCN' | 'issuerCN' | 'dnsNames' | 'uris'>>();
assertType<
  Equal<
    keyof Request,
    'method' | 'url' | 'headers' | 'body_b64' | 'tlsPeer' | 'native_state_ref' | 'arrival'
  >
>();
assertType<Equal<keyof BindingJSON, 'agent_id' | 'operator_id' | 'holder_jkt' | 'status'>>();
assertType<Equal<ExpectBinding['enrolled_elsewhere'], boolean | null>>();
assertType<
  Equal<
    keyof Case,
    | 'case_version'
    | 'id'
    | 'title'
    | 'draft'
    | 'workloads'
    | 'now'
    | 'native_state'
    | 'request'
    | 'call'
    | 'expect'
  >
>();

test('Hooks records the hooks that ran, in order', () => {
  const h = new Hooks();
  assert.deepEqual(h.fired(), []);
  h.fire('execute');
  h.fire('notify');
  h.fire('execute');
  const got = h.fired();
  assert.deepEqual(got, ['execute', 'notify', 'execute']);
  got.push('tampered');
  assert.deepEqual(h.fired(), ['execute', 'notify', 'execute'], 'fired returns a copy');
});

test('the request decoder reads a case tls_peer into RawRequest.tlsPeer', () => {
  const d = decodeRequest({
    method: 'GET',
    url: 'https://gw.example/x',
    tls_peer: {
      subject_cn: 'svc-a',
      issuer_cn: 'Corp CA',
      dns_names: ['a.example'],
      uris: ['spiffe://example.org/a'],
    },
    native_state_ref: 'alice',
    arrival: 'direct',
  });
  const want: TLSPeer = {
    subjectCN: 'svc-a',
    issuerCN: 'Corp CA',
    dnsNames: ['a.example'],
    uris: ['spiffe://example.org/a'],
  };
  assert.deepEqual(d.request.tlsPeer, want);
  assert.equal(d.request.rawRequestURI, 'https://gw.example/x');
  assert.equal(d.nativeStateRef, 'alice');
  assert.equal(d.arrival, 'direct');
});
