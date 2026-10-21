// Port of go/adapter/descriptors_test.go.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  type Adapter,
  type Descriptor,
  descriptorsOf,
  type MultiDescriber,
} from '../src/adapter/index.ts';

// An adapter that publishes one descriptor; only describe is called.
function single(d: Descriptor): Adapter {
  return { describe: () => d } as unknown as Adapter;
}

// An adapter that serves several native protocol forms.
function multi(d: Descriptor, ds: Descriptor[]): Adapter & MultiDescriber {
  return { describe: () => d, descriptors: () => ds } as unknown as Adapter & MultiDescriber;
}

// One GatewayMetadata.adapters entry per pinned protocol revision (draft
// 13.3): every descriptor of a MultiDescriber, otherwise the one describe
// returns.
test('TestDescriptorsOf', () => {
  const intro: Descriptor = {
    protocol: 'oauth-introspection',
    version: 'rfc7662',
    mappingRevision: 'pact-oauth-1',
  };
  const entra: Descriptor = {
    protocol: 'entra-access-token',
    version: '2.0',
    mappingRevision: 'pact-oauth-1',
  };
  assert.deepEqual(descriptorsOf(single(intro)), [intro], 'one form');
  assert.deepEqual(descriptorsOf(multi(intro, [intro, entra])), [intro, entra], 'two forms');

  const ds = [{ ...intro }];
  const got = descriptorsOf(multi(intro, ds));
  (got[0] as { protocol: string }).protocol = 'changed';
  got.push(entra);
  assert.deepEqual(ds, [intro], 'the result shares the adapter values');
});
