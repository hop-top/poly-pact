// Port of the state tests of go/adapters/memory/memory_unit_test.go and
// fold_test.go: the constructor validates the state, the state document is
// read strictly, and the origin is normalized with ASCII case folding only.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Adapter } from '../src/adapter/index.ts';
import {
  fromJSON,
  MemoryAdapter,
  normalizeOrigin,
  parseState,
  type State,
} from '../src/adapters/memory/index.ts';
import { FakeClock } from '../src/core/clock.ts';
import { baseState, enrollment, type MState, newAdapter, rule, T0 } from './support/memory.ts';

function errorOf(f: () => unknown): string {
  try {
    f();
  } catch (err) {
    return (err as Error).message;
  }
  return '';
}

test('TestNewValidatesTheState', async (t) => {
  const tests: [string, (st: MState) => void, string][] = [
    ['valid', () => {}, ''],
    [
      'wrong model',
      (st) => {
        st.model = 'common/2';
      },
      'model',
    ],
    [
      'no tenant',
      (st) => {
        st.gateway.tenant_id = '';
      },
      'tenant_id',
    ],
    [
      'http origin',
      (st) => {
        st.gateway.origin = 'http://gateway.example';
      },
      'https origin',
    ],
    [
      'origin with a path',
      (st) => {
        st.gateway.origin = 'https://gateway.example/api';
      },
      'bare origin',
    ],
    [
      'origin with userinfo',
      (st) => {
        st.gateway.origin = 'https://u:p@gateway.example';
      },
      'bare origin',
    ],
    // The baseline mapping's own configuration checks apply too.
    [
      'origin with a trailing slash',
      (st) => {
        st.gateway.origin = 'https://gateway.example/';
      },
      'invalid configuration',
    ],
    [
      'presentation header on the allowlist',
      (st) => {
        st.gateway.header_allowlist = ['pact-trace'];
      },
      'invalid configuration',
    ],
    [
      'allowlist entry is not a token',
      (st) => {
        st.gateway.header_allowlist = ['x kind'];
      },
      'invalid configuration',
    ],
    [
      'mapping version too long',
      (st) => {
        (st.mappings[0] as MState['mappings'][number]).version = 'v'.repeat(1025);
      },
      'invalid configuration',
    ],
    [
      'credential header on the allowlist',
      (st) => {
        st.gateway.header_allowlist = ['authorization'];
      },
      'never belong',
    ],
    [
      'hop-by-hop header on the allowlist',
      (st) => {
        st.gateway.header_allowlist = ['connection'];
      },
      'never belong',
    ],
    [
      'uppercase allowlist entry',
      (st) => {
        st.gateway.header_allowlist = ['X-Kind'];
      },
      'lowercase',
    ],
    [
      'mapping without a version',
      (st) => {
        (st.mappings[0] as MState['mappings'][number]).version = '';
      },
      'no version',
    ],
    [
      'incomplete route',
      (st) => {
        ((st.mappings[0] as MState['mappings'][number]).routes[0] as { action: string }).action =
          '';
      },
      'incomplete route',
    ],
    [
      'identity without a secret',
      (st) => {
        (st.identities[0] as { secret: string }).secret = '';
      },
      'needs a ref',
    ],
    [
      'duplicate identity ref',
      (st) => {
        (st.identities[1] as { ref: string }).ref = 'alice';
      },
      'used twice',
    ],
    [
      'bad enrollment status',
      (st) => {
        st.enrollments = [
          enrollment({
            workload: 'w',
            status: 'SUSPENDED',
            agent_id: 'https://a.example/a',
            source_id: 's',
          }),
        ];
      },
      'status',
    ],
    [
      'enrollment without a source',
      (st) => {
        st.enrollments = [
          enrollment({ workload: 'w', agent_id: 'https://a.example/a', source_id: '' }),
        ];
      },
      'source_id',
    ],
    [
      'enrollment agent is not a URI',
      (st) => {
        st.enrollments = [enrollment({ workload: 'w', agent_id: 'agent', source_id: 's' })];
      },
      'absolute URI',
    ],
    [
      'enrollment holder key is not a thumbprint',
      (st) => {
        st.enrollments = [
          enrollment({
            workload: 'w',
            agent_id: 'https://a.example/a',
            source_id: 's',
            holder_jkt: 'x',
          }),
        ];
      },
      'digest',
    ],
    [
      'claim outside the approved paths',
      (st) => {
        (st.claims[0] as { path: string }).path = '/other';
      },
      'approved path',
    ],
    [
      'claim without a value',
      (st) => {
        (st.claims[0] as { value: unknown }).value = null;
      },
      'no value',
    ],
    [
      'claim without a source',
      (st) => {
        (st.claims[0] as { source_id: string }).source_id = '';
      },
      'source_id',
    ],
    [
      'check with a bad result',
      (st) => {
        (st.checks[0] as { result: string }).result = 'OK';
      },
      'needs an id',
    ],
    [
      'policy with a bad effect',
      (st) => {
        st.policy = [rule({ principal: 'p', action: 'a', effect: 'PERMIT' })];
      },
      'needs a principal',
    ],
    [
      'bad visibility',
      (st) => {
        st.visibility = 'partial';
      },
      'visibility',
    ],
    [
      'reporting without a key id',
      (st) => {
        (st.reporting as { kid: string }).kid = '';
      },
      'reporting',
    ],
  ];
  for (const [name, mutate, want] of tests) {
    await t.test(name, () => {
      const st = baseState();
      mutate(st);
      const err = errorOf(() => new MemoryAdapter(st as State, new FakeClock(T0)));
      if (want === '') assert.equal(err, '');
      else assert.ok(err.includes(want), `err = ${err}, want it to mention ${want}`);
    });
  }

  await t.test('no clock', () => {
    const { a } = newAdapter();
    assert.throws(() => new MemoryAdapter(a.state(), undefined as never), /no clock/);
  });
});

test('TestParseStateIsStrict', () => {
  const base =
    '{"model":"common/1","gateway":{"tenant_id":"t","environment_id":"e","origin":"https://g.example"}';
  for (const [name, doc] of Object.entries({
    'unknown member': `${base},"surprise":1}`,
    'duplicate member': `${base},"visibility":"none","visibility":"none"}`,
    'unknown in nested': `${base.replace('"origin"', '"extra":1,"origin"')}}`,
    'not an object': '[]',
    'a time that is not an integer': `${base},"sightings":[{"source_id":"s","source_ref":"r","observed_at":1.5}]}`,
  })) {
    assert.throws(() => parseState(doc), Error, `${name}: parseState accepted ${doc}`);
  }
  assert.doesNotThrow(() => parseState(`${base}}`), 'minimal state');
  assert.doesNotThrow(() => fromJSON(`${base}}`, new FakeClock(T0)), 'fromJSON');
  assert.throws(() => fromJSON('{', new FakeClock(T0)), Error, 'fromJSON accepted broken JSON');
});

test('TestNormalizeOrigin', () => {
  for (const [input, want] of Object.entries({
    'https://gateway.example': 'https://gateway.example',
    'HTTPS://Gateway.Example:443': 'https://gateway.example',
    'https://gateway.example:8443': 'https://gateway.example:8443',
    'https://gateway.example/': 'https://gateway.example',
    'https://[::1]:443': 'https://[::1]',
    'https://[2001:db8::1]:8443': 'https://[2001:db8::1]:8443',
  })) {
    assert.equal(normalizeOrigin(input), want, input);
  }
  for (const input of [
    '',
    'gateway.example',
    'http://gateway.example',
    'https://',
    'https://g.example/x',
    'https://g.example?x=1',
    'https://g.example#f',
    'mailto:a@b.example',
  ]) {
    assert.throws(() => normalizeOrigin(input), Error, `normalizeOrigin(${input})`);
  }
});

// Hosts are compared without regard to ASCII case only (RFC 3986 3.2.2; a
// reg-name is ASCII). toLowerCase maps U+212A KELVIN SIGN to "k" and U+0130
// to "i̇", so an origin naming either is another origin, never the ASCII one
// it lowercases to.
test('TestNormalizeOriginFoldASCII', () => {
  for (const [input, ascii] of Object.entries({
    'https://pacK.example': 'https://pack.example',
    'https://İdp.example': 'https://idp.example',
  })) {
    let got = '';
    try {
      got = normalizeOrigin(input);
    } catch {
      continue;
    }
    assert.notEqual(got, ascii, `normalizeOrigin(${input}) is the ASCII origin`);
  }
  assert.equal(normalizeOrigin('https://PACK.Example'), 'https://pack.example');
  assert.equal(normalizeOrigin('HtTpS://pack.example'), 'https://pack.example');
});

test('TestDescribe', () => {
  const { a } = newAdapter();
  const d = a.describe();
  assert.ok(d.protocol !== '' && d.version !== '' && d.mappingRevision !== '', JSON.stringify(d));
  const _: Adapter = a;
  void _;
});
