// Port of go/adapter/adaptertest/leak_test.go: the credential patterns and
// the scan of every value and error a function returns.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { findCredentials } from '../src/adapter/adaptertest/leak.ts';
import { AdapterError, DenialReason, NativeDenial, NoVisibility } from '../src/adapter/index.ts';
import {
  authCase,
  authFake,
  authzCase,
  authzFake,
  bindCase,
  checkCase,
  checkFake,
  claimCase,
  claimFake,
  fake,
  goodOp,
  goodPrincipal,
  mapCase,
  mapFake,
  type Row,
  recordCase,
  recordFake,
  runFake,
  runRows,
  signedFake,
  wantClean,
  wantFails,
  ZERO_PRINCIPAL,
} from './support/adaptertest.ts';

test('TestFindCredentials', async (t) => {
  const tests: [string, string, string[], string[]][] = [
    ['clean', '{"Result":"PASS","ReasonCode":"REQUIREMENT_SATISFIED"}', [], []],
    [
      'prose that is not a credential',
      'basic authentication failed; the bearer is unknown',
      [],
      [],
    ],
    [
      'event kind is not a header',
      '{"event_kind":"AUTHORIZATION","details":"authorization denied"}',
      [],
      [],
    ],
    [
      'literal secret',
      'failed for tok-alice-7f3a',
      ['tok-alice-7f3a'],
      ['secret "tok-alice-7f3a"'],
    ],
    ['empty secret is ignored', 'anything', [''], []],
    ['bearer value', 'Authorization: Bearer abcdefghijklmnop1234', [], ['authorization value']],
    ['short bearer is not a value', 'Bearer abc', [], []],
    ['basic value', 'Basic dXNlcjpwYXNzd29yZDEyMzQ1', [], ['authorization value']],
    [
      'compact JWS',
      'token eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl',
      [],
      ['compact JWS'],
    ],
    [
      'authorization header member',
      '{"headers":{"authorization":"x"}}',
      [],
      ['credential header as a member name'],
    ],
    [
      'cookie header member, any case',
      '{"Cookie" :"x"}',
      [],
      ['credential header as a member name'],
    ],
    [
      'presentation header member',
      '{"pact-presentation":"x"}',
      [],
      ['credential header as a member name'],
    ],
    ['private JWK d', '{"kty":"EC","d":"abc"}', [], ['private JWK parameter']],
    ['private JWK k', '{"kty":"oct","k":"abc"}', [], ['private JWK parameter']],
    ['public JWK', '{"kty":"EC","x":"abc","y":"def"}', [], []],
    [
      'access token in a URL',
      'https://e.example/a?access_token=tok-evidence-5c0e8b13',
      [],
      ['credential assignment'],
    ],
    ['session cookie value', 'session=sess-cookie-93ab1f60', [], ['credential assignment']],
    ['password', 'password=hunter22', [], ['credential assignment']],
    ['redaction mask in brackets', 'access_token=[redacted]', [], []],
    ['redaction mask in words', 'session=REDACTED password=removed', [], []],
    ['redaction mask in stars', 'secret=****** api_key=xxxxxxxx', [], []],
    [
      'mask followed by a credential',
      'access_token=[redacted] session=sess-cookie-93ab1f60',
      [],
      ['credential assignment'],
    ],
    ['short value is not a credential', 'sid=abc', [], []],
    // The mask characters are trimmed before the value is lowered.
    ['upper-case x is a value', 'secret=XXXXXXXX', [], ['credential assignment']],
  ];
  for (const [name, text, secrets, want] of tests) {
    await t.test(name, () => {
      const got = findCredentials(text, secrets);
      if (want.length === 0) {
        assert.deepEqual(got, [], `found ${JSON.stringify(got)} in ${text}`);
        return;
      }
      for (const w of want)
        assert.ok(
          got.some((g) => g.includes(w)),
          `findings ${JSON.stringify(got)} lack ${w}`,
        );
    });
  }
});

// An authenticate_native case that asks for a leak scan.
const leakCase = (...secrets: string[]) => authCase('denied', { leak_scan: { secrets } });

test('TestLeakScanOfErrors', async (t) => {
  const denial = new NativeDenial(DenialReason.CREDENTIAL_REJECTED);
  const rows: Row[] = [
    ['clean denial', authFake(ZERO_PRINCIPAL, denial), leakCase('tok-forged-4e1d7a09'), null],
    [
      'token in a wrapping error',
      authFake(ZERO_PRINCIPAL, new Error('token tok-forged-4e1d7a09 rejected', { cause: denial })),
      leakCase('tok-forged-4e1d7a09'),
      ['error carries a credential', 'tok-forged-4e1d7a09'],
    ],
    [
      'bearer value in a wrapping error',
      authFake(ZERO_PRINCIPAL, new Error('Bearer abcdefghijklmnop1234', { cause: denial })),
      leakCase(),
      ['authorization value'],
    ],
    // A cause is part of the error's text, as a wrapped error is in Go.
    [
      'token in the cause of an error',
      authFake(
        ZERO_PRINCIPAL,
        AdapterError.dependencyUnavailable('', { cause: new Error('token tok-forged-4e1d7a09') }),
      ),
      authCase('error', { leak_scan: { secrets: ['tok-forged-4e1d7a09'] } }),
      ['authenticateNative error carries a credential'],
    ],
    [
      'no scan asked, no scan made',
      authFake(ZERO_PRINCIPAL, new Error('token tok-forged-4e1d7a09 rejected', { cause: denial })),
      authCase('denied'),
      null,
    ],
  ];
  await runRows(t, rows);
});

test('TestLeakScanOfValues', async (t) => {
  const scan = { secrets: ['tok-secret-1234'] };
  const loose = {
    environment_id: '',
    principal_id: '',
    action: '',
    resources: null,
    method: '',
    target_uri: '',
    body_digest: '',
    headers: null,
  };

  await t.test('operation', async () => {
    const c = mapCase('mapped', { operation: loose, leak_scan: scan });
    wantClean(await runFake(mapFake(goodOp()), c));
    wantFails(
      await runFake(mapFake({ ...goodOp(), headers: { authorization: 'x' } }), c),
      'operation carries a credential',
    );
    wantFails(
      await runFake(mapFake({ ...goodOp(), headers: { 'x-kind': 'tok-secret-1234' } }), c),
      'secret "tok-secret-1234"',
    );
  });

  await t.test('operation error', async () => {
    const c = mapCase('error', { leak_scan: scan });
    wantClean(await runFake(mapFake({}, AdapterError.contextMismatch()), c));
    wantFails(
      await runFake(mapFake({}, AdapterError.contextMismatch('tok-secret-1234')), c),
      'mapOperation error carries a credential',
    );
  });

  await t.test('check outcome', async () => {
    const c = checkCase('x', 'PASS', { leak_scan: scan });
    const clean = { result: 'PASS', reasonCode: 'R', sourceRef: 'appr-42' } as const;
    wantClean(await runFake(checkFake(clean), c));
    wantFails(
      await runFake(
        checkFake({ ...clean, sourceRef: 'https://e.example/a?access_token=tok-secret-1234' }),
        c,
      ),
      'checkContext outcome carries a credential',
    );
  });

  await t.test('claim', async () => {
    const c = claimCase('claim', {
      claim: {
        value: null,
        observed_at: null,
        status_checked_at: null,
        source_id: '',
        source_ref: '',
      },
      leak_scan: scan,
    });
    const good = {
      value: ['approver'],
      observedAt: null,
      statusCheckedAt: null,
      sourceId: 'directory-1',
      sourceRef: 'entry-17',
    };
    wantClean(await runFake(claimFake(good), c));
    wantFails(
      await runFake(claimFake({ ...good, sourceRef: 'tok-secret-1234' }), c),
      'claim carries a credential',
    );
  });

  await t.test('decision', async () => {
    const c = authzCase('DENY', { leak_scan: scan });
    wantClean(await runFake(authzFake({ effect: 'DENY', sourceId: 'policy-1' }), c));
    wantFails(
      await runFake(
        authzFake({ effect: 'DENY', reason: 'tok-secret-1234', sourceId: 'policy-1' }),
        c,
      ),
      'decision carries a credential',
    );
  });

  await t.test('principal', async () => {
    const c = authCase('authenticated', {
      principal: { id: '', realm: null, workload: '', mechanism: '', attributes: null },
      leak_scan: scan,
    });
    wantClean(await runFake(authFake(goodPrincipal()), c));
    wantFails(
      await runFake(authFake({ ...goodPrincipal(), attributes: { token: 'tok-secret-1234' } }), c),
      'principal carries a credential',
    );
  });

  await t.test('signed outcome, decoded', async () => {
    const c = recordCase('signed', { leak_scan: scan }, 'EXECUTION', 'SUCCESS');
    wantClean(await runFake(signedFake(), c));
    // A credential in the payload is base64url in the JWS string, so only
    // the decoded payload shows it.
    wantFails(
      await runFake(
        signedFake((p) => {
          p.rep.details = 'rejected: tok-secret-1234';
        }),
        c,
      ),
      'signed outcome segment 1 carries a credential',
    );
    wantFails(
      await runFake(
        signedFake((p) => {
          p.rep.details = 'Authorization: Bearer abcdefghijklmnop1234';
        }),
        c,
      ),
      'authorization value',
    );
    wantFails(
      await runFake(
        signedFake((p) => {
          p.rep.evidence_refs = ['https://e.example/x?access_token=abcdef123456'];
        }),
        c,
      ),
      'credential assignment',
    );
    // A masked value is not a credential.
    wantClean(
      await runFake(
        signedFake((p) => {
          p.rep.details = 'Authorization: [redacted] access_token=[redacted]';
        }),
        c,
      ),
    );
  });

  await t.test('no visibility declaration', async () => {
    const c = recordCase('no_visibility', { leak_scan: scan }, 'EXECUTION', 'SUCCESS');
    wantClean(await runFake(recordFake(new NoVisibility('cannot see')), c));
    wantFails(
      await runFake(recordFake(new NoVisibility('cannot see tok-secret-1234')), c),
      'declaration carries a credential',
    );
  });
});

test('TestLeakScanRunsOnEveryError', async (t) => {
  // One error per function, each carrying the secret.
  const secretErr = () => Promise.reject(new Error('tok-secret-1234'));
  const scan = { secrets: ['tok-secret-1234'] };
  const f = fake({
    auth: secretErr,
    bind: secretErr,
    claim: secretErr,
    authz: secretErr,
    record: secretErr,
    mapOp: secretErr,
  });
  for (const [name, c] of Object.entries({
    authenticate: authCase('error', { leak_scan: scan }),
    binding: bindCase('error', { leak_scan: scan }),
    map: mapCase('error', { leak_scan: scan }),
    claim: claimCase('error', { leak_scan: scan }),
    authorize: authzCase('error', { leak_scan: scan }),
    record: recordCase('error', { leak_scan: scan }, 'EXECUTION', 'SUCCESS'),
  })) {
    await t.test(name, async () => {
      wantFails(await runFake(f, c), 'error carries a credential');
    });
  }
});
