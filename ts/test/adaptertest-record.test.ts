// Port of go/adapter/adaptertest/checks_record_test.go: the record_outcome
// checks, over compact JWS strings a fake puts together (the signature is
// not verified unless the subject has a verifyOutcome hook).

import { test } from 'node:test';
import type { Factory } from '../src/adapter/adaptertest/index.ts';
import { runCase } from '../src/adapter/adaptertest/run.ts';
import { AdapterError, NoVisibility, Signed } from '../src/adapter/index.ts';
import type { EventKind, OutcomeResult } from '../src/core/enums.ts';
import {
  factoryFor,
  NOW,
  type Row,
  recordCase,
  recordFake,
  runRows,
  signedFake,
  type TestCase,
  wantClean,
  wantFails,
} from './support/adaptertest.ts';

const nowSec = NOW / 1000;

const exec = (outcome: string, result: OutcomeResult = 'SUCCESS'): TestCase =>
  recordCase(outcome, {}, 'EXECUTION', result);

test('TestRecordSignedChecks', async (t) => {
  const signedCase = exec('signed');
  const rows: Row[] = [
    ['signed', signedFake(), signedCase, null],
    [
      'signed but declares no visibility',
      recordFake(new NoVisibility('r')),
      signedCase,
      ['want a signed outcome'],
    ],
    [
      'signed but rejects',
      recordFake(null, AdapterError.dependencyUnavailable()),
      signedCase,
      ['want signed'],
    ],
    ['signed but nothing', recordFake(null), signedCase, ['no result']],
    [
      'signed as a plain object',
      recordFake({ jws: 'a.b.c' }),
      signedCase,
      ['return a Signed or a NoVisibility'],
    ],
    ['not a compact JWS', recordFake(new Signed('abc')), signedCase, ['not a compact JWS']],
    [
      'header is not base64url',
      recordFake(new Signed('!.e30.c2ln')),
      signedCase,
      ['header is not unpadded base64url'],
    ],
    [
      'payload is not base64url',
      recordFake(new Signed('e30.!.c2ln')),
      signedCase,
      ['payload is not unpadded base64url'],
    ],
    [
      'wrong typ',
      signedFake((p) => {
        p.hdr.typ = 'JWT';
      }),
      signedCase,
      ['JWS typ is JWT'],
    ],
    [
      'alg none',
      signedFake((p) => {
        p.hdr.alg = 'none';
      }),
      signedCase,
      ['JWS alg is none'],
    ],
    [
      'alg HS256',
      signedFake((p) => {
        p.hdr.alg = 'HS256';
      }),
      signedCase,
      ['JWS alg is HS256'],
    ],
    [
      'alg EdDSA',
      signedFake((p) => {
        p.hdr.alg = 'EdDSA';
      }),
      signedCase,
      ['JWS alg is EdDSA'],
    ],
    [
      'alg Ed25519',
      signedFake((p) => {
        p.hdr.alg = 'Ed25519';
      }),
      signedCase,
      null,
    ],
    [
      'no kid',
      signedFake((p) => {
        delete p.hdr.kid;
      }),
      signedCase,
      ['no kid'],
    ],
    [
      'jku in header',
      signedFake((p) => {
        p.hdr.jku = 'https://x.example/keys';
      }),
      signedCase,
      ['carries "jku"'],
    ],
    [
      'payload is not an object',
      signedFake((p) => {
        p.payload = '[1]';
      }),
      signedCase,
      ['not an outcome report'],
    ],
    [
      'unknown member',
      signedFake((p) => {
        p.payload = '{"pact_version":"0.1","surprise":1}';
      }),
      signedCase,
      ['not an outcome report'],
    ],
    [
      'duplicate member',
      signedFake((p) => {
        p.payload = '{"jti":"a","jti":"b"}';
      }),
      signedCase,
      ['not an outcome report'],
    ],
    [
      'required member missing',
      signedFake((p) => {
        delete (p.rep as Record<string, unknown>).evidence_refs;
      }),
      signedCase,
      ['lacks the required member "evidence_refs"'],
    ],
    [
      'array member null',
      signedFake((p) => {
        p.rep.supersedes = null as never;
      }),
      signedCase,
      ['not an outcome report', '/supersedes'],
    ],
    [
      'wrong pact version',
      signedFake((p) => {
        p.rep.pact_version = '0.2';
      }),
      signedCase,
      ['pact_version'],
    ],
    [
      'wrong event id',
      signedFake((p) => {
        p.rep.event_id = 'other';
      }),
      signedCase,
      ['event_id'],
    ],
    [
      'wrong operation id',
      signedFake((p) => {
        p.rep.operation_id = 'other';
      }),
      signedCase,
      ['operation_id'],
    ],
    [
      'wrong task id',
      signedFake((p) => {
        p.rep.task_id = 'other';
      }),
      signedCase,
      ['task_id'],
    ],
    [
      'wrong kind',
      signedFake((p) => {
        p.rep.event_kind = 'QUALITY' as EventKind;
      }),
      signedCase,
      ['event_kind'],
    ],
    [
      'assumed result',
      signedFake((p) => {
        p.rep.result = 'FAILURE';
      }),
      signedCase,
      ['result is'],
    ],
    [
      'wrong dimension',
      signedFake((p) => {
        p.rep.dimension = 'none' as never;
      }),
      signedCase,
      ['dimension'],
    ],
    [
      'wrong severity',
      signedFake((p) => {
        p.rep.severity = 'high';
      }),
      signedCase,
      ['severity'],
    ],
    [
      'wrong tenant',
      signedFake((p) => {
        p.rep.tenant_id = 'globex';
      }),
      signedCase,
      ['tenant_id'],
    ],
    [
      'wrong environment',
      signedFake((p) => {
        p.rep.environment_id = 'other';
      }),
      signedCase,
      ['environment_id'],
    ],
    [
      'wrong subject',
      signedFake((p) => {
        p.rep.sub = 'https://x.example/agents/other';
      }),
      signedCase,
      ['sub is'],
    ],
    [
      'restamped observation',
      signedFake((p) => {
        p.rep.observed_at = nowSec;
      }),
      signedCase,
      ['original observation time'],
    ],
    [
      'wrong context',
      signedFake((p) => {
        p.rep.context = { ...p.rep.context, purpose_id: 'other' };
      }),
      signedCase,
      ['context is'],
    ],
    [
      'undefined reporter role',
      signedFake((p) => {
        p.rep.reporter_role = 'robot' as never;
      }),
      signedCase,
      ['reporter_role'],
    ],
    [
      'short jti',
      signedFake((p) => {
        p.rep.jti = 'short';
      }),
      signedCase,
      ['jti has 5 characters'],
    ],
    [
      'expired',
      signedFake((p) => {
        p.rep.exp = nowSec;
      }),
      signedCase,
      ['validity'],
    ],
    [
      'issued in the future',
      signedFake((p) => {
        p.rep.iat = nowSec + 60;
      }),
      signedCase,
      ['validity'],
    ],
    [
      'valid for too long',
      signedFake((p) => {
        p.rep.exp = p.rep.iat + 301;
      }),
      signedCase,
      ['lifetime'],
    ],
    [
      'no issuer',
      signedFake((p) => {
        p.rep.iss = '';
      }),
      signedCase,
      ['iss is empty'],
    ],
    [
      'no audience',
      signedFake((p) => {
        p.rep.aud = '';
      }),
      signedCase,
      ['aud is empty'],
    ],
  ];
  await runRows(t, rows);
});

test('TestRecordOutcomes', async (t) => {
  const noVis = new NoVisibility('execution happens in a system the adapter cannot observe');
  const rows: Row[] = [
    ['no visibility', recordFake(noVis), exec('no_visibility', 'UNKNOWN'), null],
    [
      'no visibility but signed',
      signedFake(),
      exec('no_visibility', 'UNKNOWN'),
      ['want a declared absence'],
    ],
    [
      'no visibility without a reason',
      recordFake(new NoVisibility(' ')),
      exec('no_visibility', 'UNKNOWN'),
      ['no-visibility declaration'],
    ],
    [
      'no visibility as a plain object',
      recordFake({ reason: 'r' }),
      exec('no_visibility', 'UNKNOWN'),
      ['return a Signed or a NoVisibility'],
    ],

    ['no success, declared', recordFake(noVis), exec('no_execution_success'), null],
    [
      'no success, assumed',
      signedFake(),
      exec('no_execution_success'),
      ['although the case gives the adapter no execution visibility'],
    ],
    ['no success, unknown signed', signedFake(), exec('no_execution_success', 'UNKNOWN'), null],
    ['no success, failure signed', signedFake(), exec('no_execution_success', 'FAILURE'), null],
    [
      'no success, admission signed',
      signedFake(),
      recordCase('no_execution_success', {}, 'ADMISSION', 'SUCCESS'),
      null,
    ],
    [
      'no success, bad declaration',
      recordFake(new NoVisibility('')),
      exec('no_execution_success'),
      ['no-visibility declaration'],
    ],

    ['error', recordFake(null, AdapterError.unsupportedRequirement()), exec('error'), null],
    [
      'error with a code',
      recordFake(null, AdapterError.unsupportedRequirement()),
      recordCase('error', { reason_code: 'UNSUPPORTED_REQUIREMENT' }, 'QUALITY', 'SUCCESS'),
      null,
    ],
    ['error expected, recorded', signedFake(), exec('error'), ['want an error']],
    [
      'error of another code',
      recordFake(null, new Error('x')),
      recordCase('error', { reason_code: 'UNSUPPORTED_REQUIREMENT' }, 'QUALITY', 'SUCCESS'),
      ['carries no draft 13.4 code'],
    ],
  ];
  await runRows(t, rows);

  await t.test('verification', async () => {
    const f = signedFake();
    const verify =
      (err?: Error): Factory =>
      (env) => ({
        ...factoryFor(f)(env),
        verifyOutcome: () => {
          if (err !== undefined) throw err;
        },
      });
    const c = exec('signed') as never;
    wantClean(await runCase(verify(), c));
    wantFails(
      await runCase(verify(new Error('bad signature')), c),
      'signature of the outcome does not verify',
    );
  });
});
