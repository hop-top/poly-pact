// Port of go/runner/evalcase/evalcase_test.go: the committed evaluation
// cases through the case loader, and the stale, trust and format rules.

import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { type TestContext, test } from 'node:test';
import {
  type Case,
  Decision,
  dirs,
  load,
  loadKeys,
  read,
  verify,
} from '../src/conformance/case.ts';
import {
  Reason,
  Role,
  reasonOf,
  TYP_EVIDENCE,
  TYP_PRESENTATION,
  TYP_REPUTATION,
  TYP_REQUIREMENTS,
} from '../src/core/jws/index.ts';
import { Kind, load as loadManifest } from '../src/runner/manifest/index.ts';
import {
  at,
  caseTree,
  edit,
  editJSON,
  flipSignature,
  type JSONObject,
  payloadOf,
  REPO_FIXTURES,
  readFile,
  removeFile,
  wantThrows,
  writeFile,
} from './support/evalcase.ts';
import { fixturesPresent } from './support/fixtures.ts';

// The committed signed files that a case makes fail verification against
// its trust records on purpose, with the jws reason. An artifact entry with
// payload_signed must fail with signature-invalid (spec/v1.0/fixtures/README.md,
// Generator contract) and need not be listed. A new case whose artifact
// fails verification by design adds a row here.
const designedUntrusted: Readonly<Record<string, Reason>> = {
  // The presentation is signed by a holder key other than the enrolled one
  // (native_context.json authenticated.holder_jkt).
  'admission/old-holder-key/signed/presentation.jws': Reason.HOLDER_JKT_MISMATCH,
  // The presentation is signed by the key that a rotation retired; the
  // enrollment names the key after the rotation.
  'admission/rotated-holder-key/signed/presentation.jws': Reason.HOLDER_JKT_MISMATCH,
  // The presented agent has no binding on the authenticated workload:
  // native_context.json authenticated.holder_jkt is null, so no enrolled key
  // exists to verify the presentation against.
  'admission/agent-of-other-workload/signed/presentation.jws': Reason.KEY_UNAVAILABLE,
  'admission/other-realm-agent-other-tenant/signed/presentation.jws': Reason.KEY_UNAVAILABLE,
  'admission/unenrolled-agent/signed/presentation.jws': Reason.KEY_UNAVAILABLE,
  'admission/workload-two-enrollments/signed/presentation.jws': Reason.KEY_UNAVAILABLE,
};

interface EvaluateEntry {
  readonly id: string;
  readonly path: string;
  readonly expected: string;
}

function evaluateEntries(): EvaluateEntry[] {
  const out = loadManifest(REPO_FIXTURES)
    .entries.filter((e) => e.kind === Kind.EVALUATE)
    .map((e) => ({ id: e.id, path: e.path, expected: e.expected ?? '' }));
  assert.ok(out.length > 0, 'no evaluate entry in the manifest');
  return out;
}

const text = new TextDecoder();

// Every evaluate entry of the manifest loads, v1 and v2 alike; every signed
// file its signing.json names is read and verified, and verifies against
// the case's trust records unless the case makes it fail by design.
test('TestLoadsEveryCommittedCase', async (t) => {
  if (!fixturesPresent(t)) return;
  const seen = new Set<string>();
  for (const e of evaluateEntries()) {
    await t.test(e.id, () => {
      const c = load(REPO_FIXTURES, e.id);
      assert.ok(
        c.id === e.id && c.path === e.path && c.exchanges.length > 0,
        `case ${c.id} path ${c.path} with ${c.exchanges.length} exchanges`,
      );
      assert.equal(
        c.exchanges[c.subject]?.expectedPath,
        e.expected,
        'subject exchange expected file',
      );
      for (const x of c.exchanges) {
        assert.ok(
          x.config.now !== 0 && x.config.trust.length > 0 && x.nativeContext.authenticated !== null,
          `${x.path}: config or native context not read`,
        );
        const n = x.signing.artifacts.length + x.signing.presentations.length;
        assert.ok(
          x.signed.length === n && n > 0,
          `${x.path}: ${x.signed.length} signed files for ${n} signing.json entries`,
        );
        assert.equal(
          Decision.expectedResponses(x.expected).length,
          x.submissions.length,
          `${x.path}: expected responses per submission`,
        );
        const tampered = new Set(
          x.signing.artifacts.filter((a) => a.payload_signed !== null).map((a) => a.signed),
        );
        for (const s of x.signed) {
          const id = `${x.path}/${s.path}`;
          let want = designedUntrusted[id];
          if (tampered.has(s.path)) want = Reason.SIGNATURE_INVALID;
          seen.add(id);
          if (want !== undefined) {
            assert.equal(
              reasonOf(s.trust),
              want,
              `${id}: trust ${s.trust?.message}, want reason ${want} by design`,
            );
          } else {
            assert.equal(
              s.trust,
              null,
              `${id}: does not verify against the trust records: ${s.trust?.message}`,
            );
          }
        }
      }
    });
  }
  for (const id of Object.keys(designedUntrusted)) {
    assert.ok(seen.has(id), `designedUntrusted lists ${id}, which no case signs`);
  }
});

function jwsFilesUnder(root: string): string[] {
  return readdirSync(root, { withFileTypes: true, recursive: true })
    .filter((d) => d.isFile() && d.name.endsWith('.jws'))
    .map((d) => relative(root, join(d.parentPath, d.name)).split(sep).join('/'))
    .sort();
}

// verify accepts every directory that dirs lists, outcome cases included,
// and returns one result per signed file found under it.
test('TestVerifiesEverySignedDirectory', (t) => {
  if (!fixturesPresent(t)) return;
  const keys = loadKeys(REPO_FIXTURES);
  let total = 0;
  const kinds = new Set<string>();
  const failures: string[] = [];
  for (const d of dirs(REPO_FIXTURES)) {
    let signed: ReturnType<typeof verify>;
    try {
      signed = verify(REPO_FIXTURES, d, keys);
    } catch (err) {
      failures.push(`${d.id}: ${(err as Error).message}`);
      continue;
    }
    kinds.add(d.entry.split('/')[0] ?? '');
    const files = jwsFilesUnder(at(REPO_FIXTURES, d.path));
    const got = signed.map((s) => s.path).sort();
    assert.deepEqual(got, files, `${d.id}: verified files`);
    total += signed.length;
  }
  assert.deepEqual(failures, []);
  assert.ok(
    total > 0 && kinds.has('admission') && kinds.has('outcomes'),
    `${total} signed files in groups ${[...kinds]}`,
  );
});

// admission/valid reads into the values of the README section
// admission/valid and the defaults of format v2 for a case without
// exchange.json.
test('TestValidCase', (t) => {
  if (!fixturesPresent(t)) return;
  const c = load(REPO_FIXTURES, 'admission/valid');
  assert.equal(c.exchanges.length, 1);
  assert.equal(c.subject, 0);
  const x = c.exchanges[0];
  assert.ok(x !== undefined);
  assert.equal(x.name, '');
  assert.equal(x.path, 'admission/valid');
  assert.equal(x.expectedPath, 'expected/admission/valid/decision.json');
  const cfg = x.config;
  assert.equal(cfg.mode, 'enforced');
  assert.equal(cfg.now, 1792080000);
  assert.equal(cfg.clock_skew_seconds, 5);
  assert.equal(cfg.gateway.gateway_id, 'https://gateway.example/finance');
  assert.equal(cfg.gateway.tenant_id, 'acme');
  assert.equal(cfg.trust.length, 3);
  assert.equal(cfg.trust[2]?.role, Role.REPUTATION_SERVICE);
  assert.deepEqual(cfg.trust[2]?.keys, ['keys/reputation-service.jwk.json']);
  assert.equal(cfg.validator.key, 'keys/validator.jwk.json');
  assert.equal(cfg.limits.evaluation_seconds, 30);
  assert.equal(cfg.selection, null);
  const nc = x.nativeContext;
  assert.equal(nc.authenticated?.holder_jkt, 'xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M');
  assert.equal(nc.authorize, true);
  assert.equal(nc.approval?.state, 'approved');
  assert.equal(nc.delegation?.state, 'active');
  assert.deepEqual(x.submissions, [
    {
      signed: 'signed/presentation.jws',
      jti: 'v6wxT-_cB0Ua8Xkqgcuu2g',
      replica: 'r1',
      concurrent: false,
      evictReplayRecords: false,
      actualOperation: 'actual_operation.json',
      transport: 'https',
      evaluation: { startedAt: 1792080000, nativeReadsAt: null, cancelledAt: null },
    },
  ]);
  assert.equal(x.availability.replayStore, 'available');
  assert.deepEqual(x.availability.sources, []);
  assert.deepEqual(x.handoff, []);
  const want = [
    ['signed/contract.jws', TYP_REQUIREMENTS, 'zIMh1jdcSU0EP90CYPIbwA'],
    ['signed/evidence/runtime.jws', TYP_EVIDENCE, '7oJQ-3bglLNLRx8Tpz275Q'],
    ['signed/reputation.jws', TYP_REPUTATION, 'VW7HSF227CWWBU7wN09Q5A'],
    ['signed/presentation.jws', TYP_PRESENTATION, 'v6wxT-_cB0Ua8Xkqgcuu2g'],
  ] as const;
  assert.equal(x.signed.length, want.length);
  for (const [i, [path, typ, jti]] of want.entries()) {
    const got = x.signed[i];
    assert.ok(got !== undefined);
    assert.deepEqual(
      [got.path, got.typ, payloadOf(got.payload).jti, got.trust],
      [path, typ, jti, null],
      `signed[${i}]`,
    );
    const raw = text.decode(readFile(at(REPO_FIXTURES, `admission/valid/${path}`)));
    assert.equal(got.compact, raw, `${path}: compact is not the committed file`);
  }
  assert.deepEqual(
    x.signed[0]?.payload,
    x.decoded.get('contract.json'),
    'the contract payload is not contract.json',
  );
  for (const f of [
    'profile.json',
    'intent.json',
    'operation.json',
    'actual_operation.json',
    'contract.json',
    'evidence/runtime.json',
    'reputation.json',
  ]) {
    assert.ok((x.decoded.get(f)?.length ?? 0) > 0, `decoded ${f} not read`);
  }
  for (const f of ['config.json', 'native_context.json', 'signing.json']) {
    assert.ok(!x.decoded.has(f), `control file ${f} listed as a decoded object`);
  }
  const rs = Decision.expectedResponses(x.expected);
  assert.equal(rs.length, 1);
  assert.equal(rs[0]?.decision, 'ADMISSIBLE');
  assert.equal(rs[0]?.checks.length, 20);
  assert.equal(rs[0]?.transport_code, null);
  assert.equal(rs[0]?.receipt?.typ, 'pact-admission+jwt');
  assert.equal(rs[0]?.receipt?.signer, 'keys/validator.jwk.json');
});

// exchange.json members fill the submissions and handoff attempts with the
// defaults of README section exchange.json.
test('TestExchangeDefaults', (t) => {
  if (!fixturesPresent(t)) return;
  let x = load(REPO_FIXTURES, 'admission/attestation-reuse').exchanges[0];
  assert.ok(x !== undefined);
  assert.equal(x.submissions.length, 1);
  assert.equal(x.handoff.length, 3);
  assert.equal(x.expected.handoff.length, 3);
  const first = x.submissions[0];
  assert.ok(first !== undefined);
  for (const [i, h] of x.handoff.entries()) {
    const op = i === 0 ? 'other_operation.json' : 'actual_operation.json';
    assert.deepEqual(
      h,
      { presentation: first.jti, actualOperation: op, at: first.evaluation.startedAt },
      `handoff[${i}]`,
    );
  }
  assert.ok(
    (x.decoded.get('other_operation.json')?.length ?? 0) > 0,
    'other_operation.json not read',
  );

  let ss = load(REPO_FIXTURES, 'admission/replay-same-nonce-two-replicas').exchanges[0]
    ?.submissions;
  assert.deepEqual(
    ss?.map((s) => [s.replica, s.concurrent]),
    [
      ['r1', true],
      ['r2', true],
    ],
  );

  ss = load(REPO_FIXTURES, 'admission/old-presentation-after-eviction').exchanges[0]?.submissions;
  assert.deepEqual(
    ss?.map((s) => [s.replica, s.evictReplayRecords, s.evaluation.startedAt]),
    [
      ['r1', false, 1792080000],
      ['r1', true, 1792080070],
    ],
  );

  x = load(REPO_FIXTURES, 'admission/replay-store-unavailable').exchanges[0];
  assert.equal(x?.availability.replayStore, 'unavailable');
  assert.deepEqual(
    x?.submissions.map((s) => s.signed),
    ['signed/presentation.jws'],
  );
});

// A sequence.json case loads each exchange directory in order, with the
// expected file under expected/<id>/<exchange>/, and the subject is the
// exchange sequence.json names.
test('TestMultiExchangeCase', (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'approval/approved-fresh-exchange';
  const c = load(REPO_FIXTURES, id);
  assert.equal(c.exchanges.length, 2);
  assert.equal(c.subject, 1);
  for (const [i, x] of c.exchanges.entries()) {
    const name = `exchanges/${i + 1}`;
    assert.equal(x.name, name);
    assert.equal(x.path, `${id}/${name}`);
    assert.equal(x.expectedPath, `expected/${id}/${name}/decision.json`);
    assert.ok(x.signed.length > 0, `exchange ${i}: no signed file`);
  }
});

// A signed file that is not what the generator would keep
// (spec/v1.0/fixtures/README.md, Signed artifacts) fails load and verify, naming
// the file.
test('TestStaleSignatureFails', async (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'admission/valid';
  const cases: [string, string, (root: string) => void][] = [
    [
      'decoded edited',
      'signed/evidence/runtime.jws',
      (root) =>
        edit(root, `${id}/evidence/runtime.json`, 'finance-agent-0001', 'finance-agent-0009'),
    ],
    [
      'signature octet',
      'signed/contract.jws',
      (root) => flipSignature(root, `${id}/signed/contract.jws`),
    ],
    [
      'presentation input edited',
      'signed/presentation.jws',
      (root) => edit(root, `${id}/intent.json`, 'invoice-summary', 'invoice-summarx'),
    ],
    [
      'signer changed',
      'signed/reputation.jws',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[2].signer = 'issuer';
        }),
    ],
  ];
  for (const [name, file, mutate] of cases) {
    await t.test(name, (t: TestContext) => {
      const root = caseTree(t, id);
      load(root, id);
      mutate(root);
      wantThrows(() => load(root, id), id, file, 'stale');
      const keys = loadKeys(root);
      const d = dirs(root).find((d) => d.id === id);
      assert.ok(d !== undefined, `dirs lists no ${id}`);
      wantThrows(() => verify(root, d, keys), file, 'stale');
    });
  }
});

// A decoded file whose digests member is not the artifact_digest of the
// signed file it names fails verify, as generate -check counts it as
// changed.
test('TestStaleDigestsFail', (t) => {
  if (!fixturesPresent(t)) return;
  const root = caseTree(t, 'admission/valid');
  editJSON(root, 'admission/valid/signing.json', (s) => {
    s.artifacts[1].digests = { '/subject': 'signed/contract.jws' };
  });
  const keys = loadKeys(root);
  const d = dirs(root).find((d) => d.id === 'admission/valid');
  assert.ok(d !== undefined);
  wantThrows(() => verify(root, d, keys), 'evidence/runtime.json', 'digests');
});

// A signed file that verifies under its signing key but not against the
// trust records loads, with the reason in trust.
test('TestTrustRecords', async (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'admission/valid';
  const cases: [string, string, Reason, (c: JSONObject, n: JSONObject) => void][] = [
    [
      'no record for the issuer',
      'signed/reputation.jws',
      Reason.KID_UNKNOWN,
      (c) => {
        c.trust = c.trust.slice(0, 2);
      },
    ],
    [
      'record for another issuer',
      'signed/reputation.jws',
      Reason.KID_UNKNOWN,
      (c) => {
        c.trust[2].iss = 'https://reputation.example/other';
      },
    ],
    [
      'record for another role',
      'signed/evidence/runtime.jws',
      Reason.KID_UNKNOWN,
      (c) => {
        c.trust[1].role = 'reputation-service';
      },
    ],
    [
      'record with another key',
      'signed/contract.jws',
      Reason.KID_UNKNOWN,
      (c) => {
        c.trust[0].keys = ['keys/reputation-service.jwk.json'];
      },
    ],
    [
      'other enrolled holder',
      'signed/presentation.jws',
      Reason.HOLDER_JKT_MISMATCH,
      (_, n) => {
        n.authenticated.holder_jkt = 'B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU';
      },
    ],
  ];
  for (const [name, file, want, mutate] of cases) {
    await t.test(name, (t: TestContext) => {
      const root = caseTree(t, id);
      let cfg: JSONObject = {};
      let nc: JSONObject = {};
      editJSON(root, `${id}/config.json`, (c) => {
        cfg = c;
      });
      editJSON(root, `${id}/native_context.json`, (n) => {
        nc = n;
      });
      mutate(cfg, nc);
      writeFile(at(root, `${id}/config.json`), JSON.stringify(cfg));
      editJSON(root, `${id}/config.json`, () => {});
      writeFile(at(root, `${id}/native_context.json`), JSON.stringify(nc));
      editJSON(root, `${id}/native_context.json`, () => {});
      const c = load(root, id);
      for (const s of c.exchanges[0]?.signed ?? []) {
        if (s.path === file)
          assert.equal(reasonOf(s.trust), want, `${s.path}: trust ${s.trust?.message}`);
        else assert.equal(s.trust, null, `${s.path}: trust ${s.trust?.message}`);
      }
    });
  }
});

// load fails on a case it cannot read as the format defines it.
test('TestLoadRejects', async (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'admission/valid';
  const cases: [string, (root: string) => void, string[]][] = [
    [
      'unknown config member',
      (root) =>
        editJSON(root, `${id}/config.json`, (c) => {
          c.nowx = 1;
        }),
      ['config.json'],
    ],
    [
      'no native context',
      (root) => removeFile(at(root, `${id}/native_context.json`)),
      ['native_context.json'],
    ],
    [
      'expected responses for a missing submission',
      (root) =>
        writeFile(
          at(root, `${id}/exchange.json`),
          '{"presentations":[{"signed":"signed/presentation.jws","jti":"v6wxT-_cB0Ua8Xkqgcuu2g"},{"signed":"signed/presentation.jws","jti":"v6wxT-_cB0Ua8Xkqgcuu2g"}]}',
        ),
      ['decision.json', '2 submissions'],
    ],
    [
      'unknown exchange member',
      (root) => writeFile(at(root, `${id}/exchange.json`), '{"presentation":[]}'),
      ['exchange.json'],
    ],
    [
      'unknown expected member',
      (root) =>
        editJSON(root, `expected/${id}/decision.json`, (d) => {
          d.decison = 'ADMISSIBLE';
        }),
      ['decision.json'],
    ],
  ];
  for (const [name, mutate, want] of cases) {
    await t.test(name, (t: TestContext) => {
      const root = caseTree(t, id);
      mutate(root);
      wantThrows(() => load(root, id), ...want);
    });
  }
  wantThrows(
    () => load(REPO_FIXTURES, 'outcomes/qualification/correction-recompute'),
    'outcomes/qualification/correction-recompute',
    'kind outcomes',
  );
  wantThrows(
    () => load(REPO_FIXTURES, 'admission/no-such-case'),
    'admission/no-such-case',
    'no manifest entry',
  );
});

function withoutSigned(c: Case): Case {
  return { ...c, exchanges: c.exchanges.map((x) => ({ ...x, signed: [] })) };
}

// read returns the case that load does, with no signed file verified: it
// needs no test keys, and a stale signed file is no error. The structure of
// the case is still checked.
test('TestRead', async (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'admission/valid';
  for (const e of evaluateEntries()) {
    const want = load(REPO_FIXTURES, e.id);
    const got = read(REPO_FIXTURES, e.id);
    for (const x of got.exchanges) {
      assert.equal(
        x.signed.length,
        0,
        `${e.id} ${x.path}: read verified ${x.signed.length} signed files`,
      );
    }
    assert.deepStrictEqual(
      got,
      withoutSigned(want),
      `${e.id}: read and load differ beyond the signed files`,
    );
  }

  await t.test('no keys', (t: TestContext) => {
    const root = caseTree(t, id);
    removeFile(at(root, 'keys/test-private-scalars.json'));
    read(root, id);
    assert.throws(() => load(root, id), 'load without the private test values succeeded');
  });
  await t.test('stale signed file', (t: TestContext) => {
    const root = caseTree(t, id);
    flipSignature(root, `${id}/signed/contract.jws`);
    read(root, id);
    assert.throws(() => load(root, id), 'load of a stale signed file succeeded');
  });
  await t.test('structure', (t: TestContext) => {
    const root = caseTree(t, id);
    removeFile(at(root, `expected/${id}/decision.json`));
    wantThrows(() => read(root, id), id, 'decision.json');
    wantThrows(() => read(root, 'admission/nope'), 'admission/nope', 'no manifest entry');
    wantThrows(() => read(root, 'keys/holder'), 'keys/holder');
  });
});
