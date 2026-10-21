// Port of go/runner/evalcase/rules_test.go: the key, directory, walk and
// digest rules of the generator contract.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { type TestContext, test } from 'node:test';
import { dirs, type File, load, loadKeys, walk } from '../src/conformance/case.ts';
import { TYP_PRESENTATION, TYP_REQUIREMENTS } from '../src/core/jws/index.ts';
import {
  at,
  caseTree,
  copyTree,
  editJSON,
  payloadOf,
  REPO_FIXTURES,
  readFile,
  removeFile,
  wantThrows,
  writeFile,
} from './support/evalcase.ts';
import { fixturesPresent } from './support/fixtures.ts';

// A public JWK file that is not the public key of its role's private scalar
// stops loadKeys.
test('TestLoadKeysChecksPublicFiles', (t) => {
  if (!fixturesPresent(t)) return;
  const keys = loadKeys(REPO_FIXTURES);
  const k = keys.get('issuer');
  assert.ok(k !== undefined, 'no issuer key');
  assert.equal(k.role, 'issuer');
  assert.equal(k.private.type, 'private');
  assert.equal(k.public.kid, 'test-issuer-key-1');
  assert.ok(!keys.has('ed25519'), 'the Ed25519 pair is listed as an ES256 key');

  let root = copyTree(t, 'keys');
  writeFile(
    at(root, 'keys/issuer.jwk.json'),
    readFile(at(root, 'keys/reputation-service.jwk.json')),
  );
  wantThrows(() => loadKeys(root), 'issuer.jwk.json', 'role issuer');

  // The same kid on another public point is no better.
  root = copyTree(t, 'keys');
  const other = readFileSync(at(root, 'keys/reputation-service.jwk.json'), 'utf8').replace(
    'test-reputation-service-key-1',
    'test-issuer-key-1',
  );
  assert.ok(!other.includes('reputation'), `kid not replaced: ${other}`);
  writeFile(at(root, 'keys/issuer.jwk.json'), other);
  wantThrows(() => loadKeys(root), 'issuer.jwk.json', 'role issuer');
});

// Under payload_signed the signature covers one file and the JWS carries
// another; a JWS whose carried payload is not the decoded file is stale
// although its signature still verifies over the covered file.
test('TestStaleCarriedPayload', (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'selection/agent-requests-weaker-set';
  const root = caseTree(t, id);
  load(root, id);
  editJSON(root, `${id}/contract.json`, (m) => {
    m.zz_extra = 1;
  });
  wantThrows(() => load(root, id), id, 'signed/contract.jws', 'stale');
});

// The directory rules of the generator contract (README section Generator
// contract: signing.json).
test('TestDirsRules', async (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'admission/valid';
  const cases: [string, (root: string) => void, string[]][] = [
    [
      'signed files without signing.json',
      (root) => removeFile(at(root, `${id}/signing.json`)),
      [id, 'holds signed files', 'no signing.json'],
    ],
    [
      'signed file no entry names',
      (root) => writeFile(at(root, `${id}/signed/extra.jws`), 'x'),
      ['signed/extra.jws', 'named by no entry'],
    ],
    [
      'artifacts absent',
      (root) => writeFile(at(root, `${id}/signing.json`), '{"presentations":[]}'),
      ['artifacts is required'],
    ],
    [
      'unknown member',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifact = [];
        }),
      ['signing.json'],
    ],
    [
      'path leaving the case',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[0].decoded = '../contract.json';
        }),
      ['artifacts[0]', 'not a relative path'],
    ],
    [
      'presentation typ for an artifact',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[0].typ = 'pact-presentation+jwt';
        }),
      ['artifacts[0]', 'typ'],
    ],
    [
      'digests naming a later entry',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[0].digests = { '/x': 'signed/reputation.jws' };
        }),
      ['artifacts[0]', 'not the signed file of an earlier entry'],
    ],
    [
      'signed file named twice',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.presentations[0].signed = 'signed/contract.jws';
        }),
      ['presentations[0]', 'named twice'],
    ],
    [
      'presentation without jti',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          delete s.presentations[0].jti;
        }),
      ['presentations[0]', 'required'],
    ],
  ];
  for (const [name, mutate, want] of cases) {
    await t.test(name, (t: TestContext) => {
      const root = caseTree(t, id);
      dirs(root);
      mutate(root);
      wantThrows(() => dirs(root), ...want);
    });
  }

  const multi = 'approval/approved-fresh-exchange';
  for (const [name, seq, want] of [
    ['no exchanges', '{"exchanges":[],"subject":"exchanges/1"}', 'exchanges is empty'],
    ['exchange outside the case', '{"exchanges":["../x"],"subject":"../x"}', 'not a relative path'],
  ] as const) {
    await t.test(name, (t: TestContext) => {
      const root = caseTree(t, multi);
      writeFile(at(root, `${multi}/sequence.json`), seq);
      wantThrows(() => dirs(root), multi, 'sequence.json', want);
    });
  }
});

// The decoded-file and presentation rules of the generator contract,
// applied by walk whatever the signed files hold.
test('TestWalkRules', async (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'admission/valid';
  const cases: [string, (root: string) => void, string[]][] = [
    [
      'decoded not canonical',
      (root) => {
        const p = at(root, `${id}/contract.json`);
        writeFile(p, `${readFileSync(p, 'utf8')}\n`);
      },
      ['contract.json', 'RFC 8785 canonical'],
    ],
    [
      'jti not the fixed one',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[1].jti = 'other';
        }),
      ['evidence/runtime.json', 'jti'],
    ],
    [
      'iat not the fixed one',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[1].iat = 1792080001;
        }),
      ['evidence/runtime.json', 'iat'],
    ],
    [
      'exp not the stated one',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[1].exp = 1;
        }),
      ['evidence/runtime.json', 'exp'],
    ],
    [
      'null decoded artifact',
      (root) => writeFile(at(root, `${id}/reputation.json`), 'null'),
      ['reputation.json is null'],
    ],
    [
      'no test key for the signer',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[0].signer = 'nobody';
        }),
      ['contract.json', 'no test key for role nobody'],
    ],
    [
      'two snapshots and no reputation named',
      (root) =>
        editJSON(root, `${id}/signing.json`, (s) => {
          s.artifacts[1].typ = 'pact-reputation+jwt';
        }),
      ['signed/presentation.jws', '2 snapshot artifacts'],
    ],
  ];
  for (const [name, mutate, want] of cases) {
    await t.test(name, (t: TestContext) => {
      const root = caseTree(t, id);
      mutate(root);
      const keys = loadKeys(root);
      const ds = dirs(root);
      const d = ds[0];
      assert.ok(d !== undefined);
      wantThrows(() => walk(root, d, keys, (f) => f.sign()), ...want);
    });
  }
});

// walk hands over each signed file with its typ, key, payload and signed
// bytes, and a fresh signature passes File.check.
test('TestWalkFiles', (t) => {
  if (!fixturesPresent(t)) return;
  const keys = loadKeys(REPO_FIXTURES);
  const d = dirs(REPO_FIXTURES).find((d) => d.id === 'selection/agent-requests-weaker-set');
  assert.ok(d !== undefined, 'no selection/agent-requests-weaker-set');
  let n = 0;
  walk(REPO_FIXTURES, d, keys, (f: File) => {
    n++;
    const dir = at(REPO_FIXTURES, d.path);
    switch (f.signed) {
      case 'signed/contract.jws':
        // payload_signed: the JWS carries contract.json, the signature
        // covers the file payload_signed names.
        assert.equal(f.typ, TYP_REQUIREMENTS);
        assert.equal(f.key.role, 'issuer');
        assert.equal(f.decoded, 'contract.json');
        assert.deepEqual(f.payload, readFile(at(dir, 'contract.json')));
        assert.notDeepEqual(f.over, f.payload);
        break;
      case 'signed/presentation.jws':
        assert.equal(f.typ, TYP_PRESENTATION);
        assert.equal(f.key.role, 'holder');
        assert.equal(f.decoded, '');
        assert.deepEqual(f.over, f.payload);
        break;
    }
    f.check(f.sign());
    const committed = readFileSync(at(dir, f.signed), 'utf8');
    f.check(committed);
    return committed;
  });
  assert.equal(n, d.signing.artifacts.length + d.signing.presentations.length);
});

// walkPayloads runs walk over the directory id of the tree root and returns
// the payload of each file by signed path.
function walkPayloads(root: string, id: string): Map<string, Uint8Array> {
  const keys = loadKeys(root);
  const d = dirs(root).find((d) => d.id === id);
  assert.ok(d !== undefined, `dirs lists no ${id}`);
  const out = new Map<string, Uint8Array>();
  walk(root, d, keys, (f) => {
    out.set(f.signed, f.payload);
    return f.sign();
  });
  return out;
}

// Without an evidence member, the presentation embeds the compact evidence
// artifacts in signing.json order.
test('TestPresentationEmbedsEvidenceInOrder', (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'admission/valid';
  const root = caseTree(t, id);
  for (const [name, jti] of [
    ['extra-a', 'extra-a-jti'],
    ['extra-b', 'extra-b-jti'],
  ]) {
    writeFile(
      at(root, `${id}/evidence/${name}.json`),
      `{"iat":1792080000,"jti":"${jti}","nbf":1792080000}`,
    );
  }
  editJSON(root, `${id}/signing.json`, (s) => {
    for (const e of ['extra-a', 'extra-b']) {
      s.artifacts.push({
        decoded: `evidence/${e}.json`,
        signed: `signed/evidence/${e}.jws`,
        typ: 'pact-evidence+jwt',
        signer: 'issuer',
        jti: `${e}-jti`,
      });
    }
  });
  const keys = loadKeys(root);
  const d = dirs(root).find((d) => d.id === id);
  assert.ok(d !== undefined);
  const signed = new Map<string, string>();
  let got: unknown;
  walk(root, d, keys, (f) => {
    const c = f.sign();
    signed.set(f.signed, c);
    if (f.typ === TYP_PRESENTATION) got = payloadOf(f.payload).evidence;
    return c;
  });
  assert.deepEqual(got, [
    signed.get('signed/evidence/runtime.jws'),
    signed.get('signed/evidence/extra-a.jws'),
    signed.get('signed/evidence/extra-b.jws'),
  ]);
});

// The digests of an artifact entry set a member of an object or replace an
// element of an array, and name nothing else.
test('TestDigestPointers', async (t) => {
  if (!fixturesPresent(t)) return;
  const id = 'admission/valid';
  for (const [name, ptr, want] of [
    ['new member', '/extra', ''],
    ['array element', '/list/1', ''],
    ['array element out of range', '/list/2', 'no array element'],
    ['array element with a leading zero', '/list/01', 'no array element'],
    ['missing step', '/absent/x', 'no member'],
    ['inside a string', '/name/x', 'not an object or array'],
  ] as const) {
    await t.test(name, (t: TestContext) => {
      const root = caseTree(t, id);
      writeFile(
        at(root, `${id}/evidence/extra.json`),
        '{"iat":1792080000,"jti":"extra-jti","list":[1,2],"name":"n","nbf":1792080000}',
      );
      editJSON(root, `${id}/signing.json`, (s) => {
        s.artifacts.push({
          decoded: 'evidence/extra.json',
          signed: 'signed/evidence/extra.jws',
          typ: 'pact-evidence+jwt',
          signer: 'issuer',
          jti: 'extra-jti',
          digests: { [ptr]: 'signed/contract.jws' },
        });
      });
      if (want !== '') {
        wantThrows(() => walkPayloads(root, id), 'evidence/extra.json', ptr, want);
        return;
      }
      const m = payloadOf(
        walkPayloads(root, id).get('signed/evidence/extra.jws') ?? new Uint8Array(),
      );
      if (ptr === '/extra') assert.equal(typeof m.extra, 'string', 'digest not set');
      else assert.equal(typeof m.list[1], 'string', 'digest not set');
    });
  }
});
