// Port of go/adapter/errors_test.go. A Go sentinel error is an AdapterError
// with its code; errors.Is and errors.As become codeOf and instanceof over
// the cause chain.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AdapterError, Code, codeOf, DenialReason, NativeDenial } from '../src/adapter/index.ts';
import { headingSection } from './support/draft.ts';
import { DRAFT, specText } from './support/repo.ts';

// Each Go sentinel and the draft 13.4 code the contract assigns it. The
// literals are copied from the 13.4 table, not from the code.
const SENTINELS: readonly { name: string; err: () => AdapterError; code: string }[] = [
  { name: 'ErrInvalidMessage', err: () => AdapterError.invalidMessage(), code: 'INVALID_MESSAGE' },
  { name: 'ErrInvalidProof', err: () => AdapterError.invalidProof(), code: 'INVALID_PROOF' },
  {
    name: 'ErrContextMismatch',
    err: () => AdapterError.contextMismatch(),
    code: 'CONTEXT_MISMATCH',
  },
  {
    name: 'ErrDependencyUnavailable',
    err: () => AdapterError.dependencyUnavailable(),
    code: 'DEPENDENCY_UNAVAILABLE',
  },
  {
    name: 'ErrUnsupportedRequirement',
    err: () => AdapterError.unsupportedRequirement(),
    code: 'UNSUPPORTED_REQUIREMENT',
  },
  {
    name: 'ErrUnsupportedPurpose',
    err: () => AdapterError.unsupportedPurpose(),
    code: 'UNSUPPORTED_PURPOSE',
  },
  { name: 'ErrMissingField', err: () => AdapterError.missingField(), code: 'MISSING_FIELD' },
];

function wrap(err: unknown): Error {
  return new Error('read claim', { cause: new Error('lookup', { cause: err }) });
}

// The first error of class C in the cause chain of err, err included.
function find<C>(err: unknown, cls: abstract new (...a: never[]) => C): C | undefined {
  for (let e = err; e instanceof Error; e = e.cause) if (e instanceof cls) return e;
  return undefined;
}

test('TestSentinelsMapToDraftCodes', async (t) => {
  for (const s of SENTINELS) {
    await t.test(s.name, () => {
      const err = s.err();
      assert.ok(err instanceof AdapterError);
      assert.equal(err.code, s.code);
      assert.equal(codeOf(err), s.code, 'codeOf');
      assert.equal(codeOf(wrap(err)), s.code, 'codeOf(wrapped)');
      assert.equal(find(wrap(err), AdapterError), err, 'the wrapped error is in the chain');
      assert.notEqual(err.message, '', 'empty text');
      assert.ok(err.message.startsWith('adapter: '), err.message);
      const withDetail = new AdapterError(err.code, 'source ldap-1', { cause: new Error('down') });
      assert.ok(withDetail.message.endsWith(': source ldap-1'), withDetail.message);
      assert.equal((withDetail.cause as Error).message, 'down');
    });
  }
});

test('TestSentinelsAreDistinct', () => {
  SENTINELS.forEach((a, i) => {
    SENTINELS.forEach((b, j) => {
      assert.equal(codeOf(a.err()) === codeOf(b.err()), i === j, `${a.name} against ${b.name}`);
    });
  });
  assert.deepEqual(
    Object.values(Code),
    SENTINELS.map((s) => s.code),
  );
});

test('TestCodeOfIgnoresForeignErrors', () => {
  const cycle = new Error('a');
  cycle.cause = new Error('b', { cause: cycle });
  for (const err of [
    null,
    undefined,
    new Error('INVALID_PROOF'),
    wrap(new Error('x')),
    { code: 'INVALID_PROOF' },
    Object.assign(new Error('x'), { code: 'INVALID_PROOF' }),
    'INVALID_PROOF',
    cycle,
  ]) {
    assert.equal(codeOf(err), '', String(err));
  }
});

// Every code is a code of the 13.4 table.
test('TestCodesAreInDraftTable', (t) => {
  const draft = specText(t, DRAFT);
  if (draft === undefined) return;
  const sec = headingSection(draft, '### 13.4 Errors');
  const table = new Set<string>();
  for (const m of sec.matchAll(/^\| (`[A-Z_]+`(?: \/ `[A-Z_]+`)*) \|/gm)) {
    for (const c of (m[1] ?? '').matchAll(/`([A-Z_]+)`/g)) table.add(c[1] ?? '');
  }
  assert.ok(table.size >= 15, `parsed ${table.size} codes from 13.4, want at least 15`);
  for (const c of Object.values(Code)) {
    assert.ok(table.has(c), `${c} is not in the draft 13.4 table`);
  }
});

test('TestNativeDenialIsAnInvalidProof', () => {
  const d = new NativeDenial(DenialReason.CREDENTIAL_REJECTED);
  assert.ok(d instanceof AdapterError, 'a denial is an AdapterError');
  assert.equal(d.code, Code.INVALID_PROOF);
  assert.notEqual(codeOf(d), Code.CONTEXT_MISMATCH);
  assert.equal(codeOf(new Error('authn', { cause: d })), Code.INVALID_PROOF);
  assert.equal(find(new Error('authn', { cause: d }), NativeDenial)?.reason, 'CREDENTIAL_REJECTED');
});

// The Go test pins that only *NativeDenial is an error, so errors.As has one
// target; here a denial is one class, an Error, and carries no cause.
test('TestNativeDenialIsPointerOnly', () => {
  const d = new NativeDenial(DenialReason.NO_CREDENTIAL);
  assert.ok(d instanceof Error);
  assert.ok(d instanceof NativeDenial);
  assert.equal(d.cause, undefined);
  assert.equal(d.detail, '');
});

// The text of a denial depends only on the public reason set. Free text that
// an adapter puts in the reason, such as the name of an account, never
// reaches the message or the public reason.
test('TestNativeDenialDoesNotDisclose', () => {
  const leaks = [
    'user alice@corp.example not found',
    'password mismatch for svc-billing',
    'issuer https://idp.internal.example rejected the token',
    '',
  ];
  const base = new NativeDenial(DenialReason.CREDENTIAL_REJECTED).message;
  for (const r of leaks) {
    const d = new NativeDenial(r);
    assert.equal(d.message, base, `message for ${JSON.stringify(r)}`);
    assert.equal(d.publicReason(), DenialReason.CREDENTIAL_REJECTED);
    if (r !== '') assert.ok(!d.message.includes(r));
    assert.ok(!String(d).includes(r) || r === '', String(d));
  }
  for (const r of [DenialReason.NO_CREDENTIAL, DenialReason.CREDENTIAL_REJECTED]) {
    const d = new NativeDenial(r);
    assert.equal(d.publicReason(), r);
    assert.ok(d.message.includes(r), d.message);
  }
  assert.notEqual(new NativeDenial(DenialReason.NO_CREDENTIAL).message, base);
});

// The Go test calls the methods on a nil *NativeDenial; the nearest value
// here is a denial built without a reason.
test('TestNilNativeDenialDoesNotPanic', () => {
  const d = new NativeDenial();
  assert.notEqual(d.message, '');
  assert.equal(d.publicReason(), DenialReason.CREDENTIAL_REJECTED);
});
