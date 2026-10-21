// Port of go/core/enums_test.go: every value of each enum passes its guard,
// and strings outside the set do not. The table of enums is the drift
// test's (core-schema-drift.test.ts), so an enum the schema adds and this
// port lacks fails there.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ENUM_NAMES, enumOf } from './support/enums.ts';

test('TestEnumValid', () => {
  for (const name of ENUM_NAMES) {
    const { values, guard } = enumOf(name);
    for (const v of values) assert.equal(guard(v), true, `is${name}(${JSON.stringify(v)})`);
    for (const bad of ['', 'bogus', ' ', 'Enforced', 'enforced ', 'toString', '__proto__']) {
      if (values.includes(bad)) continue;
      assert.equal(guard(bad), false, `is${name}(${JSON.stringify(bad)})`);
    }
    for (const bad of [
      undefined,
      null,
      0,
      1,
      true,
      {},
      [],
      [values[0]],
      { toString: () => values[0] },
    ]) {
      assert.equal(guard(bad), false, `is${name}(${String(bad)})`);
    }
  }
});
