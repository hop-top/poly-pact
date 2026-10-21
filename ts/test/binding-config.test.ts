// Port of go/core/binding/config_test.go. Go Config.Validate is
// Config.validate(cfg). A configuration error is a RequestError of kind
// INVALID_CONFIG, never INVALID_REQUEST. The body limit is a safe integer
// here, and an identifier that is not UTF-8 is a string that is not
// well-formed.

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { Config, type RequestError } from '../src/core/binding/index.ts';
import { config, from, get, type MutableConfig, mustBind, wantKind } from './support/binding.ts';

function validateError(cfg: Config): unknown {
  try {
    Config.validate(cfg);
  } catch (e) {
    return e;
  }
  return undefined;
}

// The Appendix B configuration and its variants pass.
describe('TestConfigValid', () => {
  const many = Array.from({ length: 63 }, (_, i) => `x-h${i}`);
  const tests: [name: string, edit: (c: MutableConfig) => void][] = [
    ['appendix B', () => {}],
    [
      'no allowlist',
      (c) => {
        c.headerAllowlist = [];
      },
    ],
    [
      'token characters',
      (c) => {
        c.headerAllowlist = ["x-a!#$%&'*+.^_`|~1"];
      },
    ],
    [
      '63 names plus content-type',
      (c) => {
        c.headerAllowlist = many;
      },
    ],
    [
      '64 names with content-type',
      (c) => {
        c.headerAllowlist = [...many, 'content-type'];
      },
    ],
    [
      'zero MaxBody',
      (c) => {
        c.maxBody = 0;
      },
    ],
    [
      '1024 character identifiers',
      (c) => {
        c.mappingVersion = 'm'.repeat(1024);
        c.headerNormalizationId = 'n'.repeat(1024);
      },
    ],
    [
      '1024 characters outside the BMP',
      (c) => {
        c.mappingVersion = '\u{1F600}'.repeat(1024);
      },
    ],
  ];
  for (const [name, edit] of tests) {
    test(name, () => {
      const cfg = config();
      edit(cfg);
      Config.validate(cfg);
      mustBind(cfg, get('/x'));
    });
  }
});

// Each configuration rule has a failing input. fromRequest refuses an
// invalid configuration with INVALID_CONFIG, not a request error.
describe('TestRejectConfig', () => {
  const many = Array.from({ length: 64 }, (_, i) => `x-h${i}`);
  const origins: [name: string, origin: string][] = [
    ['empty', ''],
    ['http scheme', 'http://gateway.example'],
    ['no scheme', 'gateway.example'],
    ['trailing slash', 'https://gateway.example/'],
    ['path', 'https://gateway.example/base'],
    ['query', 'https://gateway.example?x'],
    ['fragment', 'https://gateway.example#f'],
    ['userinfo', 'https://u@gateway.example'],
    ['non-ASCII host', 'https://bücher.example'],
    ['percent-encoded host', 'https://b%C3%BCcher.example'],
    ['empty host', 'https://'],
    ['empty host with port', 'https://:443'],
    ['space in host', 'https://gate way.example'],
    ['port not a number', 'https://gateway.example:abc'],
    ['port with leading zero', 'https://gateway.example:0443'],
    ['port zero', 'https://gateway.example:0'],
    ['port too large', 'https://gateway.example:65536'],
    ['port with sign', 'https://gateway.example:+443'],
    ['IPv6 zone', 'https://[fe80::1%25en0]'],
    ['IPvFuture', 'https://[v1.x]'],
    ['IPv4 in brackets', 'https://[192.0.2.1]'],
    ['unclosed bracket', 'https://[::1'],
    ['text after bracket', 'https://[::1]x'],
  ];
  const headers: [name: string, allow: string[]][] = [
    ['authorization', ['authorization']],
    ['authorization any case', ['Authorization']],
    ['cookie', ['cookie']],
    ['set-cookie', ['set-cookie']],
    ['pact-presentation', ['pact-presentation']],
    ['pact-admission any case', ['PACT-Admission']],
    ['any pact- name', ['pact-anything']],
    ['connection', ['connection']],
    ['keep-alive', ['keep-alive']],
    ['te', ['te']],
    ['transfer-encoding', ['transfer-encoding']],
    ['upgrade', ['upgrade']],
    ['proxy-authorization', ['proxy-authorization']],
    ['proxy-connection', ['proxy-connection']],
    ['any proxy- name', ['proxy-anything']],
    ['signature', ['signature']],
    ['signature-input', ['signature-input']],
    ['host', ['host']],
    ['host any case', ['Host']],
    ['empty name', ['']],
    ['space in name', ['x dry']],
    ['colon in name', ['x:y']],
    ['non-ASCII name', ['x-café']],
    ['duplicate', ['x-a', 'X-A']],
    ['65 names with content-type', many],
  ];
  const tests: [name: string, edit: (c: MutableConfig) => void][] = [
    [
      'empty mapping version',
      (c) => {
        c.mappingVersion = '';
      },
    ],
    [
      'long mapping version',
      (c) => {
        c.mappingVersion = 'm'.repeat(1025);
      },
    ],
    [
      'mapping version not UTF-8',
      (c) => {
        c.mappingVersion = 'm\ud800';
      },
    ],
    [
      'empty header normalization id',
      (c) => {
        c.headerNormalizationId = '';
      },
    ],
    [
      'long header normalization id',
      (c) => {
        c.headerNormalizationId = 'n'.repeat(1025);
      },
    ],
    [
      'negative MaxBody',
      (c) => {
        c.maxBody = -1;
      },
    ],
    [
      'fractional MaxBody',
      (c) => {
        c.maxBody = 1.5;
      },
    ],
    [
      'unsafe MaxBody',
      (c) => {
        c.maxBody = 2 ** 53;
      },
    ],
    [
      'NaN MaxBody',
      (c) => {
        c.maxBody = Number.NaN;
      },
    ],
    ...origins.map(
      ([name, origin]) =>
        [
          `origin/${name}`,
          (c: MutableConfig) => {
            c.origin = origin;
          },
        ] as [string, (c: MutableConfig) => void],
    ),
    ...headers.map(
      ([name, allow]) =>
        [
          `allowlist/${name}`,
          (c: MutableConfig) => {
            c.headerAllowlist = allow;
          },
        ] as [string, (c: MutableConfig) => void],
    ),
  ];
  for (const [name, edit] of tests) {
    test(name, () => {
      const cfg = config();
      edit(cfg);
      wantKind(validateError(cfg), 'INVALID_CONFIG');
      let err: unknown;
      try {
        from(cfg, get('/x'));
      } catch (e) {
        err = e;
      }
      wantKind(err, 'INVALID_CONFIG');
      assert.equal((err as RequestError).rule, '');
    });
  }
});

// A non-ASCII or percent-encoded host in the origin is reported as such (RFC
// 3986 3.2.2), not as a stray character.
test('TestRejectConfigNonASCIIHost', () => {
  for (const o of ['https://bücher.example', 'https://b%C3%BCcher.example']) {
    const cfg = config();
    cfg.origin = o;
    const err = validateError(cfg);
    wantKind(err, 'INVALID_CONFIG');
    assert.match((err as Error).message, /non-ASCII host/, o);
  }
  const cfg = config();
  cfg.origin = 'https://xn--bcher-kva.example';
  Config.validate(cfg);
});
