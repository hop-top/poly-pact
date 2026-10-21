# TypeScript SDK primitive probes

Probe record, 2026-10-16. Six questions, one throwaway program each, to choose primitives for the TypeScript core SDK before anything is pinned. Builtins (`node:crypto`, `TextDecoder`, `node:test`) come first; a dependency is chosen only where the builtin fails its probe. Every fact below cites the program and the output pasted under it. Nothing here ships: the programs are throwaway and live in [`ts/`](ts/).

The rules being probed come from [`spec/v1.0/draft.md`](../../../spec/v1.0/draft.md): section 6.2 (`holder_jkt` is the RFC 7638 thumbprint), 7.1 (reject duplicate property names, non-finite numbers and invalid Unicode; integers `0..9007199254740991`), 7.2 (baseline `ES256`, `Ed25519` optional), 7.4 (`object_digest` over RFC 8785) and 22.2 (cross-language tests cover JCS ordering and number serialization, JOSE signature encoding and JWK thumbprints).

## Environment

| Item | Value |
|---|---|
| Node | v26.8.1, the pin in [`mise.toml`](../../../mise.toml); called by absolute path from the mise install, not through the shim |
| npm | 11.19.0 (same install) |
| V8 / OpenSSL | 14.6.202.34-node.28 / 3.5.7 |
| Platform | darwin-arm64 only; no other platform was run |
| Packages | `ajv@8.20.0`, `ajv-formats@3.0.1`, installed outside the repository (Q5 only) |

Output blocks are verbatim except: absolute paths are shortened to `<repo>`, `<parent>` and `$SCRATCH`, process ids are elided, and where a block says "excerpt" only the lines naming the error, the failing statement and the pass and fail totals are kept (stack frames dropped).

## How to run

Run from the repository root, with `node` being v26.8.1. Q1 to Q4 and Q6 need nothing installed. Q5 needs ajv; it is installed in a directory outside the repository and the committed program is run from there by absolute path (it resolves `ajv` from the current directory).

```sh
node docs/sdk/probes/ts/q1-es256-jws.mjs
node docs/sdk/probes/ts/q1b-fixture-jws.mjs
node docs/sdk/probes/ts/q2-jwk-thumbprint.mjs
node docs/sdk/probes/ts/q3-strict-parse.mjs
node docs/sdk/probes/ts/q4-jcs.mjs
node --test docs/sdk/probes/ts/q6-runner.test.ts

REPO=$PWD; SCRATCH=$(mktemp -d); cd "$SCRATCH"
npm init -y >/dev/null && npm install --ignore-scripts --no-audit --no-fund ajv@8.20.0 ajv-formats@3.0.1
node "$REPO/docs/sdk/probes/ts/q5-schema-ajv.mjs"; cd "$REPO"
```

## Q1. ES256 JWS with `node:crypto`

Programs: [`q1-es256-jws.mjs`](ts/q1-es256-jws.mjs), [`q1b-fixture-jws.mjs`](ts/q1b-fixture-jws.mjs). References: [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) section 3.4 (the ES256 signature is R || S, 32 octets each) and [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) Appendix A.3 (the P-256 example).

```text
$ node docs/sdk/probes/ts/q1-es256-jws.mjs
lengths over 2000 signs: p1363 [ 64 ] default [ 69, 70, 71, 72 ] p1363 round trip true
DER sig read as p1363: false | 63-byte: false | 65-byte: false
A.3 signature bytes: 64 | verifies: true
own signature with A.3 d: bytes 64 verifies true | equals RFC bytes false
A.3 signature with one bit flipped verifies: false
```

```text
$ node docs/sdk/probes/ts/q1b-fixture-jws.mjs
header: {"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"} | signature bytes: 64
verifies under issuer: true | under holder: false
signing input with one byte appended, under issuer: false
```

Facts:

1. With `dsaEncoding: 'ieee-p1363'`, `crypto.sign('sha256', data, {key, dsaEncoding})` returned 64 bytes in each of 2000 signatures (`p1363 [ 64 ]`). Without `dsaEncoding` the same call returns DER, 69 to 72 bytes (`default [ 69, 70, 71, 72 ]`). (q1, line 1)
2. The p1363 round trip verifies (`p1363 round trip true`). (q1, line 1)
3. `verify` with `ieee-p1363` returns `false`, and does not throw, for a DER signature, a 63-byte signature and a 65-byte signature. (q1, line 2)
4. The RFC 7515 A.3 vector verifies: the 64-byte signature decoded from base64url, the public key imported from the RFC's `x`/`y` with `createPublicKey({key, format: 'jwk'})`, and the signing input `BASE64URL(header).BASE64URL(payload)` give `verifies: true`. Flipping one bit of the signature gives `false`. (q1, lines 3 and 5)
5. A key imported with `createPrivateKey` from the RFC's JWK (including `d`) signs the A.3 input to 64 bytes that verify under the A.3 public key, and are not byte-equal to the RFC signature. The A.3 check is therefore a verification, not a regeneration. (q1, line 4)
6. The Appendix C JWS in [`spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws`](../../../spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws) has a 64-byte signature and verifies under [`issuer.jwk.json`](../../../spec/v1.0/fixtures/keys/issuer.jwk.json); it does not verify under `holder.jwk.json` or with one byte appended to the signing input. (q1b)

Expectation in the task (64-byte r || s, round trip, A.3 verifies): met. A builtin is enough.

## Q2. JWK import/export and RFC 7638 thumbprint

Program: [`q2-jwk-thumbprint.mjs`](ts/q2-jwk-thumbprint.mjs). References: [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) sections 3.1 and 3.2, [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) section 2 and Appendix A.3, [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) section 6.2.1.2.

```text
$ node docs/sdk/probes/ts/q2-jwk-thumbprint.mjs
RFC 7638 3.1 RSA kty,n,e,alg,kid | exported kty,n,e | NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs | known: true
adversarial.jwk.json           kty,crv,x,y,kid,alg,use | exported kty,x,y,crv | B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU | known: n/a | same from export: true
ed25519.jwk.json               kty,crv,x,kid,alg,use | exported crv,x,kty | kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k | known: true | same from export: true
holder.jwk.json                kty,crv,x,y,kid,alg,use | exported kty,x,y,crv | xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M | known: true | same from export: true
issuer.jwk.json                kty,crv,x,y,kid,alg,use | exported kty,x,y,crv | AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE | known: n/a | same from export: true
learning-controller.jwk.json   kty,crv,x,y,kid,alg,use | exported kty,x,y,crv | yiaHWTOH-NAS43bw6yPHO8YTK_T9cLz9jZaCu3qOg_k | known: n/a | same from export: true
reputation-service.jwk.json    kty,crv,x,y,kid,alg,use | exported kty,x,y,crv | BcYkeRReg8Py6HmUFJw6240ruOKnvInXb5rRtK6Z9xQ | known: n/a | same from export: true
validator.jwk.json             kty,crv,x,y,kid,alg,use | exported kty,x,y,crv | uhdbksqePVMcTx2Fvr5RY78RjuSE2bd16nNAkdfZ36I | known: n/a | same from export: true
4000 generated keys: coordinates with leading 0x00: 23 | coordinates not 32 bytes: 0
```

Facts:

1. The RFC 7638 section 3.1 example is an RSA key, not an EC key. Its required members are `e`, `kty`, `n`. The thumbprint computed here from those members, in that order, is `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`, equal to the RFC value (`known: true`). (q2, line 1)
2. `holder.jwk.json` gives `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M` (`known: true`), the `holder_jkt` of Appendix C. (q2, holder row)
3. `ed25519.jwk.json` gives `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` (`known: true`), the value printed in RFC 8037 Appendix A.3 for the same key. (q2, ed25519 row)
4. `createPublicKey({key: jwk, format: 'jwk'})` accepts the fixture JWKs with their extra `kid`, `alg`, `use` members. `export({format: 'jwk'})` returns only the key members: EC `kty,x,y,crv`; OKP `crv,x,kty`; RSA `kty,n,e`. `kid`, `alg` and `use` are not carried by the `KeyObject`. (q2, "exported" column)
5. For all seven fixture keys the thumbprint computed from the file equals the thumbprint computed from the exported JWK (`same from export: true`). (q2)
6. Over 4000 generated P-256 keys, some coordinates began with a `0x00` byte (the count is random and varied from run to run, 19 to 40) and none of the 8000 coordinates exported shorter than 32 bytes (`not 32 bytes: 0`). Export pads, as RFC 7518 section 6.2.1.2 requires. (q2, last line)
7. `node:crypto` exposes no thumbprint function: no export of `crypto` has a name matching `thumb|jwk|jws`, and no `KeyObject.prototype` method matches `thumb|jwk|fingerprint` (inline probe below). The thumbprint is `createHash('sha256')` over `JSON.stringify` of the required members in lexicographic order, then `digest('base64url')`.
8. Self-check: in a copy of the program with the EC member list reordered to `kty,crv,x,y`, the holder row changes to `d-xv9KenJkELSjvoc5fR3q9B_fgPPqjTn92vi0UQfKI` with `known: false`, so the `known` comparison is not vacuous.

```text
$ node -p "const c=require('node:crypto'); [Object.keys(c).filter(k=>/thumb|jwk|jws/i.test(k)), Object.getOwnPropertyNames(c.KeyObject.prototype).filter(k=>/thumb|jwk|fingerprint/i.test(k))]"
[ [], [] ]
```

Difference from the task text: the task describes the RFC 7638 example as covered by the `{crv,kty,x,y}` EC member set. The RFC 7638 section 3.1 example is RSA, so the required-member table needs an RSA row for that vector to be reproduced; the SDK itself needs only the EC and OKP rows.

## Q3. Strict parsing: `JSON.parse` and `TextDecoder`

Program: [`q3-strict-parse.mjs`](ts/q3-strict-parse.mjs). Rule under test: [`spec/v1.0/draft.md`](../../../spec/v1.0/draft.md) section 7.1.

```text
$ node docs/sdk/probes/ts/q3-strict-parse.mjs
duplicate keys             {"a":2}
duplicate keys + reviver   [ 'a=2', '=[object Object]' ]
1e999                      Infinity
lone surrogate escape      { length: 1, wellFormed: false }
lone surrogate in key      [ false ]
BOM char in JSON.parse     THROWS SyntaxError: Unexpected token '<U+FEFF>', "<U+FEFF>{}" is not valid JSON
2^53+1 and 2^64            [ 9007199254740992, 18446744073709552000 ]
reviver context.source     [
  [ '9007199254740992', '9007199254740993' ],
  [ 'Infinity', '1e999' ],
  [ '1', '1.0' ]
]
fatal: ff byte             THROWS TypeError: The encoded data was not valid for encoding utf-8
fatal: overlong c0 80      THROWS TypeError: The encoded data was not valid for encoding utf-8
fatal: surrogate ed a0 80  THROWS TypeError: The encoded data was not valid for encoding utf-8
fatal: truncated e2 82     THROWS TypeError: The encoded data was not valid for encoding utf-8
fatal: above 10ffff f4 90 80 80 THROWS TypeError: The encoded data was not valid for encoding utf-8
fatal: noncharacter ef bf be code points: fffe
non-fatal: ff byte         code points: 7b fffd 7d
fatal: BOM ef bb bf 7b 7d  code points: 7b 7d
fatal+ignoreBOM: same      code points: feff 7b 7d
fatal: valid 4-byte f0 9f 98 80 code points: 1f600
```

Facts:

1. Duplicate keys: `JSON.parse('{"a":1,"a":2}')` returns `{"a":2}`; the last value wins and nothing is reported. A reviver is called once for `a`, with `2`, so duplicates cannot be detected through the reviver either. A scanner over the source text is needed to reject them. (q3, rows `duplicate keys` and `duplicate keys + reviver`)
2. `JSON.parse('1e999')` returns `Infinity`. (q3, row `1e999`)
3. A lone surrogate written as an escape (`"\ud800"`) is accepted; the string has length 1 and `isWellFormed()` is `false`. The same holds for an object key (`"\udc00"`). (q3, rows `lone surrogate escape` and `lone surrogate in key`)
4. A U+FEFF character at the start of the text is rejected by `JSON.parse` (`SyntaxError: Unexpected token '<U+FEFF>'`). (q3, row `BOM char in JSON.parse`)
5. `JSON.parse('[9007199254740993,18446744073709551616]')` returns `[9007199254740992, 18446744073709552000]`: integers above 2^53 are rounded silently. (q3, row `2^53+1 and 2^64`)
6. The reviver's third argument (`context.source`) is available on this Node. It gives the source text of each primitive: `9007199254740993` (value `9007199254740992`), `1e999` (value `Infinity`), `1.0` (value `1`). Numbers above 2^53, non-finite numbers and non-canonical integer spellings can therefore be seen after a plain `JSON.parse`; duplicates cannot (fact 1). (q3, row `reviver context.source`)
7. `new TextDecoder('utf-8', {fatal: true})` throws `TypeError: The encoded data was not valid for encoding utf-8` for a stray `0xff`, the overlong `c0 80`, the encoded surrogate `ed a0 80`, the truncated `e2 82`, and `f4 90 80 80` (above U+10FFFF). It decodes the valid 4-byte `f0 9f 98 80` to U+1F600. (q3, `fatal:` rows)
8. `fatal: true` accepts the noncharacter `ef bf be` (U+FFFE). (q3, row `fatal: noncharacter`)
9. Without `fatal`, a stray `0xff` becomes U+FFFD (`7b fffd 7d`) and decoding continues. (q3, row `non-fatal: ff byte`)
10. A leading BOM (`ef bb bf`) is silently dropped by default, even with `fatal: true` (`7b 7d`). With `ignoreBOM: true` it is kept as U+FEFF (`feff 7b 7d`), which `JSON.parse` then rejects (fact 4). A decoder with default options therefore hides a BOM from the JSON layer. (q3, rows `fatal: BOM` and `fatal+ignoreBOM`)

Expectation in the task (last wins; `1e999` is `Infinity`; fatal decoding rejects invalid bytes): met. Additions: a BOM is dropped by `TextDecoder` unless `ignoreBOM: true`; escaped lone surrogates pass both `TextDecoder` and `JSON.parse`, so well-formedness of every decoded string and key needs its own check (`isWellFormed`); `context.source` covers numbers but not duplicates.

## Q4. JCS (RFC 8785) from `JSON.stringify`

Program: [`q4-jcs.mjs`](ts/q4-jcs.mjs). References: [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) sections 3.2.2 and 3.2.3 and Appendix B.

```text
$ node docs/sdk/probes/ts/q4-jcs.mjs
Appendix B rows: 24 | mismatches: []
1e21 1e-7 -0 4.5 0.000001 1E30 -> 1e+21 1e-7 0 4.5 0.000001 1e+30
NaN Infinity -Infinity -> null null null | lone surrogate -> "\ud800"
3.2.2 sample canonical form equals the RFC 3.2.3 text: true
RFC 3.2.3 expected  : CR One Control o-umlaut Euro Emoji Dalet
Object.keys order   : One Euro CR Dalet Emoji Control o-umlaut
default sort()      : CR One Control o-umlaut Euro Emoji Dalet
localeCompare       : Control CR Emoji Euro One o-umlaut Dalet
code point order    : CR One Control o-umlaut Euro Dalet Emoji
```

Facts:

1. All 24 numeric rows of the RFC 8785 Appendix B table (IEEE 754 bit pattern to JSON text) match `JSON.stringify` exactly (`mismatches: []`). The two non-numeric rows (NaN, Infinity) are the third output line. (q4, lines 1 and 3)
2. The samples listed in the task serialize as `1e+21 1e-7 0 4.5 0.000001 1e+30`; `-0` serializes as `0`, as in Appendix B. (q4, line 2)
3. `JSON.stringify(NaN)`, `JSON.stringify(Infinity)` and `JSON.stringify(-Infinity)` return `null`, not an error. RFC 8785 section 3.2.2.3 requires an error. (q4, line 3)
4. `JSON.stringify('\ud800')` returns `"\ud800"` (a lone surrogate is escaped), not an error. RFC 8785 section 3.2.2.2 requires an error. (q4, line 3)
5. A one-line recursive serializer (`canon` in the program: arrays, objects with `Object.keys(v).sort()`, primitives through `JSON.stringify`) turns the RFC 8785 section 3.2.2 input into exactly the section 3.2.3 canonical text, including `\u000f`, `\n`, `\"`, `\\` and `€` unescaped (`equals the RFC 3.2.3 text: true`). (q4, line 4)
6. `Object.keys` order is not sorted: the integer-like key `"1"` comes first, then insertion order (`One Euro CR Dalet Emoji Control o-umlaut`). Sorting has to be explicit. (q4, row `Object.keys order`)
7. The default `Array.prototype.sort()` on the keys gives the RFC 8785 section 3.2.3 expected order (`CR One Control o-umlaut Euro Emoji Dalet`). `localeCompare` gives a different order (`Control CR Emoji Euro One o-umlaut Dalet`), and sorting by code point puts `Dalet` (U+FB33) before `Emoji` (U+1F600), the reverse of the UTF-16 code unit order the RFC requires. (q4, rows `default sort()`, `localeCompare`, `code point order`)
8. Self-check: changing one expected value in a copy of the program (`333333333.3333332` to `333333333.3333399`) reports one mismatch for `41b3de4355555553`.

Differences from the task text: RFC 8785 section 3.2.2.3 contains no sample values; it points to Appendix B. `1e-7` is not in Appendix B (the table has `9.999999999999997e-7` and `0.000001`), and `4.5` and `1e+30` appear in the section 3.2.2 sample, not in the table. All of them were run (facts 1, 2, 5).

## Q5. Schema validation with ajv (draft 2020-12, strict)

Program: [`q5-schema-ajv.mjs`](ts/q5-schema-ajv.mjs), run with the current directory set to the install directory. Schema: [`spec/v1.0/schemas/pact.schema.json`](../../../spec/v1.0/schemas/pact.schema.json) (`$schema` 2020-12). Install: `npm install --ignore-scripts --no-audit --no-fund ajv@8.20.0 ajv-formats@3.0.1`, giving `ajv-formats@3.0.1`, `ajv@8.20.0`, `fast-deep-equal@3.1.3`, `fast-uri@3.1.8`, `json-schema-traverse@1.0.0`, `require-from-string@2.0.2`.

```text
$ cd "$SCRATCH" && node "$REPO/docs/sdk/probes/ts/q5-schema-ajv.mjs"
$ref targets not starting with "#/": []
no ajv-formats: compile error: unknown format "uri" ignored in schema at path "#/properties/gateway_id"
validateFormats:false: compiled; true,true,true,true,true | ack=true | ack status OK=false | ack received_at 2^53=false | problem=true | problem type "not a uri"=true | Appendix C payload (0.2)=false | same, pact_version 0.1=true
addFormat uri=URL.canParse: compiled; true,true,true,true,true | ack=true | ack status OK=false | ack received_at 2^53=false | problem=true | problem type "not a uri"=false | Appendix C payload (0.2)=false | same, pact_version 0.1=true
ajv-formats: compiled; true,true,true,true,true | ack=true | ack status OK=false | ack received_at 2^53=false | problem=true | problem type "not a uri"=false | Appendix C payload (0.2)=false | same, pact_version 0.1=true
```

```text
$ grep -o '"format":"[^"]*"' spec/v1.0/schemas/pact.schema.json | sort | uniq -c
  65 "format":"uri"
```

Summary of the four configurations (all with `strict: true, allErrors: true`; the five flags printed are `strictSchema, strictNumbers, strictTypes, strictTuples, strictRequired`):

| Configuration | Result | `problem` with `type: "not a uri"` |
|---|---|---|
| ajv only | compile error: `unknown format "uri" ignored in schema at path "#/properties/gateway_id"` | not reached |
| `validateFormats: false` | compiles | `true` (accepted) |
| `addFormat('uri', v => URL.canParse(v))` | compiles | `false` (rejected) |
| ajv-formats 3.0.1 | compiles | `false` (rejected) |

Facts:

1. No `$ref` target lacks the `#/` prefix (`[]`), so compilation needs no remote or cross-file resolution; no `loadSchema` was configured and compilation succeeded. (q5, line 1)
2. `strict: true` sets all five strict flags to `true`, `strictRequired` included. (q5)
3. Without ajv-formats, strict compilation fails on the first `uri` format with the error above. The schema uses `format` 65 times, always `uri`. (q5 and the grep)
4. With ajv-formats 3.0.1 the schema compiles. Against the root schema (a `oneOf` over the 16 transport and artifact objects): a valid `Acknowledgment` and a valid `Problem` are accepted; `status: "OK"` (not in the enum), `received_at: 2^53` (above the 9007199254740991 maximum) and `type: "not a uri"` are rejected. (q5)
5. The Appendix C payload (`pact_version` `0.2`) is rejected, and the same payload with `pact_version` set to `0.1` is accepted, so the version is its only schema defect. (q5, last two documents)
6. `validateFormats: false` compiles but stops checking URIs; a hand-registered `uri` format compiles and rejected the one non-URI document tried. Equivalence of `URL.canParse` with RFC 3986 `uri` was not probed.

Expectation in the task (compile in strict mode, offline, with and without ajv-formats): ajv alone does not compile this schema in strict mode; ajv-formats (or a registered `uri` format) is required.

## Q6. Test runner: `node --test` on `.ts`

Program: [`q6-runner.test.ts`](ts/q6-runner.test.ts) (types, an interface, `import type`, generics, `as`, `process.features.typescript`). Extra cases are throwaway files in a directory outside the repository, built with the commands under "Q6 scratch files" below.

```text
$ node --test docs/sdk/probes/ts/q6-runner.test.ts
(node:<pid>) [MODULE_TYPELESS_PACKAGE_JSON] Warning: Module type of file://<repo>/docs/sdk/probes/ts/q6-runner.test.ts is not specified and it doesn't parse as CommonJS.
Reparsing as ES module because module syntax was detected. This incurs a performance overhead.
To eliminate this warning, add "type": "module" to <parent>/package.json.
(Use `node --trace-warnings ...` to show where the warning was created)
✔ sha256("abc") base64url equals the FIPS 180-2 vector (0.586458ms)
✔ annotations, generics and `as` casts are erased at load (0.079125ms)
ℹ tests 2
ℹ suites 0
ℹ pass 2
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 89.547208
```

```text
$ cd docs/sdk/probes/ts && node --test
(node:<pid>) [MODULE_TYPELESS_PACKAGE_JSON] Warning: Module type of file://<repo>/docs/sdk/probes/ts/q6-runner.test.ts is not specified and it doesn't parse as CommonJS.
Reparsing as ES module because module syntax was detected. This incurs a performance overhead.
To eliminate this warning, add "type": "module" to <parent>/package.json.
(Use `node --trace-warnings ...` to show where the warning was created)
✔ sha256("abc") base64url equals the FIPS 180-2 vector (0.598ms)
✔ annotations, generics and `as` casts are erased at load (0.07575ms)
ℹ tests 2
ℹ suites 0
ℹ pass 2
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 87.308166
```

```text
$ node --no-strip-types --test docs/sdk/probes/ts/q6-runner.test.ts    # excerpt
TypeError [ERR_UNKNOWN_FILE_EXTENSION]: Unknown file extension ".ts" for <repo>/docs/sdk/probes/ts/q6-runner.test.ts
Node.js v26.8.1
ℹ pass 0
ℹ fail 1
```

```text
$ node --help | grep strip-types
  --experimental-strip-types, --no-strip-types
```

Q6 scratch files (`$SCRATCH/q6`, with `{"type":"module"}` in `package.json`):

```sh
mkdir -p "$SCRATCH/q6" && cd "$SCRATCH/q6" && echo '{"type":"module"}' > package.json
cp "$REPO/docs/sdk/probes/ts/q6-runner.test.ts" ok.test.ts
printf "import { test } from 'node:test';\nenum Color { Red }\ntest('enum', () => {});\n" > enum.test.ts
printf "import { test } from 'node:test';\nimport assert from 'node:assert/strict';\nconst n: number = 'not a number';\ntest('type error', () => assert.equal(n, 'not a number'));\n" > typeerror.test.ts
printf "export interface Shape { a: number }\nexport const k = 1;\n" > types.ts
printf "import { test } from 'node:test';\nimport { Shape, k } from './types.ts';\ntest('type-only import without import type', () => { const s: Shape = { a: k }; });\n" > typeimport.test.ts
printf "import { test } from 'node:test';\nimport { k } from './types';\ntest('extensionless import', () => { k; });\n" > extless.test.ts
for f in ok enum typeerror typeimport extless; do node --test $f.test.ts; done
```

```text
$ node --test ok.test.ts          # exit 0
✔ sha256("abc") base64url equals the FIPS 180-2 vector (0.701083ms)
✔ annotations, generics and `as` casts are erased at load (0.108333ms)
ℹ tests 2
ℹ suites 0
ℹ pass 2
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 91.58975
```

```text
$ node --test enum.test.ts        # exit 1, excerpt
enum Color { Red }
SyntaxError [ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX]: TypeScript enum is not supported in strip-only mode
ℹ pass 0
ℹ fail 1
```

```text
$ node --experimental-transform-types --test enum.test.ts
node: bad option: --experimental-transform-types
```

```text
$ node --test typeerror.test.ts   # exit 0
✔ type error (0.472209ms)
ℹ tests 1
ℹ suites 0
ℹ pass 1
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 82.917792
```

```text
$ node --test typeimport.test.ts  # exit 1, excerpt
import { Shape, k } from './types.ts';
SyntaxError: The requested module './types.ts' does not provide an export named 'Shape'
ℹ pass 0
ℹ fail 1
```

```text
$ node --test extless.test.ts     # exit 1, excerpt
Error [ERR_MODULE_NOT_FOUND]: Cannot find module '$SCRATCH/q6/types' imported from $SCRATCH/q6/extless.test.ts
ℹ pass 0
ℹ fail 1
```

Facts:

1. On v26.8.1 `process.features.typescript` is `strip`, and `node --test` runs a `.ts` file with no flag and no build step: 2 tests, 2 passed, exit 0. (Q6, first block; the test asserts the feature value itself)
2. `node --test` with no arguments, run in the probe directory, discovers `q6-runner.test.ts` (2 passed); the `.mjs` probes next to it are not picked up. (Q6, second block)
3. With `--no-strip-types` the same file fails with `ERR_UNKNOWN_FILE_EXTENSION` (exit 1). Type stripping is what runs the file. (Q6, third block)
4. Run in the repository, where no `package.json` exists yet, Node walks up to a `package.json` outside the repository that has no `type` field and prints `MODULE_TYPELESS_PACKAGE_JSON` (the file is reparsed as ESM). With `{"type":"module"}` in the nearest `package.json` there is no warning. (Q6, first block versus `ok.test.ts`)
5. Only erasable syntax loads: `enum` fails with `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX: TypeScript enum is not supported in strip-only mode`. `--experimental-transform-types` is a bad option on this Node; the help lists only `--experimental-strip-types, --no-strip-types`. (Q6, `enum.test.ts` and `--experimental-transform-types` blocks)
6. There is no type checking: `const n: number = 'not a number'` runs and its test passes. (Q6, `typeerror.test.ts` block)
7. A type imported without `import type` fails at link time: `The requested module './types.ts' does not provide an export named 'Shape'`. (Q6, `typeimport.test.ts` block)
8. Relative imports need the `.ts` extension: `./types` fails with `ERR_MODULE_NOT_FOUND`. (Q6, `extless.test.ts` block)

Expectation in the task (does `node --test` run `.ts` directly, or is vitest needed): it runs `.ts` directly; vitest is not needed to run tests. Type checking is a separate step that was not probed.

## Decision table

| Primitive | Chosen | Evidence |
|---|---|---|
| ES256 sign and verify | builtin: `node:crypto` `sign`/`verify` with `dsaEncoding: 'ieee-p1363'` | q1: 64 bytes in 2000 of 2000 signatures (DER default is 69 to 72); RFC 7515 A.3 verifies, one flipped bit fails; q1b: Appendix C fixture verifies under `issuer.jwk.json` |
| JWK import and export | builtin: `createPublicKey({format: 'jwk'})`, `export({format: 'jwk'})` for EC P-256, OKP Ed25519 and RSA | q2: all eight keys import; export keeps only key members (drops `kid`, `alg`, `use`); 8000 of 8000 exported coordinates are 32 bytes |
| JWK thumbprint | builtin: `createHash('sha256')` plus a short in-house required-member selection per `kty`; no dependency | q2: RFC 7638 3.1 RSA vector, RFC 8037 A.3 Ed25519 vector and `holder_jkt` `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M` all reproduced; no thumbprint API in `node:crypto` |
| base64url | builtin: `Buffer` and `digest('base64url')` | q1, q2 (signatures, thumbprints) |
| UTF-8 decoding | builtin: `new TextDecoder('utf-8', {fatal: true, ignoreBOM: true})` | q3: five invalid sequences throw; default options drop a BOM, `ignoreBOM: true` keeps it for the JSON layer to reject |
| Strict JSON parse | in-house scanner for duplicate keys; `JSON.parse` for values, plus checks for non-finite, > 2^53 (via `context.source`) and `isWellFormed`; no dependency chosen | q3: duplicates last-wins and invisible to a reviver; `1e999` is `Infinity`; escaped lone surrogates pass; 2^53+1 rounds silently; `context.source` exposes `9007199254740993`, `1e999`, `1.0` |
| JCS (RFC 8785) | builtin: `JSON.stringify` plus an in-house recursive writer using the default key `sort()`, with explicit errors for non-finite numbers and lone surrogates; no dependency | q4: 24 of 24 Appendix B rows match; section 3.2.2 to 3.2.3 sample matches; default sort equals the RFC order; `JSON.stringify` gives `null` for NaN and Infinity and an escape for a lone surrogate (guards needed) |
| JSON Schema 2020-12 validation | dependency: `ajv@8.20.0` (`ajv/dist/2020`, `strict: true`) | q5: compiles in strict mode with all five strict flags on, local `$ref`s only; no builtin validator exists |
| `format: "uri"` in the schema | dependency: `ajv-formats@3.0.1`; alternative to settle in the vet task: a hand-registered `uri` format | q5: ajv alone throws `unknown format "uri"`; `validateFormats: false` accepts `"not a uri"`; ajv-formats and a registered format reject it |
| Test runner | builtin: `node --test` with type stripping; vitest not needed | q6: `.ts` runs with no flag (`process.features.typescript` is `strip`); `--no-strip-types` fails with `ERR_UNKNOWN_FILE_EXTENSION` |

## Constraints the Q6 facts put on SDK source

Stated as observed, not as design decisions: relative imports carry `.ts` extensions; type-only imports use `import type`; no `enum` (the only non-erasable construct probed; other non-erasable constructs were not run); a `package.json` with `"type": "module"` avoids the typeless-package warning; type checking is not done by `node --test`.

## Dependencies named for the vet task

| Package | Version | License | Published | Direct runtime dependencies |
|---|---|---|---|---|
| `ajv` | 8.20.0 (npm `latest`) | MIT | 2026-04-24 | `fast-deep-equal` 3.1.3 (MIT), `fast-uri` 3.1.8 (BSD-3-Clause), `json-schema-traverse` 1.0.0 (MIT), `require-from-string` 2.0.2 (MIT) |
| `ajv-formats` | 3.0.1 (npm `latest`) | MIT | 2024-03-30 | `ajv` ^8.0.0 (also an optional peer) |

```text
$ npm view ajv version
8.20.0
$ npm view ajv-formats version
3.0.1
```

Integrity as installed: `ajv` `sha512-Thbli+OlOj+iMPYFBVBfJ3OmCAnaSyNn4M1vz9T6Gka5Jt9ba/HIR56joy65tY6kx/FCF5VXNB819Y7/GUrBGA==`; `ajv-formats` `sha512-8iUql50EUR+uUcdRQ3HDqa6EVyo3docL8g5WJ3FNcWmu62IbkGUue/pEyLBW8VGKKucTPgqeks4fIU1DA4yowQ==`. Installed with `--ignore-scripts`. Nothing else was installed: no JWS, JCS, duplicate-key or test-runner package.

## Not probed

- Candidate libraries for duplicate-key rejection or a strict JSON tokenizer; the in-house scanner is the stated need, not a measured comparison.
- Whether `URL.canParse` matches the RFC 3986 `uri` format for inputs beyond the six documents in q5.
- Whether spec section 7.1 "invalid Unicode" includes noncharacters; q3 shows only that a fatal `TextDecoder` accepts U+FFFE.
- Type checking (`tsc`) and the build output of the package.
- Signature malleability (high-S) handling in `verify`.
- Any platform other than darwin-arm64.

## Phase-2 probes (2026-10-19)

Second probe round, run before the core ports start. It answers the open `node:http` and `node --test` questions of [ports-plan-ts.md](../ports-plan-ts.md) (section 9, phase 0, and the first risk of section 10) and re-runs every fact that plan marks "probed 2026-10-16". The programs are throwaway and are not committed as files: each is printed in full below, followed by its output. They ran in a scratch directory outside the repository (`$SCRATCH`); packages were installed there with `npm install --ignore-scripts`, never globally, and removed afterwards.

### Environment

| Item | Value |
|---|---|
| Node | 22.11.0, 22.12.0 (P7 only), 22.14.0, 22.22.3, 24.21.0, 26.8.1; each called by absolute path (`<node>/<version>/bin/node`), never through a shim |
| Node 22.18.0 | not run (not installed). The nearest versions run are 22.14.0 (below the floor) and 22.22.3 (above it) |
| Platform | darwin-arm64 only |
| Packages (P4, P5) | `typescript@7.0.2`, `@biomejs/biome@2.5.15`, `ajv@8.20.0`, `ajv-formats@3.0.1`, `@types/node@22.20.5` (the versions in [`ts/package.json`](../../../ts/package.json)); npm resolved `fast-uri@3.1.9` under `ajv` this time (3.1.8 in Q5) |
| npm | 11.19.0, bundled with Node 26.8.1 |

Output conventions are those of the first round: the scratch directory is shortened to `$SCRATCH`, process ids are elided. Where a program condenses its own output (the shell drivers print one line per run, built with `grep`), the block is that program's exact output. A "diff" line compares the output of one Node version with the 26.8.1 output, the first line (the version string) excluded.

### P1. `node:http`: request-target, header order, chunked bodies, body replay

Program `h1-http.mjs`: a `node:http` server records what the handler sees; a `node:net` client sends each request as raw bytes on its own connection. Run on all five versions.

```js
// node:http probe: request-target, rawHeaders, chunked decoding, body replay.
import http from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';

const cases = [
  ['dot segments, encoded slash, fragment', 'GET /a/./b/../%2F%2f/c;p?q=1&q=2#frag HTTP/1.1\r\nHost: x\r\n\r\n'],
  ['absolute-form', 'GET http://Example.COM:80/p?x HTTP/1.1\r\nHost: example.com\r\n\r\n'],
  ['asterisk-form', 'OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n'],
  ['double slash', 'GET //double//slash HTTP/1.1\r\nHost: x\r\n\r\n'],
  ['percent-encoded UTF-8', 'GET /caf%C3%A9/%7e HTTP/1.1\r\nHost: x\r\n\r\n'],
  ['malformed and encoded-dot percent', 'GET /%zz/%2e%2E/%2 HTTP/1.1\r\nHost: x\r\n\r\n'],
  ['lowercase method', 'get /m HTTP/1.1\r\nHost: x\r\n\r\n'],
  ['raw non-ASCII byte', 'GET /cafÃ© HTTP/1.1\r\nHost: x\r\n\r\n'],
  ['space in target', 'GET /a b HTTP/1.1\r\nHost: x\r\n\r\n'],
  ['header order and case', 'GET /h HTTP/1.1\r\nHost: x\r\nX-B: 1\r\nx-a: first\r\nX-A: second\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nCookie: c=1\r\nCookie: d=2\r\nX-Empty:\r\nX-Space:   padded  value \t\r\n\r\n'],
  ['duplicate Host', 'GET /dh HTTP/1.1\r\nHost: one\r\nHost: two\r\n\r\n'],
  ['no Host', 'GET /nh HTTP/1.1\r\n\r\n'],
  ['obs-fold', 'GET /f HTTP/1.1\r\nHost: x\r\nX-Fold: a\r\n b\r\n\r\n'],
  ['chunked with extension and trailer', 'POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n'],
  ['Content-Length and chunked', 'POST /cl HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'],
  ['binary body, Content-Length', Buffer.concat([Buffer.from('POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n'), Buffer.from([0x00, 0xff, 0x0d, 0x0a])])],
];

const server = http.createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);
  let again = 0;
  for await (const c of req) again += c.length;
  const out = {
    method: req.method,
    url: req.url,
    rawHeaders: req.rawHeaders,
    joined: Object.fromEntries(['x-a', 'set-cookie', 'cookie', 'host', 'x-space', 'x-empty'].filter((k) => k in req.headers).map((k) => [k, req.headers[k]])),
    body: body.toString('hex'),
    secondRead: again,
    readableEnded: req.readableEnded,
    rawTrailers: req.rawTrailers,
    sha256: createHash('sha256').update(body).digest('base64url'),
  };
  res.end(JSON.stringify(out));
});

function send(raw) {
  return new Promise((resolve) => {
    const s = net.connect(server.address().port, '127.0.0.1');
    const got = [];
    s.on('data', (d) => got.push(d));
    s.on('close', () => resolve(Buffer.concat(got).toString('latin1')));
    s.on('error', () => {});
    s.end(typeof raw === 'string' ? Buffer.from(raw, 'latin1') : raw);
  });
}

server.listen(0, '127.0.0.1', async () => {
  console.log(process.version);
  for (const [name, raw] of cases) {
    const resp = await send(raw);
    const status = resp.split('\r\n')[0];
    const i = resp.indexOf('\r\n\r\n');
    const body = status.includes(' 200 ') ? resp.slice(i + 4).replace(/^[0-9a-f]+\r\n|\r\n0\r\n\r\n$/g, '') : '';
    console.log(`${name.padEnd(36)} ${status}${body ? ' ' + body : ''}`);
  }
  server.close();
});
```

```text
$ node h1-http.mjs    # Node 26.8.1
v26.8.1
dot segments, encoded slash, fragment HTTP/1.1 200 OK {"method":"GET","url":"/a/./b/../%2F%2f/c;p?q=1&q=2#frag","rawHeaders":["Host","x"],"joined":{"host":"x"},"body":"","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
absolute-form                        HTTP/1.1 200 OK {"method":"GET","url":"http://Example.COM:80/p?x","rawHeaders":["Host","example.com"],"joined":{"host":"example.com"},"body":"","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
asterisk-form                        HTTP/1.1 200 OK {"method":"OPTIONS","url":"*","rawHeaders":["Host","x"],"joined":{"host":"x"},"body":"","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
double slash                         HTTP/1.1 200 OK {"method":"GET","url":"//double//slash","rawHeaders":["Host","x"],"joined":{"host":"x"},"body":"","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
percent-encoded UTF-8                HTTP/1.1 200 OK {"method":"GET","url":"/caf%C3%A9/%7e","rawHeaders":["Host","x"],"joined":{"host":"x"},"body":"","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
malformed and encoded-dot percent    HTTP/1.1 200 OK {"method":"GET","url":"/%zz/%2e%2E/%2","rawHeaders":["Host","x"],"joined":{"host":"x"},"body":"","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
lowercase method                     HTTP/1.1 400 Bad Request
raw non-ASCII byte                   HTTP/1.1 400 Bad Request
space in target                      HTTP/1.1 400 Bad Request
header order and case                HTTP/1.1 200 OK {"method":"GET","url":"/h","rawHeaders":["Host","x","X-B","1","x-a","first","X-A","second","Set-Cookie","a=1","Set-Cookie","b=2","Cookie","c=1","Cookie","d=2","X-Empty","","X-Space","padded  value"],"joined":{"x-a":"first, second","set-cookie":["a=1","b=2"],"cookie":"c=1; d=2","host":"x","x-space":"padded  value","x-empty":""},"body":"","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
duplicate Host                       HTTP/1.1 200 OK {"method":"GET","url":"/dh","rawHeaders":["Host","one","Host","two"],"joined":{"host":"one"},"body":"","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
no Host                              HTTP/1.1 400 Bad Request
obs-fold                             HTTP/1.1 400 Bad Request
chunked with extension and trailer   HTTP/1.1 200 OK {"method":"POST","url":"/c","rawHeaders":["Host","x","Transfer-Encoding","chunked"],"joined":{"host":"x"},"body":"68656c6c6f20776f726c64","secondRead":0,"readableEnded":true,"rawTrailers":["X-Trailer","t"],"sha256":"uU0nuZNNPgilLlLX2n2r-sSE7-N6U4DukIj3rOLvzek"}
Content-Length and chunked           HTTP/1.1 400 Bad Request
binary body, Content-Length          HTTP/1.1 200 OK {"method":"POST","url":"/b","rawHeaders":["Host","x","Content-Length","4"],"joined":{"host":"x"},"body":"00ff0d0a","secondRead":0,"readableEnded":true,"rawTrailers":[],"sha256":"6UifN_swUenvodyRYATXJ057Y5deMglwiUcmfyOTqb4"}
```

```text
$ for v in 22.11.0 22.14.0 22.22.3 24.21.0 26.8.1; do <node>/$v/bin/node h1-http.mjs > out-$v.txt 2>&1; done
$ for v in 22.11.0 22.14.0 22.22.3 24.21.0; do echo "diff $v: $(diff <(tail -n +2 out-$v.txt) <(tail -n +2 out-26.8.1.txt) | wc -l | tr -d ' ') lines"; done
diff 22.11.0: 0 lines
diff 22.14.0: 0 lines
diff 22.22.3: 0 lines
diff 24.21.0: 0 lines
```

Facts (identical on 22.11.0, 22.14.0, 22.22.3, 24.21.0 and 26.8.1):

1. `msg.url` is the request-target exactly as sent. Nothing is decoded, normalized or rejected in it: dot segments (`/a/./b/../`), `%2F` and `%2f` side by side, `;p`, the query, a fragment (`#frag`), the absolute form with its host case and port (`http://Example.COM:80/p?x`), the asterisk form (`*`), `//double//slash`, and malformed escapes (`%zz`, `%2`) and encoded dots (`%2e%2E`) all reach the handler unchanged. Every binding rule on the target (fragment, encoded slash, hex case, dot segments) is therefore the SDK's to enforce; `node:http` neither applies nor hides any of them.
2. The parser answers `400 Bad Request` before the handler runs for: a raw non-ASCII byte in the target, a space in the target, a lowercase method (`get`), a missing `Host`, an obs-fold continuation line, and `Content-Length` together with `Transfer-Encoding: chunked`.
3. `msg.rawHeaders` keeps arrival order, the name case as sent (`x-a` then `X-A`) and every duplicate as its own pair (`Set-Cookie`, `Cookie`, `X-A`). Values are not raw bytes: leading and trailing whitespace is removed (`X-Space:   padded  value ` plus a tab arrives as `padded  value`, inner spaces kept); an empty value is kept as `""`. `msg.headers` lowercases names and joins duplicates (`first, second`; `c=1; d=2` for `cookie`; an array for `set-cookie`).
4. Two `Host` lines are accepted (200). Both appear in `rawHeaders`; `msg.headers.host` is the first (`one`).
5. A chunked body arrives decoded (`hello world`); the chunk extension (`;ext=1`) and the framing are not observable. `Transfer-Encoding: chunked` stays in `rawHeaders`; the trailer is in `rawTrailers` (`["X-Trailer","t"]`), not in `rawHeaders`.
6. A `Content-Length` body arrives byte-exact, including `00 ff 0d 0a`.
7. Body replay: the request stream is single use. After one full read, a second `for await` over the same message yields 0 bytes and `readableEnded` is `true`. A body that has to be digested and also passed on must be buffered once (`Uint8Array`) and the buffer reused; the digest printed is over that buffer.

Answer to the risk in section 10 of the plan: `node:http` gives the raw request-target and the header order in every case tried. It does not give raw header values (fact 3) or the chunked wire framing (fact 5).

### P2. `node --test`: discovery and reporter

Files (`mk.sh`, run once in an empty directory):

```sh
echo '{"type":"module"}' > package.json
t() { printf "import { test } from 'node:test';\nconst label: string = '%s';\ntest(label, () => {});\n" "$2" > "$1"; }
t test/a.test.ts 'ran test/a.test.ts'
t test/sub/b.test.ts 'ran test/sub/b.test.ts'
t test/broken/defect.ts 'ran test/broken/defect.ts'
t test/helper.ts 'ran test/helper.ts'
t root.test.ts 'ran root.test.ts'
printf "import { test } from 'node:test';\ntest('ran test/c.test.mjs', () => {});\n" > test/c.test.mjs
```

Driver `run.sh`, run with stdin and stdout not a terminal (the CI condition):

```sh
# Usage: sh run.sh <node-install-dir>; stdin and stdout are not a terminal.
M=$1
for v in 22.11.0 22.14.0 22.22.3 24.21.0 26.8.1; do
  N=$M/$v/bin/node
  for flags in "" "--experimental-strip-types"; do
    case $v in 22.11.0|22.14.0) ;; *) [ -n "$flags" ] && continue ;; esac
    for args in "" "'test/**/*.test.ts'" "--test-reporter=spec 'test/**/*.test.ts'"; do
      eval "$N $flags --test $args" </dev/null >o.txt 2>&1; rc=$?
      first=$(grep -m1 -E '^(TAP version|✔|✖|ℹ)' o.txt | cut -c1-14)
      ran=$(grep -oE 'ran [a-z/.]+' o.txt | sort -u | sed 's/^ran //' | paste -sd ' ' -)
      err=$(grep -oE 'ERR_[A-Z_]+' o.txt | sort -u | paste -sd ' ' -)
      echo "$v | node $flags --test $args | exit $rc | first: $first | ran: ${ran:--} | ${err}" | sed -E 's/[ |]+$//'
    done
  done
done
```

```text
$ sh run.sh <node>
22.11.0 | node  --test  | exit 0 | first: TAP version 13 | ran: test/c.test.mjs
22.11.0 | node  --test 'test/**/*.test.ts' | exit 1 | first: TAP version 13 | ran: - | ERR_TEST_FAILURE ERR_UNKNOWN_FILE_EXTENSION
22.11.0 | node  --test --test-reporter=spec 'test/**/*.test.ts' | exit 1 | first: ✖ test/a.test. | ran: - | ERR_UNKNOWN_FILE_EXTENSION
22.11.0 | node --experimental-strip-types --test  | exit 0 | first: TAP version 13 | ran: root.test.ts test/a.test.ts test/broken/defect.ts test/c.test.mjs test/helper.ts test/sub/b.test.ts
22.11.0 | node --experimental-strip-types --test 'test/**/*.test.ts' | exit 0 | first: TAP version 13 | ran: test/a.test.ts test/sub/b.test.ts
22.11.0 | node --experimental-strip-types --test --test-reporter=spec 'test/**/*.test.ts' | exit 0 | first: ✔ ran test/a.t | ran: test/a.test.ts test/sub/b.test.ts
22.14.0 | node  --test  | exit 0 | first: TAP version 13 | ran: test/c.test.mjs
22.14.0 | node  --test 'test/**/*.test.ts' | exit 1 | first: TAP version 13 | ran: - | ERR_TEST_FAILURE ERR_UNKNOWN_FILE_EXTENSION
22.14.0 | node  --test --test-reporter=spec 'test/**/*.test.ts' | exit 1 | first: ✖ test/a.test. | ran: - | ERR_UNKNOWN_FILE_EXTENSION
22.14.0 | node --experimental-strip-types --test  | exit 0 | first: TAP version 13 | ran: root.test.ts test/a.test.ts test/broken/defect.ts test/c.test.mjs test/helper.ts test/sub/b.test.ts
22.14.0 | node --experimental-strip-types --test 'test/**/*.test.ts' | exit 0 | first: TAP version 13 | ran: test/a.test.ts test/sub/b.test.ts
22.14.0 | node --experimental-strip-types --test --test-reporter=spec 'test/**/*.test.ts' | exit 0 | first: ✔ ran test/a.t | ran: test/a.test.ts test/sub/b.test.ts
22.22.3 | node  --test  | exit 0 | first: TAP version 13 | ran: root.test.ts test/a.test.ts test/broken/defect.ts test/c.test.mjs test/helper.ts test/sub/b.test.ts
22.22.3 | node  --test 'test/**/*.test.ts' | exit 0 | first: TAP version 13 | ran: test/a.test.ts test/sub/b.test.ts
22.22.3 | node  --test --test-reporter=spec 'test/**/*.test.ts' | exit 0 | first: ✔ ran test/a.t | ran: test/a.test.ts test/sub/b.test.ts
24.21.0 | node  --test  | exit 0 | first: ✔ ran root.tes | ran: root.test.ts test/a.test.ts test/broken/defect.ts test/c.test.mjs test/helper.ts test/sub/b.test.ts
24.21.0 | node  --test 'test/**/*.test.ts' | exit 0 | first: ✔ ran test/a.t | ran: test/a.test.ts test/sub/b.test.ts
24.21.0 | node  --test --test-reporter=spec 'test/**/*.test.ts' | exit 0 | first: ✔ ran test/a.t | ran: test/a.test.ts test/sub/b.test.ts
26.8.1 | node  --test  | exit 0 | first: ✔ ran root.tes | ran: root.test.ts test/a.test.ts test/broken/defect.ts test/c.test.mjs test/helper.ts test/sub/b.test.ts
26.8.1 | node  --test 'test/**/*.test.ts' | exit 0 | first: ✔ ran test/a.t | ran: test/a.test.ts test/sub/b.test.ts
26.8.1 | node  --test --test-reporter=spec 'test/**/*.test.ts' | exit 0 | first: ✔ ran test/a.t | ran: test/a.test.ts test/sub/b.test.ts
```

Driver `nomatch.sh` (same directory):

```sh
# Usage: sh nomatch.sh <node-install-dir>; a glob that matches no file.
for v in 22.22.3 24.21.0 26.8.1; do
  "$1/$v/bin/node" --test 'nomatch/**/*.test.ts' </dev/null >nm.txt 2>&1; rc=$?
  echo "$v | node --test 'nomatch/**/*.test.ts' | exit $rc | $(grep -E '^(# |ℹ )tests' nm.txt)"
done
```

```text
$ sh nomatch.sh <node>
22.22.3 | node --test 'nomatch/**/*.test.ts' | exit 0 | # tests 0
24.21.0 | node --test 'nomatch/**/*.test.ts' | exit 0 | ℹ tests 0
26.8.1 | node --test 'nomatch/**/*.test.ts' | exit 0 | ℹ tests 0
```

Facts:

1. Without type stripping (22.11.0 and 22.14.0 with no flag), bare `node --test` runs only `test/c.test.mjs` and exits 0: the five `.ts` files are skipped silently. The explicit glob `'test/**/*.test.ts'` exits 1 with `ERR_UNKNOWN_FILE_EXTENSION`. The scaffold's `test` script therefore fails on those versions unless `--experimental-strip-types` is added.
2. With type stripping (the flag on 22.11.0 and 22.14.0; the default on 22.22.3, 24.21.0, 26.8.1), bare `node --test` runs all six files: `test/helper.ts` and `test/broken/defect.ts` (no `.test.` in the name) and `root.test.ts` outside `test/` included. The quoted glob `'test/**/*.test.ts'` runs exactly `test/a.test.ts` and `test/sub/b.test.ts`.
3. Default reporter with output not on a terminal: TAP (`TAP version 13`) on 22.11.0, 22.14.0 and 22.22.3; spec (`✔ ...`) on 24.21.0 and 26.8.1. `--test-reporter=spec` gives spec on every version.
4. A glob that matches no file exits 0 with `tests 0` (22.22.3, 24.21.0, 26.8.1): a mistyped glob passes.
5. Node 22.18.0 was not run. Between the versions run, unflagged `.ts` support begins after 22.14.0 and is present in 22.22.3; this probe does not place it more precisely.

### P3. Type stripping across Node versions

Sources: `types.ts`, `main.ts`, `enum.ts`, `paramprop.ts`, `value-import-of-type.ts`, created by the P4 `mk.sh` and copied into a directory with `{"type":"module"}` in `package.json`. Driver `run.sh`:

```sh
# Usage: sh run.sh <node-install-dir>; sources are the tsc probe sources.
for v in 22.11.0 22.14.0 22.22.3 24.21.0 26.8.1; do
  N="$1/$v/bin/node"
  feat=$($N -p 'process.features.typescript'); featf=$($N --experimental-strip-types -p 'process.features.typescript' 2>/dev/null)
  echo "$v | process.features.typescript: $feat, with --experimental-strip-types: $featf" | sed -E 's/[ |]+$//'
  for f in main enum paramprop value-import-of-type; do
    for flags in "" "--experimental-strip-types"; do
      case $v in 22.11.0|22.14.0) ;; *) [ -n "$flags" ] && continue ;; esac
      $N $flags $f.ts >o.txt 2>&1; rc=$?
      echo "  node $flags $f.ts | exit $rc | $(grep -oE "^main 1|ERR_[A-Z_]+|does not provide an export named '[A-Za-z]+'|ExperimentalWarning: Type Stripping" o.txt | sort -u | paste -sd ' ' -)" | sed -E 's/[ |]+$//'
    done
  done
done
```

```text
$ sh run.sh <node>
22.11.0 | process.features.typescript: false, with --experimental-strip-types: strip
  node  main.ts | exit 1 | ERR_UNKNOWN_FILE_EXTENSION
  node --experimental-strip-types main.ts | exit 0 | ExperimentalWarning: Type Stripping main 1
  node  enum.ts | exit 1 | ERR_UNKNOWN_FILE_EXTENSION
  node --experimental-strip-types enum.ts | exit 1 | ERR_INVALID_TYPESCRIPT_SYNTAX ExperimentalWarning: Type Stripping
  node  paramprop.ts | exit 1 | ERR_UNKNOWN_FILE_EXTENSION
  node --experimental-strip-types paramprop.ts | exit 1 | ERR_INVALID_TYPESCRIPT_SYNTAX ExperimentalWarning: Type Stripping
  node  value-import-of-type.ts | exit 1 | ERR_UNKNOWN_FILE_EXTENSION
  node --experimental-strip-types value-import-of-type.ts | exit 1 | does not provide an export named 'Shape' ExperimentalWarning: Type Stripping
22.14.0 | process.features.typescript: false, with --experimental-strip-types: strip
  node  main.ts | exit 1 | ERR_UNKNOWN_FILE_EXTENSION
  node --experimental-strip-types main.ts | exit 0 | ExperimentalWarning: Type Stripping main 1
  node  enum.ts | exit 1 | ERR_UNKNOWN_FILE_EXTENSION
  node --experimental-strip-types enum.ts | exit 1 | ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
  node  paramprop.ts | exit 1 | ERR_UNKNOWN_FILE_EXTENSION
  node --experimental-strip-types paramprop.ts | exit 1 | ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
  node  value-import-of-type.ts | exit 1 | ERR_UNKNOWN_FILE_EXTENSION
  node --experimental-strip-types value-import-of-type.ts | exit 1 | does not provide an export named 'Shape' ExperimentalWarning: Type Stripping
22.22.3 | process.features.typescript: strip, with --experimental-strip-types: strip
  node  main.ts | exit 0 | main 1
  node  enum.ts | exit 1 | ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
  node  paramprop.ts | exit 1 | ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
  node  value-import-of-type.ts | exit 1 | does not provide an export named 'Shape'
24.21.0 | process.features.typescript: strip, with --experimental-strip-types: strip
  node  main.ts | exit 0 | main 1
  node  enum.ts | exit 1 | ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
  node  paramprop.ts | exit 1 | ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
  node  value-import-of-type.ts | exit 1 | does not provide an export named 'Shape'
26.8.1 | process.features.typescript: strip, with --experimental-strip-types: strip
  node  main.ts | exit 0 | main 1
  node  enum.ts | exit 1 | ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
  node  paramprop.ts | exit 1 | ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX
  node  value-import-of-type.ts | exit 1 | does not provide an export named 'Shape'
```

Facts:

1. `process.features.typescript` is `false` on 22.11.0 and 22.14.0 (`strip` with `--experimental-strip-types`) and `strip` on 22.22.3, 24.21.0 and 26.8.1. Without the flag, 22.11.0 and 22.14.0 refuse every `.ts` file with `ERR_UNKNOWN_FILE_EXTENSION`.
2. With stripping on, `enum` and a parameter property fail on every version. The code is `ERR_INVALID_TYPESCRIPT_SYNTAX` on 22.11.0 and `ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX` from 22.14.0 on.
3. A type imported without `import type` fails at link time on every version (`does not provide an export named 'Shape'`); `main.ts` (with `import type`) runs on every version with stripping.
4. 22.11.0 and 22.14.0 print `ExperimentalWarning: Type Stripping`; 22.22.3, 24.21.0 and 26.8.1 print no warning.

### P4. `tsc` 7.0.2: the four flags, emit, the ajv import

Setup `mk.sh` (in a directory under the install directory, so `ajv` and `@types/node` resolve). `base.json` repeats the `compilerOptions` of [`ts/tsconfig.json`](../../../ts/tsconfig.json); each probe config extends it, overrides at most the named flags and lists its files.

```sh
# Throwaway sources and configs; base.json is the scaffold tsconfig.json compilerOptions.
cat > base.json <<'J'
{ "compilerOptions": { "target": "es2024", "lib": ["es2024"], "module": "nodenext", "moduleResolution": "nodenext",
  "types": ["node"], "strict": true, "erasableSyntaxOnly": true, "verbatimModuleSyntax": true,
  "allowImportingTsExtensions": true, "rewriteRelativeImportExtensions": true, "noEmit": true } }
J
cfg() { name=$1; shift; files=$1; shift; printf '{ "extends": "./base.json", "compilerOptions": {%s}, "files": [%s] }\n' "$*" "$files" > "$name.json"; }
cat > src/types.ts <<'T'
export interface Shape { a: number }
export const k = 1;
T
cat > src/ajv-default.ts <<'T'
import Ajv2020 from 'ajv/dist/2020.js';
const ajv = new Ajv2020({ strict: true });
console.log('default import:', typeof ajv.compile);
T
cat > src/ajv-dot-default.ts <<'T'
import Ajv2020Mod from 'ajv/dist/2020.js';
const Ajv2020 = Ajv2020Mod.default;
const ajv = new Ajv2020({ strict: true });
ajv.addFormat('uri', (s: string) => URL.canParse(s));
const v = ajv.compile({ type: 'object', properties: { u: { type: 'string', format: 'uri' } } });
console.log('.default idiom:', v({ u: 'https://a.example/' }), v({ u: 'not a uri' }), Ajv2020Mod.default === (Ajv2020Mod as unknown));
T
printf 'export enum Color { Red }\n' > src/enum.ts
printf 'export class P { constructor(private readonly x: number) {} get v() { return this.x; } }\n' > src/paramprop.ts
printf "import { Shape, k } from './types.ts';\nexport const s: Shape = { a: k };\n" > src/value-import-of-type.ts
printf "import type { Shape } from './types.ts';\nimport { k } from './types.ts';\nexport const s: Shape = { a: k };\nconsole.log('main', s.a);\n" > src/main.ts
cfg ajv-default '"src/ajv-default.ts"'
cfg ajv-dot-default '"src/ajv-dot-default.ts"'
cfg erasable '"src/enum.ts", "src/paramprop.ts"'
cfg erasable-off '"src/enum.ts", "src/paramprop.ts"' '"erasableSyntaxOnly": false'
cfg verbatim '"src/value-import-of-type.ts"'
cfg verbatim-off '"src/value-import-of-type.ts"' '"verbatimModuleSyntax": false'
cfg ts-ext-off '"src/main.ts"' '"allowImportingTsExtensions": false, "rewriteRelativeImportExtensions": false'
cfg emit-no-rewrite '"src/main.ts"' '"noEmit": false, "outDir": "dist-a", "rootDir": "src", "rewriteRelativeImportExtensions": false'
cfg emit-no-rootdir '"src/main.ts"' '"noEmit": false, "outDir": "dist-c"'
cfg emit-rewrite '"src/main.ts"' '"noEmit": false, "outDir": "dist-b", "rootDir": "src", "declaration": true'
```

Driver `run.sh`:

```sh
# Usage: sh run.sh <dir with node on it>; run from this directory.
export PATH=$1:$PATH
TSC=../node_modules/.bin/tsc
$TSC --version
for c in ajv-default ajv-dot-default erasable erasable-off verbatim verbatim-off ts-ext-off emit-no-rewrite emit-no-rootdir emit-rewrite; do
  out=$($TSC -p $c.json --pretty false 2>&1); rc=$?
  echo "--- tsc -p $c.json: exit $rc"; [ -n "$out" ] && echo "$out"
done
echo "--- dist-b"; (cd dist-b && find . -type f | sort && grep -n "from" main.js main.d.ts)
echo "--- node dist-b/main.js"; node dist-b/main.js
echo "--- node src/ajv-dot-default.ts"; node src/ajv-dot-default.ts
echo "--- node src/ajv-default.ts"; node src/ajv-default.ts
```

```text
$ sh run.sh <node>/26.8.1/bin
Version 7.0.2
--- tsc -p ajv-default.json: exit 1
src/ajv-default.ts(2,17): error TS2351: This expression is not constructable.
  Type 'typeof import("$SCRATCH/pkg/node_modules/ajv/dist/2020")' has no construct signatures.
--- tsc -p ajv-dot-default.json: exit 0
--- tsc -p erasable.json: exit 1
src/enum.ts(1,13): error TS1294: This syntax is not allowed when 'erasableSyntaxOnly' is enabled.
src/paramprop.ts(1,30): error TS1294: This syntax is not allowed when 'erasableSyntaxOnly' is enabled.
--- tsc -p erasable-off.json: exit 0
--- tsc -p verbatim.json: exit 1
src/value-import-of-type.ts(1,10): error TS1484: 'Shape' is a type and must be imported using a type-only import when 'verbatimModuleSyntax' is enabled.
--- tsc -p verbatim-off.json: exit 0
--- tsc -p ts-ext-off.json: exit 1
src/main.ts(2,19): error TS5097: An import path can only end with a '.ts' extension when 'allowImportingTsExtensions' is enabled.
--- tsc -p emit-no-rewrite.json: exit 2
emit-no-rewrite.json(1,29): error TS5096: Option 'allowImportingTsExtensions' can only be used when one of 'noEmit', 'emitDeclarationOnly', or 'rewriteRelativeImportExtensions' is set.
--- tsc -p emit-no-rootdir.json: exit 2
emit-no-rootdir.json(1,66): error TS5011: The common source directory of 'emit-no-rootdir.json' is './src'. The 'rootDir' setting must be explicitly set to this or another path to adjust your output's file layout.
  Visit https://aka.ms/ts6 for migration information.
--- tsc -p emit-rewrite.json: exit 0
--- dist-b
./main.d.ts
./main.js
./types.d.ts
./types.js
main.js:1:import { k } from './types.js';
main.d.ts:1:import type { Shape } from './types.ts';
--- node dist-b/main.js
main 1
--- node src/ajv-dot-default.ts
.default idiom: true false true
--- node src/ajv-default.ts
default import: function
```

Consumer `consumer.sh`: the emitted `dist-b` installed as a package whose `exports` point at `dist/*.d.ts`, compiled by a project with none of the `.ts`-extension flags. Line 3 of `use.ts` is a deliberate type error, there to show that the imported type is resolved (an unresolved import would type `s` as an error or `any`).

```sh
# Consumer of the emitted dist-b as an installed package (exports -> dist .d.ts), no .ts-extension flags.
rm -rf consumer && mkdir -p consumer/node_modules/emitted consumer/src
cp -R dist-b consumer/node_modules/emitted/dist
printf '{"name":"emitted","type":"module","exports":{".":{"types":"./dist/main.d.ts","default":"./dist/main.js"}}}\n' > consumer/node_modules/emitted/package.json
printf "import { s } from 'emitted';\nconst n: number = s.a;\nconst bad: string = s.a;\nconsole.log(n, bad);\n" > consumer/src/use.ts
printf '{ "compilerOptions": { "module": "nodenext", "moduleResolution": "nodenext", "strict": true, "noEmit": true, "skipLibCheck": %s, "types": [] }, "files": ["src/use.ts"] }\n' "$1" > consumer/tsconfig.json
../node_modules/.bin/tsc -p consumer/tsconfig.json --pretty false --traceResolution 2>&1 | grep -E "error|'./types.ts' was successfully|Module name './types.ts'" ; echo "exit ${PIPESTATUS[0]}"
```

```text
$ for sk in false true; do echo "skipLibCheck $sk"; sh consumer.sh $sk; done
skipLibCheck false
======== Module name './types.ts' was successfully resolved to '$SCRATCH/pkg/tsc/consumer/node_modules/emitted/dist/types.d.ts'. ========
consumer/src/use.ts(3,7): error TS2322: Type 'number' is not assignable to type 'string'.
exit 1
skipLibCheck true
======== Module name './types.ts' was successfully resolved to '$SCRATCH/pkg/tsc/consumer/node_modules/emitted/dist/types.d.ts'. ========
consumer/src/use.ts(3,7): error TS2322: Type 'number' is not assignable to type 'string'.
exit 1
```

Facts:

1. `import Ajv2020 from 'ajv/dist/2020.js'; new Ajv2020(...)` fails `tsc` 7.0.2 with TS2351 (`This expression is not constructable`). `import Ajv2020Mod from 'ajv/dist/2020.js'; const Ajv2020 = Ajv2020Mod.default` compiles. At run time both forms work: the plain default import is the constructor (`default import: function`), and the `.default` form compiles a schema with a registered `uri` format that accepts `https://a.example/` and rejects `not a uri` (`true false`); `Ajv2020Mod.default === Ajv2020Mod` is `true` at run time. The error is a typing one, and the `.default` idiom is what satisfies `tsc`.
2. `erasableSyntaxOnly`: `enum` and a parameter property each give TS1294; with the flag off the same files compile.
3. `verbatimModuleSyntax`: importing an interface without `import type` gives TS1484; with the flag off it compiles.
4. `allowImportingTsExtensions`: with it off, the value import `'./types.ts'` gives TS5097; the `import type` from `'./types.ts'` on the line above is not reported.
5. `allowImportingTsExtensions` with emit and without `rewriteRelativeImportExtensions` is a configuration error (TS5096, exit 2). With both, emit succeeds and `main.js` imports `'./types.js'`.
6. `tsc` 7.0.2 requires an explicit `rootDir` when emitting with `outDir` here (TS5011, exit 2); [`ts/tsconfig.build.json`](../../../ts/tsconfig.build.json) sets it.
7. Declarations are not rewritten: `main.d.ts` keeps `import type { Shape } from './types.ts'`. A `tsc` 7.0.2 consumer without the `.ts` flags resolves that specifier to `dist/types.d.ts`, with `skipLibCheck` off and on, and the type reaches it (the only error is the deliberate TS2322). Consumers on other TypeScript versions were not run.

### P5. Biome 2.5.15 rules

`biome.json` is [`ts/biome.json`](../../../ts/biome.json) with only the `$schema` path changed (`../node_modules/...`); the sources are the P4 sources. The control directory uses the same files with the three `style` rule lines removed (`grep -v -E '"(noEnum|noParameterProperties|useImportType)"' biome.json`). Driver `run.sh`, run in each directory:

```sh
# biome.json is ts/biome.json with only the $schema path adjusted; sources are the tsc probe sources.
B=../node_modules/.bin/biome
$B --version
for f in enum.ts paramprop.ts value-import-of-type.ts main.ts types.ts; do
  out=$($B lint --colors=off $f 2>&1); rc=$?
  rules=$(printf '%s\n' "$out" | grep -oE 'lint/[a-zA-Z]+/[a-zA-Z]+' | sort -u | paste -sd ' ' -)
  echo "biome lint $f: exit $rc | ${rules:-no diagnostics}" | sed -E 's/[ |]+$//'
done
```

```text
$ sh run.sh    # ts/biome.json
Version: 2.5.15

biome lint enum.ts: exit 1 | lint/style/noEnum
biome lint paramprop.ts: exit 1 | lint/style/noParameterProperties
biome lint value-import-of-type.ts: exit 1 | lint/style/useImportType
biome lint main.ts: exit 0 | no diagnostics
biome lint types.ts: exit 0 | no diagnostics
```

```text
$ sh run.sh    # control: the three style entries removed
Version: 2.5.15

biome lint enum.ts: exit 0 | no diagnostics
biome lint paramprop.ts: exit 0 | no diagnostics
biome lint value-import-of-type.ts: exit 0 | lint/style/useImportType
biome lint main.ts: exit 0 | no diagnostics
biome lint types.ts: exit 0 | no diagnostics
```

Facts:

1. With the scaffold configuration, `lint/style/noEnum`, `lint/style/noParameterProperties` and `lint/style/useImportType` each fire on their file with exit 1; `main.ts` and `types.ts` give no diagnostic.
2. Without the three entries, `noEnum` and `noParameterProperties` do not fire, and `useImportType` is still reported but exits 0. The three explicit `"error"` entries are what make Biome fail on these constructs.

### P6. Bytes and keys: base64url, JWK coordinates, `timingSafeEqual`, high-S

Program `c1-bytes.mjs`, given [`spec/v1.0/fixtures/keys/holder.jwk.json`](../../../spec/v1.0/fixtures/keys/holder.jwk.json). `canonical` is the decoder rule of section 4 of the plan.

```js
// Usage: node c1-bytes.mjs <path to spec/v1.0/fixtures/keys/holder.jwk.json>
import { readFileSync } from 'node:fs';
import { createPublicKey, generateKeyPairSync, sign, timingSafeEqual } from 'node:crypto';

console.log(process.version);
const holder = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const b = (s) => Buffer.from(s, 'base64url');
const canonical = (s) => /^[A-Za-z0-9_-]*$/.test(s) && Buffer.from(s, 'base64url').toString('base64url') === s;

// 1. Buffer base64url leniency and the canonical check.
for (const s of ['AQ', 'AQ==', 'AR', 'A Q', 'AQ\n', 'A', '+/8', '-_8', 'AQ=']) {
  console.log(`base64url ${JSON.stringify(s).padEnd(7)} decodes to [${[...b(s)]}] | canonical ${canonical(s)}`);
}

// 2. JWK coordinate import: padded, non-canonical, wrong length.
const imp = (label, jwk, want = holder) => {
  try {
    const k = createPublicKey({ key: jwk, format: 'jwk' });
    const e = k.export({ format: 'jwk' });
    console.log(`import ${label.padEnd(30)} accepted | exported x and y equal the 32-octet originals: ${e.x === want.x && e.y === want.y}`);
  } catch (err) {
    console.log(`import ${label.padEnd(30)} THROWS ${err.code ?? err.name}: ${err.message}`);
  }
};
const base = { kty: 'EC', crv: 'P-256', x: holder.x, y: holder.y };
imp('fixture x', base);
imp('x with "=" padding', { ...base, x: `${holder.x}=` });
imp('x and y with "=" padding', { ...base, x: `${holder.x}=`, y: `${holder.y}=` });
imp('x with spare bits set', { ...base, x: holder.x.slice(0, -1) + String.fromCharCode(holder.x.charCodeAt(42) + 1) });
imp('x as 33 octets (00 prefix)', { ...base, x: Buffer.concat([Buffer.from([0]), b(holder.x)]).toString('base64url') });
imp('y in standard base64', { ...base, y: b(holder.y).toString('base64') });
// A key whose x starts with 0x00, imported with the leading zero stripped (31 octets).
let short;
for (let i = 0; i < 5000 && !short; i++) {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const j = publicKey.export({ format: 'jwk' });
  if (b(j.x)[0] === 0) short = j;
}
imp('x as 31 octets (zero stripped)', { kty: 'EC', crv: 'P-256', x: b(short.x).subarray(1).toString('base64url'), y: short.y }, short);

// 3. timingSafeEqual on unequal lengths.
try {
  timingSafeEqual(Buffer.alloc(32), Buffer.alloc(31));
  console.log('timingSafeEqual 32 vs 31: returned');
} catch (err) {
  console.log(`timingSafeEqual 32 vs 31: THROWS ${err.code} ${err.name}`);
}
console.log('timingSafeEqual 32 vs 32 equal:', timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32)));

// 4. High-S share of ES256 signatures (P-256 order n).
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
let high = 0;
for (let i = 0; i < 2000; i++) {
  const sig = sign('sha256', Buffer.from(`m${i}`), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  if (BigInt(`0x${sig.subarray(32).toString('hex')}`) > n / 2n) high++;
}
console.log(`high-S signatures: ${high} of 2000`);
```

```text
$ node c1-bytes.mjs spec/v1.0/fixtures/keys/holder.jwk.json    # Node 26.8.1
v26.8.1
base64url "AQ"    decodes to [1] | canonical true
base64url "AQ=="  decodes to [1] | canonical false
base64url "AR"    decodes to [1] | canonical false
base64url "A Q"   decodes to [1] | canonical false
base64url "AQ\n"  decodes to [1] | canonical false
base64url "A"     decodes to [] | canonical false
base64url "+/8"   decodes to [251,255] | canonical false
base64url "-_8"   decodes to [251,255] | canonical true
base64url "AQ="   decodes to [1] | canonical false
import fixture x                      accepted | exported x and y equal the 32-octet originals: true
import x with "=" padding             accepted | exported x and y equal the 32-octet originals: true
import x and y with "=" padding       accepted | exported x and y equal the 32-octet originals: true
import x with spare bits set          accepted | exported x and y equal the 32-octet originals: true
import x as 33 octets (00 prefix)     accepted | exported x and y equal the 32-octet originals: true
import y in standard base64           accepted | exported x and y equal the 32-octet originals: true
import x as 31 octets (zero stripped) accepted | exported x and y equal the 32-octet originals: true
timingSafeEqual 32 vs 31: THROWS ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH RangeError
timingSafeEqual 32 vs 32 equal: true
high-S signatures: 1011 of 2000
```

```text
$ for v in 22.11.0 22.14.0 22.22.3 24.21.0 26.8.1; do <node>/$v/bin/node c1-bytes.mjs spec/v1.0/fixtures/keys/holder.jwk.json > out-$v.txt 2>&1; done
$ for v in 22.11.0 22.14.0 22.22.3 24.21.0; do echo "diff $v (high-S line excluded): $(diff <(tail -n +2 out-$v.txt | grep -v high-S) <(tail -n +2 out-26.8.1.txt | grep -v high-S) | wc -l | tr -d ' ') lines | $(grep high-S out-$v.txt)"; done
diff 22.11.0 (high-S line excluded): 0 lines | high-S signatures: 1018 of 2000
diff 22.14.0 (high-S line excluded): 0 lines | high-S signatures: 983 of 2000
diff 22.22.3 (high-S line excluded): 0 lines | high-S signatures: 986 of 2000
diff 24.21.0 (high-S line excluded): 0 lines | high-S signatures: 1006 of 2000
```

Facts (identical on all five versions except the random high-S count):

1. `Buffer.from(s, 'base64url')` decodes `AQ==`, `AQ=`, `AR` (spare bits set), `A Q` and `AQ\n` to `[1]`, decodes the standard-alphabet `+/8` like `-_8`, and turns the length-1 input `A` into zero bytes, all without an error. The canonical check (alphabet scan, then re-encode equals input) accepts only `AQ` and `-_8`.
2. `createPublicKey({format: 'jwk'})` imports the holder key with `x` padded, with `x` and `y` padded, with spare bits set in `x`, with `x` as 33 octets (a `00` prefix), with `y` in the standard alphabet with padding, and a generated key with its leading-zero `x` cut to 31 octets. Every import exports the canonical 32-octet coordinates. Node enforces neither the encoding nor the length of a coordinate; the decoder and a 32-octet check have to run before `createPublicKey`.
3. `timingSafeEqual` on 32 and 31 bytes throws `RangeError` with code `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH`; on equal lengths it returns.
4. Over 2000 ES256 signatures per run, 983 to 1018 had `s > n/2` in the recorded runs on the five versions (981 to 1032 over earlier runs of the same program): about half, so low-S normalization is needed on sign.

### P7. `require` of an ES module

Setup: `esm/package.json` is `{"type":"module"}`, `esm/index.js` is `export const v = 1;`, `package.json` is `{"type":"commonjs"}`, and `use.cjs`:

```js
const m = require('./esm/index.js');
console.log(process.version, 'require(esm):', m.v);
```

Driver `run.sh`:

```sh
# Usage: sh run.sh <node-install-dir>; a CommonJS file requires an ES module.
for v in 22.11.0 22.12.0 22.14.0 22.22.3 24.21.0 26.8.1; do
  "$1/$v/bin/node" use.cjs >o.txt 2>&1; rc=$?
  echo "$v | exit $rc | $(grep -oE "require\(esm\): 1|ERR_REQUIRE_ESM|ExperimentalWarning: CommonJS module [^ ]+ is loading ES Module" o.txt | sort -u | sed "s|$PWD|\$SCRATCH/req|g" | paste -sd ' ' -)" | sed -E 's/[ |]+$//'
done
```

```text
$ sh run.sh <node>
22.11.0 | exit 1 | ERR_REQUIRE_ESM
22.12.0 | exit 0 | ExperimentalWarning: CommonJS module $SCRATCH/req/use.cjs is loading ES Module require(esm): 1
22.14.0 | exit 0 | require(esm): 1
22.22.3 | exit 0 | require(esm): 1
24.21.0 | exit 0 | require(esm): 1
26.8.1 | exit 0 | require(esm): 1
```

Facts: 22.11.0 refuses with `ERR_REQUIRE_ESM` (exit 1); 22.12.0 loads it with an `ExperimentalWarning`; 22.14.0, 22.22.3, 24.21.0 and 26.8.1 load it with no warning.

### Re-run of the facts marked "probed 2026-10-16"

| Fact in [ports-plan-ts.md](../ports-plan-ts.md) | Section | Record | Result |
|---|---|---|---|
| `tsc` 7.0.2 emits `.js` specifiers in `dist` | 1 | P4 fact 5 (fact 7: `.d.ts` keeps `.ts`, resolved by a 7.0.2 consumer) | reproduced |
| `erasableSyntaxOnly` rejects `enum` and parameter properties with TS1294 | 2 | P4 fact 2 | reproduced |
| `verbatimModuleSyntax`, `allowImportingTsExtensions`, `rewriteRelativeImportExtensions` on 7.0.2 | 2 | P4 facts 3 to 5 | reproduced |
| Biome `style/noEnum`, `style/noParameterProperties`, `style/useImportType` fire on 2.5.15 | 2 | P5 fact 1 (with the scaffold configuration; fact 2 for the defaults) | reproduced |
| Node imports a padded JWK coordinate | 3 | P6 fact 2 | reproduced; also 31- and 33-octet coordinates, spare bits and the standard alphabet |
| `Buffer.from` accepts `AQ==`, `AR`, embedded spaces and newlines | 4 | P6 fact 1 | reproduced |
| `timingSafeEqual` throws `ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH` on unequal lengths | 4 | P6 fact 3 | reproduced |
| The plain ajv default import fails `tsc` 7.0.2 with TS2351; `.default` idiom | 4 | P4 fact 1 | reproduced |
| Bare `node --test` loads every `.ts` under `test/`; Node 22 defaults to TAP off a terminal | 8 | P2 facts 2 and 3 | reproduced (22.11.0, 22.14.0, 22.22.3) |
| Node 22.11 versus 22.22, 24 and 26: type stripping and test discovery | header | P2, P3 | reproduced; 22.11.0 needs `--experimental-strip-types` |

Also checked, not marked in the plan: about half of Node's ES256 signatures are high-S (section 3, P6 fact 4); `require(esm)` works unflagged from 22.12 (section 4, P7). No fact failed to reproduce, so the plan is unchanged.

### Not run in this round

- Node 22.18.0 itself (not installed); see P2 fact 5.
- Any platform other than darwin-arm64, including the Windows leg of section 8.
- `node --test` with output on a terminal.
- `node:http` over TLS (`tlsPeer`), HTTP/2, pipelined requests on one connection, and requests larger than one packet.
- Go's refusal of a padded coordinate (a Go-side fact, outside this probe).
- Consumers of the emitted declarations on TypeScript versions other than 7.0.2.
