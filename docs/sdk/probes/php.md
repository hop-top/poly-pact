# PHP SDK primitive probes

Probe record, 2026-10-16. Purpose: choose the primitives for the PHP core SDK before anything is pinned. Facts come first: each one names the program that produced it, and the observed output is pasted verbatim. A dependency is chosen only where the builtin extensions failed their probe. Where a probe contradicted what was expected, the contradiction is recorded in the section's "Departures" list. The decision table is at the end, followed by the dependencies for the vet step and the open design questions.

The rules being probed come from [`spec/v1.0/draft.md`](../../../spec/v1.0/draft.md): section 6.2 (`holder_jkt` is the RFC 7638 thumbprint), 7.1 (reject duplicate property names, non-finite numbers and invalid Unicode; integers `0..9007199254740991`), 7.2 (baseline `ES256`, `Ed25519` optional, verify the received signing input), 7.4 (`object_digest` over RFC 8785), 20.1 (JSON nesting depth 16, decoded presentation 256 KiB) and 22.2 (cross-language tests cover JCS ordering and number serialization, JOSE signature encoding and JWK thumbprints). The TypeScript and Python records are [`ts.md`](ts.md) and [`py.md`](py.md); the same fixtures are used, so numbers are comparable across the three.

## Environment

| Item | Value |
|---|---|
| PHP, newest | 8.5.11 (cli) (NTS), the pin in [`mise.toml`](../../../mise.toml); the Homebrew build at `/opt/homebrew/bin/php`, called by path |
| PHP, oldest supported minor | 8.2.34 (cli) (NTS), the Homebrew keg `php@8.2` (`/opt/homebrew/opt/php@8.2/bin/php`); see Q6 for why 8.2 is the floor |
| OpenSSL | 3.6.4 (`OPENSSL_VERSION_TEXT`); both PHP builds report the same library, so a difference between 8.2 and 8.5 below is PHP, not OpenSSL |
| PCRE | 10.49 with JIT |
| Composer | 2.10.3, used only inside scratch directories (Q1e, Q3d, Q4f, Q5) |
| Platform | Darwin 24.6.0 arm64 (macOS 15.6.1); no other platform was run |
| Node | v26.8.1 (V8 14.6.202.34-node.28), used only as a reference implementation for number and string text (Q2b, Q4) |

Output blocks are verbatim except: absolute paths are shortened to `<repo>` and `$SCRATCH`, and a block marked "excerpt" keeps only the named lines.

- Every program ran as `php -d error_reporting=-1 <program>` from the repository root. The Homebrew `php.ini` sets `error_reporting` to 30719 (`E_ALL` without the unused `E_STRICT` bit) and `display_errors` on; `-d error_reporting=-1` sets every bit. No program printed an unexpected warning or deprecation on 8.5.11 or 8.2.34; the warnings that do appear are the program's own handler (Q2) and the `openssl_verify` warnings shown for 8.2.34 in Q1b.
- Extensions: `php -m` on 8.5.11 lists `bcmath bz2 calendar Core ctype curl date dba dom exif FFI fileinfo filter ftp gd gettext gmp hash iconv intl json ldap lexbor libxml mbstring mysqli mysqlnd odbc openssl pcntl pcre PDO pdo_dblib pdo_mysql PDO_ODBC pdo_pgsql pdo_sqlite pgsql Phar posix random readline Reflection session shmop SimpleXML snmp soap sockets sodium SPL sqlite3 standard sysvmsg sysvsem sysvshm tidy tokenizer uri xml xmlreader xmlwriter xsl Zend OPcache zip zlib`. The 8.2.34 build lists the same set except that it has no `lexbor`, `snmp` or `uri` (`uri` is new in 8.5) and has `pspell`. The Homebrew builds compile these in: `php -n` (no `php.ini`) lists them too, and every deterministic program printed byte-identical output with and without `php.ini` (table in Q6).
- Extensions the probe programs call into, found by tokenizing every program (q6_versions, Q6): `openssl`, `json`, `mbstring`, `pcre`, `hash`, plus Core, `standard` and (PHP 8.2 and later) `random`. `filter` (`filter_var`) appears once, as a comparison in Q5b, and `tokenizer` only in q6_versions itself. `sodium`, `intl`, `gmp`, `bcmath` and `iconv` are loaded but not called by any program here; `iconv` and `filter` are required by two of the Composer packages (Q5).
- Isolation: Composer packages were installed only inside separate scratch directories outside the repository, each with `composer require --no-scripts --no-plugins --no-progress <package>:<exact version>`, with `COMPOSER_HOME` pointing into scratch so no global Composer configuration was read. Nothing was installed globally, nothing through Homebrew or PECL, and the repository gained no `composer.json`, lock file or `vendor/` directory; only `docs/sdk/probes/php/` and this file. Fetched code was read and run only through the probe programs, never executed by itself; no package script ran (`--no-scripts --no-plugins`).
- Network use: Packagist metadata and archives (Composer), `composer search`, the PHP supported-versions page (read only, through a page fetch tool that summarizes), and nothing else. The schema programs unregister the `http`, `https` and `ftp` stream wrappers before they touch the schema, so a remote `$ref` or `$schema` fetch would fail.
- Downloaded artifacts: each package in its own scratch directory; the programs run from the repository root and receive the package directory as an argument.

Test vectors come from the RFCs and from the repository fixtures: RFC 7515 Appendix A.3, RFC 7638 section 3.1, RFC 8037 Appendix A.3, RFC 8785 section 3.2.3 and Appendix B, [`spec/v1.0/fixtures/keys/*.jwk.json`](../../../spec/v1.0/fixtures/keys), [`spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws`](../../../spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws), [`spec/v1.0/fixtures/vectors/jcs/`](../../../spec/v1.0/fixtures/vectors/jcs) (six input and output pairs and `numbers.json`, 10000 rows), [`spec/v1.0/fixtures/vectors/strictjson/`](../../../spec/v1.0/fixtures/vectors/strictjson) (36 vectors) and [`spec/v1.0/schemas/pact.schema.json`](../../../spec/v1.0/schemas/pact.schema.json).

## How to run

Programs find repository files from their own location (`dirname(__DIR__, 4)`), so they run from any directory; the commands below run from the repository root. Programs that take a Composer project directory get it as an argument and load `vendor/autoload.php` from there.

```sh
php -d error_reporting=-1 docs/sdk/probes/php/q1_es256.php          # and q1b, q1c, q1d, q2, q2b, q3, q3b, q3c, q3e, q4, q4b, q4c, q4d, q4e, q4g, q6
SCRATCH=$(mktemp -d); export COMPOSER_HOME=$SCRATCH/home COMPOSER_NO_INTERACTION=1
for spec in opis:opis/json-schema:2.6.0 jr:justinrainbow/json-schema:6.13.1 jwt:firebase/php-jwt:v7.2.1 psl:phpseclib/phpseclib:3.0.57 \
            lint:seld/jsonlint:1.12.1 jcs1:root23/php-json-canonicalization:1.0.1 jcs2:mmccook/php-json-canonicalization-scheme:1.0.0 jcs3:truschery/kanon:v1.0.1; do
  d=${spec%%:*}; r=${spec#*:}; mkdir -p $SCRATCH/$d && (cd $SCRATCH/$d && echo '{}' > composer.json && composer require --no-scripts --no-plugins --no-progress "${r%%:*}:${r#*:}"); done
php -d error_reporting=-1 docs/sdk/probes/php/q1e_packages.php $SCRATCH/jwt $SCRATCH/psl
php -d error_reporting=-1 docs/sdk/probes/php/q3d_jsonlint.php $SCRATCH/lint
php -d error_reporting=-1 docs/sdk/probes/php/q4f_jcs_packages.php $SCRATCH/jcs1 $SCRATCH/jcs2 $SCRATCH/jcs3
php -d error_reporting=-1 docs/sdk/probes/php/q5_schema.php opis $SCRATCH/opis
php -d error_reporting=-1 docs/sdk/probes/php/q5_schema.php jr $SCRATCH/jr
php -d error_reporting=-1 docs/sdk/probes/php/q5b_format_pattern.php $SCRATCH/opis $SCRATCH/jr
php -d error_reporting=-1 docs/sdk/probes/php/q5c_vectors.php $SCRATCH/opis
```

| Question | Programs (lines) | Needs |
|---|---|---|
| Q1 ES256 | [q1_es256.php](php/q1_es256.php) (12), [q1b_rfc7515.php](php/q1b_rfc7515.php) (13), [q1c_fixture.php](php/q1c_fixture.php) (12), [q1d_b64url.php](php/q1d_b64url.php) (14), [q1e_packages.php](php/q1e_packages.php) (13); helper [jws.php](php/jws.php) (19) | openssl; q1e: php-jwt, phpseclib |
| Q2 thumbprint | [q2_thumbprint.php](php/q2_thumbprint.php) (16), [q2b_export.php](php/q2b_export.php) (15) | openssl |
| Q3 strict parse | [q3_json_decode.php](php/q3_json_decode.php) (9), [q3b_depth.php](php/q3b_depth.php) (11), [q3c_vectors.php](php/q3c_vectors.php) (9), [q3d_jsonlint.php](php/q3d_jsonlint.php) (9), [q3e_scale.php](php/q3e_scale.php) (11); helper [strict.php](php/strict.php) (15) | json, pcre; q3d: seld/jsonlint |
| Q4 JCS | [q4_jcs_numbers.php](php/q4_jcs_numbers.php) (14), [q4b_jcs_document.php](php/q4b_jcs_document.php) (11), [q4c_boundaries.php](php/q4c_boundaries.php) (9), [q4d_jcs_domain.php](php/q4d_jcs_domain.php) (16), [q4e_strings.php](php/q4e_strings.php) (10), [q4f_jcs_packages.php](php/q4f_jcs_packages.php) (10), [q4g_ini_locale.php](php/q4g_ini_locale.php) (9); helpers [esnum.php](php/esnum.php) (16), [jcs.php](php/jcs.php) (16) | json, mbstring; q4f: three packages |
| Q5 schema | [q5_schema.php](php/q5_schema.php) (15), [q5b_format_pattern.php](php/q5b_format_pattern.php) (14), [q5c_vectors.php](php/q5c_vectors.php) (8) | opis, justinrainbow |
| Q6 versions | [q6_versions.php](php/q6_versions.php) (7) | tokenizer |

The task asked for one program per question, each 20 lines or fewer. Every question here needed more than one program to cover its sub-questions, so each program is self-contained apart from small shared helpers; every file, helpers included, is 20 lines or fewer (some lines are long). The helpers are probe code, not a library design.

## Q1. ES256 over P-256 (RFC 7515, RFC 7518 section 3.4)

### q1_es256.php

Signs 5000 messages with a generated P-256 key through `openssl_sign(..., OPENSSL_ALGO_SHA256)` and converts each signature with the hand-rolled `der2raw` and back with `raw2der` ([jws.php](php/jws.php)). The key is random, so the numbers on the first line vary from run to run (the count of signatures with a leading-zero half was 32 to 56 in the runs made).

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q1_es256.php
DER lens [68,69,70,71,72] raw lens [64] raw with a leading 0x00 half: 56 of 5000
round trip true DER->raw->DER identical true
tampered msg false 63 bytes false 65 bytes false DER as raw false
openssl_verify returns: valid 1 wrong message 0 raw 64 bytes -1 garbage -1 -1 is truthy: true
```

### q1b_rfc7515.php

RFC 7515 Appendix A.3, with the JWK turned into a key two ways: a hand-built PEM (`jwk_pub`: the 26-byte P-256 `SubjectPublicKeyInfo` prefix plus `04 || x || y`; `jwk_prv`: a SEC1 `ECPrivateKey` with `d`, `x`, `y`), and `openssl_pkey_new(['ec' => ['curve_name' => 'prime256v1', 'x' => ..., 'y' => ...]])`.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q1b_rfc7515.php            # PHP 8.5.11
PEM import: public OpenSSLAsymmetricKey private OpenSSLAsymmetricKey | public key details have d: false
A.3 signature bytes 64 verifies true tampered input false one bit flipped false
own signature with A.3 d: bytes 64 verifies true equals RFC bytes false
details of the imported public key: type 3 (OPENSSL_KEYTYPE_EC=3) bits 256 curve prime256v1 x equals y equals the RFC value
openssl_pkey_new(ec: x, y): d present false, x equals input true | openssl_pkey_new(ec: x, y, d): x equals input true d equals input true
A.3 verify with the openssl_pkey_new(ec: x, y) key: 1
```

```text
$ /opt/homebrew/opt/php@8.2/bin/php -d error_reporting=-1 docs/sdk/probes/php/q1b_rfc7515.php    # PHP 8.2.34, diff against the 8.5.11 output above
5,6c5,12
< openssl_pkey_new(ec: x, y): d present false, x equals input true | openssl_pkey_new(ec: x, y, d): x equals input true d equals input true
< A.3 verify with the openssl_pkey_new(ec: x, y) key: 1
---
> openssl_pkey_new(ec: x, y): d present true, x equals input false | openssl_pkey_new(ec: x, y, d): x equals input true d equals input true
> A.3 verify with the openssl_pkey_new(ec: x, y) key: PHP Warning:  openssl_verify(): Don't know how to get public key from this private key in <repo>/docs/sdk/probes/php/q1b_rfc7515.php on line 13
> 
> Warning: openssl_verify(): Don't know how to get public key from this private key in <repo>/docs/sdk/probes/php/q1b_rfc7515.php on line 13
> PHP Warning:  openssl_verify(): Supplied key param cannot be coerced into a public key in <repo>/docs/sdk/probes/php/q1b_rfc7515.php on line 13
> 
> Warning: openssl_verify(): Supplied key param cannot be coerced into a public key in <repo>/docs/sdk/probes/php/q1b_rfc7515.php on line 13
> false
```

### q1c_fixture.php

The Appendix C JWS in [`appendix-c-wrong-version.jws`](../../../spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws) under [`issuer.jwk.json`](../../../spec/v1.0/fixtures/keys/issuer.jwk.json), and what the PEM import does with bad keys.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q1c_fixture.php
header {"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"} signature bytes 64
verifies under issuer true under holder false input with one byte appended false
y replaced by 32 x 0x01 (off curve): REJECTED error:1E08010C:DECODER routines::unsupported
issuer x with holder y (valid coordinates of two different keys): REJECTED error:1E08010C:DECODER routines::unsupported
x of 31 bytes (leading byte dropped): REJECTED (jwk_pub length check, openssl not called) | x of 33 bytes (0x00 prepended): REJECTED (jwk_pub length check, openssl not called)
openssl_pkey_get_public on a PEM whose point is 63 bytes: false error:1E08010C:DECODER routines::unsupported
```

On 8.2.34 only the OpenSSL error text differs (`error:0480006C:PEM routines::no start line` in place of `error:1E08010C:DECODER routines::unsupported`); the accept and reject outcomes are identical (diff in Q6).

### q1d_b64url.php

`base64_decode($s, true)` after `strtr('-_', '+/')`, against a guard that requires the base64url alphabet only and re-encodes the decoded bytes to compare with the input.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q1d_b64url.php
"AA"      canonical, 1 byte                base64_decode(strict) after strtr: 00       guard: 00
"AB"      non-zero trailing bits           base64_decode(strict) after strtr: 00       guard: REJECT
"AAB"     non-zero trailing bits, 2 bytes  base64_decode(strict) after strtr: 0000     guard: REJECT
"AA=="    padded                           base64_decode(strict) after strtr: 00       guard: REJECT
"AA\n"    trailing newline                 base64_decode(strict) after strtr: 00       guard: REJECT
"A A"     inner space                      base64_decode(strict) after strtr: 00       guard: REJECT
"+\/"     standard alphabet                base64_decode(strict) after strtr: fb       guard: REJECT
"-_-_"    url alphabet, 3 bytes            base64_decode(strict) after strtr: fbffbf   guard: fbffbf
"A"       one character                    base64_decode(strict) after strtr: false    guard: REJECT
"AA=A"    pad then data                    base64_decode(strict) after strtr: false    guard: REJECT
"AAAAA"   length 5 (1 mod 4)               base64_decode(strict) after strtr: false    guard: REJECT
""        empty                            base64_decode(strict) after strtr:          guard: 
RFC A.3 signature: guard accepts; last char Q -> R (same 64 bytes): decodes equal true guard REJECT
return type string with a false result, strict_types off: '' (coerced; with declare(strict_types=1) it is a TypeError)
```

### q1e_packages.php

`firebase/php-jwt` v7.2.1 and `phpseclib/phpseclib` 3.0.57 as alternatives to hand-rolled DER conversion. php-jwt is given `JWT::$timestamp` (a static) so the A.3 `exp` of 2011 and the fixture's claims are in range. The last line times 300 verifications and is run-dependent.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q1e_packages.php $SCRATCH/jwt $SCRATCH/psl
php-jwt  A.3: accepts {"iss":"joe"} | fixture under issuer: accepts {"pact_version":"0.2"} | A.3 with last signature char Q->R: accepts {"iss":"joe"}
php-jwt  header {"alg":"ES256","typ":"nope","crit":["unknown-ext"],"unknown-ext":1}: accepts {"iss":"joe"}
phpseclib A.3: accepts | fixture under issuer: accepts | A.3 with last signature char Q->R: accepts | fixture under holder key: rejects
verify cost over 300 runs: phpseclib 493 us, ext-openssl 140 us
```

### Facts

1. `openssl_sign` returns a DER `ECDSA-Sig-Value`, not the 64-byte JWS form. Over 5000 signatures the DER length was 69, 70, 71 or 72 bytes in every run but one; the block above is that run, where one signature had both integers short and was 68 bytes (q1_es256, `DER lens`). DER integers are minimal-length and carry a `0x00` prefix when the top bit is set, so the length varies; it is not usable as a JWS signature length.
2. The hand-rolled converter (`der2raw`, 8 lines, `raw2der`, 4 lines in [jws.php](php/jws.php)) returned 64 bytes for all 5000 (`raw lens [64]`), and `raw2der(der2raw(d))` reproduced the original DER bytes for all 5000 (`DER->raw->DER identical true`). All 5000 raw signatures verified through `openssl_verify` (`round trip true`). In 56 of 5000 signatures in the run shown (32 to 56 in the runs made; the expected rate is 2 in 256) `r` or `s` had a leading `0x00` byte, so its DER integer was shorter than 32 bytes and the `str_pad` branch ran; a converter that copies the integers without padding fails for about 0.8 % of signatures.
3. A modified message was rejected (`tampered msg false`). 63-byte and 65-byte signatures and a DER signature offered as raw were rejected by the helper's own `strlen === 64` test before `openssl_verify` runs; the library never sees another length.
4. `openssl_verify` returns `1` for a valid signature, `0` for a wrong message and `-1` for a 64-byte raw signature and for garbage (both are a DER parse error). `(bool) -1` is `true` in PHP, so `if (openssl_verify(...))` accepts an error. On 8.2.34 with an unusable key it returned `false` plus two warnings (q1b, last line, below), so the result type is `int|false`. The verify wrapper must compare `=== 1`.
5. The RFC 7515 Appendix A.3 vector verified (`A.3 signature bytes 64 verifies true`) and failed with one byte appended to the signing input or with one bit of the signature flipped. A signature made with the RFC's `d` verified under the RFC's public key and is not byte-equal to the RFC signature (`equals RFC bytes false`), so the A.3 check is a verification, not a regeneration. The imported public key's `openssl_pkey_get_details` has `x` and `y` equal to the RFC values, `type` 3 (`OPENSSL_KEYTYPE_EC`), `bits` 256 and `curve_name` `prime256v1`; the details of a public key have no `d`.
6. The Appendix C JWS has a 64-byte signature and verifies under `issuer.jwk.json`; it does not verify under `holder.jwk.json` or with one byte appended (q1c). Its header decodes to `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`.
7. Hand-built PEM works on both PHP versions. `jwk_pub` uses the constant `3059301306072a8648ce3d020106082a8648ce3d030107034200` (the DER of `SubjectPublicKeyInfo { ecPublicKey, prime256v1, BIT STRING }` up to the point) followed by `04 || x || y`; `jwk_prv` writes a SEC1 `ECPrivateKey` of 121 bytes (`30 77 ...`). The import rejected a point that is not on the curve (`y` replaced, or `x` from one fixture key with `y` from another): `openssl_pkey_get_public` returned `false` (q1c).
8. `openssl_pkey_new(['ec' => [curve_name, x, y]])` (no `d`) is version-dependent. On 8.5.11 it imports the public key (`d present false, x equals input true`) and verifies A.3 (`1`). On 8.2.34 it ignores the supplied `x` and `y` and generates a fresh random private key (`d present true, x equals input false`); verifying with it emits `Don't know how to get public key from this private key` and `false`. With `d` supplied (`x, y, d`) both versions return the input values. A JWK import built on `openssl_pkey_new` therefore works on 8.5 and breaks on 8.2, the declared floor, by returning a key that is not the one supplied.
9. `openssl_pkey_get_details` exposes the EC `x`, `y` and (for private keys) `d` as raw big-endian strings, but without left padding: over 20000 generated keys, 156 had an `x` or `y` of 31 bytes and none was padded or started with `0x00` (q2b below). A JWK needs exactly 32 octets (RFC 7518 section 6.2.1.2).
10. `base64_decode($s, true)` is not a canonical base64url decoder (q1d). After `strtr` it accepts padding (`AA==`), a trailing newline, an inner space and non-zero trailing bits (`AB` decodes to the same byte as `AA`), and, without the `strtr`, the standard alphabet. It rejected a lone character, data after padding and a length of 1 mod 4. The A.3 signature with its last character changed from `Q` to `R` (the four spare bits of 86 characters) decodes to the same 64 bytes and the guard rejects it. A compact JWS whose signature has spare bits changed is the same signature under a different `artifact_digest` (spec 7.4 hashes the exact string), so the SDK needs the guard.
11. A function declared `: string` that returns `base64_decode`'s `false` returns `''` when `strict_types` is off (the last line of q1d). The decode helper is declared `string|false` for this reason.
12. php-jwt v7.2.1 verifies A.3 and the fixture (it verifies the received `header.payload` text, as spec 7.2 requires). It also accepts the non-canonical signature (`Q -> R`), a header with `"typ":"nope"` and `"crit":["unknown-ext"]` (spec 7.2 prohibits unrecognized critical headers and requires a checked `typ`), applies `exp`, `nbf` and `iat` against the wall clock (the static `JWT::$timestamp` overrides it), and has no dependencies (`composer show` lists one package). phpseclib 3.0.57 (`withSignatureFormat('IEEE')`, which is the 64-byte form) verifies A.3 and the fixture, rejects the fixture under the holder key, accepts the non-canonical signature, and was about 3.5 times slower than the `ext-openssl` path (493 against 140 microseconds in the run shown, on a busy machine; 193 against 57 in an earlier run; 300 verifications each); it brings two dependencies (`paragonie/constant_time_encoding`, `paragonie/random_compat`).

### Departures from the expectation

- The task expected `openssl_sign` to return DER, a converter to be needed, and the A.3 vector to verify: all met. It did not say that `openssl_verify` has three outcomes, that the JWK import through `openssl_pkey_new` is wrong on 8.2, or that coordinates are unpadded; those are findings 4, 8 and 9.
- The task's "hand-rolled parser vs a package" is answered by findings 2 and 12: the hand-rolled converter passed every check; the packages bring dependencies and neither removes the header, `typ`, `crit` and canonical-signature checks the SDK needs anyway.

## Q2. JWK thumbprint (RFC 7638) and export

### q2_thumbprint.php

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q2_thumbprint.php
holder xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M == expected: true | kid/alg/use ignored: true | extra member ignored: true
RFC 7638 3.1 NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs == expected: true | default json_encode flags (escaped slashes) same: true
  adversarial.jwk.json          B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU
  ed25519.jwk.json              kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
  holder.jwk.json               xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M
  issuer.jwk.json               AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE
  learning-controller.jwk.json  yiaHWTOH-NAS43bw6yPHO8YTK_T9cLz9jZaCu3qOg_k
  reputation-service.jwk.json   BcYkeRReg8Py6HmUFJw6240ruOKnvInXb5rRtK6Z9xQ
  validator.jwk.json            uhdbksqePVMcTx2Fvr5RY78RjuSE2bd16nNAkdfZ36I
RFC 8037 A.3 Ed25519 thumbprint matches: true
missing required member y: thumbprint computed anyway =   [E_WARNING handler] Undefined array key "y"
4q4_v44N1-TH-QAcqEnoGpxwkbfhDGqHzV00vWBZXRE
```

### q2b_export.php

The output is random (generated keys). The block is one run; the Node block computes the thumbprint of the printed key's PEM independently.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q2b_export.php
length histogram x: {"31":89,"32":19911}
length histogram y: {"31":67,"32":19933}
length histogram d: {"30":1,"31":84,"32":19915}
keys with a short x or y: 156 of 20000 | unpadded thumbprint differs from padded in 156 of them | exported values starting with a 0x00 byte: 0
first short key, padded x: i4DId--PnrXVx4Q_H8HbM5DsEcflAVjCgRxIxD-LYMc y: AN1yajl8LaBRw-HwlGRYKUCJXnOBiT6dlgguNClfokU thumbprint: hne0iJcNxCPAKPKSLErDC52y0qWxDBejACAoMHA54P4
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi4DId++PnrXVx4Q/H8HbM5DsEcfl
AVjCgRxIxD+LYMcA3XJqOXwtoFHD4fCUZFgpQIlec4GJPp2WCC40KV+iRQ==
-----END PUBLIC KEY-----
issuer export equals file: true
holder export equals file: true
validator export equals file: true
```

```text
$ node -e '<export the PEM above as a JWK, SHA-256 of {"crv","kty","x","y"} in that order, base64url>'      # shell command, not a committed program
x i4DId--PnrXVx4Q_H8HbM5DsEcflAVjCgRxIxD-LYMc y AN1yajl8LaBRw-HwlGRYKUCJXnOBiT6dlgguNClfokU
thumbprint hne0iJcNxCPAKPKSLErDC52y0qWxDBejACAoMHA54P4
x bytes 32 y bytes 32
```

### Facts

1. The RFC 7638 section 3.1 example is an RSA key, not an EC key. Its required members are `e`, `kty`, `n`; the thumbprint computed here from those members, in that order, is `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`, equal to the RFC value (`== expected: true`). (q2, line 2)
2. `holder.jwk.json` gives `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M` (`== expected: true`), the `holder_jkt` of Appendix C. `ed25519.jwk.json` gives `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` (`matches: true`), the value in RFC 8037 Appendix A.3. All seven fixture thumbprints are identical to the ones in the TypeScript and Python records. (q2)
3. Members outside the required set did not change the result: `kid`, `alg`, `use` and an arbitrary extra member (q2, line 1).
4. The implementation is builtin only: `json_encode` of the required members, `ksort($m, SORT_STRING)`, `hash('sha256', ..., true)` and base64url. `json_encode` with its default flags (which escape `/`) gave the same value as with `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` for the RFC 7638 key, because base64url has no `/`. Required members per `kty`: EC `crv kty x y`; RSA `e kty n`; OKP `crv kty x`.
5. A JWK missing a required member does not fail: `$jwk['y']` raises an `E_WARNING` (`Undefined array key "y"`) and yields `null`, and the thumbprint is then computed over `"y":null` (`4q4_v44N1-TH-QAcqEnoGpxwkbfhDGqHzV00vWBZXRE`). Unless warnings are made fatal the program carries on, so the SDK has to test for the members and their types before hashing. (q2, last two lines)
6. `openssl_pkey_get_details` returns `x`, `y`, `d` without padding. In the run shown, 156 of 20000 keys had a 31-byte `x` or `y`; the counts varied from run to run (145 to 160 in the runs made). For each of those keys a thumbprint over the unpadded values differs from the padded one (`differs from padded in 156 of them`). Node 26.8.1 exports the first such key's PEM with 32-byte `x` and `y` and the same padded values, and its thumbprint equals the padded PHP value (`hne0iJcNxCPAKPKSLErDC52y0qWxDBejACAoMHA54P4`). No exported value began with `0x00` (`starting with a 0x00 byte: 0`). Export has to left-pad to 32 bytes.
7. The three fixture keys tried (`issuer`, `holder`, `validator`) imported by PEM and exported through `openssl_pkey_get_details` gave `x` and `y` equal to the file after padding (`export equals file: true`).

### Departures from the expectation

- The task pairs an EC JWK from `spec/v1.0/fixtures/keys` with "reproduce the RFC 7638 section 3.1 example". That example is RSA, so reproducing it needs an RSA row in the required-member table; the EC fixtures have no independent reference value except `holder_jkt` (in the Appendix C payload).

## Q3. Strict JSON: `json_decode`

### q3_json_decode.php

Columns: input label; the result of `json_decode` in assoc mode with no flags; the result in object mode with `JSON_BIGINT_AS_STRING`. Both add `JSON_THROW_ON_ERROR` so that an error shows as `ERR <code> <message>`. Without that flag the call returns `null` and the error is in `json_last_error()` (q3b).

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q3_json_decode.php
dup key           assoc, flags 0: array ( 'a' => 2, )                                  object, BIGINT_AS_STRING: (object) array( 'a' => 2, )
dup key, escaped  assoc, flags 0: array ( 'a' => 2, )                                  object, BIGINT_AS_STRING: (object) array( 'a' => 2, )
1e999             assoc, flags 0: INF (float)                                          object, BIGINT_AS_STRING: INF (float)
-1e999            assoc, flags 0: -INF (float)                                         object, BIGINT_AS_STRING: -INF (float)
1e-400            assoc, flags 0: 0.0 (float)                                          object, BIGINT_AS_STRING: 0.0 (float)
NaN               assoc, flags 0: 'ERR 4 Syntax error'                                 object, BIGINT_AS_STRING: 'ERR 4 Syntax error'
Infinity          assoc, flags 0: 'ERR 4 Syntax error'                                 object, BIGINT_AS_STRING: 'ERR 4 Syntax error'
-Infinity         assoc, flags 0: 'ERR 4 Syntax error'                                 object, BIGINT_AS_STRING: 'ERR 4 Syntax error'
lone high \ud800  assoc, flags 0: 'ERR 10 Single unpaired UTF-16 surrogate in unicode  object, BIGINT_AS_STRING: 'ERR 10 Single unpaired UTF-16 surrogate in unicode escape'
lone low \udc00   assoc, flags 0: 'ERR 10 Single unpaired UTF-16 surrogate in unicode  object, BIGINT_AS_STRING: 'ERR 10 Single unpaired UTF-16 surrogate in unicode escape'
high + A          assoc, flags 0: 'ERR 10 Single unpaired UTF-16 surrogate in unicode  object, BIGINT_AS_STRING: 'ERR 10 Single unpaired UTF-16 surrogate in unicode escape'
valid pair        assoc, flags 0: '😀'                                               object, BIGINT_AS_STRING: '😀'
2^53+1            assoc, flags 0: 9007199254740993 (int)                               object, BIGINT_AS_STRING: 9007199254740993 (int)
2^53+1.0          assoc, flags 0: 9007199254740992.0 (float)                           object, BIGINT_AS_STRING: 9007199254740992.0 (float)
INT_MAX           assoc, flags 0: 9223372036854775807 (int)                            object, BIGINT_AS_STRING: 9223372036854775807 (int)
INT_MAX+1         assoc, flags 0: 9.223372036854776E+18 (float)                        object, BIGINT_AS_STRING: '9223372036854775808'
INT_MIN-1         assoc, flags 0: -9.223372036854776E+18 (float)                       object, BIGINT_AS_STRING: '-9223372036854775809'
30 digits         assoc, flags 0: 1.2345678901234568E+29 (float)                       object, BIGINT_AS_STRING: '123456789012345678901234567890'
-0                assoc, flags 0: 0 (int)                                              object, BIGINT_AS_STRING: 0 (int)
-0.0              assoc, flags 0: -0.0 (float)                                         object, BIGINT_AS_STRING: -0.0 (float)
1.0               assoc, flags 0: 1.0 (float)                                          object, BIGINT_AS_STRING: 1.0 (float)
1E2               assoc, flags 0: 100.0 (float)                                        object, BIGINT_AS_STRING: 100.0 (float)
key \u0000a       assoc, flags 0: array ( '' . "\0" . 'a' => 1, )                      object, BIGINT_AS_STRING: 'ERR 9 The decoded property name is invalid'
numeric keys      assoc, flags 0: array ( 0 => 'a', 1 => 'b', )                        object, BIGINT_AS_STRING: (object) array( '0' => 'a', '1' => 'b', )
empty object      assoc, flags 0: array ( )                                            object, BIGINT_AS_STRING: (object) array( )
trailing {}       assoc, flags 0: 'ERR 4 Syntax error'                                 object, BIGINT_AS_STRING: 'ERR 4 Syntax error'
two values        assoc, flags 0: 'ERR 4 Syntax error'                                 object, BIGINT_AS_STRING: 'ERR 4 Syntax error'
trailing ws       assoc, flags 0: array ( )                                            object, BIGINT_AS_STRING: (object) array( )
empty text        assoc, flags 0: 'ERR 4 Syntax error'                                 object, BIGINT_AS_STRING: 'ERR 4 Syntax error'
BOM + {}          assoc, flags 0: 'ERR 4 Syntax error'                                 object, BIGINT_AS_STRING: 'ERR 4 Syntax error'
ff in string      assoc, flags 0: 'ERR 5 Malformed UTF-8 characters, possibly incorrec object, BIGINT_AS_STRING: 'ERR 5 Malformed UTF-8 characters, possibly incorrectly enco
c0 af             assoc, flags 0: 'ERR 5 Malformed UTF-8 characters, possibly incorrec object, BIGINT_AS_STRING: 'ERR 5 Malformed UTF-8 characters, possibly incorrectly enco
e2 82             assoc, flags 0: 'ERR 5 Malformed UTF-8 characters, possibly incorrec object, BIGINT_AS_STRING: 'ERR 5 Malformed UTF-8 characters, possibly incorrectly enco
ed a0 80          assoc, flags 0: 'ERR 5 Malformed UTF-8 characters, possibly incorrec object, BIGINT_AS_STRING: 'ERR 5 Malformed UTF-8 characters, possibly incorrectly enco
f4 90 80 80       assoc, flags 0: 'ERR 5 Malformed UTF-8 characters, possibly incorrec object, BIGINT_AS_STRING: 'ERR 5 Malformed UTF-8 characters, possibly incorrectly enco
U+FFFE            assoc, flags 0: '￾'                                                object, BIGINT_AS_STRING: '￾'
raw U+0001        assoc, flags 0: 'ERR 3 Control character error, possibly incorrectly object, BIGINT_AS_STRING: 'ERR 3 Control character error, possibly incorrectly encoded
UTF-16LE          assoc, flags 0: 'ERR 5 Malformed UTF-8 characters, possibly incorrec object, BIGINT_AS_STRING: 'ERR 5 Malformed UTF-8 characters, possibly incorrectly enco
```

### q3b_depth.php

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q3b_depth.php
1          needs $depth 1
[]         needs $depth 2
[[]]       needs $depth 3
[1]        needs $depth 2
{}         needs $depth 2
{"a":{}}   needs $depth 3
100 nested arrays: depth 512 -> ok | depth 2147483647 -> ok
1000 nested arrays: depth 512 -> Maximum stack depth exceeded | depth 2147483647 -> ok
5000 nested arrays: depth 512 -> Maximum stack depth exceeded | depth 2147483647 -> Syntax error
100000 nested arrays: depth 512 -> Maximum stack depth exceeded | depth 2147483647 -> Syntax error
depth 0 -> ValueError: json_decode(): Argument #3 ($depth) must be greater than 0 | depth PHP_INT_MAX -> ValueError: json_decode(): Argument #3 ($depth) must be less than 2147483647
accept-depth-16-arrays      expect accept | depth 16: Maximum stack depth exceeded | depth 17: ok | depth 18: ok
accept-depth-16-objects     expect accept | depth 16: Maximum stack depth exceeded | depth 17: ok | depth 18: ok
nesting-depth-17-arrays     expect reject | depth 16: Maximum stack depth exceeded | depth 17: Maximum stack depth exceeded | depth 18: ok
nesting-depth-17-objects    expect reject | depth 16: Maximum stack depth exceeded | depth 17: Maximum stack depth exceeded | depth 18: ok
without THROW: json_decode("null") = NULL json_last_error 0 | json_decode("nul") = NULL json_last_error 4 (Syntax error)
json_last_error after a THROW-flag success that follows a failure: 4
```

### q3c_vectors.php

The 36 vectors in `spec/v1.0/fixtures/vectors/strictjson/` through (a) `json_decode($t, true, 17, JSON_THROW_ON_ERROR)` and (b) `strict_decode` from [strict.php](php/strict.php): the same `json_decode` followed by a regex token scan (duplicate keys by decoded name, integer literals outside `+-(2^53-1)` from their text, floats that overflow to infinity). Verdict against the vector's `expect`.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q3c_vectors.php
bare: 24 of 36 agree with expect; disagree: duplicate-key-escaped-form, duplicate-key-identical-values, duplicate-key-in-headers, duplicate-key-nested, duplicate-key-top-level, integer-overflow-2-pow-53, integer-overflow-huge, integer-overflow-negative, non-finite-number-1e999, non-finite-number-negative-1e999, unknown-core-field-case-variant, unknown-core-field
strict: 34 of 36 agree with expect; disagree: unknown-core-field-case-variant, unknown-core-field
```

The two `unknown-core-field*` vectors need the schema (Q5c).

### q3d_jsonlint.php

`seld/jsonlint` 1.12.1 `JsonParser::parse($in, JsonParser::DETECT_KEY_CONFLICTS)`, alone and after `json_decode(depth 17)`.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q3d_jsonlint.php $SCRATCH/lint
jsonlint alone: 20 of 36 agree; disagree: integer-overflow-2-pow-53, integer-overflow-huge, integer-overflow-negative, invalid-utf8-byte-ff, invalid-utf8-encoded-surrogate, invalid-utf8-overlong-encoding, invalid-utf8-truncated-sequence, lone-surrogate-high-then-bmp, lone-surrogate-high, lone-surrogate-low, nesting-depth-17-arrays, nesting-depth-17-objects, non-finite-number-1e999, non-finite-number-negative-1e999, unknown-core-field-case-variant, unknown-core-field
json_decode(depth 17) then jsonlint: 29 of 36 agree; disagree: integer-overflow-2-pow-53, integer-overflow-huge, integer-overflow-negative, non-finite-number-1e999, non-finite-number-negative-1e999, unknown-core-field-case-variant, unknown-core-field
jsonlint parse of numbers and keys: array ( 'a' => 1, 'b' => array ( 0 => 1.5, 1 => 9223372036854775807, 2 => INF, 3 => '&#xd800;', ), '' => 2, 0 => 3, )
```

### q3e_scale.php

Cost of `strict_decode` at the spec's 256 KiB presentation limit and 16 times above it. Timings and memory are run-dependent.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q3e_scale.php
pcre.jit=1 pcre.backtrack_limit=1000000 pcre.jit enabled in this build: true memory_limit=128M
one 256 KiB string                   262152 bytes  json_decode    0.6 ms  scan     0.3 ms  peak +  0.3 MB  ok
one 4 MiB string                    4194312 bytes  json_decode   10.2 ms  scan     4.3 ms  peak +  3.2 MB  RuntimeException: token scan failed: Backtrack limit exhausted preg: Backtrack limit exhausted
10000 short keys                     147789 bytes  json_decode    0.8 ms  scan     5.1 ms  peak +  3.0 MB  ok
160000 short keys                   2817791 bytes  json_decode   14.1 ms  scan    84.1 ms  peak + 49.2 MB  ok
40000 floats                         388895 bytes  json_decode    1.5 ms  scan     9.2 ms  peak +  3.7 MB  ok
640000 floats                       6928896 bytes  json_decode   27.2 ms  scan   149.5 ms  peak + 59.2 MB  ok
whitespace around {}                 260002 bytes  json_decode    0.2 ms  scan     0.2 ms  peak +  0.0 MB  ok
```

### Facts

1. Duplicate keys: `json_decode` keeps the last value and reports nothing, for the literal duplicate and for the escaped form (`{"a":1,"a":2}` gives `a => 2`), in assoc and object mode. A custom scan is needed; there is no `object_pairs_hook`. (q3, rows `dup key`)
2. `1e999` decodes to `INF` and `-1e999` to `-INF` without error. `1e-400` decodes to `0.0`. The literals `NaN`, `Infinity` and `-Infinity` are a syntax error (code 4). (q3)
3. Lone surrogate escapes are rejected: `"\ud800"`, `"\udc00"` and `"\ud800A"` all give error 10, `Single unpaired UTF-16 surrogate in unicode escape`; the valid pair `"\ud83d\ude00"` decodes to one 4-byte character. (q3) PHP rejects this by itself, unlike `json.loads` and `JSON.parse`.
4. Invalid UTF-8 is rejected with error 5 `Malformed UTF-8 characters` for a stray `ff`, the overlong `c0 af`, the truncated `e2 82`, the encoded surrogate `ed a0 80`, the out-of-range `f4 90 80 80` and for UTF-16LE input. The noncharacter U+FFFE is accepted. A raw U+0001 in a string is error 3 (control character). A UTF-8 BOM before `{}` is a syntax error. (q3) `json_decode` is therefore a strict UTF-8 validator for string contents and for the text as a whole; no separate `mb_check_encoding` step is needed.
5. Integers: `9007199254740993` decodes to the exact `int` 9007199254740993 (PHP integers are 64-bit); `9223372036854775807` is exact; `9223372036854775808` becomes `float` 9.223372036854776E+18, as does a 30-digit literal. With `JSON_BIGINT_AS_STRING` the integers beyond `PHP_INT_MAX` become strings (`'9223372036854775808'`) and everything else is unchanged, so a string value in the tree cannot be told from a JSON string with the same digits. `9007199254740993.0` is a float and rounds to 9007199254740992.0. `-0` decodes to `int` 0 and `-0.0` to `float` -0.0. (q3) The flag does not help detect out-of-range integers; the text has to be inspected.
6. `JSON_THROW_ON_ERROR` throws `JsonException` with the same codes and does not touch the global error state: after a failed call, a later successful call with the flag still leaves `json_last_error()` at 4 (q3b, last line). Without the flag the result is `null` for both the valid text `null` and a syntax error; only `json_last_error()` tells them apart (q3b).
7. `$depth` counts one more than the container nesting. `1` needs depth 1, `[]` and `{}` and `[1]` need 2, `[[]]` and `{"a":{}}` need 3 (q3b). The vectors confirm it: `accept-depth-16-*` (16 containers) fail at `$depth` 16 and pass at 17; `nesting-depth-17-*` fail at 17 and pass at 18. The spec limit of 16 therefore needs `$depth` 17, and `$depth` 16 is an off-by-one that rejects valid input.
8. The parser stack has its own limit: with `$depth` 2147483647, 1000 nested arrays decode, but 5000 fail with `Syntax error` and not with a depth error (q3b). `$depth` 0 and `PHP_INT_MAX` raise `ValueError`. 100000 nested arrays at the default depth 512 fail cleanly with `Maximum stack depth exceeded` and do not crash.
9. Assoc mode loses information JCS needs. `{}` decodes to `[]` and re-encodes as `[]` (q4d); `{"0":"a","1":"b"}` decodes to a list and re-encodes as `["a","b"]` (q4d); an int-like key becomes an `int` key. Object mode keeps `{}` and numeric names as strings, but a valid key such as `"\u0000a"` fails with error 9 `The decoded property name is invalid` (q3, row `key \u0000a`), while assoc mode accepts it.
10. The 36 vectors: `json_decode` with depth 17 and `JSON_THROW_ON_ERROR` agrees with `expect` on 24. It accepts all five duplicate-key vectors, the three integer-overflow vectors, both `1e999` vectors and the two unknown-field vectors (12 disagreements). Adding the token scan fixes everything except the two unknown-field vectors, which are a schema matter (34 of 36; Q5c reaches 36 of 36).
11. `strict_scan` is 13 lines. It must fail closed: with the pattern's string alternative `"(?:[^"\\]++|\\.)*+"`, a 4 MiB string of 1,048,576 escapes made `preg_match_all` return `false` (`Backtrack limit exhausted`, `pcre.backtrack_limit` 1000000, JIT on); the first version ignored the return value and the scan silently covered nothing (re-break check RB4b below). With the check, the same input raises. A 256 KiB string (65,536 escapes) scans in under 1 ms. The scan keeps all tokens in memory: 49.2 MB peak for 160,000 keys (2.8 MB of input), 59.2 MB for 640,000 floats (6.9 MB); the size limit of 256 KiB has to be enforced before the scan. (q3e)
12. `seld/jsonlint` 1.12.1 detects all five duplicate-key vectors, including the escaped form (`jsonlint alone`: none of the duplicate vectors is in the disagree list), but it is a different parser with different rules: it accepts invalid UTF-8 and lone surrogates (and mangles `\ud800` into the text `&#xd800;`), accepts depth 17 and `1e999`, and clamps `9223372036854775808` to `9223372036854775807` (q3d, last line). After `json_decode` it still misses the three integer and two non-finite vectors.

### Departures from the expectation

- The task expected `1e999` to be `INF` (met), invalid UTF-8 to be `JSON_ERROR_UTF8` (met, code 5), lone surrogates to need a check (not needed: error 10), integers above 2^53 to become float (they stay exact `int` up to `PHP_INT_MAX`; only beyond that they become float) and a custom tokenizer for duplicates (met).
- Not in the task: the `$depth` off-by-one (finding 7), `JSON_BIGINT_AS_STRING` being no help (finding 5), the parser-stack `Syntax error` (finding 8), the assoc-versus-object trade-off (finding 9) and the fail-open regex (finding 11).

## Q4. JCS (RFC 8785)

### q4_jcs_numbers.php

Columns: IEEE 754 bits (or `literal`), the RFC string (`want`, from `numbers.json` for the 24 Appendix B rows and from ECMAScript for the 8 literals), then `json_encode`, `var_export`, `strval` and the in-house `es_num` ([esnum.php](php/esnum.php), 15 lines). `*` marks a mismatch with `want`. `es_num` takes the shortest digits that round-trip from `sprintf('%.{p}e')` (so it does not read `serialize_precision`), tries the neighbouring decimal when the nearest one does not round-trip, and lays the digits out per ECMA-262 Number::toString.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q4_jcs_numbers.php
serialize_precision=-1 precision=14
0000000000000000  want=0                          json_encode=0                          var_export=0.0                       * strval=0                          es_num=0                         
8000000000000000  want=0                          json_encode=-0                        * var_export=-0.0                      * strval=-0                        * es_num=0                         
0000000000000001  want=5e-324                     json_encode=5.0e-324                  * var_export=5.0E-324                  * strval=4.9406564584125E-324      * es_num=5e-324                    
8000000000000001  want=-5e-324                    json_encode=-5.0e-324                 * var_export=-5.0E-324                 * strval=-4.9406564584125E-324     * es_num=-5e-324                   
7fefffffffffffff  want=1.7976931348623157e+308    json_encode=1.7976931348623157e+308    var_export=1.7976931348623157E+308   * strval=1.7976931348623E+308      * es_num=1.7976931348623157e+308   
ffefffffffffffff  want=-1.7976931348623157e+308   json_encode=-1.7976931348623157e+308   var_export=-1.7976931348623157E+308  * strval=-1.7976931348623E+308     * es_num=-1.7976931348623157e+308  
4340000000000000  want=9007199254740992           json_encode=9007199254740992           var_export=9007199254740992.0        * strval=9.007199254741E+15        * es_num=9007199254740992          
c340000000000000  want=-9007199254740992          json_encode=-9007199254740992          var_export=-9007199254740992.0       * strval=-9.007199254741E+15       * es_num=-9007199254740992         
4430000000000000  want=295147905179352830000      json_encode=2.9514790517935283e+20    * var_export=2.9514790517935283E+20    * strval=2.9514790517935E+20       * es_num=295147905179352830000     
44b52d02c7e14af5  want=9.999999999999997e+22      json_encode=9.999999999999997e+22      var_export=9.999999999999997E+22     * strval=1.0E+23                   * es_num=9.999999999999997e+22     
44b52d02c7e14af6  want=1e+23                      json_encode=1.0e+23                   * var_export=1.0E+23                   * strval=1.0E+23                   * es_num=1e+23                     
44b52d02c7e14af7  want=1.0000000000000001e+23     json_encode=1.0000000000000001e+23     var_export=1.0000000000000001E+23    * strval=1.0E+23                   * es_num=1.0000000000000001e+23    
444b1ae4d6e2ef4e  want=999999999999999700000      json_encode=9.999999999999997e+20     * var_export=9.999999999999997E+20     * strval=1.0E+21                   * es_num=999999999999999700000     
444b1ae4d6e2ef4f  want=999999999999999900000      json_encode=9.999999999999999e+20     * var_export=9.999999999999999E+20     * strval=1.0E+21                   * es_num=999999999999999900000     
444b1ae4d6e2ef50  want=1e+21                      json_encode=1.0e+21                   * var_export=1.0E+21                   * strval=1.0E+21                   * es_num=1e+21                     
3eb0c6f7a0b5ed8c  want=9.999999999999997e-7       json_encode=9.999999999999997e-7       var_export=9.999999999999997E-7      * strval=1.0E-6                    * es_num=9.999999999999997e-7      
3eb0c6f7a0b5ed8d  want=0.000001                   json_encode=1.0e-6                    * var_export=1.0E-6                    * strval=1.0E-6                    * es_num=0.000001                  
41b3de4355555553  want=333333333.3333332          json_encode=333333333.3333332          var_export=333333333.3333332          strval=333333333.33333           * es_num=333333333.3333332         
41b3de4355555554  want=333333333.33333325         json_encode=333333333.33333325         var_export=333333333.33333325         strval=333333333.33333           * es_num=333333333.33333325        
41b3de4355555555  want=333333333.3333333          json_encode=333333333.3333333          var_export=333333333.3333333          strval=333333333.33333           * es_num=333333333.3333333         
41b3de4355555556  want=333333333.3333334          json_encode=333333333.3333334          var_export=333333333.3333334          strval=333333333.33333           * es_num=333333333.3333334         
41b3de4355555557  want=333333333.33333343         json_encode=333333333.33333343         var_export=333333333.33333343         strval=333333333.33333           * es_num=333333333.33333343        
becbf647612f3696  want=-0.0000033333333333333333  json_encode=-3.3333333333333333e-6    * var_export=-3.3333333333333333E-6    * strval=-3.3333333333333E-6       * es_num=-0.0000033333333333333333 
43143ff3c1cb0959  want=1424953923781206.2         json_encode=1424953923781206.2         var_export=1424953923781206.2         strval=1.4249539237812E+15       * es_num=1424953923781206.2        
literal           want=1e+21                      json_encode=1.0e+21                   * var_export=1.0E+21                   * strval=1.0E+21                   * es_num=1e+21                     
literal           want=1e-7                       json_encode=1.0e-7                    * var_export=1.0E-7                    * strval=1.0E-7                    * es_num=1e-7                      
literal           want=0                          json_encode=-0                        * var_export=-0.0                      * strval=-0                        * es_num=0                         
literal           want=4.5                        json_encode=4.5                        var_export=4.5                        strval=4.5                        es_num=4.5                       
literal           want=1e+30                      json_encode=1.0e+30                   * var_export=1.0E+30                   * strval=1.0E+30                   * es_num=1e+30                     
literal           want=1                          json_encode=1                          var_export=1.0                       * strval=1                          es_num=1                         
literal           want=100                        json_encode=100                        var_export=100.0                     * strval=100                        es_num=100                       
literal           want=10000000000000000          json_encode=10000000000000000          var_export=10000000000000000.0       * strval=1.0E+16                   * es_num=10000000000000000         
Appendix B rows and literals: 32 rows, mismatches json_encode 14 var_export 25 strval 28 es_num 0
numbers.json: 10000 rows, mismatches json_encode 121 var_export 9679 strval 9990 es_num 0
random doubles 499843: float(es_num(x)) === x for 499843 | json_encode equals es_num for 496959 | var_export equals es_num for 109428
```

Cross-check of the 499,843 random doubles against V8 (the program writes `bits es_num(x)` lines to a file when given a path; Node reads the bits as a double and compares `String(x)`):

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q4_jcs_numbers.php $SCRATCH/dump.txt >/dev/null && node $SCRATCH/cmp.js $SCRATCH/dump.txt
rows 499843 mismatches vs V8 Number::toString 0 []
```

### q4c_boundaries.php

Every power of two from 2^-1074 to 2^1023, and the doubles next to each, both signs: the values where the shortest-digits interval is asymmetric.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q4c_boundaries.php $SCRATCH/pow.txt && node $SCRATCH/cmp.js $SCRATCH/pow.txt
values 12586 | float(es_num(x)) === x for 12586 | significant digits histogram: {"1":24,"2":30,"3":28,"4":34,"5":28,"6":30,"7":28,"8":30,"9":24,"10":34,"11":36,"12":34,"13":48,"14":98,"15":674,"16":6138,"17":5268}
2^-1074 5e-324 | 2^53 9007199254740992 | 2^70 1.1805916207174113e+21 | 2^-20 9.5367431640625e-7 | 2^1023 8.98846567431158e+307
rows 12586 mismatches vs V8 Number::toString 0 []
```

### q4g_ini_locale.php

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q4g_ini_locale.php
defaults (-1, precision 14)                    json_encode mismatches   121 | var_export  9679 | es_num 0 | json_encode(0.1) 0.1 | es_num(0.1) 0.1 | sprintf('%.3e', 1.5) 1.500e+0
ini_set('serialize_precision', '17') (was '-1') json_encode mismatches  4432 | var_export  9829 | es_num 0 | json_encode(0.1) 0.10000000000000001 | es_num(0.1) 0.1 | sprintf('%.3e', 1.5) 1.500e+0
ini_set('serialize_precision', '14') (was '-1') json_encode mismatches  9938 | var_export  9995 | es_num 0 | json_encode(0.1) 0.1 | es_num(0.1) 0.1 | sprintf('%.3e', 1.5) 1.500e+0
ini_set('serialize_precision', '-1') (was '-1') json_encode mismatches   121 | var_export  9679 | es_num 0 | json_encode(0.1) 0.1 | es_num(0.1) 0.1 | sprintf('%.3e', 1.5) 1.500e+0
ini_set('precision', '17') (was '14')          json_encode mismatches   121 | var_export  9679 | es_num 0 | json_encode(0.1) 0.1 | es_num(0.1) 0.1 | sprintf('%.3e', 1.5) 1.500e+0
ini_set('precision', '-1') (was '14')          json_encode mismatches   121 | var_export  9679 | es_num 0 | json_encode(0.1) 0.1 | es_num(0.1) 0.1 | sprintf('%.3e', 1.5) 1.500e+0
setlocale(LC_ALL, 'de_DE.UTF-8') => 'de_DE.UTF-8' json_encode mismatches   121 | var_export  9679 | es_num 0 | json_encode(0.1) 0.1 | es_num(0.1) 0.1 | sprintf('%.3e', 1.5) 1.500e+0
setlocale(LC_ALL, 'fr_FR.UTF-8') => 'fr_FR.UTF-8' json_encode mismatches   121 | var_export  9679 | es_num 0 | json_encode(0.1) 0.1 | es_num(0.1) 0.1 | sprintf('%.3e', 1.5) 1.500e+0
locale-dependent in the same process: sprintf("%.1f", 1.5) = 1,5 | sprintf("%.1F", 1.5) = 1.5 | number_format(1.5, 1) = 1.5
```

### q4b_jcs_document.php

The six input and output pairs in `spec/v1.0/fixtures/vectors/jcs/` through `jcs()` ([jcs.php](php/jcs.php): `json_decode` in object mode, then a recursive writer: strings by `json_encode` with three flags, numbers by `es_num`, keys sorted by their UTF-16BE bytes), against the obvious PHP route (assoc decode, `ksort`, `json_encode` with `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE`). Then the key order of the RFC 8785 section 3.2.3 sample.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q4b_jcs_document.php
arrays.json    jcs() equals expected bytes: true  | obvious route equals: true  
french.json    jcs() equals expected bytes: true  | obvious route equals: true  
structures.json jcs() equals expected bytes: true  | obvious route equals: false {"":"empty","1":{"\n":56,"f":{"F":5,"f":"hi"}},"10":[],"111":[{"E":"no","e":"yes"}],"A":[],"a":[]}
unicode.json   jcs() equals expected bytes: true  | obvious route equals: true  
values.json    jcs() equals expected bytes: true  | obvious route equals: false {"literals":[null,true,false],"numbers":[333333333.3333333,1.0e+30,4.5,0.002,1.0e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}
weird.json     jcs() equals expected bytes: true  | obvious route equals: false {"\n":"Newline","\r":"Carriage Return","1":"One","</script>":"Browser Challenge","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","דּ":"Hebrew Letter Dalet With Dagesh","😂":"Smiley"}
UTF-16 order : Carriage Return, One, Control, Latin Small Letter O With Diaeresis, Euro Sign, Emoji: Grinning Face, Hebrew Letter Dalet With Dagesh
UTF-8 bytes  : Carriage Return, One, Control, Latin Small Letter O With Diaeresis, Euro Sign, Hebrew Letter Dalet With Dagesh, Emoji: Grinning Face
ksort default: Carriage Return, One, Control, Latin Small Letter O With Diaeresis, Euro Sign, Hebrew Letter Dalet With Dagesh, Emoji: Grinning Face
jcs() output : {"\r":"Carriage Return","1":"One","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}
```

### q4d_jcs_domain.php

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q4d_jcs_domain.php
9007199254740991                             9007199254740991
9007199254740992                             raises DomainException: integer 9007199254740992 outside +-(2^53-1)
-9007199254740991                            -9007199254740991
-9007199254740992                            raises DomainException: integer -9007199254740992 outside +-(2^53-1)
9223372036854775807                          raises DomainException: integer 9223372036854775807 outside +-(2^53-1)
9007199254740992.0                           9007199254740992
1.0                                          1
-0.0                                         0
INF                                          raises DomainException: non-finite number
NAN                                          raises DomainException: non-finite number
true                                         true
NULL                                         null
string, hex eda080                           raises JsonException: Malformed UTF-8 characters, possibly incorrectly encoded
string, hex 61e280a862                       "a b"
string, hex 7f                               ""
string, hex c3a9                             "é"
array ( 'a' => 1, 'b' => array ( 0 => 1, 1 => 2, ), ) raises DomainException: PHP map where a JSON array is expected
stdClass property "\u0000a" (json_decode obj) raises JsonException: The decoded property name is invalid
{"\u0000a":1} assoc decode, then jcs of object {"\u0000a":1}
{} assoc decode then json_encode             []
{"0":1,"1":2} assoc decode then json_encode  ["a","b"]
{"10":1,"9":2} assoc then ksort() default    [9,10,"a"]
{"10":1,"9":2,"a":3} jcs() key order         {"10":1,"9":2,"a":3}
object with int-like keys: get_object_vars key types ["integer","integer","string"]
jcs(object(a: object())) nested empty object {"a":{}}
jcs(float 1e400 literal in PHP source)       raises DomainException: non-finite number
jcs of a resource                            raises DomainException: unsupported type resource (stream)
```

### q4e_strings.php

Every Unicode scalar value (1,112,064 code points, surrogates excluded) through `json_encode` with `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS`. The program lists the code points whose output differs from the raw character, and writes `code point, output hex` lines for Node to compare with `JSON.stringify(String.fromCodePoint(cp))`.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q4e_strings.php $SCRATCH/str.txt        # excerpt: the first 12 of 37 lines
36 code points differ from the raw character:
  U+0000 => \u0000
  U+0001 => \u0001
  U+0002 => \u0002
  U+0003 => \u0003
  U+0004 => \u0004
  U+0005 => \u0005
  U+0006 => \u0006
  U+0007 => \u0007
  U+0008 => \b
  U+0009 => \t
  U+000A => \n
code points 1112064 mismatches vs JSON.stringify 0
```

### q4f_jcs_packages.php

Three Packagist RFC 8785 packages against the RFC pairs, the 10000 numbers and edge inputs. Mismatches shown are the first three.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q4f_jcs_packages.php $SCRATCH/jcs1 $SCRATCH/jcs2 $SCRATCH/jcs3
root23 1.0.1: RFC pairs 6 of 6 | numbers.json mismatches 9941 of 10000 e.g. 4.940656e-324 (want 5e-324) ; -4.940656e-324 (want -5e-324) ; -3.333333e+21 (want -3.3333333333333335e+21)
    edge: 100.0 -> 1 | 1e21 -> 1e+21 | NAN -> raises LogicException | INF -> raises LogicException | 2^53 (int) -> 9007199254740992 | PHP_INT_MAX -> 9223372036854775807 | "\xff" -> raises JsonException | {} -> {} | [] -> []
mmccook 1.0.0: RFC pairs 6 of 6 | numbers.json mismatches 9941 of 10000 e.g. 4.940656e-324 (want 5e-324) ; -4.940656e-324 (want -5e-324) ; -3.333333e+21 (want -3.3333333333333335e+21)
    edge: 100.0 -> 1 | 1e21 -> 1e+21 | NAN -> raises RuntimeException | INF -> raises RuntimeException | 2^53 (int) -> 9007199254740992 | PHP_INT_MAX -> 9223372036854775807 | "\xff" ->  | {} -> {} | [] -> []
kanon v1.0.1: RFC pairs 6 of 6 | numbers.json mismatches 113 of 10000 e.g. -3.333333333333333e+20 (want -333333333333333300000) ; -3.3333333333333336e+19 (want -33333333333333336000) ; -3.333333333333334e+18 (want -3333333333333334000)
    edge: 100.0 -> 100 | 1e21 -> 1e+21 | NAN -> null | INF -> null | 2^53 (int) -> 9007199254740992 | PHP_INT_MAX -> 9223372036854775807 | "\xff" -> raises TypeError | {} -> {} | [] -> []
```

### Facts

1. PHP's float printers do not give RFC 8785 text. Over the 32 Appendix B rows and literals, `json_encode` (with the default `serialize_precision` -1) mismatched 14, `var_export` 25 and `strval` 28; `es_num` 0. Over the 10000 rows of `numbers.json`: `json_encode` 121, `var_export` 9679, `strval` 9990, `es_num` 0. (q4)
2. How they differ. `json_encode` prints `1.0e+21` for 1e21, `1.0e-7` for 1e-7, `1.0e+30` for 1E30 (a `.0` in the mantissa; the RFC strings are `1e+21`, `1e-7`, `1e+30`) and `-0` for `-0.0` (the RFC string is `0`); it prints `1e16` positionally (`10000000000000000`, which matches) but `2.9514790517935283e+20` in exponent form where ECMAScript prints `295147905179352830000` (ECMAScript switches at 1e21), and `1.0e-6` for 0.000001 where ECMAScript prints `0.000001` (ECMAScript switches below 1e-6). `4.5` matches. `var_export` has the same digits with an upper-case `E` and `.0` on integral values (`1.0`, `100.0`, `10000000000000000.0`). `strval` and `echo` use the `precision` ini setting (14), so they lose digits (`4.9406564584125E-324` for 5e-324, `9.007199254741E+15` for 2^53). (q4)
3. The task's expectation, "PHP prints exponents like `1.0E+25`", holds for `var_export` and `echo`; `json_encode` prints `1.0e+25`.
4. `es_num` has 0 mismatches on 32 rows and 10000 rows; for 499,843 random doubles (seed 0: random bit patterns without NaN and infinities, 100000 uniform values in plus or minus 1e9, 100000 integer-valued floats up to 2^53) `float(es_num(x)) === x` held for all, and `es_num(x)` equalled V8's `String(x)` for all 499,843 (Node block). Over the 12,586 boundary values it also matched V8 for all (q4c). `json_encode` equalled `es_num` for 496,959 of the 499,843, `var_export` for 109,428.
5. The first version of `es_num` searched `p = 0..16` for the first `sprintf('%.{p}e')` that round-trips. It was exact on every other set and wrong at binade boundaries: 92 of the 12,586 boundary values mismatched V8; the three printed (below, RB2) have 17 digits where V8 prints 16 (`7.1202363472230444e-307` against `7.120236347223045e-307` for `0060000000000000`). The cause: at an exact power of two the interval of values that round to the double is asymmetric, the nearest p-digit decimal can fall outside it while the neighbour on the wider side is inside. The final version tries that neighbour (`$D - 1` or `$D + 1`) before adding a digit (re-break check RB2).
6. `serialize_precision` is process-wide and changeable at runtime: `ini_set('serialize_precision', '17')` turned 121 `json_encode` mismatches into 4432 (`json_encode(0.1)` gave `0.10000000000000001`), and `'14'` into 9938; `es_num` stayed at 0. `precision` changes `strval` and `echo` only. A library that formats floats through `json_encode` inherits whatever another library or the application set. (q4g)
7. `sprintf('%e')` is locale-independent (`1.500e+0` under `de_DE.UTF-8` and `fr_FR.UTF-8`, which were available on this machine), `json_encode`, `var_export` and `strval` were unaffected, but `sprintf('%f')` is not (`1,5`), while `sprintf('%F')` and `number_format` are unaffected. (q4g)
8. Strings: `json_encode` with `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` still escapes U+2028 and U+2029; adding `JSON_UNESCAPED_LINE_TERMINATORS` fixes that. With the three flags exactly 34 of the 1,112,064 scalar values are escaped (the program's first line says 36 because it also lists U+2028 and U+2029, which are escaped only without the third flag): `\"`, `\\`, `\b \t \n \f \r` and `\u00xx` (lower-case hex) for the other 27 control characters; U+007F and everything else is raw. The output equalled `JSON.stringify` for all 1,112,064 code points (`mismatches vs JSON.stringify 0`). A string holding the UTF-8 form of a surrogate (`ed a0 80`) makes `json_encode` throw `JsonException` (`Malformed UTF-8`), which is the RFC 8785 requirement to reject. (q4e, q4d)
9. Key order: the RFC 8785 order (UTF-16 code units) is `Carriage Return, One, Control, Latin Small Letter O With Diaeresis, Euro Sign, Emoji, Hebrew Letter Dalet With Dagesh`. Sorting the UTF-8 bytes (`strcmp`, `ksort` with `SORT_STRING`) puts the Hebrew letter (U+FB33) before the emoji (U+1F600), the reverse. `mb_convert_encoding($k, 'UTF-16BE', 'UTF-8')` plus `strcmp` gives the RFC order and `jcs()` reproduced it. `ksort` with default flags sorts int-like keys numerically (`[9,10,"a"]`), while `jcs()` gives `10`, `9`, `a`, the string order the RFC requires. (q4b, q4d)
10. Pairs: `jcs()` equalled the expected bytes for all 6 RFC pairs; the obvious route failed 3 of 6: `structures.json` (empty objects `{}` came out as `[]`), `values.json` (`1.0e+30`, `1.0e-27`) and `weird.json` (emoji order). (q4b)
11. Domain (q4d): `jcs()` rejects integers outside `+-(2^53-1)` (`9007199254740992`, `PHP_INT_MAX`), `INF` and `NAN`, an invalid UTF-8 string, a resource, and a PHP map where a list is expected; it prints `9007199254740992.0` as `9007199254740992`, `-0.0` as `0`, `1.0` as `1`. PHP ints between 2^53 and `PHP_INT_MAX` are exact in PHP but other languages cannot hold them, so they must be rejected or converted before canonicalizing.
12. Packages (q4f): none is usable. `root23/php-json-canonicalization` 1.0.1 and `mmccook/php-json-canonicalization-scheme` 1.0.0 (identical algorithm) matched the 6 RFC pairs and mismatched 9941 of 10000 numbers on 8.5.11 (9937 on 8.2.34; the cause of the difference was not isolated): `100.0` becomes `1` (`rtrim($s, '.0')` strips the trailing zeros of the integer part), `5e-324` becomes `4.940656e-324` (`sprintf('%e')` default precision). mmccook's `"\xff"` gives an empty string and no error; root23 declares no license. `truschery/kanon` v1.0.1 matched the 6 pairs and mismatched 113 of 10000 (it converts `json_encode` output, so large positional values come out in exponent form), returns `null` for NaN and INF where RFC 8785 requires an error, and raises `TypeError` on `"\xff"`. The RFC 8785 pairs alone do not expose any of this; the 10000-number list does.

### Departures from the expectation

- The task cites RFC 8785 section 3.2.2.3 for the samples `1e21`, `1e-7`, `-0.0`, `4.5`, `1E30`. As in the other records: that section holds no sample table (it requires ECMA-262 7.1.12.1 and points to Appendix B); `1e+21` and `0` (minus zero) are in Appendix B, `4.5` and `1e+30` in the section 3.2.2 and 3.2.3 example, and no RFC row has `1e-7`. Expected strings for the 8 literals were taken from ECMAScript and confirmed with Node 26.8.1 (the Python record's V8 table has the same eight).
- `serialize_precision=-1` float text matches the RFC string for only one of the five named samples, `4.5`; `1e21`, `1e-7`, `-0.0` and `1E30` differ.
- Not in the task: the `strval` and `precision` path, the asymmetric-interval defect in a naive shortest-digits search (finding 5), the locale test, the three packages.

## Q5. JSON Schema validation

### q5_schema.php

[`pact.schema.json`](../../../spec/v1.0/schemas/pact.schema.json): `$schema` Draft 2020-12, `$id` `urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60`, 31 `$defs`, 40 `$ref` members, all `#/$defs/...`. Keywords used (counted by a throwaway script): `$defs $id $ref $schema additionalProperties anyOf const enum format items maxItems maxLength maxProperties maximum minItems minLength minProperties minimum oneOf pattern properties propertyNames required title type uniqueItems`; `format` appears 65 times, always `"uri"`. No `$anchor`, `$dynamicRef`, `prefixItems` or `unevaluated*`. The input is the Appendix C payload decoded in object mode (it has `pact_version` `0.2`), validated against `#/$defs/Evidence`.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q5_schema.php opis $SCRATCH/opis
-- schema as published
  payload as published (pact_version 0.2)  const@/pact_version
  pact_version 0.1                         valid
  iss "not a uri"                          format@/iss
  iat 2^53                                 maximum@/iat
  iat 2.0 (float)                          valid
  iat 1.5                                  type@/iat
  iat "5"                                  type@/iat
  extra member                             additionalProperties@/
```

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q5_schema.php jr $SCRATCH/jr
-- schema as published
  THROWS JsonSchema\Exception\ResourceNotFoundException: file_get_contents(file://<repo>/urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60): Failed to open stream: No such file or directory
-- copy with the urn:uuid $id replaced by an https URI
  payload as published (pact_version 0.2)  const@/pact_version
  pact_version 0.1                         valid
  iss "not a uri"                          urlFormat@/iss
  iat 2^53                                 maximum@/iat
  iat 2.0 (float)                          type@/iat
  iat 1.5                                  type@/iat
  iat "5"                                  type@/iat
  extra member                             additionalProp@/
```

### q5b_format_pattern.php

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q5b_format_pattern.php $SCRATCH/opis $SCRATCH/jr
input                                                        opis 2.6.0             justinrainbow 6.13.1   filter_var URL         Uri\Rfc3986\Uri (8.5+)
valid   "https://trust.example/issuers/finance"              ok                     ok                     ok                     ok                    
valid   "urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60"      ok                     ok                     WRONG (rejects)        ok                    
valid   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" ok                     WRONG (rejects)        WRONG (rejects)        ok                    
valid   "mailto:user@example.com"                            ok                     ok                     ok                     ok                    
valid   "a:b"                                                ok                     WRONG (rejects)        WRONG (rejects)        ok                    
valid   "https://[2001:db8::1]:8443/p?q=1#f"                 ok                     ok                     ok                     ok                    
valid   "https://user@host.example:80/p"                     ok                     ok                     ok                     ok                    
valid   "https://host.example/a%20b"                         ok                     ok                     ok                     ok                    
valid   "file:///etc/hosts"                                  ok                     ok                     ok                     ok                    
invalid "not a uri"                                          ok                     ok                     ok                     ok                    
invalid "/relative/path"                                     ok                     ok                     ok                     WRONG (accepts)       
invalid "https://exa mple/"                                  ok                     ok                     ok                     ok                    
invalid "https://host/%zz"                                   ok                     WRONG (accepts)        WRONG (accepts)        ok                    
invalid ""                                                   ok                     ok                     ok                     WRONG (accepts)       
invalid "http://[::1"                                        ok                     ok                     ok                     ok                    
invalid "1http://x"                                          ok                     ok                     WRONG (accepts)        ok                    
invalid "https://host/\\path"                                ok                     ok                     WRONG (accepts)        ok                    
invalid "https://host/ü"                                    ok                     ok                     ok                     ok                    
invalid "https://host:port/"                                 ok                     ok                     ok                     ok                    
invalid "https://host/\n"                                    WRONG (accepts)        WRONG (accepts)        ok                     ok                    
opis 2.6.0: 1 of 20 differ from the RFC 3986 verdict
justinrainbow 6.13.1: 4 of 20 differ from the RFC 3986 verdict
filter_var URL: 6 of 20 differ from the RFC 3986 verdict
Uri\Rfc3986\Uri (8.5+): 2 of 20 differ from the RFC 3986 verdict
pattern ^[A-Za-z0-9_-]{43}$ (body_digest in the schema), value = 43 characters plus a suffix:
  suffix none     opis accepts  justinrainbow accepts  preg_match('/^..$/') 1  preg_match('/^..$/D') 1
  suffix "\n"     opis rejects  justinrainbow accepts  preg_match('/^..$/') 1  preg_match('/^..$/D') 0
  suffix "\n\n"   opis rejects  justinrainbow rejects  preg_match('/^..$/') 0  preg_match('/^..$/D') 0
  suffix "\r\n"   opis rejects  justinrainbow rejects  preg_match('/^..$/') 0  preg_match('/^..$/D') 0
```

On 8.2.34 the last column is `n/a` (the `Uri\Rfc3986\Uri` class is new in 8.5); everything else is identical.

### q5c_vectors.php

The 36 strict-json vectors through `strict_decode` in object mode and then `opis/json-schema` against `#/$defs/OperationContext`.

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q5c_vectors.php $SCRATCH/opis
36 vectors; agree with expect: 36; disagree: -
verdicts: {"accept":9,"reject (json: JsonException)":15,"reject (json: RuntimeException)":10,"reject (schema)":2}
```

### Facts

1. `opis/json-schema` 2.6.0 validates the schema as published. `registerRaw($text)` registers it by `$id` and the reference `urn:uuid:...#/$defs/Evidence` resolves; no remote fetch is made (the wrappers are unregistered). The Appendix C payload fails with exactly one error, `const` at `/pact_version`; with `pact_version` set to `0.1` it is valid and the root schema (`oneOf`) accepts it. `format: "uri"` is asserted by default (`iss "not a uri"` fails `format@/iss`); `iat` `2^53` fails `maximum`; `iat` `1.5` and `"5"` fail `type`; an extra member fails `additionalProperties`; `iat` `2.0` (a PHP `float`) is valid, as Draft 2020-12 treats `2.0` as an integer. (q5, opis)
2. `justinrainbow/json-schema` 6.13.1 cannot resolve the schema as published: the `urn:uuid:` `$id` is treated as a relative file path and the call throws `ResourceNotFoundException` (`file_get_contents(file://<repo>/urn:uuid:...)`). Its README lists Draft 3, 4, 6, 7 and 2019-09, not 2020-12. In a copy with the `$id` replaced by an `https` URI it gives the same verdicts as opis on `const`, `maximum`, `type`, `additionalProperties` (the constraint names differ: `urlFormat`, `additionalProp`), but rejects `iat` `2.0` as a `type` error, which is stricter than Draft 2020-12. (q5, jr)
3. `format: "uri"` against RFC 3986 verdicts for 20 inputs (q5b): opis differs on 1 (it accepts `https://host/\n`, a trailing newline); justinrainbow on 4 (it rejects the valid `did:key:z6Mk...` and `a:b`, and accepts `https://host/%zz` and the same trailing newline); `filter_var(FILTER_VALIDATE_URL)` on 6 (rejects `urn:uuid:...`, `did:key:...`, `a:b`; accepts `1http://x` and a backslash path); PHP 8.5's `Uri\Rfc3986\Uri::parse` on 2 (it parses relative references, so `/relative/path` and the empty string are accepted).
4. `pattern` and the trailing newline: PCRE's `$` matches before a final newline, ECMA-262's does not. For the schema's `^[A-Za-z0-9_-]{43}$`, a value of 43 characters plus `"\n"` is rejected by opis, accepted by justinrainbow, and accepted by `preg_match('/^...$/')` but rejected with the `D` modifier (q5b, pattern block). A validator that passes patterns to PCRE unchanged makes `body_digest`, `holder_jkt`, `method` and the other anchored fields accept a trailing newline.
5. Pipeline: `strict_decode` (object mode) followed by opis against `OperationContext` agreed with `expect` on all 36 vectors (15 rejected by `json_decode`, 10 by the token scan, 2 by the schema, 9 accepted). (q5c)
6. Dependency footprint (Composer, `composer require` in empty directories): opis 2.6.0 resolved to 3 packages (`opis/json-schema` 2.6.0, `opis/string` 2.1.0, `opis/uri` 1.1.0), requiring `ext-json` and `ext-iconv`; justinrainbow 6.13.1 resolved to 2 (`marc-mabe/php-enum` v4.7.2), requiring `ext-filter`, `ext-json`, `ext-reflection`. All resolved and `composer check-platform-reqs` passed on 8.5.11. See "Dependencies named for the vet step". `opis/uri` 1.1.0 is dated 2021-05-22 in `composer.lock`.

### Departures from the expectation

- The task asked which library supports 2020-12 on this schema with offline `$ref`. opis works unmodified; justinrainbow works only on a modified copy and is documented to 2019-09. The schema itself uses only keywords common to Draft 7 and later.
- Not in the task: the `pattern` newline behavior and the `uri` verdict table (findings 3 and 4).

## Q6. PHP versions

CI coverage and the floor. In the sibling poly-cite repository (main), the `php` and `parity` jobs of `.github/workflows/ci.yml` use one version, and `php/composer.json` requires `>=8.2`:

```text
$ grep -n "php-version" .github/workflows/ci.yml
90:          php-version: "8.2"
118:          php-version: "8.2"
$ grep -n "\"php\"" php/composer.json
8:    "php": ">=8.2"
```

This repository has no CI yet and pins only the newest:

```text
$ test -d .github && echo present || echo absent
absent
$ grep -n "^php" mise.toml
26:php = "8.5.11"
```

PHP's supported-versions page (fetched 2026-10-16 through a page fetch tool that summarizes, so treat the cells as second-hand): 8.2 active support ended 2024-12-31 and security support ends 2026-12-31; 8.3 security support ends 2027-12-31; 8.4 2028-12-31; 8.5 2029-12-31.

Every program was run on 8.5.11 and 8.2.34, with and without `php.ini` (`-n`), and the outputs compared (`diff`). `same` means byte-identical output; the programs marked `random` print generated or timing values.

| Program | 8.2.34 vs 8.5.11 | `-n` vs default |
|---|---|---|
| q1_es256 | random output, same structure | random output, same structure |
| q1b_rfc7515 | differs, listed below | same on 8.5.11; on 8.2.34 only the duplicated `PHP Warning:` log lines (`log_errors` in the Homebrew ini) are missing |
| q1c_fixture | differs, listed below | same |
| q1d_b64url | same | same |
| q1e_packages | random output, same structure | random output, same structure |
| q2_thumbprint | same | same |
| q2b_export | random output, same structure | random output, same structure |
| q3_json_decode | same | same |
| q3b_depth | same | same |
| q3c_vectors | same | same |
| q3d_jsonlint | same | same |
| q3e_scale | random output, same structure | random output, same structure |
| q4_jcs_numbers | same | same |
| q4b_jcs_document | same | same |
| q4c_boundaries | same | same |
| q4d_jcs_domain | same | same |
| q4e_strings | same | same |
| q4f_jcs_packages | differs, listed below | same |
| q4g_ini_locale | same | same |
| q5_schema (opis) | same | same |
| q5_schema (jr) | same | same |
| q5b_format_pattern | differs, listed below | same |
| q5c_vectors | same | same |
| q6_versions | differs by design (version strings, `lexbor`, `uri`) | differs by design (`php.ini` path) |

The differences, from `diff` of the 8.5.11 output against the 8.2.34 output:

```text
5,6c5,12
< openssl_pkey_new(ec: x, y): d present false, x equals input true | openssl_pkey_new(ec: x, y, d): x equals input true d equals input true
< A.3 verify with the openssl_pkey_new(ec: x, y) key: 1
---
> openssl_pkey_new(ec: x, y): d present true, x equals input false | openssl_pkey_new(ec: x, y, d): x equals input true d equals input true
> A.3 verify with the openssl_pkey_new(ec: x, y) key: PHP Warning:  openssl_verify(): Don't know how to get public key from this private key in <repo>/docs/sdk/probes/php/q1b_rfc7515.php on line 13
> 
> Warning: openssl_verify(): Don't know how to get public key from this private key in <repo>/docs/sdk/probes/php/q1b_rfc7515.php on line 13
> PHP Warning:  openssl_verify(): Supplied key param cannot be coerced into a public key in <repo>/docs/sdk/probes/php/q1b_rfc7515.php on line 13
> 
> Warning: openssl_verify(): Supplied key param cannot be coerced into a public key in <repo>/docs/sdk/probes/php/q1b_rfc7515.php on line 13
> false
3,4c3,4
< y replaced by 32 x 0x01 (off curve): REJECTED error:1E08010C:DECODER routines::unsupported
< issuer x with holder y (valid coordinates of two different keys): REJECTED error:1E08010C:DECODER routines::unsupported
---
> y replaced by 32 x 0x01 (off curve): REJECTED error:0480006C:PEM routines::no start line
> issuer x with holder y (valid coordinates of two different keys): REJECTED error:0480006C:PEM routines::no start line
6c6
< openssl_pkey_get_public on a PEM whose point is 63 bytes: false error:1E08010C:DECODER routines::unsupported
---
> openssl_pkey_get_public on a PEM whose point is 63 bytes: false error:0480006C:PEM routines::no start line
1c1
< root23 1.0.1: RFC pairs 6 of 6 | numbers.json mismatches 9941 of 10000 e.g. 4.940656e-324 (want 5e-324) ; -4.940656e-324 (want -5e-324) ; -3.333333e+21 (want -3.3333333333333335e+21)
---
> root23 1.0.1: RFC pairs 6 of 6 | numbers.json mismatches 9937 of 10000 e.g. 4.940656e-324 (want 5e-324) ; -4.940656e-324 (want -5e-324) ; -3.333333e+21 (want -3.3333333333333335e+21)
3c3
< mmccook 1.0.0: RFC pairs 6 of 6 | numbers.json mismatches 9941 of 10000 e.g. 4.940656e-324 (want 5e-324) ; -4.940656e-324 (want -5e-324) ; -3.333333e+21 (want -3.3333333333333335e+21)
---
> mmccook 1.0.0: RFC pairs 6 of 6 | numbers.json mismatches 9937 of 10000 e.g. 4.940656e-324 (want 5e-324) ; -4.940656e-324 (want -5e-324) ; -3.333333e+21 (want -3.3333333333333335e+21)
1c1
< PHP 8.5.11 cli Darwin int size 8 OpenSSL 3.6.4 25 Aug 2026 PCRE 10.49 2026-09-28 jit true /opt/homebrew/etc/php/8.5/php.ini
---
> PHP 8.2.34 cli Darwin int size 8 OpenSSL 3.6.4 25 Aug 2026 PCRE 10.49 2026-09-28 jit true /opt/homebrew/etc/php/8.2/php.ini
```

```text
$ php -d error_reporting=-1 docs/sdk/probes/php/q6_versions.php                                   # PHP 8.5.11
PHP 8.5.11 cli Darwin int size 8 OpenSSL 3.6.4 25 Aug 2026 PCRE 10.49 2026-09-28 jit true /opt/homebrew/etc/php/8.5/php.ini
 serialize_precision='-1' precision='14' pcre.backtrack_limit='1000000' pcre.jit='1' memory_limit='128M' zend.assertions='1' display_errors='1' error_reporting='-1' allow_url_fopen='1' disable_functions=''
loaded extensions: core date lexbor openssl pcre sqlite3 zlib bcmath bz2 calendar ctype curl dba uri json mbstring spl ffi fileinfo filter ftp gd gettext gmp hash iconv intl session ldap standard libxml mysqlnd mysqli odbc zend opcache pcntl pdo pdo_dblib pdo_mysql pdo_odbc pdo_pgsql pdo_sqlite pgsql phar posix random readline reflection exif shmop simplexml snmp soap sockets sodium sysvmsg sysvsem sysvshm tidy tokenizer dom xml xmlreader xmlwriter xsl zip
core      class_exists function_exists get_class get_loaded_extensions get_object_vars set_error_handler strcmp strlen
filter    filter_var
hash      hash
json      json_decode json_encode json_last_error json_last_error_msg
mbstring  mb_chr mb_convert_encoding
openssl   openssl_error_string openssl_pkey_get_details openssl_pkey_get_private openssl_pkey_get_public openssl_pkey_new openssl_sign openssl_verify
pcre      preg_last_error preg_last_error_msg preg_match preg_match_all preg_replace
random    mt_getrandmax mt_rand mt_srand
standard  abs array_column array_count_values array_diff_key array_filter array_is_list array_key_last array_keys array_map array_merge array_pop array_push array_reduce array_slice array_unique array_values base64_decode base64_encode basename bin2hex chr chunk_split count dirname end explode file_get_contents file_put_contents fopen fwrite get_debug_type glob hex2bin hrtime implode in_array ini_get ini_set is_array is_bool is_finite is_float is_int is_object is_string ksort ltrim memory_get_peak_usage memory_get_usage memory_reset_peak_usage number_format ord pack php_ini_loaded_file printf range rtrim setlocale sort sprintf str_pad str_repeat str_replace str_starts_with stream_wrapper_unregister strtolower strtr substr trim uasort unpack usort var_export
tokenizer token_get_all
```

Facts:

1. Everything the SDK would use produced identical output on 8.2.34 and 8.5.11, with and without `php.ini`: the DER conversion round trip, the A.3 and fixture verification through PEM, thumbprints, `json_decode` behavior and depth, the strict scan, `es_num`, `jcs()`, the string escaping, the schema verdicts of opis and justinrainbow and the 36-vector pipeline.
2. Four differences, none in the chosen path: (a) `openssl_pkey_new` with `x`, `y` and no `d` (finding Q1.8: public key on 8.5.11, random private key on 8.2.34); (b) the OpenSSL error text for a rejected PEM (`DECODER routines::unsupported` against `PEM routines::no start line`), so error text must not be matched; (c) PHP 8.5's `Uri\Rfc3986\Uri` does not exist on 8.2; (d) `root23` and `mmccook` produce 9941 against 9937 mismatches (not chosen; the cause was not isolated).
3. All programs ran unmodified on 8.2.34, so none calls a function newer than 8.2 (`memory_reset_peak_usage` and `array_is_list` are the newest; q6_versions lists every function called).
4. The platform requirements of the chosen path: `php >=8.2`, 64-bit (`PHP_INT_SIZE` 8; 32-bit PHP would decode integers above 2^31 as floats, not probed), `ext-openssl`, `ext-json`, `ext-mbstring` (`mb_convert_encoding` for key order), `ext-pcre`, plus `ext-iconv` through opis/string. Composer has a `php-64bit` platform package for the second.
5. The latest `lcobucci/jwt` requires PHP `~8.4.0 || ~8.5.0` and `ext-sodium`, so it cannot run on 8.2; it was not probed further:

```text
$ composer show -a lcobucci/jwt | grep -E "^(versions|php |ext-)"
ext-openssl *
ext-sodium *
php ~8.4.0 || ~8.5.0
versions : 6.0.x-dev, 5.7.x-dev, 5.6.x-dev, 5.6.1, 5.6.0, 5.5.x-dev, 5.5.0, 5.4.
```

## Probe sensitivity

Scratch copies of the programs (outside the repository, with `spec/` symlinked), each with one deliberate defect, to confirm the probes can fail. None is committed.

- `q1_es256.php` and `jws.php` with `OPENSSL_ALGO_SHA256` replaced by `OPENSSL_ALGO_SHA384` (the round trip still passes because signing and verifying share the digest; the fixed RFC vector does not):

```text
$ php -d error_reporting=-1 <copy>/q1_es256.php | sed -n 2p
round trip true DER->raw->DER identical true
$ php -d error_reporting=-1 <copy>/q1b_rfc7515.php | sed -n 2,3p
A.3 signature bytes 64 verifies false tampered input false one bit flipped false
own signature with A.3 d: bytes 64 verifies false equals RFC bytes false
```

- `esnum.php` without the neighbour candidate (`foreach ([$D] as $c)`), run through `q4c_boundaries.php` and compared with V8:

```text
$ php -d error_reporting=-1 <copy>/q4c_boundaries.php $SCRATCH/pow_rb.txt | head -1 | cut -c1-60 ; node $SCRATCH/cmp.js $SCRATCH/pow_rb.txt
values 12586 | float(es_num(x)) === x for 12586 | significan
rows 12586 mismatches vs V8 Number::toString 92 [["0060000000000000","7.1202363472230444e-307","7.120236347223045e-307"],["8060000000000000","-7.1202363472230444e-307","-7.120236347223045e-307"],["0100000000000000","7.2911220195563975e-304","7.291122019556398e-304"]]
```

- `esnum.php` with the positional limit `<= 21` changed to `<= 20`, run through `q4_jcs_numbers.php`:

```text
$ php -d error_reporting=-1 <copy>/q4_jcs_numbers.php | tail -3 | cut -c1-160
Appendix B rows and literals: 32 rows, mismatches json_encode 14 var_export 25 strval 28 es_num 3
numbers.json: 10000 rows, mismatches json_encode 121 var_export 9679 strval 9990 es_num 18
random doubles 499843: float(es_num(x)) === x for 499843 | json_encode equals es_num for 497425 | var_export equals es_num for 109428
```

- `q2_thumbprint.php` with the EC member list `kty,crv,x,y` and no `ksort` (the same wrong value as the TypeScript record's reordered copy):

```text
$ php -d error_reporting=-1 <copy>/q2_thumbprint.php | sed -n 1p
holder d-xv9KenJkELSjvoc5fR3q9B_fgPPqjTn92vi0UQfKI == expected: false | kid/alg/use ignored: false | extra member ignored: false
```

- `strict.php` comparing the raw key token instead of the decoded key, and `strict.php` without the `preg_match_all` failure check:

```text
$ php -d error_reporting=-1 <copy>/q3c_vectors.php | tail -1    # key compared as the raw token
strict: 33 of 36 agree with expect; disagree: duplicate-key-escaped-form, unknown-core-field-case-variant, unknown-core-field
$ php -d error_reporting=-1 <copy>/q3e_scale.php | sed -n 3p    # scanner without the preg_match_all failure check
one 4 MiB string                    4194312 bytes  json_decode   10.3 ms  scan     4.3 ms  peak +  3.2 MB  ok preg: Backtrack limit exhausted
```

## Decision table

| Primitive | Chosen | Evidence |
|---|---|---|
| ES256 sign and verify | Builtin: `ext-openssl` `openssl_sign` and `openssl_verify` with `OPENSSL_ALGO_SHA256`; accept only a result `=== 1` | q1: A.3 and the Appendix C fixture verify; 5000 of 5000 round trips; `openssl_verify` returns 1, 0, -1 or `false` and `-1` is truthy |
| DER to JWS `r\|\|s` and back | In-house, 12 lines, no package | q1: 64 bytes for 5000 of 5000, DER identical after the round trip, 32 to 56 of 5000 signatures needed the padding branch; php-jwt and phpseclib add dependencies and still accept non-canonical signatures and unchecked headers (q1e) |
| JWK to an OpenSSL key | In-house PEM: SPKI for the public key, SEC1 for the private key; not `openssl_pkey_new(['ec' => ...])` | q1b: PEM works on 8.2.34 and 8.5.11; `openssl_pkey_new` with `x`, `y` returns a random private key on 8.2.34; q1c: off-curve points rejected |
| EC JWK export | Builtin: `openssl_pkey_get_details`, then left-pad `x`, `y` (and `d`) to 32 bytes | q2b: 156 of 20000 keys exported a 31-byte coordinate; the padded thumbprint equals Node's |
| base64url | Builtin: `base64_encode`/`base64_decode(strict)` plus `strtr`, with a guard: alphabet check and re-encode equality | q1d: strict decode accepts padding, whitespace, non-zero trailing bits; the guard rejects them and accepts the A.3 signature |
| JWK thumbprint (RFC 7638) | Builtin: `json_encode`, `hash('sha256')`, base64url; check required members first | q2: RFC 7638 3.1, RFC 8037 A.3 and `holder_jkt` reproduced; a missing member gives a warning and a wrong value |
| UTF-8, surrogates, syntax, nesting depth | Builtin: `json_decode($t, assoc, 17, JSON_THROW_ON_ERROR)`, depth 17 for a limit of 16 | q3: error 5 for five invalid sequences, error 10 for lone surrogates, BOM and trailing data are syntax errors; q3b: `$depth` is containers + 1 and the depth vectors agree at 17 |
| Duplicate keys, integer range, non-finite numbers | In-house token scan (13 lines) after `json_decode`; fail closed on a PCRE error | q3c: 34 of 36 vectors (36 of 36 with the schema, q5c); `json_decode` alone 24; `seld/jsonlint` clamps big integers and accepts invalid UTF-8 (q3d) |
| JCS number text | In-house `es_num` (15 lines): shortest digits from `sprintf('%e')` with a neighbour check, laid out per ECMA-262; not `json_encode`, `var_export` or `strval` | q4: 0 mismatches on 32 rows and 10000 rows; equal to V8 on 499,843 random and 12,586 boundary doubles; `json_encode` mismatched 121 of 10000 and changes with `serialize_precision` (q4g) |
| JCS strings | Builtin: `json_encode` with `JSON_UNESCAPED_SLASHES \| JSON_UNESCAPED_UNICODE \| JSON_UNESCAPED_LINE_TERMINATORS \| JSON_THROW_ON_ERROR` | q4e: equal to `JSON.stringify` for 1,112,064 of 1,112,064 scalar values |
| JCS key order | Builtin: `mb_convert_encoding(..., 'UTF-16BE', 'UTF-8')` and `strcmp` | q4b: RFC 8785 3.2.3 order; UTF-8 byte order reverses Dalet and emoji |
| JCS document | In-house writer over a tree that keeps `{}` and `[]` apart (object-mode `json_decode` in the probe) | q4b: 6 of 6 RFC pairs; the assoc route fails 3 of 6; q4d guards; the packages fail the 10000 numbers (q4f) |
| JSON Schema 2020-12 validation | Dependency: `opis/json-schema` 2.6.0 (with `opis/string` 2.1.0 and `opis/uri` 1.1.0) | q5: the schema as published, offline, one `const` error on the fixture; q5c: 36 of 36 vectors with `strict_decode`; justinrainbow throws on the `urn:uuid:` `$id` and is documented to 2019-09 |
| `format: "uri"` and anchored patterns | opis's checker, plus an SDK check for a trailing newline | q5b: opis differs from RFC 3986 on 1 of 20 inputs (trailing newline); justinrainbow on 4 and also accepts a newline after `$` in patterns |
| PHP floor | 8.2 (`php >=8.2`), tested on the floor and the newest | q6: identical output on 8.2.34 and 8.5.11 for every chosen primitive; poly-cite CI uses 8.2 only; 8.2 security support ends 2026-12-31 |

## Dependencies named for the vet step

Chosen:

| Package | Version | License | Published (lock) | Requires |
|---|---|---|---|---|
| `opis/json-schema` | 2.6.0 | Apache-2.0 | 2025-10-17 | php `^7.4 \|\| ^8.0`, `ext-json`, `opis/string` ^2.1, `opis/uri` ^1.0 |
| `opis/string` | 2.1.0 | Apache-2.0 | 2025-10-17 | php, `ext-json`, `ext-iconv` |
| `opis/uri` | 1.1.0 | Apache-2.0 | 2021-05-22 | php, `opis/string` ^2.0 |

Probed and not chosen (a chosen alternative would put them back on this list):

| Package | Version | License | Direct requirements | Why not |
|---|---|---|---|---|
| `justinrainbow/json-schema` | 6.13.1 | MIT | `marc-mabe/php-enum` v4.7.2 (BSD-3-Clause); `ext-filter`, `ext-json`, `ext-reflection` | q5: urn `$id` fails, 2019-09 ceiling, `2.0` is not an integer, weak `uri`, newline after `$` |
| `firebase/php-jwt` | v7.2.1 | BSD-3-Clause | none | q1e: accepts unknown `crit`, any `typ`, non-canonical signature; global `JWT::$timestamp` |
| `phpseclib/phpseclib` | 3.0.57 | MIT | `paragonie/constant_time_encoding` v3.1.3, `paragonie/random_compat` v9.99.100 | q1e: about 3.5 times slower than `ext-openssl`, non-canonical signature accepted |
| `seld/jsonlint` | 1.12.1 | MIT | none | q3d: clamps big integers, accepts invalid UTF-8 and lone surrogates |
| `root23/php-json-canonicalization` | 1.0.1 | none declared | none | q4f: 9941 of 10000 numbers wrong |
| `mmccook/php-json-canonicalization-scheme` | 1.0.0 | MIT | none | q4f: 9941 of 10000 numbers wrong |
| `truschery/kanon` | v1.0.1 | MIT | none | q4f: 113 of 10000 numbers wrong, NaN to `null` |

Source references from `composer.lock` (the first 12 characters of the git commit): `opis/json-schema` 8458763e0dd0, `opis/string` 3e4d2aaff518, `opis/uri` 0f3ca49ab1a5, `justinrainbow/json-schema` e54aacc4c065, `marc-mabe/php-enum` bb426fcdd65c, `firebase/php-jwt` 0501f5729b9e, `phpseclib/phpseclib` d17e0ddaeaf6, `paragonie/constant_time_encoding` d5b01a39b341, `paragonie/random_compat` 996434e5492c, `seld/jsonlint` 9a90eb5d32d5, `root23/php-json-canonicalization` be888e03a171, `mmccook/php-json-canonicalization-scheme` cd6d3e7645a2, `truschery/kanon` abd8fbd3ca39. Each was installed with `composer require --no-scripts --no-plugins` (commands in "How to run"). The next two blocks are reformatted output of `composer show` and `composer check-platform-reqs` (8.5.11) per scratch directory, and of a throwaway script over each `composer.lock`; `composer check-platform-reqs` also passed on 8.2.34 for every directory (`composer82` below):

```text
== opis: composer.json {"require":{"opis/json-schema":"2.6.0"}}
   opis/json-schema 2.6.0
   opis/string 2.1.0
   opis/uri 1.1.0
   platform: ext-iconv 8.5.11   success 
   platform: ext-json  8.5.11   success 
   platform: php       8.5.11   success 
== jr: composer.json {"require":{"justinrainbow/json-schema":"6.13.1"}}
   justinrainbow/json-schema 6.13.1
   marc-mabe/php-enum 4.7.2
   platform: ext-filter     8.5.11   success 
   platform: ext-json       8.5.11   success 
   platform: ext-reflection 8.5.11   success 
   platform: php            8.5.11   success 
== jwt: composer.json {"require":{"firebase/php-jwt":"v7.2.1"}}
   firebase/php-jwt 7.2.1
   platform: php 8.5.11   success 
== psl: composer.json {"require":{"phpseclib/phpseclib":"3.0.57"}}
   paragonie/constant_time_encoding 3.1.3
   paragonie/random_compat 9.99.100
   phpseclib/phpseclib 3.0.57
   platform: php 8.5.11   success 
== lint: composer.json {"require":{"seld/jsonlint":"1.12.1"}}
   seld/jsonlint 1.12.1
   platform: php 8.5.11   success 
== jcs1: composer.json {"require":{"root23/php-json-canonicalization":"1.0.1"}}
   root23/php-json-canonicalization 1.0.1
   platform: php 8.5.11   success 
== jcs2: composer.json {"require":{"mmccook/php-json-canonicalization-scheme":"1.0.0"}}
   mmccook/php-json-canonicalization-scheme 1.0.0
   platform: php 8.5.11   success 
== jcs3: composer.json {"require":{"truschery/kanon":"v1.0.1"}}
   truschery/kanon 1.0.1
   platform: php 8.5.11   success 
```

```text
opis  opis/json-schema                             2.6.0      8458763e0dd0 2025-10-17 Apache-2.0 php:^7.4 || ^8.0 ext:ext-json
opis  opis/string                                  2.1.0      3e4d2aaff518 2025-10-17 Apache-2.0 php:^7.4 || ^8.0 ext:ext-iconv,ext-json
opis  opis/uri                                     1.1.0      0f3ca49ab1a5 2021-05-22 Apache-2.0 php:^7.4 || ^8.0 ext:-
jr    justinrainbow/json-schema                    6.13.1     e54aacc4c065 2026-09-30 MIT php:^7.2 || ^8.0 ext:ext-filter,ext-json
jr    marc-mabe/php-enum                           v4.7.2     bb426fcdd65c 2025-09-14 BSD-3-Clause php:^7.1 | ^8.0 ext:ext-reflection
jwt   firebase/php-jwt                             v7.2.1     0501f5729b9e 2026-09-28 BSD-3-Clause php:^8.0 ext:-
psl   paragonie/constant_time_encoding             v3.1.3     d5b01a39b341 2025-09-24 MIT php:^8 ext:-
psl   paragonie/random_compat                      v9.99.100  996434e5492c 2020-10-15 MIT php:>= 7 ext:-
psl   phpseclib/phpseclib                          3.0.57     d17e0ddaeaf6 2026-08-26 MIT php:>=5.6.1 ext:-
lint  seld/jsonlint                                1.12.1     9a90eb5d32d5 2026-06-12 MIT php:^5.3 || ^7.0 || ^8.0 ext:-
jcs1  root23/php-json-canonicalization             1.0.1      be888e03a171 2023-09-27 - php:>=8.0 ext:-
jcs2  mmccook/php-json-canonicalization-scheme     1.0.0      cd6d3e7645a2 2023-08-07 MIT php:^8.1 ext:-
jcs3  truschery/kanon                              v1.0.1     abd8fbd3ca39 2026-03-12 MIT php:^8.2 ext:-
```

```text
$ composer check-platform-reqs    # run as php@8.2 composer, in each scratch directory
== opis
   platform: ext-iconv 8.2.34   success 
   platform: ext-json  8.2.34   success 
   platform: php       8.2.34   success 
== jr
   platform: ext-filter     8.2.34   success 
   platform: ext-json       8.2.34   success 
   platform: ext-reflection 8.2.34   success 
   platform: php            8.2.34   success 
== jwt
   platform: php 8.2.34   success 
== psl
   platform: php 8.2.34   success 
== lint
   platform: php 8.2.34   success 
== jcs1
   platform: php 8.2.34   success 
== jcs2
   platform: php 8.2.34   success 
== jcs3
   platform: php 8.2.34   success 
```

Dev tooling for the SDK itself (a test runner, a linter, a formatter) was not probed.

## Open design questions

1. Parser architecture. The strict path here is two passes: `json_decode` (syntax, UTF-8, surrogates, depth) and a regex scan of the same bytes (duplicates, integer text, overflow). The scan assumes `json_decode` already accepted the text, and a second parser over the same input can disagree with the first. The alternative is one in-house parser that builds the tree itself, which also removes the object-versus-assoc problem (Q3 finding 9) and the `$depth` off-by-one, at the cost of speed and code. Which one?
2. Decoded data model. Opis needs `stdClass` objects (assoc arrays fail `type`, q5); canonicalization needs `{}` and `[]` kept apart; object mode rejects a key beginning with `\u0000`. Does the SDK use `stdClass`, assoc arrays with a marker, or its own types, and is a key beginning with NUL rejected as invalid input?
3. Where integer-range checking lives. A PHP `int` above 2^53 is exact in PHP and not in other languages. The scan rejects integer literals above 2^53-1 anywhere (also in `extensions`); the spec limits core integer fields and says nothing about numbers inside `extensions`. Should those be rejected, kept exact, or converted to float for `object_digest`? The vectors `integer-overflow-*` expect reject for `extensions.n`.
4. The floor. `>=8.2` matches poly-cite and mise pins 8.5.11, but 8.2 is in security-only support until 2026-12-31. Raise the floor to 8.3, or keep 8.2 and run a two-version matrix (floor and newest)? The `openssl_pkey_new` difference shows a single-version CI misses real defects.
   Settled: the floor is 8.3, with CI on the floor and the newest pinned release; [deps-php.md](../deps-php.md) pins accordingly.
5. `format: "uri"` assertion. opis checks RFC 3986 syntax; PHP gives no builtin that does. The SDK needs its own trailing-newline check (and decides whether a relative reference or an empty string is allowed). Does `format` stay an assertion or become an annotation plus SDK checks on the fields that matter?
6. Field-rule `schema` objects (spec: restricted keyword set, finite evaluation budgets). Reuse opis behind a keyword allowlist walk, or write an in-house evaluator for the 23 keywords the spec lists for field rules? Opis offers no evaluation budget; this was not probed.
7. Float formatting inputs. `es_num` takes a PHP `float`; the input may carry `1.0` and `1` for the same value (both print `1`). Is it acceptable that `object_digest` is insensitive to that spelling, as it is in the other two SDKs?
8. Extension footprint. `ext-mbstring` is used for UTF-16BE key order only. A userland UTF-8 to UTF-16 comparison would remove it; opis already needs `ext-iconv`. Is `ext-mbstring` an acceptable requirement?
9. Error hygiene. `openssl_*` calls push onto a per-process error queue that must be drained to avoid stale text, and the text differs between PHP versions; the SDK should map failures to its own codes and never surface or match OpenSSL text.

## Not probed

- Signature malleability (an ECDSA `s` and `n - s` both verify) and constant-time behavior of `openssl_verify` and of `hash_equals` use in the SDK.
- `Ed25519` through `ext-sodium` or `ext-openssl` (the `sodium` extension is loaded; no signature was made or verified) and RSA.
- PHP 8.3 and 8.4 (only the floor 8.2.34 and 8.5.11 were run), 32-bit PHP, ZTS builds, Linux, Windows and musl (Alpine) builds, other OpenSSL major versions (both builds here use OpenSSL 3.6.4), other `php.ini` settings such as `disable_functions` (which could remove `ini_set` or `openssl_*`), `open_basedir`, a different `pcre.jit`.
- Performance and memory beyond q1e and q3e: no benchmark of `es_num` and no profile of opis on large instances.
- Other schema libraries (`swaggest/json-schema` was not run; `web-token/jwt-library` and `lcobucci/jwt` were only read from `composer show -a`), supply-chain review of the named packages (the vet step), and Composer lock or integrity checks beyond the commit references above.
- A test runner, linter and formatter for the PHP package, and the Composer `scripts` the Makefile calls.
