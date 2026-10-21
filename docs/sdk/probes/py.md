# Python SDK primitive probes

Probe record, 2026-10-16. Purpose: choose the primitives for the Python core SDK before anything is pinned. Facts come first: each one names the program that produced it and the observed output is pasted verbatim. A dependency is chosen only where the standard library failed its probe. Where a probe contradicted what was expected, the contradiction is recorded in the section's "Departures" list. The decision table is at the end.

## Environment

- Interpreter: CPython 3.11.16, `3.11.16 (main, Sep  1 2026, 14:08:22) [Clang 22.1.3 ]` on macOS 15.6.1 arm64. It is the build behind the `python = "3.11"` pin in `mise.toml` and was called by its versioned path, not through the mise shim.
- Isolation: every program ran as `python -I` (isolated mode: `PYTHON*` variables and the user site directory are ignored and the script directory is not put on `sys.path`) from a virtual environment created outside the repository. Nothing was installed outside scratch virtual environments. The repository gained no manifest, lockfile or virtual environment; only `docs/sdk/probes/py/` and this file.
- Main virtual environment, `pip list` after `pip install cryptography jsonschema referencing rfc8785`:

```
Package                   Version
------------------------- --------
attrs                     26.1.0
cffi                      2.1.1
cryptography              50.0.2
jsonschema                4.26.0
jsonschema-specifications 2025.9.1
pip                       24.0
pycparser                 3.11
referencing               0.37.0
rfc8785                   0.1.4
rpds-py                   2026.9.1
setuptools                79.0.1
typing_extensions         4.16.0
```

- Two further scratch virtual environments. `venv-fmt` is the main set plus `rfc3986-validator`, used only for the format-checker question (Q5). `venv-deps` holds only pip 24.0 and setuptools 79.0.1 and is used for the dry-run dependency counts (Q1). `ecdsa` 0.19.2 was not installed: its dependency count came from `pip install --dry-run --report` and its README from the downloaded wheel.
- Licenses as declared in package metadata (`importlib.metadata`, main venv):

```
attrs                      26.1.0       license=MIT                                          classifiers=[]
cffi                       2.1.1        license=MIT-0                                        classifiers=[]
cryptography               50.0.2       license=Apache-2.0 OR BSD-3-Clause                   classifiers=[]
jsonschema                 4.26.0       license=MIT                                          classifiers=[]
jsonschema-specifications  2025.9.1     license=MIT                                          classifiers=[]
pycparser                  3.11         license=BSD-3-Clause                                 classifiers=[]
referencing                0.37.0       license=MIT                                          classifiers=[]
rfc8785                    0.1.4        license=-                                            classifiers=['Apache Software License']
rpds-py                    2026.9.1     license=MIT                                          classifiers=[]
typing_extensions          4.16.0       license=PSF-2.0                                      classifiers=[]
```

- `rfc3986-validator` in `venv-fmt` (`importlib.metadata`):

```
rfc3986-validator 0.1.1 license= MIT license ['MIT License'] Requires-Dist: None
```

- Network use: pip installs and downloads, RFC text from rfc-editor.org (read only), PyPI metadata (read only). The Q5 program blocks sockets in-process before it touches the schema.
- Downloaded artifacts (pact-python wheels, the `pact` sdist, the `ecdsa` wheel) went into separate scratch directories; the programs read member names with `zipfile` and `tarfile` and extract nothing. Fetching the `pact` 1.12.0 sdist with `pip download` made pip prepare its metadata, which runs that sdist's build backend in pip's isolated build environment. No other sdist was fetched.

Test vectors come from the RFC text and from the repository fixtures: RFC 7515 Appendix A.3, RFC 7638 section 3.1, RFC 8037 Appendix A.3, RFC 8785 sections 3.2.2 to 3.2.4 and Appendix B Table 1, `spec/v1.0/fixtures/keys/*.jwk.json`, `spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws`, `spec/v1.0/schemas/pact.schema.json`.

Programs find repository files from their own location (`Path(__file__).resolve().parents[4]`), so they run from any directory:

```
$VENV/bin/python -I $REPO/docs/sdk/probes/py/q1_es256.py
```

| Question | Program | Lines | Venv |
|---|---|---|---|
| Q1 ES256 | [q1_es256.py](py/q1_es256.py), [q1b_fixture.py](py/q1b_fixture.py), [q1c_depcount.py](py/q1c_depcount.py), [q1_q5_stdlib.py](py/q1_q5_stdlib.py) | 20, 19, 9, 12 | main; q1c in `venv-deps` |
| Q2 thumbprint | [q2_thumbprint.py](py/q2_thumbprint.py) | 20 | main |
| Q3 strict parse | [q3_strict_json.py](py/q3_strict_json.py) | 19 | main |
| Q4 JCS | [q4_jcs_numbers.py](py/q4_jcs_numbers.py), [q4b_jcs_document.py](py/q4b_jcs_document.py), [q4c_jcs_domain.py](py/q4c_jcs_domain.py) | 16, 19, 17 | main |
| Q5 schema | [q5_schema.py](py/q5_schema.py), [q1_q5_stdlib.py](py/q1_q5_stdlib.py) | 20, 12 | main and `venv-fmt` |
| Q6 import name | [q6_import_name.py](py/q6_import_name.py) | 11 | main |

The task asked for one program per question. Q1, Q4 and Q5 each needed more than 20 lines to cover their sub-questions, so they use several programs of 20 lines or fewer, each self-contained.

## Q1. ES256 over P-256 (RFC 7515)

### q1_es256.py, main venv

```
round trip True raw lens {64} DER lens [69, 70, 71, 72]
tampered msg False 63 bytes False 65 bytes False
RFC 7515 A.3 verifies True sig bytes 64 tampered input False
```

### q1b_fixture.py, main venv

```
header b'{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}' sig bytes 64 verifies True other payload False
off-curve point rejected: Invalid EC key. Point is not on the curve specified.
```

### q1_q5_stdlib.py, main venv

```
python 3.11.16 | openssl OpenSSL 3.5.8 25 Aug 2026
stdlib modules matching: ['_signal', 'signal']
hashlib names/attrs matching: []
ssl attrs matching: ['HAS_ECDH', 'OP_SINGLE_ECDH_USE']
ssl.SSLContext attrs matching: ['set_ecdh_curve']
urlsplit('not a uri') -> scheme='' netloc='', no exception
urlsplit('http://a b/c d') -> scheme='http' netloc='a b', no exception
urlsplit('urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60') -> scheme='urn' netloc='', no exception
urlsplit('https://trust.example/issuers/finance') -> scheme='https' netloc='trust.example', no exception
```

### q1c_depcount.py, `venv-deps`

Run as `q1c_depcount.py $VENV_DEPS/bin/python cryptography ecdsa jsonschema rfc8785`.

```
cryptography: 2 transitive deps -> ['cffi 2.1.1', 'pycparser 3.11']
   artifacts: ['cryptography-50.0.2-cp311-abi3-macosx_11_0_arm64.whl', 'cffi-2.1.1-cp311-cp311-macosx_11_0_arm64.whl', 'pycparser-3.11-py3-none-any.whl']
ecdsa: 1 transitive deps -> ['six 1.17.0']
   artifacts: ['ecdsa-0.19.2-py2.py3-none-any.whl', 'six-1.17.0-py2.py3-none-any.whl']
jsonschema: 5 transitive deps -> ['attrs 26.1.0', 'jsonschema-specifications 2025.9.1', 'referencing 0.37.0', 'rpds-py 2026.9.1', 'typing_extensions 4.16.0']
   artifacts: ['jsonschema-4.26.0-py3-none-any.whl', 'attrs-26.1.0-py3-none-any.whl', 'jsonschema_specifications-2025.9.1-py3-none-any.whl', 'referencing-0.37.0-py3-none-any.whl', 'rpds_py-2026.9.1-cp311-cp311-macosx_11_0_arm64.whl', 'typing_extensions-4.16.0-py3-none-any.whl']
rfc8785: 0 transitive deps -> []
   artifacts: ['rfc8785-0.1.4-py3-none-any.whl']
```

### ecdsa 0.19.2 README, read from its wheel metadata

Shell command, not a committed program: `zipfile` over the downloaded wheel, printing the `## Security` section of `METADATA`.

```
## Security

This library was not designed with security in mind. If you are processing
data that needs to be protected we suggest you use a quality wrapper around
OpenSSL. [pyca/cryptography](https://cryptography.io) is one example of such
a wrapper. The primary use-case of this library is as a portable library for
interoperability testing and as a teaching tool.

**This library does not protect against side-channel attacks.**
```

### Facts

- `cryptography` 50.0.2, `private_key.sign(m, ec.ECDSA(hashes.SHA256()))`, returns DER. Over 5000 signatures the DER length was 69, 70, 71 or 72 bytes (q1_es256, "DER lens"). DER INTEGERs are minimal-length, so the length varies; it is not usable as a JWS signature length.
- `decode_dss_signature` returned `(r, s)`. `r.to_bytes(32, "big") + s.to_bytes(32, "big")` was 64 bytes for all 5000 signatures (`raw lens {64}`). Splitting that value in halves, `encode_dss_signature` and `verify` succeeded for all 5000 (`round trip True`).
- A modified message was rejected (`tampered msg False`). The 63-byte and 65-byte inputs were rejected by the probe's own `len(sig) != 64` test, which runs before `cryptography` is called; the library never sees a length other than 64.
- The RFC 7515 Appendix A.3 vector verified (`RFC 7515 A.3 verifies True`, signature 64 bytes) and failed when the signing input gained one byte (`tampered input False`). The probe verifies the RFC signature; it does not reproduce it by signing.
- The compact JWS in `spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws` verified under `spec/v1.0/fixtures/keys/issuer.jwk.json` (`verifies True`); the same signature failed over another payload (`other payload False`). Its header decodes to `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`.
- Building a public key from a JWK whose `y` does not belong to its `x` raised `ValueError: Invalid EC key. Point is not on the curve specified.` at construction time (q1b_fixture, last line).
- The Python 3.11.16 standard library has no ECDSA sign or verify. A name search over `sys.stdlib_module_names`, `hashlib`, `ssl` and `ssl.SSLContext` found only `signal`, `_signal` (substring match, unrelated) and the TLS key-agreement names `HAS_ECDH`, `OP_SINGLE_ECDH_USE`, `set_ecdh_curve` (q1_q5_stdlib). The interpreter's `ssl` reports OpenSSL 3.5.8; `cryptography`'s backend reports OpenSSL 4.0.3 (output below), a different library.
- Transitive dependency counts from `pip install --dry-run --report` on 3.11 / macOS arm64 (q1c_depcount): `cryptography` 2 (`cffi` 2.1.1, `pycparser` 3.11), `ecdsa` 1 (`six` 1.17.0), `jsonschema` 5, `rfc8785` 0. The `cryptography` wheel is a compiled `abi3` wheel and `cffi` is a compiled `cp311` wheel; `pycparser`, `ecdsa` and `six` are pure-Python wheels.
- The `ecdsa` README states: "This library was not designed with security in mind", recommends `pyca/cryptography` as a wrapper around OpenSSL, and states "This library does not protect against side-channel attacks."

```
$ python -I -c "from cryptography.hazmat.backends.openssl.backend import backend; print(backend.openssl_version_text())"
OpenSSL 4.0.3 29 Sep 2026
```

### Departures from the expectation

- The task expected a dependency-count argument against the pure-Python `ecdsa`. The count does not favour `cryptography`: 2 transitive dependencies against 1, and compiled wheels against pure-Python ones. The case for `cryptography` rests on the stdlib having no ECDSA and on the `ecdsa` README's own security statement, not on the count.

## Q2. JWK and RFC 7638 thumbprint

### q2_thumbprint.py, main venv

```
holder xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M == expected: True
kid/alg/use ignored: True | extra member ignored: True
RFC 7638 3.1 NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs == expected: True
  adversarial.jwk.json B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU
  ed25519.jwk.json kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
  holder.jwk.json xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M
  issuer.jwk.json AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE
  learning-controller.jwk.json yiaHWTOH-NAS43bw6yPHO8YTK_T9cLz9jZaCu3qOg_k
  reputation-service.jwk.json BcYkeRReg8Py6HmUFJw6240ruOKnvInXb5rRtK6Z9xQ
  validator.jwk.json uhdbksqePVMcTx2Fvr5RY78RjuSE2bd16nNAkdfZ36I
missing required member y -> KeyError 'y'
RFC 8037 A.3 Ed25519 thumbprint matches: True
```

### Facts

- The thumbprint of `spec/v1.0/fixtures/keys/holder.jwk.json` is `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M`, equal to the expected value (`== expected: True`).
- The RFC 7638 section 3.1 example (an RSA key) reproduces `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs`. The RFC 8037 Appendix A.3 Ed25519 thumbprint `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k` reproduces for `ed25519.jwk.json`.
- Members outside the required set did not change the result: `kid`, `alg`, `use` (`kid/alg/use ignored: True`) and an arbitrary extra member (`extra member ignored: True`).
- A JWK missing a required member raised `KeyError 'y'`. That is the program's own dictionary lookup, not library behavior.
- The implementation is stdlib only: `json.dumps(members, separators=(",", ":"), sort_keys=True, ensure_ascii=False)`, UTF-8, `hashlib.sha256`, `base64.urlsafe_b64encode` without padding, over the required members per `kty` (EC: `crv kty x y`; RSA: `e kty n`; OKP: `crv kty x`). `sort_keys` orders by code point, which equals the RFC 7638 order for these ASCII member names.
- The thumbprints of the other fixtures are computed values with no independent reference in this probe: adversarial, issuer, learning-controller, reputation-service, validator (listed in the output).

## Q3. Strict JSON parse

### q3_strict_json.py, main venv

Columns: input length, first 30 characters, mode (`default` is plain `json.loads`; `strict` adds `object_pairs_hook`, `parse_constant`, `parse_float`, `parse_int` and a post-parse `json.dumps(..., ensure_ascii=False).encode("utf-8")`), result.

```
   13 '{"a":1,"a":2}'                    default  {'a': 2}
   13 '{"a":1,"a":2}'                    strict   REJECT ValueError: duplicate key
   18 '{"a":1,"\\u0061":2}'              default  {'a': 2}
   18 '{"a":1,"\\u0061":2}'              strict   REJECT ValueError: duplicate key
    5 '[NaN]'                            default  [nan]
    5 '[NaN]'                            strict   REJECT ValueError: rejected NaN
   10 '[Infinity]'                       default  [inf]
   10 '[Infinity]'                       strict   REJECT ValueError: rejected Infinity
   11 '[-Infinity]'                      default  [-inf]
   11 '[-Infinity]'                      strict   REJECT ValueError: rejected -Infinity
    7 '[1e999]'                          default  [inf]
    7 '[1e999]'                          strict   REJECT ValueError: rejected 1e999
   10 '["\\ud800"]'                      default  ['\ud800']
   10 '["\\ud800"]'                      strict   REJECT UnicodeEncodeError: 'utf-8' codec can't encode character '\u
   16 '["\\ud83d\\ude00"]'               default  ['😀']
   16 '["\\ud83d\\ude00"]'               strict   ['😀']
   18 '[9007199254740991]'               default  [9007199254740991]
   18 '[9007199254740991]'               strict   [9007199254740991]
   18 '[9007199254740993]'               default  [9007199254740993]
   18 '[9007199254740993]'               strict   REJECT ValueError: rejected int 90071992
   20 '[9007199254740993.0]'             default  [9007199254740992.0]
   20 '[9007199254740993.0]'             strict   [9007199254740992.0]
   36 '[0.1,333333333.33333329,5e-324'   default  [0.1, 333333333.3333333, 5e-324, 1e+22]
   36 '[0.1,333333333.33333329,5e-324'   strict   [0.1, 333333333.3333333, 5e-324, 1e+22]
 4303 '[10000000000000000000000000000'   default  REJECT ValueError: Exceeds the limit (4300 digits) for inte
 4303 '[10000000000000000000000000000'   strict   REJECT ValueError: rejected int 10000000
 4000 '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[['   default  REJECT RecursionError: maximum recursion depth exceeded while d
 4000 '[[[[[[[[[[[[[[[[[[[[[[[[[[[[[['   strict   REJECT RecursionError: maximum recursion depth exceeded while d
b'\xff'                  decode=REJECT UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in  | loads(bytes)=REJECT UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in 
b'\xc0\xaf'              decode=REJECT UnicodeDecodeError: 'utf-8' codec can't decode byte 0xc0 in  | loads(bytes)=REJECT UnicodeDecodeError: 'utf-8' codec can't decode byte 0xc0 in 
b'\xe2\x82'              decode=REJECT UnicodeDecodeError: 'utf-8' codec can't decode bytes in posi | loads(bytes)=REJECT UnicodeDecodeError: 'utf-8' codec can't decode bytes in posi
b'["\xed\xa0\x80"]'      decode=REJECT UnicodeDecodeError: 'utf-8' codec can't decode byte 0xed in  | loads(bytes)=['\ud800']
b'\xf4\x90\x80\x80'      decode=REJECT UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf4 in  | loads(bytes)=REJECT UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf4 in 
b'\xef\xbb\xbf{}'        decode='\ufeff{}' | loads(bytes)={}
b'\xff\xfe{\x00}\x00'    decode=REJECT UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in  | loads(bytes)={}
```

### Facts

- Duplicate keys: `json.loads` keeps the last value (`{'a': 2}`). `object_pairs_hook` receives all pairs; comparing `len(dict(pairs))` with `len(pairs)` rejected both `{"a":1,"a":2}` and `{"a":1,"\u0061":2}` (the escaped key is decoded before the hook runs).
- `NaN`, `Infinity`, `-Infinity`: accepted by default (`nan`, `inf`, `-inf`); `parse_constant` is called for each and rejected them.
- `1e999`: accepted by default as `inf`. `parse_constant` is not called for it; `parse_float` receives the text `1e999`, and rejecting `inf` there worked.
- Lone surrogate escape `"\ud800"`: accepted by default and returned as a one-character string holding U+D800. `json.loads` has no string hook; the strict mode detected it after parsing, because `json.dumps(v, ensure_ascii=False).encode("utf-8")` raised `UnicodeEncodeError`. The valid pair `"\ud83d\ude00"` parsed to the single character U+1F600 in both modes.
- Big integers: `9007199254740993` parses to the exact `int` 9007199254740993 by default. `parse_int` rejected it in strict mode and accepted `9007199254740991`. Python's default integer-string limit applies too: a 4301-digit integer raised `ValueError: Exceeds the limit (4300 digits) for integer string conversion`; the strict hook rejected it first, on its length.
- Floats: `9007199254740993.0` parses to `9007199254740992.0` without any error (nearest double). `333333333.33333329` parses to `333333333.3333333`; `5e-324` and `1e22` parse and print (`1e+22`). The `repr` round trip is covered at scale in Q4 (499844 doubles).
- 2000 levels of nested arrays raised `RecursionError` in both modes.
- `bytes.decode("utf-8")` is strict: it rejected `ff` (invalid start byte), the overlong `c0 af`, the truncated `e2 82`, the encoded surrogate `ed a0 80` and the out-of-range `f4 90 80 80`. It accepted the UTF-8 BOM `ef bb bf` and returned a string starting with U+FEFF.
- `json.loads(bytes)` is not equivalent to a strict UTF-8 decode. It returned `['\ud800']` for the bytes `["` `ed a0 80` `"]`, accepted the UTF-8 BOM (`{}`) and accepted UTF-16 input (`ff fe 7b 00 7d 00` gave `{}`).

### Departures from the expectation

- No check the task listed contradicted its expectation, but two behaviors it did not list matter: `json.loads(bytes)` accepts encoded surrogates and UTF-16, so the SDK must decode bytes itself with strict UTF-8 and pass a `str`; and `bytes.decode("utf-8")` passes a leading BOM through.

## Q4. JCS (RFC 8785)

### q4_jcs_numbers.py, main venv

Columns: IEEE 754 bits (or `literal`), the RFC string (`want`), `repr(float)`, the in-house formatter `es` (ECMA-262 7.1.12.1 over the digits of `repr`), `rfc8785.dumps`, then one verdict per implementation. The 24 finite rows of RFC 8785 Appendix B Table 1 come first; the 8 literals follow.

```
0000000000000000  want=0                          repr=0.0                        es=0                          rfc8785=0                          REPR-DIFF es-ok pkg-ok
8000000000000000  want=0                          repr=-0.0                       es=0                          rfc8785=0                          REPR-DIFF es-ok pkg-ok
0000000000000001  want=5e-324                     repr=5e-324                     es=5e-324                     rfc8785=5e-324                     repr-ok es-ok pkg-ok
8000000000000001  want=-5e-324                    repr=-5e-324                    es=-5e-324                    rfc8785=-5e-324                    repr-ok es-ok pkg-ok
7fefffffffffffff  want=1.7976931348623157e+308    repr=1.7976931348623157e+308    es=1.7976931348623157e+308    rfc8785=1.7976931348623157e+308    repr-ok es-ok pkg-ok
ffefffffffffffff  want=-1.7976931348623157e+308   repr=-1.7976931348623157e+308   es=-1.7976931348623157e+308   rfc8785=-1.7976931348623157e+308   repr-ok es-ok pkg-ok
4340000000000000  want=9007199254740992           repr=9007199254740992.0         es=9007199254740992           rfc8785=9007199254740992           REPR-DIFF es-ok pkg-ok
c340000000000000  want=-9007199254740992          repr=-9007199254740992.0        es=-9007199254740992          rfc8785=-9007199254740992          REPR-DIFF es-ok pkg-ok
4430000000000000  want=295147905179352830000      repr=2.9514790517935283e+20     es=295147905179352830000      rfc8785=295147905179352830000      REPR-DIFF es-ok pkg-ok
44b52d02c7e14af5  want=9.999999999999997e+22      repr=9.999999999999997e+22      es=9.999999999999997e+22      rfc8785=9.999999999999997e+22      repr-ok es-ok pkg-ok
44b52d02c7e14af6  want=1e+23                      repr=1e+23                      es=1e+23                      rfc8785=1e+23                      repr-ok es-ok pkg-ok
44b52d02c7e14af7  want=1.0000000000000001e+23     repr=1.0000000000000001e+23     es=1.0000000000000001e+23     rfc8785=1.0000000000000001e+23     repr-ok es-ok pkg-ok
444b1ae4d6e2ef4e  want=999999999999999700000      repr=9.999999999999997e+20      es=999999999999999700000      rfc8785=999999999999999700000      REPR-DIFF es-ok pkg-ok
444b1ae4d6e2ef4f  want=999999999999999900000      repr=9.999999999999999e+20      es=999999999999999900000      rfc8785=999999999999999900000      REPR-DIFF es-ok pkg-ok
444b1ae4d6e2ef50  want=1e+21                      repr=1e+21                      es=1e+21                      rfc8785=1e+21                      repr-ok es-ok pkg-ok
3eb0c6f7a0b5ed8c  want=9.999999999999997e-7       repr=9.999999999999997e-07      es=9.999999999999997e-7       rfc8785=9.999999999999997e-7       REPR-DIFF es-ok pkg-ok
3eb0c6f7a0b5ed8d  want=0.000001                   repr=1e-06                      es=0.000001                   rfc8785=0.000001                   REPR-DIFF es-ok pkg-ok
41b3de4355555553  want=333333333.3333332          repr=333333333.3333332          es=333333333.3333332          rfc8785=333333333.3333332          repr-ok es-ok pkg-ok
41b3de4355555554  want=333333333.33333325         repr=333333333.33333325         es=333333333.33333325         rfc8785=333333333.33333325         repr-ok es-ok pkg-ok
41b3de4355555555  want=333333333.3333333          repr=333333333.3333333          es=333333333.3333333          rfc8785=333333333.3333333          repr-ok es-ok pkg-ok
41b3de4355555556  want=333333333.3333334          repr=333333333.3333334          es=333333333.3333334          rfc8785=333333333.3333334          repr-ok es-ok pkg-ok
41b3de4355555557  want=333333333.33333343         repr=333333333.33333343         es=333333333.33333343         rfc8785=333333333.33333343         repr-ok es-ok pkg-ok
becbf647612f3696  want=-0.0000033333333333333333  repr=-3.3333333333333333e-06    es=-0.0000033333333333333333  rfc8785=-0.0000033333333333333333  REPR-DIFF es-ok pkg-ok
43143ff3c1cb0959  want=1424953923781206.2         repr=1424953923781206.2         es=1424953923781206.2         rfc8785=1424953923781206.2         repr-ok es-ok pkg-ok
literal           want=1e+21                      repr=1e+21                      es=1e+21                      rfc8785=1e+21                      repr-ok es-ok pkg-ok
literal           want=1e-7                       repr=1e-07                      es=1e-7                       rfc8785=1e-7                       REPR-DIFF es-ok pkg-ok
literal           want=0                          repr=-0.0                       es=0                          rfc8785=0                          REPR-DIFF es-ok pkg-ok
literal           want=4.5                        repr=4.5                        es=4.5                        rfc8785=4.5                        repr-ok es-ok pkg-ok
literal           want=1e+30                      repr=1e+30                      es=1e+30                      rfc8785=1e+30                      repr-ok es-ok pkg-ok
literal           want=1                          repr=1.0                        es=1                          rfc8785=1                          REPR-DIFF es-ok pkg-ok
literal           want=100                        repr=100.0                      es=100                        rfc8785=100                        REPR-DIFF es-ok pkg-ok
literal           want=10000000000000000          repr=1e+16                      es=10000000000000000          rfc8785=10000000000000000          REPR-DIFF es-ok pkg-ok
rows 32 repr mismatches 15 es mismatches 0 pkg mismatches 0
random doubles 499844 es==rfc8785 499844 float(es(x))==x 499844
```

### q4b_jcs_document.py, main venv

```
3.2.4 bytes equal: in-house True | rfc8785 True | json.dumps(sort_keys) True
3.2.3 order, UTF-16: ['Carriage Return', 'One', 'Control', 'Latin Small Letter O With Diaeresis', 'Euro Sign', 'Emoji: Grinning Face', 'Hebrew Letter Dalet With Dagesh'] 
          code point: ['Carriage Return', 'One', 'Control', 'Latin Small Letter O With Diaeresis', 'Euro Sign', 'Hebrew Letter Dalet With Dagesh', 'Emoji: Grinning Face']
sorting sample: in-house == rfc8785 True | rfc8785 order True
```

### q4c_jcs_domain.py, main venv

```
9007199254740991         in-house=b'9007199254740991'                rfc8785=b'9007199254740991'
9007199254740992         in-house=raises ValueError                  rfc8785=raises IntegerDomainError
-9007199254740991        in-house=b'-9007199254740991'               rfc8785=b'-9007199254740991'
-9007199254740992        in-house=raises ValueError                  rfc8785=raises IntegerDomainError
9007199254740992.0       in-house=b'9007199254740992'                rfc8785=b'9007199254740992'
inf                      in-house=raises ValueError                  rfc8785=raises FloatDomainError
nan                      in-house=raises ValueError                  rfc8785=raises FloatDomainError
'\ud800'                 in-house=raises UnicodeEncodeError          rfc8785=raises CanonicalizationError
{'\ud800': 1}            in-house=raises UnicodeEncodeError          rfc8785=raises UnicodeEncodeError
b'x'                     in-house=raises TypeError                   rfc8785=raises CanonicalizationError
{1: 2}                   in-house=raises AttributeError              rfc8785=raises CanonicalizationError
True                     in-house=b'true'                            rfc8785=b'true'
1.0                      in-house=b'1'                               rfc8785=b'1'
```

### V8 cross-check of the 8 literals

Shell command, not a committed program: `node -e 'for (const x of [1e21, 1e-7, -0, 4.5, 1e30, 1.0, 100.0, 1e16]) console.log(String(x).padEnd(20), JSON.stringify(x))'`

```
1e+21                1e+21
1e-7                 1e-7
0                    0
4.5                  4.5
1e+30                1e+30
1                    1
100                  100
10000000000000000    10000000000000000
```

### Facts

- `repr(float)` matched the RFC string in 17 of the 32 rows and differed in 15. It matched, among others, for `1e21` (`1e+21`), `4.5`, `1e30` (`1e+30`), `5e-324`, `1.7976931348623157e+308` and the `333333333.333...` rows. It differed for `1e-7` (`repr` gives `1e-07`, a two-digit exponent), `-0.0` (`-0.0`, RFC `0`), integer-valued floats (`1.0` against `1`, `100.0` against `100`, `9007199254740992.0` against `9007199254740992`), `1e16` (`repr` switches to exponent form at 1e16, ECMAScript at 1e21: `1e+16` against `10000000000000000`, and `2.9514790517935283e+20` against `295147905179352830000`), and small values (`repr` uses exponent form below 1e-4, ECMAScript positional down to 1e-6: `1e-06` against `0.000001`, `-3.3333333333333333e-06` against `-0.0000033333333333333333`).
- The in-house formatter `es` is 4 lines: it takes the shortest round-trip digits from `repr` and re-lays them out per ECMA-262 7.1.12.1 with `decimal.Decimal`. It had 0 mismatches against the 32 rows. The `rfc8785` 0.1.4 package also had 0 mismatches on the same rows.
- Over 499844 doubles (seed 0: random bit patterns without NaN and infinities, 100000 uniform values in plus or minus 1e9, 100000 integer-valued floats up to 2^53 in magnitude) `es(x)` equalled `rfc8785.dumps(x)` for all 499844, and `float(es(x)) == x` for all 499844.
- Document level (q4b): the stdlib-only `canon` (sorted keys by `key.encode("utf-16-be")`, strings by `json.dumps(ensure_ascii=False)`, numbers by `es`) produced exactly the 3.2.4 byte sequence of the RFC 8785 section 3.2.2 sample, as did `rfc8785`. It also matched `rfc8785` on the section 3.2.3 sorting sample, and its key order equals the order the RFC lists (Carriage Return, One, Control, Latin Small Letter O With Diaeresis, Euro Sign, Emoji, Hebrew Letter Dalet With Dagesh).
- `json.dumps(sort_keys=True)` produced the section 3.2.2 bytes too, because that sample has only ASCII keys and numbers that `repr` already prints in ECMAScript form. On the sorting sample it ordered the Hebrew letter (U+FB33) before the emoji (U+1F600), the reverse of the RFC order, because it sorts by code point and the RFC sorts by UTF-16 code unit.
- Domain (q4c), in-house `canon` with its `ValueError` guard against `rfc8785`: both accept 9007199254740991 and -9007199254740991 and reject 9007199254740992 and -9007199254740992 as `int`; both accept `float(2**53)` and print `9007199254740992`; both reject infinity and NaN, a lone surrogate in a value or in a key, `bytes`, and a non-string key; both print `true` for `True` and `1` for `1.0`. The two reject the same inputs; only the exception types differ (for example `IntegerDomainError` against `ValueError`).
- `rfc8785` 0.1.4 is one 254-line pure-Python module (`rfc8785/_impl.py`) with 0 transitive dependencies (q1c output) and the Apache Software License classifier (licenses block).

### Departures from the expectation

- The task cites RFC 8785 section 3.2.2.3 for the samples `1e21`, `1e-7`, `-0.0`, `4.5` and `1e30`. That section holds no sample table; it requires ECMA-262 7.1.12.1 and points to Appendix B. `4.5` and `1e+30` appear in the section 3.2.2 and 3.2.3 example, `1e+21` and `0` (for minus zero) in Appendix B, and no row or example of the RFC has the value `1e-7` (its neighbours in Appendix B are `9.999999999999997e-7` and `0.000001`). The expected strings for the 8 literals were therefore taken from ECMAScript itself and confirmed with Node 26.8.1 (V8), shown above; they are marked `literal` in the output.
- `repr(float)` does not match the samples, contrary to the premise of the question: 3 of the 5 named samples match (`1e21`, `4.5`, `1e30`), and `1e-7` and `-0.0` do not.

## Q5. JSON Schema validation

### q5_schema.py, main venv

```
formats the schema uses: ['uri'] | checkers available: ['date', 'email', 'idn-email', 'ipv4', 'ipv6', 'regex', 'uuid']
fixture as-is: ['const@/pact_version'] | without registry: RAISED _WrappedReferencingError
pact_version 0.1: [] | root oneOf valid: True
iss='not a uri' format on: [] | format off: []
iat=2**53: ['maximum@/iat']
iat=2.0 (float): []
```

### q5_schema.py, `venv-fmt` (adds `rfc3986-validator` 0.1.1)

```
formats the schema uses: ['uri'] | checkers available: ['date', 'email', 'idn-email', 'ipv4', 'ipv6', 'regex', 'uri', 'uri-reference', 'uuid']
fixture as-is: ['const@/pact_version'] | without registry: RAISED _WrappedReferencingError
pact_version 0.1: [] | root oneOf valid: True
iss='not a uri' format on: ['format@/iss'] | format off: []
iat=2**53: ['format@/iss', 'maximum@/iat']
iat=2.0 (float): ['format@/iss']
```

Schema facts, shell command over `spec/v1.0/schemas/pact.schema.json`:

```
ref targets not starting with #: 0
$anchor/$dynamicRef/$dynamicAnchor/$recursiveRef: 0
"format" members:  65 "format":"uri"
local $ref members: 40
$id: "$id": "urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60"
```

### Facts

- `Draft202012Validator.check_schema(schema)` accepted `pact.schema.json`. The schema is Draft 2020-12 (`$schema`), has `$id` `urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60`, 40 `$ref` members that all point to `#/$defs/...`, and no `$anchor`, `$dynamicRef`, `$dynamicAnchor` or `$recursiveRef`.
- Offline validation worked with `Registry().with_resource(schema["$id"], Resource.from_contents(schema))` and a wrapper schema `{"$ref": "<$id>#/$defs/Evidence"}`, with `socket.socket`, `socket.create_connection` and `socket.getaddrinfo` replaced by functions that raise. The same wrapper with an empty `Registry()` raised `_WrappedReferencingError`, a private jsonschema class.
- The Appendix C fixture payload, decoded, failed `Evidence` with exactly one error, `const` at `/pact_version` (`"0.2"` against `"0.1"`). With `pact_version` set to `"0.1"` it had no errors, and the root schema (`oneOf` over 16 definitions) reported it valid.
- `Draft202012Validator.FORMAT_CHECKER` in the main venv holds `date`, `email`, `idn-email`, `ipv4`, `ipv6`, `regex`, `uuid`. The schema uses one format, `uri`, in 65 members. `uri` is not in the main venv's checker, so `"iss": "not a uri"` produced no error with the format checker enabled (`fmt on: []`).
- With `rfc3986-validator` 0.1.1 installed (`venv-fmt`) the checker gained `uri` and `uri-reference`, and the same input produced `format@/iss`. Without a `format_checker` argument no format is asserted in either venv (`format off: []`).
- jsonschema's `_format.py` (4.26.0) takes `uri` from `rfc3987` if importable, otherwise from `rfc3986_validator`. `rfc3987` 1.3.8 declares GNU GPLv3+ on PyPI; `rfc3986-validator` 0.1.1 declares MIT and has no requirements. `rfc3987-syntax` 1.1.0 (requires `lark`) is used by jsonschema for the `iri` formats, not `uri`.
- The standard library does not validate URIs: `urllib.parse.urlsplit("not a uri")` returned scheme `''` and `urlsplit("http://a b/c d")` returned scheme `http` and netloc `a b`, both without an exception (q1_q5_stdlib). The same program found no standard-library module matching `schema` or `validat`.
- Integer limits: `iat = 2**53` produced `maximum@/iat`. `iat = 2.0` (a Python `float`) produced no error: Draft 2020-12 treats `2.0` as an integer for `type: integer`.
- Dependency footprint (q1c output): `jsonschema` 4.26.0 requires `attrs`, `jsonschema-specifications`, `referencing` and `rpds-py` (a compiled `cp311` wheel on this platform); `referencing` requires `typing-extensions` for Python below 3.13 (package metadata, `importlib.metadata.requires`).

### Departures from the expectation

- The task expected format checking to be a matter of which formats need extra packages. For this schema it is one format, `uri`, and without the extra package the keyword is ignored silently rather than failing.

## Q6. Import name

### q6_import_name.py, main venv

Run with the four downloaded artifacts as arguments (pact-python 2.3.3, 3.4.1 and 4.0.0 wheels, `pact` 1.12.0 sdist).

```
'hop_top_pact' importable here: False
'pact' importable here: False
pact_python-2.3.3-cp311-cp311-macosx_11_0_arm64.whl -> top-level packages: ['pact']
pact_python-3.4.1-py3-none-any.whl -> top-level packages: ['pact']
pact_python-4.0.0-py3-none-any.whl -> top-level packages: ['pact']
pact-1.12.0.tar.gz -> top-level packages: ['pact', 'tests']
```

### PyPI queries, read only

```
$ pip index versions pact-python
pact-python (4.0.0)
Available versions: 4.0.0, 3.4.1, 3.4.0, 3.3.1, 3.3.0, ... (list truncated)
$ pip index versions hop-top-pact
ERROR: No matching distribution found for hop-top-pact
$ pip index versions hop_top_pact
ERROR: No matching distribution found for hop_top_pact
$ pip index versions pact
pact (1.12.0)
Available versions: 1.12.0, 1.11.0, 1.10.0, 1.9.0, 1.8.0, ... (list truncated)

hop-top-pact -> HTTP 404
hop_top_pact -> HTTP 404
pact -> HTTP 200
pact-python -> HTTP 200
```

### Facts

- `hop_top_pact` and `pact` are not importable in the main venv (first two lines of q6_import_name).
- The names `hop-top-pact` and `hop_top_pact` are not registered on PyPI: `pip index versions` found no distribution and `https://pypi.org/pypi/<name>/json` returned 404 for both for both spellings.
- Every pact-python release inspected ships a top-level package `pact`: 2.3.3, 3.4.1 and 4.0.0. The unrelated distribution `pact` 1.12.0 (a different project that owns the PyPI name `pact`) also ships a top-level `pact` package, and a `tests` package.
- Consequence for the SDK: a top-level import name `pact` would put files at the same `site-packages/pact/` path as pact-python. Installing the two together was not exercised.

## Probe sensitivity

Two scratch copies, each with one deliberate defect, to confirm the probes can fail. Neither copy is committed.

- `q4_jcs_numbers.py` with the positional-notation limit `< 1e21` changed to `< 1e20` in `es`:

```
rows 32 repr mismatches 15 es mismatches 3 pkg mismatches 0
random doubles 499844 es==rfc8785 499361 float(es(x))==x 499844
```

- `q1_es256.py` with `hashes.SHA256()` replaced by `hashes.SHA384()` (round trip still passes because signing and verifying share the digest; the fixed RFC vector does not):

```
round trip True raw lens {64} DER lens [69, 70, 71, 72]
tampered msg False 63 bytes False 65 bytes False
RFC 7515 A.3 verifies False sig bytes 64 tampered input False
```

## Decision table

| Primitive | Chosen | Evidence |
|---|---|---|
| ES256 sign and verify | Dependency: `cryptography` 50.0.2 (deps `cffi` 2.1.1, `pycparser` 3.11) | Stdlib has no ECDSA (q1_q5_stdlib). `ecdsa` 0.19.2 README: not designed with security in mind, no side-channel protection (README extract). Verified the RFC 7515 A.3 vector and the Appendix C fixture (q1_es256, q1b_fixture). The dependency count does not favour it (2 against 1, q1c_depcount). |
| DER to JWS `r\|\|s` conversion | Via the chosen dependency: `decode_dss_signature` and `encode_dss_signature` from `cryptography`, plus stdlib `int.to_bytes(32, "big")` | 5000 of 5000 signatures gave 64 bytes and verified after re-encoding; DER length ranged 69 to 72 (q1_es256). |
| JWK thumbprint (RFC 7638) | Builtin: `json`, `hashlib`, `base64` | Holder fixture `xx0BcA-...Mvl0M`, RFC 7638 section 3.1 and RFC 8037 Appendix A.3 all reproduced (q2_thumbprint). |
| Strict JSON parse | Builtin: `json.loads` with `object_pairs_hook`, `parse_constant`, `parse_float`, `parse_int`, a post-parse surrogate check, and a strict `bytes.decode("utf-8")` beforehand | Defaults accept duplicates, NaN, Infinity, 1e999, lone surrogates and integers above 2^53; each hook rejected them. `json.loads(bytes)` accepts encoded surrogates, a BOM and UTF-16 (q3_strict_json). |
| JCS (RFC 8785) | Builtin: a stdlib canonicalizer (`repr` digits re-laid per ECMA-262, UTF-16 key order, `json.dumps(ensure_ascii=False)` strings, explicit guards). `rfc8785` 0.1.4 (0 dependencies) only as a differential test oracle | `repr(float)` mismatched 15 of 32 rows and `json.dumps(sort_keys=True)` mis-ordered the sorting sample; the in-house formatter had 0 mismatches on 32 rows and agreed with `rfc8785` on 499844 doubles, on the RFC 3.2.4 bytes, on the sorting sample and on 13 domain cases (q4_jcs_numbers, q4b_jcs_document, q4c_jcs_domain). |
| JSON Schema Draft 2020-12 validation | Dependency: `jsonschema` 4.26.0 with `referencing` 0.37.0 (also `attrs`, `jsonschema-specifications`, `rpds-py`, `typing_extensions`) | No stdlib validator (q1_q5_stdlib). The schema validated offline through a `referencing` registry, and the Appendix C fixture failed only `const /pact_version` (q5_schema). |
| `format: "uri"` assertion | Open. If asserted: `rfc3986-validator` 0.1.1 (MIT, no dependencies). `rfc3987` is GPLv3+ | `uri` is absent from the default checker and `"not a uri"` passes; with `rfc3986-validator` it fails (q5_schema, both venvs). `urlsplit` accepts `"not a uri"` (q1_q5_stdlib). |
| Python import name | `hop_top_pact` (distribution `hop-top-pact`); not `pact` | `hop_top_pact` not importable and `hop-top-pact` is 404 on PyPI; pact-python 2.3.3, 3.4.1 and 4.0.0 and `pact` 1.12.0 all ship a top-level `pact` (q6_import_name, PyPI queries). |

Dependencies for the vet task, with the exact versions in the main venv: `cryptography` 50.0.2, `jsonschema` 4.26.0 and their transitive set (see `pip list` above); `rfc3986-validator` 0.1.1 only if `uri` is asserted; `rfc8785` 0.1.4 only as a test oracle.

## Not probed

- Signature malleability (an ECDSA `s` and `n - s` both verify) and constant-time behavior of the verify path.
- Platforms other than macOS arm64 with CPython 3.11.16: wheel availability of `cryptography`, `cffi` and `rpds-py` on Linux and Windows was not checked.
- Deterministic (RFC 6979) signing, performance, memory use, and the cost of the surrogate check by re-encoding versus a tree walk.
- Behavior of two distributions that both provide `pact/` installed in one environment.

## Phase-2 probes, 2026-10-19

Probe record, 2026-10-19. Purpose: settle the unknowns the Python plan ([ports-plan-py.md](../ports-plan-py.md), section 9, task py-probe-2) left open, and re-run every fact that plan marks "probed 2026-10-16". The programs are reproduced in full below, each followed by its output pasted verbatim. Questions continue the numbering above (Q7 to Q13).

### Environment

- Interpreters, each called by its versioned path, not through the mise shim: CPython 3.11.16 (`3.11.16 (main, Sep  1 2026, 14:08:22) [Clang 22.1.3 ]`, the build behind the `python = "3.11"` pin in `mise.toml`) and CPython 3.14.8 (`3.14.8 (main, Sep 30 2026, 17:55:09) [Clang 17.0.0 (clang-1700.6.4.2)]`, Homebrew). CPython 3.12.13 and 3.13.13 (mise installs) ran the depth program of Q13 only. macOS 15.6.1 arm64.
- Go 1.26.9 for the Go-side comparisons; Node 26.10.0 for the `ajv-formats` cross-check; mise 2026.10.3.
- Isolation: every Python program ran as `python -I` from the current directory `/tmp`, in a virtual environment created outside the repository. Nothing was installed outside scratch virtual environments. pip was upgraded to 26.2.1 in every virtual environment before any other install. The package was built from a `git archive` copy of `py/` at the branch base (`43ab48b`), outside the repository; the repository gained no build output, virtual environment or lockfile.
- Virtual environments: `venv-build` (3.11.16; `build` 1.6.1, `packaging` 26.3, `pyproject-hooks` 1.3.3), `venv-wheel311` and `venv-wheel314` (the built wheel installed with `pip install -c constraints.txt hop_top_pact-0.1.0a0-py3-none-any.whl`, so the runtime set at the `constraints.txt` pins: `cryptography` 50.0.2, `jsonschema` 4.26.0, `referencing` 0.37.0, `attrs` 26.1.0, `jsonschema-specifications` 2025.9.1, `rpds-py` 2026.9.1, `typing_extensions` 4.16.0, `cffi` 2.1.1, `pycparser` 3.11), `venv-p5` and `venv-hash` (3.11.16, pip only, for Q11).
- Downloaded: `ajv-formats-3.0.1.tgz` from `registry.npmjs.org`, into its own directory. Its SHA-512 equals the integrity recorded in [ts.md](ts.md) (`sha512-8iUql50EUR+uUcdRQ3HDqa6EVyo3docL8g5WJ3FNcWmu62IbkGUue/pEyLBW8VGKKucTPgqeks4fIU1DA4yowQ==`). The programs read `package/dist/formats.js` as text; no package code was run. Node ran only the regular expression extracted from it. Network use otherwise: pip installs and the mise documentation (read only).

| Question | Program | Run under |
|---|---|---|
| Q7 walker throughput | `p1_walker.py` | `venv-wheel311`, `venv-wheel314` |
| Q8 sdist and wheel round trip | `python -m build`, `p2_dist.py` | `venv-build` |
| Q9 registry from package data | `p3_registry.py` | `venv-wheel311`, `venv-wheel314` |
| Q10 `MISE_PYTHON_VERSION` | not run on a runner; documentation and a local analogue | mise 2026.10.3 |
| Q11 hashed constraints | `p5_hashes.py`, `p5_install.sh` | `venv-p5`, `venv-hash` |
| Q12 `uri` expression in `re` | `p6_uri_re.py`, `p6_node.mjs` | 3.11.16, 3.14.8, Node 26.10.0 |
| Q13 re-run of the 2026-10-16 facts | `r1_facts.py`, `r1b_depth.py`, `r2_numbers.py`, `main.go` | 3.11.16, 3.14.8 (`r1b_depth.py` also 3.12.13, 3.13.13), Go 1.26.9 |

## Q7. Strict parse: two-pass design against a walker port

`p1_walker.py` implements both designs over the generated member tables of the installed package (`hop_top_pact.core.types._MEMBERS`). Design 1 is section 3 of the plan: strict UTF-8 decode with a BOM check, a surrogate-escape scan, `json.loads` with hooks, then a typed walk over the tree. Design 2 is a pure-Python port of `go/core/strictjson/walk.go`: one pass with its own scanner that builds the tree while it tracks the path, the depth and the member tables, and checks surrogate pairs inside string decoding. Both share `check_kind`. The document is a `RequirementContract` grown with `FieldRule` entries to just under 256 KiB; the program first asserts that both designs return the tree that produced it, then runs 17 small inputs through both (16 refusals and a 16-deep document that must be accepted), then times each design 25 times.

### p1_walker.py

```python
"""Strict parse throughput on 256 KiB: two-pass design against a pure-Python port of the Go walker.

Member tables come from the installed package (hop_top_pact.core.types._MEMBERS).
"""
import json, re, statistics, sys, time
from hop_top_pact.core import types as T

MAX_SAFE, MAX_DEPTH, MAX_BYTES = 2**53 - 1, 16, 256 << 10
INT_LIMIT = 16  # digits of 2^53-1

class Reject(Exception):
    def __init__(self, kind, path="", offset=0):
        super().__init__(kind); self.kind, self.path, self.offset = kind, path, offset

def members_of(ref):
    return getattr(T, ref)._MEMBERS if ref else None

def ptr(path):
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in path)

def check_kind(m, v, path):  # member kind against a decoded value; shared by both designs
    if v is None:
        if not m.nullable: raise Reject("null", ptr(path))
        return
    k = m.kind
    ok = (k == "any" or (k == "string" and isinstance(v, str)) or (k == "boolean" and isinstance(v, bool))
          or (k == "integer" and isinstance(v, int) and not isinstance(v, bool))
          or (k == "number" and isinstance(v, (int, float)) and not isinstance(v, bool))
          or (k == "object" and isinstance(v, dict)) or (k == "array" and isinstance(v, list))
          or (k == "object|boolean" and isinstance(v, (dict, bool))))
    if not ok: raise Reject("integer" if k == "integer" and isinstance(v, float) else "type", ptr(path))
    if k == "integer" and v < 0: raise Reject("integer", ptr(path))

# ---- design 1: surrogate scan, json.loads with hooks, typed walk over the tree ----
_SUR_HINT = re.compile(r"\\u[dD][89a-fA-F]")
_ESC = re.compile(r"\\(?:u([0-9a-fA-F]{4})|.)", re.S)

def scan_surrogates(text):
    if not _SUR_HINT.search(text): return
    pending = None
    for m in _ESC.finditer(text):
        h = m.group(1); c = int(h, 16) if h else -1
        if pending is not None:
            if 0xDC00 <= c <= 0xDFFF and m.start() == pending: pending = None; continue
            raise Reject("lone-surrogate", offset=pending - 6)
        if 0xD800 <= c <= 0xDBFF: pending = m.end()
        elif 0xDC00 <= c <= 0xDFFF: raise Reject("lone-surrogate", offset=m.start())
    if pending is not None: raise Reject("lone-surrogate", offset=pending - 6)

def _pairs(ps):
    d = dict(ps)
    if len(d) != len(ps): raise Reject("duplicate-key")
    return d
def _int(s):
    if len(s) - (s[0] == "-") > INT_LIMIT or abs(i := int(s)) > MAX_SAFE: raise Reject("integer")
    return i
def _float(s):
    f = float(s)
    if f in (float("inf"), float("-inf")): raise Reject("non-finite")
    return f
def _const(s): raise Reject("non-finite")

def typed(v, members, path, depth):
    if isinstance(v, dict):
        if depth + 1 > MAX_DEPTH: raise Reject("depth", ptr(path))
        for k, x in v.items():
            path.append(k)
            if members is not None:
                m = members.get(k)
                if m is None: raise Reject("unknown-field", ptr(path))
                check_kind(m, x, path)
                typed(x, members_of(m.ref) if m.kind in ("object", "array") else None, path, depth + 1)
            else:
                typed(x, None, path, depth + 1)
            path.pop()
    elif isinstance(v, list):
        if depth + 1 > MAX_DEPTH: raise Reject("depth", ptr(path))
        for i, x in enumerate(v):
            path.append(i)
            if members is not None and not isinstance(x, dict): raise Reject("null" if x is None else "type", ptr(path))
            typed(x, members, path, depth + 1)
            path.pop()

def two_pass(data, cls):
    if len(data) > MAX_BYTES: raise Reject("size")
    if data.startswith(b"\xef\xbb\xbf"): raise Reject("syntax", offset=0)
    try: text = data.decode("utf-8")
    except UnicodeDecodeError as e: raise Reject("invalid-utf8", offset=e.start)
    scan_surrogates(text)
    try: tree = json.loads(text, object_pairs_hook=_pairs, parse_int=_int, parse_float=_float, parse_constant=_const)
    except json.JSONDecodeError as e: raise Reject("trailing-data" if e.msg == "Extra data" else "syntax", offset=e.pos)
    except RecursionError: raise Reject("depth")
    if cls is not None and not isinstance(tree, dict): raise Reject("type")
    typed(tree, cls._MEMBERS if cls else None, [], 0)
    return tree

# ---- design 2: one pass, a pure-Python port of go/core/strictjson/walk.go with its own scanner ----
_WS = re.compile(r"[ \t\n\r]*")
_NUM = re.compile(r"-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?")
_CHUNK = re.compile(r'([^"\\\x00-\x1f]*)(["\\\x00-\x1f])')
_SIMPLE = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}

class Walker:
    def __init__(self, s): self.s, self.pos, self.path, self.depth = s, 0, [], 0
    def fail(self, kind): raise Reject(kind, ptr(self.path), self.pos)
    def ws(self): self.pos = _WS.match(self.s, self.pos).end()
    def value(self, members):  # members: table for an object (or array items), None for free-form
        self.ws(); s = self.s
        if self.pos >= len(s): self.fail("syntax")
        c = s[self.pos]
        if c == "{": return self.obj(members)
        if c == "[": return self.arr(members)
        if c == '"': return self.string()
        if c == "-" or "0" <= c <= "9":
            m = _NUM.match(s, self.pos)
            if not m: self.fail("non-finite" if s.startswith("-Infinity", self.pos) else "syntax")
            self.pos, t = m.end(), m.group()
            if m.group(1) or m.group(2):
                f = float(t)
                if f in (float("inf"), float("-inf")): self.fail("non-finite")
                return f
            if len(t) - (t[0] == "-") > INT_LIMIT or abs(i := int(t)) > MAX_SAFE: self.fail("integer")
            return i
        for lit, v in (("true", True), ("false", False), ("null", None)):
            if s.startswith(lit, self.pos): self.pos += len(lit); return v
        self.fail("non-finite" if s.startswith(("NaN", "Infinity", "+Infinity"), self.pos) else "syntax")
    def enter(self):
        self.depth += 1
        if self.depth > MAX_DEPTH: self.fail("depth")
    def obj(self, members):
        self.enter(); self.pos += 1; s = self.s; out = {}
        self.ws()
        if s.startswith("}", self.pos): self.pos += 1; self.depth -= 1; return out
        while True:
            self.ws()
            if not s.startswith('"', self.pos): self.fail("syntax")
            key = self.string(); self.path.append(key)
            if key in out: self.fail("duplicate-key")
            m = None
            if members is not None:
                m = members.get(key)
                if m is None: self.fail("unknown-field")
            self.ws()
            if not s.startswith(":", self.pos): self.fail("syntax")
            self.pos += 1
            v = self.value(members_of(m.ref) if m is not None and m.kind in ("object", "array") else None)
            if m is not None: check_kind(m, v, self.path)
            out[key] = v; self.path.pop(); self.ws()
            if s.startswith(",", self.pos): self.pos += 1; continue
            if s.startswith("}", self.pos): self.pos += 1; self.depth -= 1; return out
            self.fail("syntax")
    def arr(self, members):
        self.enter(); self.pos += 1; s = self.s; out = []
        self.ws()
        if s.startswith("]", self.pos): self.pos += 1; self.depth -= 1; return out
        while True:
            self.path.append(len(out)); v = self.value(members)
            if members is not None and not isinstance(v, dict): self.fail("null" if v is None else "type")
            out.append(v); self.path.pop(); self.ws()
            if s.startswith(",", self.pos): self.pos += 1; continue
            if s.startswith("]", self.pos): self.pos += 1; self.depth -= 1; return out
            self.fail("syntax")
    def string(self):
        s = self.s; self.pos += 1; parts = []
        while True:
            m = _CHUNK.match(s, self.pos)
            if not m: self.fail("syntax")
            parts.append(m.group(1)); self.pos = m.end(); t = m.group(2)
            if t == '"': return "".join(parts)
            if t != "\\": self.fail("syntax")
            e = s[self.pos:self.pos + 1]
            if e != "u":
                if e not in _SIMPLE: self.fail("syntax")
                parts.append(_SIMPLE[e]); self.pos += 1; continue
            c = self.hex4(self.pos + 1); start = self.pos - 1; self.pos += 5
            if 0xDC00 <= c <= 0xDFFF: self.pos = start; self.fail("lone-surrogate")
            if 0xD800 <= c <= 0xDBFF:
                lo = self.hex4(self.pos + 2) if s.startswith("\\u", self.pos) else -1
                if not 0xDC00 <= lo <= 0xDFFF: self.pos = start; self.fail("lone-surrogate")
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00); self.pos += 6
            parts.append(chr(c))
    def hex4(self, at):
        h = self.s[at:at + 4]
        if len(h) != 4 or not all(ch in "0123456789abcdefABCDEF" for ch in h): self.fail("syntax")
        return int(h, 16)

def walker(data, cls):
    if len(data) > MAX_BYTES: raise Reject("size")
    try: text = data.decode("utf-8")
    except UnicodeDecodeError as e: raise Reject("invalid-utf8", offset=e.start)
    if text.startswith("\ufeff"): raise Reject("syntax")
    w = Walker(text); w.ws()
    if cls is not None and not text.startswith("{", w.pos): w.fail("type")
    tree = w.value(cls._MEMBERS if cls else None); w.ws()
    if w.pos != len(text): w.fail("trailing-data")
    return tree

# ---- document, agreement check, timing ----
def document(escapes):
    rule = lambda i: {"rule_id": f"rule-{i:05d}", "path": f"/claims/{i}/value", "schema": {"type": "string", "maxLength": 64,
            "enum": ["café", "a\U0001F600b" if escapes else "plain", "x" * 8]}, "source": "evidence", "comparison": "exact",
            "allowed_issuers": ["https://issuer.example/a", "https://issuer.example/b"], "native_path": None if i % 2 else "/x",
            "max_age_seconds": 300, "status_max_age_seconds": 60, "extensions": {"n": [1, 2.5, -3, True, None]}}
    base = {"pact_version": "0.1", "iss": "https://issuer.example", "sub": "agent", "aud": "https://gw.example", "jti": "j",
            "iat": 1, "nbf": 1, "exp": 2**53 - 1, "tenant_id": "t", "contract_id": "c", "environment_id": "e", "holder_jkt": "h",
            "operation_digest": "sha-256:x", "intent_digest": "sha-256:y", "base_revision": "r", "selected_set": "s",
            "field_rules": [], "context_checks": [], "learning_policy_digest": "d", "learning_artifact_digest": "d",
            "nonce": "n", "mode": "enforce"}
    enc = lambda d: json.dumps(d, ensure_ascii=escapes, separators=(",", ":")).encode()
    while len(enc(base)) < MAX_BYTES - 1024:
        base["field_rules"].append(rule(len(base["field_rules"])))
    return enc(base), base

C = T.RequirementContract
good, tree = document(escapes=True)
plain, _ = document(escapes=False)
print("python", sys.version.split()[0], "| document", len(good), "bytes,", len(tree["field_rules"]), "field rules,",
      good.count(b"\\ud83d"), "surrogate pairs; plain variant", len(plain), "bytes, no escapes")
assert two_pass(good, C) == walker(good, C) == tree and two_pass(plain, C) == walker(plain, C)
bad = {"dup": b'{"iss":"a","iss":"b"}', "unknown": b'{"isss":"a"}', "null": b'{"iss":null}', "int-type": b'{"iat":1.0}',
       "neg": b'{"iat":-1}', "2^53": b'{"iat":9007199254740992}', "17-deep": b'{"extensions":' + b'{"a":' * 16 + b'1' + b'}' * 17,
       "16-deep": b'{"extensions":' + b'{"a":' * 15 + b'1' + b'}' * 16, "lone": b'{"iss":"\\ud800"}', "nan": b'{"extensions":{"a":NaN}}',
       "1e400": b'{"extensions":{"a":1e400}}', "trailing": b'{"iss":"a"} x', "bom": b'\xef\xbb\xbf{}', "item-null": b'{"field_rules":[null]}',
       "unknown-nested": b'{"field_rules":[{"rule_idd":"x"}]}', "utf8": b'{"iss":"\xff"}', "any:100000 [": b"[" * 100000}
def kind(f, d, cls):
    try: f(d, cls); return "accept"
    except Reject as e: return f"{e.kind}@{e.path or '-'}+{e.offset}"
for name, d in bad.items():
    cls = None if name.startswith("any:") else C
    a, b = kind(two_pass, d, cls), kind(walker, d, cls)
    same = a.split("@")[0] == b.split("@")[0]
    print(f"  {name:15} two-pass {a:32} walker {b[:44]:44} {'same kind' if same else 'DIFFERENT KIND'}")

def bench(f, *a, n=25):
    ts = []
    for _ in range(n):
        t = time.perf_counter(); f(*a); ts.append((time.perf_counter() - t) * 1e3)
    return f"min {min(ts):7.2f} ms  median {statistics.median(ts):7.2f} ms"
text, ptext = good.decode(), plain.decode()
print("plain json.loads           ", bench(json.loads, text))
print("surrogate scan, pairs      ", bench(scan_surrogates, text))
print("surrogate scan, no escapes ", bench(scan_surrogates, ptext, n=200))
print("two-pass, pairs            ", bench(two_pass, good, C))
print("two-pass, no escapes       ", bench(two_pass, plain, C))
print("walker port, pairs         ", bench(walker, good, C))
print("walker port, no escapes    ", bench(walker, plain, C))
```

### Output, `venv-wheel311`

```
python 3.11.16 | document 261265 bytes, 711 field rules, 711 surrogate pairs; plain variant 261226 bytes, no escapes
  dup             two-pass duplicate-key@-+0                walker duplicate-key@/iss+16                        same kind
  unknown         two-pass unknown-field@/isss+0            walker unknown-field@/isss+7                        same kind
  null            two-pass null@/iss+0                      walker null@/iss+0                                  same kind
  int-type        two-pass integer@/iat+0                   walker integer@/iat+0                               same kind
  neg             two-pass integer@/iat+0                   walker integer@/iat+0                               same kind
  2^53            two-pass integer@-+0                      walker integer@/iat+23                              same kind
  17-deep         two-pass depth@/extensions/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a+0 walker depth@/extensions/a/a/a/a/a/a/a/a/a/a/a/a/a/ same kind
  16-deep         two-pass accept                           walker accept                                       same kind
  lone            two-pass lone-surrogate@-+8               walker lone-surrogate@/iss+8                        same kind
  nan             two-pass non-finite@-+0                   walker non-finite@/extensions/a+19                  same kind
  1e400           two-pass non-finite@-+0                   walker non-finite@/extensions/a+24                  same kind
  trailing        two-pass trailing-data@-+12               walker trailing-data@-+12                           same kind
  bom             two-pass syntax@-+0                       walker syntax@-+0                                   same kind
  item-null       two-pass null@/field_rules/0+0            walker null@/field_rules/0+20                       same kind
  unknown-nested  two-pass unknown-field@/field_rules/0/rule_idd+0 walker unknown-field@/field_rules/0/rule_idd+27     same kind
  utf8            two-pass invalid-utf8@-+8                 walker invalid-utf8@-+8                             same kind
  any:100000 [    two-pass depth@-+0                        walker depth@/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0+16    same kind
plain json.loads            min    1.19 ms  median    1.40 ms
surrogate scan, pairs       min    0.53 ms  median    0.55 ms
surrogate scan, no escapes  min    0.05 ms  median    0.06 ms
two-pass, pairs             min    5.97 ms  median    6.14 ms
two-pass, no escapes        min    5.78 ms  median    7.18 ms
walker port, pairs          min   29.37 ms  median   31.75 ms
walker port, no escapes     min   29.04 ms  median   30.21 ms
```

### Output, `venv-wheel314`

```
python 3.14.8 | document 261265 bytes, 711 field rules, 711 surrogate pairs; plain variant 261226 bytes, no escapes
  dup             two-pass duplicate-key@-+0                walker duplicate-key@/iss+16                        same kind
  unknown         two-pass unknown-field@/isss+0            walker unknown-field@/isss+7                        same kind
  null            two-pass null@/iss+0                      walker null@/iss+0                                  same kind
  int-type        two-pass integer@/iat+0                   walker integer@/iat+0                               same kind
  neg             two-pass integer@/iat+0                   walker integer@/iat+0                               same kind
  2^53            two-pass integer@-+0                      walker integer@/iat+23                              same kind
  17-deep         two-pass depth@/extensions/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a+0 walker depth@/extensions/a/a/a/a/a/a/a/a/a/a/a/a/a/ same kind
  16-deep         two-pass accept                           walker accept                                       same kind
  lone            two-pass lone-surrogate@-+8               walker lone-surrogate@/iss+8                        same kind
  nan             two-pass non-finite@-+0                   walker non-finite@/extensions/a+19                  same kind
  1e400           two-pass non-finite@-+0                   walker non-finite@/extensions/a+24                  same kind
  trailing        two-pass trailing-data@-+12               walker trailing-data@-+12                           same kind
  bom             two-pass syntax@-+0                       walker syntax@-+0                                   same kind
  item-null       two-pass null@/field_rules/0+0            walker null@/field_rules/0+20                       same kind
  unknown-nested  two-pass unknown-field@/field_rules/0/rule_idd+0 walker unknown-field@/field_rules/0/rule_idd+27     same kind
  utf8            two-pass invalid-utf8@-+8                 walker invalid-utf8@-+8                             same kind
  any:100000 [    two-pass syntax@-+100000                  walker depth@/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0/0+16    DIFFERENT KIND
plain json.loads            min    1.67 ms  median    1.76 ms
surrogate scan, pairs       min    0.72 ms  median    0.73 ms
surrogate scan, no escapes  min    0.11 ms  median    0.12 ms
two-pass, pairs             min    8.72 ms  median    8.99 ms
two-pass, no escapes        min    8.74 ms  median    9.52 ms
walker port, pairs          min   33.43 ms  median   37.30 ms
walker port, no escapes     min   32.79 ms  median   33.81 ms
```

Refusal columns: reason kind, `@` RFC 6901 path (`-` for none), `+` offset.

### Facts

- Both designs returned the input tree for both 256 KiB documents (the program's `assert`). On the 17 small inputs they gave the same verdict kind on all 17 under 3.11.16 and on 16 under 3.14.8.
- The exception is `any:100000 [` (100 000 unclosed `[`, free-form target, the input of Go's `TestDepthIsCheckedBeforeBodyIsRead`): on 3.11.16 the two-pass design reports `depth` (from `RecursionError`), on 3.14.8 it reports `syntax` at offset 100000, because `json.loads` reaches the end of the input before it exhausts the stack (Q13). The walker port reports `depth` on both, at the 17th bracket.
- Throughput, best of 25 runs on the 261 265-byte document: on 3.11.16, two-pass 5.97 ms and walker port 29.37 ms (4.9 times slower); on 3.14.8, 8.72 ms and 33.43 ms (3.8 times). The escape-free variant gave the same picture (5.78 against 29.04 ms; 8.74 against 32.79 ms). Plain `json.loads` without hooks took 1.19 ms and 1.67 ms.
- The surrogate scan took 0.05 ms on the escape-free text under 3.11.16 and 0.11 ms under 3.14.8 (it stops after one regular-expression search), and 0.53 ms and 0.72 ms on the text with 711 surrogate pairs (it walks every escape).
- Location detail differs. Two-pass refusals raised in a `json.loads` hook (duplicate key, integer range, non-finite) carry neither path nor offset; a lone surrogate found by the scan carries an offset but no path; pass-2 refusals carry the path and offset 0. The walker port gives a path for every refusal and a positive offset for every refusal its scanner raises (`check_kind` sets none, so `null` and kind refusals show offset 0 in both).
- Go's `TestErrorFields` (`go/core/strictjson/strictjson_test.go`) requires kind `ErrUnknownField`, path `/items/1/x~0~1` and `Offset > 0` for an unknown member. The two-pass design reports that member in pass 2 with offset 0 (row `unknown`: `unknown-field@/isss+0`), so the test does not pass unchanged under it; under the walker port it does (`+7`).

### Departures from the expectation

- The plan expected the walker port to matter only for throughput. Two ported Go tests do not pass unchanged under the two-pass design: `TestErrorFields` (offset 0 for a pass-2 finding) on every interpreter, and `TestDepthIsCheckedBeforeBodyIsRead` on 3.14.8. Section 3 of the plan names this case as the trigger for the walker fallback.

## Q8. sdist and wheel round trip with flit-core

`python -m build --outdir dist2` from the `py/` copy in `venv-build` (build log with the per-package lines removed):

```
* Creating isolated environment: venv+pip...
* Installing packages in isolated environment:
* Getting build dependencies for sdist...
* Installed build dependency versions:
* Building sdist...
* Building wheel from sdist
* Creating isolated environment: venv+pip...
* Installing packages in isolated environment:
* Getting build dependencies for wheel...
* Installed build dependency versions:
* Building wheel...
Successfully built hop_top_pact-0.1.0a0.tar.gz and hop_top_pact-0.1.0a0-py3-none-any.whl
```

### p2_dist.py

```python
"""Members of the flit-core sdist and wheel; schema bytes against the spec schema."""
import hashlib, sys, tarfile, zipfile
from pathlib import Path

sdist, wheel, spec = (Path(a) for a in sys.argv[1:4])
want = hashlib.sha256(spec.read_bytes()).hexdigest()
with tarfile.open(sdist) as t:
    names = sorted(m.name.split("/", 1)[1] for m in t.getmembers() if m.isfile())
    print("sdist", sdist.name, len(names), "files:", names)
    data = t.extractfile(t.getmember(f"{sdist.name[:-7]}/src/hop_top_pact/schema/pact.schema.json")).read()
    print("  sdist schema == spec:", hashlib.sha256(data).hexdigest() == want)
with zipfile.ZipFile(wheel) as z:
    names = sorted(z.namelist())
    print("wheel", wheel.name, len(names), "files")
    print("  py.typed:", "hop_top_pact/py.typed" in names, "| schema:", "hop_top_pact/schema/pact.schema.json" in names)
    print("  tests/ or scripts/ members:", [n for n in names if n.startswith(("tests/", "scripts/"))])
    print("  schema == spec:", hashlib.sha256(z.read("hop_top_pact/schema/pact.schema.json")).hexdigest() == want)
    print("  dist-info:", [n for n in names if ".dist-info/" in n])
    print("  WHEEL:", z.read(next(n for n in names if n.endswith(".dist-info/WHEEL"))).decode().split("\n")[:4])
```

Run as `p2_dist.py hop_top_pact-0.1.0a0.tar.gz hop_top_pact-0.1.0a0-py3-none-any.whl $REPO/spec/v1.0/schemas/pact.schema.json`:

```
sdist hop_top_pact-0.1.0a0.tar.gz 30 files: ['LICENSE', 'PKG-INFO', 'README.md', 'pyproject.toml', 'src/hop_top_pact/__init__.py', 'src/hop_top_pact/adapter/__init__.py', 'src/hop_top_pact/adapter/adaptertest/__init__.py', 'src/hop_top_pact/adapters/__init__.py', 'src/hop_top_pact/adapters/memory/__init__.py', 'src/hop_top_pact/conformance/__init__.py', 'src/hop_top_pact/core/__init__.py', 'src/hop_top_pact/core/binding/__init__.py', 'src/hop_top_pact/core/digest.py', 'src/hop_top_pact/core/enums.py', 'src/hop_top_pact/core/jcs.py', 'src/hop_top_pact/core/jws/__init__.py', 'src/hop_top_pact/core/limits.py', 'src/hop_top_pact/core/schema.py', 'src/hop_top_pact/core/strictjson.py', 'src/hop_top_pact/core/types.py', 'src/hop_top_pact/py.typed', 'src/hop_top_pact/runner/__init__.py', 'src/hop_top_pact/runner/manifest/__init__.py', 'src/hop_top_pact/schema/pact.schema.json', 'src/hop_top_pact/vectors/__init__.py', 'src/hop_top_pact/vectors/__main__.py', 'src/hop_top_pact/vectors/_common.py', 'src/hop_top_pact/vectors/_gates.py', 'src/hop_top_pact/vectors/_groups.py', 'src/hop_top_pact/vectors/_jws.py']
  sdist schema == spec: True
wheel hop_top_pact-0.1.0a0-py3-none-any.whl 30 files
  py.typed: True | schema: True
  tests/ or scripts/ members: []
  schema == spec: True
  dist-info: ['hop_top_pact-0.1.0a0.dist-info/METADATA', 'hop_top_pact-0.1.0a0.dist-info/RECORD', 'hop_top_pact-0.1.0a0.dist-info/WHEEL', 'hop_top_pact-0.1.0a0.dist-info/licenses/LICENSE']
  WHEEL: ['Wheel-Version: 1.0', 'Generator: flit 4.1.0', 'Root-Is-Purelib: true', 'Tag: py3-none-any']
```

### Facts

- `[build-system] requires = ["flit_core==4.1.0"]` built both artifacts; `python -m build` built the sdist first and the wheel from the sdist (`Building wheel from sdist`), so the wheel round trip passes through the sdist.
- The src layout works: the sdist holds `src/hop_top_pact/...`, the wheel holds `hop_top_pact/...` at its root (`Root-Is-Purelib: true`, `Tag: py3-none-any`, `Generator: flit 4.1.0`).
- Package data: `hop_top_pact/schema/pact.schema.json` is in both, with no `__init__.py` in `schema/` and no package-data configuration beyond `[tool.flit.module]`. Its bytes equal `spec/v1.0/schemas/pact.schema.json` in both (`schema == spec: True`); the vendored copy in the repository equals the spec file too (`cmp`).
- `py.typed` is in both.
- The wheel contains no `tests/` or `scripts/` member. The sdist contains neither either, nor `constraints.txt` or `ruff.toml`: flit-core's sdist is the package, `pyproject.toml`, `README.md`, `LICENSE` and `PKG-INFO`.
- A second build gave a byte-identical wheel (`cmp` of the two wheels: equal).

## Q9. `referencing` registry from installed package data

### p3_registry.py

```python
"""Offline referencing registry from the installed wheel's package data."""
import base64, json, socket, sys
from importlib.resources import files
from pathlib import Path

def _no_net(*a, **k): raise OSError("network blocked by probe")
socket.socket = socket.create_connection = socket.getaddrinfo = _no_net  # type: ignore[assignment,misc]

import hop_top_pact, jsonschema
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable

res = files("hop_top_pact") / "schema" / "pact.schema.json"
print("package from:", Path(hop_top_pact.__file__).parent.relative_to(sys.prefix), "| version", hop_top_pact.__version__)
print("resource:", type(res).__name__, Path(str(res)).relative_to(sys.prefix))
schema = json.loads(res.read_bytes())
registry = Registry().with_resource(schema["$id"], Resource.from_contents(schema))
jws = Path(sys.argv[1]).read_text().strip().split(".")
payload = json.loads(base64.urlsafe_b64decode(jws[1] + "=" * (-len(jws[1]) % 4)))
v = jsonschema.Draft202012Validator({"$ref": schema["$id"] + "#/$defs/Evidence"}, registry=registry)
print("Appendix C as-is:", [f"{e.validator}@{e.json_path}" for e in v.iter_errors(payload)])
print("pact_version 0.1:", [f"{e.validator}@{e.json_path}" for e in v.iter_errors({**payload, "pact_version": "0.1"})])
try:
    list(jsonschema.Draft202012Validator({"$ref": schema["$id"] + "#/$defs/Evidence"}, registry=Registry()).iter_errors(payload))
    print("empty registry: no error")
except Exception as e:
    print("empty registry raised", type(e).__name__, "| is referencing Unresolvable:", isinstance(e, Unresolvable))
```

Run as `p3_registry.py $REPO/spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws`.

### Output, `venv-wheel311`

```
package from: lib/python3.11/site-packages/hop_top_pact | version 0.1.0a0
resource: PosixPath lib/python3.11/site-packages/hop_top_pact/schema/pact.schema.json
Appendix C as-is: ['const@$.pact_version']
pact_version 0.1: []
empty registry raised _WrappedReferencingError | is referencing Unresolvable: True
```

### Output, `venv-wheel314`

```
package from: lib/python3.14/site-packages/hop_top_pact | version 0.1.0a0
resource: PosixPath lib/python3.14/site-packages/hop_top_pact/schema/pact.schema.json
Appendix C as-is: ['const@$.pact_version']
pact_version 0.1: []
empty registry raised _WrappedReferencingError | is referencing Unresolvable: True
```

### Facts

- From the installed wheel (not the repository: the package and the resource resolve under `site-packages` of the virtual environment), `importlib.resources.files("hop_top_pact") / "schema" / "pact.schema.json"` returned a `PosixPath` whose bytes parse to the schema.
- `Registry().with_resource(schema["$id"], Resource.from_contents(schema))` resolved `{"$ref": "<$id>#/$defs/Evidence"}` with sockets blocked. The Appendix C payload failed with exactly `const` at `pact_version`, and passed with `pact_version` set to `"0.1"`, as in Q5.
- With an empty registry the validator raised `_WrappedReferencingError`, a private class, which is an instance of the public `referencing.exceptions.Unresolvable`.

## Q10. `MISE_PYTHON_VERSION` on the runner

Not run locally: the CI runner cannot be reproduced here. `.github/workflows/ci-py.yml` sets `env: MISE_PYTHON_VERSION: ${{ matrix.python }}` on the test job with `python: ["3.11", "3"]` and installs tools with `jdx/mise-action@v2` (`install: true`).

The mise documentation, read 2026-10-19:

- <https://mise.jdx.dev/configuration/environment-variables.html>, section `MISE_<TOOL>_VERSION`: "Selects a version of one tool and overrides every config file for the commands that see it", with the example `MISE_NODE_VERSION=22 mise exec -- node --version`; "Write the tool name in upper case with `-` changed to `_`".
- <https://mise.jdx.dev/dev-tools/versions.html>, "How a request resolves": a prefix request is "A release that starts with the prefix"; "If an installed version matches the request, mise uses it." "Otherwise mise asks the tool's backend for its versions and picks a match."

Local analogue, not the runner: `MISE_AUTO_INSTALL=false MISE_PYTHON_VERSION=<v> mise exec -- python -c 'import sys; print(sys.version.split()[0])'` in an empty scratch directory with no project configuration (first line: `mise --version`):

```
2026.10.3 macos-arm64 (2026-10-05)
MISE_PYTHON_VERSION=<unset>: mise ERROR No version is set for shim: python
Set a global default version with one of the following:
MISE_PYTHON_VERSION=3.11: 3.11.16
MISE_PYTHON_VERSION=3.12: 3.12.13
MISE_PYTHON_VERSION=3: 3.13.13
```

### Facts

- Locally the variable selected the interpreter with no configuration file present: `3.11` gave 3.11.16, `3.12` gave 3.12.13.
- `3` gave 3.13.13, the newest 3.x that mise has installed, not the Homebrew 3.14.8 (outside mise). This matches the documented rule that an installed match wins. On a runner, `3` resolves to the newest installed 3.x when a tool cache is restored, and to the backend's newest otherwise; which one the job gets depends on the runner's cache, not observed here.

## Q11. Hashed constraints next to an editable install

### p5_hashes.py

```python
"""Write constraints.txt with the sha256 of every artifact pip's dry-run report resolved."""
import json, sys
from pathlib import Path

report, plain, out = (Path(a) for a in sys.argv[1:4])
hashes = {}
for item in json.loads(report.read_text())["install"]:
    name = item["metadata"]["name"].lower().replace("_", "-")
    info = item["download_info"].get("archive_info", {})
    if "hashes" in info:
        hashes[name] = info["hashes"]["sha256"]
lines = []
for line in plain.read_text().splitlines():
    if line and not line.startswith("#"):
        name = line.split("==")[0].lower()
        if name in hashes:
            lines.append(f"{line} --hash=sha256:{hashes[name]}")
        else:
            print("not resolved on this platform, left out:", line)
out.write_text("\n".join(lines) + "\n")
print(len(lines), "pins written,", len(hashes), "hashes in report; first:", lines[0][:60] + "...")
print("report entries without archive hash:", [i["metadata"]["name"] for i in json.loads(report.read_text())["install"] if "hashes" not in i["download_info"].get("archive_info", {})])
```

### p5_install.sh

```sh
#!/bin/bash
# Usage: p5_install.sh VENV HASHED_CONSTRAINTS WHEEL   (run from the py/ copy)
venv=$1 hashed=$2 wheel=$3
"$venv/bin/python" -I -m pip --version | cut -d' ' -f1-2
for args in "-e .[dev]" ".[dev]" "$wheel[dev]" "-e ."; do
  echo "\$ pip install -c constraints-hashed.txt ${args/$(dirname "$wheel")\//}"
  # shellcheck disable=SC2086
  "$venv/bin/python" -I -m pip install -q -c "$hashed" $args 2>&1 | head -12
  echo "exit ${PIPESTATUS[0]}"
done
"$venv/bin/python" -I -m pip list 2>/dev/null | grep -ci hop-top-pact | sed 's/^/hop-top-pact installed rows: /'
```

The report came from `pip install --dry-run --report report.json -c constraints.txt -e ".[dev]"` (pip 26.2.1, 3.11.16) in the `py/` copy. Then, in the `py/` copy with `venv-p5` (scratch prefix shown as `$SCRATCH`):

```
not resolved on this platform, left out: colorama==0.4.6
23 pins written, 23 hashes in report; first: cryptography==50.0.2 --hash=sha256:fa8f5efb344d6908a1ce62f4a...
report entries without archive hash: ['hop-top-pact']
pip 26.2.1
$ pip install -c constraints-hashed.txt -e .[dev]
ERROR: The editable requirement file://$SCRATCH/py cannot be installed when requiring hashes, because there is no single file to hash.
exit 1
$ pip install -c constraints-hashed.txt .[dev]
ERROR: Can't verify hashes for these file:// requirements because they point to directories:
    file://$SCRATCH/py
exit 1
$ pip install -c constraints-hashed.txt hop_top_pact-0.1.0a0-py3-none-any.whl[dev]
ERROR: Hashes are required in --require-hashes mode, but they are missing from some requirements. Here is a list of those requirements along with the hashes their downloaded archives actually had. Add lines like these to your requirements files to prevent tampering. (If you did not enable --require-hashes manually, note that it turns on automatically when any package has a hash.)
    file://$SCRATCH/dist/hop_top_pact-0.1.0a0-py3-none-any.whl --hash=sha256:a54f0ee3bd34ed4c160d3b84b42ccd1dcfe108695360712b7917b0cc3232b2f7
exit 1
$ pip install -c constraints-hashed.txt -e .
ERROR: The editable requirement file://$SCRATCH/py cannot be installed when requiring hashes, because there is no single file to hash.
exit 1
hop-top-pact installed rows: 0
```

Controls (shell commands in the `py/` copy): the plain `constraints.txt` with the editable install in a clean virtual environment, then the two-step form in `venv-hash`:

```
$ pip install -c constraints.txt -e .[dev]
exit 0
$ pip install --require-hashes -r constraints-hashed.txt
exit 0
$ pip install --no-deps -e .
exit 0
$ pip check
No broken requirements found.
```

### Facts

- pip 26.2.1 turns on hash-checking mode as soon as a constraint carries `--hash`, and then refuses the editable install: "The editable requirement ... cannot be installed when requiring hashes, because there is no single file to hash." It refuses a non-editable install of the directory too ("Can't verify hashes for these file:// requirements because they point to directories"), and a local wheel unless the wheel itself has a hash. The scaffold's finding (`py/constraints.txt` header) reproduces.
- The same install with the unhashed `constraints.txt` succeeds.
- Hashes and an editable install can coexist in two steps: `pip install --require-hashes -r constraints-hashed.txt`, then `pip install --no-deps -e .`; `pip check` found no broken requirement. A hashed file is per platform: the dry run resolved 23 of the 24 pins on macOS arm64 (`colorama` 0.4.6 is a Windows-only dependency) and records one wheel hash each.

## Q12. Python `re` and the `ajv-formats` `uri` expression

### p6_node.mjs

```js
// Usage: node p6_node.mjs SRC_JSON VECTORS -> {id: verdict} with the ajv-formats uri test: /\/|:/ and URI.
import { readFileSync } from "node:fs";
const { src, flags } = JSON.parse(readFileSync(process.argv[2], "utf8"));
const re = new RegExp(src, flags);
const out = {};
for (const r of JSON.parse(readFileSync(process.argv[3], "utf8"))) out[r.id] = /\/|:/.test(r.input) && re.test(r.input);
console.log(JSON.stringify(out));
```

### p6_uri_re.py

```python
"""Python re on the ajv-formats 3.0.1 uri expression, unchanged, and on the shared expression."""
import json, re, sys
from pathlib import Path

formats_js, vectors, readme, node_out = (Path(a) for a in sys.argv[1:5])
m = re.search(r"^const URI = /(.*)/(\w*);$", formats_js.read_text(), re.M)
src, js_flags = m.group(1), m.group(2)
shared = re.search(r"```text\n(.*?)\n```", readme.read_text(), re.S).group(1)
rows = json.loads(vectors.read_text())
node = json.loads(node_out.read_text())  # id -> verdict of new RegExp(src, flags) plus /\/|:/ in Node
print("ajv uri source:", len(src), "chars, JS flags", repr(js_flags), "| shared:", len(shared), "chars | rows", len(rows))
def ajv(rx, search):
    return lambda s: bool(re.search(r"/|:", s)) and bool(search(rx, s))
cands = {
    "ajv re.I search": ajv(re.compile(src, re.I), re.Pattern.search),
    "ajv re.I|re.A search": ajv(re.compile(src, re.I | re.A), re.Pattern.search),
    "ajv re.I|re.A fullmatch": ajv(re.compile(src, re.I | re.A), re.Pattern.fullmatch),
}
for name, f in cands.items():
    diff = [r["id"] for r in rows if f(r["input"]) != node[r["id"]]]
    print(f"{name:24} compiled; differs from Node ajv on {len(diff)}: {diff}")
print("Node ajv vs expect differs exactly on ajv_formats_differs rows:",
      [r["id"] for r in rows if (node[r["id"]] != (r["expect"] == "accept"))] == [r["id"] for r in rows if r["ajv_formats_differs"]])
rx = re.compile(shared)
for name, f in {"shared search": rx.search, "shared fullmatch": rx.fullmatch}.items():
    bad = [r["id"] for r in rows if bool(f(r["input"])) != (r["expect"] == "accept")]
    print(f"{name:24} wrong verdicts {len(bad)}: {bad}")
```

The `URI` source and flags were extracted from `package/dist/formats.js` (`const URI = /.../i;`) into a JSON file; `p6_node.mjs` produced the Node verdicts over `spec/v1.0/fixtures/vectors/schema/uri-format.json`, and `p6_uri_re.py` ran as `p6_uri_re.py formats.js uri-format.json README.md node-ajv.json`:

```
== Python 3.11.16
ajv uri source: 1147 chars, JS flags 'i' | shared: 1322 chars | rows 50
ajv re.I search          compiled; differs from Node ajv on 5: ['line-feed-at-end', 'kelvin-sign-in-path', 'long-s-in-path', 'kelvin-sign-in-host', 'non-ascii-digit-in-port']
ajv re.I|re.A search     compiled; differs from Node ajv on 1: ['line-feed-at-end']
ajv re.I|re.A fullmatch  compiled; differs from Node ajv on 0: []
Node ajv vs expect differs exactly on ajv_formats_differs rows: True
shared search            wrong verdicts 1: ['line-feed-at-end']
shared fullmatch         wrong verdicts 0: []
== Python 3.14.8
ajv uri source: 1147 chars, JS flags 'i' | shared: 1322 chars | rows 50
ajv re.I search          compiled; differs from Node ajv on 5: ['line-feed-at-end', 'kelvin-sign-in-path', 'long-s-in-path', 'kelvin-sign-in-host', 'non-ascii-digit-in-port']
ajv re.I|re.A search     compiled; differs from Node ajv on 1: ['line-feed-at-end']
ajv re.I|re.A fullmatch  compiled; differs from Node ajv on 0: []
Node ajv vs expect differs exactly on ajv_formats_differs rows: True
shared search            wrong verdicts 1: ['line-feed-at-end']
shared fullmatch         wrong verdicts 0: []
```

### Facts

- Python `re` compiles the `ajv-formats` 3.0.1 `uri` expression unchanged (1147 characters, JS flag `i` given as `re.I`) on 3.11.16 and 3.14.8.
- Compiled unchanged, it does not give the JavaScript verdicts. With `re.I` and `search` it differs from Node on 5 of the 50 vectors: `line-feed-at-end` (`$` matches before a final line feed in Python), and `kelvin-sign-in-path`, `long-s-in-path`, `kelvin-sign-in-host`, `non-ascii-digit-in-port` (Unicode case folding and `\d`). Adding `re.ASCII` removes the last four; `fullmatch` removes the first. With `re.I | re.ASCII` and `fullmatch` it agrees with Node on all 50.
- Node's verdicts differ from `expect` exactly on the rows marked `ajv_formats_differs`.
- The shared expression of `spec/v1.0/fixtures/vectors/schema/README.md` compiles with no flags and gives the `expect` verdict on all 50 rows with `fullmatch`; with `search` it fails only `line-feed-at-end`, as that README warns.

## Q13. Re-run of the facts marked "probed 2026-10-16"

### r1_facts.py

```python
"""Re-run of the plan facts marked probed 2026-10-16 (standard library only)."""
import base64, binascii, json, sys

print("python", sys.version.split()[0], "| recursion limit", sys.getrecursionlimit())

def raises(f, *a, **k):
    try:
        return repr(f(*a, **k))
    except Exception as e:
        return f"{type(e).__name__}: {str(e)[:60]}"

def first_failure(make, hi=2_000_000):
    def bad(n):
        try:
            json.loads(make(n))
            return False
        except RecursionError:
            return True
    lo = 1
    while lo < hi:  # bisection: the smallest nesting that raises RecursionError
        mid = (lo + hi) // 2
        lo, hi = (lo, mid) if bad(mid) else (mid + 1, hi)
    return lo

for name, make in {"arrays": lambda n: "[" * n + "]" * n, "objects": lambda n: '{"a":' * n + "1" + "}" * n}.items():
    print(f"RecursionError first at nesting ({name}):", first_failure(make))

try:
    json.loads("[" + "1" * 5000 + "]")
except ValueError as e:
    print("5000-digit int:", type(e).__name__, "| is JSONDecodeError:", isinstance(e, json.JSONDecodeError), "|", str(e)[:58])
print("parse_int sees text first:", raises(json.loads, "[" + "1" * 5000 + "]", parse_int=lambda s: len(s)))

for s in ["AB", "AB==", "AQ==", "A\nQ==", "AQ", "AQ=", "A-_A", "A+/A"]:
    print(f"{s!r:8}", "urlsafe_b64decode", raises(base64.urlsafe_b64decode, s), "| b64decode(validate)",
          raises(base64.b64decode, s, validate=True), "| a2b strict", raises(binascii.a2b_base64, s, strict_mode=True),
          "| b64decode(-_ validate)", raises(base64.b64decode, s, altchars=b"-_", validate=True))

for ea in (False, True):
    out = json.dumps("a" + chr(0x2028) + "b" + chr(0x2029) + "c", ensure_ascii=ea)
    print(f"json.dumps U+2028 U+2029 ensure_ascii={ea}: raw characters kept {chr(0x2028) in out and chr(0x2029) in out} | escapes {out.count(chr(92) + chr(117) + '202')}")

for s in ["1e-400", "1e400", "-0.0", "2.5e-324", "5e-324", "2.4e-324", "1.7976931348623157e308", "1.7976931348623159e308"]:
    v = float(s)
    print(f"float({s!r}) = {v!r} | json.loads = {raises(json.loads, s)} | signbit {str(v).startswith('-')}")
```

### Output, 3.11.16

```
python 3.11.16 | recursion limit 1000
RecursionError first at nesting (arrays): 994
RecursionError first at nesting (objects): 994
5000-digit int: ValueError | is JSONDecodeError: False | Exceeds the limit (4300 digits) for integer string convers
parse_int sees text first: [5000]
'AB'     urlsafe_b64decode Error: Incorrect padding | b64decode(validate) Error: Incorrect padding | a2b strict Error: Incorrect padding | b64decode(-_ validate) Error: Incorrect padding
'AB=='   urlsafe_b64decode b'\x00' | b64decode(validate) b'\x00' | a2b strict b'\x00' | b64decode(-_ validate) b'\x00'
'AQ=='   urlsafe_b64decode b'\x01' | b64decode(validate) b'\x01' | a2b strict b'\x01' | b64decode(-_ validate) b'\x01'
'A\nQ==' urlsafe_b64decode b'\x01' | b64decode(validate) Error: Only base64 data is allowed | a2b strict Error: Only base64 data is allowed | b64decode(-_ validate) Error: Only base64 data is allowed
'AQ'     urlsafe_b64decode Error: Incorrect padding | b64decode(validate) Error: Incorrect padding | a2b strict Error: Incorrect padding | b64decode(-_ validate) Error: Incorrect padding
'AQ='    urlsafe_b64decode Error: Incorrect padding | b64decode(validate) Error: Incorrect padding | a2b strict Error: Incorrect padding | b64decode(-_ validate) Error: Incorrect padding
'A-_A'   urlsafe_b64decode b'\x03\xef\xc0' | b64decode(validate) Error: Only base64 data is allowed | a2b strict Error: Only base64 data is allowed | b64decode(-_ validate) b'\x03\xef\xc0'
'A+/A'   urlsafe_b64decode b'\x03\xef\xc0' | b64decode(validate) b'\x03\xef\xc0' | a2b strict b'\x03\xef\xc0' | b64decode(-_ validate) b'\x03\xef\xc0'
json.dumps U+2028 U+2029 ensure_ascii=False: raw characters kept True | escapes 0
json.dumps U+2028 U+2029 ensure_ascii=True: raw characters kept False | escapes 2
float('1e-400') = 0.0 | json.loads = 0.0 | signbit False
float('1e400') = inf | json.loads = inf | signbit False
float('-0.0') = -0.0 | json.loads = -0.0 | signbit True
float('2.5e-324') = 5e-324 | json.loads = 5e-324 | signbit False
float('5e-324') = 5e-324 | json.loads = 5e-324 | signbit False
float('2.4e-324') = 0.0 | json.loads = 0.0 | signbit False
float('1.7976931348623157e308') = 1.7976931348623157e+308 | json.loads = 1.7976931348623157e+308 | signbit False
float('1.7976931348623159e308') = inf | json.loads = inf | signbit False
```

### Output, 3.14.8

```
python 3.14.8 | recursion limit 1000
RecursionError first at nesting (arrays): 116182
RecursionError first at nesting (objects): 116182
5000-digit int: ValueError | is JSONDecodeError: False | Exceeds the limit (4300 digits) for integer string convers
parse_int sees text first: [5000]
'AB'     urlsafe_b64decode Error: Incorrect padding | b64decode(validate) Error: Incorrect padding | a2b strict Error: Incorrect padding | b64decode(-_ validate) Error: Incorrect padding
'AB=='   urlsafe_b64decode b'\x00' | b64decode(validate) b'\x00' | a2b strict b'\x00' | b64decode(-_ validate) b'\x00'
'AQ=='   urlsafe_b64decode b'\x01' | b64decode(validate) b'\x01' | a2b strict b'\x01' | b64decode(-_ validate) b'\x01'
'A\nQ==' urlsafe_b64decode b'\x01' | b64decode(validate) Error: Only base64 data is allowed | a2b strict Error: Only base64 data is allowed | b64decode(-_ validate) Error: Only base64 data is allowed
'AQ'     urlsafe_b64decode Error: Incorrect padding | b64decode(validate) Error: Incorrect padding | a2b strict Error: Incorrect padding | b64decode(-_ validate) Error: Incorrect padding
'AQ='    urlsafe_b64decode Error: Incorrect padding | b64decode(validate) Error: Incorrect padding | a2b strict Error: Incorrect padding | b64decode(-_ validate) Error: Incorrect padding
'A-_A'   urlsafe_b64decode b'\x03\xef\xc0' | b64decode(validate) Error: Only base64 data is allowed | a2b strict Error: Only base64 data is allowed | b64decode(-_ validate) b'\x03\xef\xc0'
'A+/A'   urlsafe_b64decode b'\x03\xef\xc0' | b64decode(validate) b'\x03\xef\xc0' | a2b strict b'\x03\xef\xc0' | b64decode(-_ validate) b'\x03\xef\xc0'
json.dumps U+2028 U+2029 ensure_ascii=False: raw characters kept True | escapes 0
json.dumps U+2028 U+2029 ensure_ascii=True: raw characters kept False | escapes 2
float('1e-400') = 0.0 | json.loads = 0.0 | signbit False
float('1e400') = inf | json.loads = inf | signbit False
float('-0.0') = -0.0 | json.loads = -0.0 | signbit True
float('2.5e-324') = 5e-324 | json.loads = 5e-324 | signbit False
float('5e-324') = 5e-324 | json.loads = 5e-324 | signbit False
float('2.4e-324') = 0.0 | json.loads = 0.0 | signbit False
float('1.7976931348623157e308') = 1.7976931348623157e+308 | json.loads = 1.7976931348623157e+308 | signbit False
float('1.7976931348623159e308') = inf | json.loads = inf | signbit False
```

### r1b_depth.py

```python
"""Smallest array nesting at which json.loads raises RecursionError, main thread and a worker thread."""
import json, sys, threading

def bad(n):
    try:
        json.loads("[" * n + "]" * n)
        return False
    except RecursionError:
        return True

def first(lo=1, hi=2_000_000):
    while lo < hi:
        mid = (lo + hi) // 2
        lo, hi = (lo, mid) if bad(mid) else (mid + 1, hi)
    return lo

out = {}
t = threading.Thread(target=lambda: out.setdefault("worker", first()))
t.start(); t.join()
print(sys.version.split()[0], "| main thread:", first(), "| worker thread:", out["worker"],
      "| 131072 levels (fits 256 KiB) raise:", bad(131072), "| 100000 unclosed '[':", end=" ")
try:
    json.loads("[" * 100000)
except RecursionError:
    print("RecursionError")
except json.JSONDecodeError as e:
    print("JSONDecodeError", e.msg, "pos", e.pos)
```

Output, one line per interpreter (3.11.16, 3.12.13, 3.13.13, 3.14.8):

```
3.11.16 | main thread: 994 | worker thread: 991 | 131072 levels (fits 256 KiB) raise: True | 100000 unclosed '[': RecursionError
3.12.13 | main thread: 9998 | worker thread: 9998 | 131072 levels (fits 256 KiB) raise: True | 100000 unclosed '[': RecursionError
3.13.13 | main thread: 9999 | worker thread: 9999 | 131072 levels (fits 256 KiB) raise: True | 100000 unclosed '[': RecursionError
3.14.8 | main thread: 116182 | worker thread: 116336 | 131072 levels (fits 256 KiB) raise: True | 100000 unclosed '[': JSONDecodeError Expecting value pos 100000
```

### r2_numbers.py

```python
"""ECMA-262 Number::toString layout over repr digits, against numbers.json and the literal set."""
import inspect, json, struct, sys
from pathlib import Path

def es(x: float) -> str:
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite")
    if x == 0:
        return "0"
    if x < 0:
        return "-" + es(-x)
    mant, _, exp = repr(x).partition("e")
    ip, _, fp = mant.partition(".")
    digits = (ip + fp).lstrip("0")
    n = len(ip) + int(exp or 0) - (len(ip + fp) - len(digits))  # decimal point position
    s = digits.rstrip("0")
    k = len(s)
    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * -n + s
    e = n - 1
    return (s if k == 1 else s[0] + "." + s[1:]) + "e" + ("+" if e >= 0 else "-") + str(abs(e))

rows = json.loads(Path(sys.argv[1]).read_text())
bad = [r for r in rows if es(struct.unpack(">d", bytes.fromhex(r["ieee754_hex"]))[0]) != r["expected"]]
print("es() lines:", len(inspect.getsource(es).splitlines()), "| numbers.json rows", len(rows), "mismatches", len(bad), bad[:3])
lits = {"1e-7": 1e-7, "1e+21": 1e21, "0.000001": 1e-6, "123456789012345680000": 123456789012345680000.0, "5e-324": 5e-324}
print("literals:", {want: (es(v), repr(v), es(v) == want) for want, v in lits.items()})
```

Run as `r2_numbers.py $REPO/spec/v1.0/fixtures/vectors/jcs/numbers.json`, under 3.11.16 then 3.14.8:

```
es() lines: 21 | numbers.json rows 10000 mismatches 0 []
literals: {'1e-7': ('1e-7', '1e-07', True), '1e+21': ('1e+21', '1e+21', True), '0.000001': ('0.000001', '1e-06', True), '123456789012345680000': ('123456789012345680000', '1.2345678901234568e+20', True), '5e-324': ('5e-324', '5e-324', True)}
es() lines: 21 | numbers.json rows 10000 mismatches 0 []
literals: {'1e-7': ('1e-7', '1e-07', True), '1e+21': ('1e+21', '1e+21', True), '0.000001': ('0.000001', '1e-06', True), '123456789012345680000': ('123456789012345680000', '1.2345678901234568e+20', True), '5e-324': ('5e-324', '5e-324', True)}
```

### main.go (Go 1.26.9, scratch module)

```go
// Go-side comparisons for the Python plan: encoding/json escapes, ParseFloat edges.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"runtime"
	"strconv"
)

func main() {
	fmt.Println("go", runtime.Version())
	b, _ := json.Marshal(map[string]string{"s": "a\u2028b\u2029c"})
	fmt.Printf("json.Marshal U+2028 U+2029: %s\n", b)
	for _, s := range []string{"1e-400", "1e400", "-0.0", "2.5e-324", "5e-324", "2.4e-324", "1.7976931348623157e308", "1.7976931348623159e308"} {
		f, err := strconv.ParseFloat(s, 64)
		fmt.Printf("ParseFloat(%q) = %v signbit %v err %v\n", s, f, math.Signbit(f), err)
	}
}
```

```
go go1.26.9
json.Marshal U+2028 U+2029: {"s":"a\u2028b\u2029c"}
ParseFloat("1e-400") = 0 signbit false err <nil>
ParseFloat("1e400") = +Inf signbit false err strconv.ParseFloat: parsing "1e400": value out of range
ParseFloat("-0.0") = -0 signbit true err <nil>
ParseFloat("2.5e-324") = 5e-324 signbit false err <nil>
ParseFloat("5e-324") = 5e-324 signbit false err <nil>
ParseFloat("2.4e-324") = 0 signbit false err <nil>
ParseFloat("1.7976931348623157e308") = 1.7976931348623157e+308 signbit false err <nil>
ParseFloat("1.7976931348623159e308") = +Inf signbit false err strconv.ParseFloat: parsing "1.7976931348623159e308": value out of range
```

### Facts

| Plan fact (2026-10-16) | 2026-10-19 | Evidence |
|---|---|---|
| Surrogate scan 0.06 ms on 256 KiB | reproduced on escape-free text: 0.05 ms (3.11.16), 0.11 ms (3.14.8); 0.53 and 0.72 ms with 711 pairs | Q7 |
| `RecursionError` first raised at nesting 995 under the default limit | not reproduced as a fixed value. On 3.11.16 it depends on the caller's stack: 994 from these programs (one frame deeper than a direct call), 991 on a worker thread. On 3.12.13 and 3.13.13: 9998 and 9999. On 3.14.8: 116 182 (main thread) and 116 336 (worker thread). Every interpreter raised it at 131 072 levels, the most a 256 KiB document can open; 100 000 unclosed `[` gave `RecursionError` up to 3.13 and `JSONDecodeError` "Expecting value" at position 100000 on 3.14.8 | `r1_facts.py`, `r1b_depth.py` |
| A 5000-digit literal raises `ValueError` from the digit limit, not `JSONDecodeError` | reproduced on both: `ValueError`, not an instance of `JSONDecodeError`, "Exceeds the limit (4300 digits)"; a `parse_int` hook receives the text first (`[5000]`) | `r1_facts.py` |
| `urlsafe_b64decode`, `b64decode(validate=True)` and `a2b_base64(strict_mode=True)` accept `AB`; `urlsafe_b64decode` skips newlines | reproduced for the padded form: all three (and `b64decode(altchars=b"-_", validate=True)`) return `b'\x00'` for `AB==`; unpadded `AB` raises `binascii.Error: Incorrect padding` in all of them. `urlsafe_b64decode` skipped the newline in `A\nQ==`; the other three refused it. `urlsafe_b64decode` also accepted the standard alphabet (`A+/A`) | `r1_facts.py` |
| `json.dumps` leaves U+2028 and U+2029 raw; Go's `encoding/json` escapes them | reproduced: raw with `ensure_ascii=False` (the plan's setting), escaped only with `ensure_ascii=True`; Go 1.26.9 `json.Marshal` wrote `\u2028` and `\u2029` | `r1_facts.py`, `main.go` |
| Go `ParseFloat`: `1e-400` gives 0 without error, `1e400` errors; Python gives `0.0` and `inf`; `-0.0` is negative zero in both; `2.5e-324` becomes `5e-324` | reproduced: Go `0 <nil>`, `+Inf value out of range`, `-0` with sign bit, `5e-324`; Python `0.0`, `inf`, `-0.0` with sign, `5e-324`; also agree on `2.4e-324` (0), the largest double and its overflow | `r1_facts.py`, `main.go` |
| A 25-line layout of `repr` digits matched all 10 000 `numbers.json` rows and `1e-7`, `1e+21`, `0.000001`, `123456789012345680000`, `5e-324` | reproduced with an independent 21-line `es()`: 0 mismatches over 10 000 rows, all five literals, on both interpreters | `r2_numbers.py` |

## Not run locally (phase-2 probes)

- `MISE_PYTHON_VERSION` on a GitHub Actions runner with `jdx/mise-action@v2` (Q10). Recorded from the mise documentation and a local analogue only.
- Platforms other than macOS arm64: the wheel is pure Python (`py3-none-any`), but the runtime set's compiled wheels and the hashed constraints of Q11 were resolved for macOS arm64 only.

## Binding helpers: server facts, 2026-10-19

`hop_top_pact.core.binding.from_asgi` and `from_wsgi` build a `RawRequest` from what a server hands an application. Neither is on the conformance path, which reads the vectors' request objects with `decode_request`. This section records the server facts the helpers rely on, each with the source read on 2026-10-19, and the facts still to probe against real servers.

### Facts and sources

| Fact | Source |
|---|---|
| ASGI `raw_path` is a byte string, "the original HTTP path component, excluding any query string, unmodified from the bytes that were received by the web server"; it is optional and defaults to `None`. `path` has percent-encodings and UTF-8 decoded. | [ASGI HTTP and WebSocket specification](https://asgi.readthedocs.io/en/latest/specs/www.html), version 2.5, HTTP connection scope |
| ASGI `query_string` is the byte string after the `?`, percent-encoded. An empty query and no query give the same value, so a scope cannot carry `/a?`. | same |
| ASGI `headers` are `[name, value]` byte pairs, "the exact byte sequences sent by the client"; the order of values is preserved and duplicates are kept; names should be lowercased, which is not required. | same |
| An ASGI server de-chunks a chunked request body and presents plain body bytes; the application concatenates the `body` of the `http.request` messages while `more_body` is true. | same, `http.request` and the transfer-encoding notes |
| WSGI `environ` strings are native strings holding only code points representable in ISO-8859-1. | [PEP 3333](https://peps.python.org/pep-3333/), Unicode issues |
| WSGI defines no raw request-target: `PATH_INFO` is decoded, `QUERY_STRING`, `CONTENT_TYPE` and `CONTENT_LENGTH` may be empty or absent, and the URL reconstruction "may not be precisely the same URI as requested by the client". PEP 3333 does not mention `REQUEST_URI` or `RAW_URI`, nor how repeated header fields are combined. | same, environ variables and URL reconstruction |
| A WSGI application should not read more than `CONTENT_LENGTH` octets of `wsgi.input`; the server decodes any inbound transfer coding, chunked included. | same, input stream and hop-by-hop headers |
| gunicorn sets `RAW_URI` to `req.uri`; it builds `HTTP_` keys by replacing `-` with `_` and joins a repeated header as `"%s,%s"` (a comma without a space); `CONTENT-TYPE` and `CONTENT-LENGTH` go to `CONTENT_TYPE` and `CONTENT_LENGTH`. | [gunicorn/http/wsgi.py](https://github.com/benoitc/gunicorn/blob/master/gunicorn/http/wsgi.py), `default_environ` and `create` (master) |
| nginx's `uwsgi_params` passes `REQUEST_URI` as `$request_uri`, the "full original request URI (with arguments)"; `$uri` is normalized (decoded, dot segments resolved, slashes merged). | [nginx conf/uwsgi_params](https://github.com/nginx/nginx/blob/master/conf/uwsgi_params); [ngx_http_core_module](https://nginx.org/en/docs/http/ngx_http_core_module.html), embedded variables |
| The standard library's `wsgiref.simple_server.WSGIRequestHandler.get_environ` sets neither `RAW_URI` nor `REQUEST_URI`, unquotes `PATH_INFO` as ISO-8859-1, strips header values, joins a repeated header with `,`, and sets `CONTENT_TYPE` to `text/plain` when the request has no Content-Type. `http.server` decodes the request line and the header block as ISO-8859-1 and reduces a target that starts with `//` to a single `/` (gh-87389). | CPython 3.14.8 sources of `wsgiref/simple_server.py`, `http/server.py` (`parse_request`) and `http/client.py` (`_parse_header_lines`), read from the installed interpreter |

### What the helpers do with them

- `from_asgi` uses `raw_path`, then `?` and `query_string` when it is not empty; it never reads `path`, and refuses a scope without `raw_path` with `Rule.TARGET_FORM`. Header values are read as UTF-8 with `surrogateescape`, so an octet that is not UTF-8 survives as a lone surrogate and `from_request` refuses the header with `Rule.HEADER_VALUE` when it is covered.
- `from_wsgi` uses `RAW_URI`, else `REQUEST_URI`, else refuses with `Rule.TARGET_FORM` ("no raw request-target"); it never rebuilds a target from `PATH_INFO`. Environ strings are turned back into their ISO-8859-1 octets and read as UTF-8 with `surrogateescape`. Each `HTTP_` variable, `CONTENT_TYPE` and `CONTENT_LENGTH` (when not empty) is one field line. The body is `CONTENT_LENGTH` octets, or, without one, `wsgi.input` to its end when `HTTP_TRANSFER_ENCODING` is present; `max_body` bounds the read.
- Known divergences from the baseline normalization, by construction: under gunicorn and `wsgiref`, two field lines of one header reach the binding as one value joined with `,`, where the baseline joins with `, ` (vector `bind-16-repeated-header` would bind another digest); `wsgiref` adds a `text/plain` content type the client never sent; an ASGI scope binds `/a?` as `/a`.

### To probe

1. ASGI servers (uvicorn with h11 and with httptools, hypercorn, daphne): what `raw_path` holds for an absolute-form target; whether a `#` fragment reaches `raw_path` or `query_string` or is dropped or refused; whether header value octets above 0x7F pass unchanged; whether header names keep their case.
2. gunicorn: whether `RAW_URI` is the request-line target octet for octet (fragment, absolute-form, leading `//`); how header octets are decoded into native strings; how a header name with `_` is handled, since it maps to the same `HTTP_` key as the one with `-`; whether a chunked request arrives without `CONTENT_LENGTH`, with `HTTP_TRANSFER_ENCODING` set and a de-chunked `wsgi.input`.
3. uWSGI behind nginx: whether `REQUEST_URI` is `$request_uri` unchanged, and how nginx treats a fragment or an absolute-form target before it.
4. The ASGI TLS extension as a source for `RawRequest.tls_peer`; `from_asgi` sets none.
