# Rust SDK primitive probes

Probe record, 2026-10-16. Purpose: choose the crates for the Rust core SDK before anything is pinned. Facts come first: each one names the program that produced it and the observed output is pasted verbatim. Rust's standard library has no ECDSA, SHA-256, base64, JSON, canonicalization or schema validation, so every primitive ends in a crate or in code written here. A crate is chosen only where nothing built from the standard library, or from a crate the SDK needs anyway, passed its probe; where an in-house routine passed, the crate that could replace it is named as the alternative. Where a probe contradicted what was expected, the contradiction is recorded in the section's "Departures" list. The decision table and the open design questions are at the end.

The rules being probed come from [`spec/v1.0/draft.md`](../../../spec/v1.0/draft.md): section 6.2 (`holder_jkt` is the RFC 7638 thumbprint), 7.1 (reject duplicate property names, non-finite numbers, invalid Unicode and unknown core fields; integers `0..9007199254740991`), 7.2 (baseline `ES256`), 7.4 (`object_digest` over RFC 8785) and 22.2 (cross-language tests cover JCS ordering and number serialization, JOSE signature encoding and JWK thumbprints). The sibling records are [`ts.md`](ts.md) and [`py.md`](py.md); the questions and fixtures are the same, so results can be compared across languages.

## Environment

- Toolchain: `rustc 1.99.0 (b940084d7 2026-09-28)` and `cargo 1.99.0 (5f94df478 2026-08-27)`, Homebrew builds, host `aarch64-apple-darwin`, macOS 15.6.1. 1.99.0 is the version of the `rust` pin in `mise.toml`. cargo was reached through the mise shim with the repository's mise configuration ignored (`MISE_IGNORED_CONFIG_PATHS`). `rustfmt` and `clippy` were not run: the programs are probes.
- Isolation: every probe is its own crate in a scratch directory outside the repository, with `CARGO_HOME` inside that directory, so the registry cache is throwaway too. Nothing was installed (no `cargo install`, no `rustup`, no toolchain, no global change). The repository gained no `Cargo.toml` and no `Cargo.lock`; only `docs/sdk/probes/rs/` and this file.
- Untrusted code: every crate was fetched from crates.io and treated as untrusted. `cargo build` and `cargo run` execute the build scripts of the crates in the tree; the crates that have one are listed with the dependency counts below. `cargo metadata`, `cargo tree` and `cargo info` fetch index data and `.crate` files and build nothing.
- Network use: the crates.io index and downloads, RFC text from rfc-editor.org (read only), the crates.io metadata API (read only). The Q5 programs ran as built binaries under a macOS sandbox profile that denies network access, `sandbox-exec -p '(version 1)(allow default)(deny network*)' <binary>`. The same profile stops `curl -sS -m 5 -o /dev/null https://crates.io`:

```text
curl: (6) Could not resolve host: crates.io
```

Test vectors come from the RFC text and from the repository fixtures: RFC 7515 Appendix A.3, RFC 6979 Appendix A.2.5, RFC 7638 section 3.1, RFC 8037 Appendix A.3, RFC 8785 sections 3.2.2 to 3.2.4 and Appendix B, `spec/v1.0/fixtures/keys/*.jwk.json`, `spec/v1.0/fixtures/keys/test-private-scalars.json`, `spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws`, `spec/v1.0/fixtures/vectors/jcs/` (six input and output pairs and the 10000-row `numbers.json`), the 36 vectors in `spec/v1.0/fixtures/vectors/strictjson/` and `spec/v1.0/schemas/pact.schema.json`.

### Crates and programs

Each crate is a scratch crate whose `[dependencies]` are below, with exact (`=`) versions. A program is copied to `<crate>/examples/<name>.rs`; `q3_lib.rs` and `q4_lib.rs` are the `src/lib.rs` of their crates. Programs read the repository through the `REPO` variable, so they run from any directory:

```sh
export REPO=$PWD CARGO_HOME=$SCRATCH/cargo-home
cd $SCRATCH/crates/q1-p256 && cargo run -q --example q1_es256
```

| Crate | Programs (lines) |
|---|---|
| `q1-p256` | [q1_es256](rs/q1_es256.rs) (20), [q1b_fixture](rs/q1b_fixture.rs) (18), [q1c_rfc6979](rs/q1c_rfc6979.rs) (20), [q1d_malformed](rs/q1d_malformed.rs) (12), [q1e_base64](rs/q1e_base64.rs) (16) |
| `q1-ring` | [q1f_ring](rs/q1f_ring.rs) (18), [q1g_ring_fixture](rs/q1g_ring_fixture.rs) (14), [q1h_ring_highs](rs/q1h_ring_highs.rs) (15), [q1i_ring_malformed](rs/q1i_ring_malformed.rs) (12) |
| `q2-jwk` | [q2_thumbprint](rs/q2_thumbprint.rs) (20), [q2b_fixtures](rs/q2b_fixtures.rs) (16), [q2c_jwk_p256](rs/q2c_jwk_p256.rs) (20) |
| `q2-jwk-013` | [q2d_jwk_013](rs/q2d_jwk_013.rs) (19) |
| `q3-json` | [q3_lib](rs/q3_lib.rs) (78, the strict checker under test), [q3_defaults](rs/q3_defaults.rs) (13), [q3b_vectors](rs/q3b_vectors.rs) (18), [q3c_float_parse](rs/q3c_float_parse.rs) (15) |
| `q3-derive` | [q3d_decode](rs/q3d_decode.rs) (20), [q3e_ap_effects](rs/q3e_ap_effects.rs) (16) |
| `q4-jcs` | [q4_lib](rs/q4_lib.rs) (79, the in-house canonicalizer under test), [q4_numbers](rs/q4_numbers.rs) (14), [q4b_numbers10k](rs/q4b_numbers10k.rs) (20), [q4c_document](rs/q4c_document.rs) (15), [q4d_domain](rs/q4d_domain.rs) (13) |
| `q5-jsonschema` | [q5_jsonschema](rs/q5_jsonschema.rs) (19), [q5b_jsonschema_formats](rs/q5b_jsonschema_formats.rs) (19), [q5c_jsonschema_patterns](rs/q5c_jsonschema_patterns.rs) (15) |
| `q5-boon` | [q5d_boon](rs/q5d_boon.rs) (20), [q5e_boon_formats](rs/q5e_boon_formats.rs) (18), [q5f_boon_patterns](rs/q5f_boon_patterns.rs) (17) |
| none (shell) | [q6_setup.sh](rs/q6_setup.sh) (8), [q6_package.sh](rs/q6_package.sh) (13), [q6b_vcs_license.sh](rs/q6b_vcs_license.sh) (10) |
| none (counts) | [depcount.sh](rs/depcount.sh) (30, of which 20 are the dependency lines), [depstat.py](rs/depstat.py) (11) |

The task asked for one program of 20 lines or fewer per question. Every question needed more than one, so each program answers one sub-question in 20 lines or fewer. The two library files and the dependency list are longer; they are the code under test and the data of the count.

Manifests (`[dependencies]` and `[features]` only; `[package]` is `name`, `version = "0.0.0"`, `edition = "2021"`, `publish = false`):

```toml
# q1-p256
p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa", "getrandom", "pkcs8"] }
base64 = "=0.23.1"
serde_json = "=1.0.154"
# q1-ring
ring = "=0.17.14"
base64 = "=0.23.1"
serde_json = "=1.0.154"
# q2-jwk
p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa", "getrandom"] }
sha2 = "=0.11.1"
base64 = "=0.23.1"
serde_json = "=1.0.154"
# q2-jwk-013
p256 = { version = "=0.13.2", default-features = false, features = ["ecdsa", "jwk"] }
serde_json = "=1.0.154"
# q3-json
serde = "=1.0.229"
serde_json = "=1.0.154"
base64 = "=0.23.1"
[features]
ap = ["serde_json/arbitrary_precision"]
fr = ["serde_json/float_roundtrip"]
# q3-derive
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.154"
q3-json = { path = "../q3-json" }
base64 = "=0.23.1"
[features]
ap = ["q3-json/ap", "serde_json/arbitrary_precision"]
# q4-jcs
serde_json = { version = "=1.0.154", features = ["float_roundtrip"] }
serde_jcs = "=0.2.0"
serde_json_canonicalizer = "=0.4.1"
ryu = "1"
[features]
po = ["serde_json/preserve_order"]
# q5-jsonschema
jsonschema = { version = "=0.58.6", default-features = false }
serde_json = "=1.0.154"
base64 = "=0.23.1"
# q5-boon
boon = "=0.6.1"
serde_json = "=1.0.154"
base64 = "=0.23.1"
```

## Q1. ES256 over P-256 (RFC 7515, RFC 7518 section 3.4)

### q1_es256.rs, crate q1-p256

```text
round trip true raw lens {64} DER lens {69, 70, 71, 72} | one message signed 5000 times: 1 distinct
tampered msg false 63 bytes false 65 bytes false
RFC 7515 A.3 verifies true sig bytes 64 tampered input false
```

### q1b_fixture.rs, crate q1-p256

```text
header {"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"} sig bytes 64 verifies true other payload false
off-curve point rejected: signature error
```

### q1c_rfc6979.rs, crate q1-p256

```text
RFC 6979 A.2.5 SHA-256 "sample": r||s matches true
RFC 6979 A.2.5 SHA-256 "test": r||s matches true
scalar 2 re-sign of Appendix C input == fixture signature false | verifies true
high-S twin (n-s) differs true | verifies true | normalize_s restores true
```

### q1d_malformed.rs, crate q1-p256

```text
all zero     from_slice Err("signature error") | verify false
r = n        from_slice Err("signature error") | verify false
s = n        from_slice Err("signature error") | verify false
r = 0        from_slice Err("signature error") | verify false
r = 2^256-1  from_slice Err("signature error") | verify false
good         from_slice Ok("Ok") | verify true
```

### q1e_base64.rs, crate q1-p256, `--release`

```text
valid 'AAA'                crate Some([0, 0]) in-house Some([0, 0])
padding 'AA=='             crate None in-house None
std alphabet 'A+/A'        crate None in-house None
newline 'AA\nA'            crate None in-house None
trailing bits 'AB'         crate None in-house None
length 5 mod 4 'AAAAA'     crate None in-house None
non-ASCII                  crate None in-house None
1000000 random strings, 253568 accepted by the crate; disagreements with the in-house decoder: 0
```

### q1f_ring.rs, crate q1-ring

```text
RFC 7515 A.3 verifies true sig bytes 64 tampered input false
round trip true raw lens {64} | one message signed 5000 times: 5000 distinct
63 bytes false 65 bytes false tampered msg false
```

### q1g_ring_fixture.rs, crate q1-ring

```text
Appendix C verifies true other payload false
issuer x with holder y (off-curve) verifies false
```

### q1h_ring_highs.rs, crate q1-ring

```text
original verifies true | high-S twin (n-s) differs true verifies true
```

### q1i_ring_malformed.rs, crate q1-ring

```text
all zero     verify Err("ring::error::Unspecified")
r = n        verify Err("ring::error::Unspecified")
s = n        verify Err("ring::error::Unspecified")
r = 0        verify Err("ring::error::Unspecified")
r = 2^256-1  verify Err("ring::error::Unspecified")
empty        verify Err("ring::error::Unspecified")
good         verify Ok("Ok")
```

### Facts

- `p256` 0.14.0 (RustCrypto, feature `ecdsa`): `SigningKey::sign` returns an `ecdsa::Signature`, the fixed-size r and s. `to_bytes()` was 64 bytes in 5000 of 5000 signatures (`raw lens {64}`). The DER form (`to_der()`, available in the probe crate because it enables `pkcs8`, which turns on `ecdsa`'s `der` feature) varied from 69 to 72 bytes, so DER is not usable as a JWS signature. No conversion step exists or is needed.
- The round trip verified 5000 of 5000. A modified message failed. `Signature::from_slice` itself rejected the 63-byte and 65-byte inputs: the library never sees a length other than 64, and the probe has no length test of its own.
- RFC 6979: signing one message 5000 times gave 1 distinct signature, and both RFC 6979 Appendix A.2.5 P-256 and SHA-256 vectors ("sample" and "test") matched byte for byte (q1c_rfc6979). `p256` signs deterministically by default, with no flag.
- The RFC 7515 Appendix A.3 signature verified, and failed when the signing input gained one byte. The compact JWS in `appendix-c-wrong-version.jws` verified under `issuer.jwk.json`; its header decodes to `{"alg":"ES256","typ":"pact-evidence+jwt","kid":"test-issuer-key-1"}`; the same signature failed over another payload.
- Re-signing the Appendix C signing input with the fixture's private scalar 2 (from `test-private-scalars.json`) gave a signature that verifies but is not the signature in the fixture (`== fixture signature false`). The fixture signature was therefore not produced by an RFC 6979 signer of this kind. A cross-language fixture can only be checked by verification, never by re-signing and comparing bytes.
- An off-curve JWK point (the issuer `x` with the holder `y`) was rejected when the `VerifyingKey` was built. The error text is `signature error`: it carries no reason.
- Malformed signatures: all-zero, `r = n`, `s = n`, `r = 0` and `r = 2^256 - 1` were rejected by `Signature::from_slice` (q1d_malformed).
- Malleability: the high-S twin `(r, n - s)` of a signature differs from it and verifies (q1c_rfc6979: `high-S twin (n-s) differs true | verifies true`). `p256` 0.14.0 sets `NORMALIZE_S = false` for `NistP256` in its `src/ecdsa.rs`. A `normalize_s` method exists and restored the low-S form. Verification therefore does not reject high-S; rejecting it would be an explicit SDK check.
- `ring` 0.17.14, `ECDSA_P256_SHA256_FIXED` and `ECDSA_P256_SHA256_FIXED_SIGNING`: signatures are 64 bytes (`raw lens {64}`), the A.3 vector and the Appendix C fixture verify, and one message signed 5000 times gave 5000 distinct signatures (random nonces; the source comment says the message digest is mixed into the nonce to hedge a faulty random source). There is no deterministic mode. The signing key was built with `EcdsaKeyPair::from_private_key_and_public_key`, which needs the 65-byte public point as well as the scalar. 63 and 65 byte signatures, an empty signature and the malformed scalars were rejected at verify time with `ring::error::Unspecified`; the high-S twin verifies here too (q1h_ring_highs).
- `ring` has no public key validation step: a public key with a foreign `y` is only seen as a failed verification (`off-curve key verifies false`), indistinguishable from a bad signature.
- base64url: the standard library has none. `base64` 0.23.1 with `URL_SAFE_NO_PAD` rejected padding (`AA==`), the standard alphabet (`A+/A`), a newline, non-canonical trailing bits (`AB`), a length of 1 mod 4 and non-ASCII input. A 7-line in-house strict decoder (the `dec` function in q1e_base64.rs) agreed with the crate on all of these and on 1,000,000 random strings, 253,568 of which the crate accepted.

### Departures from the expectation

- The task names `p256::ecdsa` and the `jwk` feature, which describe the 0.13 series. The current release, `p256` 0.14.0 (published 2026-07-03), has a different API (`Sec1Point`, `to_sec1_point`, `Generate` for key generation) and sits on `ecdsa` 0.17.0, `signature` 3.0.0, `digest` 0.11.3 and `sha2` 0.11.1. The probes use 0.14.0 as resolved on 2026-10-16.
- Determinism holds as the task expected (RFC 6979 by default, unlike Go's randomized signatures). The consequence for fixtures is the one noted above: signature bytes cannot be shared between SDKs except as verification inputs.

## Q2. JWK and RFC 7638 thumbprint

### q2_thumbprint.rs, crate q2-jwk

```text
holder xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M == expected: true
kid/alg/use ignored: true | extra member ignored: true
RFC 7638 3.1 NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs == expected: true
missing required member y -> Err("missing member y") | unknown kty -> Err("unsupported kty Some(\"oct\")")
```

### q2b_fixtures.rs, crate q2-jwk

```text
  adversarial.jwk.json B3zQUJfL8WPQJT3fRc_9F85aNjqoqRkk-HMzwyAp7WU
  ed25519.jwk.json kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
  holder.jwk.json xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M
  issuer.jwk.json AhqHzaYXA5MzmDCrsseUsVBGKyfhDhvekx0THjH_xIE
  learning-controller.jwk.json yiaHWTOH-NAS43bw6yPHO8YTK_T9cLz9jZaCu3qOg_k
  reputation-service.jwk.json BcYkeRReg8Py6HmUFJw6240ruOKnvInXb5rRtK6Z9xQ
  validator.jwk.json uhdbksqePVMcTx2Fvr5RY78RjuSE2bd16nNAkdfZ36I
RFC 8037 A.3 Ed25519 thumbprint matches: true
```

### q2c_jwk_p256.rs, crate q2-jwk

```text
  holder scalar 1 -> x,y == jwk true
  issuer scalar 2 -> x,y == jwk true
  adversarial scalar 3 -> x,y == jwk true
  reputation-service scalar 4 -> x,y == jwk true
  learning-controller scalar 5 -> x,y == jwk true
  validator scalar 6 -> x,y == jwk true
5000 random keys: base64url (x, y) lengths {(43, 43)} (43 chars = 32 bytes)
x(32)+y(32): naive true strict true | x(31)+y(33), same 64 bytes: naive true strict false
```

### q2d_jwk_013.rs, crate q2-jwk-013 (`p256` 0.13.2 with its `jwk` feature)

```text
issuer.jwk.json
  as shipped (kid, alg, use present): Err("crypto error")
  four members only: Ok("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg\",\"y\":\"B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E\"}")
  hand-built:        Ok("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"fPJ7GI0DT36KUjgDBLUaw8CJaeJ38hs1pgtI_EdmmXg\",\"y\":\"B3dVENuO0EApPZrGn3Qw27p9reY86YIpngS3nSJ4c9E\"}")
holder.jwk.json
  as shipped (kid, alg, use present): Err("crypto error")
  four members only: Ok("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY\",\"y\":\"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU\"}")
  hand-built:        Ok("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY\",\"y\":\"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU\"}")
foreign y (off-curve): Err("crypto error")
42-char x: Err("crypto error")
crv P-384: Err("crypto error")
```

### `jwk` on `p256` 0.14.0 (crate `q2-jwk-p256-014-jwk`, `cargo build`)

Manifest: `p256 = { version = "=0.14.0", default-features = false, features = ["ecdsa", "jwk"] }`.

```text
    Updating crates.io index
error: failed to select a version for `p256`.
    ... required by package `q2-jwk-p256-014-jwk v0.0.0 ($SCRATCH/crates/q2-jwk-p256-014-jwk)`
versions that meet the requirements `=0.14.0` are: 0.14.0

package `q2-jwk-p256-014-jwk` depends on `p256` with feature `jwk` but `p256` does not have that feature.
help: there is a feature `pem` with a similar name


failed to select a version for `p256` which could resolve this conflict
```

### Facts

- The thumbprint function is 5 lines over `sha2`, `base64` and `serde_json`: the required members per `kty` in a fixed list (EC: `crv kty x y`; RSA: `e kty n`; OKP: `crv kty x`), each name and value written through `serde_json`'s string escaping, joined without whitespace, hashed with SHA-256 and written as unpadded base64url. It does not use `serde_json::Map` ordering, so enabling `preserve_order` somewhere in the dependency tree cannot change it.
- `holder.jwk.json` gives `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M`, equal to the Appendix C `holder_jkt`. The RFC 7638 section 3.1 example (an RSA key) gives `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs` and the RFC 8037 Appendix A.3 Ed25519 key gives `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`. `kid`, `alg`, `use` and an extra member did not change the result. A JWK without `y` returned `Err("missing member y")` and `kty` `oct` returned an error.
- The seven fixture thumbprints are identical to the ones in the Python record (`py.md`, "q2_thumbprint.py"): holder, issuer, adversarial, reputation-service, learning-controller, validator and ed25519.
- `p256` 0.14.0 has no `jwk` feature (and `elliptic-curve` 0.14.1 has none): cargo refuses the manifest, as above. A separate `jose-jwk` 0.1.2 crate exists (`cargo info jose-jwk`); it was not probed.
- `p256` 0.13.2 does have `jwk` (through `elliptic-curve` 0.13.8, `ecdsa` 0.16.9, `sha2` 0.10.9). `PublicKey::from_jwk_str` rejected both fixture JWKs as shipped (`Err("crypto error")`): `elliptic-curve` 0.13.8 `src/jwk.rs` accepts only the members `kty`, `crv`, `x`, `y` and `d` and returns `unknown_field` for anything else, and every fixture carries `kid`, `alg` and `use`. With those three removed it parsed. Its `to_jwk_string` wrote the members in the order `kty, crv, x, y`, not the lexicographic `crv, kty, x, y` that RFC 7638 needs, so its output cannot be hashed as the thumbprint input. An off-curve `y`, a 42-character `x` and `crv` `P-384` were all rejected with the same text, `crypto error`.
- JWK to key with `p256` 0.14.0 and no JWK feature: the six P-256 fixture scalars (1 to 6 in `test-private-scalars.json`) derive public points equal to the `x` and `y` of the fixtures. 5000 random keys exported `x` and `y` as 43 characters (32 bytes) each; no coordinate lost a leading zero.
- A loader that concatenates the decoded `x` and `y` before calling `VerifyingKey::from_sec1_bytes` accepts `x` of 31 bytes with `y` of 33 bytes when the 64 bytes are the same (`naive true`, same point); a per-coordinate length check of exactly 32 bytes rejects it (`strict false`). The hand-built loader must check both lengths.

### Departures from the expectation

- The task expected a `p256` `jwk` feature round trip. On the current release the feature does not exist; on the previous release it exists but cannot read the fixtures and writes the wrong member order. The hand-built path is the only one that passed.
- The RFC 7638 example is an RSA key, so the `p256` JWK types are not involved in reproducing it.

## Q3. Strict parsing: `serde_json`, `std::str::from_utf8` and a checker

`q3_lib.rs` is the checker under test: `check(bytes)` decodes with `std::str::from_utf8`, rejects a leading U+FEFF, runs a `serde::de::Visitor` over `serde_json::Deserializer` that rejects duplicate keys at every level (keys are compared after unescaping), non-finite numbers, integers outside plus or minus 9007199254740991 and nesting deeper than 16 (the root counts as depth 1), calls `Deserializer::end()` so trailing data is rejected, and, without `arbitrary_precision`, runs a lexical pass over the text for integer literals.

### q3_defaults.rs, crate q3-json, default features

Columns: the input; `stock` is `serde_json::from_slice::<Value>`; `strict` is `q3_json::check`. The last seven rows are raw bytes: `from_slice`, `str::from_utf8` and `strict` side by side.

```text
{"a":1,"a":2}                              stock {"a":2}                                                    strict REJECT duplicate key at line 1 column 10
{"a":1,"\u0061":2}                         stock {"a":2}                                                    strict REJECT duplicate key at line 1 column 15
[NaN]                                      stock REJECT expected value at line 1 column 2                   strict REJECT expected value at line 1 column 2
[Infinity]                                 stock REJECT expected value at line 1 column 2                   strict REJECT expected value at line 1 column 2
[-Infinity]                                stock REJECT invalid number at line 1 column 3                   strict REJECT invalid number at line 1 column 3
[1e999]                                    stock REJECT number out of range at line 1 column 6              strict REJECT number out of range at line 1 column 6
[-1e999]                                   stock REJECT number out of range at line 1 column 7              strict REJECT number out of range at line 1 column 7
[1e-999]                                   stock [0.0]                                                      strict ok depth 1
["\ud800"]                                 stock REJECT unexpected end of hex escape at line 1 column 9     strict REJECT unexpected end of hex escape at line 1 column 9
["\udc00"]                                 stock REJECT lone leading surrogate in hex escape at line 1 column 8 strict REJECT lone leading surrogate in hex escape at line 1 column 8
["\ud800\u0041"]                           stock REJECT lone leading surrogate in hex escape at line 1 column 14 strict REJECT lone leading surrogate in hex escape at line 1 column 14
["\ud83d\ude00"]                           stock ["😀"]                                                      strict ok depth 1
[9007199254740991]                         stock [9007199254740991]                                         strict ok depth 1
[9007199254740993]                         stock [9007199254740993]                                         strict REJECT integer above 2^53-1 at line 1 column 17
[18446744073709551615]                     stock [18446744073709551615]                                     strict REJECT integer above 2^53-1 at line 1 column 21
[18446744073709551616]                     stock [1.8446744073709552e+19]                                   strict REJECT integer literal 18446744073709551616 outside +-(2^53-1)
[123456789012345678901234567890]           stock [1.2345678901234568e+29]                                   strict REJECT integer literal 123456789012345678901234 outside +-(2^53-1)
[9007199254740993.0]                       stock [9007199254740994.0]                                       strict ok depth 1
[0.1,333333333.33333329,5e-324,1e22]       stock [0.1,333333333.33333325,5e-324,1e+22]                      strict ok depth 1
[-0,-0.0,0.0]                              stock [-0.0,-0.0,0.0]                                            strict ok depth 1
{"$serde_json::private::Number":"7"}       stock {"$serde_json::private::Number":"7"}                       strict ok depth 1
{}}                                        stock REJECT trailing characters at line 1 column 3              strict REJECT trailing characters at line 1 column 3
[1,]                                       stock REJECT trailing comma at line 1 column 4                   strict REJECT trailing comma at line 1 column 4
[1] [2]                                    stock REJECT trailing characters at line 1 column 5              strict REJECT trailing characters at line 1 column 5
128 nested arrays                          stock REJECT recursion limit exceeded at line 1 column 128       strict REJECT nesting depth above 16 at line 1 column 17
129 nested arrays                          stock REJECT recursion limit exceeded at line 1 column 128       strict REJECT nesting depth above 16 at line 1 column 17
100000 nested arrays                       stock REJECT recursion limit exceeded at line 1 column 128       strict REJECT nesting depth above 16 at line 1 column 17
ff                                         from_slice REJECT expected value at line 1 column 1 | str::from_utf8 REJECT invalid utf-8 sequence of 1 bytes from index 0 | strict REJECT utf-8: invalid utf-8 sequence of 1 bytes from index 0
overlong c0 af in string                   from_slice REJECT invalid unicode code point at line 1 column 3 | str::from_utf8 REJECT invalid utf-8 sequence of 1 bytes from index 2 | strict REJECT utf-8: invalid utf-8 sequence of 1 bytes from index 2
truncated e2 82 in string                  from_slice REJECT invalid unicode code point at line 1 column 3 | str::from_utf8 REJECT invalid utf-8 sequence of 2 bytes from index 2 | strict REJECT utf-8: invalid utf-8 sequence of 2 bytes from index 2
encoded surrogate ed a0 80                 from_slice REJECT invalid unicode code point at line 1 column 3 | str::from_utf8 REJECT invalid utf-8 sequence of 1 bytes from index 2 | strict REJECT utf-8: invalid utf-8 sequence of 1 bytes from index 2
out of range f4 90 80 80                   from_slice REJECT invalid unicode code point at line 1 column 3 | str::from_utf8 REJECT invalid utf-8 sequence of 1 bytes from index 2 | strict REJECT utf-8: invalid utf-8 sequence of 1 bytes from index 2
BOM + {}                                   from_slice REJECT expected value at line 1 column 1 | str::from_utf8 Ok("\u{feff}{}") | strict REJECT byte order mark
UTF-16LE {}                                from_slice REJECT expected value at line 1 column 1 | str::from_utf8 REJECT invalid utf-8 sequence of 1 bytes from index 0 | strict REJECT utf-8: invalid utf-8 sequence of 1 bytes from index 0
```

### q3_defaults.rs, `--features fr`: rows that differ from the default run (`-` default, `+` with the feature)

```text
-[9007199254740993.0]                       stock [9007199254740994.0]                                       strict ok depth 1
-[0.1,333333333.33333329,5e-324,1e22]       stock [0.1,333333333.33333325,5e-324,1e+22]                      strict ok depth 1
+[9007199254740993.0]                       stock [9007199254740992.0]                                       strict ok depth 1
+[0.1,333333333.33333329,5e-324,1e22]       stock [0.1,333333333.3333333,5e-324,1e+22]                       strict ok depth 1
```

### q3_defaults.rs, `--features ap`: rows that differ from the default run (`-` default, `+` with the feature)

```text
-[1e999]                                    stock REJECT number out of range at line 1 column 6              strict REJECT number out of range at line 1 column 6
-[-1e999]                                   stock REJECT number out of range at line 1 column 7              strict REJECT number out of range at line 1 column 7
-[1e-999]                                   stock [0.0]                                                      strict ok depth 1
+[1e999]                                    stock [1e+999]                                                   strict REJECT non-finite number at line 1 column 6
+[-1e999]                                   stock [-1e+999]                                                  strict REJECT non-finite number at line 1 column 7
+[1e-999]                                   stock [1e-999]                                                   strict ok depth 1
-[18446744073709551616]                     stock [1.8446744073709552e+19]                                   strict REJECT integer literal 18446744073709551616 outside +-(2^53-1)
-[123456789012345678901234567890]           stock [1.2345678901234568e+29]                                   strict REJECT integer literal 123456789012345678901234 outside +-(2^53-1)
-[9007199254740993.0]                       stock [9007199254740994.0]                                       strict ok depth 1
-[0.1,333333333.33333329,5e-324,1e22]       stock [0.1,333333333.33333325,5e-324,1e+22]                      strict ok depth 1
-[-0,-0.0,0.0]                              stock [-0.0,-0.0,0.0]                                            strict ok depth 1
-{"$serde_json::private::Number":"7"}       stock {"$serde_json::private::Number":"7"}                       strict ok depth 1
+[18446744073709551616]                     stock [18446744073709551616]                                     strict REJECT integer above 2^53-1 at line 1 column 21
+[123456789012345678901234567890]           stock [123456789012345678901234567890]                           strict REJECT integer above 2^53-1 at line 1 column 31
+[9007199254740993.0]                       stock [9007199254740993.0]                                       strict ok depth 1
+[0.1,333333333.33333329,5e-324,1e22]       stock [0.1,333333333.33333329,5e-324,1e+22]                      strict ok depth 1
+[-0,-0.0,0.0]                              stock [-0,-0.0,0.0]                                              strict ok depth 1
+{"$serde_json::private::Number":"7"}       stock 7                                                          strict ok depth 0
```

### q3b_vectors.rs, crate q3-json: default features, then `--features ap`

```text
36 vectors: 34 agree with expect, 2 disagree
  unknown-core-field-case-variant: expected reject, got Ok(2)
  unknown-core-field: expected reject, got Ok(2)
```

```text
36 vectors: 34 agree with expect, 2 disagree
  unknown-core-field-case-variant: expected reject, got Ok(2)
  unknown-core-field: expected reject, got Ok(2)
```

### q3c_float_parse.rs, crate q3-json, `--release`: default features, `--features fr`, `--features ap`

```text
  e.g. -3.3333333333333335e-7 want bits be965e9f80f29212 from_str::<f64> be965e9f80f29213 Value::as_f64 be965e9f80f29213
  e.g. -3.333333333333333e-10 want bits bdf6e80fe033c8c6 from_str::<f64> bdf6e80fe033c8c5 Value::as_f64 bdf6e80fe033c8c5
  e.g. -3.3333333333333334e-13 want bits bd5774ccac3d3817 from_str::<f64> bd5774ccac3d3818 Value::as_f64 bd5774ccac3d3818
10000 rows, bits differ from ieee754_hex: std str::parse 0 | serde_json::from_str::<f64> 2709 | serde_json Value::as_f64 2709
```

```text
10000 rows, bits differ from ieee754_hex: std str::parse 0 | serde_json::from_str::<f64> 0 | serde_json Value::as_f64 0
```

```text
  e.g. -3.3333333333333335e-7 want bits be965e9f80f29212 from_str::<f64> be965e9f80f29213 Value::as_f64 be965e9f80f29212
  e.g. -3.333333333333333e-10 want bits bdf6e80fe033c8c6 from_str::<f64> bdf6e80fe033c8c5 Value::as_f64 bdf6e80fe033c8c6
  e.g. -3.3333333333333334e-13 want bits bd5774ccac3d3817 from_str::<f64> bd5774ccac3d3818 Value::as_f64 bd5774ccac3d3817
10000 rows, bits differ from ieee754_hex: std str::parse 0 | serde_json::from_str::<f64> 2709 | serde_json Value::as_f64 0
```

### q3d_decode.rs, crate q3-derive: default features, then `--features ap`

```text
36 vectors | struct decode alone disagrees on 7:
  duplicate-key-in-headers: expected reject, decode alone accepted
  duplicate-key-nested: expected reject, decode alone accepted
  integer-overflow-2-pow-53: expected reject, decode alone accepted
  integer-overflow-huge: expected reject, decode alone accepted
  integer-overflow-negative: expected reject, decode alone accepted
  nesting-depth-17-arrays: expected reject, decode alone accepted
  nesting-depth-17-objects: expected reject, decode alone accepted
check + struct decode disagrees on 0: []
```

```text
36 vectors | struct decode alone disagrees on 9:
  duplicate-key-in-headers: expected reject, decode alone accepted
  duplicate-key-nested: expected reject, decode alone accepted
  integer-overflow-2-pow-53: expected reject, decode alone accepted
  integer-overflow-huge: expected reject, decode alone accepted
  integer-overflow-negative: expected reject, decode alone accepted
  nesting-depth-17-arrays: expected reject, decode alone accepted
  nesting-depth-17-objects: expected reject, decode alone accepted
  non-finite-number-1e999: expected reject, decode alone accepted
  non-finite-number-negative-1e999: expected reject, decode alone accepted
check + struct decode disagrees on 0: []
```

### q3e_ap_effects.rs, crate q3-derive: default features, then `--features ap`

```text
untagged enum from 5:            Ok(N(5))
untagged enum from "x":          Ok(S("x"))
flatten struct:                  Ok(F { a: 1, rest: {"b": Number(2)} })
plain u64 and f64 fields:        Ok(T { n: 9007199254740991, f: 1e22 })
u64 field from 1.0 / 1e2:        Err("invalid type: floating point `1.0`, expected u64 at line 1 column 8") Err("invalid type: floating point `100.0`, expected u64 at line 1 column 8")
object with the private token key: {"k":{"$serde_json::private::Number":"7"}} | is_number false is_object true
```

```text
untagged enum from 5:            Ok(N(5))
untagged enum from "x":          Ok(S("x"))
flatten struct:                  Ok(F { a: 1, rest: {"b": Number(2)} })
plain u64 and f64 fields:        Ok(T { n: 9007199254740991, f: 1e22 })
u64 field from 1.0 / 1e2:        Err("invalid type: floating point `1.0`, expected u64 at line 1 column 8") Err("invalid type: floating point `100.0`, expected u64 at line 1 column 8")
object with the private token key: {"k":7} | is_number true is_object false
```

### Facts

- Duplicate keys: `serde_json::Value` keeps the last value (`{"a":2}`), also when one key is written escaped (`{"a":1,"\u0061":2}`). The checker rejected both (`duplicate key`). A serde struct with `#[serde(deny_unknown_fields)]` rejects a duplicated known field by itself, so only maps and `Value` need the visitor: struct decode alone missed `duplicate-key-in-headers` (a `BTreeMap`) and `duplicate-key-nested` (a `Value` under `extensions`) and caught the other three duplicate vectors and both unknown-field vectors (q3d_decode).
- Non-finite numbers: `NaN`, `Infinity` and `-Infinity` are syntax errors in `serde_json`. `1e999` and `-1e999` gave `number out of range` with default features. `1e-999` is accepted as `0.0`: a finite underflow.
- Strings and Unicode: a lone surrogate escape is rejected by `serde_json` itself (`unexpected end of hex escape` for `\ud800`, `lone leading surrogate in hex escape` for `\udc00` and for `\ud800\u0041`, the library's own wording); a valid pair parses to U+1F600. A Rust `String` cannot hold a surrogate, which is why Python and TypeScript needed a post-parse check and this language does not. `std::str::from_utf8` rejected `ff`, the overlong `c0 af`, the truncated `e2 82`, the encoded surrogate `ed a0 80` and `f4 90 80 80`, and rejected UTF-16 input; it accepted the UTF-8 BOM and returned a string starting with U+FEFF (`Ok("\u{feff}{}")`). `serde_json::from_slice` rejected the BOM (`expected value at line 1 column 1`), so the explicit BOM test in `check` is a clearer message, not an additional rule.
- Integers: `serde_json` keeps `9007199254740993` and `18446744073709551615` exactly (as `u64`) and turns `18446744073709551616` and `123456789012345678901234567890` into `f64` without any error (`1.8446744073709552e+19`, `1.2345678901234568e+29`). The visitor receives an `f64` for those and cannot tell it from the equivalent float literal such as `1.2345678901234568e29`; floats of that size must be accepted (`accept-finite-float-max` is `1.7976931348623157e308`), so `integer-overflow-huge` cannot be decided from the parsed value. With `arbitrary_precision` the text is kept and the visitor decides; without it, the lexical pass over the text decides. With the lexical pass off, `integer-overflow-huge` was accepted (re-break below).
- Floats: default `serde_json` does not parse decimal strings to the nearest double: `9007199254740993.0` gave `9007199254740994.0` (the nearest double is `9007199254740992`) and `333333333.33333329` gave `333333333.33333325`. Over the 10000 `expected` strings of `numbers.json`, `serde_json::from_str::<f64>` and `Value::as_f64` returned a different double than `ieee754_hex` for 2709, and `str::parse::<f64>` for 0 (q3c_float_parse). Feature `float_roundtrip` brought both to 0. With `arbitrary_precision`, `Value::as_f64` was 0 but `from_str::<f64>` stayed at 2709.
- Minus zero: `-0` parses to the float `-0.0` (and prints `-0.0`) with default features.
- Depth: `serde_json` fails at nesting 128 (`recursion limit exceeded at line 1 column 128`) for 128, 129 and 100000 nested arrays, without a stack overflow. 16 is not configurable there; the checker enforces it (`nesting depth above 16 at line 1 column 17`).
- Trailing data: `{}}` and `[1] [2]` were rejected by `from_slice` (`trailing characters`). `check` calls `Deserializer::end()` because a `Deserializer` built by hand does not reject trailing data by itself.
- Vectors: `q3_json::check` agreed with `expect` on 34 of the 36 strict-JSON vectors with default features and with `ap`. The 2 it accepts, `unknown-core-field` and `unknown-core-field-case-variant`, are decode-level rules (member names of `OperationContext`), not JSON-level ones. In q3d_decode a serde struct with `deny_unknown_fields` rejected both, and `check` plus the struct decode disagreed with `expect` on 0 of the 36 vectors in both configurations. The struct decode alone disagreed on 7 (default) and 9 (`ap`: `1e999` and `-1e999` are accepted by `serde_json` itself).
- `arbitrary_precision` side effects: in `serde_json` 1.0.154 an untagged enum, a `#[serde(flatten)]` map and `u64` and `f64` fields behaved the same with and without the feature (q3e_ap_effects). A JSON object whose only key is `$serde_json::private::Number` is turned into a number: `{"k":{"$serde_json::private::Number":"7"}}` is `{"k":7}` with the feature and stays an object without it, and the checker under `ap` treats that object as the number 7 (`strict ok depth 0` in the last row of the `ap` diff). Input from outside can therefore produce a number where another SDK sees an object.
- Typed decoding of a `u64` field rejects `1.0` and `1e2` (`invalid type: floating point`), while JSON Schema 2020-12 treats `2.0` as an integer (Q5, `iat 2.0`).

### Departures from the expectation

- Expected last-wins on `{"a":1,"a":2}`: true for `Value` and maps; false for struct fields, which serde rejects.
- Expected `1e999` to give `number out of range`: true with default features, false with `arbitrary_precision`.
- Not expected: the default float parser is not correctly rounded; lone surrogates are impossible in a Rust `String`; `arbitrary_precision` rewrites an object with the private key.

## Q4. JCS (RFC 8785)

`q4_lib.rs` holds the in-house canonicalizer. `canonicalize(&Value)`: object members sorted by their UTF-16 code units, strings through `serde_json::to_string`, integers with an explicit range error outside plus or minus (2^53 - 1), other numbers by `es(f64)`, which takes the shortest digits from `serde_json::to_string(&f64)` and lays them out per ECMA-262 7.1.12.1. `es_std` is the same layout over the digits of the standard library's `{:e}`; `es_ryu` is the same layout over the `ryu` crate's digits. The formatter columns: `ryu` and `json` are the raw outputs of the `ryu` crate and of `serde_json`, `dbg` and `disp` are the standard library's `{:?}` and `{}`, `jcs` is `serde_jcs`, `sjc` is `serde_json_canonicalizer`.

### q4_numbers.rs, crate q4-jcs

The 24 finite rows of RFC 8785 Appendix B Table 1 come first (by IEEE 754 bits), then the 8 literals (`literal`). Texts longer than 40 characters are cut and show their length. The expected strings of the literals are the ECMAScript ones (V8 cross-check below).

```text
0000000000000000  want=0                          ryu=0.0 json=0.0 dbg=0.0 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
8000000000000000  want=0                          ryu=-0.0 json=-0.0 dbg=-0.0 disp=-0 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
0000000000000001  want=5e-324                     ryu:ok json:ok dbg:ok disp=0.0000000000000000000000000000...[326 chars] es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
8000000000000001  want=-5e-324                    ryu:ok json:ok dbg:ok disp=-0.000000000000000000000000000...[327 chars] es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
7fefffffffffffff  want=1.7976931348623157e+308    ryu=1.7976931348623157e308 json:ok dbg=1.7976931348623157e308 disp=179769313486231570000000000000...[309 chars] es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
ffefffffffffffff  want=-1.7976931348623157e+308   ryu=-1.7976931348623157e308 json:ok dbg=-1.7976931348623157e308 disp=-17976931348623157000000000000...[310 chars] es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
4340000000000000  want=9007199254740992           ryu=9007199254740992.0 json=9007199254740992.0 dbg=9007199254740992.0 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
c340000000000000  want=-9007199254740992          ryu=-9007199254740992.0 json=-9007199254740992.0 dbg=-9007199254740992.0 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
4430000000000000  want=295147905179352830000      ryu=2.9514790517935283e20 json=2.9514790517935283e+20 dbg=2.9514790517935283e20 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
44b52d02c7e14af5  want=9.999999999999997e+22      ryu=9.999999999999997e22 json:ok dbg=9.999999999999997e22 disp=99999999999999970000000 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
44b52d02c7e14af6  want=1e+23                      ryu=1e23 json:ok dbg=1e23 disp=100000000000000000000000 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
44b52d02c7e14af7  want=1.0000000000000001e+23     ryu=1.0000000000000001e23 json:ok dbg=1.0000000000000001e23 disp=100000000000000010000000 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
444b1ae4d6e2ef4e  want=999999999999999700000      ryu=9.999999999999997e20 json=9.999999999999997e+20 dbg=9.999999999999997e20 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
444b1ae4d6e2ef4f  want=999999999999999900000      ryu=9.999999999999999e20 json=9.999999999999999e+20 dbg=9.999999999999999e20 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
444b1ae4d6e2ef50  want=1e+21                      ryu=1e21 json:ok dbg=1e21 disp=1000000000000000000000 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
3eb0c6f7a0b5ed8c  want=9.999999999999997e-7       ryu:ok json:ok dbg:ok disp=0.0000009999999999999997 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
3eb0c6f7a0b5ed8d  want=0.000001                   ryu=1e-6 json=1e-6 dbg=1e-6 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
41b3de4355555553  want=333333333.3333332          ryu:ok json:ok dbg:ok disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
41b3de4355555554  want=333333333.33333325         ryu:ok json:ok dbg:ok disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
41b3de4355555555  want=333333333.3333333          ryu:ok json:ok dbg:ok disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
41b3de4355555556  want=333333333.3333334          ryu:ok json:ok dbg:ok disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
41b3de4355555557  want=333333333.33333343         ryu:ok json:ok dbg:ok disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
becbf647612f3696  want=-0.0000033333333333333333  ryu=-3.3333333333333333e-6 json=-3.3333333333333333e-6 dbg=-3.3333333333333333e-6 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
43143ff3c1cb0959  want=1424953923781206.2         ryu:ok json:ok dbg=1424953923781206.3 disp=1424953923781206.3 es_std=1424953923781206.3 es_json:ok es_ryu:ok jcs:ok sjc:ok
literal           want=1e+21                      ryu=1e21 json:ok dbg=1e21 disp=1000000000000000000000 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
literal           want=1e-7                       ryu:ok json:ok dbg:ok disp=0.0000001 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
literal           want=0                          ryu=-0.0 json=-0.0 dbg=-0.0 disp=-0 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
literal           want=4.5                        ryu:ok json:ok dbg:ok disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
literal           want=1e+30                      ryu=1e30 json:ok dbg=1e30 disp=1000000000000000000000000000000 es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
literal           want=1                          ryu=1.0 json=1.0 dbg=1.0 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
literal           want=100                        ryu=100.0 json=100.0 dbg=100.0 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
literal           want=10000000000000000          ryu=1e16 json=1e+16 dbg=1e16 disp:ok es_std:ok es_json:ok es_ryu:ok jcs:ok sjc:ok
rows 32 mismatches per formatter: {"dbg": 22, "disp": 15, "es_std": 1, "json": 13, "ryu": 21}
```

### V8 cross-check of the 8 literals

Shell command, not a committed program, with Node v26.10.0: `node -e 'for (const x of [1e21, 1e-7, -0, 4.5, 1e30, 1.0, 100.0, 1e16]) console.log(String(x).padEnd(20), JSON.stringify(x))'`

```text
1e+21                1e+21
1e-7                 1e-7
0                    0
4.5                  4.5
1e+30                1e+30
1                    1
100                  100
10000000000000000    10000000000000000
```

### q4b_numbers10k.rs, crate q4-jcs, `--release`

```text
numbers.json rows 10000 mismatches per formatter: {"dbg": 3779, "disp": 9539, "es_std": 3, "json": 129, "ryu": 3761}
random doubles 500000: es_json!=jcs 0 | es_ryu!=jcs 0 | sjc!=jcs 0 | es_json text not parsing back to the same bits 0
```

### q4c_document.rs, crate q4-jcs

```text
in-house                  3.2.4 sample true | sorting order Carriage,One,Control,Latin,Euro,Emoji:,Hebrew | vector pairs 6/6 [true, true, true, true, true, true]
serde_jcs                 3.2.4 sample true | sorting order Carriage,One,Control,Latin,Euro,Emoji:,Hebrew | vector pairs 6/6 [true, true, true, true, true, true]
serde_json_canonicalizer  3.2.4 sample true | sorting order Carriage,One,Control,Latin,Euro,Emoji:,Hebrew | vector pairs 6/6 [true, true, true, true, true, true]
serde_json::to_string     3.2.4 sample true | sorting order Carriage,One,Control,Latin,Euro,Hebrew,Emoji: | vector pairs 4/6 [true, true, false, true, true, false]
```

### q4d_domain.rs, crate q4-jcs: default features, then the lines that differ with `--features po` (`-` default, `+` with the feature)

```text
serde_json preserve_order feature on: false
[9007199254740991]         in-house [9007199254740991]               serde_jcs [9007199254740991]         serde_json_canonicalizer [9007199254740991]
[9007199254740992]         in-house Err(integer 9007199254740992 outside +-(2^53-1)) serde_jcs [9007199254740992]         serde_json_canonicalizer [9007199254740992]
[-9007199254740991]        in-house [-9007199254740991]              serde_jcs [-9007199254740991]        serde_json_canonicalizer [-9007199254740991]
[-9007199254740992]        in-house Err(integer -9007199254740992 outside +-(2^53-1)) serde_jcs [-9007199254740992]        serde_json_canonicalizer [-9007199254740992]
[9007199254740993]         in-house Err(integer 9007199254740993 outside +-(2^53-1)) serde_jcs [9007199254740992]         serde_json_canonicalizer [9007199254740992]
[18446744073709551615]     in-house Err(integer 18446744073709551615 outside +-(2^53-1)) serde_jcs [18446744073709552000]     serde_json_canonicalizer [18446744073709552000]
[9007199254740992.0]       in-house [9007199254740992]               serde_jcs [9007199254740992]         serde_json_canonicalizer [9007199254740992]
[-0]                       in-house [0]                              serde_jcs [0]                        serde_json_canonicalizer [0]
[-0.0]                     in-house [0]                              serde_jcs [0]                        serde_json_canonicalizer [0]
[1.0]                      in-house [1]                              serde_jcs [1]                        serde_json_canonicalizer [1]
[1E30]                     in-house [1e+30]                          serde_jcs [1e+30]                    serde_json_canonicalizer [1e+30]
[0.000001]                 in-house [0.000001]                       serde_jcs [0.000001]                 serde_json_canonicalizer [0.000001]
[1e-7]                     in-house [1e-7]                           serde_jcs [1e-7]                     serde_json_canonicalizer [1e-7]
{"b":1,"a":{"d":1,"c":2}}  in-house {"a":{"c":2,"d":1},"b":1}        serde_jcs {"a":{"c":2,"d":1},"b":1}  serde_json_canonicalizer {"a":{"c":2,"d":1},"b":1}
NaN: serde_json::to_string null | to_value Null | Number::from_f64 None | serde_jcs Err(invalid float value) | serde_json_canonicalizer Err(NaN and +/-Infinity are not permitted in JSON)
Infinity: serde_json::to_string null | to_value Null | Number::from_f64 None | serde_jcs Err(invalid float value) | serde_json_canonicalizer Err(NaN and +/-Infinity are not permitted in JSON)
```

```text
-serde_json preserve_order feature on: false
+serde_json preserve_order feature on: true
```

### Facts

- The standard library's float printers are not ECMAScript. `{:?}` matched the RFC string in 10 of the 32 rows and the 10000-row file in 6221 (3779 mismatches); `{}` never uses an exponent (`5e-324` is a 326-character string); the `ryu` crate prints `1e23`, `2.9514790517935283e20` and `1.0` where ECMAScript prints `1e+23`, `295147905179352830000` and `1` (21 of 32 rows, 3761 of 10000). `serde_json` 1.0.154 prints with `zmij`, a dependency of `serde_json` and not `ryu` (the dependency counts show `zmij`); its output equals the RFC string in 19 of 32 rows and 9871 of 10000 (129 mismatches) and differs in the exponent form (`1e+16` against `10000000000000000`) and in `1.0` against `1`.
- The digits are not the problem except in one place: the standard library's `{:e}` gives `1424953923781206.3` for the double `43143ff3c1cb0959`, whose exact value `1424953923781206.25` is a tie between two shortest candidates. ECMAScript, RFC 8785 Appendix B (`1424953923781206.2`), `ryu`, `ryu-js` and `serde_json`'s printer choose the even digit. So `es_std` has 1 mismatch in 32 rows and 3 in 10000, and the standard library cannot be the digit source.
- `es` (`serde_json` digits, 0 new dependencies), `es_ryu` (`ryu` digits), `serde_jcs` 0.2.0 and `serde_json_canonicalizer` 0.4.1 all have 0 mismatches on the 32 rows and on the 10000 rows. Over 500000 pseudo-random doubles (xorshift64 bit patterns, NaN and infinities skipped) `es`, `es_ryu` and `serde_json_canonicalizer` equalled `serde_jcs` for all 500000, and `es(x)` parsed back to the same bits for all 500000.
- Document level (q4c_document): the in-house canonicalizer, `serde_jcs` and `serde_json_canonicalizer` all produced the exact RFC 8785 3.2.4 bytes for the 3.2.2 sample, the UTF-16 key order of the 3.2.3 sorting sample (Euro Sign, then Emoji U+1F600, then Hebrew letter U+FB33) and all six input and output pairs in `vectors/jcs`. `serde_json::to_string(&Value)` reproduced the 3.2.4 bytes, because that sample has ASCII keys and numbers `serde_json` prints the ECMAScript way, but ordered the sorting sample by code point (Hebrew before Emoji) and failed 2 of the 6 pairs (`structures`, `weird`).
- Domain (q4d_domain): the in-house canonicalizer rejected 9007199254740992, -9007199254740992, 9007199254740993 and 18446744073709551615 with an error and accepted 9007199254740991 and -9007199254740991. Both crates canonicalize 9007199254740993 as `9007199254740992` and 18446744073709551615 as `18446744073709552000`: two different integers give the same canonical bytes, so a crate must never see an integer the strict layer has not range-checked. All three print `-0` and `-0.0` as `0`, `1.0` as `1`, `1E30` as `1e+30`, `0.000001` as `0.000001` and `1e-7` as `1e-7`. All three sorted nested objects.
- Non-finite values: `serde_json::to_string(&f64::NAN)` returns `null` and `serde_json::to_value` of NaN or infinity returns `Null`, silently; `Number::from_f64` returns `None`. Both crates return an error for NaN and infinity. A non-finite `f64` that reaches `Value` through `to_value` becomes `null` before any canonicalizer sees it.
- Key order under feature unification: with `serde_json`'s `preserve_order` enabled the output of every canonicalizer in q4d_domain is unchanged (the diff shows only the feature line). The two crates and the in-house code sort explicitly; plain `serde_json::to_string(&Value)` does not.
- `serde_jcs` 0.2.0 depends on `serde_json` with `float_roundtrip` and on `ryu-js` 0.2.2; `serde_json_canonicalizer` 0.4.1 depends on `serde_json` with `float_roundtrip` and on `ryu-js` 1.0.3; both versions of `ryu-js` are in the tree of q4-jcs. Depending on either crate switches `float_roundtrip` on for every use of `serde_json` in the build.

### Departures from the expectation

- The task cites RFC 8785 for the samples `1e21`, `1e-7`, `-0`, `4.5` and `1E30`; the Python record already notes that the RFC has no sample table with these values (`1e-7` appears nowhere in the RFC) and takes the expected strings from ECMAScript. The same eight literals were used here, with the V8 cross-check above.
- Expected: `ryu` formatting differs from ECMAScript. Confirmed (21 of 32 rows). The standard library's printers differ too, and its digits are wrong on ties; `serde_json`'s printer has the right digits but not the right layout.
- Not expected: `serde_json` 1.0.154 no longer prints floats with `ryu` (it uses `zmij`), and its digits match ECMAScript.

## Q5. JSON Schema validation (Draft 2020-12, offline)

`spec/v1.0/schemas/pact.schema.json` declares `$schema` 2020-12 and `$id` `urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60`. Keywords it uses (counted by a one-off script over the file): `type` 361, `maxLength` 159, `minLength` 153, `format` 65 (all `uri`), `pattern` 62, `minimum` 52, `maximum` 52, `$ref` 40, `additionalProperties` 36, `properties`, `maxProperties`, `required` 33 each, `items`, `minItems`, `maxItems` 32 each, `enum` 25, `uniqueItems` 24, `anyOf` 14, `const` 11, `minProperties` 2, `oneOf`, `propertyNames`, `$defs` 1 each. Its 8 distinct patterns are anchored and use no lookaround. All 40 `$ref` members point into `#/$defs/`.

All six programs below ran as built binaries under the network-denying sandbox profile shown in the environment section. The wrapper `{"$ref": "<$id>#/$defs/Evidence"}` is validated against a registry that holds the schema under its `$id`.

### q5_jsonschema.rs, crate q5-jsonschema (`jsonschema` 0.58.6, `default-features = false`)

```text
root schema compiles: true | $id urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60
Evidence wrapper without registry: RAISED Resource 'urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60' is not present in a registry and retrieving it failed: Unknown scheme urn
Appendix C payload as shipped: ["Constant@/pact_version"]
pact_version 0.1: [] | root oneOf valid: true
```

### q5b_jsonschema_formats.rs, crate q5-jsonschema

```text
as fixed        format off [] | format on []
iss not a uri   format off [] | format on ["Format@/iss"]
iss with space  format off [] | format on ["Format@/iss"]
iss urn         format off [] | format on []
iss relative    format off [] | format on ["Format@/iss"]
iss empty       format off ["MinLength@/iss"] | format on ["MinLength@/iss", "Format@/iss"]
iat 2^53        format off ["Maximum@/iat"] | format on ["Maximum@/iat"]
iat 2.0         format off [] | format on []
iat 1.5         format off ["Type@/iat"] | format on ["Type@/iat"]
iat -1          format off ["Minimum@/iat"] | format on ["Minimum@/iat"]
```

### q5c_jsonschema_patterns.rs, crate q5-jsonschema

```text
as fixture           []
method GET+LF        ["Pattern@/method"]
method get           ["Pattern@/method"]
method G-acute-T     ["Pattern@/method"]
digest 43+LF         ["Pattern@/body_digest"]
target http://       ["Pattern@/target_uri"]
resources duplicate  ["UniqueItems@/resources"]
header name upper    ["PropertyNames@/headers"]
header name a+LF     ["PropertyNames@/headers"]
```

### q5d_boon.rs, crate q5-boon (`boon` 0.6.1)

```text
Evidence wrapper without add_resource: RAISED error loading urn:uuid:8381317d-882e-4292-ae88-24d8f0b78f60
Appendix C payload as shipped: ["const@/pact_version"]
pact_version 0.1: [] | root oneOf valid: true
```

### q5e_boon_formats.rs, crate q5-boon

```text
as fixed        format off [] | format on []
iss not a uri   format off [] | format on ["format@/iss"]
iss with space  format off [] | format on ["format@/iss"]
iss urn         format off [] | format on []
iss relative    format off [] | format on ["format@/iss"]
iss empty       format off ["minLength@/iss"] | format on ["format@/iss", "minLength@/iss"]
iat 2^53        format off ["maximum@/iat"] | format on ["maximum@/iat"]
iat 2.0         format off [] | format on []
iat 1.5         format off ["type@/iat"] | format on ["type@/iat"]
iat -1          format off ["minimum@/iat"] | format on ["minimum@/iat"]
```

### q5f_boon_patterns.rs, crate q5-boon

```text
as fixture           []
method GET+LF        ["pattern@/method"]
method get           ["pattern@/method"]
method G-acute-T     ["pattern@/method"]
digest 43+LF         ["pattern@/body_digest"]
target http://       ["pattern@/target_uri"]
resources duplicate  ["uniqueItems@/resources"]
header name upper    ["propertyNames@", "pattern@"]
header name a+LF     ["propertyNames@", "pattern@"]
```

### `serde_json` features in each resolved tree (`cargo tree -e features -i serde_json --depth 1`)

q5-jsonschema:

```text
serde_json v1.0.154
├── serde_json feature "default"
├── serde_json feature "float_roundtrip"
└── serde_json feature "std"
```

q5-boon:

```text
serde_json v1.0.154
├── serde_json feature "default"
└── serde_json feature "std"
```

### Facts

- Both crates compiled the whole schema as Draft 2020-12, with no network (`jsonschema::draft202012::new` returned `Ok`, and `boon` compiled the root). The local `#/$defs/...` references need nothing. A reference to the schema's own `$id` (the `Evidence` wrapper) needs the schema registered under that `urn:uuid:` identifier: `jsonschema` through `Registry::new().add(id, Resource::from_contents(schema))` and `with_registry`, `boon` through `Compiler::add_resource`. Without it `jsonschema` raised `is not present in a registry and retrieving it failed: Unknown scheme urn` and `boon` raised `error loading urn:uuid:...`.
- The Appendix C payload, decoded, failed `Evidence` with exactly one error in both crates, the `const` at `/pact_version` (`"0.2"` against `"0.1"`). With `pact_version` set to `"0.1"` there were no errors and the root schema (`oneOf` over 16 definitions) reported it valid. This is the result the Python record has.
- `format: "uri"` is built into both crates; no extra package is needed (Python needed one). Format assertion is off by default in both, as Draft 2020-12 allows: `"not a uri"` produced no error until it was switched on (`should_validate_formats(true)`, `enable_format_assertions()`), and then `not a uri`, `http://a b/c d` and the relative `foo/bar` were rejected and `urn:uuid:...` was accepted. The empty string gave `MinLength` and `Format` errors.
- Integers: `iat` of 9007199254740992 failed `maximum`, `-1` failed `minimum`, `1.5` failed `type`, and `2.0` was accepted, in both crates. Values arrive as `serde_json::Value`; the integer domain of the JSON layer is the strict checker's job, not the validator's.
- Patterns: both crates rejected `GET` followed by a newline for `^[A-Z]+$`, a 43-character digest followed by a newline for `^[A-Za-z0-9_-]{43}$` and the other cases (lower case, non-ASCII, `http://`, duplicate `resources`, upper-case or newline-suffixed header names). The two crates gave the same accept or reject outcome in all 19 format, integer and pattern cases; the error detail differs (`boon` lists two entries for a bad header name).
- `jsonschema` turns on `serde_json`'s `float_roundtrip` itself; `boon` leaves `serde_json` at its defaults (the feature trees above).
- Footprint (dependency counts below): `jsonschema` with default features pulls `reqwest`, `rustls` and `aws-lc-sys` (151 crates, 21 with a build script, including a C and cmake build); `default-features = false` gives 65 crates with 15 build scripts. `boon` is 56 crates with 13 build scripts and brings the ICU data crates through `idna` and `url` (`icu_normalizer_data` and `icu_properties_data` have build scripts).

### Departures from the expectation

- The task expected offline `$ref` to be a question about remote references. The schema has none; the question that matters is the `$id` registration for wrapper references, and the default features of `jsonschema`, which are not offline: they include an HTTP client and a TLS stack.

## Q6. `cargo package` and files outside the crate

The layout reproduces the one in the cite SDK (`hop-top/poly-cite`, `rs/Cargo.toml`): the crate lives in `rs/`, the shared fixtures in `../spec/v1.0/fixtures`, and its `include` lists `"../spec/v1.0/fixtures/**"`. `q6_setup.sh` builds that layout in a scratch directory (a `rs/` crate with `include = ["Cargo.toml", "src/**", "tests/**", "schema/**", "../spec/v1.0/fixtures/**"]`, a file in `spec/v1.0/fixtures`, and a copy of it in `rs/schema`).

### q6_package.sh

```text
== A: cargo package --list, include has ../spec/v1.0/fixtures/**
Cargo.lock
Cargo.toml
Cargo.toml.orig
schema/contract.json
src/lib.rs
== B: cargo package, include_str! of an in-crate path
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.50s
q6-probe-0.0.0/Cargo.lock
q6-probe-0.0.0/Cargo.toml
q6-probe-0.0.0/Cargo.toml.orig
q6-probe-0.0.0/schema/contract.json
q6-probe-0.0.0/src/lib.rs
== C: src/lib.rs also include_str!s ../../spec/v1.0/fixtures/contract.json
error: couldn't read `src/../../spec/v1.0/fixtures/contract.json`: No such file or directory (os error 2)
 --> src/lib.rs:2:36
  |
2 | pub fn outside() -> &'static str { include_str!("../../spec/v1.0/fixtures/contract.json") }
  |                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

error: could not compile `q6-probe` (lib) due to 1 previous error
error: failed to verify package tarball
== D: the outside include_str! only in tests/contract.rs
   Verifying q6-probe v0.0.0 ($SCRATCH/q6/rs)
   Compiling q6-probe v0.0.0 ($SCRATCH/q6/rs/target/package/q6-probe-0.0.0)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.05s
0
-- cargo test in the unpacked package:
   Compiling q6-probe v0.0.0 ($SCRATCH/q6/x/q6-probe-0.0.0)
error: couldn't read `tests/../../spec/v1.0/fixtures/contract.json`: No such file or directory (os error 2)
 --> tests/contract.rs:1:17
  |
1 | const _: &str = include_str!("../../spec/v1.0/fixtures/contract.json");
  |                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  |
help: there is a file with the same name in a different directory
  |
1 | const _: &str = include_str!("../../../spec/v1.0/fixtures/contract.json");
  |                                     +++

error: could not compile `q6-probe` (test "contract") due to 1 previous error
warning: build failed, waiting for other jobs to finish...
```

### q6b_vcs_license.sh (a clean git tree in the scratch layout, then `readme` and `license-file` pointing outside the crate)

```text
== E: clean git tree, cargo package --list
.cargo_vcs_info.json
Cargo.lock
Cargo.toml
Cargo.toml.orig
schema/contract.json
src/lib.rs
tests/contract.rs
== F: readme and license-file point outside the crate
.cargo_vcs_info.json
Cargo.lock
Cargo.toml
Cargo.toml.orig
LICENSE
README.md
schema/contract.json
src/lib.rs
tests/contract.rs
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.07s
readme = "README.md"
license-file = "LICENSE"
```

### Facts

- `cargo package --list` with `"../spec/v1.0/fixtures/**"` in `include` did not list `spec/v1.0/fixtures/contract.json`, with or without a git tree (A, E), and gave no warning or error about the entry. cargo ignores include patterns that leave the package root, silently.
- `include_str!` of a path inside the crate (`../schema/contract.json` from `src/`) packaged and verified (B). Adding `include_str!("../../spec/v1.0/fixtures/contract.json")` to `src/lib.rs` made `cargo package` fail at its verification build: `couldn't read ...: No such file or directory`, `failed to verify package tarball` (C).
- The same `include_str!` in `tests/contract.rs` (the layout of the cite SDK's `tests/contract.rs`) passed `cargo package` verification, because verification does not compile the tests, and the tarball contained no file from `spec` (`0`). `cargo test` inside the unpacked package failed to compile that test (D). A crate packaged this way ships tests that cannot run from the published source.
- `readme` and `license-file` that point outside the crate (`../README.md`, `../LICENSE`) were copied into the package root and rewritten to `README.md` and `LICENSE` in the packaged manifest (F), without being named in `include`. `cargo package` also adds `Cargo.lock` and, in a git tree, `.cargo_vcs_info.json`.
- The vendoring that `Makefile` already describes (`rs/schema/pact.schema.json`, copied from `spec/v1.0/schemas`) is the packaging-safe form: the path is inside the crate.

### Departures from the expectation

- None. The task expected cargo to ignore the outside entry and the outside `include_str!` to fail verification; both held. The test-only case does not fail verification and is the one to watch.

## Dependency counts

Run as `depcount.sh $SCRATCH/depcount` (one scratch crate per line; `cargo tree --prefix none -e normal,build` for the host platform, which counts every crate in the tree including the named one, with the crates that carry a `build.rs` or are proc-macros read from `cargo metadata`; nothing is built). The `sdk-set-*` lines are the chosen primitives together: `p256` (feature `ecdsa`), `sha2`, `base64`, `serde_json` with `float_roundtrip`, and the schema validator named in the label.

```text
p256-ecdsa               33 deps | build.rs: 2 ['libc 0.2.190', 'num-traits 0.2.19'] | proc-macro: 0 []
p256-probe               36 deps | build.rs: 3 ['getrandom 0.4.3', 'libc 0.2.190', 'num-traits 0.2.19'] | proc-macro: 0 []
p256-default             38 deps | build.rs: 3 ['getrandom 0.4.3', 'libc 0.2.190', 'num-traits 0.2.19'] | proc-macro: 0 []
p256-013-jwk             37 deps | build.rs: 6 ['generic-array 0.14.9', 'libc 0.2.190', 'serde 1.0.229', 'serde_core 1.0.229', 'serde_json 1.0.154', 'zmij 1.0.23'] | proc-macro: 0 []
sha2                     10 deps | build.rs: 1 ['libc 0.2.190'] | proc-macro: 0 []
ring                     8 deps | build.rs: 2 ['libc 0.2.190', 'ring 0.17.14'] | proc-macro: 0 []
base64                   1 deps | build.rs: 0 [] | proc-macro: 0 []
serde_json               5 deps | build.rs: 3 ['serde_core 1.0.229', 'serde_json 1.0.154', 'zmij 1.0.23'] | proc-macro: 0 []
serde_json-fr            5 deps | build.rs: 3 ['serde_core 1.0.229', 'serde_json 1.0.154', 'zmij 1.0.23'] | proc-macro: 0 []
serde_json-ap            5 deps | build.rs: 3 ['serde_core 1.0.229', 'serde_json 1.0.154', 'zmij 1.0.23'] | proc-macro: 0 []
serde-derive             7 deps | build.rs: 4 ['proc-macro2 1.0.107', 'quote 1.0.47', 'serde 1.0.229', 'serde_core 1.0.229'] | proc-macro: 1 ['serde_derive 1.0.229']
serde_jcs                8 deps | build.rs: 4 ['serde 1.0.229', 'serde_core 1.0.229', 'serde_json 1.0.154', 'zmij 1.0.23'] | proc-macro: 0 []
serde_json_canonicalizer 8 deps | build.rs: 4 ['serde 1.0.229', 'serde_core 1.0.229', 'serde_json 1.0.154', 'zmij 1.0.23'] | proc-macro: 0 []
ryu                      1 deps | build.rs: 0 [] | proc-macro: 0 []
jsonschema-nodefault     65 deps | build.rs: 15 ['ahash 0.8.12', 'getrandom 0.3.4', 'jsonschema-value 0.58.6', 'libc 0.2.190', 'num-traits 0.2.19', 'parking_lot_core 0.9.12', 'proc-macro2 1.0.107', 'quote 1.0.47', 'ref-cast 1.0.27', 'serde 1.0.229', 'serde_core 1.0.229', 'serde_json 1.0.154', 'unicode-general-category 1.1.0', 'zerocopy 0.8.63', 'zmij 1.0.23'] | proc-macro: 3 ['ref-cast-impl 1.0.27
jsonschema-default       151 deps | build.rs: 21 ['ahash 0.8.12', 'aws-lc-rs 1.18.2', 'aws-lc-sys 0.46.0', 'getrandom 0.3.4', 'httparse 1.10.1', 'icu_normalizer_data 2.3.0', 'icu_properties_data 2.3.0', 'jsonschema-value 0.58.6', 'libc 0.2.190', 'num-traits 0.2.19', 'parking_lot_core 0.9.12', 'proc-macro2 1.0.107', 'quote 1.0.47', 'ref-cast 1.0.27', 'rustls 0.23.46', 'serde 1.0.229', 'serde_core 1
boon                     56 deps | build.rs: 13 ['ahash 0.8.12', 'getrandom 0.3.4', 'icu_normalizer_data 2.3.0', 'icu_properties_data 2.3.0', 'libc 0.2.190', 'proc-macro2 1.0.107', 'quote 1.0.47', 'ref-cast 1.0.27', 'serde 1.0.229', 'serde_core 1.0.229', 'serde_json 1.0.154', 'zerocopy 0.8.63', 'zmij 1.0.23'] | proc-macro: 5 ['displaydoc 0.2.7', 'ref-cast-impl 1.0.27', 'yoke-derive 0.8.4', 'zerofr
sdk-set-no-schema        39 deps | build.rs: 5 ['libc 0.2.190', 'num-traits 0.2.19', 'serde_core 1.0.229', 'serde_json 1.0.154', 'zmij 1.0.23'] | proc-macro: 0 []
sdk-set-jsonschema       95 deps | build.rs: 15 ['ahash 0.8.12', 'getrandom 0.3.4', 'jsonschema-value 0.58.6', 'libc 0.2.190', 'num-traits 0.2.19', 'parking_lot_core 0.9.12', 'proc-macro2 1.0.107', 'quote 1.0.47', 'ref-cast 1.0.27', 'serde 1.0.229', 'serde_core 1.0.229', 'serde_json 1.0.154', 'unicode-general-category 1.1.0', 'zerocopy 0.8.63', 'zmij 1.0.23'] | proc-macro: 3 ['ref-cast-impl 1.0.27
sdk-set-boon             88 deps | build.rs: 14 ['ahash 0.8.12', 'getrandom 0.3.4', 'icu_normalizer_data 2.3.0', 'icu_properties_data 2.3.0', 'libc 0.2.190', 'num-traits 0.2.19', 'proc-macro2 1.0.107', 'quote 1.0.47', 'ref-cast 1.0.27', 'serde 1.0.229', 'serde_core 1.0.229', 'serde_json 1.0.154', 'zerocopy 0.8.63', 'zmij 1.0.23'] | proc-macro: 5 ['displaydoc 0.2.7', 'ref-cast-impl 1.0.27', 'yoke-d
```

## Probe sensitivity

Eight scratch edits, each with one deliberate defect, to confirm the probes can fail. Each edit was made in place, the program was run, and the file was restored; the SHA-256 prefixes show the restore.

q1c_rfc6979.rs, one hex digit of the expected RFC 6979 `r` changed:

```text
file q1c_rfc6979.rs | sed 's/EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716/EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3717/' | lines changed: 1
RFC 6979 A.2.5 SHA-256 "sample": r||s matches false
RFC 6979 A.2.5 SHA-256 "test": r||s matches true
scalar 2 re-sign of Appendix C input == fixture signature false | verifies true
high-S twin (n-s) differs true | verifies true | normalize_s restores true
restored: sha256 182d466b2fe6 before, 182d466b2fe6 after
```

q1_es256.rs, one character of the RFC 7515 A.3 signature changed:

```text
file q1_es256.rs | sed 's/"DtEhU3ljbEg8L38VWAfUAqOyKAM6/"EtEhU3ljbEg8L38VWAfUAqOyKAM6/' | lines changed: 1
round trip true raw lens {64} DER lens {69, 70, 71, 72} | one message signed 5000 times: 1 distinct
tampered msg false 63 bytes false 65 bytes false
RFC 7515 A.3 verifies false sig bytes 64 tampered input false
restored: sha256 0e9f89f26357 before, 0e9f89f26357 after
```

q1f_ring.rs, the verification algorithm changed from the fixed to the ASN.1 form:

```text
file q1f_ring.rs | sed 's/UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pk)/UnparsedPublicKey::new(\&ring::signature::ECDSA_P256_SHA256_ASN1, pk)/' | lines changed: 1

RFC 7515 A.3 verifies false sig bytes 64 tampered input false
round trip false raw lens {64} | one message signed 5000 times: 5000 distinct
63 bytes false 65 bytes false tampered msg false
restored: sha256 94f7b510d4a4 before, 94f7b510d4a4 after
```

q2_thumbprint.rs, the EC member order changed from lexicographic to `kty, crv, x, y`:

```text
file q2_thumbprint.rs | sed 's/Some("EC") => &\["crv", "kty", "x", "y"\]/Some("EC") => \&["kty", "crv", "x", "y"]/' | lines changed: 1
holder d-xv9KenJkELSjvoc5fR3q9B_fgPPqjTn92vi0UQfKI == expected: false
kid/alg/use ignored: true | extra member ignored: true
RFC 7638 3.1 NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs == expected: true
missing required member y -> Err("missing member y") | unknown kty -> Err("unsupported kty Some(\"oct\")")
restored: sha256 fefe3220a572 before, fefe3220a572 after
```

q3_lib.rs, the duplicate-key test disabled:

```text
file lib.rs | sed 's/if !seen.insert(k) {/if false \&\& !seen.insert(k) {/' | lines changed: 1
36 vectors: 29 agree with expect, 7 disagree
  duplicate-key-escaped-form: expected reject, got Ok(2)
  duplicate-key-identical-values: expected reject, got Ok(2)
  duplicate-key-in-headers: expected reject, got Ok(2)
  duplicate-key-nested: expected reject, got Ok(3)
  duplicate-key-top-level: expected reject, got Ok(2)
  unknown-core-field-case-variant: expected reject, got Ok(2)
  unknown-core-field: expected reject, got Ok(2)
restored: sha256 8b40d7727fed before, 8b40d7727fed after
```

q3_lib.rs, the lexical integer pass disabled (this is also the evidence that the pass is needed without `arbitrary_precision`):

```text
file lib.rs | sed 's/^    scan_ints(s)?;/    \/\/ scan_ints(s)?;/' | lines changed: 1
36 vectors: 33 agree with expect, 3 disagree
  integer-overflow-huge: expected reject, got Ok(2)
  unknown-core-field-case-variant: expected reject, got Ok(2)
  unknown-core-field: expected reject, got Ok(2)
restored: sha256 8b40d7727fed before, 8b40d7727fed after
```

q4_lib.rs, the positional-notation limit `n <= 21` lowered to `n <= 20`:

```text
file lib.rs | sed 's/k <= n \&\& n <= 21/k <= n \&\& n <= 20/; s/0 < n \&\& n <= 21/0 < n \&\& n <= 20/' | lines changed: 2
numbers.json rows 10000 mismatches per formatter: {"dbg": 3779, "disp": 9539, "es_json": 18, "es_ryu": 18, "es_std": 21, "json": 129, "ryu": 3761}
random doubles 500000: es_json!=jcs 840 | es_ryu!=jcs 840 | sjc!=jcs 0 | es_json text not parsing back to the same bits 0
restored: sha256 527b18a0e3cd before, 527b18a0e3cd after
```

q5_jsonschema.rs, the corrected `pact_version` changed from `"0.1"` to `"0.3"`:

```text
file q5_jsonschema.rs | sed 's/p\["pact_version"\] = json!("0.1")/p["pact_version"] = json!("0.3")/' | lines changed: 1
Appendix C payload as shipped: ["Constant@/pact_version"]
pact_version 0.1: ["Constant@/pact_version"] | root oneOf valid: false
restored: sha256 f3e746fbbf63 before, f3e746fbbf63 after
```

## Decision table

| Primitive | Chosen | Evidence |
|---|---|---|
| ES256 sign and verify | Dependency: `p256` 0.14.0 with feature `ecdsa` only (RustCrypto; 33 crates in its tree, 2 with a build script, `libc` and `num-traits`; no `cc` crate) | q1_es256: 64-byte r and s for 5000 of 5000, A.3 verifies; q1c_rfc6979: both RFC 6979 A.2.5 vectors match and one message gives 1 distinct signature in 5000; q1b_fixture: Appendix C verifies. `ring` 0.17.14 also passes verify but signs with random nonces (5000 distinct, q1f_ring) and compiles C and assembly (build script `ring`, build dependency `cc`). |
| JWS signature encoding | The same crate: `Signature::to_bytes` and `from_slice`; no DER step | q1_es256: raw lengths `{64}`, DER 69 to 72; q1d_malformed: zero, `r = n`, `s = n` rejected in `from_slice`. |
| SHA-256 | Dependency: `sha2` 0.11.1 (the version `p256` already resolves; also needed for the thumbprint and `object_digest`) | The standard library has none; q2_thumbprint reproduces the three reference vectors with it. |
| base64url | Dependency: `base64` 0.23.1 (no transitive crates), or an in-house 7-line decoder (open question) | q1e_base64: the crate rejects padding, the standard alphabet, whitespace, non-canonical trailing bits and bad lengths; the in-house decoder agreed on 1,000,000 random strings. |
| JWK read and write for P-256 | Hand-built over `serde_json` and the `p256` SEC1 API; no `jwk` feature | `p256` 0.14.0 has no `jwk` feature (cargo error, q2); 0.13.2 rejects the fixtures' `kid`, `alg` and `use` and writes `kty` first (q2d_jwk_013); q2c_jwk_p256: scalars 1 to 6 give the fixture coordinates, and a per-coordinate length check is required. |
| RFC 7638 thumbprint | In-house (a 5-line function) over `sha2`, `base64`, `serde_json` | q2_thumbprint, q2b_fixtures: holder `xx0BcA-...Mvl0M`, RFC 7638 3.1, RFC 8037 A.3 reproduced; the seven fixture values equal the Python record's. |
| UTF-8 decoding | Builtin: `std::str::from_utf8`, plus an explicit BOM test | q3_defaults: five invalid sequences and UTF-16 rejected; the BOM is accepted by `from_utf8`. |
| Strict JSON parse | Dependency: `serde_json` 1.0.154 with `float_roundtrip`; in-house visitor (duplicate keys, depth 16, non-finite, integer range) and in-house lexical integer pass; `arbitrary_precision` not enabled | q3b_vectors and q3d_decode: 0 disagreements on the 36 vectors with the struct decode (34 of 36 for the JSON layer alone); q3c_float_parse: default float parse wrong for 2709 of 10000, 0 with `float_roundtrip`; q3e_ap_effects and the `ap` diff: `arbitrary_precision` turns an object into a number. |
| Unknown core fields, duplicate known fields | Dependency: `serde` with `derive`, `#[serde(deny_unknown_fields)]` (adds `serde_derive`, `proc-macro2`, `quote`, `syn`) | q3d_decode: both unknown-field vectors and three of five duplicate vectors rejected by the struct decode alone. |
| JCS (RFC 8785) | In-house canonicalizer over `serde_json::Value`: UTF-16 key sort, `serde_json` string escaping, number digits from `serde_json`'s printer laid out per ECMA-262 7.1.12.1, range error outside plus or minus (2^53 - 1). `serde_jcs` 0.2.0 and `serde_json_canonicalizer` 0.4.1 only as dev-dependency oracles | q4_numbers, q4b_numbers10k: 0 mismatches on 32 rows, 10000 rows and 500000 random doubles against both crates; q4c_document: RFC bytes and 6 of 6 pairs; the standard library's digits fail on ties (3 of 10000), `ryu` and `{:?}` are not ECMAScript (3761 and 3779 of 10000); both crates are lossy above 2^53 (q4d_domain). |
| JSON Schema 2020-12 | Dependency: `jsonschema` 0.58.6 with `default-features = false` (65 crates, 15 with a build script); alternative `boon` 0.6.1 (56 crates, 13) | q5_jsonschema and q5d_boon: the same single `const` error on Appendix C, offline; 19 of 19 format, integer and pattern cases identical in outcome; the default features of `jsonschema` are 151 crates with a TLS stack. |
| `format: "uri"` | Built into both validators; switch assertion on explicitly | q5b_jsonschema_formats, q5e_boon_formats: `not a uri`, a space and a relative reference rejected only with assertion on. |
| Packaging the schema | Vendor into `rs/schema/` and `include_str!` an in-crate path; no `../spec` in `include`, no outside path in `tests/` | q6_package: the `include` entry is silently ignored, an outside `include_str!` in `src/` fails verification, in `tests/` it passes verification and breaks `cargo test` of the unpacked crate. |

## Dependencies named for the vet task

Metadata read from the crates.io API on 2026-10-16 (read only). Shell command, not a committed program, per crate: `curl -sS -H 'User-Agent: ...' https://crates.io/api/v1/crates/<name>`, then the `versions[]` entry for the version and the `crate` object.

| Crate | Version | License | Published | Role | Notes |
|---|---|---|---|---|---|
| `p256` | 0.14.0 | Apache-2.0 OR MIT | 2026-07-03 | ES256 | RustCrypto; crate downloads 207,216,708; previous 0.13.2 published 2023-04-15 |
| `sha2` | 0.11.1 | MIT OR Apache-2.0 | 2026-10-12 | SHA-256 | RustCrypto; downloads 1,067,406,525 |
| `base64` | 0.23.1 | MIT OR Apache-2.0 | 2026-08-04 | base64url | no transitive crates; downloads 1,739,663,208 |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | 2026-10-11 | JSON | feature `float_roundtrip`; downloads 1,440,407,085 |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | 2026-07-18 | derive | adds `serde_derive`, `proc-macro2`, `quote`, `syn` |
| `jsonschema` | 0.58.6 | MIT | 2026-10-06 | schema validation | `default-features = false`; downloads 103,545,209 |
| `boon` | 0.6.1 | MIT OR Apache-2.0 | 2025-01-07 | alternative validator | downloads 611,638 |
| `ring` | 0.17.14 | Apache-2.0 AND ISC | 2025-03-11 | alternative ES256 | C and assembly build; downloads 808,723,373 |
| `serde_jcs` | 0.2.0 | MIT OR Apache-2.0 | 2026-03-25 | JCS oracle (dev only) | downloads 5,230,904 |
| `serde_json_canonicalizer` | 0.4.1 | MIT | 2026-10-13 | JCS oracle (dev only) | downloads 12,061,942 |
| `ryu` | 1.0.23 | Apache-2.0 OR BSL-1.0 | 2026-02-08 | alternative digit source | no transitive crates; downloads 1,226,372,946 |
| `zmij` | 1.0.23 | MIT | 2026-07-13 | serde_json's float printer (transitive) | created 2025-12-18; downloads 542,340,332 |

`sha2` 0.11.1, `serde_json` 1.0.154 and `serde_json_canonicalizer` 0.4.1 were published 4, 5 and 3 days before this record.

The resolved crates of the chosen primitives without a schema validator (39, `depcount.sh` line `sdk-set-no-schema`), from `cargo tree --prefix none -e normal,build`:

```text
autocfg@1.5.1, base16ct@1.0.0, base64@0.23.1, block-buffer@0.12.1, cfg-if@1.0.5, cmov@0.5.4, const-oid@0.10.2,
cpubits@0.1.1, cpufeatures@0.3.1, crypto-bigint@0.7.5, crypto-common@0.2.2, ctutils@0.4.3, der@0.8.2, digest@0.11.3,
ecdsa@0.17.0, elliptic-curve@0.14.1, ff@0.14.0, group@0.14.0, hmac@0.13.0, hybrid-array@0.4.15, itoa@1.0.18,
libc@0.2.190, memchr@2.8.3, num-traits@0.2.19, p256@0.14.0, primefield@0.14.0, primeorder@0.14.0, rand_core@0.10.1,
rfc6979@0.6.0, sec1@0.8.1, serde_core@1.0.229, serde_json@1.0.154, sha2@0.11.1, signature@3.0.0, subtle@2.6.1,
typenum@1.20.1, wnaf@0.14.1, zeroize@1.9.1, zmij@1.0.23
```

Crates added by `jsonschema` 0.58.6 with `default-features = false` (56 more, 95 in all):

```text
ahash@0.8.12, aho-corasick@1.1.5, allocator-api2@0.2.21, bit-set@0.8.0, bit-vec@0.8.0, borrow-or-share@0.2.4,
bytecount@0.6.9, data-encoding@2.11.1, email_address@0.2.9, equivalent@1.0.3, fancy-regex@0.19.2, fluent-uri@0.4.1,
foldhash@0.2.0, fraction@0.17.0, getrandom@0.3.4, hashbrown@0.17.1, heck@0.5.0, jsonschema@0.58.6,
jsonschema-regex@0.58.6, jsonschema-value@0.58.6, lock_api@0.4.14, micromap@0.3.0, num@0.4.3, num-bigint@0.4.8,
num-cmp@0.1.0, num-complex@0.4.6, num-integer@0.1.47, num-iter@0.1.46, num-rational@0.4.2, once_cell@1.21.4,
outref@0.5.2, parking_lot@0.12.5, parking_lot_core@0.9.12, percent-encoding@2.3.2, proc-macro2@1.0.107, quote@1.0.47,
ref-cast@1.0.27, ref-cast-impl@1.0.27, referencing@0.58.6, regex@1.13.1, regex-automata@0.4.18, regex-syntax@0.8.11,
scopeguard@1.2.0, serde@1.0.229, serde_derive@1.0.229, smallvec@1.16.3, strum@0.28.0, strum_macros@0.28.0,
syn@2.0.119, syn@3.0.9, unicode-general-category@1.1.0, unicode-ident@1.0.27, uuid-simd@0.8.0, version_check@0.9.5,
vsimd@0.8.0, zerocopy@0.8.63
```

Crates added by `boon` 0.6.1 (49 more, 88 in all):

```text
ahash@0.8.12, aho-corasick@1.1.5, appendlist@1.4.0, base64@0.22.1, boon@0.6.1, borrow-or-share@0.2.4,
displaydoc@0.2.7, fluent-uri@0.3.2, form_urlencoded@1.2.2, getrandom@0.3.4, icu_collections@2.3.0,
icu_locale_core@2.3.0, icu_normalizer@2.3.0, icu_normalizer_data@2.3.0, icu_properties@2.3.0,
icu_properties_data@2.3.0, icu_provider@2.3.1, idna@1.1.0, idna_adapter@1.2.2, litemap@0.8.3, once_cell@1.21.4,
percent-encoding@2.3.2, potential_utf@0.1.6, proc-macro2@1.0.107, quote@1.0.47, ref-cast@1.0.27, ref-cast-impl@1.0.27,
regex@1.13.1, regex-automata@0.4.18, regex-syntax@0.8.11, serde@1.0.229, smallvec@1.16.3, stable_deref_trait@1.2.1,
syn@3.0.9, synstructure@0.14.0, tinystr@0.8.4, unicode-ident@1.0.27, url@2.5.8, utf8_iter@1.0.4, version_check@0.9.5,
writeable@0.6.4, yoke@0.8.3, yoke-derive@0.8.4, zerocopy@0.8.63, zerofrom@0.1.8, zerofrom-derive@0.1.8,
zerotrie@0.2.5, zerovec@0.11.8, zerovec-derive@0.11.6
```

## Open design questions

1. `p256` 0.14.0 or 0.13.2. 0.14.0 is current but has no JWK support and a changed API; 0.13.2 has a `jwk` feature that cannot read the fixtures. This record chooses 0.14.0 with a hand-built JWK. Confirm.
2. `p256` or `ring`. `ring` verifies and signs correctly but cannot sign deterministically, has no key validation step and compiles C and assembly. If the vet task rejects the freshness of the RustCrypto releases (`sha2` 0.11.1 is 4 days old), `ring` with `ring::digest` for SHA-256 is the alternative; its tree is 8 crates.
3. `base64` crate or an in-house decoder. Both passed. The crate adds one dependency with no transitive ones; the decoder is 7 lines and carries the canonical-trailing-bits rule itself.
4. Strict integers: the lexical pass over the text (chosen, no `arbitrary_precision`) or a full in-house tokenizer for the whole strict layer. The pass duplicates the integer logic of the visitor in a second place.
5. Core integer fields and `1.0`: typed decoding into `u64` rejects `1.0` and `1e2`; the schema validator accepts `2.0` for `type: integer`. Which one defines the wire rule, and what do the Go, TypeScript and Python SDKs do? The question needs a shared vector.
6. High-S signatures: `p256` and `ring` both accept the `(r, n - s)` twin. The draft does not say whether an SDK must reject it. If it must, the check is an explicit one in the SDK.
7. JCS number digits: `serde_json`'s printer (chosen, no new dependency, but its formatter changed from `ryu` to `zmij` between releases, so the 10000-row and Appendix B vectors must run in the SDK's tests) or the `ryu` crate (documented algorithm, one more crate, 0 transitive).
8. JCS input: canonicalizing a `serde_json::Value` (this record) or canonicalizing the checked text directly (`serde_json_canonicalizer::pipe` exists; not probed). A `Value` forces `float_roundtrip` and loses `-0` and the integer or float distinction of the source.
9. Schema validator: `jsonschema` (65 crates, active, recent) or `boon` (56 crates, last release 2025-01-07). Both have build-script crates in the tree (15 and 13); `jsonschema` brings two versions of `syn`. If the weight matters more than release cadence, `boon` is lighter.
10. `format: "uri"` assertion: both crates implement it. The decision whether the SDK asserts formats belongs to the spec (the Python and TypeScript records leave it open as well).
11. Release freshness: two of the chosen versions (`sha2` 0.11.1 and `serde_json` 1.0.154) are less than a week old at the time of this record, and so is the `serde_json_canonicalizer` oracle. Pin to those, or to the previous release of each.
12. `cargo package` layout for the SDK: the finding that an `include` entry with `..` is silently ignored, and that an outside path in `tests/` passes verification and breaks the published tests, argues for vendoring the schema and the fixtures under `rs/` and for a check in the SDK's own CI that runs `cargo test` from an unpacked `cargo package` output.

## Not probed

- Platforms other than macOS arm64 (Linux, Windows, 32-bit): build, build scripts and the `ring` assembly were run only on `aarch64-apple-darwin`.
- Minimum supported Rust version beyond the 1.99.0 pin; `p256` 0.14.0 declares 1.85 and `sha2` 0.11.1 declares 1.88 in their metadata.
- Constant-time behavior of verification and signing, performance, memory use, binary size, compile time and `no_std` or WebAssembly builds.
- `cargo audit` or `cargo vet`; that is the vet task's input, which this record feeds.
- The `jose-jwk` crate, any JSON tokenizer crate for strict parsing, `serde_json::value::RawValue`, `serde_json`'s `unbounded_depth` feature and `serde_json_canonicalizer::pipe`.
- Ed25519 in Rust (`ed25519-dalek` or `ring`): the optional algorithm is not part of the ES256 baseline.
- Remote `$ref` resolution (the schema has none) and the output formats of the validators beyond the error list.
