# Test keys

## Purpose

These are the public test keys of the PACT draft, Appendix C (the cryptographic fixture), extended with eight more roles and one Ed25519 pair. They are deliberately public. They MUST NOT be used in production: not for production identities, not for signing, not as trust anchors. The private values are published in `test-private-scalars.json`, so anyone can derive every key here. Files are JSON only (JWK), so any SDK harness can load them; nothing in this directory is specific to one language.

## Files

Public JWK files carry `kty`, `crv`, `x`, `y` (OKP has no `y`), `kid`, `alg` and `use "sig"`, and no private members.

| File | Role | Private value | kid | alg |
|---|---|---|---|---|
| `holder.jwk.json` | holder | P-256 scalar 1 | `test-holder-key-1` | ES256 |
| `issuer.jwk.json` | issuer | P-256 scalar 2 | `test-issuer-key-1` | ES256 |
| `adversarial.jwk.json` | adversarial | P-256 scalar 3 | `test-adversarial-key-1` | ES256 |
| `reputation-service.jwk.json` | reputation service | P-256 scalar 4 | `test-reputation-service-key-1` | ES256 |
| `learning-controller.jwk.json` | learning controller | P-256 scalar 5 | `test-learning-controller-key-1` | ES256 |
| `validator.jwk.json` | validator | P-256 scalar 6 | `test-validator-key-1` | ES256 |
| `executor.jwk.json` | executor | P-256 scalar 7 | `test-executor-key-1` | ES256 |
| `evaluator.jwk.json` | evaluator | P-256 scalar 8 | `test-evaluator-key-1` | ES256 |
| `security-authority.jwk.json` | security authority | P-256 scalar 9 | `test-security-authority-key-1` | ES256 |
| `holder-2.jwk.json` | second holder | P-256 scalar 10 | `test-holder-key-2` | ES256 |
| `ed25519.jwk.json` | optional algorithm negotiation test | Ed25519 seed (see below) | `test-ed25519-key-1` | Ed25519 |
| `test-private-scalars.json` | private values for all eleven keys, labeled as public test keys | | | |

Appendix C defines only the holder (scalar 1) and issuer (scalar 2) keys. Its issuer JWK has `kid` `test-issuer-key-1`. Its holder JWK has no `kid`, `alg` or `use`; this fixture adds `kid` `test-holder-key-1`, `alg` ES256 and `use` `sig`. That does not change the thumbprint, because RFC 7638 covers only the required members. The `kid`s for the other roles are chosen by this fixture.

## Format v2 keys

Format v2 of the fixtures ([../README.md](../README.md), section Format v2) adds the four P-256 keys of scalars 7 to 10. Each is registered in the manifest as an entry of kind `key`, scope `core`, spec-map row `CL-C`, draft section `C`, with the id `keys/<role>`, like the keys above.

| File | Signs |
|---|---|
| `executor.jwk.json` | Outcome reports of a resource service or trusted executor (draft Section 14.2). |
| `evaluator.jwk.json` | Outcome reports of an authorized evaluator or task owner (Section 14.2). |
| `security-authority.jwk.json` | `SECURITY` and `REMEDIATION` reports (Sections 14.2, 14.5 and 15.4). |
| `holder-2.jwk.json` | Presentations of the same agent after a key rotation (Sections 6.4 and 15.4). Its RFC 7638 thumbprint, the `holder_jkt` of a presentation it signs, is `ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg`. |

The role names are the `signer` values of a case's `signing.json`. The issuer key still stands in for the gateway reporter and the policy authority, as [../vectors/jws/README.md](../vectors/jws/README.md) describes, and the committed outcome mapping cases keep it for every reporter.

## Derivation

**P-256 keys.** The private scalar is the integer n (1 to 10), written as a 32-byte big-endian value. The public point is n times the P-256 base point. The JWK `x` and `y` are the base64url (no padding) encodings of the 32-byte coordinates. In `test-private-scalars.json`, `d` is the base64url of that same 32-byte scalar.

**Ed25519 pair.** The seed is the 32-byte value from RFC 8032 section 7.1, test vector 1, hex `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`. It is also the private key in RFC 8037 appendix A.1. The public key `x` is `11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`. The JWK is `kty` OKP, `crv` Ed25519, `alg` Ed25519 (the fully specified JOSE algorithm of RFC 9864). The pair exists for the optional Ed25519 algorithm negotiation test; ES256 stays the baseline.

## Probe result

Run on 2026-10-15 with a throwaway Go program using only the standard library (`crypto/ecdh`, cross-checked against `crypto/elliptic`). Results:

* The public point of scalar 1 equals the Appendix C holder JWK `x` and `y`.
* The public point of scalar 2 equals the Appendix C issuer JWK `x` and `y`.
* The RFC 7638 thumbprint of the holder JWK is `xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M`, which equals `holder_jkt` in Appendix C.
* The compact evidence JWS in Appendix C verifies under `issuer.jwk.json`.
* The Ed25519 public key equals the RFC 8032 and RFC 8037 values given above.

Scalars 7 to 10 were derived on 2026-10-16 in the same way (`crypto/ecdh`, cross-checked against `crypto/elliptic`). The RFC 7638 thumbprint of `holder-2.jwk.json` is `ahxE1XEYqxvLIZy3r4nx9RE4E0683KndykyuZTK9xQg`; the pactfix tests recompute every public key from its scalar and the thumbprint from the file.

A mismatch on any of these would have stopped the work; none occurred.
