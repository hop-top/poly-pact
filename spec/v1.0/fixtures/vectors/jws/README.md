# JWS vectors

Test vectors for the PACT JWS profile of draft Sections 7.2 and 7.3: ES256 compact JWS, the `typ` table, embedded holder keys, and RFC 7638 JWK thumbprints. Every SDK runs the same files unchanged. They hold public data only: public JWKs, compact JWS strings and digests. The private values behind the signatures are the published test scalars of `../../keys/` (P-256 scalars 1 to 6), except where a vector names another value.

The vectors test the baseline, ES256 alone: none of them negotiates Ed25519, which draft 7.2 allows only by explicit negotiation, so an `Ed25519` header or an OKP Ed25519 key is refused here as a deployment that has not negotiated it refuses it. A vector that tests Ed25519 lists the manifest capability `jws-ed25519` (section Optional capabilities of the [fixture README](../../README.md)) and runs with Ed25519 negotiated besides ES256. The ambiguous `EdDSA` identifier is refused everywhere.

ES256 signing is randomized, so the signatures here are fixed bytes: a harness verifies them and never re-signs to compare. Regenerating a vector changes its signature but not its meaning.

## Files

| File | Content | Manifest outcome |
|---|---|---|
| one file per verify vector, such as `header-alg-none.json` | a single verify vector | `ACCEPTED` or `REJECTED`, as its `expect` |
| `thumbprint.json` | array of thumbprint vectors | `ACCEPTED` |
| `jwk-reject.json` | array of JWKs a key loader must refuse | `REJECTED` |
| `appendix-c-keys.json` | array: the Appendix C holder and issuer keys derived from their scalars | `ACCEPTED` |

The name prefix groups the verify vectors: `appendix-c` and `rfc7515-a3` (published examples), `es256-` (signature encoding), `compact-` (segments and base64url), `header-` and `payload-` (protected header and payload rules), `holder-` (embedded holder keys), `typ-` (the 7.3 table) and `kid-`.

## Verify vectors

Every verify vector has exactly these members; a member that does not apply is `null`.

| Member | Meaning |
|---|---|
| `id` | The manifest id. |
| `description` | What the vector exercises, and its source. |
| `compact` | The compact JWS, exactly as received. |
| `expected_typ` | The typ the consumer expects, or `null` for any typ of the 7.3 table. |
| `trusted_keysets` | Object from signer role to an array of public JWKs: the keys trusted for that role. A kid is looked up only in the set of the role the typ requires. |
| `expected_holder_jkt` | For a holder-signed typ, the enrolled `holder_jkt` the embedded `jwk` must match. |
| `decode_as` | `null`, or `Evidence`: after the JWS verifies, decode the payload strictly as that type of `pact.schema.json` and validate it against the schema. |
| `expect` | `accept` or `reject`. |
| `reject_reason` | For `reject`, the reason (table below). |
| `signer_jwk` | The public JWK that made the signature, or `null`. |
| `signature_valid` | Whether the signature octets are a valid ES256 signature over the received signing input under `signer_jwk`, with the octets read by a lenient base64 decoder (padding, line breaks and the standard alphabet accepted, spare bits ignored). `null` when `signer_jwk` is not a P-256 key or the compact form has no signature segment. It shows that a vector rejected for one reason does not also fail on its signature. |
| `expected_payload` | For `accept`, the decoded payload as text, which the verifier must return byte for byte. |

A harness builds the trusted key sets and the expected `holder_jkt` from the vector, verifies `compact`, applies `decode_as` when set, and compares the outcome and, for a rejection, the reason. Each negative vector has exactly one defect, so the reason does not depend on the order of the checks; most carry a valid signature over their own signing input (`signature_valid` true).

### Signer roles

| Role | typ | Required signer (draft 7.3) |
|---|---|---|
| `requirement-publisher` | `pact-requirements+jwt` | Gateway-authorized requirement publisher |
| `issuer` | `pact-evidence+jwt` | Issuer authorized for its claim paths and scope |
| `holder` | `pact-presentation+jwt` | Enrolled agent holder key |
| `validator` | `pact-admission+jwt` | Gateway-authorized validator |
| `reporter` | `pact-outcome+jwt` | Authorized reporter for the observation type |
| `reputation-service` | `pact-reputation+jwt` | Authorized reputation service |
| `policy-authority` | `pact-learning-policy+jwt` | Native administrator or delegated policy authority |
| `learning-controller` | `pact-learning-artifact+jwt`, `pact-learning-event+jwt` | Authorized learning controller; controller authorized for that transition |
| `enrollment-authority` | none | Native administrator that enrolls agents (draft 6.1); a trust role of `config.json` only |
| `hold-authority` | none | Authority that sets and clears security holds (draft 15.4); a trust role of `config.json` only |

The role names are fixture vocabulary for the rows of the table; the draft defines no tokens for them. `enrollment-authority` and `hold-authority` sign no artifact of the 7.3 table: they name `trust` records of a case's `config.json` that the conformance profile `single-owner` checks ([../../README.md](../../README.md), section config.json additions). A holder-signed artifact is verified with its embedded `jwk` after its RFC 7638 thumbprint equals the expected `holder_jkt`; every other artifact is verified by `kid` within the key set trusted for its role. The issuer test key stands in for the requirement publisher, reporter and policy authority, which have no test key of their own; which key a role trusts is configuration.

### Reject reasons

| Reason | Meaning |
|---|---|
| `compact-form` | Not three segments separated by two periods, or an empty header segment. |
| `base64url` | A segment is not canonical unpadded base64url: padding, white space, a line break, the standard alphabet, a length of 1 mod 4, or non-zero spare bits. |
| `header-json` | The protected header is not a strict JSON object (duplicate members, invalid Unicode, not an object). |
| `header-crit`, `header-b64`, `header-jku`, `header-x5u`, `header-x5c` | The header has that member. |
| `alg-unsupported` | `alg` is missing or not `ES256` (or, where negotiated, `Ed25519`). |
| `typ-unsupported` | `typ` is missing or not in the 7.3 table. |
| `typ-mismatch` | `typ` is in the table but is not `expected_typ`. |
| `kid-missing` | A service-signed artifact has no `kid`. |
| `kid-unknown` | `kid` is not in the key set trusted for the role. |
| `jwk-missing` | A holder-signed artifact embeds no `jwk`. |
| `jwk-unexpected` | A service-signed artifact embeds a `jwk`. |
| `jwk-private` | A JWK carries a private member. |
| `jwk-invalid` | A JWK member has the wrong JSON type, `x` or `y` is not the canonical base64url of exactly 32 octets, or `key_ops` names an operation twice (RFC 7517 section 4.3). |
| `jwk-curve` | `kty` is not `EC` or `crv` is not `P-256` (where Ed25519 is negotiated, an OKP `Ed25519` key is accepted too). |
| `jwk-off-curve` | `x` and `y` are not a point of P-256; for a negotiated OKP `Ed25519` key, `x` is not the RFC 8032 section 5.1.3 encoding of a point of the subgroup of prime order L of RFC 8032 section 5.1 (small and mixed order points are refused). |
| `jwk-usage` | The JWK's `alg` is not the algorithm of its key (`ES256` for a P-256 key, `Ed25519` for a negotiated OKP key), its `use` is not `sig`, or its `key_ops` do not name `verify` (RFC 7517 sections 4.2 to 4.4); or the key that verifies a JWS is not a key for the header's `alg`. |
| `holder-jkt-mismatch` | The embedded `jwk` does not match the expected `holder_jkt`. |
| `payload-detached` | The payload segment is empty. |
| `payload-json` | The payload is not a strict JSON object. |
| `signature-length` | The signature is not 64 octets. |
| `signature-invalid` | The signature does not verify under the resolved key. |
| `payload-schema` | Used with `decode_as`: the JWS verifies, but the decoded artifact fails the schema. |

## Thumbprint, key and JWK vectors

`thumbprint.json` elements have `id`, `description`, `jwk`, `expected_thumbprint` and `source`. The RFC 7638 SHA-256 thumbprint of `jwk` must equal `expected_thumbprint`. Only the required members `crv`, `kty`, `x`, `y` enter it, in that order. The holder vectors reproduce `holder_jkt` of Appendix C; the other values are computed (`source` says which). The RFC 7638 section 3.1 example is an RSA key, outside the PACT JWS profile; `jwk-reject.json` uses it as a key to refuse.

`jwk-reject.json` elements have `id`, `description`, `jwk` and `reject_reason`. Loading `jwk` as an ES256 public key, or computing its thumbprint, must fail with that reason.

`appendix-c-keys.json` elements have `id`, `description`, `d`, `expected_x`, `expected_y` and `expected_thumbprint`. `d` is the base64url 32-octet big-endian P-256 scalar; the public point `d` times the base point must have the JWK coordinates `expected_x` and `expected_y`, which are the values Appendix C prints.

## Notes

- `es256-high-s` records current behaviour, not a decision of the draft: the ECDSA verification equation holds for the high-S twin `(R, n - S)` of a valid signature as it does for the original, and neither RFC 7518 section 3.4 nor the draft adds a low-S rule. If the draft decides to reject high S, that vector changes to `reject`.
- `appendix-c-version-mismatch` is the earlier Appendix C JWS, kept in `../../parse/appendix-c-wrong-version.jws`. Its signature is valid; its payload carries `pact_version` `0.2` where the schema requires `0.1`.
- `rfc7515-a3` is RFC 7515 Appendix A.3. Its signature is valid (`signature_valid` true), which checks the R || S handling; its header has no `typ`, so a PACT verifier rejects it.
