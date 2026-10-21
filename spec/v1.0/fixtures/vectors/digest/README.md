# Digest vectors

`appendix-b.json` holds test vectors for the three digests of draft Section 7.4: `object_digest`, `artifact_digest` and `bytes_digest`. Each digest is SHA-256 written as base64url without padding, 43 characters. The file is a JSON array, and every element has exactly these members:

| Member | Meaning |
|---|---|
| `id` | Unique name of the vector. |
| `input_kind` | `object`, `artifact` or `bytes`: which digest function applies. |
| `input` | `object`: the JSON object itself. `artifact`: the compact JWS string. `bytes`: the bytes as lowercase hex, `""` for no bytes. |
| `expected_digest` | The digest an implementation must produce for `input`. |
| `spec_defect` | `true` when the draft's printed value is not the digest its algorithm gives for `input`. |
| `appendix_value` | The digest as the draft prints it, or `null` when the draft prints none for this input. |

A harness computes the digest of `input` and requires it to equal `expected_digest`. For `object`, the digest is over the RFC 8785 canonical form, so member order and white space in the file do not matter. For `artifact`, it is over the ASCII bytes of the string, not over its decoded segments.

`appendix_value` is then compared with the computed digest. A match passes. A difference with `spec_defect` true is reported as a named skip that gives both values, never as a pass. A difference with `spec_defect` false, `spec_defect` true on a matching value, and `spec_defect` true with a `null` `appendix_value` are errors. No vector is a spec defect at this pin: every printed value reproduces.

## Sources

- `empty-body`: the `body_digest` of Appendix B.3, the digest of zero bytes.
- `intent-b2` and `operation-b3`: the JSON blocks of Appendix B.2 and B.3, with the `intent_digest` and `operation_digest` of Appendix B.4 as `appendix_value`.
- `evidence-jws-appendix-c`: the exact compact evidence JWS of Appendix C. The draft prints no digest for it, so `appendix_value` is `null`.

Every `expected_digest` was computed from the canonical bytes by two SHA-256 implementations unrelated to the SDKs, and agrees with each value the draft prints.
