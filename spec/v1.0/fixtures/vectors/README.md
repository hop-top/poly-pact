# Test vectors

This directory holds the shared test vectors of PACT. Each vector file is language-neutral JSON, and each is registered in [`../manifest.json`](../manifest.json) as an entry of kind `vector`. An implementation in any language reads the files unchanged and must produce the expected results. The groups:

| Group | Draft section | Manifest `scope` | Format |
|---|---|---|---|
| `jcs/` | 7.4, RFC 8785 canonicalization | `core` | [jcs/LICENSE-NOTE.md](jcs/LICENSE-NOTE.md) |
| `digest/` | 7.4 digests | `core` | [digest/README.md](digest/README.md) |
| `jws/` | 7.2 and 7.3 JWS profile | `core` | [jws/README.md](jws/README.md) |
| `strictjson/` | 7.1 strict parse | `core` | One vector per file: `id`, `input_text` or `input_b64`, `expect` (`accept` or `reject`), `reason`. The input is decoded as an `OperationContext`. |
| `binding/` | 10.2 baseline HTTP mapping | `adapter` | This file, below. |
| `schema/` | A.3 schema, JSON Schema format `uri` per RFC 3986 | `core` | [schema/README.md](schema/README.md) |

## Binding vectors

The files of `binding/` pin the baseline HTTP mapping of draft Section 10.2: how a protected HTTP request becomes an `OperationContext`, and which requests are refused. Two implementations that pass every vector compute the same operation context, and so the same `operation_digest`, for each request the vectors describe.

The vectors have scope `adapter`: the core SDKs do not implement the HTTP baseline binding, so the adapter conformance harnesses run them. Every refused request is `INVALID_MESSAGE` (draft Section 13.4). A refused configuration is a gateway fault, not a fault of the request, and has no error code ([request-binding.md](../../profiles/request-binding.md) section 4.2).

### File format

One vector per file, named after its id. Every member is present in every file.

| Member | Value |
|---|---|
| `id` | The manifest id, `vectors/binding/<name>`. |
| `description` | What the vector shows, for readers. |
| `config` | The trusted gateway configuration, below. |
| `request` | The request as the gateway received it, below. |
| `operation_id` | The operation identifier the caller assigns. The binding does not derive it. |
| `principal_id` | The principal that native authentication established for the request. |
| `action` | The action that the installed mapping row gives the request. |
| `resources` | The resources that the installed mapping row gives the request. |
| `expect` | An object with exactly one member: `operation_context`, the complete expected `OperationContext`; `reject_reason`, the string `INVALID_MESSAGE`; or `config_error`, the value `true`: `config` fails a configuration check and no request is bound. |
| `expect_operation_digest` | `object_digest` (draft Section 7.4) of `expect.operation_context`, or `null` for a refused request or configuration. |

`config` has these members:

| Member | Value |
|---|---|
| `origin` | The public HTTPS origin of the gateway. The scheme and host are lowercased and port 443 is omitted in `target_uri`. |
| `header_allowlist` | The application headers that can alter action semantics, published as `GatewayMetadata.protected_header_names`. |
| `normalization_id` | The header normalization, published as `GatewayMetadata.header_normalization_id`. Every vector uses the baseline normalization: names in lowercase, each field line value without leading and trailing SP and HTAB, the lines of one name joined in order with a comma and one SP. |
| `mapping_version` | The installed mapping version, published as `GatewayMetadata.operation_mapping_version`. |
| `environment_id` | The environment of the gateway, `GatewayMetadata.environment_id`. It becomes `OperationContext.environment_id`. |

`request` has these members:

| Member | Value |
|---|---|
| `method` | The request method as received. |
| `raw_request_uri` | The request-target as received, octet for octet (RFC 9112 Section 3.2): origin-form or absolute-form. |
| `headers` | Every field line in the order received, each `{"name", "value"}`. `Host` is included, except in the vector of its absence, and so is `Content-Length` when there is a body. `value` is the text after the colon and the one SP that follows it; it can start or end with more SP or HTAB, which the field line then carries as optional whitespace (RFC 9112 Section 5). |
| `body_b64` | The body after transfer decoding, in standard base64 with padding; `""` for no body. |

The vectors use the configuration of the Appendix B finance gateway (Appendix B.13): origin `https://gateway.example`, allowlist `if-match` and `x-dry-run`. No vector tests a body size limit; a harness configures a maximum body size of at least 65536 bytes.

### Running a vector

1. Build the request from `request`. A harness that parses HTTP/1.1 writes the request line `method SP raw_request_uri SP HTTP/1.1`, then each header as `name: value`, then an empty line and the body. A harness that takes a request object can build one from the same members.
2. Bind it under `config` with `principal_id`, `action` and `resources` as the caller's values, and set `operation_id` and `environment_id`.
3. For `expect.config_error`, validating `config` must fail with the configuration error of the implementation, never with `INVALID_MESSAGE`; for example `bind-22-host-allowlisted` has `"expect": {"config_error": true}` and `"expect_operation_digest": null`. For `expect.reject_reason`, the binding must refuse the request with `INVALID_MESSAGE`. For `expect.operation_context`, it must produce that object, member for member, and its `object_digest` must equal `expect_operation_digest`.

The manifest entry of a vector has kind `vector`, scope `adapter`, outcome `ACCEPTED` for an expected operation context and `REJECTED` for an expected refusal or configuration error, `spec_map_row` `BIND-NN`, and `draft_section` `10.2`; its `path` and `expected` are both the file.

### The vectors

Some rows are pairs. The relation between their digests follows from the expected values, so an implementation that matches both vectors of a pair has it.

| Row | Files | Shows | Basis |
|---|---|---|---|
| BIND-01 | `bind-01-appendix-b3` | The request of the finance gateway binds to the Appendix B.3 operation context. Its digest is `R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0`, the `operation_digest` of Appendix B.4 and B.7. `Authorization` and `PACT-Presentation` are never covered, and `Accept` is not allowlisted. | draft 10.2, B.3, B.4 |
| BIND-02 | `bind-02-query-order-ab`, `bind-02-query-order-ba` | Query order is kept: `?a=1&b=2` and `?b=2&a=1` have different digests. | draft 10.2 |
| BIND-03 | `bind-03-space-percent-20`, `bind-03-space-plus` | `%20` and `+` in the query are kept as sent and have different digests. | draft 10.2 |
| BIND-04 | `bind-04-duplicate-key` | A repeated query parameter is kept with both values in order. | draft 10.2 |
| BIND-05 | `bind-05-fragment` | A fragment is refused. | draft 10.2 |
| BIND-06 | `bind-06-userinfo` | Userinfo in an absolute-form target is refused. | draft 10.2 |
| BIND-07 | `bind-07-content-encoding-gzip` | A body with `Content-Encoding: gzip` is refused. | draft 10.2 |
| BIND-08 | `bind-08-body-compact`, `bind-08-body-spaced` | The same JSON with and without white space: other body bytes, so other `body_digest` values and digests. `content-type` is covered because the body is not empty. | draft 7.4, 10.2 |
| BIND-09 | `bind-09-header-plain`, `bind-09-header-case-and-whitespace` | `if-match: "v1"` and `IF-MATCH:` with SP and HTAB around `"v1"` have the same digest: names are lowercased, and a field value excludes leading and trailing whitespace. | draft 10.2; RFC 9110 Section 5.5; RFC 9112 Section 5 |
| BIND-10 | `bind-10-header-not-allowlisted` | Headers outside the allowlist are not covered: the BIND-01 request with `X-Request-Kind` and another `Accept` has the B.3 digest. | draft 10.2 |
| BIND-11 | `bind-11-forwarding-headers` | `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port` and `Forwarded` do not select the origin: the B.3 digest. | draft 10.2 |
| BIND-12 | `bind-12-default-port` | The configured origin `https://gateway.example:443` is written without the default port: the B.3 digest. | draft 10.2 |
| BIND-13 | `bind-13-encoded-unreserved` | `%41` encodes the unreserved `A`: refused. | draft 10.2; RFC 3986 Section 2.3 |
| BIND-14 | `bind-14-encoded-slash-path` | `%2F` in the path: refused. | draft 10.2 |
| BIND-15 | `bind-15-non-ascii-host` | An absolute-form target whose host has raw non-ASCII octets, which the host grammar does not allow: refused. | RFC 3986 Section 3.2.2; [request-binding.md](../../profiles/request-binding.md) section 4.1 |
| BIND-16 | `bind-16-repeated-header` | Two `If-Match` field lines are joined in order as `"a", "b"`. | draft 10.2; RFC 9110 Sections 5.2, 5.3 |
| BIND-17 | `bind-17-lowercase-hex-path`, `bind-17-lowercase-hex-query` | Lowercase hexadecimal digits in an escape, in the path (`%c3%a9`) and in the query (`%2f`, where `%2F` is accepted): refused. | draft 10.2; RFC 3986 Section 2.1 |
| BIND-18 | `bind-18-overlong-utf8`, `bind-18-invalid-utf8-query` | Escapes that are not well-formed UTF-8: `%C0%AF`, an overlong form of `/`, in the path, and `%FF` in the query. Refused. | draft 10.2; RFC 3629 Sections 1, 3, 10 |
| BIND-19 | `bind-19-normal-form-query` | A query in normal form is kept octet for octet: uppercase escapes, `%2F`, an empty value, a repeated key, a key without a value, the order as sent. | draft 10.2 |
| BIND-20 | `bind-20-dot-segment`, `bind-20-dots-in-segment` | A complete `..` path segment would be removed by path segment normalization, so it is an ambiguous encoding and is refused. Dots inside a segment (`INV..1042`, `...`) and in the query (`?x=./..`) are not dot segments and are kept. | draft 10.2; RFC 3986 Sections 3.3, 5.2.4, 6.2.2.3 |
| BIND-21 | `bind-21-duplicate-host` | Two `Host` field lines, `Host` and `host` with the same value: refused. | RFC 9112 Section 3.2; [request-binding.md](../../profiles/request-binding.md) RB-65 |
| BIND-22 | `bind-22-host-allowlisted` | The Appendix B allowlist with `host` added: a configuration error, not a refused request. | [request-binding.md](../../profiles/request-binding.md) RB-20, section 4.2 |
| BIND-23 | `bind-23-missing-host` | An origin-form request with no `Host` field line: refused. | RFC 9112 Section 3.2; [request-binding.md](../../profiles/request-binding.md) RB-66 |
| BIND-24 | `bind-24-invalid-host` | `Host: gateway.example:abc`, a port that is not digits: refused. | RFC 9112 Section 3.2; RFC 3986 Section 3.2.3; [request-binding.md](../../profiles/request-binding.md) RB-66 |

Every expected operation context was written from the draft rules above. Every `body_digest` and `expect_operation_digest` was computed by a cross-check script of the source repository, outside the mirrored tree, which shares no code with any SDK: SHA-256, base64url without padding, and RFC 8785 canonicalization of the context. The script also derives each operation context, or refusal, from the request on its own and agrees with every vector.
