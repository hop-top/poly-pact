# PACT request binding and native translation profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## 1. Purpose and status

The [draft](../draft.md) binds a presentation to one actual operation (§10.2, §11.3 step 5) and gives the baseline HTTP mapping in a few sentences. An adapter still has to decide, for every request it protects, where the origin comes from, which headers are consequential, how a path becomes an action and resources, what the mapping version covers, and what the gateway may send downstream once the request is admitted. Two adapters that decide differently compute different digests for the same request, or the same digest for requests that do different things. This document makes those decisions once for every integration profile and adapter. Which encodings are ambiguous is no longer one of them: draft §10.2 defines them, and section 4.1 gives the rule that refuses each.

It is the profile deliverable for finding G04 of `docs/handoff.md` (source repository only, not part of the mirror): pin the origin, method, path and query, body, principal, resource and action mapping, consequential headers, mapping version, paging, fixed queries, and downstream translations. The cross-language test vectors of the baseline HTTP mapping are the binding vectors of [`fixtures/vectors/README.md`](../fixtures/vectors/README.md#binding-vectors); they are not part of this document.

It covers:

- the operation context of a protected HTTP request under the baseline mapping (section 3);
- every request form the baseline mapping refuses (section 4);
- the table that maps a request to an action and resources (section 5);
- what the mapping version names and when it changes (section 6);
- the translation of an admitted gateway request into downstream requests, with paging and fixed queries (section 7);
- a worked example for the finance gateway of Appendix B (section 8).

Canonical message mappings for JSON-native protocols (draft §10.2, last paragraph) are not covered; the [MCP profile](mcp/profile.md) states its own. Transport profiles (draft §13.3.1) are not covered.

The document adds no wire field and no protocol requirement. Where this document and the draft differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. Sections 2 to 7 and 9 are normative for a profile that claims enforced support; sections 8, 10, 11, and 12 are informative. A profile can make a rule stricter. It MUST NOT weaken one.

The rules carry the identifiers RB-1 to RB-66 so that profiles, fixtures, and reviews can cite them. In the "Basis" column, "draft §x" cites the draft, an RFC or other external source cites the section read for this document (section 12), and "profile" marks a convention this document adds.

### 1.1 Draft anchors

| Draft section | What it fixes for request binding |
|---|---|
| §4.2 | Native context mappings come from trusted gateway configuration; a profile, discovery response, or signed claim cannot install or broaden them. |
| §4.3 | PACT never exchanges a declaration for a more privileged identity; a connector with a service account preserves the principal's native restrictions. |
| §7.1, §7.4 | PACT objects are UTF-8 JSON; `object_digest` and `bytes_digest` are SHA-256, base64url without padding. |
| §10.2 | The members of `OperationContext` and the baseline HTTP mapping: method, target URI, body digest, headers, and the same mapping version at issuance and validation. |
| §10.3 | A material change needs a new contract and presentation; native idempotency governs side effects; an ambiguous non-idempotent action is never repeated automatically. |
| §11.3 step 5, §11.5 | The validator reconstructs the actual operation with the installed adapter and compares its digest; the gateway enforces active revisions at handoff. |
| §13.1, §13.4 | Metadata publishes the operation mapping version; error codes `INVALID_MESSAGE`, `CONTEXT_MISMATCH`, `REQUIREMENTS_CHANGED`, `UNSUPPORTED_REQUIREMENT`. |
| §17.1, §17.2, §17.5 | `map_operation` covers all consequential request data; mappings are explicit and versioned; the executor identity class is declared per operation. |
| §19 | Credential headers never appear in receipts, outcome reports, or logs. |
| §20.1 | At most 256 resources in an operation. |
| §22.2 | A modified body, query, consequential header, action, or resource yields a context mismatch. |
| Appendix A | The schema bounds of `OperationContext` and `GatewayMetadata`. |
| Appendix B.2, B.3, B.13 | The finance gateway used in section 8. |

## 2. Terms

| Term | Meaning in this document |
|---|---|
| Gateway request | The protected HTTP request as the gateway receives it from the agent. |
| Binding | Deriving the `OperationContext` of a gateway request (section 3). |
| Covered | Part of the operation context. A change to a covered part changes the operation digest (draft §7.4, Appendix A.2). |
| Consequential header | An application header that can alter action semantics (draft §10.2). |
| Mapping table | The installed, versioned table that gives the action and resources of a gateway request (section 5). One row per protected route. |
| Translation table | The installed, versioned table that gives the downstream requests of an admitted gateway request (section 7). One row per mapping row. |
| Downstream request | A request the gateway or its connector sends to the native resource service to execute the admitted operation. |
| Continuation | A value in a downstream response that names the next part of a result: an OData or Microsoft Graph next link, a skip token, a cursor. |
| Fixed query | A downstream query or statement whose text is a constant of the translation row. |
| Mapping version | The value the gateway publishes as `GatewayMetadata.operation_mapping_version` (section 6). |

## 3. Binding a request

### 3.1 Origin

| # | Rule | Basis |
|---|---|---|
| RB-1 | `target_uri` begins with the public HTTPS origin set in trusted gateway configuration. The origin is `https://`, a host, and an optional port, with no path, query, fragment, or userinfo. The scheme and host are lowercased and port 443 is omitted. | draft §4.2, §10.2; RFC 3986 §6.2.2.1, §6.2.3; RFC 9110 §4.2.2, §4.2.3 |
| RB-2 | The configured host is ASCII: a registered name of unreserved and sub-delims characters (an internationalized name in its IDNA encoding, such as `xn--bcher-kva.example`), a dotted IPv4 address, or a bracketed IPv6 address without a zone identifier. A non-ASCII or percent-encoded host is a configuration error, because percent-encoding in a host only represents UTF-8 octets. | RFC 3986 §3.2.2; profile |
| RB-3 | No request header selects or changes the origin, the path, or the query: not `Host`, not `Forwarded`, not the `X-Forwarded-*` family, and not a header that rewrites the path such as `X-Original-URL` (fixture `COMMON-03.target-uri`). `Forwarded` cannot be relied on, because any node on the way, including the client, can modify it. | draft §10.2; RFC 7239 §8.1 |
| RB-4 | An absolute-form request-target is accepted. Its authority is checked (no userinfo, ASCII, a non-empty host) and then dropped, and `target_uri` uses the configured origin whatever scheme (`http` or `https`) and authority the target names. An origin server would otherwise use the host of an absolute-form target. Whether a differing authority should be refused is open item O1. | RFC 9112 §3.2.2; profile |

### 3.2 Method

| # | Rule | Basis |
|---|---|---|
| RB-5 | `method` is the request method with its ASCII letters uppercased. A method that is empty or has any octet other than an ASCII letter is refused, because the schema pattern of `method` is `^[A-Z]+$`; only ASCII letters are mapped, so no Unicode case mapping can produce a letter. | draft §10.2; Appendix A schema |
| RB-6 | HTTP methods are case-sensitive tokens, so uppercasing makes `get` and `GET` one operation, and a token method with a digit or hyphen, such as `M-SEARCH`, cannot be bound. Open item O4. | RFC 9110 §9.1 |

### 3.3 Path and query

| # | Rule | Basis |
|---|---|---|
| RB-7 | `target_uri` is the origin followed by the exact path and query of the request-target: the whole origin-form target, or the part of an absolute-form target after its authority. Octets, percent-encodings, and query order are kept. Nothing is decoded, re-encoded, or reordered. | draft §10.2; RFC 9112 §3.2.1, §3.2.2 |
| RB-8 | These forms are not ambiguous encodings, because RFC 3986 syntax-based normalization leaves them unchanged, and they are bound exactly as sent: empty segments (`//a//b`), dots that are not a complete segment (`/a..b`, `/.../`, `/a.b/`), dots in the query (`?x=./..`), an empty query (`/a?`), escapes of reserved and other characters in the path except `%2F` (`%3F`, `%25`, `%5C`, `%00`), `%2F` in the query, `+` in the query, and repeated query parameters. Section 5 decides whether a mapping row accepts them, and section 7 forbids sending a decoded or normalized form downstream. Encoding a reserved character changes how a URI is interpreted, and `%00` and back-end file systems need care. A complete `.` or `..` segment is not in this list: it is refused (RB-9). | draft §10.2; RFC 3986 §2.2, §3.3, §6.2.2, §7.3; profile |
| RB-9 | A fragment, userinfo, a non-ASCII host, a character RFC 3986 does not allow in a path or query, a malformed escape, and the ambiguous encodings are refused: an escape of an unreserved character, a lowercase hexadecimal digit in an escape, decoded octets that are not UTF-8, `%2F` in the path, and a complete `.` or `..` path segment, which path segment normalization removes. Section 4.1 has one sentence per rule. | draft §10.2; RFC 3986 §3.3, §5.2.4, §6.2.2.3; section 4 |
| RB-10 | `target_uri` has at most 1024 characters. | Appendix A schema |

### 3.4 Body

| # | Rule | Basis |
|---|---|---|
| RB-11 | `body_digest` is `bytes_digest` of the request body after transfer decoding. An empty body hashes the empty byte string, `47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU`. | draft §7.4, §10.2, Appendix B.3 |
| RB-12 | A request with a `Content-Encoding` field is refused, whatever the value, including `identity` and an empty value. | draft §10.2; RFC 9110 §8.4 |
| RB-13 | Chunked is the only transfer coding accepted, and it is removed before hashing. A request with any other transfer coding is refused, because the body would not be known to be transfer-decoded. Every recipient must be able to parse chunked. | RFC 9112 §6.1; profile |
| RB-14 | A body longer than the gateway's configured maximum is refused, whether a `Content-Length` declares it or the read finds it. A maximum of zero admits only an empty body. The request keeps its body for the native error path. | profile |
| RB-15 | A body that cannot be read to its end for another reason, such as a reset connection, is not a refused request form. No operation context is produced, nothing is admitted, and the native error path applies. | profile |

### 3.5 Headers

| # | Rule | Basis |
|---|---|---|
| RB-16 | `headers` holds, under lowercase names, every allowlisted header that is present, plus `content-type` when the body is not empty. An absent header has no member. An empty value is kept as `""`. With no covered header, `headers` is `{}`. | draft §10.2, Appendix B.3 |
| RB-17 | The gateway publishes its allowlist as `GatewayMetadata.protected_header_names`. Each name is an RFC 9110 token, matched without regard to case, written in lowercase, and listed once. The allowlist and `content-type` together have at most 64 names. Draft §19 reads the same list as credential material (open item O5). | draft §10.2, §13.1, Appendix B.13; RFC 9110 §5.1, §5.6.2; Appendix A schema |
| RB-18 | The baseline list of consequential headers is the table that follows this one. For each protected route, an integration profile either covers each baseline header (puts it in the allowlist) or records one of two reasons for not doing so: (a) the translation row does not forward the header downstream, or replaces it with a constant (RB-51); or (b) a declared native dependency that the downstream gives the header no action-changing meaning on that route, in the form of deployment requirement DR5 of the [basic profile](basic/profile.md). Saying nothing is not a reason. `content-type` is covered without being listed whenever the body is not empty (RB-16); listing it also covers it on a request without a body. | draft §10.2; profile |
| RB-19 | Mechanism and application additions: an integration profile adds to the allowlist every other header that the gateway or the downstream gives action-changing meaning on a protected route, and names it in its route table (template section 2) or its native dependencies (template section 4). Appendix B.13 adds `x-dry-run`. | draft §10.2, Appendix B.13; profile |
| RB-20 | These names are never covered, and allowlisting one is a configuration error: `authorization`, `cookie`, `set-cookie`, every `pact-` name (including `pact-presentation` and `pact-admission`), `connection`, `keep-alive`, `te`, `transfer-encoding`, `upgrade`, every `proxy-` name (including `proxy-authorization` and `proxy-connection`), `signature`, `signature-input`, and `host`. `Host` never selects the origin (RB-3) and is never part of the operation context, whether or not a server keeps it among the field lines it hands over. | draft §10.2, §19; RFC 9110 §7.6.1, §11.6.2, §11.7.2; RFC 9421 §4.1, §4.2; RB-3 |
| RB-21 | A header that carries the identity or credential of a mechanism is never allowlisted. The integration profile names such headers; for example, the [mTLS profile](mtls/profile.md) reads the forwarded-certificate header of an allowlisted terminator for identity (MTLS-24) and ignores and removes every other forwarded-identity header (MTLS-26). Identity is bound through `principal_id` and native authentication. | draft §10.2; profile |
| RB-22 | A name listed as a connection option in any `Connection` field line is hop-by-hop for that request and is left out of `headers`, even when it is allowlisted. An intermediary removes such fields before forwarding. Open item O2. | RFC 9110 §7.6.1 |
| RB-23 | The baseline header normalization: names are lowercased (ASCII only); each field line value loses its leading and trailing SP and HTAB; the field lines of one name are joined in the order received, separated by a comma and one SP. Nothing else changes: list members, inner whitespace, quoting, and the case of values are kept. Repeated lines of a singleton field are joined too (open item O11). | RFC 9110 §5.2, §5.3, §5.5 |
| RB-24 | A covered value is refused when it has a control octet other than HTAB (NUL, CR, LF, DEL, and the others), when it is not valid UTF-8 and so cannot be carried exactly in PACT JSON, when it has more than 8192 characters after joining, and when one header is held under two names that differ only in case, so that the order of its field lines is lost. | RFC 9110 §5.3, §5.4, §5.5; draft §7.1; Appendix A schema |
| RB-25 | `header_normalization_id` names the normalization of RB-22 to RB-24 with the exclusions of RB-20, at version 0.1 of this document. A gateway that applies it publishes an identifier of its own choosing (Appendix B.13 uses `finance-header-normalization-1`) and states in its integration profile that the identifier names this normalization (open item O7). A gateway that normalizes otherwise publishes another identifier and documents its rules. | draft §10.2; profile |
| RB-65 | A request with more than one `Host` field line is refused, with names in any case and even when the values are equal. A server must answer such a request with 400 (Bad Request). Some servers refuse it before the binding runs and others pass it on, so the binding refuses every such request it receives, and every implementation gives the same result. The binding still reads no `Host` value (RB-3). | RFC 9112 §3.2; profile |
| RB-66 | A request with an origin-form target and no `Host` field line is refused. The authority of an absolute-form target, or the `:authority` pseudo-header field of HTTP/2, stands in for `Host`, so a request with either and no `Host` line is not refused; a request object of field lines carries `:authority` as its `Host` line, as an ASGI server does. A `Host` value that is present is refused unless, without leading and trailing SP and HTAB, it is `uri-host [ ":" port ]` with a host that is not empty: an IP literal (an IPv6 address without a zone identifier, or IPvFuture), or a registered name of unreserved, sub-delims, and percent-encoded characters, which includes a dotted IPv4 address; then an optional `:` and port of digits. The binding still reads no `Host` value (RB-3). | RFC 9112 §3.2, §3.2.2; RFC 9110 §4.2.2, §7.2; RFC 9113 §8.3.1; RFC 3986 §3.2.2, §3.2.3; ASGI HTTP specification 2.5 |

The baseline list of RB-18:

| Header | Why it can alter action semantics | Source |
|---|---|---|
| `content-type` | The media type defines the data format and how the recipient processes the content. Without it, a recipient may assume `application/octet-stream` or examine the data to decide. | RFC 9110 §8.3 |
| `accept` | States the client's preferences for the response media type. It can select another representation, and OData services may refuse to change format between pages. | RFC 9110 §12.5.1; OData Part 1 §11.2.6.7 |
| `prefer` | Asks for server behaviors such as an asynchronous response (`respond-async`), strict or lenient handling of errors (`handling`), or, for OData, a maximum page size (`maxpagesize`). A server ignores preferences it does not support. | RFC 7240 §2, §4.1, §4.4; OData Part 1 §11.2.6.7 |
| `if-match` | Makes the method conditional on the current entity tag of the target resource, to prevent lost updates. | RFC 9110 §13.1.1 |
| `if-none-match` | Makes the method conditional; with `*` it prevents an unsafe method such as PUT from modifying an existing representation. | RFC 9110 §13.1.2 |
| `idempotency-key` | Lets the resource recognize a retry of the same request: a duplicate key and fingerprint returns the earlier result instead of executing again. It is defined only by an expired Internet-Draft (open item O13). | draft-ietf-httpapi-idempotency-key-header-07 §2, §2.6 |

### 3.6 Principal

| # | Rule | Basis |
|---|---|---|
| RB-26 | `principal_id` is the principal that `authenticate_native` established for this request: the user or workload whose native authority is relevant. Under the [identity mapping rules](identity-mapping.md) (§3.4) it is the authenticated entity itself, or the user for whom a registered client acts. It is never the `agent_id` of the presentation, and never the gateway's or the executor's own identity. | draft §3, §10.2, §17.1, §17.5 |
| RB-27 | No header, query parameter, body member, AgentProfile field, presentation member, or model output selects or changes `principal_id`, even when it is signed. | draft §10.2; profile |

### 3.7 Members the binding does not derive

| # | Rule | Basis |
|---|---|---|
| RB-28 | `environment_id` comes from trusted configuration and equals `GatewayMetadata.environment_id`. | draft §4.2, Appendix B.13 |
| RB-29 | `operation_id` is a correlation identifier, not a guarantee of exactly-once execution. Which party assigns it, and how the gateway obtains the same value when it reconstructs the operation at validation, is open item O9. | draft §10.3 |
| RB-30 | `action` and `resources` come from the mapping table (section 5). | draft §10.2 |

## 4. Requests the baseline mapping refuses

### 4.1 Request rules

The baseline mapping refuses a request in each case below. The table has 23 rows, one for each request rule of the reference implementation (section 10). Every refusal is reported as `INVALID_MESSAGE` (draft §13.4, HTTP 400). It happens before any PACT evaluation, and the request is not executed through the protected path. This document does not fix which rule is reported when a request breaks several; the reference implementation checks the method, then the target, the target length, the `Host` field lines, the codings, the body, and the headers, in that order.

| Rule | Refused when | Source |
|---|---|---|
| `no-request` | There is no request, or the request has no target URL. Only a program that calls the binding directly can cause this; a server never does. | profile |
| `method` | The method is empty or has an octet other than an ASCII letter: `M-SEARCH` and `GET1` are refused, and so are methods with non-ASCII letters such as `ſet` and `GİT`. | Appendix A schema; RFC 9110 §9.1 |
| `target-form` | The request-target is not origin-form or an `http` or `https` absolute-form: asterisk-form (`*`), authority-form (`gateway.example:443`), an opaque or other-scheme URI (`foo:bar`, `ftp://gateway.example/x`), an absolute-form with an empty host (`https:///x`), an absolute-form with an empty path (`https://gateway.example`, `https://gateway.example?x`), which is refused rather than normalized to `/`, and an empty request-target. | RFC 9112 §3.2; RFC 9110 §4.2.1, §4.2.2, §4.2.3 |
| `fragment` | The request-target contains `#`, even with an empty fragment, or a program set a fragment on the request. | draft §10.2; RFC 9112 §3.2.1 |
| `userinfo` | An absolute-form target has userinfo, even an empty one (`https://@gateway.example/x`), or a program set userinfo on the request. | draft §10.2; RFC 9110 §4.2.4 |
| `non-ascii-host` | The authority of an absolute-form target has a non-ASCII octet or a percent-encoding, which in a host only represents UTF-8. | RFC 3986 §3.2.2 |
| `invalid-character` | The path or query has an octet RFC 3986 does not allow there: a raw non-ASCII octet, space, a control, DEL, `"`, `<`, `>`, `\`, `^`, `` ` ``, `{`, `}`, the vertical bar, `[`, or `]` (open item O3). The query may contain `/` and `?`. | RFC 3986 §3.2.2, §3.3, §3.4 |
| `malformed-escape` | A `%` is not followed by two hexadecimal digits. | RFC 3986 §2.1 |
| `encoded-unreserved` | An escape encodes an unreserved character (`%41`, `%7A`, `%30`, `%2D`, `%5F`, `%7E`, `%2E`). Such a URI is equivalent to the one with the character itself, so one target would have two spellings, and `%2E%2E` would hide a dot segment. | RFC 3986 §2.3, §6.2.2.2; RFC 9110 §4.2.3 |
| `lowercase-hex` | An escape has a lowercase hexadecimal digit (`%2f`, `%c3%a9`, `%aB`). The case of the digits is not significant, so one target would have two spellings. | RFC 3986 §2.1, §6.2.2.1 |
| `invalid-utf8` | The path, or the query, is not valid UTF-8 once its escapes are decoded: an overlong form (`%C0%AF`, `%E0%80%AF`, `%C0%80`), a surrogate (`%ED%A0%80`), a code point above U+10FFFF (`%F4%90%80%80`), a stray or truncated octet (`%FF`, `%C3`). The check runs over the whole decoded component, so a sequence split by a slash (`%C3/%A9`) is refused too. Overlong forms have been used to hide `/../` from a check. | RFC 3629 §3, §10 |
| `encoded-slash` | The path contains `%2F`. A downstream that decodes before it splits the path sees another segment structure. `%2F` in the query is data and is kept. | RFC 3986 §2.2, §7.3; profile |
| `dot-segment` | The path has a complete `.` or `..` segment, the text between two `/` or after the last one: `/a/./b`, `/a/../b`, `/.`, `/..`, `/a/.`, `/a/..`. Path segment normalization removes such segments with `remove_dot_segments`, so one target would have two spellings, and a downstream that resolves them reaches another path. Dots inside a segment (`/a..b`, `/.../`) and dots in the query are kept (RB-8). An encoded dot segment such as `%2E%2E` is refused as `encoded-unreserved`. | draft §10.2; RFC 3986 §3.3, §5.2.4, §6.2.2.3 |
| `target-too-long` | `target_uri`, the normalized origin with the path and query, has more than 1024 characters. | Appendix A schema |
| `content-encoding` | The request has a `Content-Encoding` field, whatever its value. | draft §10.2; RFC 9110 §8.4 |
| `transfer-coding` | The request names a transfer coding other than chunked, in a `Transfer-Encoding` field or in the codings the server reports. | RFC 9112 §6.1; profile |
| `body-too-large` | The body is longer than the configured maximum: a declared `Content-Length` says so before anything is read, the read finds more bytes than the maximum even though `Content-Length` declared fewer, or a server-side byte limit stops the read. | profile |
| `header-value` | The joined value of a covered header has a control octet other than HTAB, or is not valid UTF-8. This includes `content-type` when the body is not empty. | RFC 9110 §5.5; draft §7.1 |
| `header-too-long` | The joined value of a covered header has more than 8192 characters. The limit applies after the field lines are joined. | Appendix A schema; RFC 9110 §5.4 |
| `header-key-collision` | A covered header is held under two names that differ only in case, so the relative order of its field lines is lost. Only a request built by a program can have this form. | RFC 9110 §5.3 |
| `duplicate-host` | The request has more than one `Host` field line (RB-65): `Host: gateway.example` twice, `Host` and `host`, or two different values. | RFC 9112 §3.2 |
| `missing-host` | The target is origin-form and the request has no `Host` field line and no `:authority` (RB-66). An absolute-form target without `Host` is not refused. | RFC 9112 §3.2, §3.2.2; RFC 9110 §7.2; RFC 9113 §8.3.1 |
| `invalid-host` | A `Host` value is not `uri-host [ ":" port ]` with a non-empty host (RB-66): an empty value, `gate way.example`, `gateway.example/x`, `a@b`, `[::1`, `[fe80::1%25en0]`, `gateway.example:abc`, `café.example`, `%zz.example`. | RFC 9112 §3.2; RFC 9110 §4.2.2, §7.2; RFC 3986 §3.2.2, §3.2.3 |

These are not refused: a request that carries headers outside the allowlist, credentials, presentation headers, or forwarding headers (they are not covered and are ignored by the binding); empty segments, dots that are not a complete segment, and the escapes listed in RB-8; a `content-type` with an invalid value on a request without a body when `content-type` is not allowlisted (it is not covered, so it is not examined).

### 4.2 Configuration checks

A gateway configuration that fails one of these checks is a gateway fault, not a fault of the request. The gateway serves no protected request under it; it does not report `INVALID_MESSAGE` for it. The table has 16 rows, one for each configuration error of the reference implementation.

| Check | Refused configuration | Source |
|---|---|---|
| Scheme | The origin is not `https://` followed by an authority. `http`, a missing scheme, and an empty origin are refused. | draft §10.2 |
| Path, query, fragment | The origin has a path (a trailing `/` included), a query, or a fragment. | draft §10.2 |
| Userinfo | The origin has userinfo. | RFC 9110 §4.2.4 |
| Non-ASCII host | The origin host has a non-ASCII octet or a percent-encoding. A name in its IDNA encoding is accepted. | RFC 3986 §3.2.2 |
| Unclosed IP literal | The origin host starts with `[` and has no `]`. | RFC 3986 §3.2.2 |
| IP literal form | The IP literal is not an IPv6 address without a zone identifier: IPvFuture (`[v1.x]`), an IPv4 address in brackets, and a zone (`[fe80::1%25en0]`) are refused. | RFC 3986 §3.2.2 |
| Text after the IP literal | Anything but `:port` follows the closing bracket. | RFC 3986 §3.2.2 |
| Empty host | The origin host is empty (`https://`, `https://:443`). | RFC 9110 §4.2.2 |
| Host character | The registered name has a character outside unreserved and sub-delims, such as a space. | RFC 3986 §3.2.2 |
| Port | The port is not a decimal number from 1 to 65535 written without a leading zero or sign. An empty port is accepted and omitted, as is 443. | RFC 3986 §6.2.3; RFC 9110 §4.2.3; profile |
| Header name | An allowlisted name is not an RFC 9110 token: empty, with a space, a colon, or a non-ASCII character. | RFC 9110 §5.1, §5.6.2 |
| Excluded header | An allowlisted name is one of RB-20, in any case. | RB-20 |
| Duplicate header | A name is listed twice, in any case. | profile |
| Header count | The allowlist with `content-type` has more than 64 names. | Appendix A schema |
| Identifiers | `header_normalization_id` or `operation_mapping_version` is empty, has more than 1024 characters, or is not UTF-8. | Appendix A schema |
| Body limit | The configured body maximum is negative. | profile |

## 5. Action and resource mapping

### 5.1 Template

An integration profile fills one row per protected route, in its section 2 or in an annex it references.

| Row | Method | Path pattern | Path parameters and grammar | Query parameters read | Body | Action | Resources |
|---|---|---|---|---|---|---|---|
| `<id>` | `<uppercase method>` | `<literal segments and {parameters}>` | `<name: grammar, length bound>` | `<name: grammar, required or optional>`, or none | `<none, or media type and what is read>` | `<constant>` | `<constant URI templates>` |

### 5.2 Rules

| # | Rule | Basis |
|---|---|---|
| RB-31 | The mapping table comes from trusted configuration and is part of the mapping version (section 6). A route that has no row is not protected by this mapping. | draft §4.2, §17.2; template section 2 |
| RB-32 | A row is selected when its method equals the uppercased method, the path has as many segments as the pattern, and every literal segment equals the request segment octet for octet; the path is case-sensitive. Where two rows are selected, the one with a literal segment at the first position where they differ wins. Two rows that remain tied are a configuration error, found when the table is installed. | RFC 9110 §4.2.3; profile |
| RB-33 | A request that selects no row has no action. `map_operation` produces no operation context, and a contract request or presentation for it is refused with `UNSUPPORTED_REQUIREMENT`. Whether the native gateway serves the route without PACT is a matter of the integration profile's claim scope (template sections 1, 2, and 5). | draft §13.4; profile |
| RB-34 | Each path parameter and each listed query parameter has a grammar that admits only one or more unreserved characters (ALPHA, DIGIT, `-`, `.`, `_`, `~`), never admits `.` or `..`, and has a length bound. Because the binding refuses an escape of an unreserved character, a value in such a grammar has one spelling and needs no decoding: the value is the octets as bound. A row whose parameter needs other characters states its decoding and canonical form in its integration profile; this document gives no baseline for that (open item O14). | RFC 3986 §2.3, §3.3, §7.3; profile |
| RB-35 | The row lists the query parameters it reads. The query is split into pairs at `&` and each pair at its first `=`, as the `application/x-www-form-urlencoded` parser splits it. A listed name that occurs twice is refused, because the gateway and the downstream could read different occurrences. A required parameter that is absent is refused. | WHATWG URL §5.1; profile |
| RB-36 | A query parameter the row does not list is covered by `target_uri`, is not read for the action or resources, and is never forwarded downstream (RB-50). An integration profile can be stricter and refuse unlisted parameters, as the [files profile](files/profile.md) refuses every other path and query. Fixture `COMMON-03.resources` shows a `resource` parameter that changes nothing. | draft §10.2; profile |
| RB-37 | The row states whether it accepts a body. A non-empty body on a row that accepts none is refused. This document derives resources from path parameters, listed query parameters, and the authenticated native context only. A route whose resource is chosen by a body member or a header states its rule in its integration profile: the members it reads, a strict parse that refuses duplicate member names, and the same value at mapping and at translation. Until it does, the route is an unsupported form (template section 6). | draft §7.1, §10.2; profile |
| RB-38 | A refusal of a selected row under RB-34, RB-35, or RB-37 is `INVALID_MESSAGE`: the request has a structure the mapping does not support. | draft §13.4; profile |
| RB-39 | The action is a constant of the row, such as `invoice.read`, of at most 1024 characters. No request data selects or changes it. | draft §10.2; Appendix A schema |
| RB-40 | Each resource is a constant absolute URI template of the row into which parameter values are inserted as bound, or values of the authenticated native context are inserted (as the tenant of the template's mini-example row R2 is). A client-supplied resource list, in the query, a header, or the body, is never used as such (fixture `COMMON-03.resources`). Each resource has at most 1024 characters, the list has 1 to 256 members, and no member is repeated. | draft §10.2, §20.1; Appendix A schema; [template](TEMPLATE.md) mini-example |

## 6. Mapping version

| # | Rule | Basis |
|---|---|---|
| RB-41 | The mapping version names the installed binding and translation as a whole: the origin, the mapping table (section 5), the header allowlist and normalization (section 3.5), the body maximum, and the translation table with its constants and statements (section 7). A change to any of them is a new version. The gateway publishes it as `operation_mapping_version` and has one installed version at a time. | draft §10.2, §13.1, §17.2; Appendix A schema; profile |
| RB-42 | At issuance the gateway applies sections 3 to 5 to the proposed operation of the `ContractRequest` under the installed version: its method and `target_uri` select a row and pass that row's rules, the row yields the proposed action and resources, `principal_id` is the principal authenticated for the contract request, `environment_id` is the configured one, and every name in `headers` is allowlisted or is `content-type`. A proposal whose principal, environment, action, or resources differ is refused with `CONTEXT_MISMATCH`; one whose target a rule of section 4.1 refuses is `INVALID_MESSAGE`. The gateway then records the installed version with the contract (`contract_id` and `jti`) and keeps the record at least until the contract expires. The contract has no member for the version, and `operation_digest` does not cover it. | draft §10.2, §11.1 step 1, §13.4; Appendix A schema; profile |
| RB-43 | At validation the gateway compares the recorded version with the installed one before it reconstructs the operation (draft §11.3 step 5). When they differ, the contract is no longer active and its use is refused with `REQUIREMENTS_CHANGED`; the agent obtains a new contract. The gateway never reconstructs the operation under a version other than the recorded one. | draft §10.2, §13.4; profile |
| RB-44 | At sidecar handoff the gateway applies the same comparison. An installed version that differs from the recorded one makes the attestation stale; it is not accepted and the use is refused with `REQUIREMENTS_CHANGED`. | draft §11.5, §13.4; profile |
| RB-45 | A version record that cannot be read leaves the check `UNKNOWN`: the decision is `DEFERRED` with `DEPENDENCY_UNAVAILABLE`. | draft §18 |
| RB-46 | `map_operation` called with a version that is not installed returns `UNSUPPORTED_REQUIREMENT`, as the [basic](basic/profile.md), [files](files/profile.md), and [SAML](saml/profile.md) profiles state. Under RB-43 this happens only through a gateway fault. | draft §13.4, §17.1 |
| RB-47 | Draft §9.4 lists the changes that invalidate outstanding contracts and does not name the mapping version. This document adds it, following the same-version rule of §10.2 (open item O8). | draft §9.4, §10.2; profile |

## 7. Downstream translation

### 7.1 Template

An integration profile fills one translation row per mapping row, in its native dependencies (template section 4, components C07 and C08) or in an annex it references.

| Row | Gateway request | Downstream origin | Downstream method and path | Downstream query | Downstream headers | Body transformation | Actor | Continuation |
|---|---|---|---|---|---|---|---|---|
| `<id>` | `<mapping row>` | `<constant origin>` | `<method; constant path template>` | `<constants and listed parameters>` | `<covered copies, constants, executor credential>` | `<none, unchanged, or a stated function of covered inputs>` | `<executor class; credential source>` | `<none, or the rules of section 7.3>` |

### 7.2 Rules

| # | Rule | Basis |
|---|---|---|
| RB-48 | The downstream origin is a constant of the row from trusted configuration. No request data, resource identifier, or downstream response selects it. Network paths use TLS. The gateway follows a downstream redirect only to a request the same row lists. | draft §4.2, §13.1, §19; profile |
| RB-49 | The downstream method is a constant of the row. The downstream path is a constant template into which the row's path parameters are inserted as bound, or the exact bound path. A decoded, re-encoded, or dot-segment-normalized form of the gateway path never reaches the downstream. | RFC 3986 §2.4, §6.2.2.3, §7.3; profile |
| RB-50 | The downstream query consists of constants of the row and of listed parameters (RB-35) placed in positions the row names. No query parameter name or value is copied from the gateway request otherwise. | draft §10.2; profile |
| RB-51 | A downstream header is one of: (a) a covered header, copied with its received field lines in order; (b) a constant of the row; (c) the credential of the executor named in the actor column; (d) an uncovered client header, only where the integration profile records that the downstream gives it no action-changing meaning (RB-18 b). `PACT-Presentation`, `PACT-Admission`, and the admission attestation are never forwarded, and a native API never accepts the attestation as its access credential. Hop-by-hop fields and fields named in `Connection` are removed. The client's `Authorization` or `Cookie` field is forwarded only where the actor column names it as the executor's credential and the integration profile states why the downstream accepts it. | draft §10.2, §11.5, §17.5; RFC 9110 §7.6.1; profile |
| RB-52 | The downstream body is the bound body unchanged, no body, or the output of a transformation the row states as a function of covered inputs (the bound body, covered headers, parameters, the principal context) and constants. No uncovered input reaches it. A row that forwards a body sets the downstream `content-type` to the covered value or to a constant, because a recipient without one may examine the data to decide its type. | draft §10.2; RFC 9110 §8.3; profile |
| RB-53 | The actor column names the executor identity class of draft §17.5 (`delegated-user`, `registered-app-executor`, `dedicated-role`, or `impersonated-user`) and the source of its credential. `authorize_native` runs with the original principal. A fallback to a broader credential is `FAIL` with `EXECUTOR_MISMATCH`. A connector with a service account preserves the principal's native restrictions. | draft §4.3, §17.5 |
| RB-54 | The row lists every downstream request that one gateway request causes, in order; for most rows there is one. Any other downstream request is forbidden: no enrichment read, no extra write, no request the row does not list, no automatic repeat of an ambiguous non-idempotent request, and no continuation or redirect the row does not allow. Lookups that the functions of draft §17.1 make through their approved native paths are not downstream requests of the row; the integration profile lists them as enforcement points (template section 3). | draft §10.3, §17.1; profile |
| RB-55 | An admitted operation is executed under the translation row of the recorded mapping version (RB-43). Side effects use the native idempotency mechanism; when `idempotency-key` is covered, it is copied unchanged (RB-51 a). | draft §10.3; profile |

### 7.3 Paging and continuations

| # | Rule | Basis |
|---|---|---|
| RB-56 | Each page is its own operation, with its own operation context, contract, and presentation. A passing result for one page does not authorize the next. The continuation the agent sends is a listed query parameter of the gateway request (as `page_token` is in the template's mini-example row R2), so it is covered by `target_uri`. | draft §10.3; [template](TEMPLATE.md) mini-example |
| RB-57 | When a downstream response carries a continuation, the gateway records it with the task (`Intent.task_id` reconciled with the authoritative task context), the `principal_id`, the `agent_id`, the mapping row, and the mapping version. It returns to the agent a gateway token that refers to that record and is in the grammar of the row's continuation parameter (RB-34). A row that returns the downstream link itself states its decoding under RB-34. A delta link is a continuation too. | draft §10.1, §17.5; OData JSON Format §4.5.5, §4.5.7; profile |
| RB-58 | The gateway follows a continuation only when it has a record of it made for the same task, principal, and agent, under the same row and the installed mapping version, and the recorded link has the downstream origin and path of that row (scheme and host compared in lowercase, the default port omitted, the path octet for octet). Any other continuation is refused with `CONTEXT_MISMATCH`, and the agent starts again from the first page. In the paging example of Microsoft Graph, `GET https://graph.microsoft.com/v1.0/users?$top=5` returns a next link with the same origin and path, `$top=5`, and a `$skiptoken`. | draft §13.4; Microsoft Graph paging; profile |
| RB-59 | The gateway sends the recorded link unchanged. OData clients treat the next link as opaque and do not append system query options, and Microsoft Graph asks for the entire URL to be used and the skip token not to be extracted. The gateway sets the row's constant headers again on every page request, because Microsoft Graph does not carry headers such as `ConsistencyLevel` to later pages by default. Whether each next link keeps the pinned query options is open item O10. | OData Part 1 §11.2.6.7; Microsoft Graph paging, query parameters |
| RB-60 | A page size the row requests bounds nothing by itself. A page may hold zero or more results, and an API may ignore a requested size, apply its own maximum, or return an error. A deployment that needs a bound on what one operation releases enforces it on the response and records it in its integration profile. | Microsoft Graph paging; OData Part 1 §11.2.6.7 |

### 7.4 Fixed queries

These rules apply to the translation table. No Microsoft Graph profile and no database profile exists yet; when one is written, it adds its own rules and can make these stricter.

| # | Rule | Basis |
|---|---|---|
| RB-61 | For an OData service, Microsoft Graph included, the row fixes the downstream query: `$select` is a constant that names the properties the action needs, and `$top`, when used, is a constant. `$select` requests a specific set of properties and `$top` a number of items. Some Microsoft Graph directory resources return only a default subset of properties without `$select`, and `$select` can name a subset or a superset of the default, so the constant decides what is requested. | OData Part 2 §5.1.4, §5.1.6; Microsoft Graph query parameters |
| RB-62 | No system query option is taken from the gateway request. OData 4.01 services accept system query option names in any case and with or without the `$` prefix, and Microsoft Graph accepts some without the prefix, so a filter on spellings cannot be complete. The row builds the downstream query from constants and listed parameters only (RB-50). This document defines no rule for putting request data into `$filter`, `$search`, `$orderby`, or `$expand`; a row that needs one is an unsupported form (open item O12). | OData Part 2 §5.1; Microsoft Graph query parameters; profile |
| RB-63 | Headers that change query semantics downstream, such as `ConsistencyLevel` for Microsoft Graph advanced directory queries and the OData `maxpagesize` preference in `prefer`, are constants of the row where the downstream needs them. A client value for them is covered or is not forwarded (RB-18). | Microsoft Graph query parameters; OData Part 1 §11.2.6.7; profile |
| RB-64 | For a database, the row names its prepared statements by their exact text, which is part of the mapping version. No statement text contains request data. Request data reaches a statement only as a bound parameter in a position the row names, from a covered input or a constant. Tables, columns, sort keys, and limits are constants; a row that offers a choice among them maps a parameter with a closed grammar to one of several listed constant statements. The statements run under the executor of the actor column, and a gateway request runs only the statements its row lists. | draft §10.2, §17.5; profile |

## 8. Worked example: the Appendix B finance gateway

This section is informative. It fills the templates of sections 5 and 7 for the invoice read of Appendix B. Appendix B does not print the HTTP request, the mapping row, or the downstream request; the values this section adds are marked illustrative.

### 8.1 Configuration

From Appendix B.13 and B.3:

| Item | Value | Source |
|---|---|---|
| Origin | `https://gateway.example` | B.3 `target_uri` |
| `environment_id` | `https://gateway.example/environments/finance` | B.13 |
| `operation_mapping_version` | `finance-http-1` | B.13 |
| `protected_header_names` | `if-match`, `x-dry-run` | B.13 |
| `header_normalization_id` | `finance-header-normalization-1`, naming the normalization of RB-25 | B.13; this document |
| Intent | `intent-september-invoices-007`, task `native-task:september-summary-007`, purpose `https://policies.example/purposes/invoice-summary/v1` | B.2 |

Of the baseline list (RB-18), the gateway covers `if-match`. `content-type` is covered when a body is present, and row R1 accepts none. For R1 the gateway does not forward `accept`, `prefer`, `if-none-match`, or `idempotency-key`: the translation row sets `accept` as a constant and drops the others (RB-18 a).

### 8.2 Mapping row

| Row | Method | Path pattern | Path parameters and grammar | Query parameters read | Body | Action | Resources |
|---|---|---|---|---|---|---|---|
| R1 | `GET` | `/invoices/{invoice_id}` | `invoice_id`: `INV-` followed by 1 to 12 digits (illustrative) | none | none | `invoice.read` | `https://invoices.example/invoices/{invoice_id}` |

### 8.3 Request and operation context

The request, as the reference implementation's test of section 10 sends it to a real server. The credential and presentation values are placeholders.

```http
GET /invoices/INV-1042 HTTP/1.1
Host: gateway.example
Authorization: Bearer native-token
PACT-Presentation: eyJhbGciOiJFUzI1NiJ9.e30.c2ln
Accept: application/json
```

| Member | Value | Derived by |
|---|---|---|
| `operation_id` | `invoice-read-operation-0001` | The caller (RB-29; open item O9) |
| `environment_id` | `https://gateway.example/environments/finance` | Configuration (RB-28) |
| `principal_id` | `https://identity.example/principals/alice` | `authenticate_native` from the bearer credential (RB-26) |
| `action` | `invoice.read` | Row R1 (RB-39) |
| `resources` | `https://invoices.example/invoices/INV-1042` | Row R1 template with `invoice_id` = `INV-1042` (RB-40) |
| `method` | `GET` | RB-5 |
| `target_uri` | `https://gateway.example/invoices/INV-1042` | Configured origin and the exact path; `Host` not read (RB-1, RB-3, RB-7) |
| `body_digest` | `47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU` | Empty body (RB-11) |
| `headers` | `{}` | `Authorization` and `PACT-Presentation` are never covered (RB-20); `Accept` is not allowlisted; no allowlisted header is present (RB-16) |

The result is the operation context of Appendix B.3. Its `object_digest` is `R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0`, the `operation_digest` that Appendix B.4 and B.7 print. The reference implementation reproduces both the object and the digest from this request (section 10).

At issuance the gateway records `finance-http-1` with contract `contract-finance-0001` (RB-42). At validation, `finance-http-1` is still installed, so the gateway reconstructs the operation under it (RB-43).

### 8.4 Translation row

| Row | Gateway request | Downstream origin | Downstream method and path | Downstream query | Downstream headers | Body transformation | Actor | Continuation |
|---|---|---|---|---|---|---|---|---|
| T1 | R1 | `https://invoices.example` (illustrative) | `GET /invoices/{invoice_id}` | none | `accept: application/json` (constant); `if-match` and `x-dry-run` copied when present; the executor credential. The client's `Authorization`, `PACT-Presentation`, and `Accept` are not forwarded | none | `delegated-user` for the principal (illustrative: Appendix B names no executor class, and the B.4 contract does not list `execution-identity-v1`) | none |

The invoice permission check of Appendix B is `authorize_native` with the original principal (RB-53). It is not a downstream request of row T1 (RB-54).

### 8.5 Variations

| Change to the request of 8.3 | Result |
|---|---|
| `Accept: text/csv` | `headers` stays `{}` and the digest is unchanged. Row T1 sends its constant `accept`, so the downstream result does not change (RB-18 a). |
| `X-Dry-Run: 1` added | `headers` is `{"x-dry-run": "1"}`, the digest differs from the contract's `operation_digest`, and evaluation yields `CONTEXT_MISMATCH` (draft §11.3 step 5, §22.2). |
| `/invoices/INV-1042?expand=lines` | `target_uri` changes, so `CONTEXT_MISMATCH`. Row R1 does not read `expand` and row T1 never forwards it (RB-36, RB-50). |
| `/invoices/%49NV-1042` | Refused, `encoded-unreserved`: `INVALID_MESSAGE`. |
| `/invoices/INV-1042#p2` | Refused, `fragment`: `INVALID_MESSAGE`. |
| `Content-Encoding: gzip` | Refused, `content-encoding`: `INVALID_MESSAGE`. |
| `/invoices/../admin` | Refused, `dot-segment`: `INVALID_MESSAGE` (RB-9). No row is selected. |
| `/invoices/..` | Refused, `dot-segment`: `INVALID_MESSAGE` (RB-9). No row is selected. |
| `Host: evil.example`, `X-Forwarded-Host: evil.example` | `target_uri` is unchanged (RB-3). |
| `get` as the method | `method` is `GET` and the operation is the same (RB-5, open item O4). |
| A second `Host: gateway.example` line | Refused, `duplicate-host`: `INVALID_MESSAGE` (RB-65). |
| `finance-http-2` installed between issuance and validation | `REQUIREMENTS_CHANGED`; the agent obtains a new contract (RB-43). |

## 9. Using this document in a profile

| Template section | What the profile states |
|---|---|
| 1. Claim scope | That the claim uses this document at version 0.1, and every rule it makes stricter. |
| 2. Protected routes and actions | The mapping table of section 5: one row per route with the parameter grammars, the query parameters read, and the body rule. |
| 3. Enforcement points | The mapping version in the `map_operation` row (section 6), and the native lookups that RB-54 excludes from the translation. |
| 4. Native dependencies | The translation table of section 7 under C07 and C08; each RB-18 (b) dependency; the mechanism headers of RB-19 and RB-21. |
| 6. Unsupported forms | Routes whose resource comes from a body member or a header without a rule (RB-37), parameters outside the RB-34 grammar, filter expressions built from request data (RB-62). |
| 9. Residual limits | What a page size does not bound (RB-60), and every open item of section 11 the deployment relies on. |
| 10. Fixture index | Negative cases for the rules of section 4.1 that the deployment's routes can meet, and for RB-33 to RB-38, RB-43, and RB-58. |

## 10. Reference implementation

This section is informative.

The Go package `go/core/binding` implements sections 3 and 4 for a request a `net/http` server received. `FromRequest(cfg, r, principalID, action, resources)` returns the operation context: it fills `method`, `target_uri`, `body_digest`, and `headers`, and copies the principal, action, and resources the caller derived. It leaves `operation_id` and `environment_id` for the caller to set and does not check the §20.1 limits, which `core.Limits.ValidateOperation` checks.

| `binding.Config` field | Published as | Rules |
|---|---|---|
| `Origin` | (the origin of `target_uri`) | RB-1, RB-2, section 4.2 |
| `HeaderAllowlist` | `protected_header_names` | RB-17, RB-20, section 4.2 |
| `HeaderNormalizationID` | `header_normalization_id` | RB-25 |
| `MappingVersion` | `operation_mapping_version` | RB-41; the package only requires it to be set |
| `MaxBody` | (not published) | RB-14 |

Every error wraps one of three sentinels. `ErrInvalidConfig` covers the checks of section 4.2. `ErrInvalidRequest` is a `*RequestError` whose `Rule` is one of the 23 names of section 4.1. `ErrBodyRead` is RB-15. The package does not import the adapter package; a caller maps `ErrInvalidRequest` to `adapter.ErrInvalidMessage`, which carries `INVALID_MESSAGE`. It relies on the server to remove the chunked transfer coding. A `net/http` server, and `http.ReadRequest`, refuse a second `Host` field line themselves and keep no `Host` line in `Request.Header`; the package refuses a request whose `Header` holds more than one, which only a program can build. `Request.Host` stands for the `Host` line of an origin-form request: the server fills it from `Host` or, over HTTP/2, from `:authority`, and an empty one with no `Host` line in `Header` is `missing-host`. For an absolute-form target `net/http` fills `Request.Host` from the target, so the package cannot see a `Host` line beside such a target; a request object of field lines can.

The package does not select a mapping row, record or compare the mapping version, or translate downstream; sections 5 to 7 are the caller's. Its test `TestAppendixB3` sends the request of section 8.3 to a real server with the configuration of section 8.1 and checks the result against the vector `operation-b3` of [`appendix-b.json`](../fixtures/vectors/digest/appendix-b.json) and the digest `R5nfhv7g_o93VPHK6a2o56-MyyGy75GQwXxDM4M3cn0`.

## 11. Open items

This section is informative. Each item is a question this document records and does not decide.

| # | Item | What settles it |
|---|---|---|
| O1 | The authority of an absolute-form target is checked and then dropped (RB-4), so `GET http://Other.Example:8080/x` binds as `https://gateway.example/x`. An origin server uses the host of an absolute-form target (RFC 9112 §3.2.2). Refusing a target whose authority differs from the configured origin would be stricter. | Maintainer decision; then a change to the reference implementation and a rule of section 4.1 |
| O2 | An allowlisted header named in `Connection` is left out of `headers` instead of refused (RB-22). An agent can list `if-match` in `Connection` and so keep it out of the binding; RB-51 then removes it downstream. Refusing such a request would be stricter. | Maintainer decision |
| O3 | `[` and `]` in a query are refused (`invalid-character`), which is stricter than the Go `net/http` server, whose parser accepts `/a?x[]=1`. Clients that follow the WHATWG URL Standard do not percent-encode `[`, `]`, `\`, `^`, `` ` ``, `{`, `}`, or the vertical bar in a query (WHATWG URL §1.3, query percent-encode set), so their requests are refused too. | Maintainer decision; interoperability probe with common clients |
| O4 | Uppercasing the method (RB-5) merges methods that RFC 9110 §9.1 treats as distinct, because the method token is case-sensitive. Refusing a method that is not already uppercase would keep them apart. | Maintainer decision; it also needs a change to the reference implementation |
| O5 | Draft §19 forbids any header named in `protected_header_names` in receipts, outcome reports, and logs, treating those names as credential material. Appendix B.13 lists semantic headers (`if-match`, `x-dry-run`) there, and RB-17 publishes the allowlist of covered headers under the same name. The two readings conflict: either the allowlist is published elsewhere or §19 names a different list. | Draft change |
| O6 | Closed. The adapter fixture [`common-03.target-uri.json`](../fixtures/adapters/_common/common-03.target-uri.json) once expected the query `?z=1&a=%2f%7e&a=2&b` to be mapped unchanged, which this document refuses. Draft §10.2 now defines the ambiguous encodings, the fixture expects `?z=1&a=%2F%C3%A9~&a=2&b`, which is bound unchanged, and [`common-03.ambiguous-query.json`](../fixtures/adapters/_common/common-03.ambiguous-query.json) expects the old query to be refused with `INVALID_MESSAGE`. | Settled by draft §10.2 and the fixture change |
| O7 | This document names its normalization by reference (RB-25) and defines no identifier for it, so every gateway chooses its own `header_normalization_id`. A first-party identifier would let a validator recognize it. | Maintainer decision |
| O8 | Draft §9.4 does not list the mapping version among the changes that invalidate outstanding contracts; RB-43 and RB-47 add it. Whether a bounded compatibility window like the one §9.4 allows for policy changes applies to mapping versions is not stated. | Draft change |
| O9 | The draft does not say which party assigns `operation_id`, or how the gateway obtains the same value when it reconstructs the operation at validation (RB-29). The reference implementation leaves it to the caller. | Draft change |
| O10 | Whether the next link of each Microsoft Graph API keeps the pinned `$select` and `$top` is not established for every API. The paging documentation says that other query parameters of the original request are encoded in the next link, and OData treats the link as opaque. | Probe: for each API a profile uses, request with the pinned options and compare the next link |
| O11 | Repeated field lines of a singleton field, such as two `content-type` lines, are joined (RB-23) rather than refused. A sender must not generate them (RFC 9110 §5.3), and a downstream may read only one. | Maintainer decision |
| O12 | No rule exists for inserting request data into OData `$filter`, `$search`, `$orderby`, or `$expand` expressions (RB-62). | A Microsoft Graph or OData profile |
| O13 | `idempotency-key` is in the baseline list, but the only definition read is draft-ietf-httpapi-idempotency-key-header-07, an Internet-Draft that expired on 18 April 2026. | Track the draft; replace the reference when an RFC is published |
| O14 | Parameter values outside the unreserved characters (RB-34) have no baseline decoding or canonical form. Canonically equivalent Unicode sequences have distinct octets (RFC 3629 §10), and the binding does not normalize them. | A later version of this document |

## 12. Sources

Every source was read on 2026-10-16, except RFC 9113 and the ASGI specification, read on 2026-10-20.

| Source | Sections read | Used for |
|---|---|---|
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986), URI Generic Syntax | §2.1 to §2.4, §3.2.2, §3.2.3, §3.3, §3.4, §3.5, §5.2.4, §6.2.2.1 to §6.2.2.3, §6.2.3, §7.3 | Percent-encoding, reserved and unreserved characters, host, path, query, dot segments, normalization |
| [RFC 3629](https://www.rfc-editor.org/rfc/rfc3629), UTF-8 | §3, §10 | Valid UTF-8, overlong forms, surrogates |
| [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239), Forwarded HTTP Extension | §8.1 | Forwarded is not reliable |
| [RFC 7240](https://www.rfc-editor.org/rfc/rfc7240), Prefer Header for HTTP | §2, §4.1, §4.4 | The `prefer` row of the baseline list |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), HTTP Semantics | §4.2.1 to §4.2.5, §5.1 to §5.5, §5.6.2, §7.2, §7.6.1, §8.3, §8.4, §9.1, §11.6.2, §11.7.2, §12.5.1, §13.1.1, §13.1.2 | URI schemes and normalization, fields, Connection, content headers, methods, credentials, conditionals |
| [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112), HTTP/1.1 | §3.2, §3.2.1 to §3.2.4, §3.3, §6.1 | Request-target forms, `Host`, transfer codings |
| [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113), HTTP/2 | §8.3.1 | `:authority` in place of `Host` |
| [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421), HTTP Message Signatures | §4.1, §4.2 | `signature` and `signature-input` |
| [ASGI HTTP and WebSocket specification](https://asgi.readthedocs.io/en/latest/specs/www.html), version 2.5 | HTTP connection scope, `headers` | `:authority` given as the `host` header |
| [draft-ietf-httpapi-idempotency-key-header-07](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/07/), The Idempotency-Key HTTP Header Field, expired 18 April 2026 | §1, §2.1 to §2.6 | The `idempotency-key` row of the baseline list |
| [WHATWG URL Standard](https://url.spec.whatwg.org/), last updated 7 October 2026 | §1.3, §5.1 | Percent-encode sets, `application/x-www-form-urlencoded` parsing |
| [OData Version 4.01 Part 1: Protocol](https://docs.oasis-open.org/odata/odata/v4.01/odata-v4.01-part1-protocol.html), OASIS Standard | §11.2.6.7 | Server-driven paging, next links, `maxpagesize` |
| [OData Version 4.01 Part 2: URL Conventions](https://docs.oasis-open.org/odata/odata/v4.01/odata-v4.01-part2-url-conventions.html), OASIS Standard | §5.1, §5.1.4, §5.1.6 | System query options, `$select`, `$top` |
| [OData JSON Format Version 4.01](https://docs.oasis-open.org/odata/odata-json-format/v4.01/odata-json-format-v4.01.html), OASIS Standard | §4.5.5, §4.5.7 | `nextLink` and `deltaLink` |
| [Microsoft Graph: Paging](https://learn.microsoft.com/en-us/graph/paging) | Whole page | `@odata.nextLink`, page sizes, headers on later pages |
| [Microsoft Graph: Query parameters](https://learn.microsoft.com/en-us/graph/query-parameters) | System query options, encoding, `$select`, `$skipToken`, `$top` | `$select` and `$top`, the optional `$` prefix, `ConsistencyLevel` |
