# PACT integration profile: MCP adapter

This profile targets spec version 1.0 and wire version 0.1 and is a draft. It is work in progress: this revision holds only the pinned MCP references, the record of the checks behind them, and the method classification seed for the operation mapping. The ten sections of [`TEMPLATE.md`](../TEMPLATE.md) come in later changes, so the profile must not be cited as support for any claim until they exist and its negative cases pass (see "Completeness" in [`TEMPLATE.md`](../TEMPLATE.md)).

## Pinned references and verification record

Record date: 2026-10-15, the date of the first check. Every source below was fetched on 2026-10-16, and every quote in this section is taken from the 2026-10-16 fetch.

### How the record was made

- Each source was fetched with an HTTP GET. Every one answered `200`, and its page title (listed under "Sources") names the page that was asked for. A site can answer `200` with a generic page, so the title was checked; a path that does not exist under `/specification/2026-07-28/` answered `404`.
- A quote reproduces the rendered text of the page: emphasis markup is dropped, wrapped lines are joined, a link keeps its text and drops its target, and inline code stays in backticks. Each quote was matched against the Markdown rendition that the site serves at the same path with `.md` appended, and against the HTML of the page; the HTML prints straight apostrophes and quotation marks as typographic ones, and the quotes keep the straight forms of the source. A quote from a GitHub file was matched against the raw file at the pinned commit.
- A row ends `verified` (the quote supports the statement) or `contradicted` (the quote shows the statement is wrong or incomplete; the row says what the page says instead). A contradicted row is input for the profile sections that follow, which carry the correction.
- Rows `P01` to `P56` are the statements verified at the first check (pages fetched 2026-10-15) and re-checked on 2026-10-16. Rows `T1a` to `T9c` are the nine items that the first check left open, checked on 2026-10-16. Rows `X1` to `X4` support the method classification seed, checked on 2026-10-16.

### Pinned revisions

The adapter pins two MCP revisions. The era names are the ones the 2026-07-28 versioning page defines (row `P40`). Both pinned revisions use the mapping revision `pact-mcp-1`. Each pinned revision has its own `GatewayMetadata.adapters` entry (draft §13.3); the entries themselves are written with the claim scope of this profile.

| Era | Revision string | Specification | Schema at the pinned commit | Mapping revision | Era properties (rows) |
|---|---|---|---|---|---|
| modern | `2026-07-28` | [specification index](https://modelcontextprotocol.io/specification/2026-07-28) | [`schema/2026-07-28/schema.json`](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/271ecc9accafdd9b83a3c869fa67c22953b2af80/schema/2026-07-28/schema.json) at commit `271ecc9accafdd9b83a3c869fa67c22953b2af80`; SHA-256 of the file `ef70b61f99b6d2e5e3b46863822eab08dff6a45bedc7a08914e0e5b133f40203` | `pact-mcp-1` | per-request `_meta` (`P19`, `P32`), no `initialize` (`P19`), no protocol sessions (`P20`, `P38`), no resumability (`P26`, `P38`) |
| legacy | `2025-11-25` | [specification index](https://modelcontextprotocol.io/specification/2025-11-25) | [`schema/2025-11-25/schema.json`](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/c4c367f9f58296a7053f5c78a52fd02bfbb56a49/schema/2025-11-25/schema.json) at commit `c4c367f9f58296a7053f5c78a52fd02bfbb56a49`; SHA-256 of the file `268a5f82ba70fd7e4b6dc4aa1e64f116f74b4d0edcb69dc046829c79dd4e97e7` | `pact-mcp-1` | `initialize` handshake (`T1a`), optional `MCP-Session-Id` (`P04`), GET streams and server-initiated requests (`P08`) |

The schema is pinned by commit, not by path, because the published path can change after a revision is released: the repository history shows commits to `schema/2025-11-25/schema.json` on 2026-03-24 ("schema: allow null for Task.ttl in generated JSON schema") and on 2026-07-27 ("schema: fix 2025-11-25 NumberSchema min/max/default to number in generated JSON"). The last commit to `schema/2026-07-28/schema.json` is `271ecc9`, dated 2026-07-28. The specification pages link the schema under `github.com/modelcontextprotocol/specification`, which redirects to `github.com/modelcontextprotocol/modelcontextprotocol`. The SHA-256 values are of the bytes fetched on 2026-10-16 from the raw file at the pinned commit; the same bytes were served at the `main` path that day.

The tasks extension is pinned with the modern era:

| Extension identifier | Overview | Normative text at the pinned commit | Schema at the pinned commit |
|---|---|---|---|
| `io.modelcontextprotocol/tasks` | [Tasks overview](https://modelcontextprotocol.io/extensions/tasks/overview) | [`specification/2026-07-28/tasks.md`](https://github.com/modelcontextprotocol/ext-tasks/blob/899c1bbc869567670093face3591b39c28ce3219/specification/2026-07-28/tasks.md) in `modelcontextprotocol/ext-tasks` at commit `899c1bbc869567670093face3591b39c28ce3219`; SHA-256 `5fc22b9b5ff248703927c69855f751a061c2d6170f4dc3923204452f859f91a5` | [`schema/2026-07-28/schema.json`](https://github.com/modelcontextprotocol/ext-tasks/blob/899c1bbc869567670093face3591b39c28ce3219/schema/2026-07-28/schema.json) at the same commit; SHA-256 `bf30afb7ac251e3e22c037b7a685f60ef6603031b5484c0d08b1fa0bbe86d460` |

The overview page defers to the repository for the full text (row `P56`), so the repository file is the normative pin and the overview page is informative.

### Revisions not pinned

Each revision below is published (its specification index answered `200` and names its own `schema/<revision>/schema.ts`, and `schema/<revision>/schema.json` exists in the specification repository). None is pinned, and the adapter does not support it.

| Revision | Specification | Status in this profile |
|---|---|---|
| `2025-06-18` | [index](https://modelcontextprotocol.io/specification/2025-06-18) | not pinned, unsupported |
| `2025-03-26` | [index](https://modelcontextprotocol.io/specification/2025-03-26) | not pinned, unsupported |
| `2024-11-05` | [index](https://modelcontextprotocol.io/specification/2024-11-05) | not pinned, unsupported |
| `draft` | [index](https://modelcontextprotocol.io/specification/draft) | not pinned, unsupported: the path changes without a new revision string. On 2026-10-16 `schema/draft/schema.json` was byte-identical to the 2026-07-28 file |

`2026-07-28` is the newest dated revision: `https://modelcontextprotocol.io/specification/latest` redirects to `/specification/2026-07-28`; the site index `https://modelcontextprotocol.io/llms.txt` lists specification pages for exactly `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, `2026-07-28`, and `draft`; and the `schema` directory of the specification repository holds exactly those six names. The 2026-07-28 changelog names `2025-11-25` as its previous revision (row `P21`).

### Draft section 24 references

Section 24 of the [draft](../../draft.md) cites nine MCP URLs. Each was fetched on 2026-10-16; each label matches the page.

| URL cited in draft §24 | Status, page title | Finding |
|---|---|---|
| `https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization` | `200`, "Authorization" | confirmed; legacy-era authorization page |
| `https://modelcontextprotocol.io/specification/2026-07-28/basic` | `200`, "Overview" | confirmed; base protocol overview |
| `https://modelcontextprotocol.io/specification/2026-07-28/basic/transports` | `200`, "Overview" | confirmed; transports overview |
| `https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio` | `200`, "stdio" | confirmed |
| `https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http` | `200`, "Streamable HTTP" | confirmed |
| `https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization` | `200`, "Authorization" | confirmed |
| `https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations` | `200`, "Authorization Security Considerations" | confirmed |
| `https://modelcontextprotocol.io/specification/2026-07-28/server/tools` | `200`, "Tools" | confirmed |
| `https://modelcontextprotocol.io/extensions/tasks/overview` | `200`, "Tasks" | confirmed; the page is not under a revision path and names the identifier `io.modelcontextprotocol/tasks` (row `P54`). It is informative: the normative text is the repository file pinned above |

Section 24 cites no legacy-era page other than authorization. The legacy pages this record relies on (basic, lifecycle, transports, cancellation, the client features, tasks) are listed under "Sources".

### Sources

All fetched 2026-10-16. `S01` to `S19` were also fetched for the first check, on 2026-10-15. Page titles are given without the site suffix " - Model Context Protocol".

| Source | URL | Status, page title |
|---|---|---|
| S01 | https://modelcontextprotocol.io/specification/2026-07-28 | `200`, "Specification" |
| S02 | https://modelcontextprotocol.io/specification/2026-07-28/changelog | `200`, "Key Changes" |
| S03 | https://modelcontextprotocol.io/specification/2026-07-28/basic | `200`, "Overview" |
| S04 | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports | `200`, "Overview" |
| S05 | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio | `200`, "stdio" |
| S06 | https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http | `200`, "Streamable HTTP" |
| S07 | https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning | `200`, "Versioning and Compatibility" |
| S08 | https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr | `200`, "Multi Round-Trip Requests" |
| S09 | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization | `200`, "Authorization" |
| S10 | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations | `200`, "Authorization Security Considerations" |
| S11 | https://modelcontextprotocol.io/specification/2026-07-28/server/discover | `200`, "Discovery" |
| S12 | https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination | `200`, "Pagination" |
| S13 | https://modelcontextprotocol.io/specification/2026-07-28/server/tools | `200`, "Tools" |
| S14 | https://modelcontextprotocol.io/extensions/tasks/overview | `200`, "Tasks" |
| S15 | https://modelcontextprotocol.io/specification/2025-11-25/basic/transports | `200`, "Transports" |
| S16 | https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization | `200`, "Authorization" |
| S17 | https://modelcontextprotocol.io/specification/2025-11-25/changelog | `200`, "Key Changes" |
| S18 | https://modelcontextprotocol.io/specification/2025-06-18/changelog | `200`, "Key Changes" |
| S19 | https://modelcontextprotocol.io/specification/2025-11-25/basic | `200`, "Overview" |
| S20 | https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle | `200`, "Lifecycle" |
| S21 | https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation | `200`, "Cancellation" |
| S22 | https://modelcontextprotocol.io/specification/2025-11-25/client/sampling | `200`, "Sampling" |
| S23 | https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation | `200`, "Elicitation" |
| S24 | https://modelcontextprotocol.io/specification/2025-11-25/client/roots | `200`, "Roots" |
| S25 | https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks | `200`, "Tasks" |
| S26 | https://github.com/modelcontextprotocol/ext-tasks/blob/899c1bbc869567670093face3591b39c28ce3219/specification/2026-07-28/tasks.md | `200`, file page at the pinned commit |
| S27 | https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices | `200`, "Security Best Practices"; the legacy pages link it as `/specification/2025-11-25/basic/security_best_practices`, which redirects here |
| S28 | https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices | `200`, "Security Best Practices" |
| S29 | https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions | `200`, "Subscriptions" |
| S30 | https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/cancellation | `200`, "Cancellation" |
| S31 | https://modelcontextprotocol.io/specification/2026-07-28/server/resources | `200`, "Resources" |
| S32 | https://modelcontextprotocol.io/specification/2026-07-28/server/prompts | `200`, "Prompts" |
| S33 | https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/completion | `200`, "Completion" |
| S34 | https://github.com/modelcontextprotocol/modelcontextprotocol/blob/271ecc9accafdd9b83a3c869fa67c22953b2af80/schema/2026-07-28/schema.json | `200`, file page at the pinned commit |
| S35 | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration | `200`, "Client Registration" |
| S36 | https://modelcontextprotocol.io/specification/2026-07-28/deprecated | `200`, "Deprecated Features" |
| S37 | https://github.com/modelcontextprotocol/modelcontextprotocol/blob/c4c367f9f58296a7053f5c78a52fd02bfbb56a49/schema/2025-11-25/schema.json | `200`, file page at the pinned commit |
| S38 | https://github.com/modelcontextprotocol/ext-tasks/blob/899c1bbc869567670093face3591b39c28ce3219/schema/2026-07-28/schema.json | `200`, file page at the pinned commit |
| S39 | https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/ping | `200`, "Ping" |
| S40 | https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress | `200`, "Progress" |
| S41 | https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/progress | `200`, "Progress" |

### Statements verified at the first check

Pages fetched 2026-10-15 and re-fetched 2026-10-16.

| Row | Statement | Source | Quote | Result |
|---|---|---|---|---|
| P01 | 2025-11-25 stdio: newline framing; a message must not contain an embedded newline | S15 | “Messages are delimited by newlines, and MUST NOT contain embedded newlines.” | verified |
| P02 | 2025-11-25 Streamable HTTP: one MCP endpoint | S15 | “The server MUST provide a single HTTP endpoint path (hereafter referred to as the MCP endpoint) that supports both POST and GET methods.” | verified |
| P03 | 2025-11-25 Streamable HTTP: `Origin` validation, `403` on an invalid origin | S15 | “Servers MUST validate the `Origin` header on all incoming connections to prevent DNS rebinding attacks” “If the `Origin` header is present and invalid, servers MUST respond with HTTP 403 Forbidden.” | verified |
| P04 | 2025-11-25 Streamable HTTP: `MCP-Session-Id` rules (optional, echoed on every later request, `404` after termination) | S15 | “A server using the Streamable HTTP transport MAY assign a session ID at initialization time, by including it in an `MCP-Session-Id` header on the HTTP response containing the `InitializeResult`.” “If an `MCP-Session-Id` is returned by the server during initialization, clients using the Streamable HTTP transport MUST include it in the `MCP-Session-Id` header on all of their subsequent HTTP requests.” “The server MAY terminate the session at any time, after which it MUST respond to requests containing that session ID with HTTP 404 Not Found.” | verified |
| P05 | 2025-11-25 Streamable HTTP: resumability with `Last-Event-ID`, per stream | S15 | “If the client wishes to resume after a disconnection (whether due to network failure or server-initiated closure), it SHOULD issue an HTTP GET to the MCP endpoint, and include the `Last-Event-ID` header to indicate the last event ID it received.” “The server MUST NOT replay messages that would have been delivered on a different stream.” | verified |
| P06 | 2025-11-25 Streamable HTTP: one JSON-RPC message per POST body | S15 | “The body of the POST request MUST be a single JSON-RPC request, notification, or response.” | verified |
| P07 | 2025-11-25 Streamable HTTP: backward compatibility with HTTP+SSE of 2024-11-05 | S15 | “Clients and servers can maintain backwards compatibility with the deprecated HTTP+SSE transport (from protocol version 2024-11-05) as follows:” | verified |
| P08 | 2025-11-25 Streamable HTTP: GET streams and server-initiated requests | S15 | “The client MAY issue an HTTP GET to the MCP endpoint.” “The server MAY send JSON-RPC requests and notifications on the stream.” | verified |
| P09 | 2025-11-25 authorization: a stdio implementation should not follow it and takes credentials from the environment | S16 | “Implementations using an STDIO transport SHOULD NOT follow this specification, and instead retrieve credentials from the environment.” | verified |
| P10 | 2025-11-25 authorization: resource server model | S16 | “A protected MCP server acts as an OAuth 2.1 resource server, capable of accepting and responding to protected resource requests using access tokens.” | verified |
| P11 | 2025-11-25 authorization: RFC 8707 `resource` parameter with the canonical server URI | S16 | “MCP clients MUST implement Resource Indicators for OAuth 2.0 as defined in RFC 8707 to explicitly specify the target resource for which the token is being requested.” “MUST use the canonical URI of the MCP server as defined in RFC 8707 Section 2.” | verified |
| P12 | 2025-11-25 authorization: audience validation | S16 | “MCP servers MUST validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2.” | verified |
| P13 | 2025-11-25 authorization: an MCP server accepts or transits no other token | S16 | “MCP servers MUST NOT accept or transit any other tokens.” | verified |
| P14 | 2025-11-25 authorization: confused deputy, consent for static client ids | S16 | “MCP proxy servers using static client IDs MUST obtain user consent for each dynamically registered client before forwarding to third-party authorization servers (which may require additional consent).” | verified |
| P15 | JSON-RPC batching removed in 2025-06-18 | S18 | “Remove support for JSON-RPC batching (PR #416)” | verified |
| P16 | Tasks are experimental in 2025-11-25 | S17 | “Add experimental support for tasks to enable tracking durable requests with polling and deferred result retrieval (SEP-1686).” | verified |
| P17 | 2025-11-25 request id rules | S19 | “Requests MUST include a string or integer ID.” “Unlike base JSON-RPC, the ID MUST NOT be `null`.” “The request ID MUST NOT have been previously used by the requestor within the same session.” | verified |
| P18 | 2026-07-28 index: stateless requests with per-request capabilities | S01 | “Stateless, self-contained requests” “Per-request capability negotiation” | verified |
| P19 | 2026-07-28: no `initialize` handshake; version and capabilities in every request's `_meta` | S02 | “Make MCP stateless: remove the `initialize`/`notifications/initialized` handshake.” “Every request now carries its protocol version and client capabilities in `_meta` (`io.modelcontextprotocol/protocolVersion`, `io.modelcontextprotocol/clientCapabilities`).” | verified |
| P20 | 2026-07-28: no protocol sessions | S02 | “Remove protocol-level sessions and the `Mcp-Session-Id` header from the Streamable HTTP transport.” | verified |
| P21 | 2026-07-28 follows 2025-11-25 | S02 | “This document lists changes made to the Model Context Protocol (MCP) specification since the previous revision, 2025-11-25.” | verified |
| P22 | 2026-07-28: tasks moved to an extension | S02 | “Move experimental tasks out of the core protocol and into an official extension (`io.modelcontextprotocol/tasks`).” | verified |
| P23 | 2026-07-28: `ping` and `logging/setLevel` removed | S02 | “Remove `ping`, `logging/setLevel`, and `notifications/roots/list_changed`.” | verified |
| P24 | 2026-07-28: `subscriptions/listen` replaces the GET endpoint and `resources/subscribe` | S02 | “Replace the HTTP GET endpoint and `resources/subscribe`/`resources/unsubscribe` with `subscriptions/listen`: a single long-lived POST-response stream for opted-in server-to-client change notifications.” | verified |
| P25 | 2026-07-28: multi round-trip requests replace server-initiated requests | S02 | “Multi Round-Trip Requests (MRTR) pattern introduced which replaces the previous approach of sending server-initiated requests, such as `roots/list`, `sampling/createMessage`, or `elicitation/create`.” | verified |
| P26 | 2026-07-28: no stream resumability | S02 | “Remove SSE stream resumability and message redelivery (the `Last-Event-ID` header and SSE event IDs) from the Streamable HTTP transport.” | verified |
| P27 | 2026-07-28: error-code partition and the renumbered codes `-32020`, `-32021`, `-32022` | S02 | “Define an error code allocation policy partitioning the JSON-RPC server-error range: `-32000` to `-32019` remains implementation-defined (existing SDK usage is grandfathered), `-32020` to `-32099` is reserved for the MCP specification.” “Renumber the error codes introduced in this draft accordingly — `HeaderMismatch` `-32001` → `-32020`, `MissingRequiredClientCapability` `-32003` → `-32021`, `UnsupportedProtocolVersion` `-32004` → `-32022` — and add `HeaderMismatchError` to the schema, which previously existed only in transport prose.” | verified |
| P28 | 2026-07-28 request id rules | S03 | “Unlike base JSON-RPC, the ID MUST NOT be `null`.” “The request ID MUST NOT match the ID of any other request the sender has issued and not yet received a response for.” | verified |
| P29 | 2026-07-28: every result carries `resultType`; an unknown value is invalid | S03 | “The `result` MUST include a `resultType` field to indicate the type of the result.” “A `resultType` of any value unrecognized by the client MUST be considered invalid.” | verified |
| P30 | 2026-07-28: codes `-32020` to `-32099` are reserved for MCP | S03 | “`-32020` to `-32099` — reserved for the MCP specification.” “Implementations MUST NOT emit any code from this sub-range that is not defined by this specification and MUST use defined codes only with their specified meanings.” | verified |
| P31 | 2026-07-28: statelessness; cross-request state needs an explicit identifier | S03 | “Servers MUST NOT rely on prior requests over the same connection to establish context (e.g., capabilities, protocol version, client identity).” “State that needs to span multiple requests (e.g., long-running tasks, application-level handles) MUST be referenced by an explicit identifier the client passes on each request.” | verified |
| P32 | 2026-07-28: reserved `_meta` keys and prefixes; required per-request fields | S03 | “Any prefix where the second label is `modelcontextprotocol` or `mcp` is reserved for MCP use.” “The following `_meta` keys are reserved by this specification:” “A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code `-32602` (Invalid params).” | verified |
| P33 | 2026-07-28: `clientInfo` and `serverInfo` are self-reported | S03 | “`io.modelcontextprotocol/clientInfo` and `io.modelcontextprotocol/serverInfo` are self-reported by the sender and are not verified by the protocol.” | verified |
| P34 | 2026-07-28 transports: no server-initiated request; the body is the source of truth | S04 | “No other message direction exists: per the message patterns, servers do not initiate JSON-RPC requests and clients do not send JSON-RPC responses.” “The body remains the source of truth; bindings that mirror metadata define how mismatches are rejected.” | verified |
| P35 | 2026-07-28 stdio: framing, no server requests, cancellation by notification | S05 | “Messages are delimited by newlines, and MUST NOT contain embedded newlines.” “The server MUST NOT write JSON-RPC requests to `stdout`.” “To cancel an in-flight request, the client MUST send a `notifications/cancelled` notification referencing the request's ID.” | verified |
| P36 | 2026-07-28 Streamable HTTP: POST only, one message per POST body | S06 | “The server MUST provide a single HTTP endpoint path (hereafter referred to as the MCP endpoint) that supports POST.” “The body of the HTTP POST MUST be a single JSON-RPC request or notification.” | verified |
| P37 | 2026-07-28 Streamable HTTP: `Mcp-Method` and `Mcp-Name` headers, checked against the body, `HeaderMismatch` `-32020` | S06 | “These headers are REQUIRED for compliance.” “A required standard header (`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`) is missing.” “Servers MUST reject requests with a `400 Bad Request` HTTP status and JSON-RPC error code `-32020` (`HeaderMismatch`) if any validation fails.” | verified |
| P38 | 2026-07-28 Streamable HTTP: no sessions, no resumability | S06 | “An `Mcp-Session-Id` header on a request: ignore it, and do not mint or echo session IDs.” “Resumable SSE streams via `Last-Event-ID` are not supported.” | verified |
| P39 | 2026-07-28 Streamable HTTP: HTTP+SSE deprecated; `Origin` validation | S06 | “The HTTP+SSE transport from protocol version 2024-11-05 has been deprecated since protocol version `2025-03-26` and is classified as Deprecated under the feature lifecycle policy (SEP-2596).” “If the `Origin` header is present and invalid, servers MUST respond with HTTP 403 Forbidden.” | verified |
| P40 | 2026-07-28 versioning: era model | S07 | “Modern: protocol versions that convey version, identity, and capabilities as per-request metadata (revision `2026-07-28` and later).” “Legacy: protocol versions that establish a session with an `initialize` handshake (`2025-11-25` and earlier).” | verified |
| P41 | 2026-07-28 versioning: compatibility matrix and dual-era servers | S07 | “The following matrix summarizes the expected outcome of every combination of client and server era:” “An `initialize` request selects legacy semantics, scoped to the stdio process (stdio) or the session (HTTP), as specified by the negotiated legacy protocol version.” “A dual-era server MAY serve both eras concurrently on the same endpoint or process.” | verified |
| P42 | 2026-07-28 versioning: `server/discover` is mandatory for servers | S07 | “Servers MUST implement `server/discover`.” | verified |
| P43 | 2026-07-28 multi round-trip requests: `InputRequiredResult` only on three methods | S08 | “Servers MUST send server-to-client requests (such as `roots/list`, `sampling/createMessage`, or `elicitation/create`) using the MRTR pattern.” “Servers MUST NOT send `InputRequiredResult` responses on any other client requests.” | verified; the three methods are `prompts/get`, `resources/read`, and `tools/call` (table on the same page) |
| P44 | 2026-07-28 multi round-trip requests: `requestState` integrity | S08 | “If `requestState` influences authorization, resource access, or business logic, servers MUST protect its integrity (e.g. HMAC or AEAD) and MUST reject state that fails verification.” | verified |
| P45 | 2026-07-28 multi round-trip requests: the retry is a new request | S08 | “The JSON-RPC `id` MUST be different between the initial request and the retry, as they are independent requests.” | verified |
| P46 | 2026-07-28 authorization: stdio takes credentials from the environment; audience validation; no other token | S09 | “Implementations using an STDIO transport SHOULD NOT follow this specification, and instead retrieve credentials from the environment.” “MCP servers MUST validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2.” “MCP servers MUST NOT accept or transit any other tokens.” | verified |
| P47 | 2026-07-28 authorization security considerations: audience, no passthrough, static client ids | S10 | “MCP servers MUST only accept tokens specifically intended for themselves and MUST reject tokens that do not include them in the audience claim or otherwise verify that they are the intended recipient of the token.” “The MCP server MUST NOT pass through the token it received from the MCP client.” “MCP proxy servers using static client IDs MUST obtain user consent for each dynamically registered client before forwarding to third-party authorization servers (which may require additional consent).” | verified |
| P48 | 2026-07-28 `server/discover`: purpose; `serverInfo` unverified | S11 | “`server/discover` lets a client query a server's supported protocol versions, capabilities, and identity before sending any other requests.” “`serverInfo` is self-reported by the server and is not verified by the protocol.” | verified |
| P49 | 2026-07-28 pagination: opaque cursors | S12 | “Pagination in MCP uses an opaque cursor-based approach, instead of numbered pages.” “Clients MUST treat cursors as opaque tokens:” | verified |
| P50 | 2026-07-28 tools: `tools/list` content, which may vary by authorization | S13 | “Servers that declare the `tools` capability MUST respond to `tools/list` requests with the set of tools currently available to the requesting client.” “The set MAY vary by the authorization presented on the request — for example, returning only the tools the caller's granted scopes permit — since credentials are per-request input, not connection state.” | verified |
| P51 | 2026-07-28 tools: `tools/call` | S13 | “To invoke a tool, clients send a `tools/call` request:” | verified |
| P52 | 2026-07-28 tools: annotations are untrusted; tool names | S13 | “For trust & safety and security, clients MUST consider tool annotations to be untrusted unless they come from trusted servers.” “Tool names SHOULD be between 1 and 128 characters in length (inclusive).” | verified |
| P53 | 2026-07-28 tools: `listChanged` | S13 | “`listChanged` indicates whether the server will emit notifications when the list of available tools changes.” “When the list of available tools changes, servers that declared the `listChanged` capability SHOULD send a notification to clients that have opened a `subscriptions/listen` stream with `toolsListChanged: true`:” | verified |
| P54 | Tasks extension: identifier, `CreateTaskResult` with `resultType` `task` | S14 | “The client includes `io.modelcontextprotocol/tasks` in its per-request capabilities.” “In response to a supported request, the server returns a `CreateTaskResult` (identified by `resultType: "task"`) containing a `taskId`, initial status, TTL, and suggested polling interval.” | verified |
| P55 | Tasks extension: `tasks/get`, `tasks/update`, `tasks/cancel` | S14 | “The client calls `tasks/get` with the `taskId`.” “The client fulfills these via `tasks/update`.” “The client can send `tasks/cancel` at any time.” | verified |
| P56 | Tasks extension: the overview defers to the repository | S14 | “The ext-tasks repository contains the full specification and documentation for MCP Tasks.” | verified |

### Items verified on 2026-10-16

| Row | Item | Statement | Source | Quote | Result |
|---|---|---|---|---|---|
| T1a | 1 | 2025-11-25 lifecycle: `initialize` comes first and is followed by `notifications/initialized` | S20 | “The initialization phase MUST be the first interaction between client and server.” “The client MUST initiate this phase by sending an `initialize` request containing:” “After successful initialization, the client MUST send an `initialized` notification to indicate it is ready to begin normal operations:” | verified |
| T1b | 1 | 2025-11-25 lifecycle: version negotiation | S20 | “In the `initialize` request, the client MUST send a protocol version it supports.” “If the server supports the requested protocol version, it MUST respond with the same version.” “Otherwise, the server MUST respond with another protocol version it supports.” “If the client does not support the version in the server's response, it SHOULD disconnect.” | verified |
| T1c | 1 | 2025-11-25 cancellation: `notifications/cancelled`, same direction, never for `initialize`, `tasks/cancel` for tasks | S21 | “When a party wants to cancel an in-progress request, it sends a `notifications/cancelled` notification containing:” “Were previously issued in the same direction” “The `initialize` request MUST NOT be cancelled by clients” “For task-augmented requests, the `tasks/cancel` request MUST be used instead of the `notifications/cancelled` notification.” | verified |
| T2a | 2 | 2025-11-25 sampling: a server-initiated `sampling/createMessage`, gated by the `sampling` capability | S22 | “To request a language model generation, servers send a `sampling/createMessage` request:” “Clients that support sampling MUST declare the `sampling` capability during initialization:” “Servers MUST NOT send tool-enabled sampling requests to Clients that have not declared support for tool use via the `sampling.tools` capability.” | verified |
| T2b | 2 | 2025-11-25 elicitation: a server-initiated `elicitation/create` in form mode and URL mode, gated by declared modes | S23 | “Form mode: Servers can request structured data from users with optional JSON schemas to validate responses” “URL mode: Servers can direct users to external URLs for sensitive interactions that must not pass through the MCP client” “To request information from a user, servers send an `elicitation/create` request.” “Servers MUST NOT send elicitation requests with modes that are not supported by the client.” | verified |
| T2c | 2 | 2025-11-25 roots: a server-initiated `roots/list` and the client's `notifications/roots/list_changed` | S24 | “To retrieve roots, servers send a `roots/list` request:” “Clients that support roots MUST declare the `roots` capability during initialization:” “When roots change, clients that support `listChanged` MUST send a notification:” | verified |
| T2d | 2 | 2025-11-25 capability gating: only negotiated capabilities are used | S20 | “Client and server capabilities establish which optional protocol features will be available during the session.” “Only use capabilities that were successfully negotiated” | verified |
| T3a | 3 | 2025-11-25 tasks utility is experimental and bidirectional; methods `tasks/get`, `tasks/result`, `tasks/list`, `tasks/cancel` | S25 | “Tasks were introduced in version 2025-11-25 of the MCP specification and are currently considered experimental.” “The Model Context Protocol (MCP) allows requestors — which can be either clients or servers, depending on the direction of communication — to augment their requests with tasks.” “To retrieve the result of a completed task, requestors can send a `tasks/result` request:” “To retrieve a list of tasks, requestors can send a `tasks/list` request.” | verified |
| T3b | 3 | 2025-11-25 tasks utility: tasks bound to the authorization context; id entropy without one | S25 | “When an authorization context is provided, receivers MUST bind tasks to said context.” “If context-binding is unavailable, receivers MUST generate cryptographically secure task IDs with enough entropy to prevent guessing and should consider using shorter TTL durations to reduce the exposure window.” | verified |
| T4a | 4 | ext-tasks: methods and the result discriminator; only `tools/call` is task-augmented | S26 | “The extension introduces three methods: `tasks/get`, `tasks/update`, and `tasks/cancel`; a polymorphic-result discriminator (`resultType: "task"`); and a `Task` shape that carries a task status, in-progress server-to-client requests, and a final result or error.” “The following methods currently support task-augmented execution:” | verified; the list under the second quote has the single entry `tools/call` |
| T4b | 4 | ext-tasks: access control on `tasks/get`, `tasks/update`, `tasks/cancel` | S26 | “Servers MUST perform authentication and authorization checks on each task-related request to ensure that the client has permission to access a task.” “Servers MUST return this error for non-declaring clients issuing `tasks/get`, `tasks/update`, and `tasks/cancel` requests.” | verified |
| T4c | 4 | ext-tasks: task ownership, a task bound to the principal that created it | S26 | “Servers MUST perform authentication and authorization checks on each task-related request to ensure that the client has permission to access a task.” “Because there is no `tasks/list`, a server cannot inadvertently leak the existence of one caller's tasks to another.” | contradicted: the Security Considerations section has four rules (task ID unguessability, auth binding, cross-caller correlation, input-request trust model) and none of them names an owning principal or binds a task to the authorization context of the creating request; the 2025-11-25 utility did (row `T3b`). Who may access a task is left to the server's authorization check, so the profile must supply the binding itself |
| T4d | 4 | ext-tasks: task id entropy | S26 | “A server MAY use task IDs as bearer tokens for a server's stored state.” “Servers MUST generate them with sufficient entropy that a third party cannot enumerate or guess them.” | verified |
| T4e | 4 | ext-tasks: `notifications/tasks` through `subscriptions/listen`, carrying the full task | S26 | “Servers MAY push status updates via `notifications/tasks` notifications in addition to servicing client polls:” “To begin listening for task status notifications, clients send a `subscriptions/listen` request to the server including a list of task IDs the client is interested in:” “Each notification carries a complete `DetailedTask` for the current status, identical to what `tasks/get` would have returned at that moment.” | verified |
| T4f | 4 | ext-tasks: a task only for a request that declares the extension; `tasks/cancel`, never `notifications/cancelled`, for a task | S26 | “A server MUST NOT return `CreateTaskResult` to a client that did not include the extension capability on its request, regardless of prior declarations.” “The `notifications/cancelled` notification MUST NOT be used for task cancellation.” | verified |
| T5a | 5 | 2025-11-25 security best practices: session hijacking | S27 | “Session hijacking is an attack vector where a client is provided a session ID by the server, and an unauthorized party is able to obtain and use that same session ID to impersonate the original client and perform unauthorized actions on their behalf.” “MCP Servers MUST NOT use sessions for authentication.” “MCP servers MUST use secure, non-deterministic session IDs.” “MCP servers SHOULD bind session IDs to user-specific information.” | verified |
| T5b | 5 | 2026-07-28 security best practices: session hijacking | S28 | “MCP is stateless and has no protocol-level sessions.” “MCP servers MUST NOT treat possession of a state handle as authentication.” “For guidance on securing the server-assigned session IDs used by protocol version `2025-11-25` and earlier, see Session Hijacking in the 2025-11-25 version of this page.” | contradicted: the 2026-07-28 page has no session hijacking section. Its section "State Handle Hijacking" covers server-minted handles passed as tool arguments, and session-ID guidance applies to the legacy era only (row `T5a`) |
| T5c | 5 | 2025-11-25 security best practices: token passthrough | S27 | “"Token passthrough" is an anti-pattern where an MCP server accepts tokens from an MCP client without validating that the tokens were properly issued to the MCP server and passes them through to the downstream API.” “MCP servers MUST NOT accept any tokens that were not explicitly issued for the MCP server.” | verified |
| T5d | 5 | 2026-07-28 security best practices: token passthrough | S28 | “"Token passthrough" is an anti-pattern where an MCP server accepts tokens from an MCP client without validating that the tokens were properly issued to the MCP server and passes them through to the downstream API.” “MCP servers MUST NOT accept any tokens that were not explicitly issued for the MCP server.” | verified |
| T5e | 5 | 2025-11-25 security best practices: confused deputy | S27 | “To prevent confused deputy attacks, MCP proxy servers MUST implement per-client consent and proper security controls as detailed below.” | verified |
| T5f | 5 | 2026-07-28 security best practices: confused deputy | S28 | “To prevent confused deputy attacks, MCP proxy servers MUST implement per-client consent and proper security controls as detailed below.” | verified |
| T5g | 5 | 2025-11-25 security best practices: SSRF | S27 | “Server-Side Request Forgery (SSRF) is an attack where an attacker can induce an MCP client to make HTTP requests to unintended destinations, potentially accessing internal network resources, cloud metadata endpoints, or other protected services.” “MCP clients deployed to a server MUST consider SSRF risks and implement appropriate mitigations when fetching OAuth-related URLs.” | verified |
| T5h | 5 | 2026-07-28 security best practices: SSRF, now also against authorization servers | S28 | “MCP clients deployed to a server MUST consider SSRF risks and implement appropriate mitigations when fetching OAuth-related URLs.” “SSRF risks are not limited to MCP clients.” | verified |
| T6a | 6 | 2026-07-28 subscriptions: `subscriptions/listen` replaces `resources/subscribe` and the GET endpoint; only requested types; acknowledgment first | S29 | “It replaces the former `resources/subscribe` RPC and the HTTP GET endpoint.” “The server MUST NOT send notification types the client has not explicitly requested.” “The server MUST send `notifications/subscriptions/acknowledged` as the first message carrying the subscription's ID in `_meta` under `io.modelcontextprotocol/subscriptionId`, and MUST NOT send any notification on the subscription before it.” | verified |
| T6b | 6 | 2026-07-28 subscriptions: no subscription state across stdio reconnection; graceful closure | S29 | “On stdio, if the connection is terminated and then re-established, the client MUST re-send `subscriptions/listen` to re-establish its subscriptions — the server holds no subscription state across reconnections.” “When the server ends a subscription on its own initiative (for example, during shutdown), it SHOULD respond to the original `subscriptions/listen` request with a completion result before closing the stream.” | verified; see note N1 |
| T6c | 6 | 2026-07-28 cancellation: client-sent on stdio, stream close on HTTP, server-sent only to end a subscription | S30 | “A server MUST send `notifications/cancelled` referencing a `subscriptions/listen` request ID when it tears down that subscription stream (see Subscriptions).” “Servers MUST NOT send `notifications/cancelled` for any other purpose.” “Streamable HTTP: Closing the SSE response stream is the cancellation signal.” “stdio: There is no per-request stream to close. The client MUST send a `notifications/cancelled` notification referencing the request ID.” | verified; see note N1 |
| T7a | 7 | 2026-07-28 resources: URI rules | S31 | “Each resource is uniquely identified by a URI.” “Custom URI schemes MUST be in accordance with RFC3986, taking the above guidance in to account.” “Servers MUST validate all resource URIs” | verified |
| T7b | 7 | 2026-07-28 resources: templates | S31 | “Resource templates allow servers to expose parameterized resources using URI templates.” | verified; the link target of "URI templates" is RFC 6570 |
| T7c | 7 | 2026-07-28 resources: subscribe through `subscriptions/listen` | S31 | “Clients subscribe to change notifications for specific resources by sending a `subscriptions/listen` request with the resource URIs listed in `notifications.resourceSubscriptions`.” | verified |
| T7d | 7 | 2026-07-28 prompts: `prompts/get` | S32 | “To retrieve a specific prompt, clients send a `prompts/get` request.” “Implementations MUST carefully validate all prompt inputs and outputs to prevent injection attacks or unauthorized access to resources.” | verified |
| T7e | 7 | 2026-07-28 completion utility: `completion/complete` with prompt and resource references | S33 | “To get completion suggestions, clients send a `completion/complete` request specifying what is being completed through a reference type:” “The protocol supports two types of completion references:” “Control access to sensitive suggestions” | verified; the two reference types are `ref/prompt` and `ref/resource` (table on the same page) |
| T8a | 8 | 2026-07-28 schema: `CallToolRequestParams` fields `_meta` (required), `name` (required), `arguments`, `inputResponses`, `requestState` | S34 | “"description": "Parameters for a `tools/call` request.", "properties": { "_meta": { "$ref": "#/$defs/RequestMetaObject" }, "arguments": { "additionalProperties": {}, "description": "Arguments to use for the tool call.", "type": "object" }, "inputResponses": { "$ref": "#/$defs/InputResponses" }, "name": { "description": "The name of the tool.", "type": "string" }, "requestState": { "type": "string" } }, "required": [ "_meta", "name" ]” | verified |
| T8b | 8 | 2026-07-28 schema: `ReadResourceRequestParams` fields `_meta` (required), `uri` (required), `inputResponses`, `requestState` | S34 | “"description": "Parameters for a `resources/read` request.", "properties": { "_meta": { "$ref": "#/$defs/RequestMetaObject" }, "inputResponses": { "$ref": "#/$defs/InputResponses" }, "requestState": { "type": "string" }, "uri": { "description": "The URI of the resource. The URI can use any protocol; it is up to the server how to interpret it.", "format": "uri", "type": "string" } }, "required": [ "_meta", "uri" ]” | verified |
| T8c | 8 | 2026-07-28 schema: `GetPromptRequestParams` fields `_meta` (required), `name` (required), `arguments`, `inputResponses`, `requestState` | S34 | “"description": "Parameters for a `prompts/get` request.", "properties": { "_meta": { "$ref": "#/$defs/RequestMetaObject" }, "arguments": { "additionalProperties": { "type": "string" }, "description": "Arguments to use for templating the prompt.", "type": "object" }, "inputResponses": { "$ref": "#/$defs/InputResponses" }, "name": { "description": "The name of the prompt or prompt template.", "type": "string" }, "requestState": { "type": "string" } }, "required": [ "_meta", "name" ]” | verified; see note N2 |
| T9a | 9 | 2026-07-28 client registration: three mechanisms, priority order, Dynamic Client Registration deprecated | S35 | “MCP supports three client registration mechanisms.” “Clients supporting all options SHOULD use the following priority order:” “Dynamic Client Registration is deprecated.” | verified |
| T9b | 9 | 2026-07-28 deprecated-features registry: Roots, Sampling, Logging, Dynamic Client Registration, and HTTP+SSE are Deprecated, not removed | S36 | “This page is the registry of specification features that are currently in the Deprecated state under the feature lifecycle and deprecation policy (SEP-2596).” “A Deprecated feature remains part of the specification but is scheduled for removal: new implementations SHOULD NOT adopt it, and existing implementations SHOULD migrate before the feature's earliest removal.” “No features have been removed under this policy yet.” | verified; the registry table has one row each for Roots, Sampling, Logging, Dynamic Client Registration, the `includeContext` values `"thisServer"` and `"allServers"`, and the HTTP+SSE transport |
| T9c | 9 | 2026-07-28 changelog: the deprecations of Roots, Sampling, Logging, and Dynamic Client Registration | S02 | “Deprecate the Roots, Sampling, and Logging features (SEP-2577).” “Deprecate the OAuth 2.0 Dynamic Client Registration Protocol (RFC7591) as a client registration mechanism in favor of Client ID Metadata Documents (PR #2858).” | verified |

No item remains to be verified, and no item is declared out of claim.

### Rows supporting the method classification seed

Pages fetched 2026-10-16.

| Row | Statement | Source | Quote | Result |
|---|---|---|---|---|
| X1 | 2025-11-25: either party sends `ping` | S39 | “Either the client or server can initiate a ping by sending a `ping` request.” | verified |
| X2 | 2025-11-25: either party sends progress notifications | S40 | “Either side can send progress notifications to provide updates about operation status.” | verified |
| X3 | 2026-07-28: only the server sends progress notifications | S41 | “The server MAY send progress notifications to report the status of requests the client has issued.” | verified |
| X4 | 2026-07-28: a notification gets no response | S03 | “The receiver MUST NOT send a response.” | verified |

### Notes on the record

N1. The two 2026-07-28 pages give different signals for a subscription the server ends: the subscriptions page says the server SHOULD answer the `subscriptions/listen` request with a completion result (row `T6b`), and the cancellation page says the server MUST send `notifications/cancelled` referencing the `subscriptions/listen` request ID (row `T6c`). The mapping sections need to handle both signals, in either order.

N2. The 2026-07-28 parameter objects declare no `additionalProperties`, so the schema admits members it does not name; the canonical message object of draft §10.2 includes every parameter. The 2025-11-25 parameter objects differ: in S37, `CallToolRequestParams` has the members `_meta`, `arguments`, `name`, and `task` with `name` required; `ReadResourceRequestParams` has `_meta` and `uri` with `uri` required; `GetPromptRequestParams` has `_meta`, `arguments`, and `name` with `name` required. `inputResponses` and `requestState` exist only in the modern era, and `task` only in the legacy era.

N3. The 2026-07-28 changelog says the tasks extension "allows servers to return task handles unsolicited without per-request opt-in" (S02), while the extension forbids a `CreateTaskResult` to a request that does not declare the extension capability (row `T4f`). The two agree only if "per-request opt-in" means the removed per-request `task` parameter of 2025-11-25; the declaration in the request's capabilities is still required. This record takes the extension text, which is the normative pin, as authoritative.

N4. The method sets are taken from the pinned schemas, read on 2026-10-16: every definition whose `method` property is a constant. S34 defines 22 such definitions (21 distinct methods), S37 defines 31, and S38 defines `tasks/get`, `tasks/update`, `tasks/cancel`, and `notifications/tasks`, together with `elicitation/create`, `sampling/createMessage`, and `roots/list` as the alternatives of its `InputRequest`.

### Method classification seed

The seed classifies every method of the two pinned revisions and of the tasks extension for the operation mapping. `protected` means a PACT presentation is required and admission is evaluated; `passthrough` means native controls only, never PACT admission; `rejected` means the adapter fails closed with `UNSUPPORTED_REQUIREMENT` (draft §13.4). A notification gets no response (row `X4`), so how a rejected notification is reported is left to the mapping sections. A method that a revision does not define is `rejected` in that era. The experimental tasks utility of 2025-11-25 (row `T3a`) is not supported, so its methods and task-augmented requests are rejected. The defaults are: `completion/complete` protected, `logging/setLevel` passthrough, and any method not in this table rejected. The mapping sections that follow take this table as their input and may refine it; open items are marked.

| Method | Sent by | 2025-11-25 era | 2026-07-28 era | Basis |
|---|---|---|---|---|
| `initialize` | client | passthrough | not defined; on a dual-era server it selects the legacy era (`P41`) and is handled as in the 2025-11-25 column | `T1a`, `P41` |
| `notifications/initialized` | client | passthrough | rejected (removed, `P19`) | `T1a` |
| `ping` | either | passthrough | rejected (removed, `P23`) | `X1` |
| `server/discover` | client | rejected (not defined) | passthrough | `P42`, `P48` |
| `tools/list` | client | passthrough | passthrough; the list may vary by authorization (`P50`), and no PACT claim covers how it is partitioned | `P50` |
| `tools/call` | client | protected; a task-augmented request (one carrying `task`, note N2) is rejected | protected | `P51` |
| `resources/list` | client | passthrough | passthrough | `P49` |
| `resources/templates/list` | client | passthrough | passthrough | `T7b` |
| `resources/read` | client | protected | protected | `T7a` |
| `resources/subscribe` | client | protected | rejected (replaced, `P24`) | `T6a` |
| `resources/unsubscribe` | client | protected | rejected (replaced, `P24`) | `P24` |
| `prompts/list` | client | passthrough | passthrough | `P49` |
| `prompts/get` | client | protected | protected | `T7d` |
| `completion/complete` | client | protected | protected | default; `T7e` |
| `logging/setLevel` | client | passthrough | rejected (removed, `P23`) | default |
| `subscriptions/listen` | client | rejected (not defined) | protected when `notifications.resourceSubscriptions` is present; passthrough when it asks only for list-changed notifications; with `notifications.taskIds`, open item O2 | `T6a`, `T7c` |
| `tasks/get` | client | rejected (experimental tasks unsupported) | open item O1 | `T3a`, `T4a` |
| `tasks/update` | client | rejected (not defined) | protected | `T4a`, `T4b` |
| `tasks/cancel` | either in 2025-11-25; client in 2026-07-28 | rejected (experimental tasks unsupported) | protected | `T4a`, `T4f` |
| `tasks/result` | either | rejected (experimental tasks unsupported) | rejected (not defined; replaced by polling, S02) | `T3a` |
| `tasks/list` | either | rejected (experimental tasks unsupported) | rejected (not defined, `T4c`) | `T3a` |
| `sampling/createMessage` | server | rejected (server-initiated request); open item O3 | not a JSON-RPC request on the wire: it travels only inside `inputRequests` of an `InputRequiredResult`, which is passed through; a server-sent JSON-RPC request is rejected (`P34`) | `T2a`, `P43` |
| `elicitation/create` | server | rejected (server-initiated request); open item O3 | as `sampling/createMessage` | `T2b`, `P43` |
| `roots/list` | server | rejected (server-initiated request); open item O3 | as `sampling/createMessage` | `T2c`, `P43` |
| `notifications/roots/list_changed` | client | rejected (not in the passthrough set); open item O3 | rejected (removed, `P23`) | `T2c` |
| `notifications/cancelled` | either in 2025-11-25; client on stdio, and server only to end a subscription, in 2026-07-28 | passthrough | passthrough | `T1c`, `T6c` |
| `notifications/progress` | either in 2025-11-25; server in 2026-07-28 | passthrough | passthrough | `X2`, `X3` |
| `notifications/message` | server | passthrough | passthrough | |
| `notifications/resources/updated` | server | passthrough | passthrough, on an admitted subscription | `T7c` |
| `notifications/resources/list_changed` | server | passthrough | passthrough | `T6a` |
| `notifications/tools/list_changed` | server | passthrough | passthrough | `P53` |
| `notifications/prompts/list_changed` | server | passthrough | passthrough | `T6a` |
| `notifications/elicitation/complete` | server | passthrough | rejected (removed, S02) | `T2b` |
| `notifications/subscriptions/acknowledged` | server | rejected (not defined) | passthrough | `T6a` |
| `notifications/tasks/status` | either | rejected (experimental tasks unsupported) | rejected (not defined) | `T3a` |
| `notifications/tasks` | server | rejected (not defined) | follows the class of the subscription that carries it (open item O2) | `T4e` |
| a JSON-RPC batch (array) | either | rejected | rejected | `P06`, `P15`, `P35`, `P36` |
| any other method | either | rejected | rejected | default |

Open items for the mapping sections:

- O1. `tasks/get` in the modern era: either a continuation of the admitted `tools/call`, governed by the task ledger and needing no fresh presentation, or a protected operation that needs a fresh presentation on every poll. The result of a protected call is returned through it (row `T4e` shows a notification carries what `tasks/get` would return). Decision pending.
- O2. `subscriptions/listen` with `notifications.taskIds`, and the `notifications/tasks` it delivers: each notification carries the full task, including its final result (row `T4e`), so its class follows O1.
- O3. Legacy server-initiated requests (`sampling/createMessage`, `elicitation/create`, `roots/list`, and `ping` from the server) and the client's `notifications/roots/list_changed`. The default rule rejects them, which breaks legacy servers that depend on them. The alternative is to forward them outside PACT scope, never admitted and never carrying a presentation, and to state that as an unsupported claim with the residual risk assigned to the client. Decision pending.
