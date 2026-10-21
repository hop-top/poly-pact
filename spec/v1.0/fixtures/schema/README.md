# Schema cases

A manifest entry of kind `schema` tests that a document is accepted or rejected for its form alone: strict JSON (draft Section 7.1) and the Appendix A.3 schema, [`../../schemas/pact.schema.json`](../../schemas/pact.schema.json), applied to the definition that the document's type selects (Appendix A.1). The entries sit in two groups: `parse/`, one compact JWS per file, and `schema/`, lists of decoded objects in the format below. Every harness asserts the outcome of each entry from the manifest and the files named here alone.

## Inputs

An entry's `path` is one file, which holds one or more documents:

- A `.jws` file holds one compact JWS as ASCII text, the form in which an endpoint receives a signed artifact. The document is the JWS.
- A `.json` file is an object list: one strict JSON object with the members below. Each element of `objects` is one document.

| Member | Type | Required | Value |
|---|---|---|---|
| `description` | string | yes | What the objects are and where they come from. |
| `objects` | array | yes | One or more objects, in order. |
| `objects[].section` | string | yes | The draft section that shows the object, such as `"B.4"`. |
| `objects[].typ` | string | one of `typ` and `def` | The JWS `typ` of the signed artifact whose decoded payload the object is: a value of the draft Section 7.3 table. |
| `objects[].def` | string | one of `typ` and `def` | The name of the `$defs` definition of an object that is not signed, such as `AgentProfile` or `GatewayMetadata`. |
| `objects[].object` | object | yes | The decoded object. |

No other member is allowed, and the file is strict JSON as a whole. A document that is not strict JSON by itself, such as one with a duplicate member name, therefore cannot be an element of an object list; such inputs are the vectors of [`../vectors/strictjson/`](../vectors/strictjson/).

## Definition selection

The protected `typ` of a signed artifact selects its definition (Appendix A.1), after the draft Section 7.3 table:

| `typ` | Definition |
|---|---|
| `pact-requirements+jwt` | `RequirementContract` |
| `pact-evidence+jwt` | `Evidence` |
| `pact-presentation+jwt` | `Presentation` |
| `pact-admission+jwt` | `AdmissionAttestation` |
| `pact-outcome+jwt` | `OutcomeReport` |
| `pact-reputation+jwt` | `ReputationSnapshot` |
| `pact-learning-policy+jwt` | `LearningPolicy` |
| `pact-learning-artifact+jwt` | `LearningArtifact` |
| `pact-learning-event+jwt` | `LearningEvent` |

An object of an object list with `typ` gets the definition of that row; one with `def` gets the definition it names.

## Verdict

A harness gives each document a verdict, in this order, and stops at the first step that fails:

1. A compact JWS has three segments separated by two periods, and its protected header and payload are canonical unpadded base64url (RFC 7515 Section 2).
2. The protected header is a strict JSON object (draft Section 7.1) whose `typ` is a string of the table above. The other header members are not judged here; the JWS profile rules of draft Section 7.2 are the vectors of [`../vectors/jws/`](../vectors/jws/README.md).
3. The payload, or the object of an object list, is strict JSON: no duplicate member name, no non-finite number, valid UTF-8 without unpaired surrogates, no integer beyond `9007199254740991` in magnitude, and nesting no deeper than 16 (draft Sections 7.1 and 20.1).
4. The document validates against its definition: JSON Schema Draft 2020-12, with format `uri` asserted as the RFC 3986 expression of [`../vectors/schema/README.md`](../vectors/schema/README.md), so an unknown core member fails `additionalProperties` (Appendix A.1).

A document that passes every step is accepted. One that fails a step is rejected with `INVALID_MESSAGE`: invalid JSON, a schema failure, a malformed signature format or a `typ` the receiver does not consume (draft Section 13.4). The signature is not verified: the schema does not validate a compact JWS string's cryptography (Appendix A.1), and a schema case names no key.

## Outcomes

- `ACCEPTED`: every document of the input is accepted. The entry's `expected` is its `path`, since the file carries its expectation inline.
- `REJECTED`: every document is rejected with the `transport_code` of the entry's `expected` file, a `decision.json` under `expected/<id>/` with the members `transport_code` (required), `rejected_before_crypto` and `reason` (section decision.json of [`../README.md`](../README.md)).

## Cases

| Id | Input | Outcome |
|---|---|---|
| `parse/appendix-c-wrong-version` | The earlier Appendix C evidence JWS: its signature is valid, and its payload carries `pact_version` `0.2` where `Evidence` requires the constant `0.1` (draft Section 21). | `REJECTED`, `INVALID_MESSAGE` |
| `schema/appendix-b-valid` | The twelve decoded objects of Appendix B, B.1 to B.11 and B.13, copied from the draft: the agent profile, intent and operation context, the requirement contract, the runtime evidence, the reputation snapshot, the admission receipt, the outcome report, the learning policy, the learning artifact manifest, the learning lifecycle event and the gateway metadata. B.12 shows no object. | `ACCEPTED` |
| `schema/profiles/valid-stdio-metadata-no-endpoints` | Gateway metadata returned by the discovery method of the stdio-ipc transport profile: the Appendix B.13 metadata without endpoints and jwks_uri, with presentation_transports [adapter-envelope], the extension pact-transport-profile-v1 in extensions_supported and its TransportDeclaration in extensions (draft 13.3.1, 21, A.2). | `ACCEPTED` |
| `schema/profiles/valid-https-single-owner-metadata` | HTTPS gateway metadata of a single-owner deployment: the Appendix B.13 metadata with all seven endpoints, pact-conformance-profile-v1 in extensions_supported and its ConformanceDeclaration in extensions (draft 13.1, 21, 22.1). | `ACCEPTED` |
| `schema/profiles/valid-mcp-operation-context` | Operation context of an MCP tools/call bound to transport-neutral fields: method MCP, action mcp.tools.call, an https target_uri naming the MCP server and one resource naming the tool, on the Appendix B.3 object (draft 10.2, 13.3). | `ACCEPTED` |
| `schema/profiles/valid-contract-both-extensions` | Requirement contract whose extensions carry both profile declarations, pact-conformance-profile-v1 and pact-transport-profile-v1, on the Appendix B.4 object (draft 13.3.1, 21). | `ACCEPTED` |
| `schema/profiles/valid-attestation-conformance-ext` | Admission attestation whose extensions carry the pact-conformance-profile-v1 declaration, on the Appendix B.7 object (draft 21). | `ACCEPTED` |
| `schema/profiles/valid-conformance-declaration` | The ConformanceDeclaration payload of a single-owner deployment: profile single-owner 0.1, omitted roles reputation and learning, and the owner (draft 21, 22.1, A.2). | `ACCEPTED` |
| `schema/profiles/valid-transport-declaration` | The TransportDeclaration payload of the stdio-ipc transport profile: channels stdio, uds and named-pipe, framing ndjson, a frame limit of 524288 bytes, identity assurance kernel-peer and launcher (draft 13.3.1, 20.1, A.2). | `ACCEPTED` |
| `schema/profiles/valid-extensions-supported-mixed` | Gateway metadata whose extensions_supported lists the first-party token pact-transport-profile-v1 and the HTTPS URI extension https://ext.example/finance-limits (draft 21). | `ACCEPTED` |
| `schema/profiles/gm-no-endpoints-no-transport-ext` | Gateway metadata without endpoints and jwks_uri and without the extension pact-transport-profile-v1: the HTTPS baseline requires both (draft 13.1, 13.2, A.2). | `REJECTED`, `INVALID_MESSAGE`; first violation `(document)` `required` |
| `schema/profiles/gm-transport-ext-http-endpoint` | Gateway metadata of the stdio-ipc transport profile that also publishes endpoints, one of them http://: a published endpoint is HTTPS whatever the transport profile (draft 13.1, 13.3, 19). | `REJECTED`, `INVALID_MESSAGE`; first violation `/endpoints/evaluate` `pattern` |
| `schema/profiles/gm-endpoints-missing-reputation` | HTTPS gateway metadata whose endpoints lack reputation_query, without the transport extension: the baseline rule is unchanged (draft 13.2). | `REJECTED`, `INVALID_MESSAGE`; first violation `/endpoints` `required` |
| `schema/profiles/cd-omitted-role-not-optional` | ConformanceDeclaration payloads that omit a role no conformance profile may omit: gateway, validator and holder, one per document (draft 22.1). | `REJECTED`, `INVALID_MESSAGE`; first violation `/omitted_roles/0` `enum` |
| `schema/profiles/cd-unknown-profile` | ConformanceDeclaration payload naming the conformance profile lite, which is not a conformance profile (draft 22.1). | `REJECTED`, `INVALID_MESSAGE`; first violation `/conformance_profile` `enum` |
| `schema/profiles/cd-unknown-member` | ConformanceDeclaration payload with the unknown member roles_note: the declaration rejects additional members (draft 7.1, A.1). | `REJECTED`, `INVALID_MESSAGE`; first violation `(document)` `additionalProperties` |
| `schema/profiles/td-network-channel` | TransportDeclaration payload naming the channel tcp-loopback: a channel reachable over a network is not eligible for a local-channel profile (draft 13.3.1). | `REJECTED`, `INVALID_MESSAGE`; first violation `/channels/0` `enum` |
| `schema/profiles/td-frame-zero` | TransportDeclaration payload with max_frame_bytes 0 (draft 20.1: at least 360448). | `REJECTED`, `INVALID_MESSAGE`; first violation `/max_frame_bytes` `minimum` |
| `schema/profiles/td-frame-below-floor` | TransportDeclaration payload with max_frame_bytes 360447, one byte below the draft 20.1 floor of 360448. | `REJECTED`, `INVALID_MESSAGE`; first violation `/max_frame_bytes` `minimum` |
| `schema/profiles/td-frame-above-ceiling` | TransportDeclaration payload with max_frame_bytes 1048577, one byte above the draft 20.1 ceiling of 1048576. | `REJECTED`, `INVALID_MESSAGE`; first violation `/max_frame_bytes` `maximum` |
| `schema/profiles/td-framing-length-prefixed` | TransportDeclaration payload with framing length-prefixed; the stdio-ipc profile frames with ndjson (draft 13.3.1). | `REJECTED`, `INVALID_MESSAGE`; first violation `/framing` `const` |
| `schema/profiles/oc-method-native-name` | MCP operation context whose method is the native method name tools/call instead of the transport-neutral MCP (draft 10.2, 13.3). | `REJECTED`, `INVALID_MESSAGE`; first violation `/method` `pattern` |
| `schema/profiles/oc-target-file-uri` | MCP operation context whose target_uri is `file:///srv/data`; the schema requires an https target_uri (draft 10.2, A.3). | `REJECTED`, `INVALID_MESSAGE`; first violation `/target_uri` `pattern` |
| `schema/profiles/oc-empty-resources` | MCP operation context with an empty resources array; an operation names at least one resource (draft 10.2). | `REJECTED`, `INVALID_MESSAGE`; first violation `/resources` `minItems` |
| `schema/profiles/gm-ext-id-bare-token` | Gateway metadata whose extensions_supported lists transport-profile, a bare token that is neither a URI nor a pact- first-party identifier (draft 21). | `REJECTED`, `INVALID_MESSAGE`; first violation `/extensions_supported/0` `anyOf` |
