# PACT mTLS peer-identity and certificate-lifecycle profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose and status

This is the integration profile ([`TEMPLATE.md`](../TEMPLATE.md)) for a gateway that authenticates machine clients with X.509 client certificates over mutual TLS and then requires a signed PACT presentation, the scenario of [`example_I07.md`](../../examples/example_I07.md). It states which certificates the gateway accepts and how a certificate names a workload; how certificate status, renewal, connection reuse, and session resumption behave; and the one way a TLS terminator in front of the gateway may pass a peer identity on. It answers the open finding G16 of `docs/handoff.md` (source repository only, not part of the mirror); the section "G16 closure map" shows which rule answers which closure item.

The profile adds no wire field and no protocol requirement. Where it and [`draft.md`](../../draft.md) differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. The rules MTLS-1 to MTLS-31 are normative for a claim made under this profile and carry ids so that fixtures and reviews can cite them. They are language-neutral. The section "Evidence" is informative: it records what the Go standard library does, as probed for this profile, and names the Go packages of this repository that an adapter builds on. The Go standard library is the reference TLS and X.509 stack of this repository and is called "the reference stack" in the rules. Section 10 indexes the conformance cases of this profile, the behaviour tested outside them, and the common cases the adapter replaces.

Shared rules are not repeated here. Identifiers, enrollment, and lifecycle are in [`identity-mapping.md`](../identity-mapping.md) (rules IM-1 to IM-29); the vocabulary of source observation and status time is in [`freshness.md`](../freshness.md). A rule below can be stricter than those documents and none is weaker.

## Profile header

| Field | Value |
|---|---|
| Profile name | `mtls`: mTLS peer identity and certificate lifecycle |
| Target product and version | Mutual TLS 1.3 (RFC 8446) with X.509 v3 certificates and v2 certificate revocation lists (RFC 5280). Optional trusted terminator: Envoy, `x-forwarded-client-cert` text format as its upstream documentation describes it; no Envoy release is pinned (open item O2) |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `r2`, 2026-10-17 |
| Maintainer | PACT adapter maintainers |
| Reference documents | draft = `spec/v1.0/draft.md`; handoff = `docs/handoff.md` (source repository only); identity rules = [`identity-mapping.md`](../identity-mapping.md); freshness rules = [`freshness.md`](../freshness.md); scenario = [`example_I07.md`](../../examples/example_I07.md) |
| Mapping revision | `pact-mtls-1`: the revision of the identity-input mapping defined by the rules below |

## Terms

| Term | Meaning in this profile |
|---|---|
| Pinned CA set | The configured, finite set of certificate authority certificates that the gateway trusts to issue workload certificates (MTLS-2). |
| Peer leaf | The end-entity certificate that names the workload: the client certificate of the TLS peer on a direct listener, or the `Cert` element of the forwarded header on a terminated listener. |
| Direct listener | A TLS listener whose peer is the agent's own workload. |
| Terminated listener | A TLS listener whose peer is a trusted terminator that relays requests of end clients (MTLS-22). |
| Terminator | A reverse proxy or load balancer that ends the end client's TLS connection and opens its own connection to the gateway. |
| Snapshot | A certificate revocation list of one pinned CA that was accepted under MTLS-12. |
| Status time `u` | The `thisUpdate` of the snapshot that a status evaluation used. |
| Status bound `S` | The longest age of status information that the adapter relies on (MTLS-14). |
| Evaluation instant | The adapter's clock at the moment it handles a request. |
| Native denial | The result of `authenticate_native` when native authentication was evaluated and failed (draft §17.1). It carries one public reason of a closed set: `NO_CREDENTIAL` when the request carried no credential, `CREDENTIAL_REJECTED` otherwise. Its code is `INVALID_PROOF`. |

## Rules

### A. Peer certificate policy

**MTLS-1. Mutual TLS 1.3 only.** A claimed route is reachable only through a TLS listener that offers TLS 1.3 (RFC 8446), requests a client certificate, and refuses a connection that presents none. No cleartext listener and no TLS version below 1.3 serves a claimed route. Certificate-based client authentication is not available in a PSK handshake (RFC 8446 §4.4), which MTLS-17 relies on.

**MTLS-2. Pinned CA set.** The trust anchors are exactly the entries of the pinned CA set. An entry holds the `ca-id` (the configured identifier of the authority, never the text of its subject name; identity-mapping §3.3), the CA certificate, the `san-kind` (`uri` or `dns`) that this authority uses to name workloads, and the location of its revocation list (MTLS-10). No other trust store is consulted. Certificates that the peer sends besides the leaf are path-building input and never anchors. The set changes only through the gateway's administrative controls (draft §4.2); a certificate, a header, a discovery response, or an AgentProfile cannot add to it. An entry is withdrawn by removing it. A pinned CA has no revocation list entry of its own.

**MTLS-3. Pinned direct issuer.** The chain of the peer leaf verifies to the pinned set for the key purpose clientAuth at the evaluation instant, and the issuer of the leaf, the second certificate of every verified chain, is itself a certificate of the pinned set (byte-identical). Its entry gives the `ca-id`. A leaf whose verified chains name different pinned entries is refused. A chain of one certificate, which is a pinned certificate presented as the leaf, is refused. A leaf issued by an unpinned intermediate below a pinned root is refused: an intermediate that issues workload certificates is pinned explicitly (probe P8).

**MTLS-4. End-entity client certificate.** The peer leaf:

- (a) carries an extended key usage extension that lists id-kp-clientAuth. A leaf with no such extension, or whose only listed purpose is anyExtendedKeyUsage, is refused. RFC 5280 §4.2.1.12 lets an application require the extension and a particular purpose, and lets it reject the any-purpose OID when the expected one is missing;
- (b) does not assert cA in basic constraints and, when a key usage extension is present, does not assert keyCertSign or cRLSign (RFC 5280 §4.2.1.3 and §4.2.1.9: those assert the use of the key to verify certificate signatures);
- (c) includes digitalSignature when a key usage extension is present. RFC 5280 §4.2.1.12 allows digitalSignature and/or keyAgreement with clientAuth, and TLS 1.3 client authentication signs the handshake (RFC 8446 §4.4).

The reference stack enforces none of (a) to (c) and accepts a leaf with no extended key usage extension (probe P7).

**MTLS-5. Validity.** At every evaluation instant the peer leaf and its pinned issuer are inside their validity periods. The baseline clock skew of draft §7.5 applies to notBefore and no grace applies to notAfter. A certificate that expires while a connection is open fails the next request.

**MTLS-6. Identifier derivation.** The workload identifier is `mtls:` followed by `ca-id`, `san-kind`, and `workload-id`, each separated by `:`, written under identity-mapping §3.1 to §3.3. It is derived only from the `ca-id` of MTLS-3, the `san-kind` of that entry, and the `workload-id` of MTLS-7. The subject distinguished name, the common name, the serial number, the fingerprint, the validity dates, subject alternative names of other kinds, the TLS public key, and every HTTP header are never inputs (IM-1, IM-5, IM-22); MTLS-9 uses the TLS public key only to refuse a match with the holder key. Subject text may be shown to an operator and is never compared. The realm (`tenant_id`, `environment_id`) is the configuration of the listener that accepted the connection and never a value in the certificate. The leaf carries exactly one subject alternative name entry of the entry's `san-kind`; none, or more than one, is refused. IM-22 asks a profile to name the selection rule for several entries, and this is it.

**MTLS-7. Canonical form of the subject alternative name.**

- `uri`: the octets of the uniformResourceIdentifier entry exactly as issued, read from the extension and not re-serialized by a URI library (probe P9: a library changes the scheme case and rewrites invalid octets). The value is absolute, that is a scheme and a scheme-specific part (RFC 5280 §4.2.1.6), and contains only octets 0x21 to 0x7E. A relative reference, an empty value, or any other octet is refused; the reference stack accepts all three (probe P9). No normalization is applied: URIs that differ in scheme case, host case, escape case, or default port are different identifiers (IM-3), although RFC 5280 §4.2.1.6 calls scheme and host case-insensitive. A CA issues renewals with the same spelling; a renewal spelled differently is another workload without an enrollment (MTLS-16).
- `dns`: the dNSName in lower case (RFC 5280 §4.2.1.6: "no significance is attached to the case"), in the ASCII form in which a dNSName, an IA5String, is issued, so an internationalized name is in A-label form (probe P9: non-ASCII octets do not parse). It is non-empty, consists of letters, digits, hyphen, and dot, has no trailing dot, and has no wildcard character. RFC 5280 §4.2.1.6 requires the preferred name syntax, which has no underscore or asterisk, and leaves the semantics of wildcard names to the application; this profile defines them as refused. The reference stack accepts underscore, trailing dot, wildcard, and blank values (probe P9).

The component written into the identifier is the canonical value with every octet that is not `unreserved` written as `%XX` in upper-case hexadecimal (IM-2).

**MTLS-8. Enrollment resolution.** The identifier is resolved for every request through `resolve_agent_binding` (draft §17.1), without a cache: it takes the listener's realm, the workload of MTLS-6, and the agent ID that the presentation names, and returns that agent's enrollment on the workload, or `UNKNOWN` when there is none; the workload alone never names an agent. One certificate-derived workload serves one agent: a workload with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states, and shared workloads are unsupported (IM-19; section 6). A binding status that gates admission uses zero staleness (identity-mapping §7.5). The results are those of identity-mapping §8: `ACTIVE` continues; an agent ID that the workload has no record of, which `resolve_agent_binding` does not report enrolled for another workload of the realm, and a `REVOKED` binding are `INADMISSIBLE` with `INVALID_PROOF`; `COMPROMISED` is `INADMISSIBLE` with `SECURITY_HOLD`; an agent enrolled for a different workload than the authenticated one, which `resolve_agent_binding` reports with `UNKNOWN` (IM-11), is `CONTEXT_MISMATCH`; a registry that cannot answer is `DEFERRED` with `DEPENDENCY_UNAVAILABLE`. A certificate issued by a pinned CA enrolls nothing: the CA is not a trusted enrollment actor (IM-13, IM-21; identity-mapping §4.2).

**MTLS-9. The holder key is distinct from the TLS key.** The enrolled `holder_jkt` MUST differ from the RFC 7638 thumbprint of the public key in the peer leaf. When they are equal the request is refused with `INVALID_PROOF`. The presentation key must equal the enrolled `holder_jkt` (draft §6.2), so a presentation signed with the TLS key never matches an enrollment that passes this rule. `authenticate_native` reports the thumbprint of the peer leaf's public key as the attribute `cnf`, `{"jkt": <thumbprint>}`, of the principal, the confirmation attribute of the neutral native-state model of the adapter cases; it compares nothing. The validator compares that attribute with the `holder_jkt` of the binding that `resolve_agent_binding` selected and refuses equality with `INVALID_PROOF` before the presentation signature is checked. A certificate that carries or certifies the holder key does not enroll it (IM-21). The two keys have independent lifecycles: renewing or replacing the certificate never rotates the holder key, and rotating the holder key (IM-25) never needs a new certificate. The two keys SHOULD be held by different components; draft §6.4 puts the holder key in a protected key store or workload signing service.

### B. Certificate status

**MTLS-10. Mechanism and source.** Status is established by certificate revocation lists (RFC 5280 §5) and by nothing else. The location of each list is part of the pinned CA entry (draft §4.2: revocation mechanisms are trusted configuration). The CRL distribution points and authority information access extensions of a certificate are never followed. OCSP is unsupported in wire version 0.1: no OCSP request is made, and no OCSP response, fetched or stapled, is evidence of status (section 6).

**MTLS-11. Parsing.** A list is a DER-encoded X.509 v2 CRL. An armored (PEM) list is a failure (probe P1).

**MTLS-12. Acceptance as a snapshot.** A fetched list becomes the snapshot of its pinned CA only if every condition below holds. Otherwise it is discarded and the held snapshot, if any, stays unchanged.

- (a) Its signature verifies with the pinned CA certificate. Parsing alone verifies nothing (probe P2), and the signature check compares neither names nor the validity of the CA certificate (probe P5).
- (b) Its issuer name equals the subject name of the pinned CA certificate byte for byte (RFC 5280 §6.3.3 (b)(1): the CRL issuer matches the certificate issuer), and its authority key identifier, when both are present, equals the subject key identifier of that certificate.
- (c) Its thisUpdate is not later than the evaluation instant plus the baseline clock skew, and its nextUpdate is present and later than the evaluation instant (RFC 5280 §5.1.2.5 and §6.3.3 (a)(1)). The reference stack checks neither (probe P3).
- (d) No extension of the list and no extension of any entry is marked critical. RFC 5280 §5.2 and §5.3 forbid using a list with a critical extension the application cannot process, and this profile processes none. Delta lists (critical delta CRL indicator, §5.2.4), scoped or partitioned lists (critical issuing distribution point, §5.2.5), and indirect lists are therefore refused. The reference stack parses all of them as ordinary lists (probe P4). A CA that publishes such lists also publishes a complete one.
- (e) No entry carries the reason code removeFromCRL (8), which may appear only in delta lists (RFC 5280 §5.3.1).
- (f) Its CRL number is present and greater than that of the held snapshot of the same CA (RFC 5280 §5.2.3: a monotonically increasing sequence number), so that an older list never replaces a newer one.
- (g) Its size is within the configured limit.

**MTLS-13. Revocation test.** The peer leaf is revoked when its serial number, compared as an integer, is listed in the snapshot of its pinned issuer, whatever the reason code, certificateHold included (RFC 5280 §5.3.1: every reason code but removeFromCRL indicates that the certificate is to be considered revoked). A revoked leaf is a native authentication failure (a native denial with the public reason `CREDENTIAL_REJECTED`) and never a change to an enrollment record (IM-22).

**MTLS-14. Status time and bound.** The status time of an evaluation is `u`, the `thisUpdate` of the snapshot it used (freshness §4.1: for a list, the publication time of the list consulted). It is never the time of the fetch or of the evaluation (IM-10; freshness §7). The status information the adapter relies on is at most `S` seconds old: the evaluation instant minus `u` is not above `S`, and an age equal to `S` passes (freshness §3.1, rule 4). `S` is at least `P + R`, where `P` is the longest interval between two list publications that the CA commits to, and `R` is the longest time between a publication and its adoption by the adapter (freshness §4.2: for a list, the publication interval plus any cache time). The reference configuration, an illustrative policy choice and not a recommended threshold, is `P` = 300 s, `R` = 60 s, `S` = 360 s. A contract rule whose status limit is below `S` cannot be met by this source, and the result is `UNSUPPORTED_REQUIREMENT` with `DEFERRED` (freshness §4.2, convention 2; draft §17.2).

**MTLS-15. No status, no admission.** When no snapshot exists, when the held snapshot is older than `S`, or when a refresh failed and the held snapshot has aged past `S`, status cannot be established and the result is `DEFERRED` with `DEPENDENCY_UNAVAILABLE` (draft §18; freshness §5). A held snapshot is never used past `S`, and a failed refresh never extends it. An unestablished status is never `ADMISSIBLE` (draft §5, invariant 5) and is not a failure of the agent.

### C. Renewal

**MTLS-16. Renewal maps by identity.** A renewed or reissued certificate is the same workload if and only if its identifier (MTLS-6) is the same: the same `ca-id`, the same `san-kind`, and the same subject alternative name value, byte for byte. It then resolves to the same enrollment record under a new serial number (IM-22). A certificate whose identifier has no enrollment record of the agent that the presentation names resolves to `UNKNOWN` and inherits nothing from any other certificate: not from one with the same subject text or common name, not from one with the same public key, not from one issued to the same subject alternative name by another authority (a different `ca-id`, so another identity with its own enrollment, IM-22). Renewal never creates, changes, revokes, or rotates an enrollment record and never changes the holder key (MTLS-9). The old and the new certificate can be valid at once; each is evaluated on its own (MTLS-13). Enrolling the identifier of a new certificate is an administrative act (IM-12; identity-mapping §4.2). Suspected compromise of the TLS key is answered by revoking the certificate at the CA (MTLS-13) and does not mark the holder key compromised; only an enrollment authority marks that key (IM-27).

### D. Connection reuse and resumption

**MTLS-17. No resumption.** A listener of this profile MUST NOT resume TLS sessions: it issues no session ticket, accepts none, and keeps no session cache, so that every connection runs a full handshake with certificate verification. A resumed handshake carries no client certificate message (RFC 8446 §2.2 and §4.4). A connection that the TLS stack reports as resumed is refused. The reference stack does not call the certificate verification callback on a resumed connection, re-checks only notAfter and the stored chain against the current roots, never consults a revocation list, and does not reject a resumed connection whose leaf is revoked (probe P10). A ticket may be valid for up to seven days (RFC 8446 §4.6.1). The "fully authenticated connection" of MTLS-19 is a connection that ran a full handshake.

**MTLS-18. Identity per request.** For every request the adapter re-reads the peer certificate and chain from the TLS state of the connection that carried that request and applies MTLS-3 to MTLS-9 to them. Nothing about identity is carried over from an earlier request, an earlier connection, a header, or a cookie. The only state kept for a connection is its status record (MTLS-19). The checks MAY also run at connection setup, which refuses the connection early; the run for every request is required. A multiplexed connection carries one peer identity for all its streams. In the reference stack every request on a connection, HTTP/1.1 or HTTP/2, sees the same TLS state (probe P11).

**MTLS-19. Connection status record.** On a direct listener the peer leaf is tested against the snapshot (MTLS-13) once per connection, before the first request of the connection is passed on. A successful evaluation creates the status record of the connection, which holds the status time `u` of the snapshot used. The record is never refreshed: no later snapshot extends it and no later evaluation on that connection replaces it. At every request the age, the evaluation instant minus `u`, is compared with `S`, and an age equal to `S` passes. When the age is above `S` the request is not evaluated further and the adapter requires a new fully authenticated connection: the result is `DEFERRED` with `DEPENDENCY_UNAVAILABLE` and the connection is closed after the response (MTLS-20). This is the outage row of freshness §5 for a cached answer outside its limit that the source cannot refresh. An evaluation that fails creates no record: a request that finds no usable snapshot is `DEFERRED` (MTLS-15) without closing the connection, and the next request evaluates again.

**MTLS-20. Closing a connection.** In HTTP/1.1 the response carries `Connection: close` and the server closes the connection after it (RFC 9112 §9.6). HTTP/2 does not use the Connection header, and a message that carries one is malformed (RFC 9113 §8.2.2); the server starts a graceful shutdown with GOAWAY (RFC 9113 §6.8), after which the client opens a new connection. In the reference stack a handler that sets `Connection: close` ends the connection in both versions and the header is not sent in HTTP/2 (probe P11).

**MTLS-21. Re-checks on an open connection.** Every request on a connection also re-checks that the peer leaf and its issuer are inside their validity periods (MTLS-5), that the issuer is still a member of the current pinned CA set (MTLS-2), so that removing an authority ends service to the connections it issued at their next request, and the enrollment (MTLS-8). A failure is a native denial or the result named in MTLS-8, and the connection SHOULD be closed after the response.

### E. Trusted terminator

**MTLS-22. Two listener roles.** A listener has one role, direct or terminated. A listener that accepts a forwarded identity never also serves agents that present their own certificate.

**MTLS-23. A terminated listener admits only terminators.** On a terminated listener the peer certificate passes MTLS-3 to MTLS-7 and MTLS-19 like any peer leaf, and its identifier (MTLS-6) is in the terminator allowlist, a configured set of identifiers. A terminator is not an agent: MTLS-8 and MTLS-9 do not apply to it and it has no enrollment record. A peer that is not allowlisted is refused at connection setup and in any case before any header of its requests is read. A request that bypasses the terminator, with or without a valid agent certificate, therefore fails. The allowlist changes only through the gateway's administrative controls (draft §4.2).

**MTLS-24. The forwarded header.** On a terminated listener, for a request from an allowlisted terminator, the only forwarded input is the `x-forwarded-client-cert` header in the text format of the Envoy documentation: comma-separated elements; semicolon-separated key-value pairs; keys case-insensitive and values case-sensitive; a value that contains `,`, `;`, or `=` double-quoted, with `\"` for a double quote. The adapter requires exactly one element, exactly one `Cert` pair, and a `Cert` value that, percent-decoded, is exactly one PEM certificate and nothing else. A missing header is a native denial with the public reason `NO_CREDENTIAL`; any other failure is a native denial with `CREDENTIAL_REJECTED`. The `Cert` certificate is the peer leaf for MTLS-3 to MTLS-9 and is verified against the pinned set alone: it brings no intermediates, so MTLS-3 needs a pinned issuer. Every other key of the element (`By`, `Hash`, `Subject`, `URI`, `DNS`, `Issuer`, `Chain`) is ignored, never compared and never used to select the identity; where one disagrees with `Cert`, `Cert` decides. The JSON form of the header is not accepted in wire version 0.1.

**MTLS-25. Status of a forwarded leaf.** The status of the forwarded leaf is tested for every request against the snapshot (MTLS-13) with the bound `S` of MTLS-14. It has no connection record, because the connection belongs to the terminator and carries many end clients. A forwarded leaf whose status cannot be established, or whose snapshot is older than `S`, is `DEFERRED` with `DEPENDENCY_UNAVAILABLE` and the connection is not closed, because a new connection cannot establish the status. The terminator's own certificate stays under MTLS-19. The identity claim for a forwarded leaf has a status time `u` and no source observation time, because the header carries no time of the end client's handshake (open item O3).

**MTLS-26. No other forwarded identity.** On every listener, no HTTP header other than the `x-forwarded-client-cert` header on a terminated listener contributes to identity. The following are ignored: that header on a direct listener, that header from a peer that is not allowlisted, the `ssl-client-*` family, any other header that carries data from a client certificate (for example one filled from the nginx variables `$ssl_client_s_dn`, `$ssl_client_escaped_cert`, or `$ssl_client_verify`, which the nginx `ngx_http_ssl_module` documents), and every header on the deployment's configured forwarded-identity list. Ignored means not parsed, not compared, and not logged as an identity. The adapter removes these headers from the request before `authorize_native` and execution, so that an ignored header never reaches the native executor as if it were authenticated. Security telemetry MAY count them without attributing an identity (draft §12.2).

**MTLS-27. Terminator obligations.** The adapter cannot observe the configuration of the terminator. A deployment that claims a terminated listener states and maintains, for the terminator:

- (a) it requires a valid client certificate from the pinned CA set on the downstream connection (Envoy: `require_client_certificate`, "Envoy will reject connections without a valid client certificate");
- (b) it resets the header with the client certificate of that connection (Envoy: `forward_client_cert_details` set to `SANITIZE_SET`, "When the client connection is mTLS, reset the XFCC header with the client certificate information and send it to the next hop"), and never `FORWARD_ONLY`, `APPEND_FORWARD`, or `ALWAYS_FORWARD_ONLY`, which pass on a header that the client sent;
- (c) the element carries `Cert` (Envoy: `set_current_client_cert_details` with `cert` true);
- (d) its connection to the gateway is mutual TLS 1.3 with its own certificate, under MTLS-1 and MTLS-17;
- (e) the terminated listener is reachable only by the terminator. MTLS-23 is the control, and network policy is defence in depth.

The Envoy behaviours are as the upstream documentation states them and were not probed (open items O1 and O2). RFC 8705 §6.5 leaves the secure transfer of certificate metadata from an intermediary to the application server out of scope, which is why this profile defines it.

### F. Tokens, claims, and results

**MTLS-28. Not a token binding.** The certificate authenticates a workload and nothing more. This profile does not read, validate, or require an access token bound to the certificate (RFC 8705 §3: the resource server checks that the certificate matches the token), and it does not implement OAuth mutual-TLS client authentication (RFC 8705 §2). A bearer token on a request is outside this adapter. Whatever confirmation claim it carries does not enroll or bind the holder key (IM-21), and the certificate does not satisfy a rule that requires a token binding.

**MTLS-29. Results.** The adapter's checks run in this order for each request: connection setup (MTLS-1 to MTLS-7 when evaluated early); identity from the TLS state (MTLS-18 to MTLS-26); status (MTLS-13 to MTLS-15, MTLS-19, MTLS-25); then enrollment (MTLS-8, MTLS-9). Native authentication, status included, comes first (draft §17.1). Each result below uses the codes of draft §13.4 and the decisions of draft §11.4.

| Condition | Where | Decision | Code | Transport result |
|---|---|---|---|---|
| No client certificate, or a certificate refused by MTLS-1 to MTLS-7, found at connection setup | TLS setup | none: no authenticated evaluation is accepted (draft §12.2) | none | Handshake refused; no HTTP response, no receipt, no `OutcomeReport` (draft §14.5) |
| The same failures found at request time; leaf revoked (MTLS-13); leaf or issuer expired on an open connection (MTLS-5) | `authenticate_native` | native denial | `INVALID_PROOF` | 401, public reason `CREDENTIAL_REJECTED`; connection SHOULD close after the response |
| A connection that the TLS stack reports as resumed, where the stack did not refuse it at setup (MTLS-17) | `authenticate_native` | native denial | `INVALID_PROOF` | 401, public reason `CREDENTIAL_REJECTED`; connection SHOULD close after the response |
| Terminated listener: header missing | `authenticate_native` | native denial | `INVALID_PROOF` | 401, public reason `NO_CREDENTIAL` |
| Terminated listener: header malformed, several elements, `Cert` refused | `authenticate_native` | native denial | `INVALID_PROOF` | 401, public reason `CREDENTIAL_REJECTED` |
| Terminated listener: peer not allowlisted | TLS setup, or before any header is read | refused | none, or `INVALID_PROOF` | Handshake refused, or 401 without reading the header |
| Connection status record older than `S` (MTLS-19) | `authenticate_native` | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503; connection closed after the response (MTLS-20); retry guidance: open a new TLS connection and retry |
| No usable snapshot (MTLS-15); snapshot of a forwarded leaf older than `S` (MTLS-25) | `authenticate_native` | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503; connection kept; no receipt |
| Contract rule with a status limit below `S` (MTLS-14) | validator | `DEFERRED` | `UNSUPPORTED_REQUIREMENT` | 422 |
| The presented agent has no record on the workload and is not reported enrolled for another workload of the realm (IM-11), or its binding is `REVOKED` | `resolve_agent_binding` | `INADMISSIBLE` | `INVALID_PROOF` | 401 |
| `COMPROMISED` binding | `resolve_agent_binding` | `INADMISSIBLE` | `SECURITY_HOLD` | 403 |
| Agent enrolled for another workload than the authenticated one, which `resolve_agent_binding` reports with `UNKNOWN` (IM-11) | validator | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| A workload with more than one enrollment in force, a configuration error (MTLS-8) | `resolve_agent_binding` | As identity-mapping §5 states (IM-19) | As identity-mapping §5 states (IM-19) | The status of that code (draft §13.4) |
| Enrollment registry cannot answer | `resolve_agent_binding` | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503 |
| `holder_jkt` equals the thumbprint of the TLS key (MTLS-9) | validator | `INADMISSIBLE` | `INVALID_PROOF` | 401 |
| Identifier of the actual request differs from the identifier bound at contract issuance (MTLS-31) | validator, `operation_digest` | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| Presented `principal_id` differs from the identifier of MTLS-6 (MTLS-31) | validator, `native-principal-binding-v1` | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| A forwarded-identity header anywhere it is not accepted (MTLS-26) | adapter | none | none | Ignored and removed; the request continues on the identity of the TLS peer |

A `DEFERRED` result at the native authentication stage is a transport result without a receipt, because no authenticated evaluation was accepted; whether it should carry a `DEFERRED` receipt is open (open item O8). The public error never says which of revoked, expired, untrusted, or malformed applied (draft §13.4).

**MTLS-30. Native claim.** The native path this profile claims for `read_native_claim` is `/attributes/environment/workload_id`, whose value is the identifier of MTLS-6; the adapter answers it from the TLS state of the request and from no other source. Other approved paths are read from the sources the deployment installs for them under their own profiles (draft §17.2; section 6), and a path with no installed source returns `UNSUPPORTED_REQUIREMENT`. On a direct listener the source observation time is the instant of the first evaluation of the connection and the status time is `u` of its status record. On a terminated listener the observation time is absent and the status time is `u` of the snapshot used for the request (MTLS-25), so a rule that bounds the observation age of the claim is `DEFERRED` there.

**MTLS-31. Principal binding.** The identifier at contract issuance is bound by the contract's `operation_digest` and compared by the validator with the identifier of the actual request (draft §9.1, §11.3 step 5): a different identifier at evaluation is `CONTEXT_MISMATCH`. The baseline check `native-principal-binding-v1`, which the validator evaluates (draft §17.5), compares the principal the presentation claims, `/attributes/environment/principal_id`, with the identifier of MTLS-6 and returns `FAIL` with `CONTEXT_MISMATCH` when they differ (example I07, "the same authenticated principal must remain applicable"). Both comparisons are of identifiers and not of certificates or connections: a certificate renewed between issuance and evaluation keeps the identifier and passes, and a different certificate with another identifier fails. The adapter implements neither comparison.

## 1. Claim scope

The gateway evaluates PACT in-gateway (draft §4.4), claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over `header` transport, and is a partial role implementation (draft §22.1) because it claims neither Reputation nor Learning. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1; the roles it does not claim are supplied by connected services of the deployment. One adapter entry covers both listener roles: the connection between a terminator and the gateway uses the same TLS version.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced` |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` (`GatewayMetadata.adapters`, draft Appendix A) |
|---|---|---|
| `mtls` | `1.3` | `pact-mtls-1` |

## 2. Protected routes and actions

One reference route is claimed, the read route of the scenario of example I07. The route pattern is a fictional name for an internal reconciliation API; a deployment that claims other routes lists them in its own profile. The PACT endpoints of draft §13.2 that require native authentication are on the same listener and are covered in section 5 (B8).

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/api/v1/reconciliation/records/{record_id}` | `GET` | `reconciliation.record.read` | `reconciliation-record:{record_id}`, from the path parameter. The business unit of the record is checked by native authorization (`authorize_native`) and not by this profile |

## 3. Enforcement points

The five required functions run in request order inside the gateway, and the other four adapter functions of draft §17.1 are listed as supporting rows. The rules of the section "Rules" say what each function does for this mechanism.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | The TLS listener of the gateway and the adapter's evaluation of each request (MTLS-1 to MTLS-7, MTLS-13 to MTLS-26) | IAM owner and adapter owner | Produces the principal and workload, both the identifier of MTLS-6, with mechanism `mtls` and the realm of the listener; otherwise a native denial or `DEPENDENCY_UNAVAILABLE` (MTLS-29) |
| 2 | `map_operation` | Gateway mapping stage, mapping revision `pact-mtls-1` | Adapter owner | The revision fixes the identity inputs of this document; the request mapping of R1 (path, query, consequential headers) is installed by the deployment and listed under C07 |
| 3 | PACT evaluation | In-gateway validator in the same request path | Gateway implementer | Runs after mapping and before native authorization; the freshness checks of section 8 apply |
| 4 | `authorize_native` | The reconciliation API's existing record permissions for the authenticated workload | Resource owner | A native denial is final (draft §2.3); runs with the original principal (draft §17.5) |
| 5 | Execution | The reconciliation read, under the native restrictions of the authenticated workload | Resource owner | Reached only after steps 1 to 4 pass; forwarded-identity headers have been removed (MTLS-26) |
| support | `resolve_agent_binding` | Enrollment registry lookup for each request (MTLS-8) | Gateway implementer | Supplies the enrolled agent, operator, holder key, and status |
| support | `read_native_claim` | The adapter for `/attributes/environment/workload_id` (MTLS-30); other approved paths from the sources the deployment installs | Adapter owner | Returns the identifier with its observation and status times; other approved paths come from the sources the deployment installs (MTLS-30) |
| support | `check_context` | The checks the deployment installs; none of this profile | Gateway implementer | No check of this profile runs in `check_context`: `native-principal-binding-v1` is evaluated by the validator (MTLS-31). Checks the deployment installs, such as the purpose and operation check of example I07, run here under their own profiles; an id with no installed check is `UNKNOWN` with `UNSUPPORTED_REQUIREMENT` |
| support | `record_outcome` | Gateway outcome writer, after execution | Gateway implementer | Outcomes map as in draft §14.5; a failure before authentication produces no `OutcomeReport` |

## 4. Native dependencies

Eleven of the sixteen handoff components are used, and each of the other five carries the reason it does not apply. The status column is honest about the state of this profile: the rules are written and the adapter that implements them is later work.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and request path | Gateway implementer | To be supplied |
| C02 | Native authentication and claim adapters | baseline | TLS 1.3 listener with client authentication, the mTLS adapter of these rules, the snapshot store | IAM owner and adapter owner | Listener exists in the deployment; the adapter and its snapshot store are `go/adapters/mtls` |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry (a registry contract and an in-memory backend exist in `go/adapter/enroll`), administrator-run enrollment, the pinned CA set | IAM and security owner | Registry contract exists; production store to be supplied |
| C04 | Native delegation and task authority | delegated or task execution | none | none | Not used: the workload acts as itself, no delegation |
| C05 | Evidence and authoritative status sources | baseline | The private CA's list publication, the enrollment registry, the gateway configuration | PKI owner and adapter owner | Publication exists in the deployment (example I07 assumes a private PKI); snapshot adoption (MTLS-12) is `Adopt` of `go/adapters/mtls`, the fetch is to be supplied |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the read route needs no external approval |
| C07 | Purpose and exact operation mapper | baseline | Mapper for R1 | Adapter and application owner | To be supplied; request-binding rules are outside this profile |
| C08 | Native resource executor and authorization | the actual resource operation | Reconciliation API and its record permissions | Resource owner | Exists in the scenario |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store | Gateway and platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Gateway outcome writer and the API's audit log | Resource owner | To be supplied |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | To be supplied; registry only, no adaptation lifecycle |
| C13 | Revocation and security holds | baseline | List snapshots, the connection status record and closing (MTLS-19), enrollment status, the hold store | Security and IAM owner | Snapshots, connection record and closing exist in `go/adapters/mtls`; the hold store is to be supplied |
| C14 | Protected evidence and audit storage | baseline | Access-controlled audit store, including security telemetry about ignored headers | Security and data owner | To be supplied |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: read route, no transactions or budgets |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no runtime attestation or data-use guarantee is claimed |

## 5. Alternative and bypass paths

Eight other ways to reach the reconciliation data or the identity input are listed: five `closed`, two `equivalently-enforced`, and one `out-of-claim`. The cases named as evidence are in section 10.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Direct request to the reconciliation API, bypassing the gateway | `closed` | The API's listener admits only the gateway's workload certificate, and network policy admits only the gateway as a source. No fixture: a deployment control. The adapter-level bypass is `MTLS-06` and `COMMON-02.direct` |
| B2 | Connection to a terminated listener without passing through the terminator | `closed` | MTLS-23: the listener requires the terminator's certificate and refuses any other peer, with or without a valid agent certificate; cases `MTLS-02`, `MTLS-06` |
| B3 | Forwarded-identity headers: the forwarded-certificate header on a direct listener or from a peer that is not allowlisted, the `ssl-client-*` family, and any other header that names a client | `closed` | MTLS-24 and MTLS-26: only `Cert` of the forwarded-certificate header of an allowlisted terminator is read, and every other such header is ignored and removed; cases `MTLS-01`, `MTLS-02`, `MTLS-03`, `MTLS-05`, `MTLS-07` |
| B4 | Cleartext HTTP, or a TLS version below 1.3, on a claimed route | `closed` | MTLS-1: no such listener exists; case `MTLS-08` |
| B5 | A resumed TLS session | `closed` | MTLS-17: no tickets are issued or accepted and a resumed connection is refused; case `MTLS-17` |
| B6 | A connection reused for many requests, or multiplexed, including after the status bound | `equivalently-enforced` | Every request passes the enforcement points of section 3, with the identity re-read for the request (MTLS-18) and the connection status record (MTLS-19); cases `MTLS-15`, `MTLS-16` |
| B7 | Other listeners on the gateway host, such as health, metrics, or administration | `out-of-claim` | Not claimed; excluded in section 6 |
| B8 | The PACT endpoints of draft §13.2 on the same listener that require native authentication, such as `POST /pact/v0.1/requirements` | `equivalently-enforced` | Served through the same listener and `authenticate_native`, so MTLS-1 to MTLS-31 apply to them; case `MTLS-23` |

## 6. Unsupported forms

The first three rows are seeded from the I07 row of the handoff "Deliberate design choices" table, which reads: "Native certificate plus separate enrolled PACT key" is the choice and "OAuth certificate-bound tokens, SPIFFE/SPIRE, or insecure peer-header forwarding" is the wider claim not established. The other rows come from the sections that follow the rules.

| Unsupported form | Seed (handoff source row) | Why it is not established |
|---|---|---|
| OAuth certificate-bound access tokens (RFC 8705 §3) and OAuth mutual-TLS client authentication (RFC 8705 §2) | I07: "OAuth certificate-bound tokens" | The certificate authenticates the workload and nothing more (MTLS-28). No token is read, and none is checked against the certificate |
| SPIFFE and SPIRE | I07: "SPIFFE/SPIRE" | No SVID validation (SPIFFE X509-SVID §5.2 requires cA false, the scheme `spiffe`, a non-root path, and exactly one URI name), no trust-domain bundles (§6), and no Workload API. A certificate that carries a `spiffe://` URI is treated as an opaque URI name of its pinned CA under MTLS-7 |
| Insecure peer-header forwarding, and every terminator form other than the Envoy forwarded-certificate header in text format | I07: "insecure peer-header forwarding" | Only MTLS-24 is accepted. The `ssl-client-*` headers of nginx-based proxies are the alternative considered and are not specified in wire version 0.1; they are ignored (MTLS-26) |
| OCSP, fetched or stapled; delta, scoped, and indirect revocation lists; discovery of lists through certificate extensions | Section 8, F1 | Status is complete lists from configured locations (MTLS-10, MTLS-12) |
| TLS versions below 1.3, and every resumed session | Section 5, B4 and B5 | MTLS-1 and MTLS-17 |
| Telling agents apart when they share one certificate or workload identifier | Section 7, MTLS-8 | One certificate-derived workload per agent, the default of identity-mapping §5 (IM-19); a workload with more than one enrollment in force is a configuration error (MTLS-8) |
| Identity from subject text, from the common name, or from other name kinds (email address, IP address, other names, directory names), and wildcard names | Section 7 | MTLS-6 and MTLS-7 |
| Re-authentication or status refresh inside an open connection | Section 8, F1 | The status record of a connection is never refreshed (MTLS-19) |
| Any field of the I07 profile other than the workload identifier: the business-unit mapping, the runtime isolation attestation, the purpose and operation relation | Section 3 | Those sources are supplied by the deployment outside this profile; only `/attributes/environment/workload_id` is claimed (MTLS-30) |
| Any route other than R1 | Section 2 | Not listed in section 2, so not claimed |
| Other listeners on the gateway host | Section 5, B7 | Excluded by their `out-of-claim` disposition |

## 7. Identity mapping

Each agent has a dedicated workload certificate under a pinned CA, and the workload identifier is enrolled by an administrator and bound to the holder key in the enrollment registry. All other rules are those of [`identity-mapping.md`](../identity-mapping.md).

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | Workload only: `mtls:{ca-id}:{san-kind}:{workload-id}` as in identity-mapping §3.3, where `san-kind` is `uri` or `dns` as the pinned CA configures it and `workload-id` is written under MTLS-7. The principal equals the workload (identity-mapping §3.4). No `x-` namespace |
| Trusted enrollment actors | The native administrative workflow of the realm and, where configured, an authorized identity-binding issuer for the `mtls` namespace (identity-mapping §4.2). The CA that issues a certificate, the terminator, and the agent are not enrollment actors (MTLS-8) |
| Shared-account handling | Not supported, the default of identity-mapping §5 (section 6). A workload with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states (MTLS-8, IM-19) |
| Certificate, token, or role-session bindings | The certificate authenticates the workload and is bound to nothing else. The holder key is bound only by the enrollment record and is distinct from the TLS key (MTLS-9). No token binding (MTLS-28) |
| Lifecycle rules (rotation, compromise, recovery) | Identity-mapping §7 for the enrollment record. Certificate renewal and revocation are native authentication events and change no record (MTLS-16, MTLS-13). The propagation bound for the record is in section 9 |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule. Stricter choices: the pinned issuer must be a pinned entry itself (MTLS-3); one subject alternative name kind per pinned CA and exactly one entry of it (MTLS-6); no URI normalization beyond IM-2 (MTLS-7); a holder key distinct from the TLS key (MTLS-9, where IM-21 only forbids accepting it implicitly); shared workloads refused (IM-19 allows supporting them only with a stated reason) |

## 8. Freshness

Three sources are listed, with `max_age` and `status_max_age` in seconds, and every outage ends in `DEFERRED`, which fails closed (draft §18). The reference configuration of MTLS-14 is used for F1: `P` = 300 s, `R` = 60 s, `S` = 360 s. These are illustrative policy choices; a deployment declares its own and recomputes the figures with `S` = `P + R`.

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Peer certificate status: the list snapshot of the issuing pinned CA, bound to the connection that presented the certificate | Cached credential snapshot (draft §17.2). Class "open connection" of freshness §4.1, with one departure: the status time is `u`, the `thisUpdate` of the list, and not the time of the decision, because a list says nothing about revocations after its publication. On a direct listener the observation time of the identity claim is the instant of the first evaluation of the connection; on a terminated listener there is none (MTLS-30) | 360 | 360 | `DEFERRED` (MTLS-15, MTLS-19) |
| F2 Enrollment registry (workload to agent and holder key binding) | Current authoritative state, read for each evaluation (MTLS-8). The observation time is the last change of the record (IM-10) and no rule limit is read against this source, so the 0 records that nothing is cached | 0 | 0 | `DEFERRED` |
| F3 Pinned CA set and terminator allowlist (gateway configuration) | Current authoritative state, read for each request (MTLS-21) | 0 | 0 | `DEFERRED`: a configuration that cannot be read or is invalid fails closed |

A contract rule over the certificate-derived claim cannot ask for less than the F1 bounds. A limit below 360 on `max_age_seconds` or `status_max_age_seconds` is unachievable for this source and is `DEFERRED` with `UNSUPPORTED_REQUIREMENT` before the claim is read (freshness §4.2, convention 2). The baseline default of 30 seconds for cached evidence-status checks (draft §18) is therefore not achievable by revocation lists with the reference configuration, and a publisher either states the larger limit or changes the mechanism, which wire version 0.1 does not offer (OCSP is unsupported).

### 8.1 Membership and status sources

F1 and F2 supply status facts about the authenticated principal, so they are listed again here. F1 is a list that its authority publishes and the adapter fetches in full; it has no live check and its values are cached snapshots. F2 is a registry lookup made for each evaluation. The integration reads no group or role fact.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 Peer certificate status: the list snapshot of the issuing pinned CA, bound to the connection that presented the certificate | `identity`, `account_state` | `false` | Not applicable: no live check, because a list is published and not queried | `none` | Not applicable: no change feed; the adapter fetches the full list at least every `R` seconds (MTLS-14) | 360 | `cached_snapshot` |
| F2 Enrollment registry (workload to agent and holder key binding) | `identity`, `account_state` | `true` | Enrollment registry lookup | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

## 9. Residual limits

The profile states the limits that remain after a successful admission. The two figures for F1 follow from the reference configuration of MTLS-14.

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Reconciliation data already returned to the agent is not recalled by a later revocation of a certificate or an enrollment; an executed operation is not undone by revoking its receipt (draft §18); no egress or data-use control is claimed (draft §17.4) | Disclosed here; no bound |
| Revocation propagation: certificate (F1) | A serial listed in a list that its authority publishes reaches a new connection, and every request on a terminated listener, within `R` of the publication, and the authority publishes at least every `P` after the decision to revoke: at most `P + R` after the decision. An open direct connection is ended no later than `S` after the publication of the list that carries the revocation, so at most `P + S` after the decision, and it serves requests on the status of an older list until then (MTLS-19) | 360 s for a new connection; 660 s for an open connection |
| Revocation propagation: enrollment (F2) | Revocation, compromise mark, and rotation take effect at the next request, in the consistency domain of the registry (identity-mapping §7.5; draft §18) | 0 s within that domain; a registry with eventual consistency declares its replication delay |
| Revocation propagation: pinned CA set (F3) | Withdrawing an authority or a terminator takes effect at the next request after the configuration is reloaded (MTLS-21) | The reload time of the deployment, which it declares |
| Name reuse (IM-6) | The identifier names a subject alternative name that a CA can issue to another subject after the first workload is retired, and the enrollment then applies to the new holder of the name. A TLS-only impostor still fails the holder-key proof (MTLS-9; draft §6.2). An administrator revokes the enrollment of a retired workload before its name is reissued | Residual; operational rule |
| Terminated listener | The gateway verifies the certificate and its status from `Cert` but cannot verify that the end client proved possession of its key to the terminator, and cannot see the age of that connection. It relies on the obligations of MTLS-27. A terminator that passes on a header the client supplied defeats the identity, and the gateway cannot detect it when the header has one element | Disclosed; no bound |
| TLS key compromise | Between the theft of a TLS key and the propagation of its revocation, a thief can authenticate as the workload natively but cannot sign a PACT presentation, because the holder key is distinct (MTLS-9) | The revocation propagation above |
| Revocation list transport | An attacker on the path to the list location can withhold lists or replay older ones. Lists are signed by the pinned CA (MTLS-12). Withholding ends in `DEFERRED` once the snapshot is older than `S` (MTLS-15), and a replayed older list is not adopted over a newer one (MTLS-12 (f)) | The status information used is at most `S` old |
| Clock | A CA clock behind the adapter's clock only makes lists look older and fails closed. A CA clock ahead by more than the skew makes the list unusable (MTLS-12 (c)) | Skew of 5 s on notBefore and thisUpdate, none on expiry (draft §7.5) |

## 10. Fixture index

Twenty-four negative cases cover the route, every `closed` and `equivalently-enforced` path, the freshness rows, and the configuration-error rule of MTLS-8; the expected results use the wording of draft §22.2 where a case applies. The ids are those of the earlier revision without the letter `N`. Nineteen of them are adapter cases of this profile and live in `spec/v1.0/fixtures/adapters/mtls/`, each file named after its case id in lower case, such as `mtls-11.valid.json`, with the manifest id `adapters/mtls/mtls-11.valid`; `profile.json` lists the case files in `fixtures`. The [cases README](../../fixtures/adapters/mtls/README.md) defines their native state, `mtls/1`: the authorities, pinned CA set, peer certificates and revocation lists of a case, which the harness mints with keys derived from seeds, so that no key is committed and a case can state a key thumbprint. The cases do not use `request.tls_peer`, whose synthetic certificate carries no signature that an X.509 verifier could check. Connection behaviour that a single call of an adapter function cannot show (handshakes, resumption, connection reuse and closing, list acceptance) is covered by Go tests of the adapter package; `MTLS-21` is a deployment control and `MTLS-23` a gateway property.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `MTLS-01` | Direct listener, valid certificate of workload A, header naming enrolled workload B in a forwarded-certificate header. Two sub-cases: a presentation by the agent of B, and one by the agent of A | The header has no effect and is removed before authorization: the identity is A's. A presentation by the agent of B is then a context mismatch, and one by the agent of A is evaluated as A | `adapters/mtls/mtls-01.direct-listener-header-ignored`; the binding of B's agent on A is `mtls-09.binding`; the removal before `authorize_native` is a Go test of the adapter package | R1, B3 |
| `MTLS-02` | Terminated listener, peer is an agent with a valid pinned-CA certificate that is not allowlisted, sending a forwarded-certificate header that names workload B | Refused; the header is never read | `adapters/mtls/mtls-02.not-allowlisted` (native denial, `CREDENTIAL_REJECTED`); the refusal at connection setup is a Go test | R1, B2, B3 |
| `MTLS-03` | Terminated listener, allowlisted terminator, header absent; two elements; two `Cert` pairs; `Cert` with two certificates; `Cert` that does not decode | Native denial, 401: `NO_CREDENTIAL` when absent, `CREDENTIAL_REJECTED` otherwise | `adapters/mtls/mtls-03.absent`, `mtls-03.two-elements`, `mtls-03.two-cert-pairs`, `mtls-03.two-certificates`, `mtls-03.undecodable`, with the control `mtls-03.forwarded` | R1, B3 |
| `MTLS-04` | Terminated listener, allowlisted terminator, `Cert` from an unpinned CA, from an unpinned intermediate under a pinned root, without a client-auth purpose, or expired | Native denial, 401, `CREDENTIAL_REJECTED` | `adapters/mtls/mtls-04.unpinned-ca`, `mtls-04.unpinned-intermediate`, `mtls-04.no-client-auth`, `mtls-04.expired` | R1 |
| `MTLS-05` | Forwarded element whose `URI`, `DNS`, `Subject`, and `Hash` name enrolled workload B while `Cert` names an unenrolled workload A | Evaluated as A: authenticated as A, and the agent ID presented has no binding on A, so `INADMISSIBLE` with `INVALID_PROOF`, or `CONTEXT_MISMATCH` when that agent is enrolled for B (identity-mapping IM-11) | `adapters/mtls/mtls-05.authenticate`, `adapters/mtls/mtls-05.binding` | R1, B3 |
| `MTLS-06` | Connection to the terminated listener that bypasses the terminator: no certificate, and a valid agent certificate | Refused at connection setup | Go test of the adapter package: handshakes with the terminated listener; at adapter level `mtls-02.not-allowlisted` and `_common/common-02.direct` | B2 |
| `MTLS-07` | `ssl-client-verify`, `ssl-client-subject-dn`, `ssl-client-cert`, and other client-certificate headers on a direct and on a terminated listener | Ignored; absent from the request that reaches `authorize_native` | `adapters/mtls/mtls-07.direct`, `adapters/mtls/mtls-07.terminated`; the removal before `authorize_native` is a Go test | R1, B3 |
| `MTLS-08` | Cleartext HTTP to the claimed route, and a TLS 1.2 client | Refused; no response from the application | `adapters/mtls/mtls-08.tls12`, `adapters/mtls/mtls-08.cleartext`; the refusal of a TLS 1.2 handshake is a Go test | B4 |
| `MTLS-09` | Valid certificate of workload A, presentation by an agent enrolled for workload B with its own correct key | Context mismatch (draft §22.2: correct signature but wrong principal): `resolve_agent_binding` gives `UNKNOWN` for B's agent on A and reports it enrolled for another workload | `adapters/mtls/mtls-09.binding` | R1 |
| `MTLS-10` | Presentation signed with the TLS key of the certificate | `authenticate_native` reports the TLS key's thumbprint as `cnf.jkt` and never as a holder key; `resolve_agent_binding` reports the enrolled key (`IDENT-07`); the validator refuses the presentation with `INVALID_PROOF` (draft §22.2, old holder key) | `adapters/mtls/mtls-10.tls-key-reported`; `_common/ident-07.credential-key`; the validator refusal is not an adapter function; evaluation case `admission/old-holder-key` (spec map `R03`) | R1 |
| `MTLS-11` | Certificate policy violations, one case each: not issued by a pinned CA; issued by an unpinned intermediate; no extended key usage extension; server-auth purpose only; any-purpose only; cA asserted; key usage without digital signature; no subject alternative name; two names of the kind; wildcard, blank, trailing-dot, or underscore DNS name; relative or empty URI; expired; not yet valid | Not admitted: refused at setup or native denial, `CREDENTIAL_REJECTED` | `adapters/mtls/mtls-11.*`, one case per violation, with the controls `mtls-11.valid`, `mtls-11.listener-realm`, `mtls-11.dns-lowercased`, `mtls-11.uri-not-normalized` and `mtls-11.not-before-within-skew`; the same checks at connection setup are a Go test | R1 |
| `MTLS-12` | Subject text or common name equal to an enrolled workload name while the subject alternative name names an unenrolled workload | Authenticated as the workload of the subject alternative name; the subject is never used. That workload has no binding: `INADMISSIBLE` with `INVALID_PROOF`, or `CONTEXT_MISMATCH` for an agent enrolled for the workload the subject names (identity-mapping IM-11) | `adapters/mtls/mtls-12.authenticate`, `adapters/mtls/mtls-12.binding` | R1 |
| `MTLS-13` | Leaf listed in the snapshot with reason unspecified, keyCompromise, and certificateHold, with an OCSP address in the certificate | Native denial, 401; no OCSP request is made | `adapters/mtls/mtls-13.unspecified`, `mtls-13.key-compromise`, `mtls-13.certificate-hold`; the adapter has no network client | R1, F1 |
| `MTLS-14` | Unusable lists, one case each: bad signature; list of another CA; same key with another issuer name; expired nextUpdate; thisUpdate ahead of the clock; critical delta, scoped, or unknown extension; entry with reason 8; lower CRL number; oversize. Also no snapshot, and a snapshot older than `S` | The list is not adopted; with no usable snapshot `DEFERRED` with `DEPENDENCY_UNAVAILABLE`, never `ADMISSIBLE` (draft §18, §22.2) | `adapters/mtls/mtls-14.no-snapshot`, `mtls-14.stale-snapshot`, `mtls-14.forwarded-stale`, with the control `mtls-14.at-bound`; the acceptance conditions (a) to (g) of MTLS-12 are a Go test | F1 |
| `MTLS-15` | Connection evaluated at a snapshot with status time `u`; a request at `u` + `S`, and one at `u` + `S` + 1 s, over HTTP/1.1 and HTTP/2 | The first is served; the second is `DEFERRED` with `DEPENDENCY_UNAVAILABLE` and the connection closes; a new connection with a fresh snapshot is served | Go test of the adapter package over HTTP/1.1 and HTTP/2 | F1, B6 |
| `MTLS-16` | Certificate revoked after the connection opened | Served until the age exceeds `S`, then `DEFERRED` and closed; a new connection is refused with 401 | Go test of the adapter package | F1, B6 |
| `MTLS-17` | A client offering a session ticket, and a connection that the TLS stack reports as resumed | A full handshake takes place, or the connection is refused; never served as resumed. At the adapter, a connection reported as resumed is a native denial with `CREDENTIAL_REJECTED` (MTLS-29) | `adapters/mtls/mtls-17.resumed`; the refusal to issue or accept a ticket is a Go test (probe P10) | B5 |
| `MTLS-18` | Renewal: same CA and name with a new serial and key; same subject text with another name; same name from another CA; same public key with another name | The first is the same workload and is served; the others are other workloads with no binding: `INADMISSIBLE` with `INVALID_PROOF`, or `CONTEXT_MISMATCH` for an agent enrolled for the first (identity-mapping IM-11) | `adapters/mtls/mtls-18.renewed`, `mtls-18.same-subject-other-name`, `mtls-18.other-ca`, `mtls-18.other-ca-binding`, `mtls-18.same-key-other-name` | R1 |
| `MTLS-19` | Enrollment becomes `REVOKED`, `COMPROMISED`, or unavailable while a connection is open | The next request is `INVALID_PROOF`, `SECURITY_HOLD`, or `DEFERRED` | `adapters/mtls/mtls-19.revoked`, `mtls-19.compromised`, `mtls-19.registry-down` | R1, F2 |
| `MTLS-20` | A pinned CA is removed from the configuration while a connection it issued is open | The next request is refused | `adapters/mtls/mtls-20.ca-withdrawn`; the withdrawal on an open connection is a Go test | R1, F3 |
| `MTLS-21` | Request straight to the reconciliation API from a host other than the gateway | Refused; no record data returned | No fixture: a deployment control. The adapter-level bypass is `MTLS-06` and `COMMON-02.direct` | B1 |
| `MTLS-22` | Bearer token whose `cnf` names another certificate, and one that names the presented certificate | No effect on the identity; no token binding is evaluated | `adapters/mtls/mtls-22.bearer-other-cnf`, `adapters/mtls/mtls-22.bearer-same-cnf` | R1 |
| `MTLS-23` | `POST /pact/v0.1/requirements` with a revoked certificate, and with a workload that is not enrolled | No trusted personalized contract is issued | Adapter half: `MTLS-13`, `MTLS-12.binding`. The refusal to issue is a gateway property, covered by the gateway pipeline test when a gateway exists; reserved, not landed | B8, F2 |
| `MTLS-24` | Two enrollment records, for agents A and B, on one certificate-derived workload: (a) the enrollment that would add the second record; (b) both records present, and a valid certificate of the workload with a presentation by A signed with A's key, and one by B signed with B's key | (a) Refused; (b) neither record is selected, for either agent: the configuration error of identity-mapping §5 (IM-19), `UNSUPPORTED_REQUIREMENT` | (a) Go test of the adapter package against the enrollment registry; (b) `adapters/mtls/mtls-24.two-agents-a`, `adapters/mtls/mtls-24.two-agents-b`, with the control `mtls-24.dedicated` | R1, MTLS-8, section 7 |

### Replaced common cases

The common cases of the adapter conformance suite run against this adapter. Eight `authenticate_native` cases state a principal or a denial reason that a certificate cannot carry and are replaced ([adapters README](../../fixtures/adapters/README.md), "Replaced common cases"; draft §22.2). The others pass, with the deployment-supplied sources that their native state describes.

| Common case | Why mTLS cannot realize it | Replacement |
|---|---|---|
| `COMMON-01.credential-wins` | Expects `https://idp.acme.example/bob` and a workload that is not an `mtls:` identifier | `MTLS-01.direct-listener-header-ignored`: direct listener, valid leaf of workload A, `x-forwarded-client-cert` and the `ssl-client-*` headers naming enrolled workload B; authenticated as A's identifier (MTLS-6, MTLS-26) |
| `COMMON-02.via-enforcement-point` | Expects `https://idp.acme.example/alice` | `MTLS-11.valid`: pinned leaf through the listener; authenticated as its `mtls:` identifier, mechanism `mtls`, realm of the listener |
| `COMMON-09.authenticate-realm` | Expects a `globex` principal id | `MTLS-11.listener-realm`: the same leaf on a listener configured for realm `globex`; the same identifier in realm `globex` (MTLS-6) |
| `COMMON-10.authenticate-error` | Pins `CREDENTIAL_REJECTED` for a bearer token and a cookie; the only credential of this mechanism is the certificate | `MTLS-13.unspecified`: revoked leaf, with the `Authorization` and `Cookie` headers of the common case; `CREDENTIAL_REJECTED`, and none of the token, the cookie, the leaf's subject or a PEM header appears in the result |
| `IDENT-01.authenticate` | Expects `basic:acme-accounts:20511` | `MTLS-12.authenticate`: subject common name equal to the enrolled workload's name, subject alternative name naming another workload; authenticated as the latter (MTLS-6) |
| `IDENT-02.authenticate` | Expects an `oauth:` identifier of another tenant | `MTLS-18.other-ca`: the same name issued by another pinned CA; the identifier with that `ca-id` (IM-22, the analogue of IM-4) |
| `IDENT-03.authenticate` | Splits user and client; under this mechanism the principal is the workload | `MTLS-18.same-key-other-name`: the same public key under another name; the other workload (MTLS-16) |
| `IDENT-05.authenticate` | Expects `basic:acme-accounts:30981` | `MTLS-12.authenticate`: the subject common name is the analogue of a display name and is never compared |

## G16 closure map

The open finding G16 asks for a certificate identity policy, status and renewal, connection reuse and resumption, authenticated peer-identity forwarding from a trusted terminator, and a distinction from OAuth certificate-bound tokens, and it asks for evidence that forged forwarded headers, proxy bypass, wrong certificate, workload, and key combinations, and unacceptable certificate status on reused connections are all rejected. The table maps each item to the rules and planned cases of this profile.

| G16 closure item | Rules | Cases |
|---|---|---|
| Certificate identity policy | MTLS-1 to MTLS-9, MTLS-30, MTLS-31 | `MTLS-09` to `MTLS-12` |
| Certificate status | MTLS-10 to MTLS-15 | `MTLS-13`, `MTLS-14` |
| Renewal | MTLS-16 | `MTLS-18` |
| Connection reuse and resumption | MTLS-17 to MTLS-21 | `MTLS-15` to `MTLS-17`, `MTLS-19`, `MTLS-20` |
| Authenticated peer-identity forwarding from a trusted terminator | MTLS-22 to MTLS-27 | `MTLS-02` to `MTLS-07` |
| Distinguish OAuth certificate-bound tokens | MTLS-28 | `MTLS-22` |
| Evidence: reject forged forwarded headers | MTLS-24, MTLS-26 | `MTLS-01`, `MTLS-03` to `MTLS-05`, `MTLS-07` |
| Evidence: reject proxy bypass | MTLS-22, MTLS-23 | `MTLS-02`, `MTLS-06`, `MTLS-21` |
| Evidence: reject wrong certificate, workload, and key combinations | MTLS-3 to MTLS-9, MTLS-31 | `MTLS-09` to `MTLS-12`, `MTLS-18` |
| Evidence: reject unacceptable certificate status on reused connections | MTLS-13 to MTLS-15, MTLS-19 | `MTLS-13` to `MTLS-16` |

## Evidence

This section is informative. It records what was probed and read for this profile, so that each rule that states a behaviour of an external system has a source. The probes are throwaway programs run on 2026-10-16 with Go 1.26.1 (darwin/arm64) using only the standard library; they are not part of the repository, and each is described by its input and its observed result. Go source was read where a behaviour is documented there: `crypto/tls` (`common.go`, `handshake_server.go`, `handshake_server_tls13.go`), `crypto/x509` (`parser.go`, `x509.go`, `verify.go`), and `net/http` (`h2_bundle.go`). Everything else is cited to its primary source in the table at the end of this section or is an open item.

### Probes

| Probe | Input | Observed result |
|---|---|---|
| P1 | `x509.ParseRevocationList` on a CRL created for a test CA, then on the same list in PEM form | The DER list parses: CRL number, `thisUpdate`, `nextUpdate`, entries (serial, time, reason code), authority key identifier (equal to the CA's subject key identifier) and raw issuer (equal to the CA's raw subject) are exposed. The PEM form fails with `x509: malformed crl` |
| P2 | An entry of a signed list altered after signing; a list checked against another CA | Parsing succeeds and exposes the altered serial. `RevocationList.CheckSignatureFrom` then fails with `x509: ECDSA verification failure`, as it does for the wrong CA. Parsing never verifies the signature |
| P3 | A list whose `nextUpdate` is in the past; a list whose `thisUpdate` is in the future | Both parse and both pass `CheckSignatureFrom`. No time is checked against a clock |
| P4 | Lists with a critical unknown extension, a critical delta CRL indicator (2.5.29.27), a critical issuing distribution point (2.5.29.28), an entry with a critical certificate issuer extension (2.5.29.29), and an entry with reason code 8 | All parse without error and pass `CheckSignatureFrom`; the critical extensions are exposed with `Critical` true in `Extensions` and the reason code is exposed. A delta or scoped list is indistinguishable from a complete one unless the caller looks |
| P5 | `CheckSignatureFrom` with a certificate that has the CA's key and another subject; with an expired CA certificate; with a CA certificate whose key usage lacks cRLSign | The first two pass (the raw issuer of the list differs from the raw subject of the first, and nothing compares them); the third fails with `x509: invalid signature: parent certificate cannot sign this kind of certificate` |
| P6 | `Certificate.Verify` for a leaf listed in a list that is held by the program | No error. The standard library never reads revocation lists |
| P7 | Server with `RequireAndVerifyClientCert` and a pinned root, TLS 1.3 and TLS 1.2 (identical results), clients with: client-auth purpose; no extended key usage extension; server-auth purpose only; server-auth and client-auth; any-purpose only; client-auth with key usage keyEncipherment only; client-auth with cA true and keyCertSign; client-auth with no subject alternative name; no certificate | Accepted: client-auth; no extension; server-auth and client-auth; any-purpose only; keyEncipherment only; cA true; no subject alternative name. Rejected: server-auth only (`certificate specifies an incompatible key usage`), no certificate (`client didn't provide a certificate`). So MTLS-4 (a) to (c) and the SAN rules of MTLS-6 are not enforced by the stack. The source agrees: `checkChainForKeyUsage` skips a certificate with no extended key usage and accepts the any-purpose OID |
| P8 | Chains: pool {root, intermediate} with the leaf alone, and with leaf and intermediate; pool {root} with the intermediate sent by the peer; pool {intermediate} alone; intermediate restricted to server-auth with a client-auth leaf; the pinned root itself presented as the client certificate | Pool {root, intermediate}: accepted, `VerifiedChains` holds [leaf, intermediate] and, when the peer also sent the intermediate, [leaf, intermediate, root] as well, so the second certificate is the issuer in each. Pool {root} with a peer-supplied intermediate: accepted as [leaf, intermediate, root], so only the second-certificate rule of MTLS-3 refuses it. Pool {intermediate} alone: accepted as [leaf, intermediate], so a non-self-signed certificate works as an anchor. Restricted intermediate: rejected with the incompatible key usage error. A pinned root presented as the client certificate with its own key: accepted as the chain [root] |
| P9 | Leaf certificates whose subject alternative name extension was built from raw octets, parsed by `x509.ParseCertificate` | URIs: `SPIFFE://Example.ORG/...` is exposed as `spiffe://Example.ORG/...` (the scheme is lowered) and `https://example.org/a b` as `https://example.org/a%20b`, so the library's `URL.String()` differs from the raw octets; a relative reference (`workloads/a`) and an empty value parse; a host with a trailing dot fails to parse. DNS names: upper case, trailing dot, `*.example`, `a_b.example`, and a blank value all parse unchanged; non-ASCII octets fail (`SAN dNSName is malformed`). Several URI and DNS entries are all exposed |
| P10 | Server with tickets enabled, client with a session cache, two connections, TLS 1.3 and TLS 1.2 (identical results); then variants. Source read: `checkForResumption` and `checkPSK` | Second connection resumes (`DidResume` true) and `PeerCertificates` and `VerifiedChains` are populated from the session. `VerifyPeerCertificate` runs once (full handshake only); `VerifyConnection` runs for both connections, so a callback can see the resumption and the certificate. A leaf marked revoked in the program's own set is accepted on resumption unless the callback refuses it. With `SessionTicketsDisabled` both connections are full handshakes and `VerifyPeerCertificate` runs twice. With the server clock past the leaf's notAfter, or with a clone whose client CA pool no longer holds the CA, the second connection is not resumed and fails full verification. Source: the resumption check compares the leaf's notAfter with the clock and re-verifies a stored chain against the current client CAs and the client-auth purpose |
| P11 | `net/http` TLS server with `RequireAndVerifyClientCert`, HTTP/1.1 and HTTP/2; five requests from one client, the third response sets `Connection: close` | Requests on one connection see the same `*tls.ConnectionState` pointer in both versions. After the third response the next request uses a new connection in both versions (connections accepted: 1, then 2). In HTTP/1.1 the client sees the connection marked to close; in HTTP/2 no `Connection` header reaches the client. Source: `responseWriterState.writeChunk` deletes `Connection` and calls `startGracefulShutdown` when its value is `close`. The frame on the wire was not captured (open item O4) |
| P12 | The packages of this repository: `go/adapter/freshness` `Evaluate` with limits of 360 s and a status age of 360 s, of 361 s, no status time, and a time 6 s ahead; `go/adapter/enroll` `Resolver` over the in-memory registry with an enrolled workload identifier, the same with the scheme in upper case, another `ca-id`, and `CN=agent-a` | Freshness: equal to the limit `PASS`; 361 s `FAIL` `STALE_EVIDENCE`; no time `UNKNOWN` `UNSUPPORTED_REQUIREMENT`; ahead `FAIL` `CLOCK_AHEAD`. Enrollment: the enrolled identifier is `ACTIVE`; the other three are `UNKNOWN` with no agent and no error. The registry compares the workload as an opaque string and does not check the grammar of identity-mapping §3.1, so the adapter builds the identifier |

### Repository packages

The adapter of this profile is the package `go/adapters/mtls`, built with `mtls.New` from an `mtls.Config` that names the listener's role and realm, the pinned CA set, the terminator allowlist, the status bound and the deployment-supplied parts; it uses the standard library only (`crypto/tls`, `crypto/x509`). The gateway installs `ServerTLSConfig` and `ConnContext` on its HTTP server, passes each fetched list to `Adopt`, and closes a connection after a response with `CloseAfter`. The principal carries, besides `cnf`, the attribute `mtls` with the status time and, on a direct listener, the observation time of the identity, from which `read_native_claim` answers MTLS-30. Its tests run the common cases, with the replacements of section 10, and the cases of section 10 against it. It builds on five packages of this repository.

| Package | What the adapter uses | Note |
|---|---|---|
| `go/adapter` | `NativeAuthenticator.AuthenticateNative` returning a `Principal` whose `Workload` and `ID` are the identifier of MTLS-6, `Mechanism` `mtls`, and the realm of the listener, with `Principal.Attributes["cnf"]` set to `{"jkt": <RFC 7638 thumbprint of the leaf public key>}` (MTLS-9); `NativeDenial` with the public reasons `NO_CREDENTIAL` and `CREDENTIAL_REJECTED`; errors that wrap `ErrDependencyUnavailable` for a status or registry that cannot answer; `ClaimReader` for MTLS-30; `ContextChecker` for MTLS-31 | An adapter implements the composite `Adapter` and its `Describe` returns `mtls`, `1.3`, `pact-mtls-1` |
| `go/adapter/enroll` | `Resolver.ResolveAgentBinding` over a `Registry`: `Lookup` takes the realm, the workload identifier and the presented agent ID, and that agent's record on the workload resolves to `ACTIVE`, `REVOKED`, or `COMPROMISED`, or to `UNKNOWN` when it has none | The registry compares the identifier octet for octet (probe P12). The agent ID selects only among the records of the workload, never a record of another workload (identity-mapping IM-18) |
| `go/adapter/freshness` | `Evaluate` and `Evaluator` for the rule-level comparison of the status and observation ages, with the reason codes `ClockAhead`, `StaleEvidence`, and `UnsupportedRequirement` | The connection gate of MTLS-19 is a native authentication result and is not a rule evaluation: it returns `DEFERRED` where `Evaluate` returns `FAIL`. The rule-level comparison applies to a contract rule over the identity claim |
| `go/core/clock` | `BaselineSkew` (5 seconds) for MTLS-5 and MTLS-12 | |
| `go/adapter/installed` | The deployment-supplied parts: claim sources, installed checks, route tables, the permission lookup and the outcome signer | Shared with the Basic adapter |

### Primary sources read

| Source | Used for |
|---|---|
| RFC 5280 ([text](https://www.rfc-editor.org/rfc/rfc5280.txt)) | §4.2.1.3 and §4.2.1.9 (key usage, basic constraints); §4.2.1.6 (name forms, case, URI and DNS rules, wildcards); §4.2.1.12 (extended key usage); §5.1.2.3 to §5.1.2.5, §5.2, §5.2.3 to §5.2.5, §5.3, §5.3.1 (list fields, critical extensions, CRL number, reason codes); §6.3.3 (list processing) |
| RFC 8446 ([text](https://www.rfc-editor.org/rfc/rfc8446.txt)) | §2.2 and §4.4 (resumption and PSK carry no certificate authentication), §4.6.1 (ticket lifetime of at most seven days) |
| RFC 8705 ([text](https://www.rfc-editor.org/rfc/rfc8705.txt)) | §2 (mutual TLS client authentication), §3 (certificate-bound access tokens), §6.5 (TLS termination left out of scope) |
| RFC 9112 §9.6 and RFC 9113 §6.8, §8.2.2 ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.txt), [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.txt)) | Closing a connection in HTTP/1.1 and HTTP/2 |
| Envoy documentation: [header reference, x-forwarded-client-cert](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert), and the API fields `forward_client_cert_details`, `set_current_client_cert_details`, and `require_client_certificate` | The header format and keys, the modes of `forward_client_cert_details`, the fields forwarded, and the rejection of connections without a client certificate. Read from the upstream sources of the `main` branch on 2026-10-16 |
| nginx [`ngx_http_ssl_module`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html) | The names of the `$ssl_client_*` variables |
| SPIFFE [X509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md) | §2 (exactly one URI name), §5.2 (leaf validation), §6 (bundles), for the unsupported SPIFFE form |

## Open items

These are facts this profile does not establish and choices it has not settled. None is stated as a rule.

| ID | Item | Probe or decision needed |
|---|---|---|
| O1 | Whether the terminator replaces a header that the client supplied. The documentation says `SANITIZE_SET` resets the header when the client connection is mTLS and does not say what happens to a supplied header otherwise | Run the terminator at the pinned release with the configuration of MTLS-27, send a supplied header with and without a valid client certificate, and capture what the gateway receives |
| O2 | The exact serialization of the `Cert` element (quoting, and how `+` and `=` of the PEM are percent-encoded; the upstream prose also says "comma separated" where the format section says semicolon), and the Envoy release to pin | Capture the header from the pinned release for an EC and an RSA leaf and parse it with MTLS-24 |
| O3 | A source observation time for a forwarded identity. The header carries none, so MTLS-30 leaves it absent and a rule that bounds the observation age is `DEFERRED` on a terminated listener | Check whether the terminator can expose the age of the downstream connection |
| O4 | The HTTP/2 frame that ends a connection after `Connection: close` in a handler | Capture the frames of probe P11 |
| O5 | Whether lists from the deployment's CA product pass MTLS-12 (d), for example a CA that marks a distribution point extension critical on a complete list | Fetch a list from the CA and inspect its extensions |
| O6 | Resumption with a ticket that carries the status time, so that a later version could allow it. `crypto/tls` offers session wrap and unwrap hooks that were not probed | Probe in a later version; wire version 0.1 refuses resumption |
| O7 | The choice of the Envoy forwarded-certificate header over the `ssl-client-*` headers of nginx-based proxies is a draft decision that the maintainers have not confirmed. If the other form is chosen, MTLS-24, MTLS-26, and MTLS-27 change and nothing else does | Maintainer decision |
| O8 | Whether `DEFERRED` at the native authentication stage should carry a receipt. Draft §12.2 gives no receipt to invalid native authentication and a receipt to a completed authenticated evaluation, and does not classify a native check that could not be completed. MTLS-29 writes no receipt | Maintainer decision |
| O9 | Whether TLS 1.2 is admitted. Probes P7 and P10 behave the same at 1.2, and MTLS-1 sets the floor at 1.3 | Maintainer decision |
