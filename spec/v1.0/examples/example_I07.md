# Integration 07 — Client certificates and mutual TLS

**Status:** Draft
This example is informative: it does not establish a live integration, interoperability, or an end-to-end security result.


## Assumptions, components, and limitations

Component IDs C01 to C16 are the components of section 4 of the integration profile [template](../profiles/TEMPLATE.md); they are editorial identifiers, not protocol fields or registered reason codes.

### Assumptions

- The native TLS endpoint validates its PKI and maps peer identity to an enrolled workload.
- An upstream terminator, if used, provides authenticated integrity-protected peer context.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C02 | mTLS authentication and trusted peer context. |
| C03 | Certificate/workload/PACT-key registry and rotation. |
| C08 | Native resource enforcement. |
| C13 | Certificate/enrollment status and connection-lifetime policy. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Deliberate simplifications and limitations

- The sample uses plain mTLS and a separate PACT key; OAuth certificate binding and SPIFFE are not implemented.
- Peer identity forwarding is an assumed deployment-specific trusted mechanism.

### Limitations and open points

Open in every example: the enforced integration scope; native identity and the enrolled agent and key mapping; exact request binding and native translation; achievable source freshness and execution-time rechecks; native outcome and visibility mappings; executed end-to-end conformance evidence; privacy, retention, correction, and lineage operations; and transport, latency, capacity, and outage budgets. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Open points specific to this example:

- Define native certificate-to-workload and distinct holder-key binding.
- Specify terminator handoff, certificate status, renewal, and resumed/long-lived connections.

The integration profile [`mtls`](../profiles/mtls/profile.md) indexes, in its section 10, the cases and Go tests that cover forged peer headers, terminator bypass, wrong certificate, workload, and key combinations, revoked and stale certificate status, renewal, connection reuse, and resumption at the adapter; its requirement coverage table ties each requirement to rules and cases. The decisions table below names the cases. These PKI and deployment items remain unvalidated:

- The deployment's private PKI: whether its CA publishes complete revocation lists that the profile's list acceptance rule (rule MTLS-12) admits (open item O5), and the publication interval `P` and propagation time `R` that set the status bound `S` (rule MTLS-14).
- The terminator at a pinned release: replacement of a header the client supplied and the exact `Cert` serialization (open items O1 and O2), and its obligations under rule MTLS-27.
- Direct access to the reconciliation API from hosts other than the gateway (case `MTLS-21`), a deployment control with no fixture.
- The refusal to issue a contract for a revoked or unenrolled workload (case `MTLS-23`), a gateway property with no landed case.

Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

A supplier-reconciliation agent calls Northstar's internal reconciliation API. The API already authenticates machine clients with certificates issued by the organization's private PKI. Native policy limits this workload to reading reconciliation records for its own business unit.

The gateway requires both the existing mTLS identity and a signed PACT presentation. The TLS certificate key and the enrolled PACT holder key are distinct keys in this example, with an authorized registry binding them to the same workload.

## Native authentication and trust

The configured TLS endpoint requires client authentication, validates the certificate according to its PKI policy, and maps an approved certificate identity to a native workload. It also implements the required certificate status and lifecycle checks. A client certificate establishes the configured native identity; the API still decides what that identity may do. TLS client authentication is defined within [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html).

This is plain mTLS API authentication. OAuth mTLS client authentication and certificate-bound access tokens are separate mechanisms specified by [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html). They can be added, but certificate authentication alone does not mean an OAuth token is certificate-bound.

## Required profile and mapping

| Fact | Source and rule |
|---|---|
| `/attributes/environment/workload_id` | Equals native workload resolved from the authenticated certificate and enrollment registry |
| `/attributes/environment/business_unit` | Equals the workload's authoritative unit mapping |
| `/attributes/runtime/isolation` | Trusted runtime attestation required by the selected set |
| Current agent/holder binding | Existing enrollment record; distinct from TLS certificate validation |
| Purpose and operation | Installed check recognizes the exact reconciliation read as part of the approved task |

Certificate subject text supplied by an agent is not native TLS context. The gateway uses its TLS stack's authenticated peer information or a securely authenticated equivalent from its trusted TLS terminator. Ordinary caller-controlled certificate headers are ignored.

## Successful exchange

1. The agent establishes HTTPS with the required client certificate. The TLS endpoint validates it and resolves the approved native workload and PACT enrollment.
2. Over this authenticated channel, the agent requests requirements for reading reconciliation record `REC-782` for its unit.
3. The gateway maps the actual operation and returns a signed contract bound to the enrolled PACT holder key, workload principal, purpose, and exact operation.
4. The agent prepares the profile view and trusted evidence, then signs the complete presentation with its PACT key.
5. It submits the native read with `PACT-Presentation: <compact JWS>`. No Basic or OAuth header is introduced by this sample; the existing native authentication is mTLS.
6. The gateway validates the TLS-derived native identity and registered key relationship, then verifies the presentation, nonce, evidence, freshness, status, purpose, and request mapping. Passing requirements produce `ADMISSIBLE`.
7. The reconciliation API checks the authenticated workload's native record permissions. Only if those checks allow the request does the read execute.

The same authenticated principal must remain applicable between contract issuance and actual evaluation. Changing workload identity cannot be hidden behind an unchanged profile. A passing receipt is single-operation evidence, not permission for the whole TLS connection.

## Proxy and termination boundary

If a load balancer terminates TLS, the validator needs an authenticated, integrity-protected statement of peer identity from that trusted component. The backend rejects direct access and untrusted identity headers. The forwarding format is adapter configuration, not a new core PACT artifact. The [mTLS profile](../profiles/mtls/profile.md) fixes one form for wire version 0.1: a terminated listener admits only allowlisted terminators (rule MTLS-23) and reads only the `Cert` element of their `x-forwarded-client-cert` header (rule MTLS-24); every other forwarded-identity header, on any listener, is ignored and removed before native authorization (rule MTLS-26). The terminator's own configuration is a deployment obligation that the gateway cannot observe (rule MTLS-27).

This sample's conservative policy requires a new fully authenticated connection when the endpoint cannot establish sufficiently current certificate status. The profile makes that concrete. TLS sessions are never resumed (rule MTLS-17), and identity is re-read for every request (rule MTLS-18). On a direct listener the connection's status record ages against the bound `S`; past it, the request is `DEFERRED` with `DEPENDENCY_UNAVAILABLE` and the connection is closed (rules MTLS-14 and MTLS-19). A forwarded leaf is checked for every request and is `DEFERRED` without closing the connection (rule MTLS-25). Receipt freshness cannot independently renew TLS identity.

## Decisions and failure variations

The profile cases are those of section 10 of the [mTLS profile](../profiles/mtls/profile.md). Its adapter cases are in [`fixtures/adapters/mtls/`](../fixtures/adapters/mtls/README.md), registered in the fixture manifest as `adapters/mtls/<case>`. Case IDs have two digits (`MTLS-01`); rule IDs do not (rule MTLS-1). A case tests the adapter, not a deployment.

| Condition | Expected behavior | Profile case |
|---|---|---|
| Accepted certificate, correct enrolled PACT key, required evidence, allowed record | Admit and execute after native authorization | `MTLS-11`, control `mtls-11.valid` (native authentication only) |
| Valid certificate but unknown workload enrollment | Do not issue a trusted personalized contract | `MTLS-23`, adapter half only: `mtls-12.binding`; at evaluation, `MTLS-12` and `MTLS-18` |
| Correct PACT key but rejected/expired native certificate | Native authentication blocks access | `MTLS-04`, `MTLS-11` (including `mtls-11.expired`), `MTLS-13` (revoked) |
| Certificate for workload A with workload B's profile/key | Native enrollment/context mismatch | `MTLS-09` |
| Forged forwarded client-certificate header | Ignored and removed; the header establishes no native identity, which comes only from the TLS peer or from `Cert` of an allowlisted terminator | `MTLS-01`, `MTLS-02`, `MTLS-03`, `MTLS-05`, `MTLS-07` |
| Connection to a terminated listener that bypasses the terminator | Refused at connection setup | `MTLS-06` (Go test), `MTLS-02` |
| Presentation signed with the TLS certificate key | The TLS key is never a holder key; the presentation is refused with `INVALID_PROOF` | `MTLS-10`, adapter half only; the validator refusal has no case yet |
| Valid mTLS and PACT, record belongs to another business unit | Native authorization denies | None: native authorization of the API, outside the profile |
| Required certificate/evidence status cannot be established | Fail closed at the applicable layer: `DEFERRED` with `DEPENDENCY_UNAVAILABLE` | `MTLS-14`, `MTLS-19` (`mtls-19.registry-down`) |
| Certificate revoked after the connection opened | Served until the status record is older than `S`, then `DEFERRED` and closed; a new connection is refused | `MTLS-15`, `MTLS-16` (Go tests) |
| Enrollment revoked or marked compromised while a connection is open | The next request is `INVALID_PROOF` or `SECURITY_HOLD` | `MTLS-19` |
| Pinned CA withdrawn while a connection it issued is open | The next request is refused | `MTLS-20` |
| Renewed certificate: same CA and name, new serial and key | Same workload, served; the same subject text, key, or name from another CA is another workload with no binding | `MTLS-18` |
| Session ticket offered, or a connection reported as resumed | Full handshake, or refused; never served as resumed | `MTLS-17` |
| TLS 1.2 client, or cleartext HTTP | Refused | `MTLS-08` |
| Bearer token whose `cnf` names a certificate | No effect on the identity; no token binding is evaluated | `MTLS-22` |

## Rotation, reputation, and learning

Certificate renewal and PACT key rotation use authorized lifecycle processes. A new certificate is mapped through the enrollment policy; it does not automatically inherit an arbitrary workload identity. Replacing the PACT key likewise requires the draft's current holder binding and recovery rules.

A successful handshake and admission add no positive task-performance weight. Qualified reconciliation outcomes can update the agent's context-specific dimensions. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, the other-business-unit refusal is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, a rejected or expired certificate is a “Pre-authentication or transport failure” with no `OutcomeReport`, and the completed reconciliation read is “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`). An authorized selector may change capability-evidence frequency but cannot enroll a new CA, accept an unregistered certificate identity, clear a security hold, or expand native resource access.

## Boundary demonstrated

mTLS authenticates the native workload; the PACT key proves the enrolled agent's presentation; native policy authorizes the requested record operation. Both keys and their relationship are explicitly governed.

**PACT anchors:** §§4–12, 14–18.

## Primary references

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 8705 — OAuth mTLS and certificate-bound tokens](https://www.rfc-editor.org/rfc/rfc8705.html)
