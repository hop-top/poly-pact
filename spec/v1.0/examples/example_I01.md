# Integration sample 01 — HTTP Basic authentication

**Status:** Informative integration sample for PACT Protocol v1.0. All organizations, identifiers, routes, and policies are illustrative. HTTP examples contain placeholders and are not executable fixtures. Profile excerpts omit required core fields and signatures; they are not complete wire objects. The adapter configuration below is a deployment design, not a new PACT wire schema.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I01. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- An enforced gateway can be installed and can preserve the authenticated Basic account at the backend.
- A dedicated account/key enrollment exists and claimed routes cannot bypass the gateway.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C02 | HTTPS Basic authentication and native account/permission lookup. |
| C03 | Dedicated/shared account policy and enrolled key lifecycle. |
| C08 | Backend preserving the native account's effective restrictions. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G01 | Declare and test backend/alternative-route bypass boundaries. | Profile / coverage |
| G02 | Specify native account and holder-key binding, including shared-account ambiguity. | Profile |
| G25 | Distinguish attested from enforced data-use controls per §17.4. | Deployment / coverage |

### Deliberate simplifications and limitations

- A dedicated account avoids shared-password ambiguity; the shared-account multi-agent case is not demonstrated.
- A header does not make an unchanged Basic server PACT-aware; outside-path credential use is uncovered.
- `execution-control-v1` is not required, so the runtime guarantee is labeled "attested-only": `runtime.isolation` value `managed` from a configured runtime issuer establishes a verified fact only, and invoice data handling is a post-read residual limit.

### Profile and fixtures

The integration profile [`basic`](../profiles/basic/profile.md) states the conformance claim behind this sample: route R1 (`GET /invoices/{id}`), the principal `basic:{store-id}:{account-id}`, the deployment requirements DR1 to DR6, and the fixture index of its section 10. The adapter cases are in [`fixtures/adapters/basic/`](../fixtures/adapters/basic/README.md), registered in the fixture manifest under the ids below. They test the adapter and validator against a fake account database and permission lookup; they are not a live integration.

| Fixture ID | Exchange of this sample | Evidence |
|---|---|---|
| `BASIC-01` | Invalid Basic credentials: wrong, unknown, missing, malformed or colon-less, another scheme, a control character, a disabled account | `adapters/basic/basic-01.*`, with the controls `basic-01.valid` and `basic-01.colon-in-password` |
| `BASIC-02` | Valid Basic credentials, wrong PACT holder key | Evaluation case `admission/old-holder-key`; the enrolled key the adapter reports is checked by `adapters/basic/basic-07.dedicated` |
| `BASIC-03` | Direct backend request without the gateway enforcement marker, with or without headers that claim the gateway | `adapters/basic/basic-03.direct`, `adapters/basic/basic-03.forged-marker` (adapter level only) |
| `BASIC-04` | Missing presentation on the protected route | Go test of the adapter package; no fixture |
| `BASIC-05` | Reused consumed presentation | Evaluation cases `admission/replay-same-nonce-two-replicas` and `admission/attestation-reuse` |
| `BASIC-06` | Password and its Base64 form in any denial, operation context, mapping error, check outcome or outcome report | `adapters/basic/basic-06.*` |
| `BASIC-07` | Two agents enrolled on one account, which this sample avoids | `adapters/basic/basic-07.two-agents-a`, `adapters/basic/basic-07.two-agents-b`, with the control `basic-07.dedicated`; the refusal of the second enrollment is a Go test of the adapter package |
| `BASIC-08` | Profile roles beyond the roles mapped from the account | `adapters/basic/basic-08.*`, with the control `basic-08.principal-id`; evaluation case `admission/self-asserted-privileged-role` |
| `BASIC-09` | Invoice that belongs to another department | `adapters/basic/basic-09.other-department`, with the control `basic-09.same-department` |

### Validation still required

The cases above cover the adapter and validator behaviour of this exchange. These remain unvalidated:

- A live invoice backend, account database, enrollment registry, and hold store: the cases read fixture state, not the deployment's systems.
- Production network policy that closes the backend to every source but the gateway (integration profile DR1). `BASIC-03` tests the gateway enforcement marker only, not the network control.
- The other deployment requirements of the integration profile, DR2 to DR6: an HTTPS-only listener, uncached reads from the authoritative account database, replay state shared by every gateway replica, the header allowlist, and a presentation header size that every proxy in the path accepts.
- Credential exclusion from the deployment's own logs and telemetry; `BASIC-06` covers the adapter's results only.

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Scenario and placement

A legacy invoice API authenticates callers with HTTP Basic and assigns permissions through an existing account database. Northstar wants its invoice assistant to provide verified agent context before it reads an invoice.

Install a PACT-aware gateway in the request path. The gateway validates Basic credentials against the existing authentication source, resolves native account permissions, and additionally evaluates PACT. The backend accepts traffic only through that enforced path, with a trusted means of preserving the authenticated account. An unchanged Basic-only server cannot evaluate PACT merely because a client adds a profile header.

Basic transmits a Base64-encoded username/password pair. Base64 does not encrypt it; this sample uses HTTPS throughout. See [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html).

## Enrollment and native mapping

Provision a dedicated native account, `invoice-assistant-ops`, with the existing department-limited read permissions. During authorized enrollment, bind that account and operator to a stable agent ID and public signing-key thumbprint.

| Native fact | PACT use |
|---|---|
| Successfully authenticated Basic account | Establish native principal independently of the profile |
| Account-to-agent enrollment record | Resolve allowed agent ID, operator, and holder key |
| Account database roles | Compare the profile's role array using a configured native mapping |
| Invoice permission lookup | Make the ordinary native resource-authorization decision |

The password is not the PACT signing key. If Basic accounts are shared, possession of the shared password cannot distinguish agents; each accepted agent still requires an explicit authorized enrollment/key binding. This sample uses a dedicated account to avoid that ambiguity.

## Required profile excerpt

```json
{
  "attributes": {
    "environment": {
      "principal_id": "basic:legacy-accounts:20417",
      "roles": ["invoice-reader"]
    },
    "runtime": {
      "isolation": "managed"
    }
  }
}
```

The principal and role fields use `source: native`. The principal is `basic:legacy-accounts:20417`: the configured account-store id and the account's immutable key. The login `invoice-assistant-ops` only finds the account and is never part of the identifier (integration profile section 7). The runtime field uses `source: evidence` with a configured runtime issuer. The password, its Base64 representation, and other credential material never appear in the profile, receipt, or reputation record.

## Request exchange

1. The agent asks for requirements through `POST /pact/v0.1/requirements`, using its existing Basic authentication. The request body is the draft's complete `ContractRequest`, including proposed intent and operation.
2. The gateway authenticates the account and resolves the enrolled agent/key before issuing a personalized contract. It derives the actual native principal, selects the required profile fields, and returns the signed contract and nonce.
3. The agent prepares the profile and trusted runtime evidence, then signs the complete PACT presentation with its enrolled holder key.
4. It sends the exact protected request over HTTPS:

```http
GET /invoices/OPS-1042 HTTP/1.1
Host: invoices-gateway.example
Authorization: Basic <base64-of-provisioned-username-colon-password>
PACT-Presentation: <complete-compact-signed-presentation>
```

5. The gateway authenticates Basic again, reconstructs the request, verifies the PACT signature, binding, evidence, nonce, and required facts, and records its admission result.
6. Only if PACT is admissible and the existing account permissions allow this invoice does the gateway forward the authorized read. The backend preserves the same native account restrictions.

The operation digest covers the method, exact target URI, empty-body digest, authenticated principal, mapped resources, and relevant semantic headers. Per the draft, the `Authorization` and presentation headers are excluded from the hashed header set; their security context is checked independently.

## Outcomes to illustrate

| Input | Result |
|---|---|
| Valid Basic credentials, correct enrolled key, valid required evidence, allowed invoice | Admit and execute after native authorization |
| Valid Basic credentials, wrong PACT holder key | Reject proof; no protected execution |
| Valid PACT presentation, invalid Basic credentials | Native authentication fails |
| Both checks valid, invoice belongs to another department | Native authorization denies |
| Missing presentation on the protected route | No execution through enforced PACT path |
| Reused consumed presentation | Replay rejected |

A fresh PACT signature does not make stolen Basic credentials harmless outside this enforced path. The backend and alternate routes must retain the intended gateway boundary.

## Reputation and approvals

Only qualified, attributable execution or quality observations affect performance reputation. A successful password check or admission does not add positive weight. Section 14.5 maps this exchange: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, the other-department refusal is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, invalid Basic credentials are a “Pre-authentication or transport failure” that produces no `OutcomeReport` (Section 12.2), and only “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`) and an “Independent assessment” (`QUALITY`, `task_quality`) count toward reputation. If native policy requires a human approval for a particular operation, the gateway verifies that external approval separately; account possession and reputation cannot replace it.

## Integration boundary

PACT adds verified agent context to the existing account model. It does not upgrade Basic authentication into OIDC, assign account permissions, or require replacing the legacy identity store.

**PACT anchors:** §§4, 6–13, 14, 17–18.

**External reference:** [RFC 7617 — Basic authentication](https://www.rfc-editor.org/rfc/rfc7617.html).
