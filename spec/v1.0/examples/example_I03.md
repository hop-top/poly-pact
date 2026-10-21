# Integration sample 03 — OAuth-protected API

**Status:** Informative integration sample for PACT Protocol v1.0. All organizations, identifiers, routes, and policies are illustrative. HTTP examples contain placeholders and are not executable fixtures. Profile excerpts omit required core fields and signatures; they are not complete wire objects. The adapter configuration below is a deployment design, not a new PACT wire schema.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I03. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- The operator controls the CRM hook or an equivalently restricted connector.
- Its issuer can establish the native token facts and required validation/status freshness.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C02 | Issuer validation/introspection and scope/resource mapping. |
| C04 | Principal/client/agent/task authority. |
| C08 | Native CRM customer-record enforcement. |
| C15 | Native limits, retries, and refreshed-authority handling. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G17 | Specify token types, required introspection fields, audiences, refresh, and sender constraints. Specified for this sample's opaque token (form I) by the integration profile [`oauth`](../profiles/oauth/profile.md); its G17 closure map ties each item to rules and case groups. | Profile |
| G26 | Preserve native task limits and side-effect handling across fresh exchanges. Specified across operations by the [multi-operation profile](../profiles/multi-operation.md), whose G26 closure map (section 12) ties each item to rules and to the cases `TASK-01` to `TASK-09`, and whose section 13.2 works this sample: every read of the renewal task, a retried one included, is reserved against the task's `max_operations`, and a fresh contract resets no counter (rules MO-19, MO-20, MO-28; `TASK-01`); a refreshed token that yields the same principal and client keeps the task's ledger entry, and a token of another user is refused with `task-mismatch` (rule MO-7; `TASK-07`). The customer read is of the class Read (section 6.1) and needs no duplicate suppression. | Profile / deployment |

### Deliberate simplifications and limitations

- The concrete sample uses opaque bearer tokens with introspection; other profiles are not implemented.
- PACT signing does not implement DPoP or control direct SaaS bypass routes.

### Profile and fixtures

The integration profile [`oauth`](../profiles/oauth/profile.md) states the conformance claim behind this sample as its form I, an opaque token validated by introspection: route R1 (`GET /customers/{customer_id}`, action `crm.customer.read`) under issuer entry E1, the principal `oauth:{issuer-id}:{tenant}:{subject}` with `sub` as the subject (rule OAUTH-37), the OAuth client as the enrolled workload (rule OAUTH-38), the deployment requirements of its section 4, and the fixture index of its section 10. The adapter cases are in [`fixtures/adapters/oauth/`](../fixtures/adapters/oauth/README.md), registered in the fixture manifest; the decision examples below name the case group or case for each row. They test the adapter against an authorization server, introspection endpoint, and enrollment registry that the harness serves itself; they are not a live integration.

### Validation still required

The cases cover the adapter's handling of inactive, wrong-resource, and insufficient-scope tokens, absent introspection facts, unavailable introspection, changed token subjects and clients, and the bypass paths B1 to B5 of the profile. These remain unvalidated:

- A live authorization server at a named product and version: that it performs the checks of RFC 7662 §4 before it answers `active` `true`, answers `active` `true` to the gateway only for access tokens, and, for an entry in `introspection-scoped` mode, only for tokens that may be used at the CRM resource (deployment requirement DR3; open items OI-4 and OI-5, probe P6). The cases use an authorization server that the harness serves.
- Whether that authorization server returns `iat`; without it no `max_age` rule over the introspection facts can pass (open item OI-9).
- Network policy or gateway-to-API mutual TLS that closes the CRM API to every caller but the gateway (DR1). `OAUTH-26` tests the gateway enforcement marker only. The HTTPS-only listeners (DR2) and the header semantics of DR5 are deployment statements.
- A sender-constrained deployment: the native DPoP or certificate-binding verifier and how it reports to the adapter (DR4). `OAUTH-21` tests the adapter's checks only.
- The native delegation and task registry, the CRM permission system, and the executor record behind `native-delegation-v1` and `execution-identity-v1` (C04, C08); the cases read fixture state.
- The introspection cache with a bound `C` above 0 against a real endpoint; `OAUTH-08` is a Go test of the adapter package.
- Token and client-credential exclusion from the deployment's own logs and telemetry; `OAUTH-22` covers the adapter's results only.
- The refusal to issue a contract on a requirements request with an inactive token or an unenrolled client (`OAUTH-25`), a gateway property with no landed case.

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Scenario and placement

Northstar's CRM API already uses OAuth access tokens and account-level resource permissions. Its customer-success assistant needs to read customer `C-481` to prepare a renewal briefing.

The CRM operator adds PACT evaluation to its resource-server gateway. The existing authorization server continues to issue access tokens; PACT does not become the OAuth authorization server or exchange a profile for broader scopes.

This sample uses an opaque bearer token and an authenticated introspection service. A JWT access-token deployment can validate tokens according to its issuer/resource-server profile instead; it must not assume that every OAuth token is a JWT or that every provider exposes introspection.

## Existing OAuth contract

The authorization server issues a token for this CRM resource with the sample scope `customers.read`. The API is responsible for validating the token, its intended resource, applicable scopes, and native customer permissions. A read scope does not by itself authorize every customer record.

A bearer credential accompanies the native request in `Authorization: Bearer ...`. RFC 7662 defines how a resource server can obtain token metadata through introspection, including the required active-status field. The deployment must configure how its issuer supplies all other required facts; the integration profile requires `exp`, `sub`, `client_id`, `scope`, and `aud` or a declared resource binding (rules OAUTH-11 to OAUTH-13). See [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) and [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html).

## Trusted mapping

| Native source | Mapped fact or decision | Integration profile rule |
|---|---|---|
| Issuer-authenticated introspection response | Token status, expiry, subject, client, scopes, and resource binding under this issuer's contract | OAUTH-7 to OAUTH-17 |
| Tenant/account mapping | Stable, namespaced native principal; never a free-form profile username | OAUTH-37: `oauth:{issuer-id}:{tenant}:{subject}`, with the entry's configured tenant and `sub`; `username` is never used (OAUTH-11) |
| Enrollment registry | Which PACT agent and holder key the authenticated OAuth client may use | OAUTH-38: the client is the enrolled workload; one client serves one agent |
| Native delegation/task registry | Whether this agent can act for this principal on the renewal task | Outside the profile's rules: `native-delegation-v1`, supplied by the deployment (C04) |
| CRM authorization system | Whether that principal can read customer `C-481` | `authorize_native`: the route's required scope (OAUTH-31), then the CRM permission |

The gateway authenticates to its configured introspection endpoint with its own client credentials (rules OAUTH-7 and OAUTH-8). It does not fetch a token-status URL supplied by the agent. If required resource/audience binding or identity facts cannot be established, `active: true` alone does not authorize the request (rule OAUTH-10).

## Required profile excerpt

```json
{
  "attributes": {
    "environment": {
      "principal_id": "oauth:https%3A%2F%2Fauth.crm.example:northstar:user-73",
      "oauth_client_id": "oauth:https%3A%2F%2Fauth.crm.example:northstar:renewal-assistant-client",
      "oauth_scopes": ["customers.read"]
    },
    "delegation": {
      "authority_ref": "crm-task:renewal-C-481"
    }
  }
}
```

These paths use configured native comparisons. The principal is `oauth:{issuer-id}:{tenant}:{subject}`: the configured issuer identifier `https://auth.crm.example`, percent-encoded, the entry's configured tenant `northstar`, and the token's `sub` (integration profile, rule OAUTH-37). The client is compared in the namespaced form that `read_native_claim` returns for `/oauth/client_id`, so a same-spelled client of another issuer or tenant never matches. The scope array is checked against issuer-established token scope using the draft's array comparison rules. Local policy separately requires `customers.read`; a matching empty or irrelevant scope array is insufficient. Native subject/client enrollment establishes the agent/key relationship; the token does not become holder-bound merely because a profile names a key.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment registry: which agent and holder key the authenticated OAuth client may use (Sections 6.1 and 6.2; integration profile rule OAUTH-38) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: the issuer-authenticated introspection response, with `sub` mapped to the namespaced principal of rule OAUTH-37 (Section 17.1); the OAuth client is bound separately, as the enrolled workload and through `/attributes/environment/oauth_client_id` |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the native task registry entry for the renewal task |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Native delegation and task registry: whether this agent can act for this principal on the renewal task |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the CRM resource-server gateway; the authorization server keeps issuing tokens |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | The CRM API, which executes the read under the principal and client established by the validated access token |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for the token's principal, the renewal task, and the read of customer `C-481`. The check returns `PASS` only when the executor that will run the read equals that class and binding. `authorize_native` is invoked with the token's principal, never with the executor's own authority.

Adversarial results (Section 17.5):

- A token subject other than the presented principal: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- A token of another client while the presentation names the agent enrolled for the first: `resolve_agent_binding` answers `UNKNOWN` and reports the agent enrolled for another workload, and the validator refuses with `CONTEXT_MISMATCH` (integration profile rules OAUTH-38 and OAUTH-40).
- The read presented under a task other than the renewal task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The delegation for the renewal task is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- A controlled connector would call the SaaS with a broader credential than the token's: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`. Unavailable introspection ends earlier, at `authenticate_native`, with `DEFERRED` and `DEPENDENCY_UNAVAILABLE` (integration profile rule OAUTH-9).

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this without exception for the native denial of a scope or entitlement refusal. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`. An inactive or expired token yields no `OutcomeReport`.

## Exchange

1. Through the existing OAuth authorization flow, the client obtains the token appropriate to its authority. A delegated interactive deployment can use authorization code with PKCE; this sample assumes that flow has completed and any required consent exists.
2. The assistant requests requirements, authenticating with the token. The gateway introspects it, resolves the principal/client/agent binding, maps the proposed customer read, and issues a signed PACT contract.
3. The assistant signs a presentation containing the required profile, intent, evidence where required, exact operation, contract, and nonce.
4. The protected request carries both artifacts:

```http
GET /customers/C-481 HTTP/1.1
Host: crm-api.example
Authorization: Bearer <opaque-CRM-access-token>
PACT-Presentation: <complete-compact-signed-presentation>
```

5. The gateway establishes token validity under the issuer's rules and configured freshness, verifies all PACT checks, and independently enforces the required scope, native delegation, and customer-record permissions.
6. Only the permitted read executes. The gateway records admission and authorization separately; authorized execution and task-quality observations enter evidence qualification.

An access-token refresh is a native OAuth operation. PACT does not refresh tokens. Any retried protected request uses a fresh contract and presentation as required; it never reuses a consumed nonce. If the refreshed token changes relevant principal, client, scopes, or authority context, the new native facts must satisfy the new evaluation (integration profile rule OAUTH-36). Under the [multi-operation profile](../profiles/multi-operation.md), the retried request is a new operation of the renewal task: it is reserved and counted against the task's budget like the first. A refresh that yields the same principal and client keeps the task's ledger entry; one that yields another principal is refused with `task-mismatch` and changes no counter (rules MO-7, MO-20, MO-28; `TASK-01`, `TASK-07`; its section 13.2).

## Decision examples

| Token and native state | PACT state | Outcome | Profile case |
|---|---|---|---|
| Active, intended for this API, correct scope and customer permission | All required checks pass | Execute | `adapters/oauth/oauth-04.complete`, `adapters/oauth/oauth-16.scope-present` |
| Inactive or expired token | Otherwise valid presentation | Native authentication blocks execution: native denial with `CREDENTIAL_REJECTED`, no `OutcomeReport` | `OAUTH-03`; `adapters/oauth/oauth-13.introspection-expired`, `adapters/oauth/oauth-13.introspection-exp-now` |
| Active token with insufficient read scope | Profile otherwise valid | Block with `insufficient_scope`; PACT does not add scope | `adapters/oauth/oauth-16.introspection` |
| Active read token, customer outside principal's entitlement | Admission may pass its configured checks | Native resource policy denies | None: the CRM permission is native authorization; the adapter returns its decision unchanged (`adapters/oauth/oauth-16.scope-present`) |
| Active token, wrong holder key or request binding | Invalid proof or mismatch | Block | Evaluation cases `admission/old-holder-key` and `admission/modified-resource`; a token bound by `cnf.jkt` to the holder key: `OAUTH-21`, adapter half only |
| Required introspection unavailable | No authoritative token decision | Fail closed: `DEFERRED` with `DEPENDENCY_UNAVAILABLE`; no protected execution | `OAUTH-07` |
| `active: true` with `exp`, `sub`, `client_id`, `scope`, or `aud` absent | Otherwise valid presentation | Native denial; `active` alone never authenticates | `OAUTH-04` |
| Active token for another resource | Otherwise valid presentation | Native denial | `OAUTH-05` |
| Token of another subject, or of another client, than at contract issuance | Contract and presentation of the first | `CONTEXT_MISMATCH` | `OAUTH-19` |
| Refresh token sent as the access token | Otherwise valid presentation | Native denial, under DR3 | `adapters/oauth/oauth-20.introspection` |
| Token in the query or a form body, or two credentials | Otherwise valid presentation | Native denial before introspection | `OAUTH-01`, `OAUTH-02` |
| Direct request to the CRM API that bypasses the gateway | None | Rejected before any token is evaluated | `adapters/oauth/oauth-26.direct-backend`, adapter level only; DR1 has no fixture |

Ordinary OAuth failures retain the API's native error handling. A completed authenticated PACT evaluation has its signed decision; failures before that point do not require fabricating a receipt for an unverified identity.

## Security and integration boundaries

The access token and PACT presentation are different artifacts. The PACT signature proves the enrolled holder key for this request, but it does not change the bearer token's own security properties or implement OAuth DPoP. If the native OAuth deployment requires sender-constrained tokens, those proofs remain independently required.

A third-party SaaS that cannot run the hook can be accessed through a controlled connector with equivalent checks. That connector must preserve downstream authority and bind its translated operation. PACT does not automatically protect direct SaaS calls that bypass it, and a PACT receipt is never sent as a substitute access token.

## Reputation and approval

Successful token validation and admission do not improve task-performance reputation. Only qualified observations contribute. A native access denial is not automatically misconduct. Section 14.5 maps this exchange: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, a scope or entitlement refusal is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, an inactive or expired token is rejected as a “Pre-authentication or transport failure” with no `OutcomeReport`, and only “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`) and an “Independent assessment” (`QUALITY`, `task_quality`) count. Reputation cannot add consent, change a token's audience/scope, or bypass a required external approval.

**PACT anchors:** §§2.3, 4, 6–15, 17–18.

## Standards references

- [RFC 6750 — Bearer token usage](https://www.rfc-editor.org/rfc/rfc6750.html)
- [RFC 7662 — Token introspection](https://www.rfc-editor.org/rfc/rfc7662.html)
- [RFC 9700 — OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700.html)
