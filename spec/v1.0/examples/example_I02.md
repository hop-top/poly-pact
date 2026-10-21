# Integration sample 02 — Microsoft 365 with Entra ID, OIDC, and OAuth

**Status:** Informative integration sample for PACT Protocol v1.0. All organizations, identifiers, routes, and policies are illustrative. HTTP examples contain placeholders and are not executable fixtures. Profile excerpts omit required core fields and signatures; they are not complete wire objects. The adapter configuration below is a deployment design, not a new PACT wire schema.

This example is informative: it does not establish a live integration, interoperability, or an end-to-end security result.


## Assumptions, components, and limitations

Component IDs C01 to C16 are the components of section 4 of the integration profile [template](../profiles/TEMPLATE.md); they are editorial identifiers, not protocol fields or registered reason codes.

### Assumptions

- The custom API registrations, consent, delegated token flow, OBO executor, and Graph permissions are configured.
- Native user/client/agent/task enrollment and a fixed downstream mapping exist.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C02 | Custom-API issuer/tenant/audience/client validation. |
| C04 | User-to-agent task and delegated Graph authority. |
| C08 | Confidential OBO executor that requests token B for Microsoft Graph and never reads or validates it; the gateway checks only the token it receives, token A (`graph` rule GR-8). |
| C15 | Bound pagination and task/retry limits. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Deliberate simplifications and limitations

- Graph itself is not PACT-aware; enforcement is in the custom gateway.
- Other paths and app-only operation need separate native authority; no broader fallback is permitted.

### Profile and fixtures

The integration profile [`oauth`](../profiles/oauth/profile.md) states, as its form E, the conformance claim for the inbound side of this sample: route R2 (`GET /mail/messages`, action `mail.message.list`) under issuer entry E2, token A validated locally against the key set of one pinned tenant (rules OAUTH-19 to OAUTH-33), the principal `oauth:{issuer-id}:{tid}:{oid}` (rule OAUTH-37), the client `azp` as the enrolled workload (rule OAUTH-38), the deployment requirements of its section 4, and the fixture index of its section 10. It claims the inbound authentication and binding of R2 only; the translation to Microsoft Graph, the on-behalf-of executor, and token B are outside it and belong to the integration profile [`graph`](../profiles/graph/profile.md), described in the next subsection. The adapter cases are in [`fixtures/adapters/oauth/`](../fixtures/adapters/oauth/README.md), registered in the fixture manifest under the ids below. They test the adapter against discovery documents and key sets that the harness serves itself, with keys it generates; they are not a live tenant.

| Fixture ID | Token A in this sample | Evidence |
|---|---|---|
| `OAUTH-09` | Valid token of the pinned tenant; another tenant's issuer or `tid`, a v1.0 token, a templated issuer, no `ver` | `adapters/oauth/oauth-09.valid` (control), `adapters/oauth/oauth-09.other-tenant-issuer`, `adapters/oauth/oauth-09.tid-mismatch`, `adapters/oauth/oauth-09.v1-token`, `adapters/oauth/oauth-09.template-issuer`, `adapters/oauth/oauth-09.no-ver` |
| `OAUTH-10` | Token whose audience is Microsoft Graph, another API, or the client | `adapters/oauth/oauth-10.graph`, `adapters/oauth/oauth-10.other-api`, `adapters/oauth/oauth-10.client-id` |
| `OAUTH-11` | Client not in the allowlist; `appid` without `azp` | `adapters/oauth/oauth-11.azp-not-allowlisted`, `adapters/oauth/oauth-11.appid-only` |
| `OAUTH-12` | Algorithm, signature, and key selection; keys named by `jku`, `x5u`, or `jwk` | `adapters/oauth/oauth-12.*`, one case per input |
| `OAUTH-13` | Expired, not yet valid, or over the lifetime bound | `adapters/oauth/oauth-13.jwt-*`, with the control `adapters/oauth/oauth-13.jwt-at-limits` |
| `OAUTH-14` | An ID token sent as token A | `adapters/oauth/oauth-14.client-id-token`, `adapters/oauth/oauth-14.api-id-token` |
| `OAUTH-15` | An app-only token (`roles` without `scp`), an empty `scp` | `adapters/oauth/oauth-15.roles-no-scp`, `adapters/oauth/oauth-15.empty-scp` |
| `OAUTH-16` | Missing consent: `scp` without the gateway's delegated scope | `adapters/oauth/oauth-16.jwt`, with the control `adapters/oauth/oauth-16.scope-present` |
| `OAUTH-18` | Display claims naming Maya while `oid` names another user; no `oid` | `adapters/oauth/oauth-18.display-claims`, `adapters/oauth/oauth-18.no-oid` |
| `OAUTH-19` | A token of another user, client, or tenant at the protected request than at contract issuance | `adapters/oauth/oauth-19.other-subject`, `adapters/oauth/oauth-19.other-client-jwt`, with the controls `adapters/oauth/oauth-19.same-authority` and `adapters/oauth/oauth-19.same-client-binding` |
| `OAUTH-21` | A sender-constrained token (`cnf`) on an entry without a sender constraint | `adapters/oauth/oauth-21.jwt-none-entry-cnf` |
| `OAUTH-22` | Token A in the principal, a denial, or an error | `adapters/oauth/oauth-22.jwt-authenticated`, `adapters/oauth/oauth-22.jwt-denied` |
| `OAUTH-23` | Discovery and key set of the pinned tenant only; key-set outage and rollover | `adapters/oauth/oauth-23.*` |
| `OAUTH-27` | A field rule over `client_app_id` | `adapters/oauth/oauth-27.client-claim`: never `ADMISSIBLE` (see "Gateway profile mapping") |

### Graph profile and fixtures

The integration profile [`graph`](../profiles/graph/profile.md) states, as its form D, the conformance claim for the downstream side of this sample. It covers two rows of the custom gateway: GD1 (`GET /mail/messages` with the query exactly `$select=id,subject,body&$top=10`, action `mail.message.list`, resource `mailbox:{principal_id}`) and GD2 (the continuation of a page by `page_token`). The executor is the gateway application acting for the user. It exchanges the token A of the request in the on-behalf-of flow for token B with the single scope `https://graph.microsoft.com/Mail.Read` (rules GR-5 to GR-7) and makes one downstream request, `GET /v1.0/me/messages` with the same constant query (rules GR-2 and GR-23). The check `execution-identity-v1` returns `PASS` only for the executor class `delegated-user` (rule GR-26), and no failure of the exchange or of the read is followed by another credential (rule GR-11). The profile also states the deployment requirements DR1, DR2, DR4, and DR5 of its section 4 and the fixture index of its section 10. Its inbound side is the form E of the `oauth` profile above; its form A is sample [I08](example_I08.md), and the cases `GRAPH-11` to `GRAPH-17` belong to that form.

The adapter cases are in [`fixtures/adapters/graph/`](../fixtures/adapters/graph/README.md), registered in the fixture manifest under the ids below. A case file calls one adapter function and never requests a token or calls Graph, so the Evidence column also names the unit cases, which are Go tests of the adapter package against an in-process token endpoint and an in-process Graph over TLS. Neither is a live tenant.

| Fixture ID | Exchange of this sample | Evidence |
|---|---|---|
| `GRAPH-01` | Step 4's query changed: `$search`, `$filter`, `$top=11`, a percent-encoded `$`, options reordered, `$orderby`, an extra parameter, or no query | `INVALID_MESSAGE`, no token request, no Graph request: `adapters/graph/graph-01.search`, `adapters/graph/graph-01.filter`, `adapters/graph/graph-01.top-eleven`, `adapters/graph/graph-01.encoded-dollar`, `adapters/graph/graph-01.reordered`, `adapters/graph/graph-01.orderby`, `adapters/graph/graph-01.extra-parameter`, `adapters/graph/graph-01.no-query`, with the control `adapters/graph/graph-01.exact-query` |
| `GRAPH-02` | Step 7: a path, query parameter, or header naming another user or mailbox; an executor binding that names a mailbox | `adapters/graph/graph-02.other-user-path` (no row selected), `adapters/graph/graph-02.user-parameter` (`INVALID_MESSAGE`), `adapters/graph/graph-02.mailbox-header` (mapped: a header changes nothing and the resource stays the user's own mailbox), `adapters/graph/graph-02.binding-names-mailbox` (`FAIL`, `EXECUTOR_MISMATCH`); the constant downstream path and the one `Authorization` field are the unit case `GRAPH-08.token-a-not-forwarded` |
| `GRAPH-03` | Step 6: a token for Microsoft Graph sent as token A | Refused by the `oauth` profile (rule OAUTH-27; `adapters/oauth/oauth-10.graph`) and never sent as an OBO assertion: unit case `GRAPH-03.graph-token` |
| `GRAPH-04` | Step 6: the token endpoint answers the OBO request with an interaction requirement, with or without a claims challenge | Unit cases `GRAPH-04.interaction-required` and `GRAPH-04.interaction-no-claims`: one OBO request, no app-only request, no Graph request, 401 with the challenge in `WWW-Authenticate`; the signed report is `adapters/graph/graph-20.denial-report` |
| `GRAPH-05` | Step 6: Maya's consent withdrawn, her account disabled, or the token endpoint unavailable | Unit cases `GRAPH-05.consent-withdrawn`, `GRAPH-05.user-disabled`, and `GRAPH-05.endpoint-unavailable`: no downstream request, no fallback; an unavailable endpoint yields no `SUCCESS` report |
| `GRAPH-06` | A switch to app-only access after a failed exchange | `adapters/graph/graph-06.binding-client-credentials`, `adapters/graph/graph-06.binding-grant-only`, `adapters/graph/graph-06.binding-other-app` (`FAIL`, `EXECUTOR_MISMATCH`), with the control `adapters/graph/graph-06.delegated-binding`; unit cases `GRAPH-06.obo-request` and `GRAPH-06.no-token-reuse` |
| `GRAPH-07` | Step 6: the OBO response's `scope` lacks `Mail.Read`, adds `Mail.ReadWrite`, or is absent | Unit cases `GRAPH-07.scope-lacks-mail-read`, `GRAPH-07.scope-adds-readwrite`, and `GRAPH-07.no-scope`: token B is not used and nothing is executed |
| `GRAPH-08` | Step 8: Graph refuses the read | Unit case `GRAPH-08.graph-refuses`: a native denial, final, with no retry and no other credential |
| `GRAPH-09` | Step 8: a next page requested with a `page_token` that is unknown, outside its grammar, or recorded for another principal, route, or mapping version, or whose recorded link names another host, path, or drops the pinned `$select` | `adapters/graph/graph-09.unknown-token`, `adapters/graph/graph-09.token-grammar` (`INVALID_MESSAGE`), `adapters/graph/graph-09.other-principal`, `adapters/graph/graph-09.other-row`, `adapters/graph/graph-09.other-version`, `adapters/graph/graph-09.other-host`, `adapters/graph/graph-09.other-path`, `adapters/graph/graph-09.dropped-select` (the others `CONTEXT_MISMATCH`); another task and another agent are the unit cases `GRAPH-09.other-task` and `GRAPH-09.other-agent` |
| `GRAPH-10` | Step 8: a next page under its own contract, and the first page's receipt presented again | The control `adapters/graph/graph-10.continuation` (admitted as a new operation); unit cases `GRAPH-10.next-page` (own operation id, new exchange, the recorded link sent unchanged) and `GRAPH-10.link-other-host`; the refusal of the reused receipt is the validator's (draft Section 11.5) |
| `GRAPH-18` | The authority reference absent, unknown, for another task, expired, or revoked | No case yet: `native-delegation-v1` runs over the deployment's task registry, and how its reference reaches the check waits for the delegation binding model (profile open item OI-1) |
| `GRAPH-19` | A presentation naming a principal other than the authenticated user | Not an adapter case: `native-principal-binding-v1` is evaluated by the validator (draft Section 17.5) |
| `GRAPH-20` | The `AUTHORIZATION` and `EXECUTION` reports of an executed operation | `adapters/graph/graph-20.execution-report`, `adapters/graph/graph-20.denial-report`; unit cases `GRAPH-20.both-actors` and `GRAPH-20.empty-page` |
| `GRAPH-22` | The executor registry cannot answer; Graph throttles the read | `adapters/graph/graph-22.registry-unavailable` (`UNKNOWN`, `DEPENDENCY_UNAVAILABLE`); unit case `GRAPH-22.throttled` (one attempt, then 503 with `Retry-After`) |

A forbidden query gets no trusted personalized contract (case `GRAPH-21`, shown for form D by the `GRAPH-01` files); contract issuance is the gateway's.

### Limitations and open points

Open in every example: the enforced integration scope; native identity and the enrolled agent and key mapping; exact request binding and native translation; achievable source freshness and execution-time rechecks; native outcome and visibility mappings; executed end-to-end conformance evidence; privacy, retention, correction, and lineage operations; and transport, latency, capacity, and outage budgets. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Open points specific to this example:

- Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check.
- Define token, refresh, consent, interaction, and sender-proof handling. Specified for token A (form E, a Microsoft Entra ID v2.0 access token) by the integration profile [`oauth`](../profiles/oauth/profile.md); its requirement coverage table ties each item to rules and case groups.
- Publish the Graph OBO/resource/grant profile. Specified for the delegated half by the integration profile [`graph`](../profiles/graph/profile.md), form D (rows GD1 and GD2); its requirement coverage table ties each item to rules and cases. The app-only half is sample [I08](example_I08.md).
- Preserve task and page scope across exchanges. Specified across operations by the [multi-operation profile](../profiles/multi-operation.md), whose requirement coverage table (section 12) ties each item to rules and to the cases `TASK-01` to `TASK-09`, and whose section 13.1 works this sample: each page, the first included, reserves one operation and one page of the native task's budget, a new listing counts again, a continuation presented under another native task is refused with `CONTEXT_MISMATCH` before any reservation (rules MO-55 to MO-58; `TASK-04`), and a fresh contract resets no counter (rule MO-20; `TASK-01`). The Graph profile binds each continuation to the task, principal, agent, and route (rule GR-24; `GRAPH-09`, `GRAPH-10`) and reserves each page in that profile's task ledger (its component C15; open item OI-4, closed).

The `oauth` cases above cover wrong audience, tenant, and client, and missing consent as a missing delegated scope, at the adapter. The `graph` cases cover interaction requirements, OBO failure, and mutated query, mailbox, and page targets at the adapter and at the unit tier, against fakes. These remain unvalidated:

- A live tenant for the exchange and for Graph. The `graph` profile leaves these to probes, none of which was run: the error the token endpoint returns for missing or withdrawn consent (`graph` probe P2), the spelling of `Mail.Read` in the OBO response's `scope` and whether it lists other consented scopes (P3), whether declaring the client capability `cp1` changes the lifetime of token B (P8), and the path and option encoding of the `@odata.nextLink` that Graph returns for `/me/messages` (P1; a link that fails the comparison disables paging for this form).
- Graph's own decision on token B: the cases test the mapping, the executor check, and the reports, not what Graph allows (rule GR-3).
- The deployment requirements of the `graph` profile: the gateway application has no custom signing key and is the audience of token A (`graph` DR1), its Graph delegated permissions are `Mail.Read` only with consent recorded (DR2; a machine check is probe P6), the exchange credential is held in a protected store the agent cannot read (DR4), and egress is limited to Graph and the token endpoint (DR5).
- The authority reference and its registry (`GRAPH-18`), which wait for the delegation binding model (open item OI-1 of the profile).
- The page and retry budgets across operations against a real task registry. The multi-operation profile specifies them, and its cases (`TASK-01`, `TASK-04`) are tests of a Go package of the source repository against a fake registry and a fake native service, not fixture cases. A deployment still supplies the task registry, a ledger shared by every replica (multi-operation rule MO-17), and the limits of each task (rule MO-15). Whether Graph's caveat on the token of a retried page applies to message listings is to probe (multi-operation probe P5).
- A draft Section 14.5 row for a token endpoint that cannot be reached after admission, and for a Graph throttling answer; the profile sends no `SUCCESS` report for either (open item OI-3).
- The live tenant's application registration: `requestedAccessTokenVersion` 2 and no custom signing key (`oauth` deployment requirement DR6).
- Token facts of the live tenant that the `oauth` profile leaves to probes: `oid` and `tid` without the `profile` scope (`oauth` probe P1), the meaning of `iat` (P2), the Application ID URI as audience (P3), sender-constrained tokens (P4), the signing algorithms of access tokens (P5), and the lifetime of tokens under continuous access evaluation (P7).
- Key rollover against the tenant's published key set; the cases use keys that the harness generates, and the refresh every `K` is a Go test of the adapter package.
- Network policy that closes the gateway's API to every other caller (`oauth` DR1) and HTTPS-only listeners (`oauth` DR2).
- Token exclusion from the deployment's own logs and telemetry; `OAUTH-22` covers the adapter's results only.

Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Scenario and placement

Maya asks an enrolled mail assistant to summarize messages in her Microsoft 365 mailbox. A custom PACT-aware mail gateway exposes the assistant's protected API and calls Microsoft Graph on Maya's behalf.

This example introduces PACT in that custom gateway. It does not assume that Entra ID or Microsoft Graph natively understands PACT contracts, profiles, or receipts. The downstream call uses Microsoft's ordinary authorization mechanisms.

## Which mechanism does what?

| Mechanism or artifact | Purpose in this sample |
|---|---|
| OpenID Connect (OIDC) and an ID token | Establish Maya's sign-in to the client application |
| OAuth access token A | Authorize a delegated call to the custom mail gateway; its audience is that gateway's API |
| PACT presentation | Supply agent identity/key proof, required profile facts, evidence, intent, and exact request binding |
| Entra on-behalf-of (OBO) flow | Let the gateway obtain a separate delegated access token for Graph |
| OAuth access token B | Authorize the gateway's downstream Graph call; Graph is its intended resource |
| PACT admission receipt | Record admission for the gateway request; never substitute it for token A or B |

ID tokens establish authentication for their intended client; use access tokens to call protected APIs. Under form E of the [`oauth`](../profiles/oauth/profile.md) profile, which this sample uses, the gateway validates only access tokens intended for its API; that profile's form G, where a Google ID token is the credential, is not used here. Microsoft documents the token distinction, [API claims validation](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation), and [OBO](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow).

## Application setup and enrollment

Register the interactive client and custom gateway API in Entra ID. Configure the gateway's delegated API scope, such as the sample-defined `MailSummary.Read`, and the downstream delegated Graph permission required for message bodies, `Mail.Read`. Obtain the applicable consent through Entra's normal process. The application uses a supported identity library for authorization-code sign-in with PKCE and, when needed, OIDC scopes.

Enroll the assistant separately. Bind its stable PACT agent identity and public holder key to an approved operator, allowed client application, and recognized native task/delegation context. A user's successful Entra sign-in does not establish which agent may act for that user.

## Gateway profile mapping

| Required profile fact | Authoritative source | Integration profile |
|---|---|---|
| `/attributes/environment/principal_id` | Gateway mapping of validated tenant ID and user object ID into a tenant-qualified principal | `/oauth/principal_id`: `oauth:{issuer-id}:{tid}:{oid}` (rule OAUTH-37), compared by `native-principal-binding-v1` (rule OAUTH-39) |
| `/attributes/environment/tenant_id` | Validated token's `tid`, restricted to the configured tenant | `/oauth/tenant_id`; the tenant is pinned by `authenticate_native` (rule OAUTH-26) |
| `/attributes/environment/client_app_id` | Validated token's `azp`; the profile accepts v2.0 tokens only and never reads `appid` | `/oauth/client_id`, in namespaced form; the client is allowlisted (rule OAUTH-30) and is the enrolled workload (rule OAUTH-38) |
| `/attributes/delegation/authority_ref` | Gateway's native task/delegation registry, binding this user, agent, purpose, and permitted task | Outside the profile's rules: `native-delegation-v1`, supplied by the deployment (C04) |
| `/attributes/runtime/isolation` | Evidence from an approved runtime issuer | Outside the profile's rules; attested-only, because no containment control is claimed (C16) |

The gateway validates signatures, issuer, expected audience, time bounds, tenant, subject, authorized calling application, and required delegated scope (integration profile rules OAUTH-19 to OAUTH-31). It does not use an email address as the authorization key or accept arbitrary profile values as Entra facts (rule OAUTH-33).

Under the integration profile, a field rule over a fact of token A cannot pass: an Entra ID v2.0 access token has no status mechanism in wire version 0.1, so a matching value is `DEFERRED` with `UNSUPPORTED_REQUIREMENT` and a differing one is `INADMISSIBLE` (profile section F, open item OI-1; case `OAUTH-27`). Until that item is resolved, the tenant and client rows above are enforced by `authenticate_native` and the client's enrollment, and the principal row by `native-principal-binding-v1`, not by field rules over the token. Token claims are snapshots: any requirement for fresher membership facts needs an authoritative lookup that can actually meet the demanded age.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the mail assistant, bound to an approved operator, an allowed client application, and a recognized native task and delegation context (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: access token A validated by the gateway, with tenant and user object ID mapped to a tenant-qualified principal (Section 17.1; integration profile rule OAUTH-37); the authorized client is bound separately, as the enrolled workload (rule OAUTH-38) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the gateway's native task registry for the mailbox-summary task |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | The gateway's native task and delegation registry, binding this user, agent, purpose, and permitted task; Entra consent for the delegated Graph permission stays native |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the custom mail gateway, whose confidential-client credential authenticates the gateway to Entra and is not a delegation |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | The gateway's on-behalf-of exchange, which yields access token B so that Graph executes under Maya's delegated authority (integration profile `graph`, rule GR-26) |

The installed `execution-identity-v1` mapping declares the class `delegated-user`, realized through the OBO flow, for Maya, the mailbox-summary task, and the approved Graph read. The check returns `PASS` only when the executor that will run the Graph call equals that class and binding. `authorize_native` is invoked with Maya as the principal, never with the gateway's own authority.

Adversarial results (Section 17.5):

- A user or tenant other than Maya's presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`, because the principal names both (integration profile rules OAUTH-37 and OAUTH-39).
- A token of another client while the presentation names the agent enrolled for Maya's client: `resolve_agent_binding` answers `UNKNOWN` and reports the agent enrolled for another workload, and the validator refuses with `CONTEXT_MISMATCH` (rules OAUTH-38 and OAUTH-40).
- The read presented under a task other than the registered mailbox-summary task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The user-to-agent delegation is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE` (integration profile `graph`, rule GR-27; no case yet, `GRAPH-18`).
- A switch to more privileged app-only Graph access after missing consent or an interaction requirement: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH` (integration profile `graph`, rules GR-11 and GR-26; `adapters/graph/graph-06.binding-client-credentials`).
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED` (an executor registry that cannot answer: `adapters/graph/graph-22.registry-unavailable`).

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample, including the report for each page, references in `evidence_refs` an immutable native record identifying the actual executor identity. Section 14.2 states this without exception for a downstream Graph refusal. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`. The integration profile `graph` has every report name both actors and reference the executor record (rule GR-29; `adapters/graph/graph-20.execution-report`, `adapters/graph/graph-20.denial-report`).

## Exchange

1. Maya signs in through the existing Entra flow. The client acquires access token A for the custom gateway API, with the delegated scope needed for the requested gateway operation.
2. The agent requests a PACT contract using token A. The gateway authenticates the request, resolves the allowed user/client/agent/key relationship, and derives the proposed operation and task context.
3. The gateway issues its signed, short-lived requirement contract. The assistant obtains required evidence and signs a complete presentation.
4. The assistant submits the protected gateway request:

```http
GET /mail/messages?$select=id,subject,body&$top=10 HTTP/1.1
Host: mail-gateway.example
Authorization: Bearer <access-token-A-for-mail-gateway>
PACT-Presentation: <complete-compact-signed-presentation>
```

5. The gateway verifies token A and all PACT requirements, including the exact query and native delegation. Its configured purpose check confirms this read fits the mailbox-summary task. The gateway evaluates its own native policy for the request.
6. If permitted, the gateway authenticates itself to Entra and uses the OBO flow to obtain token B for Graph with the required consented delegated permission. The gateway's confidential-client credential authenticates the gateway; it does not replace Maya's delegated authority. Under the integration profile [`graph`](../profiles/graph/profile.md), the gateway application, which is the audience of token A, makes one exchange for each admitted operation from that operation's own token A, with the single scope `https://graph.microsoft.com/Mail.Read`; the gateway checks only the response's `scope` and never reads token B (rules GR-5 to GR-8; `GRAPH-06`, `GRAPH-07`).
7. The gateway maps the approved request to the configured Graph operation (row GD1 of the profile, whose query must equal the constant, rules GR-2 and GR-23; `GRAPH-01`, `GRAPH-02`) and sends:

```http
GET /v1.0/me/messages?$select=id,subject,body&$top=10 HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer <access-token-B-for-Microsoft-Graph>
```

8. Graph makes its own authorization decision. The gateway returns data only if all applicable decisions permit it. Graph's refusal is a native denial and is final: no retry and no other credential (rules GR-3 and GR-11; `GRAPH-08`). Pagination requires separately bound operations; a first-page receipt does not admit arbitrary later requests. Each next page follows only a continuation that the gateway recorded for this task, principal, agent, and route, and the recorded link is sent unchanged (rule GR-24; `GRAPH-09`, `GRAPH-10`). Under the [multi-operation profile](../profiles/multi-operation.md), each page is also an operation of the native task: it reserves one operation and one page of the task's budget before token B is requested, its answer is released only within the task's remaining bytes, and a continuation is followed only under the native task it was recorded for (rules MO-21, MO-55, MO-56, MO-59; `TASK-04`). A read that Graph throttles ends its operation; a retry is a new operation under a new contract, counted against the same budget (rule MO-34).

The adapter fixes the allowed Graph origin, path/query translation, user context, and semantic headers. No model-selected arbitrary URL or extra downstream action may be smuggled into the approved request. Missing consent, interaction requirements, or downstream denial are handled through the native flow; they never trigger a switch to more privileged app-only access (rules GR-10 and GR-11; `GRAPH-04` to `GRAPH-06`).

## Token and credential boundaries

Do not send token A to Graph or accept a Graph-audience token as authentication to the custom API (integration profile rules OAUTH-27 and OAUTH-36; case `adapters/oauth/oauth-10.graph`). Do not attempt to validate Graph tokens using the custom API's token rules (rule OAUTH-19). Graph receives token B; the gateway's PACT evaluation is its own enforcement responsibility.

Do not place ID tokens, access tokens, refresh tokens, client credentials, or signing private keys in PACT profiles or outcome logs (rule OAUTH-35; `OAUTH-22` covers the adapter's results). An Entra ID token is not itself a core PACT `Evidence` object; a native comparison or explicitly defined trusted adapter supplies the required integration. An ID token sent as token A is refused (rule OAUTH-32; `OAUTH-14`); the validator's refusal of one placed in a presentation's evidence array is an artifact-type check with no case yet.

## Delegated versus autonomous app-only operation

| Model | Native authority | Graph profile |
|---|---|---|
| This delegated sample | User context and the app's consented delegated permissions, subject to Graph's rules | Form D: rows GD1 and GD2, executor class `delegated-user`, token B by the on-behalf-of exchange |
| App-only variant | The application's explicitly granted application permissions, without a signed-in user | Form A: rows GA1 and GA2, executor class `registered-app-executor`, token B by the client credentials grant; see sample [I08](example_I08.md) |

An app-only variant requires its own native application identity, enrollment mapping, requirements, and Graph request design. It does not inherit Maya's user permissions, and the user-based OBO flow in this sample cannot simply be reused for app-only authority. The integration profile states the same boundary: no form D row runs under the client credentials grant, no form A row has a `/me` path or a user principal, and neither form borrows the other's rights (rules GR-1, GR-22, and GR-33; `adapters/graph/graph-06.binding-client-credentials`, `adapters/graph/graph-11.workload-on-delegated-route`).

## Reputation, human approval, and limitations

Reputation can adjust only the gateway's preauthorized adaptive requirements. It cannot supply missing consent or waive Graph permissions. A required human approval remains an externally verified native requirement.

Keep admissions, downstream authorization, observed execution, and summary-quality assessments distinct. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, a downstream Graph refusal is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, each page is a separately bound operation and so its own “Execution completed with data returned” report (`EXECUTION`, `SUCCESS`, `reliability`) under that operation's `operation_id` (Section 14.6 collapses the pages of one native task into one independence group), and the summary-quality assessment is an “Independent assessment” (`QUALITY`, `task_quality`). The integration profile `graph` maps its outcomes the same way and records both actors in each report (rules GR-29 and GR-30). A successful Graph response proves neither summary accuracy nor appropriate later use of mailbox content. PACT enforcement covers this gateway path; wider Microsoft 365 controls must address any other access paths.

**PACT anchors:** §§2.3, 4, 6, 8–15, 17–18.

## Official references

- [Microsoft: ID tokens](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens)
- [Microsoft: Access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [Microsoft: Validate API claims](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)
- [Microsoft: Authorization code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft: On-behalf-of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [Microsoft Graph: List messages](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0)
- [Microsoft Graph: Permission types](https://learn.microsoft.com/en-us/graph/permissions-overview)
