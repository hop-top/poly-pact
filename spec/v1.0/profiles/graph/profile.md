# PACT Microsoft Graph delegated and application execution profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose and status

This is the integration profile ([`TEMPLATE.md`](../TEMPLATE.md)) for a custom mail gateway whose admitted operations are executed by calls to Microsoft Graph. It defines two execution forms, each with its own executor, credential, and translation rows:

- **Form D, delegated (on-behalf-of).** The original actor is a signed-in user, authenticated at the gateway by access token A (form E of the [OAuth profile](../oauth/profile.md)). The downstream actor is the gateway's confidential client acting for that user: it exchanges token A in the Microsoft identity platform on-behalf-of (OBO) flow for token B, whose resource is `https://graph.microsoft.com`, under the delegated permission `Mail.Read`. This is the scenario of [`example_I02.md`](../../examples/example_I02.md).
- **Form A, application (app-only).** No user is signed in. The original actor is an enrolled workload, authenticated at the gateway by the workload profile the deployment names. The downstream actor is the executor application registered for that workload, which obtains an app-only token by the client credentials grant and reads one registered mailbox, under an Exchange Online RBAC for Applications assignment whose scope a documented preflight verifies. This is the scenario of [`example_I08.md`](../../examples/example_I08.md).

It answers the open finding G18 of the specification review: original and downstream actors, grants and consent, OBO versus app-only acquisition, mailbox and resource mapping, and parallel grants that defeat a scope. The section "G18 closure map" maps each closure item to the rules and to the cases `GRAPH-01` to `GRAPH-22` of section 10. The machine-readable form is [`profile.json`](profile.json).

The profile adds no wire field and no protocol requirement. Where it and [`draft.md`](../../draft.md) differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. The rules GR-1 to GR-34 are normative for a claim made under this profile and are language-neutral. Shared rules are not repeated: identifiers, enrollment, and lifecycle are in [`identity-mapping.md`](../identity-mapping.md) (IM-1 to IM-29), request binding and downstream translation are in [`request-binding.md`](../request-binding.md) (RB-1 to RB-64), observation and status times are in [`freshness.md`](../freshness.md), and inbound token validation for form D is in the [OAuth profile](../oauth/profile.md) (OAUTH-1 to OAUTH-40). A rule below can be stricter than those documents, and none is weaker.

Every statement about Microsoft Entra ID, Microsoft Graph, or Exchange Online has one of three bases. A label in square brackets, such as [M1], cites a Microsoft Learn page read for this profile on 2026-10-18; the section "Sources" lists each one. *Profile* marks a requirement this profile places on the adapter or the deployment; it is a rule, not a statement about Microsoft services. *To probe* marks a fact that the pages read did not establish; the section "Open items and probes" names the probe, and every rule that rests on one fails closed whichever way the probe comes out. No statement here describes a Microsoft service from memory.

Section 10 lists the cases and where each is shown: the case files of `spec/v1.0/fixtures/adapters/graph/`, registered in the manifest and listed in the `fixtures` array of `profile.json`, and an implementation's unit tier. Until an implementation passes them, this profile cannot support an enforced-support claim (draft §4.4, §22.1).

**Textual dependency.** The delegation binding model of finding G03 (how agent, principal, task, native delegation, broker, and downstream actor are bound) is being specified separately. Until it lands, `/attributes/delegation/authority_ref` is an opaque reference that this profile validates against the native task registry only (GR-27); this profile gives it no structure and draws no conclusion from its text.

## Profile header

| Field | Value |
|---|---|
| Profile name | `graph`: Microsoft Graph execution of admitted mail reads, delegated (OBO) and application (app-only) |
| Target product and version | Microsoft Graph REST API `v1.0` at `https://graph.microsoft.com`, operation "List messages" [M5]; Microsoft identity platform v2.0 token endpoint of one pinned tenant at `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, OBO flow [M1] and client credentials grant [M2]; Exchange Online RBAC for Applications [M8]. Microsoft documentation carries no release number: the pages of the section "Sources" were read on 2026-10-18, and a deployment records the date on which it re-reads them |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `r1`, 2026-10-18 |
| Maintainer | PACT adapter maintainers |
| Reference documents | draft = [`draft.md`](../../draft.md); inbound token rules = [OAuth profile](../oauth/profile.md); identity rules = [`identity-mapping.md`](../identity-mapping.md); request binding = [`request-binding.md`](../request-binding.md); freshness rules = [`freshness.md`](../freshness.md); scenarios = [`example_I02.md`](../../examples/example_I02.md), [`example_I08.md`](../../examples/example_I08.md) |
| Mapping revision | `pact-graph-1`: the mapping rows, translation rows, executor bindings, preflight, and recording rules below, used by both adapter entries of section 1 |

## Terms

| Term | Meaning in this profile |
|---|---|
| Token A | The delegated access token for the gateway's own API that the agent's client presents (form D). Its validation is OAUTH-19 to OAUTH-33 of the OAuth profile. |
| Token B | The access token for Microsoft Graph that the executor obtains: by OBO in form D, by client credentials in form A. The gateway never reads or validates it (GR-8). |
| Executor | The component of the gateway that obtains token B and sends the one downstream request of a translation row. It holds the downstream credential; no other component does. |
| Executor binding | The configured record that fixes, per mapping row, the executor identity class of draft §17.5, the Entra application that acts downstream, the token request, and, in form A, the registered mailbox. It changes only through the gateway's administrative controls (draft §4.2). |
| Executor registry | The configured, authoritative store of executor bindings (C04, C08). |
| Gateway application | The Entra application registration of the gateway's API: the audience of token A and the confidential client of the OBO request (GR-5). |
| Executor application | In form A, the Entra application registered for exactly one workload, whose service principal holds the Exchange RBAC assignment (GR-13). |
| Registered mailbox | In form A, the mailbox, named by its directory object ID, that the executor binding pins for the workload (GR-14). |
| Preflight | The procedure of section C that verifies, for an executor application, that the Exchange RBAC scope exists and covers the registered mailbox and that no parallel unscoped grant exists (GR-16 to GR-21). |
| Auditor identity | The identity that runs the preflight. It is never the executor application and never the gateway application (GR-17). |
| Continuation record | The gateway's record of an `@odata.nextLink` returned by Graph, bound to task, principal, agent, row, and mapping version (RB-57; GR-24). |

## Rules

### A. Forms and scope

**GR-1. Two forms, fixed per row.** Each mapping row of section 2 belongs to exactly one form, and its executor binding names the executor identity class of draft §17.5: `delegated-user` for form D rows, `registered-app-executor` for form A rows. No request data, AgentProfile attribute, token, or Graph response selects the form or the class. The rows of one form never execute under the other form's credential. *Basis: draft §17.5; RB-53; profile.*

**GR-2. One downstream operation.** Each row has exactly one downstream request: `GET` of the Graph "List messages" operation at a constant path [M5], with a constant query. No enrichment read, no `$batch` request, no other Graph operation, and no write is made for any row (RB-54). The executor sends no request to Graph other than that request and, for a continuation row, the recorded link (GR-24). *Basis: RB-54; profile.*

**GR-3. Graph is not PACT-aware.** Graph makes its own authorization decision on token B and the mailbox [M4, M5]; it receives no presentation, receipt, or admission attestation (RB-51), and nothing in this profile depends on Graph understanding PACT. A Graph refusal is a native denial and is final (draft §2.3). *Basis: example I02 ("Graph itself is not PACT-aware"); draft §2.3; RB-51.*

**GR-4. Tenant and endpoints are configuration.** The tenant of the token endpoint, the Graph origin `https://graph.microsoft.com`, and the token endpoint `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` [M1, M2] are constants of the executor binding, with the tenant GUID of the OAuth issuer entry for form D. A redirect from either endpoint is not followed. Network paths use TLS (draft §19). *Basis: RB-48; profile.*

### B. Form D: delegated execution by on-behalf-of

**GR-5. The gateway application is the OBO client.** The OBO request is made by the gateway application, whose application (client) ID is the audience of token A: the `assertion` of an OBO request "must have an audience (`aud`) claim of the app making this OBO request", and an application cannot redeem a token for a different app [M1]. Token A is therefore validated first by the OAuth profile (OAUTH-27 pins `aud` to the gateway application), and a token for Microsoft Graph or another resource sent to the gateway is refused there and never used as an assertion; Microsoft states that such a token "should instead" be rejected [M1]. *Basis: [M1]; OAUTH-27.*

**GR-6. The OBO request.** The executor sends `POST` to the tenant's token endpoint with `grant_type` `urn:ietf:params:oauth:grant-type:jwt-bearer`, `client_id` the gateway application, client authentication by `client_secret` or by `client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion` signed with the registered certificate, `assertion` the token A of the request being executed, `requested_token_use` `on_behalf_of`, and `scope` [M1]. The `scope` is the single value `https://graph.microsoft.com/Mail.Read`; `offline_access` is not requested, so no refresh token is issued [M1], and `.default` is not used. Which client authentication is used is a constant of the executor binding. *Basis: [M1]; profile.*

**GR-7. One exchange per operation.** Token B is obtained for each admitted operation from the token A that the operation's own request carried, and is used for that operation's one downstream request only. It is never reused for another operation, another page, another principal, or another agent. *Basis: profile (reference configuration; no token cache).*

**GR-8. Token B is opaque.** The gateway never decodes, validates, or reads claims of token B: Microsoft states that tokens for an API the caller does not own are not to be validated or read, may use a format that does not validate as a JWT, and may be encrypted [M1, M2]. The executor checks only the token response: `token_type` `Bearer`, an `access_token`, an `expires_in`, and a `scope` member [M1]. The response `scope`, "the scope of access granted in the token" [M1], MUST contain the configured Graph `Mail.Read` scope; its exact spelling in the response is to probe (P3), and a response whose `scope` lacks it, or names any Graph permission other than `Mail.Read`, is not used and nothing is executed (GR-30). *Basis: [M1], [M2]; profile.*

**GR-9. Delegated authority is the user's.** Under a delegated permission "the application can't access anything the signed-in user couldn't access", and the privileges are determined by the permissions the app has been granted *and* the user's own permissions [M4]; in the OBO flow only delegated scopes are used and roles "remain attached to the principal (the user) and never to the application" [M1]. The gateway application holds the Graph delegated permission `Mail.Read` with consent recorded by the user or an administrator [M4] (deployment requirement DR2). Consent is native: PACT never requests, grants, or infers it, and missing consent shows only as a failed OBO exchange or a Graph refusal (GR-11). *Basis: [M1], [M4]; draft §17.3.*

**GR-10. Interaction and claims challenges.** When the token endpoint answers the OBO request with an error such as `interaction_required` and a `claims` value, because a Conditional Access policy such as multifactor authentication applies [M1], nothing is executed. The gateway answers the agent's request with HTTP 401 and a `WWW-Authenticate` field carrying the error and the claims challenge, as Microsoft asks of a middle tier, and the client obtains a new token A through the native flow [M1]. The gateway does not retry with a cached token, does not interact with the user, and does not switch credential. Graph sends claims challenges only to a client that declares the `cp1` capability [M11]; the reference executor declares none, so no Graph claims challenge is expected, and whether declaring `cp1` would change token B lifetime is to probe (P8). *Basis: [M1], [M11]; profile.*

**GR-11. No fallback.** A failed OBO exchange (an error response, a consent error, an interaction requirement, an unreachable endpoint), a token response that fails GR-8, and a Graph refusal of the downstream request each end the operation with no downstream data. None of them is followed by an app-only token, the client credentials grant, another application's credential, a cached token of another operation, or a retry under another identity. Microsoft states that the OBO flow "only works for user principals" and that app-only access uses the client credentials flow instead [M1]; example I02 states that missing consent, interaction requirements, or downstream denial "never trigger a switch to more privileged app-only access". An executor that would run under any other credential is `FAIL` with `EXECUTOR_MISMATCH` (draft §17.5; GR-26). The exact error code of the token endpoint for missing or withdrawn consent is to probe (P2); every error response fails closed. *Basis: [M1]; example I02; draft §17.5.*

**GR-12. Gateway application constraints.** The gateway application has no custom signing key, because applications with custom signing keys "can't be used as middle-tier APIs in the OBO flow" [M1] (DR1; it also matches OAUTH-23, which refuses custom signing keys). The OBO client credential is held only by the executor, in a protected store, and never appears in any PACT artifact or log (draft §19). *Basis: [M1]; draft §19.*

### C. Form A: application execution and the grant preflight

**GR-13. One executor application per workload.** The executor binding of a form A row names, for the authenticated workload, exactly one executor application by its application (client) ID and its service principal object ID [M7, M8]. An executor application is registered for one workload only; an executor binding that names an application already bound to another workload is a configuration error, and no row executes for either workload until an administrator corrects it. The executor application is neither the gateway application nor the workload's own native identity. The workload never chooses its executor: example I08 states that "the agent cannot choose a different application or mailbox". *Basis: example I08; profile.*

**GR-14. Pinned mailbox.** The executor binding names the registered mailbox by the directory object ID of its user, a GUID, which is the `{id}` form of `/users/{id | userPrincipalName}` [M5]; a user principal name is never used (IM-5). The downstream path is the constant `/v1.0/users/{registered-mailbox-id}/messages`. No request data, AgentProfile attribute, task text, or Graph response supplies or changes the mailbox. *Basis: [M5]; IM-5; RB-49; profile.*

**GR-15. The client credentials request.** The executor sends `POST` to the tenant's token endpoint with `grant_type` `client_credentials`, `client_id` the executor application, client authentication by `client_secret`, by a certificate `client_assertion`, or by a federated credential assertion, and `scope` `https://graph.microsoft.com/.default` [M2, M3]. With `.default` the token carries "all the app-level permissions the admin consented to" for Graph [M3]; the response has no `scope` member in the documented examples [M2, M3], so the gateway cannot observe the grants from the response, and the preflight observes them instead (GR-16). No refresh token is issued in this grant [M2]. Token B is held by the executor only, in memory, for at most its `expires_in` [M2], is used only for the rows of this executor binding, and is discarded when a preflight fails (GR-20). The gateway never reads it (GR-8). *Basis: [M2], [M3]; profile.*

**GR-16. Why a preflight is required.** Exchange RBAC for Applications grants "are independent of the unscoped grants in Microsoft Entra ID", the effective permissions are "a union operation on the permissions from Microsoft Entra ID and the permissions assigned in Exchange Online RBAC", and an unscoped `Mail.Read` grant in Entra ID alongside a resource-scoped `Mail.Read` assignment "results in no effective resource scoping" [M8]. An application permission lets an application access "*any* data that the permission is associated with" [M4]. So the scope holds only while no parallel unscoped grant exists, and a PACT profile cannot narrow it by declaration (handoff, I08 row). The claim for a form A row therefore holds only while the latest preflight of its executor application passed (GR-21). *Basis: [M4], [M8]; handoff I08 row.*

**GR-17. Auditor identity.** The preflight runs under the auditor identity: a Graph identity holding `Application.Read.All`, the least privileged permission for reading a service principal's app role assignments [M7], and an Exchange Online identity authorized to run `Test-ServicePrincipalAuthorization` [M9]. It is configured through the gateway's administrative controls, its credentials are never PACT evidence, and it is never used to execute a row. *Basis: [M7], [M9]; draft §4.2.*

**GR-18. Preflight step 1: unscoped Entra grants.** The auditor reads `GET /v1.0/servicePrincipals(appId='{executor-app-id}')/appRoleAssignments` [M7], following every `@odata.nextLink` until none is returned [M6]. Each returned appRoleAssignment carries `appRoleId`, `resourceId`, `resourceDisplayName`, `principalId`, and `principalType` [M7]; app roles assigned to a service principal are its application permissions [M7]. The step passes only when every assignment is in the executor binding's allowlist of (`resourceId`, `appRoleId`) pairs. The reference allowlist is empty: the executor application holds no app role assignment on any resource, so Graph and every other API grant it nothing outside Exchange RBAC. The allowlist never contains a Microsoft Graph app role that grants the row's operation; the application permissions that List messages names are `Mail.ReadBasic.All`, `Mail.ReadWrite`, and `Mail.Read` [M5], and whether any other Graph application permission also grants it is to probe (P5). To classify an allowlist entry, the auditor resolves `appRoleId` against the `appRoles` of the Microsoft Graph service principal, `servicePrincipals(appId='00000003-0000-0000-c000-000000000000')` [M4]. Any assignment outside the allowlist, including one whose role cannot be resolved, fails the step. *Basis: [M4], [M5], [M6], [M7]; profile.*

**GR-19. Preflight step 2: the RBAC scope.** The auditor runs `Test-ServicePrincipalAuthorization -Identity <executor-app-id> -Resource <registered-mailbox>` [M9]. The output lists, per assigned permission, `RoleName`, `GrantedPermissions`, `AllowedResourceScope`, `ScopeType`, and `InScope`; `InScope` is `True` when the permission applies to that mailbox for that service principal [M8, M9]. The step passes only when the output has exactly one row; its `RoleName` is `Application Mail.Read` and its `GrantedPermissions` `Mail.Read` [M8]; its `ScopeType` is a custom recipient scope or an administrative unit scope and not `Organization`, because an assignment of scope type `Organization` is in scope for every mailbox [M9, example 1]; and its `InScope` is `True`. The cmdlet "excludes permissions that might be granted separately in Microsoft Entra ID" [M8], which is why step 1 is required. Whether `ScopeType` values form a closed set, and how a machine reads the output, is to probe (P9); a value the auditor does not recognize fails the step. The cmdlet is available only in the cloud-based service and no REST form of it was found [M9], so a machine reads step 2 from an attestation the operator records when running it: the application ID passed as `-Identity`, the mailbox passed as `-Resource`, the time of the run, and each output row with the five columns as the cmdlet prints them (the format is in the [Graph cases README](../../fixtures/adapters/graph/README.md)). An attestation for another application or mailbox, or older than `P`, leaves the run not completed (GR-21). This is a limit of the claim: step 2 is as current as the operator's last run, and nothing in the gateway can make it more current. *Basis: [M8], [M9]; profile.*

**GR-20. Preflight result and cache window.** The preflight result is `PASS` only when both steps pass; it is recorded with the time step 1 started, the time step 2 ended, the executor application, the registered mailbox, and an opaque reference to the auditor's immutable record of both outputs. Changes to app permissions in Exchange "are subject to cache maintenance that varies between 30 minutes and 2 hours", and the test command bypasses that cache [M8]; app role assignments read through Graph may lag recent grants or removals [M7]. Therefore: (a) a `PASS` that follows a failed or absent result counts only after a settle window `W` = 7200 s, during which every preflight run passes; (b) a failed preflight discards the executor's cached token B and stops every form A row of that executor at once; (c) the preflight repeats every `P` seconds, with reference `P` = 300 s, an illustrative policy choice. *Basis: [M7], [M8]; profile.*

**GR-21. Fail closed on a parallel grant.** For a form A row, `execution-identity-v1` (GR-26) returns `PASS` only when the latest preflight of the executor application is `PASS`, younger than `P`, and past `W`. A preflight that found an assignment outside the allowlist, an RBAC row other than the one GR-19 admits, a scope of type `Organization`, or `InScope` not `True`, shows that the executor's effective authority is broader than, or different from, the declared binding: the check returns `FAIL` with `EXECUTOR_MISMATCH`, nothing executes, and the gateway raises an operator alert. A preflight that has not completed, has failed to run, or is older than `P` makes the check `UNKNOWN` with `DEPENDENCY_UNAVAILABLE`, which yields `DEFERRED` (draft §17.5, §18). A parallel unscoped grant alongside the RBAC scope invalidates the claim; nothing narrows it. *Basis: [M8]; draft §17.5, §18; profile.*

**GR-22. No user context in form A.** No form A row has a `/me` path, a downstream path other than GR-14, or a principal that is a user: there is "no fabricated user principal or user consent" (example I08). App-only access is "without a signed-in user" [M4]. A request whose mapping would need a user context selects no form A row (RB-33). Graph's own response to `/me` under an app-only token is to probe (P4); the claim does not rely on it, because the mapping never produces such a request. A user name or user principal supplied by the agent establishes no delegation (example I08). *Basis: [M4]; example I08; RB-33.*

### D. Translation and paging

**GR-23. Fixed query.** The query of every first-page row, at the gateway and downstream, is the constant `$select=id,subject,body&$top=10`. The gateway request MUST carry exactly that query, octet for octet; a request on the row's path with any other query, including another order, a percent-encoded `$` (`%24`), another `$top`, an added parameter, or any `$filter`, `$search`, `$orderby`, `$expand`, `$skip`, or `$count`, is refused with `INVALID_MESSAGE` (RB-38) and causes no downstream request. The downstream query is the same constant (RB-61, RB-62), so the gateway and Graph receive identical `$select` and `$top`. List messages accepts `$top` between 1 and 1000 with a default of 10 and recommends `$select` [M5]; the selected `body` is returned in HTML unless `Prefer: outlook.body-content-type` is sent [M5], and the row sends no `Prefer` field. *Basis: [M5]; RB-38, RB-61, RB-62; profile.*

**GR-24. Paging is a new operation.** Each next page is its own operation with its own operation context, contract, and presentation (RB-56). When Graph returns `@odata.nextLink`, the gateway records it under RB-57 with the task, principal, agent, row, and mapping version, and returns to the agent a gateway token in the grammar of the row's `page_token` parameter. The continuation row follows the record only when RB-58 holds and, in addition: the recorded link's origin is `https://graph.microsoft.com` and its path is, octet for octet, the downstream path of the first-page row it continues (`/v1.0/me/messages` or `/v1.0/users/{registered-mailbox-id}/messages`); and its query contains `$select` and `$top` with the pinned values. List messages states that the link "includes any query parameters you may have specified in the initial request" and that the `$skip` value is not to be extracted [M5]; Graph paging says to use the entire URL [M6]. The gateway sends the recorded link unchanged (RB-59). Whether Graph returns the same path for `/me/messages` and for `/users/{registered-mailbox-id}/messages`, and how it encodes the pinned options in the link, is to probe (P1); a link that fails either comparison is refused with `CONTEXT_MISMATCH`, and the agent starts again from the first page (RB-58). A receipt for one page never admits another (RB-56; draft §11.5). *Basis: [M5], [M6]; RB-56 to RB-59; profile.*

**GR-25. Headers and throttling.** The downstream request carries only the executor's `Authorization` field with token B and no other client field (RB-51). Graph answers throttling with HTTP 429 and a `Retry-After` field and counts retries against the limit [M10]. The executor makes one downstream attempt per operation; a 429 ends the operation with no data, and the gateway answers the agent with HTTP 503 and the `Retry-After` value. A retry is a new operation under a new contract and presentation, in the same task; budgets across operations are those of the [multi-operation profile](../multi-operation.md): a retry is reserved again and counts against `max_operations` of the native task (MO-34), and each page reserves one operation and one page (MO-55 to MO-58). *Basis: [M10]; RB-54; draft §10.3.*

### E. Actors, checks, and recording

**GR-26. `execution-identity-v1`.** The check is installed for every row (draft §17.5). For the row and the authenticated principal it reads the executor binding and returns `PASS` with `REQUIREMENT_SATISFIED` only when: the binding's class is the row's class of GR-1; in form D, the executor is the gateway application, the token request is the OBO request of GR-6, and the principal of the binding is the authenticated user; in form A, the executor application is the one registered for the authenticated workload (GR-13), the mailbox is the registered mailbox (GR-14), and GR-21 gives `PASS`. It returns `FAIL` with `EXECUTOR_MISMATCH` when the binding names another class, another application, a client credentials request on a form D row, an OBO request on a form A row, or when GR-21 fails; and `UNKNOWN` with `DEPENDENCY_UNAVAILABLE` when the executor registry or the preflight cannot answer. The `CheckOutcome` carries `SourceID` the executor registry and `SourceRef` an opaque reference to the executor binding record, which names both actors (GR-29). `authorize_native` is invoked with the original principal, never with the executor's authority (draft §17.5). *Basis: draft §17.5; profile.*

**GR-27. `native-delegation-v1` and the authority reference.** The contract of every row requires `/attributes/delegation/authority_ref` with source `native` and installs `native-delegation-v1` (draft §8.5, §17.5). Until the delegation binding model of finding G03 lands, the reference is opaque. The check passes only when the native task registry holds a current record under exactly that reference that binds the authenticated principal, the presented agent, the `Intent.task_id`, the row, and the executor binding (in form A, also the executor application and the registered mailbox, as example I08 asks). It returns `FAIL` with `MISSING_FIELD` when the reference is absent, `TASK_MISMATCH` when the record is for another task, row, or mailbox, `STALE_EVIDENCE` or `REVOKED_EVIDENCE` when it is expired or revoked, and `UNKNOWN` with `DEPENDENCY_UNAVAILABLE` when the registry cannot answer (draft §17.5). A reference unknown to the registry is `FAIL` with `TASK_MISMATCH`. The text of the reference is never parsed for meaning. *Basis: draft §8.5, §17.5; profile.*

**GR-28. Principal binding.** `native-principal-binding-v1` is evaluated by the validator (draft §17.5): in form D the principal is the OAuth profile's user principal (OAUTH-37, OAUTH-39); in form A it is the workload principal of the authenticating profile. A user principal presented on a form A row, or a workload principal on a form D row, differs from the authenticated one and is `FAIL` with `CONTEXT_MISMATCH`. *Basis: draft §17.5.*

**GR-29. Both actors are recorded.** Every `AUTHORIZATION` and `EXECUTION` `OutcomeReport` of a row records both actors. Its `details` names the original actor (the principal identifier) and the downstream actor (the class, and the executor application in the namespaced form of section 7), and no other content (draft §19: no raw task content); the `EXECUTION` report of an empty page is the exception, whose `details` is `"empty"` (draft §14.5), and both actors are then in the executor record that its `evidence_refs` references. Its `evidence_refs` references the executor's immutable native record of the downstream request, which holds the executor identity, the Graph `request-id` response field [M3, sample response] when Graph answered, and the time (draft §14.2). The `CheckOutcome` of `execution-identity-v1` carries the executor binding record as `SourceRef` (GR-26) and that of `native-delegation-v1` the task registry record. A report whose executor class differs from the row's class is `UNQUALIFIED` at the receiver (draft §14.2). *Basis: draft §14.2, §19; profile.*

**GR-30. Outcomes of execution.** The outcomes map to draft §14.5 as follows: a Graph refusal of the downstream request, a failed OBO exchange, and a token response that fails GR-8 are "Native denial" (`AUTHORIZATION`, `FAILURE`, `none`), zero weight and not misconduct; a completed page is "Execution completed with data returned", or "Execution completed, zero rows or filtered result" for an empty page, one report per page under that page's `operation_id` (examples I02, I08). A token endpoint that cannot be reached after admission, and a Graph 429, have no row of their own in draft §14.5 (open item OI-3); they produce no `SUCCESS` report. *Basis: draft §14.5; examples I02, I08.*

**GR-31. Credential exclusion.** Token A, token B, the OBO and client credentials request bodies, the token responses, the gateway application's and executor application's credentials, the auditor's credentials, and claims challenge values never appear in an AgentProfile, a receipt, an `OutcomeReport`, a `CheckResult`, an error body beyond the `WWW-Authenticate` field of GR-10, or a log (draft §19; example I02, "Token and credential boundaries"). *Basis: draft §19.*

**GR-32. Native claim.** The approved native path of `read_native_claim` at mapping revision `pact-graph-1` is `/graph/execution_app_id`: for a form A row, the executor application of GR-13 in the namespaced form of section 7, compared with `equal` (draft §8.4); informative profile path `/attributes/environment/execution_app_id` (example I08). `ObservedAt` is the last change of the executor binding and `StatusCheckedAt` the read (IM-10 by analogy; freshness §4.1). On a form D row the path returns `UNSUPPORTED_REQUIREMENT`; any other path does too. A presented value that differs is `INADMISSIBLE` with `INVALID_CLAIM`, and it never changes the executor: the executor comes from the binding, not from the profile. *Basis: draft §8.4, §17.1; profile.*

**GR-33. No borrowed rights.** A form A executor never acts with a user's permissions, and a form D executor never acts with application permissions. No profile attribute, task text, or human name presented by the agent converts one into the other (example I08: "Caller supplies a human's name to imply delegated authority — Does not establish user delegation"). *Basis: examples I02, I08; draft §17.5.*

**GR-34. Results summary.** The results of this profile's conditions use the codes of draft §13.4 and the decisions of draft §11.4.

| Condition | Where | Decision or result | Code | Transport result |
|---|---|---|---|---|
| Gateway query not exactly the row's constant; `$search`, `$filter`, or another option present (GR-23) | `map_operation` | refused | `INVALID_MESSAGE` | 400; no downstream request |
| Path or parameter naming another mailbox or user (GR-14, GR-22) | `map_operation` | no row selected | `UNSUPPORTED_REQUIREMENT` (RB-33) | 422; no downstream request |
| Continuation unknown, or recorded for another task, principal, agent, row, or version; or its link's origin, path, or pinned options differ (GR-24) | `map_operation` | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| Executor binding of another class or application; OBO on a form A row or client credentials on a form D row; preflight found a parallel grant or a wrong RBAC scope (GR-21, GR-26) | `execution-identity-v1` | `FAIL`, `INADMISSIBLE` | `EXECUTOR_MISMATCH` | 403; no execution |
| Executor registry or preflight unavailable, preflight older than `P` or within `W` (GR-20, GR-21) | `execution-identity-v1` | `UNKNOWN`, `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503 |
| Authority reference absent, unknown, for another task, stale, or revoked (GR-27) | `native-delegation-v1` | `FAIL`, `INADMISSIBLE` | `MISSING_FIELD`, `TASK_MISMATCH`, `STALE_EVIDENCE`, `REVOKED_EVIDENCE` | 403 |
| Presented principal differs (GR-28) | validator | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| Presented `execution_app_id` differs (GR-32) | validator | `INADMISSIBLE` | `INVALID_CLAIM` | 403 |
| OBO error with an interaction requirement or claims (GR-10) | execution | native denial after admission | none | 401 with `WWW-Authenticate`; no downstream request |
| Other OBO error, consent missing, token response failing GR-8 (GR-8, GR-11) | execution | native denial after admission | none | 403; no downstream request |
| Graph refuses the downstream request (GR-3) | execution | native denial, final | none | 403; no retry, no other credential |
| Graph 429 (GR-25) | execution | not executed | none | 503 with `Retry-After` |

The inbound conditions of form D (token A, enrollment, scope of the gateway API) are those of OAUTH-40 and are not repeated; those of form A are those of the authenticating workload profile.

## 1. Claim scope

The gateway evaluates PACT in its own request path (draft §4.4) and claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over the `header` presentation transport. It is a partial role implementation (draft §22.1): it claims neither Holder, Reputation, nor Learning. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1, and uses [`request-binding.md`](../request-binding.md) at version 0.1 with the stricter rules GR-23 and GR-24.

This profile authenticates no inbound request itself. Form D rows are authenticated by form E of the [OAuth profile](../oauth/profile.md), whose route R2 is the inbound side of row GD1; on a deployment that claims both, the mapping and translation rows of the mail route are those of this profile, which are stricter than R2 (R2 reads no query; GD1 requires the exact constant query). Form A rows are authenticated by the integration profile of this repository that the deployment names for its workloads, such as the [mTLS profile](../mtls/profile.md); the OAuth profile refuses app-only tokens (OAUTH-31) and cannot authenticate a form A workload.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Holder 0.1`, `PACT Reputation 0.1`, and `PACT Learning 0.1` are not claimed |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced` |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` (`GatewayMetadata.adapters`, draft Appendix A) |
|---|---|---|
| `graph-delegated-obo` | `v1.0` | `pact-graph-1` |
| `graph-app-only` | `v1.0` | `pact-graph-1` |

The adapter `version` names the Graph API version the translation rows call. The mapping revision is a first-party `pact-` token, as the registry records for the other adapters (see the [profiles README](../README.md)).

## 2. Protected routes and actions

Four rows are claimed, two per form. The route patterns follow examples I02 and I08; a deployment that claims other routes lists them in its own profile.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| GD1 | `/mail/messages` with query exactly `$select=id,subject,body&$top=10` | `GET` | `mail.message.list` | `mailbox:{principal_id}`, from the authenticated user principal (RB-40). Form D |
| GD2 | `/mail/messages` with query exactly `page_token={page_token}` | `GET` | `mail.message.list` | `mailbox:{principal_id}`, as GD1; continues a GD1 or GD2 operation of the same task (GR-24). Form D |
| GA1 | `/mailbox/messages` with query exactly `$select=id,subject,body&$top=10` | `GET` | `mail.message.list` | `mailbox:{registered-mailbox-id}`, from the executor binding of the authenticated workload (GR-14). Form A |
| GA2 | `/mailbox/messages` with query exactly `page_token={page_token}` | `GET` | `mail.message.list` | `mailbox:{registered-mailbox-id}`, as GA1; continues a GA1 or GA2 operation of the same task. Form A |

The mapping table at revision `pact-graph-1`, in the form of RB §5.1:

| Row | Method | Path pattern | Path parameters and grammar | Query parameters read | Body | Action | Resources |
|---|---|---|---|---|---|---|---|
| GD1 | `GET` | `/mail/messages` | none | none; the query MUST equal the constant (GR-23) | none | `mail.message.list` | `mailbox:{principal_id}` |
| GD2 | `GET` | `/mail/messages` | none | `page_token`: 22 to 128 of `A`-`Z`, `a`-`z`, `0`-`9`, `-`, `_`; the only parameter | none | `mail.message.list` | `mailbox:{principal_id}` |
| GA1 | `GET` | `/mailbox/messages` | none | none; the query MUST equal the constant (GR-23) | none | `mail.message.list` | `mailbox:{registered-mailbox-id}` |
| GA2 | `GET` | `/mailbox/messages` | none | `page_token`, as GD2 | none | `mail.message.list` | `mailbox:{registered-mailbox-id}` |

- The binding follows draft §10.2 and RB-1 to RB-30; a path with a `.` or `..` segment is refused with `INVALID_MESSAGE`. The `page_token` grammar admits no `.` and has one spelling (RB-34). A query that is neither form of its path is refused with `INVALID_MESSAGE` (GR-23).
- Headers (RB-18): the allowlist is `accept`. No other client field is forwarded (GR-25). The `Authorization` and `PACT-Presentation` fields are never covered (RB-20, RB-21).
- Every row refuses a body (RB-37).

The translation table, in the form of RB §7.1:

| Row | Gateway request | Downstream origin | Downstream method and path | Downstream query | Downstream headers | Body transformation | Actor | Continuation |
|---|---|---|---|---|---|---|---|---|
| GD1 | GD1 | `https://graph.microsoft.com` | `GET /v1.0/me/messages` | `$select=id,subject,body&$top=10`, constant | `Authorization: Bearer` token B only | none | `delegated-user`; token B by OBO from the request's token A under the gateway application (GR-5 to GR-8) | RB-57 record of `@odata.nextLink` (GR-24) |
| GD2 | GD2 | as GD1 | `GET` of the recorded link, unchanged, only if its origin and path are those of GD1 | the recorded link's query | as GD1 | none | as GD1 | as GD1 |
| GA1 | GA1 | `https://graph.microsoft.com` | `GET /v1.0/users/{registered-mailbox-id}/messages` | `$select=id,subject,body&$top=10`, constant | `Authorization: Bearer` token B only | none | `registered-app-executor`; token B by client credentials under the executor application of the workload (GR-13 to GR-15), valid only while GR-21 passes | RB-57 record (GR-24) |
| GA2 | GA2 | as GA1 | `GET` of the recorded link, unchanged, only if its origin and path are those of GA1 | the recorded link's query | as GA1 | none | as GA1 | as GA1 |

Forbidden downstream forms, refused before any downstream request: `/v1.0/users/{other}` on any form D row and any mailbox other than the registered one on a form A row; `/me` on a form A row; `$search`, and every `$filter` (none is in the table); any other path, method, origin, or `$batch`.

## 3. Enforcement points

The five required functions run in request order inside the gateway, and the other four adapter functions of draft §17.1 are listed as supporting rows.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Inherited. Form D: OAuth profile form E (token A, OAUTH-19 to OAUTH-35). Form A: the workload profile the deployment names | IAM owner and adapter owner | Produces the user principal and client workload (form D) or the workload principal (form A) |
| 2 | `map_operation` | Gateway mapping stage, mapping revision `pact-graph-1` | Adapter owner | Rows of section 2; GR-23 and GR-24 |
| 3 | PACT evaluation | In-gateway validator in the same request path | Gateway implementer | `native-principal-binding-v1`, `native-delegation-v1`, `execution-identity-v1` (GR-26 to GR-28) |
| 4 | `authorize_native` | Form D: the gateway API's delegated scope (OAUTH-31) and the gateway's mailbox policy for the user. Form A: the gateway's policy that the workload's executor binding covers the row | Resource owner | Receives the original principal (draft §17.5); a native denial is final (draft §2.3) |
| 5 | Execution | The executor: token B (GR-6 or GR-15), then the one downstream request; Graph decides on its own (GR-3) | Resource owner | Reached only after steps 1 to 4 pass; no fallback (GR-11) |
| support | `resolve_agent_binding` | Inherited from the authenticating profile | Gateway implementer | Enrollment of the agent on the authenticated workload (IM-11) |
| support | `read_native_claim` | Executor registry, path `/graph/execution_app_id` (GR-32) | Adapter owner | Form A rows only |
| support | `check_context` | `native-delegation-v1` over the native task registry; `execution-identity-v1` over the executor registry and the latest preflight | Gateway implementer | `SourceRef` names the registry record (GR-26, GR-27) |
| support | `record_outcome` | Gateway outcome writer, after the native decision and after execution | Gateway implementer | Both actors recorded (GR-29); outcomes per GR-30 |

Token requests to the identity platform, the preflight reads, and executor registry lookups are not downstream requests of a translation row (RB-54); they are lookups of the functions above or of the executor.

## 4. Native dependencies

Thirteen of the sixteen handoff components are used, and each of the other three carries the reason it does not apply.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and filter chain | Gateway implementer | To be supplied |
| C02 | Native authentication and claim adapters | baseline | Form D: the OAuth profile's form E adapter. Form A: the named workload profile's adapter. The executor registry claim of GR-32 | IAM owner and adapter owner | Inherited adapters exist as profiles; the claim reader is `ReadNativeClaim` of the reference implementation, `go/adapters/graph` (source repository) |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry of the authenticating profile; the executor application registrations and their credential lifecycle in Entra ID (example I08) | IAM and security owner | Registry contract exists; executor registration to be supplied |
| C04 | Native delegation and task authority | delegated or task execution | Native task and delegation registry, under the opaque `authority_ref` (GR-27) | Application and IAM owner | Supplied by the deployment; structure waits for finding G03 |
| C05 | Evidence and authoritative status sources | baseline | Executor registry, the preflight result, the task registry, the hold store | Adapter owner | To be supplied |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the read rows declare no external approval; consent is native (GR-9) |
| C07 | Purpose and exact operation mapper | baseline | Mapper at revision `pact-graph-1` and the translation table of section 2 | Adapter owner | The mapper is `MapOperation` of `go/adapters/graph`; the translation rows are `Adapter.Execute` |
| C08 | Native resource executor and authorization | the actual resource operation | The executor (OBO and client credentials), Microsoft Graph, and Exchange Online mailbox authorization including RBAC for Applications | Resource owner | Graph and Exchange exist; the executor is `Adapter.Execute` of `go/adapters/graph`, with one `TokenAcquirer` per adapter: `OnBehalfOf` in form D, `ClientCredentials` in form A |
| C09 | Durable atomic exchange state | baseline | Replay, receipt, and continuation record store shared by every replica | Gateway and platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Gateway outcome writer and the executor's native request records (GR-29) | Resource owner | To be supplied |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | To be supplied; registry only |
| C13 | Revocation and security holds | baseline | Enrollment status, the hold store, the preflight (a failed preflight stops form A rows) | Security and IAM owner | To be supplied |
| C14 | Protected evidence and audit storage | baseline | Access-controlled store of executor records and preflight outputs, holding no token (GR-31) | Security and data owner | To be supplied |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | Continuation records bound to the task (GR-24); one downstream attempt per operation (GR-25); the task ledger of the [multi-operation profile](../multi-operation.md), which reserves each page against the operations, pages, bytes, and deadline of its native task (MO-55 to MO-58, MO-61) | Gateway and platform owner | The ledger is `Config.Tasks` of `go/adapters/graph`, with the pager `NewPager` and the route `ListingRoute`; without one, pages are not budgeted. The task registry and a ledger store shared by every replica (MO-17) are to be supplied |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no containment control is claimed; `runtime.isolation` is attested-only (draft §17.4) |

Deployment requirements. These are conditions the claim depends on that the adapter fixtures cannot observe; a deployer states in writing that each one holds.

| ID | Requirement | Evidence the deployer supplies |
|---|---|---|
| DR1 | The gateway application has no custom signing key and is the audience of token A (GR-5, GR-12) | The registration manifest |
| DR2 | The gateway application's Graph delegated permissions are `Mail.Read` only, with consent recorded by users or an administrator (GR-9) | The registration and its consent records; a machine check is planned (P6) |
| DR3 | Each executor application is registered for one workload, holds no app role assignment outside the allowlist of GR-18, and holds the RBAC assignment of GR-19 with a scope that contains the registered mailbox and no mailbox the workload is not authorized for | The registration, the management scope or administrative unit definition, and the preflight output |
| DR4 | The OBO credential, the executor credentials, and the auditor credentials are held in protected stores readable only by their component, and never by the agent | The store configuration |
| DR5 | The executor reaches only `https://graph.microsoft.com` and `https://login.microsoftonline.com`; the agent's runtime holds no credential for either | Egress policy |

## 5. Alternative and bypass paths

Nine other ways to reach mailbox data are listed: five `closed`, one `equivalently-enforced`, and three `out-of-claim`.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Downstream requests outside the translation table: a model-chosen URL, `/v1.0/users/{other}` in form D, another mailbox in form A, `/me` in form A, `$search`, `$filter`, `$batch`, another operation | `closed` | GR-2, GR-14, GR-22, GR-23; translation constants; cases `GRAPH-01`, `GRAPH-02`, `GRAPH-11`, `GRAPH-12` |
| B2 | A continuation that the agent forges or that points elsewhere: another host, another path, dropped pinned options, another task's record | `closed` | GR-24, RB-58; cases `GRAPH-09`, `GRAPH-10` |
| B3 | Fallback to a broader credential: app-only after a failed OBO, another application's credentials after a native denial, a cached token of another operation | `closed` | GR-7, GR-11, GR-26; cases `GRAPH-04` to `GRAPH-08`, `GRAPH-17` |
| B4 | A parallel unscoped grant that lets the form A executor read mailboxes outside the RBAC scope | `closed` | The claim is withdrawn while it exists: GR-16 to GR-21; cases `GRAPH-14` to `GRAPH-16` |
| B5 | Delegated access to another user's mail through shared folders or mailbox delegation, which Graph allows under delegated permissions [M5] | `closed` | Form D rows have the constant path `/v1.0/me/messages`; no other user is addressed; case `GRAPH-02` |
| B6 | The PACT endpoints of draft §13.2 that require native authentication, such as `POST /pact/v0.1/requirements` | `equivalently-enforced` | Served through the same inherited `authenticate_native` and the same mapping rows; case `GRAPH-21` |
| B7 | The agent's own access to Graph or Exchange with any token its client can obtain | `out-of-claim` | Graph is not PACT-aware (GR-3; handoff I02/I03 row); excluded in section 6 |
| B8 | Use of the gateway application's, executor application's, or auditor's credential outside the gateway | `out-of-claim` | DR4; native credential protection; excluded in section 6 |
| B9 | Other mailboxes inside the RBAC scope of the executor application, reached with its credential outside the translation rows | `out-of-claim` | DR3 bounds the scope; this profile cannot prove scope breadth (OI-5); excluded in section 6 |

## 6. Unsupported forms

The first rows are seeded from the I02/I03 and I08 rows of the handoff "Deliberate design choices" table. The I02/I03 row reads "Custom API hook or constrained connector" as the choice and "PACT enforcement by Graph/every SaaS or protection of bypass routes" as the wider claim not established; the I08 row reads "Explicit scheduled workload and scoped executor" and "Borrowed user rights or mailbox narrowing through profile declaration". The other rows come from the rules and from sections 2 and 5.

| Unsupported form | Seed (handoff source row) | Why it is not established |
|---|---|---|
| Microsoft Graph being PACT-aware, or PACT enforcement by Graph | I02/I03: "PACT enforcement by Graph/every SaaS" | Graph decides on token B only (GR-3); enforcement is in the gateway |
| Protection of bypass routes outside the gateway | I02/I03: "protection of bypass routes" | Only B1 to B6 are controlled; B7 to B9 are out of claim |
| Borrowed user rights in form A | I08: "Borrowed user rights" | App-only executors never act with a user's permissions (GR-22, GR-33) |
| Mailbox narrowing by profile declaration | I08: "mailbox narrowing through profile declaration" | The mailbox boundary is native, the RBAC scope that GR-19 verifies; a profile attribute narrows nothing (GR-14, GR-16) |
| `/me` in app-only execution | Example I08, "Agent switches to a user-oriented `/me` design" | No form A row has a user context (GR-22) |
| OBO-to-app-only fallback, and any fallback to a broader credential | Example I02; draft §17.5 | GR-11; `EXECUTOR_MISMATCH` |
| Application access policies as the mailbox boundary | Section C | RBAC for Applications replaces them [M8]; GR-19 accepts only an RBAC scope |
| Graph permissions or operations other than delegated `Mail.Read` and List messages; any write | Section 2 | Not in the translation table (GR-2) |
| `$filter`, `$search`, `$orderby`, `$expand` built from request data | RB-62; open item O12 of request-binding | The query is a constant (GR-23) |
| Reusing token B across operations or principals | GR-7 | One exchange per operation in form D |
| Exchange Web Services, SMTP, or any protocol other than Graph | Section 2 | Not executed; app roles for them fail GR-18 |
| National and sovereign clouds | Profile header | Their endpoints were not read |
| Shared executor applications across workloads | GR-13 | One executor application per workload |
| Use of executor or auditor credentials outside the gateway | Section 5, B8 | Excluded by its `out-of-claim` disposition |
| Agents' direct access to Graph | Section 5, B7 | Excluded by its `out-of-claim` disposition |
| Mailboxes inside the RBAC scope other than the registered one | Section 5, B9 | Excluded; reached only outside the translation rows |
| Any route other than GD1, GD2, GA1, GA2 | Section 2 | Not listed, so not claimed |
| An enforced data-use restriction after a read | Section 4, C16 | `execution-control-v1` is not installed; post-read limits in section 9 |

## 7. Identity mapping

This profile authenticates no request; the identity choices of the authenticating profile apply, and this section records only the downstream identifiers.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | Form D principal and client workload: the OAuth profile's `oauth:{issuer-id}:{tid}:{oid}` and `oauth:{issuer-id}:{tid}:{azp}` (OAUTH-37, OAUTH-38). Form A principal: the workload identifier of the authenticating profile. Executor application: `oauth:{issuer-id}:{tid}:{app-id}` with the issuer identifier of the pinned tenant, the same shape as an OAuth client workload; its service principal object ID is recorded beside it. Registered mailbox: the user's directory object ID (GR-14) |
| Trusted enrollment actors | Those of the authenticating profile for agents. Executor bindings, executor application registrations, RBAC assignments, and consent are made by native administrators only (draft §4.2); the agent, the workload, and a profile attribute are never actors |
| Shared-account handling | Inherited from the authenticating profile (identity-mapping §5): this profile authenticates no request. Executor applications are not shared: one per workload (GR-13) |
| Certificate, token, or role-session bindings | Token A is bound as the OAuth profile states. Token B is bound to nothing and is never the holder key or evidence (GR-8, GR-31) |
| Lifecycle rules (rotation, compromise, recovery) | Identity-mapping §7 for enrollment. An executor application deleted in Entra ID removes its Exchange assignments automatically [M8]; the executor binding naming it is then revoked by an administrator, and a recreated application is a new executor (new application ID) |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule |

## 8. Freshness

Three sources are read by this profile, with `max_age` and `status_max_age` in seconds, and every outage ends in `DEFERRED`, which fails closed (draft §18; freshness §5). The inbound token, enrollment registry, and hold store are those of the authenticating profile and are not repeated. The figures use the reference configuration `P` = 300 s; these are illustrative policy choices.

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| G1 Executor registry (row to executor class, executor application, registered mailbox) | Current authoritative state, read for each evaluation; `ObservedAt` is the last change of the binding, `StatusCheckedAt` the read | 0 | 0 | `DEFERRED` |
| G2 Native task and delegation registry (`authority_ref`) | Current authoritative state, read for each evaluation (GR-27) | 0 | 0 | `DEFERRED` |
| G3 Grant preflight result of the executor application (form A) | Cached snapshot of Entra app role assignments and Exchange RBAC, refreshed every `P`; `ObservedAt` is the start of step 1. Graph app role reads may lag recent changes [M7]; Exchange enforcement may lag RBAC changes by up to 2 hours [M8], which the settle window `W` covers for remediations only (GR-20) | 300 | 300 | `DEFERRED` |

### 8.1 Membership and status sources

None: this profile reads no membership, role, or account-status fact. The identity of the principal comes from the authenticating profile, which lists its own sources; the executor registry, the task registry, and the preflight supply bindings and grant facts, not membership. The machine-readable form is an empty array.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| none: no membership, role, or account-status fact is read by this profile | Not applicable | Not applicable | Not applicable | Not applicable | Not applicable | Not applicable | Not applicable |

### 8.2 Attribute sources

| Source | `category` | `attributes` | `freshness` |
|---|---|---|---|
| Executor registry | `subject` | `/graph/execution_app_id` | G1 Executor registry (row to executor class, executor application, registered mailbox) |

## 9. Residual limits

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Mail already returned to the agent is not recalled by a later revocation; an executed operation is not undone by revoking its receipt (draft §18); no egress or data-use control is claimed (draft §17.4) | Disclosed; no bound |
| Revocation propagation: form D user and consent | Each operation runs a new OBO exchange (GR-7), so a disabled user or withdrawn consent is seen by the identity platform at the next operation, in its own consistency; token A's own window is the OAuth profile's (OAUTH-29) | Token A lifetime `L` of the OAuth profile; the identity platform's consistency is not stated by the pages read |
| Revocation propagation: form A grants | A parallel grant added after a preflight is found at the next preflight; an RBAC change takes effect in Exchange within 30 minutes to 2 hours [M8]; app role assignment reads may lag [M7]; a cached app-only token B is valid up to its `expires_in` [M2] | `P` = 300 s plus Exchange cache up to 7200 s and token B lifetime |
| Executor registry and task registry | Changes take effect at the next evaluation, in each store's consistency domain | 0 s within that domain |
| RBAC attestation | Step 2 of the preflight reads the operator's attestation of `Test-ServicePrincipalAuthorization`, not the cmdlet itself (GR-19) | Disclosed; an attestation older than `P` stops form A |
| Scope breadth | `Test-ServicePrincipalAuthorization` shows whether the registered mailbox is in scope, not which other mailboxes are (OI-5) | Disclosed; DR3 |
| Token B contents | The gateway does not see token B's claims (GR-8); in form D only the response `scope` is checked; in form A grants are observed only through the preflight | Disclosed |
| Directory roles | Permissions granted to the executor through Microsoft Entra built-in roles "don't limit the app to calling Microsoft Graph APIs only" [M4]; the preflight does not read directory role assignments (P7) | Disclosed; precondition until P7 is run |
| Page size | `$top=10` requests ten items; a page may hold fewer (RB-60) [M6] | Disclosed |
| Deployment controls | DR1 to DR5 are not observable by the fixtures | Disclosed; the deployer's written statement per requirement |

## 10. Fixture index

The cases of this profile are adapter cases in `spec/v1.0/fixtures/adapters/graph/`, one file per variant, named by the lower-case ID and variant, such as `graph-01.search.json`, with the manifest id `adapters/graph/graph-01.search`. Every file is registered in `spec/v1.0/fixtures/manifest.json` and listed in the `fixtures` array of `profile.json`. Their native state is the model `graph/1` of the [Graph cases README](../../fixtures/adapters/graph/README.md). A case file calls one of the seven adapter functions, none of which requests a token or calls Graph, so the Evidence column says which part of a case the files show and which part is shown by an implementation's unit tier, which runs the executor against an in-process token endpoint and an in-process Microsoft Graph over TLS that record every token request (grant type, `requested_token_use`, client, scope, assertion) and every Graph request (path, query, `Authorization`, headers); the unit tier's case names are those of the Evidence column. The case format has no member for a token request, a downstream request, a paged sequence, a throttling answer, or the settle window across preflight runs other than the run list of `graph/1`, so those properties are unit-tier cases. The identity, freshness, and request-binding cases of `spec/v1.0/fixtures/adapters/_common/` and the cases of the OAuth profile also apply to form D and are not repeated; no common case is replaced. A stub executor that falls back to the client credentials grant after a failed OBO exchange, forwards the client's query and headers, keeps token B across operations, follows any continuation and passes every check fails `GRAPH-04`, `GRAPH-05`, and `GRAPH-06` in the unit tier, every case file but the controls, and is the mutant these cases are written against.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `GRAPH-01` | GD1 or GA1 with: `$search=x` added; `$filter=...`; `$top=11`; `%24select=...`; options reordered; `$orderby`; an extra parameter; no query | `INVALID_MESSAGE`; no token request, no downstream request | `adapters/graph/graph-01.search`, `.filter`, `.top-eleven`, `.encoded-dollar`, `.reordered`, `.orderby`, `.extra-parameter`, `.no-query`, `.app-search`, `.app-reordered`, with the controls `.exact-query` and `.app-exact-query`; the hooks `token` and `execute` must not fire | GD1, GA1, B1 |
| `GRAPH-02` | GD1 with a path, query parameter, or header naming another user or mailbox; an executor binding for a form D row that names a mailbox or user | No row selected or `INVALID_MESSAGE`; the only downstream path is `/v1.0/me/messages`, a constant of the mapping revision (RB-49); the binding is a configuration error and nothing executes | `adapters/graph/graph-02.other-user-path`, `.user-parameter`, `.mailbox-header` (mapped, resource the user's own mailbox), `.binding-names-mailbox` (`FAIL`, `EXECUTOR_MISMATCH`); the constant downstream path is unit case `GRAPH-08.token-a-not-forwarded` | GD1, B1, B5 |
| `GRAPH-03` | Form D request carrying a token for Microsoft Graph as token A | Refused by the OAuth profile; never sent as an OBO `assertion` | Unit case `GRAPH-03.graph-token`: the OAuth profile's form E adapter refuses it, the executor handed it anyway refuses it, and the token endpoint receives no request; the audience rule itself is the OAuth profile's cases | GD1 |
| `GRAPH-04` | Admitted GD1; the token endpoint answers the OBO request with `interaction_required` and a `claims` value | No downstream request; 401 with the error and claims challenge in `WWW-Authenticate`; no app-only attempt; `AUTHORIZATION` `FAILURE` report | Unit cases `GRAPH-04.interaction-required` and `GRAPH-04.interaction-no-claims`: one OBO request, no client credentials request, no Graph request, the challenge, and the report's fields; the signed report is `adapters/graph/graph-20.denial-report` | GD1, B3 |
| `GRAPH-05` | Admitted GD1; the user's consent for `Mail.Read` was withdrawn, and the token endpoint returns an error | No downstream request; native denial, no fallback; `AUTHORIZATION` `FAILURE` | Unit cases `GRAPH-05.consent-withdrawn` (`invalid_grant`, AADSTS65001), `GRAPH-05.user-disabled` (`invalid_grant`, AADSTS50057) and `GRAPH-05.endpoint-unavailable` (no `SUCCESS` report, OI-3) | GD1, B3 |
| `GRAPH-06` | GD1 whose executor binding names the client credentials grant; an executor that, after a failed OBO exchange, requests an app-only token | `execution-identity-v1` `FAIL` with `EXECUTOR_MISMATCH`; no downstream request | `adapters/graph/graph-06.binding-client-credentials`, `.binding-grant-only`, `.binding-other-app`, with the control `.delegated-binding`; unit cases `GRAPH-06.obo-request` (every token request is the OBO request of GR-6, also after a failure) and `GRAPH-06.no-token-reuse` (GR-7) | GD1, B3 |
| `GRAPH-07` | OBO token response whose `scope` lacks `Mail.Read`; one that names `Mail.ReadWrite` as well; one without `scope` | Token not used; no downstream request | Unit cases `GRAPH-07.scope-lacks-mail-read`, `GRAPH-07.scope-adds-readwrite`, `GRAPH-07.no-scope` | GD1 |
| `GRAPH-08` | Admitted GD1 or GA1; Graph answers 403 | Native denial, final; no retry, no other credential | Unit cases `GRAPH-08.graph-refuses` and, for token A never reaching Graph and only the executor's `Authorization` sent, `GRAPH-08.token-a-not-forwarded`; GA1 is `GRAPH-17` | GD1, GA1, B3 |
| `GRAPH-09` | GD2 or GA2 with: an unknown `page_token`; one recorded for another task, principal, agent, row, or mapping version; a recorded link with host `graph.microsoft.com.example`, another path such as `/v1.0/users/{other}/messages`, or without the pinned `$select` | `CONTEXT_MISMATCH`; no downstream request | `adapters/graph/graph-09.unknown-token`, `.other-principal`, `.other-row`, `.other-version`, `.other-host`, `.other-path`, `.dropped-select`, `.app-other-path`, and `.token-grammar` (`INVALID_MESSAGE`). `map_operation` has no task or agent input, so another task and another agent are unit cases `GRAPH-09.other-task` and `GRAPH-09.other-agent`, refused at execution | GD2, GA2, B2 |
| `GRAPH-10` | A first-page receipt presented again for GD2; a valid continuation of the same task under its own contract (control) | Refused as reuse; the control is admitted as a new operation | Controls `adapters/graph/graph-10.continuation` and `.app-continuation`. The receipt comparison is the validator's (draft §11.5); unit case `GRAPH-10.next-page` shows that the second page has its own operation id, a new OBO exchange, and the recorded link sent unchanged, and `GRAPH-10.link-other-host` that a recorded link to another host is not followed | GD2, GA2, B2 |
| `GRAPH-11` | A form A request whose mapping would need `/me`, such as `GET /mail/messages` authenticated as a workload; an executor binding on GA1 with no registered mailbox | No form A row selected, or the form D row refuses the workload principal; the binding is a configuration error; no downstream request, and never `/me` under an app-only token | `adapters/graph/graph-11.workload-on-delegated-route`, `.binding-no-mailbox`; unit case `GRAPH-11.app-only-path` (only the client credentials request of GR-15 and only the registered mailbox's path) | GA1, B1 |
| `GRAPH-12` | GA1 with a query parameter, header, or profile attribute naming another mailbox; an executor binding for the workload that names another workload's mailbox | The mailbox is the registered one or the request is refused; a profile value never narrows or changes it | `adapters/graph/graph-12.app-mailbox-parameter`, `.app-mailbox-header`, `.other-workload-mailbox`; unit case `GRAPH-12.header-mailbox`. No adapter function reads a profile attribute for the mailbox | GA1, B1 |
| `GRAPH-13` | Presentation with `/attributes/environment/execution_app_id` of another application; an executor binding naming an application bound to another workload | `INADMISSIBLE` with `INVALID_CLAIM`; configuration error, no execution for either workload | `adapters/graph/graph-13.claim-registered` (the value the validator compares), `.claim-delegated`, `.shared-app-claim`, `.shared-app`. The comparison with the presented value is the validator's (draft §8.4) | GA1 |
| `GRAPH-14` | Preflight step 1 returns an app role assignment of Graph `Mail.Read`; of `Mail.ReadWrite`; of `Mail.ReadBasic.All`; of any role outside the allowlist; one whose `appRoleId` cannot be resolved | Preflight fails; `execution-identity-v1` `FAIL` with `EXECUTOR_MISMATCH`; cached token B discarded; alert | `adapters/graph/graph-14.graph-mail-read`, `.graph-mail-readwrite`, `.graph-mail-readbasic-all`, `.other-resource`, `.second-page`; with the reference allowlist empty, every assignment is outside it, resolvable or not. The discarded token is unit case `GRAPH-14.preflight-fails` | GA1, GA2, B4, G3 |
| `GRAPH-15` | Preflight step 2: no row; `InScope` `False`; `ScopeType` `Organization`; an additional role row; an unrecognized `ScopeType` | Preflight fails; `FAIL` with `EXECUTOR_MISMATCH` | `adapters/graph/graph-15.no-row`, `.not-in-scope`, `.organization-scope`, `.extra-row`, `.unknown-scope-type` | GA1, GA2, B4, G3 |
| `GRAPH-16` | Preflight result older than `P`; preflight unable to run; `PASS` inside `W` after a failure | `UNKNOWN`, `DEPENDENCY_UNAVAILABLE`, `DEFERRED` | `adapters/graph/graph-16.older-than-p`, `.unable-to-run`, `.inside-settle-window`, `.no-preflight`, with the control `.settled` at both limits; unit case `GRAPH-16.no-preflight` (no token request) | GA1, G3 |
| `GRAPH-17` | Admitted GA1; Graph refuses the mailbox read; the executor would retry under another application | Native denial; no other credential; `EXECUTOR_MISMATCH` for the retry | Unit case `GRAPH-17.app-graph-refuses`: one Graph request, every token request by the executor application. An adapter holds exactly one token acquirer, so no other application's credential exists to retry with | GA1, B3 |
| `GRAPH-18` | `authority_ref` absent; unknown to the registry; for another task or mailbox; expired; revoked | `MISSING_FIELD`; `TASK_MISMATCH`; `TASK_MISMATCH`; `STALE_EVIDENCE`; `REVOKED_EVIDENCE` | Not yet a case: `native-delegation-v1` runs over the deployment's task registry (C04), installed as a deployment check, and how its reference reaches `check_context` waits for the G03 model (OI-1). The common cases `COMMON-05` and `FRESH-*` cover installed checks | all rows, G2 |
| `GRAPH-19` | Form A presentation naming a user principal or a human's name to imply delegation; form D presentation naming the workload | `CONTEXT_MISMATCH`; no delegation established | Not an adapter case: `native-principal-binding-v1` is evaluated by the validator and is not an input of `check_context` (draft §17.5) | GA1, GD1 |
| `GRAPH-20` | Any admitted and executed operation in each form | `AUTHORIZATION` and `EXECUTION` reports name both actors in `details` and reference the executor record in `evidence_refs`; `execution-identity-v1` `SourceRef` is the binding record; no token or credential in any record | `adapters/graph/graph-20.execution-report`, `.denial-report`; unit cases `GRAPH-20.both-actors` (also the check's `SourceRef`), `GRAPH-20.app-actors`, and `GRAPH-20.empty-page`, whose `details` is `"empty"` as draft §14.5 requires, with the actors in the executor record | all rows |
| `GRAPH-21` | `POST /pact/v0.1/requirements` for a GD1 or GA1 operation with a forbidden query or a workload without an executor binding | No trusted personalized contract is issued | `adapters/graph/graph-21.no-binding`, `.map-no-binding`; the forbidden query is `GRAPH-01`. Contract issuance is the gateway's | B6 |
| `GRAPH-22` | Executor registry or task registry unavailable; Graph 429 with `Retry-After` | `DEFERRED` with `DEPENDENCY_UNAVAILABLE`; for 429, one attempt only and 503 with `Retry-After` | `adapters/graph/graph-22.registry-unavailable`, `.map-registry-unavailable`; unit cases `GRAPH-22.throttled` and `GRAPH-22.registry-unavailable`. The task registry is `GRAPH-18` | G1, G2, all rows |

Coverage. GD1 is covered by cases 01 to 08, 18 to 20, and 22; GD2 by 09 and 10; GA1 by 01, 08, 11 to 20, and 22; GA2 by 09, 10, 14, and 15. B1 is covered by 01, 02, 11, 12; B2 by 09, 10; B3 by 04 to 08 and 17; B4 by 14 to 16; B5 by 02; B6 by 21. G1 and G2 by 18 and 22; G3 by 14 to 16.

## G18 closure map

The open finding G18 asks to specify original and downstream app actors, grants and consent, OBO versus app-only acquisition, mailbox and resource mapping, and parallel grants defeating scope, and asks for tests of wrong mailbox or app, broad parallel grants, consent loss, interaction or OBO failure, app-only user-endpoint misuse, and privilege-expanding fallback.

| G18 closure item | Rules | Cases |
|---|---|---|
| Original and downstream app actors | GR-1, GR-5, GR-13, GR-26, GR-28, GR-29 | `GRAPH-06`, `GRAPH-13`, `GRAPH-19`, `GRAPH-20` |
| Grants and consent | GR-8, GR-9, GR-15 to GR-19 | `GRAPH-05`, `GRAPH-07`, `GRAPH-14`, `GRAPH-15` |
| OBO versus app-only acquisition | GR-5 to GR-7, GR-11, GR-15, GR-22 | `GRAPH-03`, `GRAPH-04`, `GRAPH-06`, `GRAPH-11` |
| Mailbox and resource mapping | GR-14, GR-23, GR-24; section 2 | `GRAPH-01`, `GRAPH-02`, `GRAPH-09`, `GRAPH-12` |
| Parallel grants defeating scope | GR-16 to GR-21 | `GRAPH-14`, `GRAPH-15`, `GRAPH-16` |
| Evidence: wrong mailbox or app | GR-13, GR-14, GR-32 | `GRAPH-02`, `GRAPH-12`, `GRAPH-13` |
| Evidence: broad parallel grants | GR-18, GR-21 | `GRAPH-14` |
| Evidence: consent loss | GR-9, GR-11 | `GRAPH-05` |
| Evidence: interaction or OBO failure | GR-10, GR-11 | `GRAPH-04`, `GRAPH-05` |
| Evidence: app-only user-endpoint misuse | GR-22 | `GRAPH-11` |
| Evidence: privilege-expanding fallback | GR-11, GR-26, GR-33 | `GRAPH-06`, `GRAPH-08`, `GRAPH-17` |

## Open items and probes

### Open items

| ID | Open item | What closes it |
|---|---|---|
| OI-1 | `authority_ref` is opaque until the delegation binding model of finding G03 lands (GR-27) | The G03 change; this profile then states the reference's structure |
| OI-2 | Closed. The OAuth profile's open item OI-7 (R2's downstream Graph call) is answered by this profile, and its route R2 is narrowed by GD1 (section 1); the OAuth profile points R2 to GD1 and closes OI-7 | Closed by the edit of the OAuth profile |
| OI-3 | Draft §14.5 has no row for an executor credential failure after admission (token endpoint unreachable) or a downstream 429; GR-30 sends no `SUCCESS` report but names no row | A draft §14.5 row, or a ruling that maps them |
| OI-4 | Closed. Page and retry budgets across operations of one task (GR-25) are stated by the [multi-operation profile](../multi-operation.md): each page reserves one operation and one page of the native task's budget, a new listing counts again, a continuation is bound to its native task and ends with it (MO-55 to MO-58), bytes count against `max_bytes` (MO-21, MO-59, MO-61), and a retry after a throttle is a new operation counted against the same budget (MO-34). `go/adapters/graph` implements them with a task ledger: `Config.Tasks`, the pager `NewPager`, and the route `ListingRoute` | Closed by the multi-operation profile and its implementation in `go/adapters/graph` |
| OI-5 | `Test-ServicePrincipalAuthorization` answers per mailbox (GR-19); no read API was found that lists every mailbox of a scope, so scope breadth rests on DR3 | A documented way to enumerate the scope, or a canary-mailbox test per deployment |
| OI-6 | The translation table and the executor bindings have no field in `integration-profile.schema.json` and stay in this document | A schema change, if machine checks need them |

### Probes

Each probe needs a test tenant and was not run for this profile. A rule that depends on one fails closed until it is run.

| ID | Question | Probe | If the outcome differs |
|---|---|---|---|
| P1 | Does `@odata.nextLink` for `/v1.0/me/messages` keep the path `/v1.0/me/messages`, and the one for `/v1.0/users/{registered-mailbox-id}/messages` that path, and how are `$select=id,subject,body` and `$top=10` encoded in each? | Request GD1's and GA1's downstream with more than ten messages and compare the links | A different path or encoding fails GR-24 and paging is unavailable for that form until the profile records the observed form |
| P2 | Which error does the token endpoint return to an OBO request when consent for `Mail.Read` is missing or withdrawn, and when the user is disabled? The error code reference lists AADSTS65001 DelegationDoesNotExist and AADSTS50057 UserDisabled and asks applications not to depend on codes [M13]; which `error` value accompanies them was not read | Withdraw consent and disable a test user, then exchange token A | None: every error fails closed (GR-11); the code is recorded for diagnostics |
| P3 | How is `Mail.Read` spelled in the OBO response `scope`, and does it list other consented Graph scopes? | Exchange token A with `scope=https://graph.microsoft.com/Mail.Read` and read the response | GR-8 is configured with the observed spelling; extra scopes keep failing GR-8 until DR2 holds |
| P4 | What does Graph return to `/me/messages` under an app-only token? | Call it with a client credentials token | None: no form A row produces it (GR-22) |
| P5 | Which Graph application permissions other than `Mail.ReadBasic.All`, `Mail.ReadWrite`, and `Mail.Read` grant List messages? | Read the permissions reference and test each candidate | The reference allowlist stays empty, so none can pass GR-18 |
| P6 | Can the delegated grants of the gateway application be machine-checked through its `oauth2PermissionGrants`? The result of consent to delegated permissions is an oAuth2PermissionGrant object [M4], but its read API was not read | Read the API page and list the grants of a test registration | DR2 stays a written statement |
| P7 | Do Entra directory roles assigned to the executor service principal grant mailbox access through Graph? | Assign a role to a test executor and call List messages for an out-of-scope mailbox | If they can, the preflight adds a check of the executor's directory role assignments |
| P8 | Does declaring the `cp1` capability change the lifetime of OBO tokens for Graph? | Exchange with and without `xms_cc` | The reference executor keeps declaring none |
| P9 | Is `ScopeType` of `Test-ServicePrincipalAuthorization` a closed set, and can its output be read as structured data? | Run the cmdlet over each scope type | An unrecognized value keeps failing GR-19 |

## Sources

All Microsoft Learn pages were read on 2026-10-18; M12 and M13 were read for the reference implementation.

| Label | Source | Used for |
|---|---|---|
| M1 | Microsoft Learn: [Microsoft identity platform and OAuth2.0 On-Behalf-Of flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow) | Delegated scopes only; "only works for user principals"; custom signing key limitation; request parameters; assertion audience; response members including `scope`; not reading tokens of other APIs; `interaction_required` with claims and the middle tier's 401; consent options |
| M2 | Microsoft Learn: [OAuth 2.0 client credentials flow on the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow) | Application permissions; no delegated permissions without a user; `.default` scope; request parameters; response members; no refresh token; tokens without `roles` |
| M3 | Microsoft Learn: [Get access without a user](https://learn.microsoft.com/en-us/graph/auth-v2-service) | Admin consent for application permissions; `.default` includes all consented app-level permissions; sample response with `request-id` |
| M4 | Microsoft Learn: [Overview of Microsoft Graph permissions](https://learn.microsoft.com/en-us/graph/permissions-overview) | Delegated versus application permissions; effective delegated privileges; consent results (oAuth2PermissionGrant, appRoleAssignment); Graph service principal `appRoles`; Entra built-in roles note |
| M5 | Microsoft Learn: [List messages](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0) | Request forms, permissions table, `$top` range and default, `$select`, next link use, `Prefer: outlook.body-content-type`, other users' folders |
| M6 | Microsoft Learn: [Paging Microsoft Graph data in your app](https://learn.microsoft.com/en-us/graph/paging) | `@odata.nextLink`; entire URL; page sizes |
| M7 | Microsoft Learn: [List appRoleAssignments granted to a service principal](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0) | Request forms, `Application.Read.All`, response members, replication delay |
| M8 | Microsoft Learn: [Role Based Access Control for Applications in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac) | Independence from and union with Entra grants; role `Application Mail.Read`; scopes; test cmdlet excludes Entra grants and bypasses the cache; cache of 30 minutes to 2 hours; replacement of application access policies; deletion of service principals |
| M9 | Microsoft Learn: [Test-ServicePrincipalAuthorization](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/test-serviceprincipalauthorization) | Syntax, `-Identity`, `-Resource`, output columns, `Organization` scope example |
| M10 | Microsoft Learn: [Microsoft Graph throttling guidance](https://learn.microsoft.com/en-us/graph/throttling) | HTTP 429, `Retry-After`, retries count against limits |
| M11 | Microsoft Learn: [Claims challenges, claims requests and client capabilities](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge) | Claims challenge format; Graph sends challenges only to clients declaring `cp1` |
| M12 | Microsoft Learn: [Microsoft identity platform certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials) | Client assertion header (`alg` PS256, `typ`, `x5t#S256`), claims (`aud`, `iss`, `sub`, `jti`, `nbf`, `iat`, `exp`), PSS padding |
| M13 | Microsoft Learn: [Microsoft Entra authentication and authorization error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes) | `error` values `invalid_grant`, `interaction_required`, `invalid_client`, `temporarily_unavailable`; AADSTS65001, AADSTS50057, AADSTS50076, AADSTS50079; codes are not to be depended on |
