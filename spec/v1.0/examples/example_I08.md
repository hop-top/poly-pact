# Integration 08 — App-only service identity without a signed-in user

**Status:** Informative integration example for PACT Protocol v1.0. Organizations, identifiers, routes, requirements, and thresholds are fictional deployment choices. Excerpts are incomplete illustrations, not signed wire fixtures or a tested implementation. The gateway needs the described installed adapter; the named platform is not claimed to support PACT natively.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I08. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- The workload has explicit native application authority and a registered downstream executor.
- Complete effective mailbox permissions, including parallel grants, preserve the claimed scope.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | Scheduled workload-to-executor task authority. |
| C03 | Native application/key mapping and credential lifecycle. |
| C08 | App-only Graph executor and native mailbox restrictions. |
| C15 | Bound schedule, paging, and task limits. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G18 | Specify app-only grants and exclude scope-defeating parallel grants. Specified for this sample by the integration profile [`graph`](../profiles/graph/profile.md), form A (rows GA1 and GA2), whose G18 closure map ties each item to rules and cases; its grant preflight withdraws the claim while a parallel grant exists. The delegated half is sample [I02](example_I02.md). | Profile / deployment |
| G26 | Preserve schedule/task/page limits across new exchanges. Specified across operations by the [multi-operation profile](../profiles/multi-operation.md), whose G26 closure map (section 12) ties each item to rules and to the cases `TASK-01` to `TASK-09`, and whose section 13.3 works this sample: each page reserves one operation and one page of the run's native task (rules MO-55 to MO-57; `TASK-04`), a run that the registry has not issued is refused with `task-unknown` (rule MO-6; `TASK-07`), a run that the scheduler marks done refuses further pages with `task-completed` (rules MO-49, MO-50; `TASK-06`), and a run's budget is renewed only by a new reference that the registry issues. The Graph profile binds each continuation to the task, workload, and route (rule GR-24; `GRAPH-09`, `GRAPH-10`) and reserves each page in that profile's task ledger (its component C15; open item OI-4, closed). Whether the registry names the run or the schedule, and so whether a budget spans one run or every run, is the deployment's to state (multi-operation section 13.3). | Profile / deployment |

### Deliberate simplifications and limitations

- App-only access does not borrow user permissions or implement delegated OBO.
- Mailbox restriction depends on native grants; a profile cannot narrow broad app access on its own (integration profile `graph`, rule GR-16).

### Profile and fixtures

The integration profile [`graph`](../profiles/graph/profile.md) states, as its form A, the conformance claim for this sample. It covers two rows of the controlled mail gateway: GA1 (`GET /mailbox/messages` with the query exactly `$select=id,subject,body&$top=10`, action `mail.message.list`, resource `mailbox:{registered-mailbox-id}`) and GA2 (the continuation of a page by `page_token`). The executor application is registered for one workload and the executor binding names one mailbox by its directory object ID, never by a user principal name (rules GR-13 and GR-14). The executor obtains token B by the client credentials grant with the scope `https://graph.microsoft.com/.default` and makes one downstream request, `GET /v1.0/users/{registered-mailbox-id}/messages` with the same constant query (rules GR-15, GR-2, and GR-23). The executor class is `registered-app-executor`, and `execution-identity-v1` returns `PASS` only while the latest grant preflight of the executor application has passed (rules GR-21 and GR-26). The profile authenticates no inbound request: the integration profile that the deployment names for its workloads does, such as the [mTLS profile](../profiles/mtls/profile.md). It states the deployment requirements DR3, DR4, and DR5 of its section 4 and the fixture index of its section 10. Its form D is sample [I02](example_I02.md), and the cases `GRAPH-03` to `GRAPH-07` belong to that form.

The adapter cases are in [`fixtures/adapters/graph/`](../fixtures/adapters/graph/README.md), registered in the fixture manifest under the ids below; the decisions table below names the case for each row. A case file calls one adapter function and never requests a token or calls Graph, so the Evidence column also names the unit cases, which are Go tests of the adapter package against an in-process token endpoint and an in-process Graph over TLS. The preflight cases serve their app role assignments and RBAC attestations from the harness. None of this is a live tenant or a live Exchange Online organization.

| Fixture ID | Exchange of this sample | Evidence |
|---|---|---|
| `GRAPH-01` | The gateway request's query changed: `$search`, or the options reordered | `INVALID_MESSAGE`: `adapters/graph/graph-01.app-search`, `adapters/graph/graph-01.app-reordered`, with the control `adapters/graph/graph-01.app-exact-query` (maps to the workload's registered mailbox) |
| `GRAPH-09` | Step 8: a next page whose recorded link names a mailbox other than the registered one | `adapters/graph/graph-09.app-other-path` (`CONTEXT_MISMATCH`) |
| `GRAPH-10` | Step 8: a next page under its own contract | The control `adapters/graph/graph-10.app-continuation` (admitted as a new operation); the refusal of a reused first-page receipt is the validator's (draft Section 11.5) |
| `GRAPH-11` | The user-oriented `/me` design; a workload on the user route; an executor binding with no registered mailbox | `adapters/graph/graph-11.workload-on-delegated-route` (no form A row selected, `UNSUPPORTED_REQUIREMENT`), `adapters/graph/graph-11.binding-no-mailbox` (`FAIL`, `EXECUTOR_MISMATCH`); unit case `GRAPH-11.app-only-path` |
| `GRAPH-12` | Another mailbox named by a query parameter or header, or one that the registry also binds to another workload | `adapters/graph/graph-12.app-mailbox-parameter` (`INVALID_MESSAGE`), `adapters/graph/graph-12.app-mailbox-header` (mapped: a header changes nothing), `adapters/graph/graph-12.other-workload-mailbox` (`FAIL`, `EXECUTOR_MISMATCH`); unit case `GRAPH-12.header-mailbox` |
| `GRAPH-13` | Another application's identity presented as the executor; one application bound to two workloads | `adapters/graph/graph-13.claim-registered` (the value the validator compares; a differing value is `INADMISSIBLE` with `INVALID_CLAIM`, draft Section 8.4), `adapters/graph/graph-13.shared-app-claim` (no claim), `adapters/graph/graph-13.shared-app` (`FAIL`, `EXECUTOR_MISMATCH`) |
| `GRAPH-14` | A parallel broad grant in Entra ID: an app role assignment of `Mail.Read`, `Mail.ReadWrite`, `Mail.ReadBasic.All`, or of another resource, also on a second page of the listing | `FAIL`, `EXECUTOR_MISMATCH`: `adapters/graph/graph-14.graph-mail-read`, `adapters/graph/graph-14.graph-mail-readwrite`, `adapters/graph/graph-14.graph-mail-readbasic-all`, `adapters/graph/graph-14.other-resource`, `adapters/graph/graph-14.second-page`; the discarded token is the unit case `GRAPH-14.preflight-fails` |
| `GRAPH-15` | The Exchange scope does not defeat the boundary: no row, not in scope, scope type `Organization`, an additional role row, or an unrecognized scope type | `FAIL`, `EXECUTOR_MISMATCH`: `adapters/graph/graph-15.no-row`, `adapters/graph/graph-15.not-in-scope`, `adapters/graph/graph-15.organization-scope`, `adapters/graph/graph-15.extra-row`, `adapters/graph/graph-15.unknown-scope-type` |
| `GRAPH-16` | The preflight is older than the profile's bound, could not run, is absent, or passed inside the settle window after a failure | `UNKNOWN`, `DEPENDENCY_UNAVAILABLE`, which yields `DEFERRED`: `adapters/graph/graph-16.older-than-p`, `adapters/graph/graph-16.unable-to-run`, `adapters/graph/graph-16.no-preflight`, `adapters/graph/graph-16.inside-settle-window`, with the control `adapters/graph/graph-16.settled` |
| `GRAPH-17` | Step 8: the mailbox authorization refuses the read | Unit case `GRAPH-17.app-graph-refuses`: one Graph request, every token request by the executor application; an adapter holds one token acquirer, so no other application's credential exists to retry with |
| `GRAPH-18` | The scheduled-task authorization absent, unknown, for another task or mailbox, expired, or revoked | No case yet: `native-delegation-v1` runs over the deployment's task registry, and how its reference reaches the check waits for the delegation binding model (profile open item OI-1) |
| `GRAPH-19` | A user principal or a human's name presented to imply delegation | Not an adapter case: `native-principal-binding-v1` is evaluated by the validator (draft Section 17.5) |
| `GRAPH-20` | The `AUTHORIZATION` and `EXECUTION` reports of an executed page | Unit cases `GRAPH-20.app-actors` and `GRAPH-20.empty-page`; the signed report files `adapters/graph/graph-20.execution-report` and `adapters/graph/graph-20.denial-report` are form D files (sample [I02](example_I02.md)) |
| `GRAPH-21` | A workload with no executor binding | `adapters/graph/graph-21.no-binding` (`UNKNOWN`, `DEPENDENCY_UNAVAILABLE`), `adapters/graph/graph-21.map-no-binding` (no row selected, `UNSUPPORTED_REQUIREMENT`); contract issuance is the gateway's |
| `GRAPH-22` | The executor registry cannot answer; Graph throttles the read | `adapters/graph/graph-22.map-registry-unavailable` (`DEPENDENCY_UNAVAILABLE`: the mailbox comes only from the registry); unit case `GRAPH-22.throttled` (one attempt, then 503 with `Retry-After`) |

### Validation still required

The cases above cover another executor or mailbox, user-endpoint misuse, parallel broad grants, and a native denial that never triggers another application's credentials, at the adapter and at the unit tier, against fakes. These remain unvalidated:

- A live Exchange Online organization and Entra tenant. The scope of the executor's Exchange assignment is read from an operator's attestation of `Test-ServicePrincipalAuthorization`, which exists only as a cmdlet of the cloud service; the cases serve the attestation from the harness, and step 2 of the preflight is as current as the operator's last run (rule GR-19).
- Mailboxes inside the scope other than the registered one: the cmdlet answers per mailbox, and no way to list the scope was found, so the breadth of the scope rests on the deployment (profile open item OI-5 and requirement DR3).
- Exchange enforcement of a changed assignment, which lags by 30 minutes to 2 hours, and the lag of app role assignment reads in Graph; the settle window and the preflight interval are the profile's illustrative values (profile section 9).
- The probes of the profile that concern this sample, none of which was run: the Graph application permissions other than `Mail.Read`, `Mail.ReadWrite`, and `Mail.ReadBasic.All` that also grant List messages (probe P5), whether Entra directory roles of the executor grant mailbox access (P7; the preflight does not read them), whether `ScopeType` is a closed set and can be read as structured data (P9), and the continuation link that Graph returns for the registered mailbox's messages (probe P1 names `/me/messages`, and the profile compares the form A link in the same way, rule GR-24).
- The scheduled-task authorization and its registry (`GRAPH-18`), which wait for the delegation binding model (open item OI-1 of the profile).
- The page and retry budgets across operations against the scheduler's real task registry. The multi-operation profile specifies them, and its cases (`TASK-01`, `TASK-04`, `TASK-06`) are tests of a Go package of the source repository against a fake registry and a fake native service, not fixture cases. A deployment still supplies the registry, a ledger shared by every replica (multi-operation rule MO-17), the limits of each run (rule MO-15), and the run-or-schedule choice (its section 13.3). Whether Graph's caveat on the token of a retried page applies to message listings is to probe (multi-operation probe P5).
- A draft Section 14.5 row for a token endpoint that cannot be reached after admission, and for a Graph throttling answer (open item OI-3).
- The deployment requirements DR3, DR4, and DR5: one executor application per workload with the RBAC assignment the preflight verifies, credentials in protected stores the agent cannot read, and egress limited to Graph and the token endpoint.
- Runtime evidence and the hold store: no Graph case exercises them.

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Every morning, Northstar's support-triage assistant reads a shared support mailbox and prepares a queue summary. No employee is signed in. Native authority comes from an explicitly authorized workload/application identity, not an employee's user permissions or a permanent human approval.

A controlled mail gateway accepts the enrolled workload and executes the task using its registered downstream Graph application identity. The native registry explicitly maps that workload to the authorized application executor; the agent cannot choose a different application or mailbox.

## Native authority and placement

The gateway authenticates the caller with its established workload-authentication mechanism and resolves the current service-principal mapping. For the downstream Microsoft Graph call, the executor uses Entra's client-credentials flow and the application's configured native grants. This is app-only access, distinct from delegated user access and the user-based OBO flow. See [Graph app-only access](https://learn.microsoft.com/en-us/graph/auth-v2-service).

For this example, the administrator configures a scoped Exchange application authorization for reading the support mailbox and verifies the effective permission configuration. Exchange Application RBAC grants are independent of unscoped Entra grants; a parallel broad grant must not defeat the intended mailbox boundary. See [Exchange Application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac). PACT does not create or narrow those grants itself.

Under the integration profile, the verification is a recurring grant preflight that the gateway's auditor runs, and it does not replace the administrator's work. Step 1 lists the executor application's app role assignments in Graph and passes only if each one is in an allowlist that is empty in the reference configuration. Step 2 reads the operator's attestation of `Test-ServicePrincipalAuthorization` for the registered mailbox and passes only with exactly one `Application Mail.Read` row that is in scope and whose scope type is a custom recipient scope or an administrative unit scope (rules GR-16 to GR-19). A preflight that finds a parallel grant makes `execution-identity-v1` return `FAIL` with `EXECUTOR_MISMATCH`, discards the executor's cached token, and stops every form A row of that executor. A preflight that is older than 300 seconds, could not run, or passed less than 7200 seconds after a failure leaves the check `UNKNOWN` (rules GR-20 and GR-21; `GRAPH-14` to `GRAPH-16`). The two figures are the profile's illustrative reference values. The claim holds only while the latest preflight passed.

## Required profile and native mapping

| Fact | Source and requirement |
|---|---|
| `/attributes/environment/principal_id` | Current authenticated workload/service-principal mapping |
| `/attributes/environment/execution_app_id` | Registered downstream application assigned to that workload. The profile reads it from the executor registry at `/graph/execution_app_id`, in the form `oauth:{issuer-id}:{tid}:{app-id}`; a presented value that differs is `INADMISSIBLE` with `INVALID_CLAIM` and never changes the executor (rule GR-32; `adapters/graph/graph-13.claim-registered`) |
| `/attributes/delegation/authority_ref` | Native scheduled-task authorization identifying the workload, executor, mailbox, purpose, and schedule; opaque to the profile until the delegation binding model lands (rule GR-27) |
| `/attributes/runtime/isolation` | Evidence from the required trusted runtime issuer |
| Agent and holder binding | Enrollment registry for this workload/operator and current key |

There is no fabricated user principal or user consent. The native task authorization establishes which application may execute the schedule. Its name in the profile is only a reference until the gateway verifies it.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it. There is no signed-in user: the principal is the workload, and no user delegation is implied.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment registry for this workload, operator, and current key (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: the workload's established authentication and its current service-principal mapping (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the scheduled queue-summary task |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Native scheduled-task authorization identifying the workload, executor, mailbox, purpose, and schedule; it is not a user delegation |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the controlled mail gateway |
| Downstream executor | Check `execution-identity-v1`; declared class `registered-app-executor` | The registered downstream Graph application named by `/attributes/environment/execution_app_id`, using app-only access under its configured native grants (integration profile `graph`, rule GR-26) |

The installed `execution-identity-v1` mapping declares the class `registered-app-executor` for the workload, the queue-summary task, and the mailbox page read, and binds it to the application the native registry assigns to that workload. The check returns `PASS` only when the executor that will run the Graph call equals that class and binding. The executor's application identity is the recorded downstream native actor; it is not presented as Maya or as an extension of a user's rights.

Adversarial results (Section 17.5):

- A workload other than the authenticated one presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH` (integration profile `graph`, rule GR-28; `GRAPH-19`, not an adapter case).
- A mailbox or task other than the scheduled one presented: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH` (integration profile `graph`, rule GR-27; no case yet, `GRAPH-18`).
- The scheduled-task authorization is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- Fallback to another application's broader credentials after a native denial: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH` (integration profile `graph`, rules GR-11 and GR-26; `GRAPH-17`).
- A parallel broad grant that defeats the mailbox scope: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH` (rule GR-21; `GRAPH-14`, `GRAPH-15`).
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED` (an executor registry that cannot answer, or a preflight that is absent, unable to run, too old, or inside its settle window: `GRAPH-16`, `GRAPH-22`).

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample, including the report for each page, references in `evidence_refs` an immutable native record identifying the actual executor identity, here the registered application. Section 14.2 states this without exception for a downstream mailbox refusal. A report whose executor class differs from the declared `registered-app-executor` class is `UNQUALIFIED`. The integration profile `graph` has every report name both actors and reference the executor record (rule GR-29; unit case `GRAPH-20.app-actors`).

## Successful exchange

1. The scheduler starts the enrolled agent in its authenticated workload environment. The gateway resolves the native application/workload mapping and applicable scheduled-task authorization.
2. The agent proposes reading a specific page of messages from the registered support mailbox for the queue-summary task.
3. The gateway maps the exact operation and issues a signed PACT contract. Its installed purpose check permits the approved read shape, mailbox, and task context.
4. The agent supplies the required profile and trusted runtime evidence and signs the complete presentation. It cannot replace the execution application or resource by editing profile attributes.
5. The gateway validates PACT and its native workload/task policy. If all PACT checks pass, it records `ADMISSIBLE`.
6. The executor obtains an app-only access token for Graph through the configured confidential-client credential mechanism, with the scope `https://graph.microsoft.com/.default`. Credentials remain in the executor's protected store and never enter PACT records; the gateway never reads the token (rules GR-15 and GR-8).
7. The executor performs the approved downstream operation (row GA1 of the profile, with the registered mailbox's directory object ID in the path and the constant query, rules GR-14 and GR-23):

```http
GET /v1.0/users/<registered-support-mailbox-id>/messages?$select=id,subject,body&$top=10 HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer <app-only-Graph-access-token>
```

8. Graph and the applicable mailbox authorization enforce the application's native access. A downstream denial blocks the read even after PACT passes, with no retry under another credential (rule GR-11; `GRAPH-17`). Pagination needs its own bound operation; the receipt does not authorize unrestricted mailbox traversal, and the recorded continuation link is followed only if its host, path, and pinned options are those of the first page (rule GR-24; `GRAPH-09`, `GRAPH-10`). Under the [multi-operation profile](../profiles/multi-operation.md), each page is also an operation of the run's native task: it reserves one operation and one page of the run's budget, and once the scheduler marks the run done a further page is refused with `task-completed` (rules MO-50, MO-55, MO-58; `TASK-04`, `TASK-06`). A read that Graph throttles ends its operation; a retry is a new operation under a new contract, counted against the same budget (rule MO-34).

The executor's application identity is explicitly recorded as the downstream native actor. It is not presented as Maya or as an extension of a user's personal rights. The gateway's own authentication token, if used, has its own audience and cannot substitute for the Graph token.

## Decisions and failure variations

| Condition | Expected behavior | Profile case |
|---|---|---|
| Authorized workload, valid evidence, permitted schedule/task/mailbox, native Graph access | Admit and execute | `adapters/graph/graph-01.app-exact-query`, `adapters/graph/graph-10.app-continuation`, `adapters/graph/graph-16.settled`, `adapters/graph/graph-13.claim-registered` |
| Same agent requests another application's identity | Registry/context mismatch; block. A presented executor application that differs from the registry's is `INADMISSIBLE` with `INVALID_CLAIM`, and the executor does not change | `adapters/graph/graph-13.claim-registered` (the validator's comparison), `adapters/graph/graph-13.shared-app` |
| Same agent requests another mailbox, by a path, parameter, or header | The mailbox is the registered one or the request is refused; a profile value never narrows or changes it | `adapters/graph/graph-12.app-mailbox-parameter`, `adapters/graph/graph-12.app-mailbox-header`, `adapters/graph/graph-12.other-workload-mailbox` |
| Gateway request whose query is not the constant (an added `$search`, reordered options) | `INVALID_MESSAGE`; no token request and no Graph request | `adapters/graph/graph-01.app-search`, `adapters/graph/graph-01.app-reordered` |
| PACT passes, but native mailbox authorization denies | Return the native denial; no escalation | `GRAPH-17.app-graph-refuses`, a Go test of the adapter package |
| Agent switches to a user-oriented `/me` design | Adapter rejects unsupported app-only request mapping | `adapters/graph/graph-11.workload-on-delegated-route`, `adapters/graph/graph-11.binding-no-mailbox`; `GRAPH-11.app-only-path` |
| Parallel broad grant, in Entra ID or as an Exchange scope of type `Organization` | Preflight fails; `FAIL` with `EXECUTOR_MISMATCH`; cached token discarded; no execution | `adapters/graph/graph-14.graph-mail-read`, `adapters/graph/graph-14.second-page`, `adapters/graph/graph-15.organization-scope`, `adapters/graph/graph-15.extra-row` |
| Preflight too old, unable to run, absent, or inside the settle window after a failure | Defer; the check is `UNKNOWN` | `adapters/graph/graph-16.older-than-p`, `adapters/graph/graph-16.unable-to-run`, `adapters/graph/graph-16.inside-settle-window` |
| Next page requested with a forged or foreign continuation | `CONTEXT_MISMATCH`; no downstream request | `adapters/graph/graph-09.app-other-path` |
| Schedule/task authorization expired | No execution under the old authorization | No case yet (`GRAPH-18`) |
| Required runtime or hold source unavailable | Defer rather than reuse an expired favorable result | No Graph case; the executor registry alone: `adapters/graph/graph-22.map-registry-unavailable` |
| Caller supplies a human's name to imply delegated authority | Does not establish user delegation | `GRAPH-19`, not an adapter case |

## Lifecycle, outcomes, and learning

Application-credential rotation and workload enrollment use their native administrative processes. The gateway documents the status and propagation bounds of application grants and cached identity data. It does not assume token expiry is the only revocation mechanism. The integration profile states those bounds: a parallel grant added after a preflight is found at the next preflight, an Exchange assignment change takes effect within 30 minutes to 2 hours, and a cached token lasts until its `expires_in` (profile section 9).

Record downstream application, task, request, admission, native decision, and observed execution with privacy-preserving evidence references. Qualified queue-summary assessments can update task quality. Merely starting a scheduled process, obtaining a token, or passing PACT adds no positive performance reputation. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, a downstream mailbox refusal is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, each page is a separately bound operation and so its own “Execution completed with data returned” report (`EXECUTION`, `SUCCESS`, `reliability`) under that operation's `operation_id` (Section 14.6 collapses the pages of one native task into one independence group), and the queue-summary assessment is an “Independent assessment” (`QUALITY`, `task_quality`). The integration profile `graph` records both actors in each report and maps the outcomes the same way (rules GR-29 and GR-30).

An authorized learning policy may vary capability-evidence freshness or a permitted autonomy tier. It cannot add Graph permissions, widen mailbox scope, change application enrollment, or infer a user delegation. If native policy introduces an approval checkpoint, the external workflow and a fresh evaluation apply.

## Boundary demonstrated

PACT supports autonomous workloads with their own explicitly established native authority. No signed-in user is required, and no user authority is silently borrowed.

**PACT anchors:** §§2–4, 6–12, 14–18.

## Primary references

- [Microsoft Graph: App-only access](https://learn.microsoft.com/en-us/graph/auth-v2-service)
- [Exchange Online: Application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [Microsoft Graph: List messages](https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0)
