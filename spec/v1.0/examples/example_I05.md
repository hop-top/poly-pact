# Integration 05 — SAML enterprise SSO

**Status:** Informative integration example for PACT Protocol v1.0. Organizations, identifiers, routes, requirements, and thresholds are fictional deployment choices. Excerpts are incomplete illustrations, not signed wire fixtures or a tested implementation. The gateway needs the described installed adapter; the named platform is not claimed to support PACT natively.

This example is informative: it does not establish a live integration, interoperability, or an end-to-end security result.


## Assumptions, components, and limitations

Component IDs C01 to C16 are the components of section 4 of the integration profile [template](../profiles/TEMPLATE.md); they are editorial identifiers, not protocol fields or registered reason codes.

### Assumptions

- The SAML SP owns a valid native session and an authorized server-side agent-task broker.
- The broker preserves user/session/task authority without exporting assertions as general agent credentials.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C02 | SP/IdP validation, session mapping, and current session state. |
| C04 | Explicit user-to-agent broker-task authority. |
| C08 | Portal execution retaining session-principal restrictions. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Deliberate simplifications and limitations

- An application task broker is assumed; not every SP provides one.
- Unattended agent login/delegation is not established by browser SSO.

### Profile and fixtures

The integration profile [`saml`](../profiles/saml/profile.md), in its revision 2, states the conformance claim behind this sample: a SAML 2.0 service provider whose task broker serves two agent-facing read routes inside the SP's request path, R1 (`GET /broker/v1/tasks/{task_id}/records/{record_id}`, action `record.read`) and R2 (`GET /broker/v1/tasks/{task_id}/records`, action `record.list`). The adapter consumes two native records and no SAML message: the SP's `SPSession`, which exists only after the SP's SAML implementation accepted the assertion (rules SB-1 and SB-2), and the broker's `TaskGrant`, which the user's authenticated portal action creates for an agent that is already enrolled (rule SB-8). The principal is `saml:{sp-id}:{idp-entity-id}:{subject}` (rule SB-4). It comes only from the session recorded in the grant that the request's task reference names, never from a header or a cookie (rule SB-16), and the agent authenticates to the broker with a credential of its own, which is neither an assertion nor the user's session (rule SB-15). The executor class is `delegated-user` (rule SB-19). Unattended SAML agent login, delegation supplied by SAML itself, and operations with side effects are not claimed (unsupported forms U1 and U2, rule SB-20). The profile is a draft and must not be cited as support for an enforced claim until every case of its section 10 exists and passes.

The adapter cases are in [`fixtures/adapters/saml/`](../fixtures/adapters/saml/README.md), registered in the fixture manifest under the ids below; the decisions table below names the case for each row. They stand a fake SP in for the SP's own SAML implementation, which turns the assertions of a case into sessions; they are not a live service provider or identity provider.

| Fixture ID | Exchange of this sample | Evidence |
|---|---|---|
| `SAML-01` | An assertion valid for a different SP | No session, so no principal: `adapters/saml/saml-01.wrong-audience` (native authentication denied). That a pre-authentication failure yields no `OutcomeReport` is a gateway property with no adapter case |
| `SAML-02` | A consumed assertion presented again | `adapters/saml/saml-02.session-unchanged` (the first session and its grant are unchanged), `adapters/saml/saml-02.replay-session` (a grant naming the session the replay would have created: denied), `adapters/saml/saml-02.after-logout` (a replay after logout revives nothing) |
| `SAML-03` | The profile or the request names another session's principal | Adapter half: `adapters/saml/saml-03.identity-headers` and `adapters/saml/saml-03.session-cookie` (authenticated as the grant's session principal), `adapters/saml/saml-03.grant-user-mismatch` (denied). The comparison, `native-principal-binding-v1` `FAIL` with `CONTEXT_MISMATCH`, is the validator's (draft Section 17.5) |
| `SAML-04` | The user session expires | `adapters/saml/saml-04.expired`, `adapters/saml/saml-04.at-expiry` (no grace), with the control `adapters/saml/saml-04.before-expiry`; `adapters/saml/saml-04.delegation` (the grant of the expired session fails `native-delegation-v1` with `REVOKED_EVIDENCE`) |
| `SAML-05` | The user logs out | `adapters/saml/saml-05.logged-out`; `adapters/saml/saml-05.delegation` (every grant of the session is unusable, `REVOKED_EVIDENCE`) |
| `SAML-06` | The task delegation expires | `adapters/saml/saml-06.expired-grant`, `adapters/saml/saml-06.at-expiry` (`native-delegation-v1` `FAIL` with `STALE_EVIDENCE`, no grace) |
| `SAML-07` | A task other than the recorded one; no grant for the task; a grant made for another agent; an operation outside the grant's scope; another user's principal | `adapters/saml/saml-07.other-task` (`TASK_MISMATCH`), `adapters/saml/saml-07.no-grant` (`MISSING_FIELD`), `adapters/saml/saml-07.other-agent` (refused at native authentication, the validator never sees the request), `adapters/saml/saml-07.outside-scope` and `adapters/saml/saml-07.other-principal` (`CONTEXT_MISMATCH`), `adapters/saml/saml-07.grantee-revoked` (refused at native authentication), `adapters/saml/saml-07.grantee-compromised` (authenticated; the hold is the validator's), with the control `adapters/saml/saml-07.usable` |
| `SAML-08` | Fresh membership requested while only the login time or a later read time is available | `adapters/saml/saml-08.login-time` (`STALE_EVIDENCE`), `adapters/saml/saml-08.read-time` (`RESTAMPED`), with the control `adapters/saml/saml-08.directory-times`, where the directory's own times pass through |
| `SAML-09` | A request from an enrolled agent when no live session was ever created | `adapters/saml/saml-09.no-session`, `adapters/saml/saml-09.no-task-route` (no principal; native authentication denied) |
| `SAML-12` | A portal action granting a task to an agent that is not enrolled, or is revoked or compromised | No case yet (planned); the rule is SB-8 |
| `SAML-13` | A valid session and grant, and the agent's binding revoked or marked compromised | No case yet (planned); `adapters/saml/saml-07.grantee-revoked` and `adapters/saml/saml-07.grantee-compromised` show the two statuses at native authentication |
| `SAML-14` | The broker would act under a broader portal credential | No case yet (planned): `execution-identity-v1` `FAIL` with `EXECUTOR_MISMATCH` |
| `SAML-15` | PACT admits and the portal's access policy denies Maya the supplier record | No case yet (planned): no execution |
| `SAML-17` | The agent's own credential through the enforcement point and directly; no credential and a forged one; the same subject from two identity providers; another user's grant | `adapters/saml/saml-17.via-enforcement-point`, `adapters/saml/saml-17.direct`, `adapters/saml/saml-17.no-credential`, `adapters/saml/saml-17.forged-token`, `adapters/saml/saml-17.idp-realm`, `adapters/saml/saml-17.other-user` |

The planned cases `SAML-10` (an agent credential on a grant creation route), `SAML-11` (a method or route outside R1 and R2), and `SAML-16` (two enrollments on one broker workload) concern paths and configurations that this sample does not show.

### Limitations and open points

Open in every example: the enforced integration scope; native identity and the enrolled agent and key mapping; exact request binding and native translation; achievable source freshness and execution-time rechecks; native outcome and visibility mappings; executed end-to-end conformance evidence; privacy, retention, correction, and lineage operations; and transport, latency, capacity, and outage budgets. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Open points specific to this example:

- Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check.
- Specify SAML session/broker lifecycle and supported versus unattended flows. Specified by the integration profile [`saml`](../profiles/saml/profile.md), whose Annex C maps each requirement to rules and cases; the profile establishes none of the evidence items until all of its cases exist and pass, and `SAML-10` to `SAML-16` are still planned.

The cases above cover wrong SP, replay, expired and logged-out sessions, wrong users, and unauthorized tasks, and show that a login time is not a membership observation time, at the adapter and against a fake SP. These remain unvalidated:

- A real SP and identity provider: the SP's own SAML implementation makes every assertion check (issuer, signatures, audience, recipient, validity window, `InResponseTo`, replay, logout), the adapter sees none of them, and a deployment names its SP product and exact version (profile open item OI-9).
- The planned cases `SAML-10` to `SAML-16` listed above, none of which has a file.
- An achievable source of fresh membership: no directory adapter profile has landed, so a contract that requires a membership fact cannot be claimed as enforced (open item OI-7).
- The semantics of the authority reference, which wait for the delegation binding model (open item OI-1).
- Behaviour that depends on the identity provider: how a session that ends there reaches the SP, since only a logout request at the SP or a new authentication does (profile section 9), whether an identity provider may issue a persistent identifier again to another subject (open item OI-4), and the handling of a persistent identifier whose `NameQualifier` names another entity (OI-3).
- Sessions established by an unsolicited response, which the `SPSession` cannot tell apart (open item OI-6), and the forged portal action that creates a grant without the user's intent, which is the SP's own defence to specify (profile section 9).

Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Maya signs into Northstar's purchasing portal through its existing enterprise SAML identity provider. She asks an enrolled purchasing assistant to prepare a supplier comparison using records that her portal account can read.

The portal's service provider (SP) retains the authenticated user session. Its authorized task broker accepts work from the enrolled agent and performs operations for Maya only within a native delegation recorded for this task. The SAML assertion is not handed to the agent as a reusable API credential.

## Native authority and enforcement

SAML establishes a user session at the SP. The application still owns supplier-record permissions and delegation. An installed PACT component in the portal's protected request path evaluates each agent-requested operation before the portal uses Maya's native authority (integration profile `saml`, section 3).

The SP uses its established SAML implementation to validate the trusted issuer, signatures, intended audience/recipient, validity, and request correlation/replay rules for the negotiated SSO profile. PACT does not replace XML signature processing with its JSON signatures. The application's opaque principal is derived from trusted issuer/subject mappings rather than an email address supplied in a profile. Under the integration profile, the subject is a persistent `NameID` value or the SP's immutable local account identifier, with the local account preferred, and never a transient or e-mail-format `NameID` (rule SB-4). The profile lists the checks that the SP's SAML implementation makes and the adapter does not see (its section "Scope and boundary"). See the [SAML profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) and [Microsoft's SAML implementation documentation](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol).

## Required profile and evidence

| Profile fact | Rule and source |
|---|---|
| `/attributes/environment/principal_id` | Equals the current SP session's native principal, `saml:{sp-id}:{idp-entity-id}:{subject}`, read live from the session record (rules SB-4 and SB-23); native comparison |
| `/attributes/environment/idp_realm` | Equals the session's configured identity-provider realm, read live from the session record (rule SB-23); native comparison |
| `/attributes/delegation/authority_ref` | References the broker's current Maya-to-agent task delegation; native validation. The profile fixes only that it is an opaque reference to one `TaskGrant` and not a credential (rule SB-12, open item OI-1) |
| `/attributes/runtime/isolation` | Equals the gateway's required runtime class; trusted runtime evidence |

The enrollment registry independently binds the agent ID, operator, and holder key. Signing in as Maya does not enroll an agent or authorize every agent that knows her name. If the contract requires fresh organizational membership, a session created hours ago cannot supply a fictitiously fresh observation; the configured native source must establish the demanded freshness. Under the integration profile, a membership fact comes only from a directory adapter with its own observation time and never from the login time (rule SB-22; `SAML-08`).

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment registry, which binds the agent ID, operator, and holder key independently of the SAML sign-in (Sections 6.1 and 6.2; integration profile rules SB-14 and SB-15) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: the current SP session's native principal, derived from trusted issuer and subject mappings; `/attributes/environment/idp_realm` equals the session's configured realm (Section 17.1); the profile reads the session recorded in the grant that the request's task reference names and takes nothing from a header or cookie of the request (rule SB-16) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the task the broker recorded for the supplier comparison, with its user, agent, and expiry |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | The broker's current Maya-to-agent task delegation, the profile's `TaskGrant` (rules SB-8 to SB-12) |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the installed PACT component in the portal's protected request path |
| Downstream executor | Check `execution-identity-v1`; declared class `delegated-user` | The broker's task, which performs operations for Maya under her SP session and the recorded delegation; the SAML assertion is never exported to the agent (integration profile rule SB-19) |

The installed `execution-identity-v1` mapping declares the class `delegated-user` for Maya's session principal, the supplier-comparison task, and the supplier-record read. The check returns `PASS` only when the executor that will run the read equals that class and binding. `authorize_native` is invoked with the session principal, never with the executor's own authority.

Adversarial results (Section 17.5):

- A profile naming another session's principal: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH` (integration profile rule SB-16; `SAML-03`).
- The request presented under a task other than the recorded comparison task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH` (rule SB-11; `adapters/saml/saml-07.other-task`).
- A grant made for another enrolled agent, reached with this agent's credential: native authentication is denied and the validator never sees the request (rule SB-16; `adapters/saml/saml-07.other-agent`).
- The task delegation is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE` (rule SB-11; `SAML-04` to `SAML-06`: an expired grant is stale, and a grant of an ended session is revoked).
- The broker would act under a broader portal credential in place of Maya's session: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH` (rule SB-19; no case yet, `SAML-14`).
- The executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this without exception for the portal's refusal of an unauthorized supplier record. A report whose executor class differs from the declared `delegated-user` class is `UNQUALIFIED`. An assertion rejected by the SAML implementation yields no `OutcomeReport` (integration profile section 3, `record_outcome`).

## Successful exchange

1. Maya completes ordinary SAML sign-in. The SP creates its session and maps the validated subject to its local account.
2. Through an authenticated portal action, Maya authorizes the enrolled assistant to perform the supplier-comparison task. The existing broker records the user, agent, permitted task, and expiry; under the integration profile this record is the `TaskGrant`, which can name only an agent that is enrolled and active at that moment and ends with the session (rules SB-8 and SB-10).
3. The broker maps the agent's proposed read to the actual supplier-record operation under that session. The agent requests PACT requirements for the recognized comparison purpose and exact operation.
4. After establishing native authentication and enrolled key binding, the gateway returns a signed requirement contract with effective field rules, context checks, digests, and a single-use nonce.
5. The assistant prepares the required profile view and runtime evidence, then signs the complete presentation. The broker associates the request with the authentic task/session context; a client header cannot select Maya's identity (rule SB-16; `adapters/saml/saml-03.identity-headers`).
6. The gateway checks the presentation, native profile facts, active delegation, purpose/operation relation, and current required status. Passing checks produce `ADMISSIBLE`.
7. The portal independently evaluates Maya's access to the requested supplier record and any native conditions. Only an allowed operation executes.

Each material operation change needs a new contract and presentation. Browser session lifetime does not extend a PACT nonce or turn a receipt into a session-wide permission (rule SB-21). The broker reads the session and the grant again immediately before the read starts (rule SB-11).

## Decisions and failure variations

| Condition | Expected behavior | Profile case |
|---|---|---|
| Valid user session, agent/task binding, evidence, and supplier access | Admit, then execute after native authorization | `adapters/saml/saml-07.usable` (a usable grant), `adapters/saml/saml-17.via-enforcement-point` |
| Valid user session but no delegation to this agent | Block under the required delegation check: a task with no grant fails `native-delegation-v1` with `MISSING_FIELD`. A grant made for another agent is refused earlier, at native authentication | `adapters/saml/saml-07.no-grant`, `adapters/saml/saml-07.other-agent` |
| Agent enrollment revoked or marked compromised after the grant | A revoked agent is refused at native authentication; a compromised one is authenticated and the validator refuses it with the `SECURITY_HOLD` receipt | `adapters/saml/saml-07.grantee-revoked`, `adapters/saml/saml-07.grantee-compromised`; `SAML-13` is planned |
| SAML assertion valid for a different SP | Existing SAML implementation rejects it; no native session is established, so no principal and no `OutcomeReport` | `adapters/saml/saml-01.wrong-audience` |
| A consumed assertion presented again | No second session; the first session and its grants are unchanged | `adapters/saml/saml-02.session-unchanged`, `adapters/saml/saml-02.replay-session`, `adapters/saml/saml-02.after-logout` |
| Profile names another session's principal | Context/native-value mismatch blocks admission: `native-principal-binding-v1` `FAIL` with `CONTEXT_MISMATCH`; identity headers and a copied session cookie change nothing | `adapters/saml/saml-03.identity-headers`, `adapters/saml/saml-03.session-cookie`, `adapters/saml/saml-03.grant-user-mismatch`; the comparison is the validator's |
| User session expires or task delegation is revoked | Do not continue under a stale authenticated context: an expired or logged-out session gives no principal and makes its grants unusable (`REVOKED_EVIDENCE`); an expired grant is `STALE_EVIDENCE` | `adapters/saml/saml-04.expired`, `adapters/saml/saml-04.delegation`, `adapters/saml/saml-05.logged-out`, `adapters/saml/saml-05.delegation`, `adapters/saml/saml-06.expired-grant` |
| Enrolled agent with no live session at all | No principal; unattended SAML login is not established | `adapters/saml/saml-09.no-session`, `adapters/saml/saml-09.no-task-route` |
| Broker would act under a broader portal credential | `FAIL` with `EXECUTOR_MISMATCH` | No case yet (`SAML-14`) |
| PACT passes but Maya lacks access to the supplier | Native authorization denies; no record is returned | No case yet (`SAML-15`) |
| Required fresh membership cannot be established | Defer; do not treat the original login as a new membership lookup. An unavailable source defers; a claim that carries the login time or a read time as the observation time is inadmissible (`STALE_EVIDENCE` or `RESTAMPED`) | `adapters/saml/saml-08.login-time`, `adapters/saml/saml-08.read-time`, with the control `adapters/saml/saml-08.directory-times`; no directory adapter profile has landed (open item OI-7) |

If the environment requires reauthentication or human approval, its own workflow handles that interaction. The agent obtains a fresh contract and presentation after the resulting native state becomes applicable. Earlier terminal receipts stay unchanged.

## Outcomes, reputation, and learning

Record PACT admission separately from the application's authorization and observed execution. Successful SAML authentication or admission adds no positive task-performance weight. Qualified comparison-quality observations may update this agent's contextual reputation. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, the portal's refusal of an unauthorized supplier record is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, an assertion rejected by the SAML implementation is a “Pre-authentication or transport failure” with no `OutcomeReport`, and only the supplier read's “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`) and an “Independent assessment” (`QUALITY`, `task_quality`) count.

An authorized selector may vary adaptive runtime or capability-evidence requirements. It cannot change the trusted identity provider, accept another SP's assertion, create a delegation, or override a native denial. Required human steps remain governed by the environment.

## Boundary demonstrated

A SAML-based application can preserve its SSO and account model while checking purpose-bound agent context at its own enforcement point. This does not make browser SSO a universal unattended-agent login protocol.

**PACT anchors:** §§2–4, 6–12, 14–18.

## Primary references

- [OASIS SAML 2.0 profiles](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [Microsoft SAML SSO protocol](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol)
