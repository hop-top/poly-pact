# Integration 13 — Database privileges and row-level security

**Status:** Informative integration example for PACT Protocol v1.0. Organizations, identifiers, routes, requirements, and thresholds are fictional deployment choices. Excerpts are incomplete illustrations, not signed wire fixtures or a tested implementation. The gateway needs the described installed adapter; the named platform is not claimed to support PACT natively.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I13. Finding and component IDs are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- A trusted broker maps the user to a dedicated non-owner, non-superuser, non-BYPASSRLS role.
- The broker controls the fixed query, credentials, and complete native privilege audit.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | User/agent/report task and role binding. |
| C07 | Fixed parameterized query and report-ID mapping. |
| C08 | Actual connection/query under the restricted current role. |
| C14 | Private audit records without hidden-row or credential disclosure. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G20 | Specify pooled identity, reset, isolation, and supported query variants. Specified for PostgreSQL 16 by the integration profile [`db`](../profiles/db/profile.md), whose section 10.1 maps each G20 item to rules and cases; shared pooling that switches roles stays unsupported. | Profile / coverage |
| G07 | Adopt the Section 14.5 mapping: a zero-row or filtered result is “Execution completed, zero rows or filtered result”, with `details` of `"empty"`, and never implies that a hidden row was read. | Profile / clarification |

### Deliberate simplifications and limitations

- Dedicated login/fixed query simplify the scenario; shared pools and arbitrary SQL remain uncovered. Under the integration profile, one dedicated login role per principal with one connection pool per role is the claimed form; a shared login role that switches with `SET ROLE` is unsupported in wire version 0.1 (profile section 3.6, open decision OD-1).
- The SQL of this sample is executed only by the integration tier of the reference implementation against PostgreSQL 16; privilege changes during an open connection were probed only for a `REVOKE` of `SELECT`.

### Profile and fixtures

The integration profile [`db`](../profiles/db/profile.md) states the conformance claim behind this sample, for PostgreSQL 16 only: route R1 (`GET /api/v1/reports/{report_id}`, action `report.read`, an illustrative path) mapped to the fixed statement of step 6 in its query registry; one dedicated login role per principal, opened with that role's own credential and never changed after authentication (rules RA-1 to RA-6); the verification of every connection before the statement (rules CV-1 to CV-8); one pool per role with a rollback and `DISCARD ALL` on release (rules CR-1 to CR-7); and the zero-row semantics of rules RS-1 to RS-5. The authentication of Maya and of the agent's workload at the broker's front door is defined by the profile the deployment names for it, not by this one. The adapter cases are in [`fixtures/adapters/db/`](../fixtures/adapters/db/README.md), registered in the fixture manifest; the decisions table below names the case group or case for each row. The schema of this sample is the fixture asset [`schema.sql`](../fixtures/adapters/db/schema.sql), registered as `adapters/db/schema`. The case files call the adapter functions, none of which opens a database connection; the connections, their verification, and the reset are tested by the unit tier of the reference implementation with a recording driver, and by its integration tier (`TestIntegration` of the Go package `go/adapters/db`, source repository), which loads `schema.sql` verbatim into a PostgreSQL 16 server and runs `DB-01`, `DB-02`, `DB-05` to `DB-07`, `DB-09`, and `DB-10`. The profile's probe record of 2026-10-18 reports that tier green on PostgreSQL 16.15; the claim is limited to that version, and the tier is skipped when no server is configured.

### Validation still required

The cases and the integration tier cover tenant and principal separation across requests, owner, superuser, and `BYPASSRLS` roles, a removed `SELECT`, SQL substitution and injection, and empty results, for PostgreSQL 16.15. These remain unvalidated:

- PostgreSQL major versions other than 16, and other engines or products that speak its protocol (profile section 6).
- Facts the profile leaves to probes: whether a member of the owning role bypasses row security (open item OI-2), whether a policy change or `ALTER ROLE` reaches an open connection (OI-3, probed only for `REVOKE`), OID reuse after `DROP ROLE` (OI-4), and the error of a policy-applying query with `row_security` off (OI-6).
- Pooling beyond one pool per login role: shared pooling with role switching is unsupported, so no cross-role leakage test for it exists (open decision OD-1).
- The front-door authentication of the principal and the workload, under the profile the deployment names; network reachability of the cluster from outside the broker (bypass path B5).
- The native record of the connection role that Section 14.2 asks reports to reference (open decision OD-2), and the outcome-report sequences for the Section 14.5 rows (open decision OD-3).
- That the policy expressions are correct; the broker verifies only that row security is enabled and forced, that the role is not elevated, and which table privileges it holds (profile section 9).

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

An analytics assistant acts for Maya to retrieve one customer report. PostgreSQL already restricts the database role's table privileges and row visibility. The broker must execute the actual query as the assigned native role; it cannot query everything as a table owner and filter results only after disclosure.

This sample uses a dedicated login role, `report_maya`, bound by the trusted broker registry to Maya's native principal and the agent's authorized task. A pooled deployment requires equivalent identity isolation and reliable context reset; it cannot trust an agent-controlled session variable as proof of tenant identity.

## Native database rules

An administrator creates the following illustrative objects in a dedicated example database. Credential provisioning, TLS, schema ownership, connection limits, and the rest of the database policy are separate native setup. The statements are the fixture asset [`schema.sql`](../fixtures/adapters/db/schema.sql), verbatim; the integration tier of the reference implementation loads that file into a PostgreSQL 16 server and runs the database cases against it (see "Profile and fixtures"), and the recorded run was on PostgreSQL 16.15. No other version is claimed.

```sql
CREATE ROLE report_maya LOGIN NOSUPERUSER NOBYPASSRLS;

CREATE TABLE public.customer_reports (
    report_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    permitted_principal name NOT NULL,
    body text NOT NULL
);

REVOKE ALL ON public.customer_reports FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO report_maya;
GRANT SELECT ON public.customer_reports TO report_maya;

ALTER TABLE public.customer_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.customer_reports FORCE ROW LEVEL SECURITY;

CREATE POLICY maya_report_read
ON public.customer_reports
FOR SELECT
TO report_maya
USING (
    tenant_id = 'northstar'
    AND permitted_principal = current_user
);
```

An administrative owner distinct from `report_maya` owns the table. The execution role has no inherited elevated role, ownership, superuser privilege, or `BYPASSRLS`. Complete grants must be audited; these statements do not prove the absence of other privileges.

PostgreSQL combines ordinary privileges with row policies. For this SELECT policy, rows outside the expression are filtered; a successful query returning zero rows is not necessarily an authorization error. Owners can normally bypass RLS unless forced, and privileged bypass capabilities require separate care. See [row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) and [privileges](https://www.postgresql.org/docs/current/ddl-priv.html).

## Required PACT context

| Fact | Authoritative source | Integration profile |
|---|---|---|
| `/attributes/environment/principal_id` | Broker's authenticated user context | Produced by the front-door authentication, under the profile the deployment names |
| `/attributes/environment/database_role` | Registered mapping to `report_maya`; reconciled with the actual connection role | `db:{cluster-id}:report_maya` from the role and tenant registry (F1); the connection role is verified on every acquisition (rules RA-6, CV-1) |
| `/attributes/environment/tenant_id` | Trusted tenant mapping, independently consistent with native database policy | The tenant that the registry maps to the principal (F1); tenant isolation itself is the native row policy (rule RS-7) |
| `/attributes/delegation/authority_ref` | Current user/agent/report-task authorization | The delegation and task registry (F4), checked by `native-delegation-v1` |
| Runtime/capability evidence | Issuers specified by the effective contract | Outside the profile; attested-only, because no containment control is claimed (C16) |

The agent cannot select a login role, change tenant ownership, or install a row policy through profile attributes. The role name is a verified native fact, not a credential. Database passwords and connection secrets remain outside PACT artifacts.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Enrollment of the analytics assistant, resolved by the broker (Sections 6.1 and 6.2) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: the broker's authenticated user context for Maya (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the report task for `report.read` on report `R-481` |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Current user, agent, and report-task authorization |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the trusted broker and its registry |
| Downstream executor | Check `execution-identity-v1`; declared class `dedicated-role` | The dedicated login role `report_maya`, named by `/attributes/environment/database_role`, which the broker registry binds to Maya's principal and the agent's task |

The installed `execution-identity-v1` mapping declares the class `dedicated-role`, the role `report_maya`, for Maya, the report task, and the fixed parameterized query. The check returns `PASS` only when the role of the actual database connection equals that class and binding. The database applies table privileges and the row policy to that connection role. The role name is a verified native fact, not a credential, and an agent-controlled session variable is not proof of identity.

Adversarial results (Section 17.5):

- A principal or tenant other than Maya's presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- A task other than the registered report task presented: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The user-to-agent report authorization is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- The query would run under an owner, administrator, bypass, or pool-administrator role instead of `report_maya`: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The role mapping or connection role cannot be established: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample, including the filtered zero-row `EXECUTION` report, references in `evidence_refs` an immutable native record identifying the actual connection role. Section 14.2 states this without exception for the denial caused by a missing SELECT privilege. A report whose executor class differs from the declared `dedicated-role` class is `UNQUALIFIED`.

## Successful exchange

1. The broker authenticates Maya and the workload and resolves the enrolled agent/key, task authorization, tenant, and dedicated database-role mapping.
2. The agent requests requirements for `report.read` on report `R-481` under the recognized analytics task. The broker maps the proposed API operation to a fixed parameterized query.
3. The gateway issues its signed contract. The assistant fills the required profile, obtains evidence, and signs the complete presentation.
4. The validator checks the profile/native mapping, evidence, nonce, request and purpose binding, freshness, and holds. Passing requirements produce `ADMISSIBLE`.
5. The broker checks its native task policy and establishes a database connection authenticated as `report_maya`, without privileged-role fallback.
6. It executes its installed query, binding the report ID as a parameter:

```sql
SELECT report_id, body
FROM public.customer_reports
WHERE report_id = $1;
```

7. PostgreSQL enforces the role's SELECT privilege and RLS expression. A row for Northstar with `permitted_principal = 'report_maya'` can be returned. Another principal's or tenant's row remains invisible through this policy.
8. The broker returns only the authorized query result and resets/disposes of its native connection context safely. A later operation needs its own valid request binding.

The native query executes after applicable admission and broker conditions; the database applies row authorization during execution. A prior access estimate is not a substitute for actual execution under the correct role.

## Decisions and failure variations

| Condition | Expected behavior | Profile case |
|---|---|---|
| Correct agent/task/role, requested row satisfies RLS | Admit; query returns the permitted row | `adapters/db/db-01.role-first`, `adapters/db/db-08.mapped`; the returned row is the integration tier |
| Requested row exists but fails RLS | Query may succeed with zero rows; do not disclose hidden-row existence | `adapters/db/db-05.empty-report`; `DB-09` (integration tier) |
| Requested row does not exist | The same empty success response and outcome report as a hidden row | `DB-06`, with the report of `adapters/db/db-05.empty-report` |
| Role lacks table SELECT | No execution. The broker's connection verification finds the missing privilege and sends no statement (rule CV-4); a `SELECT` revoked after the verification fails natively with a database permission error, which is not retried | `adapters/db/db-07.denial-report`; the revocation and the native error are the integration tier |
| Agent edits profile to name an owner/admin role | Native mapping fails; never switch connection role (rule RA-6) | Evaluation of the claim against F1; a mapped role that is an owner, superuser, or `BYPASSRLS` role is refused by `DB-02` (unit and integration tiers) |
| Query/body changes after contract issuance | Request binding fails; no execution under the old presentation | Evaluation case `admission/modified-body`; a body on R1: `adapters/db/db-03.sql-body` |
| Role mapping or required source unavailable | Defer rather than execute as a pool administrator | `DB-08` |
| Arbitrary SQL submitted in place of the installed operation | Unsupported operation/mapping; no unrestricted SQL execution | `adapters/db/db-03.query-endpoint`, `adapters/db/db-03.no-registry-entry`, `adapters/db/db-03.sql-parameter` |
| SQL injected through the report ID | Outside the route grammar: `INVALID_MESSAGE`, no connection; inside it: sent only as parameter `$1` | `DB-04` |
| A second principal's request after Maya's | Its own role, pool, and tenant; nothing of the first request observed | `adapters/db/db-01.role-second`, `adapters/db/db-01.tenant-second` |
| Row security disabled or not forced on the table | Connection refused before the statement | `DB-10` (integration tier, with unit variants) |

A successful empty result cannot be recorded as evidence that a hidden report was successfully read. Execution, row visibility, and downstream analysis quality have separate meanings.

## Reputation, revocation, and learning

Qualified query-execution and report-quality observations can update the appropriate dimensions. Query acceptance alone does not prove a correct analysis. Repeated reads in one independent task group remain subject to positive contribution caps. Section 14.5 maps this exchange: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, a `SELECT` that the database refuses for lack of privilege is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight (a missing privilege that the broker's connection verification finds before any statement has no Section 14.5 row; the integration profile reports it as `EXECUTION`, `FAILURE`, `none`, rule RS-5), a returned permitted row is “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`), an RLS-filtered query is “Execution completed, zero rows or filtered result” (`EXECUTION`, `SUCCESS`, `reliability`) whose `details` is `"empty"` and which never implies that a hidden row was read, and report quality needs an “Independent assessment” (`QUALITY`, `task_quality`).

The broker documents connection/session lifetime, current-role checks, native privilege-change behavior, and cached mapping freshness; the integration profile states them in sections 3.3, 8, and 9. PACT does not instantaneously revoke already disclosed data or every open native session. Learning cannot grant SELECT, change a row policy, choose an owner connection, or enable RLS bypass.

## Boundary demonstrated

PACT validates the agent and bound task; the actual database identity and native row policy determine which records can be returned.

**PACT anchors:** §§2.3, 4.3, 8–12, 14–19.

## Primary references

- [PostgreSQL row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [PostgreSQL privileges](https://www.postgresql.org/docs/current/ddl-priv.html)
