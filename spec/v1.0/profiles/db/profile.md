# PACT integration profile: database identity, row security, and pooling (PostgreSQL)

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

It is the integration profile (template instance, [`TEMPLATE.md`](../TEMPLATE.md)) for the database broker of the integration sample [`example_I13.md`](../../examples/example_I13.md): a PACT-aware broker that runs one fixed, parameterized query on PostgreSQL under a dedicated login role mapped to the requesting principal, so that the database's own privileges and row-level security decide which rows are returned. It answers the open finding G20 of `docs/handoff.md` (source repository only, not part of the mirror): role acquisition and current-role verification, owner, superuser, and `BYPASSRLS` exclusions, grants, row semantics, query binding, connection reset, and pooled identity. Section 10.1 maps each G20 closure item to the cases `DB-01` to `DB-10`. The machine-readable form is [`profile.json`](profile.json).

The profile adds no wire field and no protocol requirement. Where it and the draft ([`draft.md`](../../draft.md)) differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. Identity rules come from [`identity-mapping.md`](../identity-mapping.md) (cited IM-n), freshness rules from [`freshness.md`](../freshness.md), and request binding rules from [`request-binding.md`](../request-binding.md) (cited RB-n); this profile records only its own choices. Its rules carry the identifiers RA-1 to RA-7, CV-1 to CV-8, CR-1 to CR-7, QB-1 to QB-7, RS-1 to RS-7, and PI-1, so that fixtures and reviews can cite them.

## How to read the evidence

No PostgreSQL behavior had been executed when these rules were written; the probe record at the end of the open items says what the gated integration cases of section 10 established since, and changes no basis below. Every statement about what PostgreSQL does carries one of three bases:

| Basis | Meaning |
|---|---|
| `doc PGn` | The cited page of the PostgreSQL 16 documentation states it. The pages, read on 2026-10-16, are listed under Sources at the end. A page that does not say something is not read as saying it. |
| `design` | A requirement this profile places on the broker. It is a rule, not a statement about PostgreSQL. |
| `probe OI-n` | Not established by any page read. The open item names the probe that settles it. Until it runs, the profile makes no claim that depends on it. |

Where a premise is `probe`, the rule that rests on it is written so that it fails closed whichever way the probe comes out.

## Profile header

| Field | Value |
|---|---|
| Profile name | Database identity, row security, and pooling, PostgreSQL (`db`) |
| Target product and version | PostgreSQL 16, read from the version 16 documentation, whose pages show release 16.15 (Sources). Frontend/backend protocol version 3.0 (`doc PG19`). Other major versions and other engines are outside the claim (section 6) |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `r1`, 2026-10-16 |
| Maintainer | PACT adapter maintainers |
| Reference documents | draft = [`draft.md`](../../draft.md); handoff = `docs/handoff.md` (source repository only; sections 4 and 6 draw on it); example = [`example_I13.md`](../../examples/example_I13.md); [`identity-mapping.md`](../identity-mapping.md); [`freshness.md`](../freshness.md); [`request-binding.md`](../request-binding.md) |

## 1. Claim scope

The broker evaluates PACT in-gateway (draft §4.4) and serves one read-only route. It claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over the `header` presentation transport. It is a partial role implementation (draft §22.1): `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1; the roles it does not claim are supplied by connected services of the deployment. The executor class is `dedicated-role` (draft §17.5, sample I13).

The profile covers the database side of the broker: which login role runs the query, how the broker establishes and verifies it, how connections are pooled and reset, how the query is bound, and what an empty result means. Authentication of the principal and of the agent's workload at the broker's front door is supplied by the integration profile that the deployment names for it, such as an OAuth or SAML profile. This profile does not define that mechanism; a deployment that claims this profile names it in row 1 of section 3.

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
| Database engine in the claim | PostgreSQL 16 only |
| Pooled identity in the claim | One dedicated login role per principal, one connection pool per login role (section 3.3). Shared pooling that switches roles with `SET ROLE` is not claimed (section 3.6, open decision OD-1) |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` |
|---|---|---|
| `postgresql` | `3.0` | `pact-db-1` |

`3.0` is the version of the frontend/backend protocol that the PostgreSQL 16 documentation describes (`doc PG19`). `pact-db-1` names the route row of section 2, its approved native paths, the query registry with the exact text of each statement, the verification statements of section 3.2, and the list of protected tables. A change to any of them is a new mapping revision (RB-41, RB-64).

Profile parameters. The two numbers are illustrative policy choices, as in the template's mini-example, not recommended thresholds. A deployment sets its own values.

| Parameter | Illustrative value | Meaning |
|---|---|---|
| `connection_max_lifetime_seconds` | 300 | Longest time a database connection stays open (CR-6) |
| `role_pool_max_connections` | 2 | Most connections open at one time for one login role (CR-1) |

## 2. Protected routes and actions

One read route is protected. Any other route is not claimed. Sample I13 names the action `report.read` on report `R-481` and no URL, so the path below is illustrative; a deployment that adopts this profile writes its own route in its instance of this section.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/api/v1/reports/{report_id}` | `GET` | `report.read` | `report:{report_id}`, from the path parameter. `report_id` is 1 to 64 characters of ALPHA, DIGIT, and `-` (RB-34); no query parameter is read and no body is accepted (RB-37). The principal is the one authenticated at the front door, never the login role (RB-26) |

The facts a requirement on R1 can name are the approved native paths of mapping revision `pact-db-1` (draft §9.2, §17.2). Any other path is refused with `UNSUPPORTED_REQUIREMENT`.

| Native path | Value | Source (section 8) |
|---|---|---|
| `/attributes/environment/database_role` | `db:{cluster-id}:{login-role}` (identity mapping §3.3) of the login role the registry maps to the principal | F1 |
| `/attributes/environment/tenant_id` | The tenant the registry maps to the principal | F1 |
| `/attributes/delegation/authority_ref` | The current user, agent, and report-task authorization | F4 |

`/attributes/environment/principal_id` is produced by the front-door authentication and is listed in that profile. Sample I13 names the four paths and their sources.

The query registry holds one entry per (action, mapping revision). It is the translation row of RB-64 and request-binding §7.1 for R1, with a downstream origin fixed in trusted configuration (the cluster endpoint), the actor `dedicated-role`, and no continuation. The statement is the one of sample I13.

| Field | Value for R1 |
|---|---|
| Key | (`report.read`, `pact-db-1`) |
| Statement text | `SELECT report_id, body FROM public.customer_reports WHERE report_id = $1` |
| Parameters | `$1` is the path parameter `report_id`, as bound, as text |
| Relations read | `public.customer_reports`, a protected table (CV-3) |
| Access | read |
| Executor | `dedicated-role`: the login role that F1 maps to the principal |

## 3. Enforcement points

PostgreSQL applies the role's privileges and the table's row policies to the registered statement itself: a policy's `USING` expression is added to queries that refer to the table (`doc PG2`). For the database part, `authorize_native` and execution are therefore one native call, made under the mapped login role. The table lists the functions in request order; subsections 3.1 to 3.6 give the rules for each mechanism.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Broker front-door authentication stage, before routing, under the integration profile the deployment names for it | Adapter owner, IAM owner | Produces the principal (sample I13: Maya) and the agent's workload; not defined by this profile |
| 2 | `map_operation` | Broker mapping stage, revision `pact-db-1` | Adapter owner | Builds the operation context for R1 (request-binding §3 to §6) and selects the query registry entry by (action, mapping revision) (QB-1) |
| 3 | PACT evaluation | In-gateway validator in the same request path, after mapping and before any database connection is acquired | Gateway implementer | Runs `native-principal-binding-v1`, `native-delegation-v1`, and `execution-identity-v1` with the declared class `dedicated-role` (3.1) |
| 4 | `authorize_native` | The broker's native task policy for the original principal, then PostgreSQL's privilege and row-policy checks during execution of the registered statement under the mapped login role (3.5) | Resource owner (database administrator), application owner for the task policy | Invoked for the original principal, never with a broader identity (draft §17.5). A native denial is final (draft §2.3) |
| 5 | Execution | The registered statement on a connection of the mapped role's pool, after the connection verification of 3.2 | Broker, resource owner | Executor class `dedicated-role`; parameters bound (3.4); connection reset on release (3.3) |
| support | `resolve_agent_binding` | Enrollment registry lookup in the broker | IAM and security owner | Selects the record by the authenticated workload and the `agent_id` the request names; `UNKNOWN` when that agent has no record on the workload; a workload alone never names an agent. Whether the workload may carry more than one record is the choice of the front-door profile (section 7) |
| support | `read_native_claim` | Broker reads of the role and tenant registry (F1) and of the delegation and task registry (F4) | Adapter owner | Approved paths only (section 2) |
| support | `check_context` | Installed broker checks | Gateway implementer | `native-principal-binding-v1`, `native-delegation-v1`, `execution-identity-v1`; none other in wire version 0.1 |
| support | `record_outcome` | Broker outcome writer, after the statement completes, is refused, or is not sent | Gateway implementer | Mapping to draft §14.5 in RS-5; the native source of the executor-identity record is open decision OD-2 |

### 3.1 Role acquisition

| # | Rule | Basis |
|---|---|---|
| RA-1 | The role and tenant registry is trusted configuration (draft §4.2). It holds one record per (realm, principal): the `cluster-id`, the login role, the role's OID recorded at registration, a reference to the role's credential, the tenant, and the registry revision. Only administrators change it. No request data, AgentProfile attribute, signed claim, or model output selects or alters a record (IM-1). | `design`, draft §4.2, sample I13 |
| RA-2 | One login role per principal, and one principal per login role. The role has the `LOGIN` attribute, so it can be given as the initial session authorization name, and `NOSUPERUSER` and `NOBYPASSRLS`, which are the defaults. It owns no protected table. | `doc PG4`, `design`, sample I13 |
| RA-3 | The broker opens each connection for the role with that role's own credential, taken from the secret store (C14), so the session user is the role: the session user identifier is initially the (possibly authenticated) user name the client provided. | `doc PG12`, `design` |
| RA-4 | No role is assumed after authentication. The broker never sends `SET ROLE`, `SET SESSION AUTHORIZATION`, `RESET ROLE`, or `SET ROLE NONE` (QB-5). A session whose authenticated user is not a superuser can change its session user only to the authenticated user name, and CV-1 refuses a superuser. The `db` identifier never names a role assumed after authentication (identity mapping §3.3). | `doc PG12`, identity mapping §3.3, `design` |
| RA-5 | `execution-identity-v1` returns `PASS` at evaluation only when F1 maps the principal to a login role, the declared class is `dedicated-role`, and the broker holds a pool for that role (3.3). A registry that has no record for the principal, or cannot answer, gives `UNKNOWN`, which yields `DEFERRED` with `DEPENDENCY_UNAVAILABLE`; no connection is opened under any role. The broker holds no credential of an owner, superuser, `BYPASSRLS`, or pool-administrator role for this route, so no fallback exists to take (`DB-08`). At execution the same check is applied to the actual connection by CV-1 to CV-7 (freshness profile, section 6). | draft §17.5, §18, sample I13, `design` |
| RA-6 | A value of `/attributes/environment/database_role` that an AgentProfile carries is a claim compared with F1, never an input that selects a connection. An agent that names an owner or administrator role fails the rule, and the connection role does not change. | draft §17.2, sample I13 |
| RA-7 | Name reuse (IM-6) is handled both ways IM-6 allows. (a) The registry records the role's OID (`pg_roles.oid`, "ID of role") at registration and CV-1 compares it at every acquisition, so a role dropped and created again with a new OID is refused. (b) Dropping a login role is a revocation event: the administrator withdraws its registry record. The `oid` type is an unsigned four-byte integer, not large enough to provide database-wide uniqueness in large databases; whether a new role can receive the OID of a dropped one is not established, so (a) is not claimed to detect that case and (b) covers it. | `doc PG7`, `doc PG20`, IM-6; reuse `probe OI-4` |

### 3.2 Connection verification

Three verification statements run on the connection itself. They read the catalog and functions below: `current_user` is the user identifier applicable for permission checking, which `SET ROLE` and functions with `SECURITY DEFINER` change; `session_user` is normally the user who initiated the connection (`doc PG10`). `pg_roles` is a publicly readable view of `pg_authid` with columns `rolname`, `rolsuper`, `rolbypassrls`, `rolcanlogin`, and `oid` (`doc PG7`). `pg_class` has `relowner`, `relkind`, `relrowsecurity` ("row-level security enabled"), and `relforcerowsecurity` ("will also apply to table owner") (`doc PG8`); `pg_namespace` has `nspname` (`doc PG9`). `pg_has_role` with `MEMBER` "denotes direct or indirect membership in the role without regard to what specific privileges may be conferred", and `has_table_privilege` with no user argument tests `current_user`, takes a table by OID, and is true for a list of privilege types "if any of the listed privileges is held" (`doc PG10`).

V1, the connection role:

```sql
SELECT current_user, session_user, r.oid, r.rolsuper, r.rolbypassrls
FROM pg_catalog.pg_roles AS r
WHERE r.rolname = current_user;
```

V2, elevated or foreign memberships:

```sql
SELECT count(*)
FROM pg_catalog.pg_roles AS r
WHERE r.rolname <> current_user
  AND (r.rolsuper OR r.rolbypassrls OR r.rolcanlogin)
  AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER');
```

V3, once per protected table, with the schema name as `$1` and the table name as `$2`:

```sql
SELECT c.relkind, c.relrowsecurity, c.relforcerowsecurity, o.rolname,
       pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER'),
       pg_catalog.has_table_privilege(c.oid, 'SELECT'),
       pg_catalog.has_table_privilege(c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_roles AS o ON o.oid = c.relowner
WHERE n.nspname = $1 AND c.relname = $2;
```

| # | Rule | Basis |
|---|---|---|
| CV-1 | V1 passes only when it returns exactly one row in which `current_user` and `session_user` both equal the login role of the F1 record, compared octet for octet, `oid` equals the OID recorded at registration (RA-7), and `rolsuper` and `rolbypassrls` are both false. Equal `current_user` and `session_user` show that no `SET ROLE` is in effect. Superusers and roles with `BYPASSRLS` always bypass row security. | `doc PG1`, `doc PG7`, `doc PG10`, `design` |
| CV-2 | V2 passes only when it returns 0: the role is not a member, directly or indirectly, of another role that has `SUPERUSER`, `BYPASSRLS`, or `LOGIN`. Role attributes are not inherited, but a member whose grant has the `SET` option can `SET ROLE` to the role and use them; row policies follow normal role membership and inheritance rules, so membership in another login role would give the mapped role that role's grants and policies. `MEMBER` counts a membership whatever its `INHERIT` and `SET` options. Group roles without `LOGIN` (`NOLOGIN` is the default) stay usable for grants. Sample I13 assumes "no inherited elevated role". | `doc PG1`, `doc PG4`, `doc PG5`, `doc PG10`, sample I13 |
| CV-3 | V3 passes for a table only when it returns exactly one row in which `relkind` is `r` (ordinary table), `relrowsecurity` and `relforcerowsecurity` are both true, the owner's `rolname` differs from `current_user`, and the role is not a member of the owner. Table owners normally bypass row security unless `FORCE ROW LEVEL SECURITY` is set. When row security is disabled, policies that exist for the table are ignored; when it is enabled and no policy exists, a default-deny policy applies. The right to modify or destroy an object, like all privileges, can be inherited by members of the owning role; whether a member of the owning role also bypasses row security is not stated in the pages read, so membership is refused whichever way it comes out. Forced row security is required although the owner never runs the statement, so that the policies stay in force for every role, as sample I13 configures the table. | `doc PG1`, `doc PG3`, `doc PG6`, `doc PG8`, sample I13; membership `probe OI-2` |
| CV-4 | In V3, `SELECT` is held and none of `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, and `TRIGGER` is. The route is read-only. Operations that apply to the whole table, such as `TRUNCATE` and `REFERENCES`, are not subject to row security, and referential integrity checks always bypass it. A role holds the sum of its direct grants, the grants to roles it is a member of, and the grants to `PUBLIC`; tables grant nothing to `PUBLIC` by default. Whether `has_table_privilege` counts a privilege the role could use only after `SET ROLE` (a membership without `INHERIT`) is not stated; registered statements never change role (QB-5), so such a privilege is not exercised. | `doc PG1`, `doc PG6`, `doc PG10`, `doc PG21`, `design`; `probe OI-3` |
| CV-5 | Every relation and function in V1 to V3 and in every registered statement is schema-qualified, the catalogs as `pg_catalog`. A session's temporary-table schema is searched first for relation names when the path does not list it, even before `pg_catalog`; the default search path suits only a single user or a few mutually trusting users; and a prepared statement that names a table without a schema is not re-parsed when a table of that name appears earlier on the path. `current_user` and `session_user` are special syntax, called without parentheses, and are not qualified. | `doc PG10`, `doc PG14`, `doc PG15`, `design` |
| CV-6 | Verification runs on every acquisition of a connection for an operation, after the reset of CR-3, on that connection, immediately before the registered statement, with no other statement in between. A result is never reused for another acquisition. | `design` |
| CV-7 | Any condition false, an unexpected row count, or an error closes the connection, which never returns to the pool, and no registered statement is sent. A failure of V1, V2, or the owner conditions of V3 is `execution-identity-v1` `FAIL` with `EXECUTOR_MISMATCH` (draft §17.5). A failure of the flags, kind, or privilege conditions of V3 is a native execution condition not satisfied (draft §2.3): no execution. A catalog that cannot be read, or a connection that cannot be opened, is `DEPENDENCY_UNAVAILABLE` with no statement (draft §18). In no case is the operation retried under another role or connection. | draft §2.3, §17.5, §18, `design` |
| CV-8 | The broker never changes `row_security`. If a deployment sets it to `off` for the role, queries that would apply a policy fail instead of returning unfiltered rows, which is a native error recorded as such and not a disclosure. The parameter has no effect on superusers and `BYPASSRLS` roles, which CV-1 refuses. | `doc PG15`, `design`; error code `probe OI-6` |

### 3.3 Pools, reset, and reuse

| # | Rule | Basis |
|---|---|---|
| CR-1 | One pool per (`cluster-id`, login role), with at most `role_pool_max_connections` connections. A connection belongs to the role it authenticated as for its whole life (RA-3, RA-4) and is never given to another role's pool, principal, or tenant. | `design`, sample I13 |
| CR-2 | A connection serves one operation at a time. It is acquired after admission and released when the result has been read or the operation has failed. | `design` |
| CR-3 | On release, an open transaction is rolled back and then `DISCARD ALL` is sent. `DISCARD ALL` "resets the session to its initial state" and has the effect of `CLOSE ALL`, `SET SESSION AUTHORIZATION DEFAULT`, `RESET ALL`, `DEALLOCATE ALL`, `UNLISTEN *`, `SELECT pg_advisory_unlock_all()`, `DISCARD PLANS`, `DISCARD TEMP`, and `DISCARD SEQUENCES`; it cannot be executed inside a transaction block, which is why the rollback comes first. `SET SESSION AUTHORIZATION DEFAULT` resets the session and current user identifiers to the originally authenticated user name. | `doc PG12`, `doc PG13` |
| CR-4 | A connection whose rollback or `DISCARD ALL` fails, or does not complete within its deadline, is closed and never returned to the pool. | `design` |
| CR-5 | Prepared statements last for the duration of the session and can be removed with `DEALLOCATE`; a named statement of the extended protocol lasts until the end of the session unless destroyed. `DISCARD ALL` includes `DEALLOCATE ALL`, so the broker prepares the registered statement again after a reset. A client library that caches prepared statement names across the reset must not reuse a name the reset removed; whether a given library does is checked in its implementation. | `doc PG13`, `doc PG14`, `doc PG17`; `probe OI-5` |
| CR-6 | A connection is closed `connection_max_lifetime_seconds` after it was opened, once an in-flight statement completes. The parameter bounds how long a connection opened before a privilege or role change can serve operations (section 9, OI-3). | `design` |
| CR-7 | No cross-role and no cross-request state. The broker sets no session state from request data (QB-5), and the reset removes what a session can carry between requests (CR-3). A second principal's operation runs on a connection of its own role's pool and observes nothing of the first (`DB-01`). | `design` |

### 3.4 Query binding

| # | Rule | Basis |
|---|---|---|
| QB-1 | `map_operation` selects the query registry entry by (action, mapping revision). An action with no entry at the installed revision is refused with `UNSUPPORTED_REQUIREMENT`, and no statement is sent (`DB-03`). | RB-33, RB-46, `design` |
| QB-2 | The statement text is a constant of the entry and part of the mapping revision. It holds no request data, one SQL statement, schema-qualified names (CV-5), and no call of a user-defined function. Tables, columns, sort keys, and limits are constants. | RB-64, `design` |
| QB-3 | Request data reaches the server only as a parameter value in the extended query protocol: the Parse message carries the query text and "cannot include more than one SQL statement", and the Bind message carries "the values to use for any parameter placeholders". Separating parameter values from the command string avoids quoting and escaping. The broker never puts request data into a simple Query message, whose string can contain several statements separated by semicolons. | `doc PG16`, `doc PG17` |
| QB-4 | A parameter value first passes the route grammar of section 2. A value outside it is refused with `INVALID_MESSAGE` at binding, before any connection is acquired (`DB-04`). A value inside it is bound unchanged as `$1`, so text such as `R-481--` reaches the server as a value and never as SQL (`DB-04`). | RB-34, RB-38 |
| QB-5 | The broker sends only these statements on a connection: the transaction end and reset of CR-3, V1 to V3, and the registered statement of the operation. No `SET`, `set_config`, `SET ROLE`, `SET SESSION AUTHORIZATION`, `LISTEN`, `COPY`, or DDL is sent. | `design` |
| QB-6 | Arbitrary SQL is unsupported. A route that carries SQL text has no mapping row and is refused with `UNSUPPORTED_REQUIREMENT` (RB-33); a query parameter that R1 does not list is covered by `target_uri`, is not read, and is not forwarded (RB-36, RB-50) (`DB-03`). | RB-33, RB-36, RB-50 |
| QB-7 | One gateway request runs exactly one registered statement. No enrichment query, no existence query, and no second query under another role or with row security off is made (RS-3). | RB-54, `design` |

### 3.5 Row semantics and outcomes

| # | Rule | Basis |
|---|---|---|
| RS-1 | The statement runs under the mapped role, and PostgreSQL applies the role's privileges and the table's row policies. For `SELECT` a policy "filters" the existing row: a row for which the `USING` expression returns false or null is not visible and is silently suppressed, with no error. A row that does not exist and a row that a policy hides both give zero rows; the broker cannot tell them apart and does not try. | `doc PG1`, `doc PG2` |
| RS-2 | Zero rows is a successful execution. The command tag is `SELECT rows`, where rows is the number of rows retrieved. The gateway answers with the route's success response and an empty result, the same response for an absent row and a hidden row, and does not synthesize a not-found or forbidden response (`DB-06`). | `doc PG18`, `design` |
| RS-3 | The existence of a hidden row is never recorded or inferred. The broker makes no second query as the owner, as a superuser, under another role, or with `row_security` off; it counts no rows beyond those returned; and it records no statement that a requested row exists (`DB-05`). | `design`, sample I13 |
| RS-4 | The result is returned as PostgreSQL produced it. The broker filters nothing in code: querying as the owner and filtering after the fact discloses before it authorizes (sample I13). | `design`, sample I13 |
| RS-5 | Outcome mapping. Errors are recognized by their SQLSTATE code, not by the message text. A refusal before any statement has no row in draft §14.5; it is reported as `EXECUTION` / `FAILURE` / `none`, a profile choice, as in the files profile. | draft §14.5, `doc PG22`, `design` |
| RS-6 | Every `EXECUTION` and `AUTHORIZATION` report references in `evidence_refs` an immutable native record that identifies the actual connection role: the V1 result of that connection (`session_user`, `current_user`, role OID) and its time (draft §14.2, Appendix A.2). Which native facility holds the record is open decision OD-2. The record holds no credential, no row content, and nothing about hidden rows. | draft §14.2, Appendix A.2, sample I13 |
| RS-7 | Tenant isolation is a native row policy. The broker compares the tenant fact of F1 with the requirement, adds no tenant filter to the statement, and sets no session value for a policy to read (QB-5); a policy whose expression depends on a session setting is outside the claim (section 6). | sample I13, identity mapping §3.3, `design` |

The outcome mapping of RS-5:

| Native result | `event_kind` / `result` / `dimension` | Draft §14.5 row |
|---|---|---|
| PACT admission decision | `ADMISSION` / `SUCCESS` or `FAILURE` / `none` | PACT admission decision; zero weight |
| The broker's task policy allows | `AUTHORIZATION` / `SUCCESS` / `none` | Native authorization allow; zero weight |
| The broker's task policy denies | `AUTHORIZATION` / `FAILURE` / `none` | Native denial; zero weight, not misconduct |
| The statement fails for lack of privilege, such as a missing `SELECT` (SQLSTATE `42501`, `insufficient_privilege`, `doc PG22`; that a missing `SELECT` raises this code is `OI-6`) | `AUTHORIZATION` / `FAILURE` / `none` | Native denial (sample I13); no retry |
| The statement completes with one or more rows | `EXECUTION` / `SUCCESS` / `reliability` | Execution completed with data returned |
| The statement completes with zero rows | `EXECUTION` / `SUCCESS` / `reliability`; `details` is `"empty"` | Execution completed, zero rows or filtered result; the report never implies that a hidden row was read |
| The connection fails or the statement is cancelled after it was sent (class `08`, or `57014` `query_canceled`, `doc PG22`) | `EXECUTION` / `UNKNOWN` / `none` | Ambiguous timeout; no automatic retry |
| Any other SQL error after the statement was sent: a SQLSTATE other than `42501`, class `08` and `57014` | `EXECUTION` / `FAILURE` / `none` | No row; profile choice, zero weight |
| Refusal by CV-7, or an execution-time dependency failure, with no statement sent | `EXECUTION` / `FAILURE` / `none` | No row; profile choice |

### 3.6 Pooled identity: why role switching is not claimed

| # | Rule | Basis |
|---|---|---|
| PI-1 | The claimed form is one dedicated login role per principal with one pool per role (RA-2, CR-1). Shared pooling under one login role that switches with `SET ROLE` or `SET LOCAL ROLE` is unsupported in wire version 0.1 (sample I13, handoff I13 row). The pages read give the reasons. The session user needs the `SET` option, directly or through a chain of memberships, for every role it switches to, so the pool's login role can become any mapped role and is broader than any one principal. `RESET ROLE` and `SET ROLE NONE` "can be executed by any user" and return the current user to the session user or the connection-time setting. `SET ROLE` does not process the role's `ALTER ROLE` settings, which happens only at login, so the session differs from a login as that role. `current_user` changes with `SET ROLE` and `session_user` does not, so CV-1 cannot hold. `SET SESSION AUTHORIZATION` to another user requires an authenticated superuser, which CV-1 refuses. Open decision OD-1 records the runner-up and what adopting it would change. | `doc PG10`, `doc PG11`, `doc PG12`, `design` |

## 4. Native dependencies

All sixteen components are listed; each unused one carries its reason. "To be supplied" means the component is a responsibility of the deployment or of later work, and listing it does not assert that it has been built.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and filter chain of the database broker | Gateway implementer | To be supplied |
| C02 | Native authentication and claim adapters | baseline | Front-door authentication under the profile the deployment names; the broker's reads of the role and tenant registry and of the delegation and task registry | IAM owner and adapter owner | To be supplied; the front-door mechanism is defined by its own profile |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry with administrator-run enrollment, looked up by the agent's front-door workload and the presented `agent_id` | IAM and security owner | Registry contract and a memory backend exist; a durable backend is to be supplied |
| C04 | Native delegation and task authority | delegated or task execution | Delegation and task registry binding user, agent, and report task, read through `authority_ref` | Application and IAM owner | To be supplied; the semantics of `authority_ref` are a dependency on the delegation and execution-identity deliverable (finding G03) |
| C05 | Evidence and authoritative status sources | baseline | Role and tenant registry, delegation and task registry, hold store, and the PostgreSQL catalog read by V1 to V3 | Adapter owner, database administrator | To be supplied; the catalog exists |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the read route needs no external approval |
| C07 | Purpose and exact operation mapper | baseline | Mapper at revision `pact-db-1` with the query registry (section 2) | Adapter owner | To be supplied |
| C08 | Native resource executor and authorization | the actual resource operation | PostgreSQL 16: table privileges and row policies applied to the mapped login role during execution | Resource owner (database administrator) | Exists in the deployment; the sample I13 schema ran in the gated integration tier (`OI-1`, probe record) |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store | Gateway and platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Broker outcome writer, and an immutable record naming the connection role | Resource owner and evidence owner | The native source of the executor record is OD-2 |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | Registry only, no adaptation lifecycle; to be supplied |
| C13 | Revocation and security holds | baseline | Revocation and hold store | Security and IAM owner | To be supplied |
| C14 | Protected evidence and audit storage | baseline | Access-controlled evidence and audit store; secret store holding the login roles' credentials | Security and data owner | To be supplied; credentials, row contents, and hidden-row facts are excluded from records (RS-6) |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | Per-role pools, connection lifetime, one statement per operation, reset on release (3.3) | Application and resource owner | To be supplied; no transactions or budgets because the route is read-only |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no containment, egress, or output control is claimed; data-use restrictions are labeled attested-only |

## 5. Alternative and bypass paths

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Execution under the table owner, a superuser, a `BYPASSRLS` role, a member of one of them, or a pool-administrator role instead of the mapped role (broader-account fallback) | `closed` | The broker holds no such credential (RA-5); every connection is verified before use (CV-1 to CV-3, CV-7); fixtures `DB-02`, `DB-08`, `DB-10` |
| B2 | Reuse of a connection, its prepared statements, or its session state by another principal, role, tenant, or request | `closed` | One pool per role, reset on release, verification on acquisition (3.3, 3.2); fixture `DB-01` |
| B3 | Arbitrary SQL, a substituted statement, or SQL injected through a parameter | `closed` | Fixed statements from the query registry, values bound in the extended protocol, route grammar (3.4); fixtures `DB-03`, `DB-04` |
| B4 | Writes through the broker: `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, or any statement not in the registry | `closed` | Only R1 exists; the registry holds one read statement (QB-1, QB-5); write privileges must be absent (CV-4); fixtures `DB-02`, `DB-03` |
| B5 | A direct database connection with the mapped role's credential, from outside the broker | `out-of-claim` | The credential stays in the broker's secret store (C14) and never reaches an agent, a profile, or a record (sample I13); network reachability of the cluster is a deployment control with no negative fixture here; excluded in section 6 |
| B6 | Other clients of the same cluster: interactive sessions, reporting tools, other applications, standbys, logical replicas, backups, and exports | `out-of-claim` | Not a broker route; native privileges and row policies apply unchanged; excluded in section 6 |

## 6. Unsupported forms

The first two rows are two of the three forms of the I13 row of the handoff "Deliberate design choices" table; the third form is no longer unsupported (below the table). The others come from sample I13 and from the rules of section 3.

| Unsupported form | Seed (handoff source row) | Why it is not established |
|---|---|---|
| Safe shared pooling, including one login role that switches with `SET ROLE` or `SET LOCAL ROLE` | I13 database: "Safe shared pooling" | One login role per principal and one pool per role are claimed (3.3); the reasons and the runner-up are in PI-1 and OD-1 |
| Arbitrary SQL | I13 database: "arbitrary SQL" | Only the fixed statements of the query registry run (3.4) |
| Database engines other than PostgreSQL, PostgreSQL major versions other than 16, and products that implement the PostgreSQL protocol | Section 1 | No documentation for them was read for this profile |
| Any route other than R1, including every write | Section 2 | Not listed in section 2, so not claimed |
| Relations other than ordinary tables in a registered statement: views, materialized views, partitioned tables, foreign tables | Section 3.2, CV-3 | Row-security behavior for them was not read; V3 refuses any `relkind` other than `r` |
| Row policies whose expression reads a session setting set by the application or the adapter, or any value the agent supplies | Sample I13: an agent-controlled session variable is not proof of identity; identity mapping §3.3, `db` row | The broker sets no session value (QB-5, RS-7) |
| A login role shared by several principals, or a principal mapped to several roles | Section 3.1, RA-2 | One role per principal |
| A registered statement that calls a user-defined function, or that lets the request choose a table, column, sort key, or limit | RB-64; section 3.4, QB-2 | Statements are constants with bound values only |
| Front-door authentication of the principal and the agent's workload | Section 1 | Defined by the profile the deployment names, not here |
| Enforced purpose or data-use restrictions | Draft §17.4 | `execution-control-v1` is not claimed, so any such restriction is labeled attested-only and no egress or output control is claimed |

Executed database verification, the third form of the I13 row ("executed database verification"), is established by the gated integration tier: the integration cases `DB-07`, `DB-09` and `DB-10` run the verification statements and the sample I13 schema against PostgreSQL 16 (`OI-1`, probe record). The tier runs only where the environment variable `PACT_TEST_PG_DSN` names a database; elsewhere those cases do not run, and a run without it establishes nothing about a database.

## 7. Identity mapping

Rules are those of [`identity-mapping.md`](../identity-mapping.md); this table records the choices of this profile.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | The principal and the agent's workload use the namespace of the front-door profile. The executor is `db:{cluster-id}:{login-role}` (identity mapping §3.3), with `cluster-id` the configured identifier of the cluster and `login-role` the role the connection authenticated as, written under IM-2. A role assumed after authentication and a value set in the session are never used (RA-4). The login role is the executor, never the principal (RB-26) |
| Trusted enrollment actors | Agent enrollment: the native administrative workflow (identity mapping §4.2). The role and tenant registry: database and registry administrators through their native administrative workflow (RA-1). The agent, an AgentProfile, and anyone presenting the holder key are not actors for either (IM-12, IM-13) |
| Shared-account handling | Inherited (identity-mapping §5, IM-19): the workload comes from the front-door authentication (section 3, row 1), so the shared-account choice and its consequence are those of the front-door profile that the deployment names. Login roles are not shared between principals (RA-2). Several agents that act for one principal run under that principal's login role, which is the executor and names no agent (IM-16); agents are told apart by their own enrollment on the front-door workload and by the presented `agent_id` (IM-18) |
| Certificate, token, or role-session bindings | None. The login role's credential is held by the broker and is not bound to the holder key (IM-21); no certificate, `cnf` constraint, or role session is used |
| Lifecycle rules (rotation, compromise, recovery) | Deferred to `identity-mapping.md`. Login role name reuse is handled by RA-7 under IM-6. A change of role attributes or memberships takes effect at the next acquisition, when CV-1 to CV-3 read the catalog again (`doc PG4`: every attribute can be changed later by `ALTER ROLE`) |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule. Narrowings: one principal per login role, and the executor identifier never names a role assumed after authentication |

## 8. Freshness

Six sources are listed; every outage ends in `DEFERRED`, which fails closed (draft §18). The class of each source is that of the freshness profile, section 4.1. The front-door authentication source that yields `principal_id` has its row in the profile that defines it, and a deployment instance of this profile copies that row here.

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Broker role and tenant registry (principal to login role and tenant) | Current authoritative state, read for each evaluation; the status time is the read time, the observation time is the last change of the record (IM-10) | 30 | 0 | `DEFERRED` |
| F2 PostgreSQL catalog read by the connection verification (connection role, role attributes, memberships, table owner, row-security flags, table privileges) | Current authoritative state at acquisition, read from the catalog and functions of section 3.2 (`doc PG7`, `doc PG8`, `doc PG10`); the observation and status time are the instant V1 is sent on the connection that will run the statement | 0 | 0 | `DEFERRED` |
| F3 PostgreSQL privilege and row-policy checks at statement execution | Current authoritative decision, made by the server when it executes the registered statement (`doc PG2`; freshness profile, section 6, execution point). Whether a revocation reaches an open connection at its next statement is `OI-3`; until settled, the bound is `connection_max_lifetime_seconds` (section 9) | 0 | 0 | `DEFERRED` |
| F4 Delegation and task registry (`authority_ref`) | Current authoritative state; the semantics of `authority_ref` depend on the delegation deliverable | 30 | 0 | `DEFERRED` |
| F5 Enrollment registry (agent and key binding status) | Current authoritative state; the status time is the read time, the observation time is the last change (IM-10) | 30 | 0 | `DEFERRED` |
| F6 Security hold store | Current authoritative state, read for each evaluation | 30 | 0 | `DEFERRED` |

### 8.1 Membership and status sources

Only F1 supplies a role fact: the login role mapped to the principal, read at `/attributes/environment/database_role`. F2 and F3 are read at execution to verify and run the operation and supply no fact to PACT evaluation; F5 supplies binding status, not membership.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 Broker role and tenant registry (principal to login role and tenant) | `roles` | `true` | Broker registry lookup by realm and principal | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

### 8.2 Attribute sources

F1 also supplies the tenant of the principal. The delegation reference of F4 is a delegation fact checked by `native-delegation-v1` and is not a subject, resource, or environment attribute.

| Source | `category` | `attributes` | `freshness` |
|---|---|---|---|
| Broker role and tenant registry | `subject` | `/attributes/environment/tenant_id` | F1 Broker role and tenant registry (principal to login role and tenant) |

## 9. Residual limits

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Report data already returned to the agent is not recalled by a later revocation. `execution-control-v1` is not claimed, so any purpose or data-use restriction is attested-only and no egress or output control is claimed (draft §17.4, §18) | Disclosed here; no bound |
| Revocation propagation | A change to F1, F4, F5, or F6 reaches the broker at the next evaluation within each source's own consistency. A change of role attributes, memberships, ownership, row-security flags, or table privileges reaches the broker at the next acquisition (CV-6). An operation already executed is not undone by revoking its receipt (draft §18) | 0 s status bound for F1, F4, F5, F6; the next acquisition for F2 |
| Open connection | Whether a `REVOKE`, a policy change, or an `ALTER ROLE` takes effect for the next statement on a connection already open, or for a statement already prepared, is not stated in the pages read (`doc PG21` describes what a role holds, not when a revocation applies). No revocation of an open session is claimed; PACT does not instantly revoke every open native session (sample I13) | At most `connection_max_lifetime_seconds` after the open; `OI-3` |
| Verification window | A catalog change that lands after V1 to V3 and before the registered statement on the same connection is not seen by that operation | One statement round trip; caught at the next acquisition |
| Role OID reuse | The OID comparison of RA-7 does not detect a new role that receives the OID of a dropped one, if that can happen; the administrator's withdrawal of the registry record on `DROP ROLE` covers it | `OI-4` |
| Policy correctness | The broker verifies that row security is enabled and forced, that the role is not elevated, and which table privileges it holds. It does not verify that the policy expressions are correct; their meaning is native (draft §17.3; sample I13: the statements "do not prove the absence of other privileges") | Disclosed; the database administrator owns the policies |
| Covert channels | Referential integrity checks bypass row security, and the documentation warns of covert-channel leaks through them (`doc PG1`); the route writes nothing and the role holds no `REFERENCES` (CV-4). Timing and result-size channels are not established | Disclosed; no bound |
| Executor evidence | Draft §14.2 asks for an immutable native record that names the actual executor identity. No native source is established; the broker's record of the V1 result is the evidence reference until one is named, and its qualification is open | OD-2 |
| Pool scale | One pool per principal multiplies connections; a role or cluster at its connection limit makes the operation fail closed | `DEPENDENCY_UNAVAILABLE`, `DEFERRED` |

## 10. Fixture index

Ten cases cover the G20 closure items. Each is a group of adapter cases of this profile in `spec/v1.0/fixtures/adapters/db/`, one file per variant, named by its lower-case ID and variant, such as `db-04.in-grammar.json`, with the manifest id `adapters/db/db-04.in-grammar`; the sample I13 schema is the native-format asset `spec/v1.0/fixtures/adapters/db/schema.sql`, the SQL of the sample verbatim, registered as `adapters/db/schema` with kind `adapter-asset`. Every file is registered in `spec/v1.0/fixtures/manifest.json` and listed in the `fixtures` array of `profile.json`. The native state of the cases is the model `db/1` of the [database cases README](../../fixtures/adapters/db/README.md). A case file calls one of the seven adapter functions, none of which sends a statement on a database connection, so the Evidence column says which part of a case the files show and which part is shown by the implementation's unit tier, with a recording database driver that answers V1 to V3 and asserts statement text, parameters, and the reset, or by its integration tier, which loads `schema.sql` into a PostgreSQL 16 server and runs only when one is configured. The identity, freshness, and request-binding cases of `spec/v1.0/fixtures/adapters/_common/` also apply and are not repeated; no common case is replaced.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `DB-01` | Two principals in sequence through the same broker, each mapped to its own role | Each statement runs on a connection whose `current_user` and `session_user` equal that principal's role; no connection serves both roles; every release sends the rollback and `DISCARD ALL` | `adapters/db/db-01.role-first`, `db-01.role-second`, `db-01.tenant-second`: each principal's role and tenant come from its own registry record. The connections, their verification results, and the reset are the unit tier of the implementation and its integration tier against `schema` | B2, CR-1, CR-3, CR-7, CV-1 |
| `DB-02` | The mapped role is the table owner, a superuser, has `BYPASSRLS`, is a member of such a role or of another login role, or holds a write privilege on a protected table | Connection refused by CV-7 before any registered statement; `FAIL` with `EXECUTOR_MISMATCH` for the owner, superuser, `BYPASSRLS`, and membership variants; no execution for the privilege variant | Unit tier, every variant and a role with another OID than recorded (RA-7); integration tier against `schema` for the owner, superuser, `BYPASSRLS`, membership, and write variants. No adapter function sees a connection role, so no case file | B1, B4, CV-1 to CV-4 |
| `DB-03` | SQL text in the operation: a route with no mapping row (a query endpoint with SQL in the body); an action with no registry entry at the installed revision; a `sql` query parameter on R1 | `UNSUPPORTED_REQUIREMENT` and no statement for the first two; for the third the parameter is not read or forwarded and the statement text equals the registry constant | `adapters/db/db-03.query-endpoint`, `db-03.no-registry-entry`, `db-03.sql-parameter`, and `db-03.sql-body`, a body on R1, which accepts none (RB-37); none opens a connection. That the statement text equals the registry constant is the unit tier | B3, B4, QB-1, QB-6 |
| `DB-04` | Injection in `report_id`: a value outside the grammar (`R-481' OR '1'='1`); a value inside it (`R-481--`) | Outside: `INVALID_MESSAGE`, no connection acquired. Inside: the statement text equals the registry constant and the value is sent only as parameter `$1`; no concatenation | `adapters/db/db-04.out-of-grammar`, `db-04.outside-alphabet`, `db-04.too-long`, with the controls `db-04.in-grammar` and `db-04.at-limit`. That `R-481--` reaches the server only as `$1` of the constant statement is the unit tier | R1, B3, QB-3, QB-4 |
| `DB-05` | The requested row exists but its row policy hides it from the mapped role | Zero rows; `EXECUTION` / `SUCCESS` / `reliability` with `details` `"empty"`; no second query, no record that the row exists, no read claim | `adapters/db/db-05.empty-report`: the report is signed with those fields and no row content. The zero rows, the single statement, and that the hidden row never leaves the server are the unit tier; the integration tier against `schema` repeats the zero rows | R1, RS-1, RS-3, RS-5 |
| `DB-06` | The requested row does not exist | The same success response with an empty result as `DB-05`; no not-found or forbidden response synthesized; the same outcome report | The report of `adapters/db/db-05.empty-report`; the identical result for an absent and a hidden row is the unit and integration tiers | R1, RS-2 |
| `DB-07` | Integration: `SELECT` revoked from the mapped role while a connection is open, then the operation runs | The statement fails with a native error, recorded as `AUTHORIZATION` / `FAILURE` / `none`; no retry under any other connection or role; the probe result for `OI-3` and `OI-6` is recorded | `adapters/db/db-07.denial-report`: the report is signed with those fields. The revocation between the verification and the statement, the native error, and the absence of a retry are the integration tier against `schema`, with a unit tier variant; a revocation before the acquisition is refused by CV-4 with no statement | F3, RS-5, CV-7 |
| `DB-08` | The role mapping is unavailable: the registry cannot answer, or has no record for the principal | `execution-identity-v1` `UNKNOWN`, `DEFERRED` with `DEPENDENCY_UNAVAILABLE`; zero connections opened under any role, never a pool-administrator connection | `adapters/db/db-08.registry-unavailable`, `db-08.no-record`, `db-08.no-credential` (a role whose credential the broker does not hold), `db-08.claim-unavailable`, with the control `db-08.mapped`; the harness's driver fires `connect` on any connection, and none may fire. Execution with the mapping unavailable is the unit tier | B1, F1, RA-5 |
| `DB-09` | Integration, sample I13 schema: a report permitted to another principal is requested | Zero rows under the mapped role; the same result as `DB-05` against a running server | Integration tier against `schema` | R1, RS-1 |
| `DB-10` | Integration, sample I13 schema: V3 on the protected table; unit variants with `relrowsecurity` or `relforcerowsecurity` false | Integration: both flags true and every V3 condition holds. Variants: connection refused by CV-7, no execution | Integration tier against `schema`; the variants, and a relation that is not an ordinary table, are the unit tier | B1, CV-3 |

A stub that queries as the pool administrator and filters rows in code fails `DB-01`, `DB-02`, and `DB-05` in the unit tier, and is the mutant those cases are written against. Freshness rows F4 to F6 and their outages are covered by the common identity and freshness fixtures; this profile adds no database-specific case for them.

### 10.1 Mapping of the G20 closure items to fixtures

The finding G20 of the handoff asks for seven specifications and names five kinds of evidence. Each item maps to rules and to `DB-*` cases.

| G20 item | Where | Fixtures | Status |
|---|---|---|---|
| Role acquisition and current-role verification | 3.1, 3.2 | `DB-01`, `DB-02`, `DB-08` | |
| Owner, superuser, and `BYPASSRLS` exclusions | 3.2, CV-1 to CV-3 | `DB-02`, `DB-10` | Owner-membership bypass `OI-2` |
| Grants | 3.2, CV-4 | `DB-02`, `DB-07` | Revocation on an open connection `OI-3` |
| Row semantics | 3.5 | `DB-05`, `DB-06`, `DB-09` | Outcome-report fixtures for draft §14.5 are absent (OD-3) |
| Query binding | 3.4 | `DB-03`, `DB-04` | |
| Connection reset | 3.3 | `DB-01` | Client statement caches `OI-5` |
| Any pooled identity mechanism | 3.6 | `DB-01` | Role switching unsupported in wire version 0.1 (OD-1) |
| Prevent cross-request tenant or role leakage | 3.3, RS-7 | `DB-01`, `DB-09` | |
| Prevent bypass or owner execution | 3.1, 3.2 | `DB-02`, `DB-08`, `DB-10` | |
| Prevent SQL substitution or injection | 3.4 | `DB-03`, `DB-04` | |
| Prevent hidden-row disclosure | 3.5 | `DB-05`, `DB-09` | |
| Preserve empty-result semantics | 3.5, RS-2 | `DB-05`, `DB-06` | |

## Open decisions for the owner

| ID | Decision | Current text | Alternative and what it would change |
|---|---|---|---|
| OD-1 | Pooled identity mechanism | This profile is written for one dedicated login role per principal, with role switching unsupported in wire version 0.1 (PI-1). The choice keeps `DB-01` a pure refusal and matches what sample I13 established. It is pending the owner's confirmation | `SET LOCAL ROLE` inside a transaction on a shared login role, with `current_user` verified in the same transaction before the statement. Adopting it would add a pooled executor form to section 3.6, replace CV-1's `session_user` condition with a transaction-scoped `current_user` check, add the pool login role's `SET`-option memberships to the residual limits, move the first row of section 6 out of the unsupported forms, and add leakage cases for a failed or skipped role switch |
| OD-2 | Native source of the executor-identity record (draft §14.2) | The broker's own record of the V1 result is the evidence reference (RS-6) | A database-side record, such as the server's connection or audit log; whether a receiver qualifies either is for the evidence owner |
| OD-3 | Outcome-report fixtures for the draft §14.5 rows | Draft §14.5 has the row "Execution completed, zero rows or filtered result" (`EXECUTION`, `SUCCESS`, `reliability`, `details` `"empty"`), and Appendix A.2 makes an `EXECUTION` `SUCCESS` with `task_quality` invalid. The outcome-report sequences and expected qualification results for these rows are not yet in `spec/v1.0/fixtures/`, so `DB-05` and `DB-06` assert the report fields of RS-5 directly | When those fixtures land, `DB-05` and `DB-06` reference the zero-row sequence and its qualification result |

## Open items to probe

The probe record below the table says which of these have been run; OI-2 and OI-4 have not. The integration items need a PostgreSQL 16 server with the sample I13 schema.

| ID | Question | Probe | Rules that wait on it |
|---|---|---|---|
| OI-1 | Do V1 to V3 and the sample I13 statements behave as section 3 states on PostgreSQL 16? | Run the integration cases `DB-07`, `DB-09`, `DB-10` against the schema asset | Section 6, the paragraph after the table |
| OI-2 | Does a member of the owning role, with `INHERIT` or with `SET`, bypass row security as the owner does? | Grant the owner role to a test login role with each option and run the registered statement | CV-3 (refuses membership either way) |
| OI-3 | Does a `REVOKE` of `SELECT`, a policy change, or `ALTER ROLE ... BYPASSRLS` take effect for the next statement on an open connection and for an already prepared statement? Does `has_table_privilege` count privileges reachable only through `SET ROLE`? | Change each on a second session while the first holds a prepared statement, then execute | F3, CR-6, CV-4, section 9 |
| OI-4 | Can a role created after `DROP ROLE` receive the dropped role's OID? | Create and drop roles and compare `pg_roles.oid` values; consult the server source for the OID assignment rule | RA-7 |
| OI-5 | Does a client library that caches prepared statements re-prepare after `DISCARD ALL` removed them, or fail with an invalid statement name (SQLSTATE `26000`, `doc PG22`)? | Release and reacquire a connection with the implementation's driver settings, and record the setting that works | CR-5 |
| OI-6 | Which SQLSTATE does a `SELECT` without the `SELECT` privilege raise (expected `42501`, `insufficient_privilege`, which the code table lists but the pages read do not tie to this case), and which does a policy-applying query raise when `row_security` is `off`? | Run both and record the codes | RS-5, CV-8 |

Probe record, 2026-10-18, PostgreSQL 16.15 with the reference implementation and pgx v5.11.0 (its package documentation has the detail). OI-1: the integration tier ran green with the asset `schema.sql`; V1 to V3 behave as section 3.2 states, and V3 on the sample table reads both row-security flags true. OI-3, in part: a `REVOKE` of `SELECT` made on a second session after the statement was prepared on an open connection made its execution fail; policy changes and `ALTER ROLE` were not probed. OI-5: with the pgx default statement cache, a cached statement used after `DISCARD ALL` failed once with SQLSTATE `26000`; with no statement or description cache, and with a statement prepared on each acquisition and closed before the reset, it did not. OI-6, in part: that execution failed with `42501` (`insufficient_privilege`); the `row_security` `off` case was not probed. OI-2 and OI-4 were not probed. The rules above are unchanged.

## Reference implementation (informative)

The reference implementation of the adapter is the Go package `go/adapters/db` (source repository), on `database/sql` with the driver `github.com/jackc/pgx/v5` that `go/docs/deps.md` vets and pins. The contracts it satisfies exist in `go/adapter`, `go/adapter/enroll`, and `go/adapter/freshness`, and this profile uses their names as they are. The other sections are language-neutral.

| Profile rule | Go package element |
|---|---|
| Descriptor | `adapter.Descriptor{Protocol: "postgresql", Version: "3.0", MappingRevision: "pact-db-1"}` |
| `map_operation`, QB-1, QB-4, QB-6 | `adapter.OperationMapper.MapOperation` fills `core.OperationContext` (`Action` `report.read`, `Resources` `report:{report_id}`); an action with no registry entry or an unknown mapping revision wraps `adapter.ErrUnsupportedRequirement`; a value outside the route grammar wraps `adapter.ErrInvalidMessage` |
| `resolve_agent_binding`, section 7 | `enroll.Resolver` over an `enroll.Registry`; the agent the request names is resolved on the authenticated workload, and a workload without a record for it gives `adapter.BindingUnknown` |
| `read_native_claim`, F1, F4 | `adapter.ClaimReader.ReadNativeClaim` with an `adapter.ClaimContext`; other paths wrap `adapter.ErrUnsupportedRequirement`; an unreachable registry wraps `adapter.ErrDependencyUnavailable` |
| `check_context`, RA-5, CV-7 | `adapter.ContextChecker.CheckContext` returns `adapter.CheckOutcome`: `VerdictPass`; `VerdictFail` with `ReasonCode` `EXECUTOR_MISMATCH`; `VerdictUnknown` with `DEPENDENCY_UNAVAILABLE` |
| `authorize_native`, RS-5 | `adapter.NativeAuthorizer.AuthorizeNative` returns `adapter.Decision` with `EffectAllow`, `EffectDeny`, or `EffectUnknown`, and `SourceID` naming the task policy; `Decision.Permits` is true only for an explicit allow |
| `record_outcome`, RS-5, RS-6 | `adapter.OutcomeRecorder.RecordOutcome` returns `adapter.Signed`; the observation carries the row count and no row content |
| Freshness of F1 to F6 | `freshness.Evaluate` and `freshness.Evaluator` |
| Execution, CV-1 to CV-7, CR-1 to CR-5, QB-3, QB-5 | `Adapter.Execute`: one `*sql.DB` per (`cluster-id`, login role), V1 to V3 on every acquisition, the registered statement prepared, executed once and closed, then `ROLLBACK` and `DISCARD ALL`; `PostgreSQL` opens the connections with the role's own credential through `pgx/v5/stdlib` |
| RS-5, RS-6 | `OutcomeOf` and `ExecutorRecord` |

## Sources

PostgreSQL 16 documentation pages, all read on 2026-10-16 under `https://www.postgresql.org/docs/16/`; each page showed release 16.15.

| Tag | Page |
|---|---|
| PG1 | `ddl-rowsecurity.html` (5.8, Row Security Policies) |
| PG2 | `sql-createpolicy.html` (CREATE POLICY, including Table 292, Policies Applied by Command Type) |
| PG3 | `sql-altertable.html` (ALTER TABLE: ENABLE and FORCE ROW LEVEL SECURITY) |
| PG4 | `sql-createrole.html` (CREATE ROLE) |
| PG5 | `role-membership.html` (22.3, Role Membership) |
| PG6 | `ddl-priv.html` (5.7, Privileges) |
| PG7 | `view-pg-roles.html` (54.20, `pg_roles`) |
| PG8 | `catalog-pg-class.html` (53.11, `pg_class`) |
| PG9 | `catalog-pg-namespace.html` (53.32, `pg_namespace`) |
| PG10 | `functions-info.html` (9.26, System Information Functions and Operators) |
| PG11 | `sql-set-role.html` (SET ROLE) |
| PG12 | `sql-set-session-authorization.html` (SET SESSION AUTHORIZATION) |
| PG13 | `sql-discard.html` (DISCARD) |
| PG14 | `sql-prepare.html` (PREPARE) |
| PG15 | `runtime-config-client.html` (20.11, Client Connection Defaults: `row_security`, `search_path`) |
| PG16 | `libpq-exec.html` (34.3, Command Execution Functions) |
| PG17 | `protocol-flow.html` (55.2, Message Flow: Simple Query, Extended Query) |
| PG18 | `protocol-message-formats.html` (55.7, Message Formats: CommandComplete) |
| PG19 | `protocol.html` (Chapter 55, Frontend/Backend Protocol) |
| PG20 | `datatype-oid.html` (8.19, Object Identifier Types) |
| PG21 | `sql-revoke.html` (REVOKE) |
| PG22 | `errcodes-appendix.html` (Appendix A, PostgreSQL Error Codes) |

The sample [`example_I13.md`](../../examples/example_I13.md), the draft, and the handoff's G20 finding and I13 row are the other references.
