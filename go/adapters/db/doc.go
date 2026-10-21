// Package db is the adapter of the integration profile "database identity,
// row security, and pooling (PostgreSQL)" (spec/v1.0/profiles/db): a broker that
// runs one fixed, parameterized statement under the dedicated login role its
// role registry maps to the principal, on database/sql with the driver
// github.com/jackc/pgx/v5/stdlib, so that PostgreSQL's privileges and row
// policies decide which rows come back.
//
// # What the adapter does
//
//   - MapOperation: the baseline HTTP mapping of package binding with the
//     route table of the installed revision ([ReportRoutes], route R1), the
//     route grammar of report_id and no body (RB-34, RB-37, QB-4), and the
//     query registry entry of the action ([ReportQuery], QB-1). It opens no
//     connection.
//   - ReadNativeClaim: database_role and tenant_id from the role registry
//     ([RoleRegistry], F1); other approved paths from configured sources.
//   - CheckContext: execution-identity-v1 at evaluation (RA-5), from the
//     registry and the secret store, with no connection; other checks are
//     the deployment's.
//   - AuthorizeNative: the broker's task policy ([Config.Permissions]),
//     unchanged; it opens no connection.
//   - AuthenticateNative, ResolveAgentBinding: the front-door
//     authentication and the enrollment registry the deployment names.
//   - RecordOutcome: signed reports of the broker's observations;
//     [OutcomeOf] gives the fields of profile RS-5 for an execution.
//   - Execute: the registered statement of an admitted operation on a
//     connection of the mapped role's own pool ([Dialer], [PostgreSQL]):
//     V1, V2 and V3 on every acquisition ([StatementV1], [StatementV2],
//     [StatementV3]), then the statement prepared, executed once with the
//     values bound and closed, then ROLLBACK and DISCARD ALL on release. A
//     failed verification closes the connection (CV-7); nothing is retried.
//
// # PostgreSQL facts
//
// From the PostgreSQL 16 documentation, release 16.15, read on 2026-10-18:
//
//   - DISCARD ALL "resets the session to its initial state", currently the
//     same as CLOSE ALL, SET SESSION AUTHORIZATION DEFAULT, RESET ALL,
//     DEALLOCATE ALL, UNLISTEN *, SELECT pg_advisory_unlock_all(), DISCARD
//     PLANS, DISCARD TEMP and DISCARD SEQUENCES, and "cannot be executed
//     inside a transaction block"
//     (https://www.postgresql.org/docs/16/sql-discard.html).
//   - "Issuing ROLLBACK outside of a transaction block emits a warning and
//     otherwise has no effect" (https://www.postgresql.org/docs/16/sql-rollback.html),
//     so the release sends it unconditionally before DISCARD ALL.
//   - The query string of a Parse message "cannot include more than one SQL
//     statement", and Bind carries "the values to use for any parameter
//     placeholders"; a simple Query message can contain several statements
//     (https://www.postgresql.org/docs/16/protocol-flow.html).
//   - Applications "should usually test the error code, rather than looking
//     at the textual error message"; 42501 is insufficient_privilege, 26000
//     invalid_sql_statement_name, 57014 query_canceled, class 08 connection
//     exceptions (https://www.postgresql.org/docs/16/errcodes-appendix.html).
//   - "Superusers and roles with the BYPASSRLS attribute always bypass the
//     row security system"; table owners normally bypass it unless FORCE ROW
//     LEVEL SECURITY is set; with row security enabled and no policy, "a
//     default-deny policy is used"
//     (https://www.postgresql.org/docs/16/ddl-rowsecurity.html).
//   - pg_has_role with MEMBER "denotes direct or indirect membership in the
//     role", and a privilege function without a user argument assumes
//     current_user (https://www.postgresql.org/docs/16/functions-info.html).
//
// # Probes
//
// Run on 2026-10-18 against PostgreSQL 16.15 (image postgres:16-alpine) with
// pgx v5.11.0:
//
//   - Statement cache after DISCARD ALL (profile OI-5). With the pgx
//     default, QueryExecModeCacheStatement, a statement with arguments run
//     again on the same connection after DISCARD ALL failed once with
//     'prepared statement "stmtcache_..." does not exist (SQLSTATE 26000)';
//     pgx invalidated its cache entry on that error, so the use after it
//     succeeded. QueryExecModeCacheDescribe, QueryExecModeDescribeExec and
//     QueryExecModeExec did not fail, nor did an explicit Prepare closed
//     before the reset in any mode. [PostgreSQL] therefore sets
//     QueryExecModeDescribeExec with statement and description cache
//     capacities 0, and Execute prepares the registered statement on each
//     acquisition and closes it before the reset (CR-5). ROLLBACK outside a
//     transaction returned no error.
//   - The integration tier (TestIntegration, PACT_TEST_PG_DSN) ran green
//     with the asset schema.sql: V1 to V3 behave as profile section 3.2
//     states (OI-1); V3 for the sample table read relkind "r" (as a string
//     through database/sql), both row-security flags true, owner the
//     administrator; the owner, superuser, BYPASSRLS, login-role member and
//     write-privilege roles were refused before the statement; a REVOKE of
//     SELECT on a second session after the statement was prepared on an
//     open connection made its execution fail with SQLSTATE 42501 (OI-3 for
//     a prepared statement, the first question of OI-6), recorded as
//     AUTHORIZATION FAILURE none with one attempt, and the next acquisition
//     was refused by V3 (CV-4).
//
// Not probed: whether a member of the owning role bypasses row security
// (OI-2; CV-3 refuses membership either way), OID reuse (OI-4), the SQLSTATE
// of a policy-applying query with row_security off (OI-6, second question),
// and a policy change or ALTER ROLE on an open connection (OI-3, the other
// changes).
package db
