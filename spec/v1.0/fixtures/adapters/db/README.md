# Database adapter cases

These are the cases of the database adapter of the integration profile
[`profiles/db`](../../../profiles/db/profile.md): a broker that runs one fixed,
parameterized PostgreSQL statement under the dedicated login role that its
role registry maps to the principal. They run after the common cases, with
the case file format, the outcomes and the checks of [`../README.md`](../README.md).
The profile inherits the shared-workload choice of the front-door profile and
claims none, so a harness runs the `dedicated` cases. Section 10 of the profile
says which case group each file belongs to and which part of a group is
tested by the harness of an implementation rather than by these files.

A case calls one of the seven adapter functions. What the broker sends on a
database connection (the verification statements, the registered statement,
the reset) is not the result of any of them, so the cases here cover the
functions that decide before a connection exists: the mapping of the route and
the query registry, the role registry's claims, the check
`execution-identity-v1` at evaluation, and the outcome reports. The connection
properties of `DB-01`, `DB-02`, `DB-05` to `DB-07`, `DB-09` and `DB-10` are
tested by an implementation's own unit tier, with a recording database driver,
and its integration tier, against PostgreSQL 16 with the asset
[`schema.sql`](schema.sql) (profile section 10).

## Model `db/1`

```
{
  "model": "db/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "cluster_id": "<cluster-id>",
  "installed": [{"revision", "routes": [...], "queries": [...]}],
  "registry": [{"realm", "principal", "login_role", "role_oid",
                "credential_ref", "tenant_id", "revision", "changed_at"}],
  "credentials": [{"ref", "secret"}],
  "unavailable_sources": [...],                       // optional
  "reporting": {"issuer", "audience", "kid"}           // optional
}
```

Times are Unix seconds.

- `gateway`: as in `common/1`.
- `cluster_id`: the configured identifier of the cluster, the `cluster-id`
  of the executor identifier `db:{cluster-id}:{login-role}` (identity mapping
  §3.3).
- `installed`: the installed mapping revisions. `routes` names rows of the
  route table of profile section 2 by their ID (`R1`), and `queries` names
  the actions whose query registry entry of that section is installed under
  the revision (`report.read`, with the statement text of the profile). A
  route whose action has no entry under the revision is installed but
  selects no statement (QB-1).
- `registry`: the role and tenant registry (profile RA-1): per realm and
  principal, the login role, its OID recorded at registration, the reference
  of its credential in the secret store, the tenant, the registry revision,
  and the time of the record's last change. The source is `role-registry`.
- `credentials`: the secret store (component C14): the credential each
  reference holds. A reference that is not listed holds none, so the broker
  holds no pool for its role.
- `unavailable_sources`: `role-registry` when the registry cannot answer.
- `reporting`: the issuer, audience and key id of the outcome reports the
  broker signs.

## Hooks

The harness's database driver fires the hook `connect` whenever a connection
is opened to the cluster, under any role. The adapter fires `execute` where it
would send the registered statement. A case with
`must_not_call: ["connect", "execute"]` fails if the adapter opened a
connection or ran the statement.

## Adapter outputs

`map_operation` maps `GET /api/v1/reports/{report_id}` (`R1`) to the action
`report.read` and the resource `report:{report_id}` with the baseline HTTP
mapping. A `report_id` outside the grammar of the row (1 to 64 characters of
ALPHA, DIGIT and `-`) and a non-empty body are `INVALID_MESSAGE` (RB-37,
RB-38, QB-4); a request no route matches, and a route whose action has no
query registry entry under the revision, are `UNSUPPORTED_REQUIREMENT` (QB-1,
RB-33). A query parameter is covered by `target_uri` and read for nothing
(RB-36).

`read_native_claim` answers `/attributes/environment/database_role` with
`db:{cluster-id}:{login-role}` and `/attributes/environment/tenant_id` with
the tenant of the principal's record, from the source `role-registry`: the
observation time is the record's last change and the status time is the time
of the read, which is a lookup of the current record (profile section 8, F1);
the source reference is the registry revision. A registry that cannot answer
is `DEPENDENCY_UNAVAILABLE`.

`check_context` with `execution-identity-v1` at evaluation (profile RA-5)
opens no connection: `PASS` with `REQUIREMENT_SATISFIED` when the registry
maps the principal of the operation to a login role of the cluster, the
operation's action has a query registry entry, whose executor class is
`dedicated-role`, and the secret store holds the role's credential; `UNKNOWN`
with `DEPENDENCY_UNAVAILABLE` when the registry cannot answer, has no record
for the principal, or the credential is absent.

`record_outcome` signs the observations of the broker, which executes the
statement, so the broker has execution visibility.

## Common cases

The common cases state their native state in `common/1`. A database harness
realizes it with the deployment-supplied parts the profile leaves to the
deployment: the front-door authentication, the enrollment registry, the
claims and checks of `common/1`, and the broker's task policy as
`authorize_native` (profile section 3, row 4), which never opens a
connection. The routes of each `common/1` mapping are installed with a query
registry entry for each of their actions, the parameter grammar of RB-34
(1 to 64 unreserved characters) and a body accepted, as the common routes
state none, so the common `map_operation` cases run
against the adapter's own mapping. No common case is replaced.
