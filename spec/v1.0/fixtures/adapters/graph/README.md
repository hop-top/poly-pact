# Microsoft Graph executor cases

These are the cases of the Microsoft Graph adapter of the integration profile
[`profiles/graph`](../../../profiles/graph/profile.md): a mail gateway whose
admitted reads are executed by one call to Microsoft Graph "List messages",
under token B obtained by the on-behalf-of (OBO) flow in form D or by the
client credentials grant in form A, with the grant preflight of profile
section C for form A. They run after the common cases, with the case file
format, the outcomes and the checks of [`../README.md`](../README.md). The
profile claims no shared workloads, so a harness runs the `dedicated` cases.

A case calls one of the seven adapter functions. What the executor sends to
the token endpoint and to Microsoft Graph (the OBO and client credentials
requests, token B, the downstream request, the continuation it follows) is not
the result of any of them. The cases here therefore cover the functions that
decide before any token request: the mapping of the rows GD1, GD2, GA1 and GA2
with their exact query and their continuations, the executor registry's claim,
the check `execution-identity-v1` over the executor registry and the latest
grant preflight, and the outcome reports. The execution properties of the
profile (no fallback, consent loss, interaction requirements, the token
response check, token A never sent to Graph, paging, throttling) are tested by
an implementation's own unit tier against an in-process token endpoint and an
in-process Graph over TLS; section 10 of the profile says which.

## Model `graph/1`

```
{
  "model": "graph/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "form": "delegated" | "application",
  "entra": {"tenant_id", "gateway_app_id"},
  "executor_app_id": "<application (client) ID>",          // form A only
  "registry": [{"realm", "row", "workload", "class", "grant", "app_id",
                "service_principal_id", "mailbox_id", "ref", "changed_at"}],
  "continuations": [{"page_token", "row", "principal", "task_id",
                     "agent_id", "mapping_version", "link"}],  // optional
  "preflight": {"allowlist": [{"resource_id", "app_role_id"}],
                "runs": [{"at", "unreachable", "assignment_pages",
                          "rbac"}]},                         // optional
  "unavailable_sources": [...],                              // optional
  "reporting": {"issuer", "audience", "kid"}                 // optional
}
```

Times are Unix seconds.

- `gateway`: as in `common/1`. The profile's header allowlist is `accept`.
- `form`: which of the two adapter entries of profile section 1 the harness
  builds: `delegated` (`graph-delegated-obo`, rows GD1 and GD2) or
  `application` (`graph-app-only`, rows GA1 and GA2). One adapter is built
  with exactly one token acquirer: the OBO acquirer of the gateway
  application in form D, the client credentials acquirer of the executor
  application in form A.
- `entra`: the pinned tenant and the gateway application, the audience of
  token A and the OBO client (GR-5). The identifiers of users and
  applications are those of the OAuth profile's form E (OAUTH-37,
  OAUTH-38; profile section 7): `oauth:{issuer-id}:{tenant_id}:{local}`,
  with `issuer-id` the tenant's issuer
  `https://login.microsoftonline.com/{tenant_id}/v2.0` and each component
  written under IM-2.
- `executor_app_id`: in form A, the executor application of the adapter
  (GR-13), whose identifier is `oauth:{issuer-id}:{tenant_id}:{app_id}`.
- `registry`: the executor registry (G1, source `executor-registry`): per
  realm and row, the executor binding. `workload` is the workload principal
  the binding is registered for in form A and absent in form D, whose binding
  acts for the authenticated user. `class` is `delegated-user` or
  `registered-app-executor`, `grant` is `on_behalf_of` or
  `client_credentials`, `app_id` and `service_principal_id` name the
  application, `mailbox_id` is the registered mailbox of a form A binding,
  `ref` is the opaque reference of the binding record and `changed_at` the
  time of its last change.
- `continuations`: the continuation records of RB-57: the gateway token the
  agent sends as `page_token`, the row whose response carried the link, the
  principal, the task, the agent, the mapping version and the recorded
  `@odata.nextLink`.
- `preflight`: the allowlist of GR-18 and the preflight runs the auditor made
  before `now`, in time order. The harness runs the adapter's preflight once
  per run with the clock at `at`, serving step 1 from its in-process Graph,
  and then holds the clock at `now`. `assignment_pages` are the pages of
  `GET /v1.0/servicePrincipals(appId='{executor_app_id}')/appRoleAssignments`,
  each a list of appRoleAssignment objects with the members of profile source M7, linked by
  `@odata.nextLink`; `unreachable` true means that Graph cannot answer step 1
  of that run; `rbac` is the operator-supplied attestation of step 2 for that
  run (below), absent when there is none.
- `unavailable_sources`: `executor-registry` when the registry cannot answer.
- `reporting`: the issuer, audience and key id of the outcome reports.

### RBAC attestation

Exchange Online exposes `Test-ServicePrincipalAuthorization` as a PowerShell
cmdlet only (profile source M9), so step 2 of the preflight reads an attestation file that the
operator produces by running it (profile GR-19): a JSON object with
`identity` (the executor application ID passed as `-Identity`), `resource`
(the registered mailbox passed as `-Resource`), `ran_at` (Unix seconds) and
`rows`, one object per output row with the members `RoleName`,
`GrantedPermissions`, `AllowedResourceScope`, `ScopeType` and `InScope`, each
the string the cmdlet prints (profile source M9).

## Hooks

The harness's token endpoint fires `token` for every request of the gateway
application or of an executor application, and `audit` for a request of the
auditor identity; its Graph fires `execute` for every request to a mail path
and `audit` for a preflight read. A case with
`must_not_call: ["token", "execute"]` fails if the adapter requested a token
or called Graph.

## Adapter outputs

- `map_operation`: rows GD1 and GA1 accept exactly the query
  `$select=id,subject,body&$top=10`, octet for octet; any other query on the
  row's path is `INVALID_MESSAGE` (GR-23). Rows GD2 and GA2 accept exactly one
  parameter `page_token` of 22 to 128 base64url characters; another spelling
  is `INVALID_MESSAGE`, and a token with no continuation record, or whose
  record is for another principal, another form's row, another mapping
  version, or holds a link whose origin, path or pinned `$select` and `$top`
  differ from the row's, is `CONTEXT_MISMATCH` (GR-24, RB-58). The resource is
  `mailbox:{principal_id}` in form D and `mailbox:{mailbox_id}` of the
  workload's binding in form A; a workload without a usable binding is
  `UNSUPPORTED_REQUIREMENT`. A path of the other form's rows selects no row
  (`UNSUPPORTED_REQUIREMENT`).
- `read_native_claim`: `/graph/execution_app_id` in form A gives the executor
  identifier of the workload's binding, observed at the binding's last change,
  status-checked at the read, with source `executor-registry` and the
  binding's `ref` (GR-32); in form D, and for an application bound to another
  workload too, it is `UNSUPPORTED_REQUIREMENT`.
- `check_context` with `execution-identity-v1`: `PASS` with
  `REQUIREMENT_SATISFIED` only under GR-26; `FAIL` with `EXECUTOR_MISMATCH`
  for a binding of another class, grant, application or mailbox, a form D
  binding naming a mailbox or a workload, an application or a mailbox bound to
  two workloads, and a form A preflight that failed; `UNKNOWN` with
  `DEPENDENCY_UNAVAILABLE` for a registry that cannot answer, no binding, and
  a preflight that is absent, failed to run, older than `P` = 300 s, or passed
  for less than the settle window `W` = 7200 s (GR-20, GR-21).
- `record_outcome`: the executor runs the downstream request, so the adapter
  has execution visibility and signs the reports.

## Common cases

The common cases state their native state in `common/1`. A Graph harness
realizes it with the deployment-supplied parts the profile leaves to the
deployment: the inbound authentication of the authenticating profile, the
enrollment registry, the claims and checks of `common/1` and the gateway's
policy as `authorize_native`. The routes of each `common/1` mapping are
installed as further routes, mapped with the baseline binding and executed by
nothing. No common case is replaced.
