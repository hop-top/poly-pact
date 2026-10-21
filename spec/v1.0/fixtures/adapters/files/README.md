# File broker adapter cases

These are the cases of the file broker of the integration profile
[`profiles/files`](../../../profiles/files/profile.md) (Windows local NTFS).
They run after the common cases, with the case file format, the outcomes and
the checks of [`../README.md`](../README.md). The profile supports workloads
shared by several agents, so a harness runs the `shared` cases. Section 10 of
the profile says which closure item each file implements; the IDs `FILES-01`
to `FILES-12` are those of the profile.

No case here depends on Windows. Each states the native systems the broker
reaches through its three seams, the security package of the Negotiate
exchange, the thread impersonation and the file system, in the model
`files/1` below, and a harness realizes them with fakes that behave as the
model says. The cases that need a real NTFS access check, `FILES-W01` and
`FILES-W02`, are tests of the adapter package that run in the Windows job,
because the case format cannot restrict a case to one platform.

The common cases state their native state in the `common/1` model. A file
broker harness realizes their identities as accounts whose completed Negotiate
exchange the security package accepts, with the identity's `secret` as the
token; the principal such an account authenticates as is
`files:{domain-sid}:{user-sid}` (profile IA-8), which cannot be the identifier
a common `authenticate_native` case expects. It realizes `policy` as files and
their access control lists: one registered file per resource that a rule
names, whose list grants or denies the rule's principal the rule's action as an
access right of its own, so that the native open decides; the broker requests
the access right its action table gives for the operation's action. The open
answers allowed or denied and nothing else, so a common `authorize_native` case
whose expected decision carries an obligation or a provenance member other
than the source cannot be realized; the profile lists the replaced common
cases. The other members of `common/1` are deployment-supplied sources, as for
every adapter.

## Model `files/1`

```
{
  "model": "files/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "parameters": {"context_max_age_seconds", "handle_max_lifetime_seconds"},
  "service_account": "<account ref>",
  "accounts": [{"ref", "sid", "display_name", "groups": [<sid>, ...],
                "negotiate_token": "<base64>"}],
  "connection": {"account", "completed_at"},              // optional
  "contexts": [{"account", "completed_at"}],              // optional
  "impersonation": {"enter": "ok" | "fails" | "service",
                    "revert": "ok" | "fails"},            // optional
  "unhealthy": true,                                      // optional
  "open_source_id": "<source id>",
  "registry": [{"file_id", "path", "final_path", "volume_serial", "object_id"}],
  "objects": [{"path", "final_path", "volume_serial", "object_id",
               "attributes": [...], "reparse_tag",          // reparse_tag optional
               "acl": [{"sid", "effect": "allow" | "deny", "access": ["read"]}],
               "content_b64"}],
  "enrollments": [...],                                   // optional, as in common/1
  "reporting": {"issuer", "audience", "kid"}              // optional, as in common/1
}
```

- `gateway`: as in `common/1`. The broker's realm is the gateway's tenant and
  environment.
- `parameters`: the profile parameters of section 1.
- `service_account`: the account the broker's process runs as. A thread that
  is not impersonating, or whose impersonation did not take effect, runs as
  this account.
- `accounts`: the Windows accounts. `sid` is the account's security identifier
  and `groups` the group SIDs of the access token a completed exchange gives,
  in token order. `display_name` is never an input of the broker.
  `negotiate_token` is the one Negotiate token that the security package
  completes in one leg for the account; any other token is rejected. The
  credential hook attaches the account that `native_state_ref` names as
  `Authorization: Negotiate <negotiate_token>` (RFC 4559, section 4.2).
- `connection`: the request arrives on a connection whose Negotiate exchange
  already completed for `account`, at `completed_at` (Unix seconds), and the
  request carries no token of its own. A harness realizes it by completing the
  exchange on the same connection at that instant before the case's call.
- `contexts`: completed Negotiate contexts the broker holds for the accounts'
  principals, each completed at `completed_at`, for the calls that take a
  principal instead of a request. A harness realizes them as `connection`.
- `impersonation`: what entering and leaving the impersonation window does.
  `enter` `fails` is a failed entry; `service` is an entry that reports success
  while the thread keeps running as the service account. `revert` `fails` is a
  failed revert. Absent: both succeed.
- `unhealthy`: the broker has already recorded a failed revert (profile TA-6).
- `open_source_id`: the source the broker names in a decision of the native
  open.
- `registry`: the file registry of profile PB-1: the opaque `file_id` of route
  R1, the configured local path, the final path recorded at registration, the
  volume serial number (16 hexadecimal digits) and the 128-bit file identifier
  (32 hexadecimal digits), as `GetFileInformationByHandleEx` reports them in
  `FILE_ID_INFO`. The resource of an entry is `file:{file_id}`.
- `objects`: what the file system holds at each path, as a handle opened at
  that path reports it: its final path, volume serial number and file
  identifier, its attributes (`directory`, `reparse_point`, `offline`,
  `recall_on_data_access`), the reparse tag of a reparse point, its
  discretionary access control list and its contents. An open under an
  identity reads the list in order and is decided by the first entry whose
  `sid` is the identity's user SID or one of its group SIDs and whose `access`
  holds the requested right: `allow` opens the file, `deny` is access denied;
  with no such entry the open is denied. An open of a path with no object
  fails as not found. An open of a reparse point opens the reparse point
  itself, as `FILE_FLAG_OPEN_REPARSE_POINT` does (profile PB-6).
- `enrollments`, `reporting`: as in `common/1`.

The installed operation mapping is revision `pact-files-1` of the profile:
`GET /files/{file_id}/content` maps to the action `file.read` and the resource
`file:{file_id}`; every other method, path or query of that revision violates
the mapping. The action table of the broker gives `file.read` the access right
`read`.

## Hooks

Besides `execute`, which fires when the broker reads the contents of a file,
a file broker harness fires `open` at every open the broker asks the file
system for, whatever its result, and `service-open` at an open asked for while
the thread runs as the service account. A case with
`must_not_call: ["open", "service-open"]` requires that nothing was opened by
any identity (profile TA-3, B2).
