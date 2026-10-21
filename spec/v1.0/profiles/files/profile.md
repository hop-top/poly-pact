# PACT integration profile: file broker, Windows local NTFS

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

It is the integration profile (template instance, [`TEMPLATE.md`](../TEMPLATE.md)) for the file broker of the integration sample [`example_I04.md`](../../examples/example_I04.md): a PACT-aware broker on a Windows file server that opens a local NTFS file under the requesting user's impersonated security context. The machine-readable form is [`profile.json`](profile.json). The companion documents [`unix.md`](unix.md) and [`smb.md`](smb.md) are stub profiles; they state boundary, required mechanisms and unsupported forms, and **make no claim**.

Where this profile and the draft ([`draft.md`](../../draft.md)) differ, the draft governs. Identity rules come from [`identity-mapping.md`](../identity-mapping.md) and freshness rules from [`freshness.md`](../freshness.md); this profile records only its own choices.

## How to read the evidence

No Windows behavior has been probed for this profile: the Windows probe is separate work and has not run. Every statement about what Windows does carries one of three bases:

| Basis | Meaning |
|---|---|
| `doc Mn` / `doc R1` | The cited page states it. The pages, read on 2026-10-16, are listed under Sources at the end. A page that does not say something is not read as saying it. |
| `design` | A requirement this profile places on the broker. It is a rule, not a statement about Windows. |
| `probe OI-n` | Not established by any page read. The open item names the probe that settles it. Until it runs, the profile makes no claim that depends on it. |

Where a premise is `probe`, the rule that rests on it is written so that it fails closed whichever way the probe comes out.

## Profile header

| Field | Value |
|---|---|
| Profile name | File broker, Windows local NTFS (`files`) |
| Target product and version | A Windows Server host with local NTFS volumes. The documentation lists Windows Server 2012 as the minimum server for `FileIdInfo` and no client edition (`doc M17`); exact versions are established by the Windows probe |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `r2`, 2026-10-18 |
| Maintainer | PACT adapter maintainers |
| Reference documents | draft = `spec/v1.0/draft.md` |

## 1. Claim scope

The broker evaluates PACT in-gateway (draft §4.4) and serves one read-only route. It claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over the `header` presentation transport. It is a partial role implementation (draft §22.1): `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1; the roles it does not claim are supplied by connected services of the deployment. The executor class is `impersonated-user` (draft §17.5, sample I04).

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

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` |
|---|---|---|
| `http` | `1.1` | `pact-files-1` |

The native mechanisms behind the one adapter are HTTP Negotiate authentication (`doc R1`), the Windows security package interface, thread impersonation, and the Windows access check of a local NTFS open. Two forms are named and **not claimed**: remote SMB access ([`smb.md`](smb.md)) and any Unix behavior ([`unix.md`](unix.md)).

Profile parameters. The two numbers are illustrative policy choices, as in the template's mini-example, not recommended thresholds. A deployment sets its own values.

| Parameter | Illustrative value | Meaning |
|---|---|---|
| `context_max_age_seconds` | 300 | Longest age of a completed Negotiate context when a request uses it (section 3.1, rule IA-9) |
| `handle_max_lifetime_seconds` | 300 | Longest time a file handle stays open (section 3.4, rule HI-2) |

## 2. Protected routes and actions

One read route is protected. Any other route is not claimed.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/files/{file_id}/content` | `GET` | `file.read` | `file:{file_id}`, from the path parameter. `file_id` is an opaque identifier that the file registry (section 3.3) maps to one configured local NTFS path, one volume serial number and one 128-bit file identifier. No path, drive letter, stream name or query parameter from the client selects a file, and a request that carries a query string or extra path segments is refused. The access mode is read and is part of the bound operation |

The mapping revision `pact-files-1` binds the uppercase method, the exact target URI (draft §10.2), the file identifier, and the access mode. A change to any of them is a material change and needs a new contract and presentation (draft §10.3).

## 3. Enforcement points

The access check of `authorize_native` and the handle that execution reads from come from one native call, the open. The table lists the functions in request order; subsections 3.1 to 3.6 give the rules for each mechanism.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Broker authentication stage, before routing: Negotiate exchange through the security package interface (3.1) | Adapter owner, Windows IAM owner for accounts | Produces the principal `files:{domain-sid}:{user-sid}`, equal to the workload; no password is handled |
| 2 | `map_operation` | Broker mapping stage, revision `pact-files-1` | Adapter owner | Builds the operation context for R1; refuses every other method, path and query |
| 3 | PACT evaluation | In-gateway validator in the same request path, after mapping and before the open | Gateway implementer | Runs `native-principal-binding-v1`, `native-delegation-v1` and `execution-identity-v1` (declared class `impersonated-user`) |
| 4 | `authorize_native` | The open under the user's impersonation token (3.2, 3.5) | Resource owner (file server administrator) | The Windows access check decides. Invoked for the original user, never with the broker's own authority. A native denial is final (draft §2.3) |
| 5 | Execution | Read from the verified handle, after the post-open checks (3.3) and inside the handle rules (3.4) | Broker, resource owner | Executor class `impersonated-user`; no byte is returned before verification |
| support | `resolve_agent_binding` | Enrollment registry lookup in the broker | IAM and security owner | Selects the record by workload and by the presented `agent_id`; the user's account is a workload that every agent acting for the user shares, supported for the reason that section 7 states |
| support | `read_native_claim` | Broker read of the user SID and group SIDs from the token of the completed exchange | Adapter owner | Approved paths only: `/attributes/environment/principal_id` and `/attributes/environment/group_ids` |
| support | `check_context` | Installed broker checks | Gateway implementer | `native-principal-binding-v1`, `native-delegation-v1`, `execution-identity-v1`; none other in wire version 0.1 |
| support | `record_outcome` | Broker outcome writer, after the open, the denial or the refusal | Gateway implementer | Mapping to draft §14.5 in 3.2, rule ER-7; the native source of the executor-identity record is `OI-12` |

### 3.1 Identity acquisition

The broker acquires the user's Windows identity from the `Authorization: Negotiate` exchange of the request, through the security package interface (SSPI). It handles no password.

| # | Rule | Basis |
|---|---|---|
| IA-1 | A request with no acceptable `Authorization` header is answered `401` with `WWW-Authenticate: Negotiate` and no token. A `401` that carries `Negotiate` and a token continues the exchange. A client may send the first token in its first request. | `doc R1` §4.1, §4.2 |
| IA-2 | Each leg's token goes to `AcceptSecurityContext` as the first buffer, of type `SECBUFFER_TOKEN`. On `SEC_I_CONTINUE_NEEDED` the broker sends the output token to the client in the next `401` and waits for the next token, which goes in again with the partial context. | `doc M1`, `doc R1` §5 |
| IA-3 | The security attributes of the context are examined only after the final call returns successfully. Any other final result, or an abandoned exchange, discards the partial context (`DeleteSecurityContext`) and is a native denial (`NativeDenial`, credential rejected). No partial context is used. | `doc M1`, `design` |
| IA-4 | The broker receives SPNEGO tokens only. Basic authentication, passwords, and password-based logon calls are not implemented. | `design` |
| IA-5 | The impersonation token is created from the completed context (`ImpersonateSecurityContext`, or `QuerySecurityContextToken` followed by a thread assignment). The documentation allows impersonation at the level of `SecurityImpersonation` or above only if the caller holds `SeImpersonatePrivilege`, or the token was made from explicit credentials by the same logon session, or the identity is the caller's; so the broker's service account needs the privilege, and a failure is `SEC_E_NO_IMPERSONATION`. The documentation says the call "allows the thread or process" to run with the context. | `doc M2`, `doc M3`; scope `probe OI-1` |
| IA-6 | Before use, the token is checked: it is an impersonation token and its level is `SecurityImpersonation` or higher, read through the token statistics. A level of `SecurityIdentification` can identify the client but cannot impersonate it. Anything else fails closed. | `doc M5`, `doc M14`, `design`; levels in practice `probe OI-2` |
| IA-7 | `SecurityImpersonation` is the level for the local system; `SecurityDelegation` is the level for remote systems. The broker obtains and uses the local level only. | `doc M5` |
| IA-8 | The principal is the user SID of the token, written `files:{domain-sid}:{user-sid}` (identity-mapping section 3.3). `domain-sid` is the SID without its last subauthority (the RID), as the documentation defines the domain identifier. Display names, `DOMAIN\user`, UPNs and SID history are never the principal. The group list of a token can contain SIDs from the user's SID history; they are group values, not the principal. | `doc M29`, `design` |
| IA-9 | The time at which the final call returned is the `AuthenticatedAt` of the context. A context older than `context_max_age_seconds` is discarded and the client must run a new exchange (`FILES-04`). | `design` |
| IA-10 | A context belongs to the connection that completed it and to no other. A proxy that shares an authenticated connection between clients makes the server lose track of contexts, so the broker accepts no intermediary between itself and the client. Authentication completes before any request data is processed. | `doc R1` §6, `design` |
| IA-11 | Channel binding between the Negotiate token and the TLS channel is not claimed. The RFC names TLS certificate hashes as a possible channel binding. | `doc R1` §6; `probe OI-11` |
| IA-12 | Not implemented, listed as alternatives. A service-for-user logon (`LsaLogonUser` with `KERB_S4U_LOGON`) takes the client's UPN as input, which cannot be null, so the broker would have to establish by other means that the named user is the requester. It requires a domain account caller, and `SeTcbPrivilege` to obtain an impersonation token (otherwise an identity token). A password logon (`LsaLogonUser` with an interactive logon structure) is password handling and is excluded by IA-4. | `doc M27`, `doc M28` |

Negotiate selects Kerberos or NTLM; it selects NTLM unless the client supplied a service principal name, a user principal name, or a NetBIOS account name (`doc M26`). Which one carries a given request is not recorded in the claim.

### 3.2 Effective rights: the native open

| # | Rule | Basis |
|---|---|---|
| ER-1 | The effective right to read is decided only by the access check inside the open, under the impersonation token. When a thread that impersonates opens a securable object, the system uses the impersonation token to check access; the check compares the requested rights and the token with the security descriptor, in ACE order, ignoring group SIDs that are not enabled. The broker computes no right from group names, from a profile, or from a separate ACL read, and never asks a preliminary "can read?" question instead of opening. | `doc M5`, `doc M10`, `doc M12`, `design` |
| ER-2 | Group values read from the token serve the claim comparison of draft §8.4 only. A matching group grants nothing and a missing group fails the rule (`FILES-08`). A group list is optional to this integration: a gateway may require verified principal and delegation facts and leave effective ACL access to the open. | `design`, sample I04 |
| ER-3 | The access mask is the smallest set that lets the read and the verification queries succeed. It starts from `FILE_READ_DATA` and `FILE_READ_ATTRIBUTES`; the probe fixes the rest. It contains no write, append, delete, `WRITE_DAC`, `WRITE_OWNER` or `ACCESS_SYSTEM_SECURITY` right and no generic right. `GENERIC_READ` expands to `FILE_READ_ATTRIBUTES`, `FILE_READ_DATA`, `FILE_READ_EA`, `STANDARD_RIGHTS_READ` and `SYNCHRONIZE`, and a deny entry cannot single out one generic right because of `SYNCHRONIZE`, so the mask changes which opens succeed. The final mask is recorded in mapping revision `pact-files-1`. | `doc M10`, `doc M11`, `design`; mask `probe OI-5` |
| ER-4 | The disposition is open-existing. The broker never creates, truncates or supersedes a file. | `design` |
| ER-5 | `FILE_FLAG_OPEN_REPARSE_POINT` is set (3.3). `FILE_FLAG_BACKUP_SEMANTICS` is never set: it makes the system override file security checks for a process with the backup and restore privileges, and it is also what opens a directory, so directories are not served. The broker enables no privilege in any token. | `doc M9`, `doc M10`, `design` |
| ER-6 | The handle is not inheritable: the security attributes are null, or the inherit member is false. The sharing mode does not deny native users their own access. | `doc M9`, `design` |
| ER-7 | A native denial maps to `Decision{Effect: EffectDeny}`: no execution, no contents, an `AUTHORIZATION` / `FAILURE` / `none` outcome with zero weight (draft §14.5). A successful verified open maps to `EffectAllow` and to `EXECUTION` / `SUCCESS` / `reliability` once data is returned. A refusal after open for object mismatch (3.3) or a revert failure (3.5) has no row in draft §14.5; it is reported as `EXECUTION` / `FAILURE` / `none`, which is a profile choice. The error code a denied open returns is `probe OI-5`. | `design`, draft §14.5 |

### 3.3 Path and object binding

| # | Rule | Basis |
|---|---|---|
| PB-1 | The file registry is trusted configuration (draft §4.2). Each entry holds the opaque `file_id`, the configured local path, the final path, the volume serial number and the 128-bit file identifier. Only an administrator changes it; a client value never selects or alters an entry (draft §10.2). | `design` |
| PB-2 | Registration is an administrator procedure. It opens the file read-only and records the final path, the volume serial number and the file identifier from that one handle, with the same name-form flags that mapping revision `pact-files-1` fixes for every check (`OI-7`), so the values describe one object and are comparable. It refuses a configured path that is not a fully qualified local path, or that contains `..`, a device-namespace prefix, a network name, or a stream name. | `design`, `doc M24`, `doc M25` |
| PB-3 | The broker opens the configured path only. No text from the client enters a path. | `design`, draft §10.2 |
| PB-4 | After the open and before any read, the broker checks, in order: (1) the attribute tag of the handle: a reparse-point attribute is a rejection; (2) a directory attribute, an offline attribute, or a recall-on-data-access attribute is a rejection; (3) the volume serial number and 128-bit file identifier of `FileIdInfo` equal the registry entry; (4) the final path of the handle equals the registry final path, compared code unit for code unit with no case folding. A mismatch closes the handle, returns no bytes, and is refused with `CONTEXT_MISMATCH` (a profile choice: draft §13.4 has no code for object substitution after admission). | `doc M18`, `doc M19`, `doc M33`, `doc M17`, `doc M16`, `design` |
| PB-5 | Two checks are needed. The file identifier and the volume serial number identify a file on one computer, so they catch a different object at the same path (`FILES-02`). The final path is the fully resolved path, so it catches the same object reached through another name or a link whose target differs from the registry; hard links give one file several paths in one volume. Which name a hard-linked handle reports is not documented. | `doc M17`, `doc M16`, `doc M22`; hard-link name `probe OI-7` |
| PB-6 | `FILE_FLAG_OPEN_REPARSE_POINT` stops normal reparse processing, so an open of a symbolic link returns a handle to the link, and the flag is ignored for a file that is not a reparse point. Junctions are implemented with reparse points. A reparse-point leaf is therefore opened as itself and rejected by PB-4(1) (`FILES-07`). The pages read do not say whether the flag also applies to reparse points in intermediate path components. PB-4(3) and PB-4(4) do not depend on the answer: a link in the middle that leads to another object fails them, and one that resolves to the registered object is the registered object. | `doc M9`, `doc M21`, `doc M23`, `doc M22`, `doc M20`; intermediate components `probe OI-6` |
| PB-7 | After verification the broker reads through the verified handle only and never opens the path again. A rename or replacement after the open changes nothing about what is read; a rename before the final-path check fails PB-4(4). | `design` |
| PB-8 | The client supplies no path text, so alternate names do not arise from the client. NTFS names are not case sensitive by default and a path can carry a short (8.3) alias and a stream suffix; what the final path returns for each is not established, which is why PB-4(4) is an exact comparison with a value recorded by the same call. | `doc M24`, `doc M25`; `probe OI-7` |
| PB-9 | Any event that gives a registered file a new file identifier, such as deletion and re-creation or replacement, fails PB-4(3) until an administrator registers it again. Whether the identifier survives a rename on one volume is `probe OI-8`. | `doc M17`, `design`; `probe OI-8` |
| PB-10 | Registration requires a local NTFS volume. The volume query that reports whether a file system supports security on files is the way to establish it. | `doc M9`, `design`; `probe OI-8` |

### 3.4 Handle isolation and lifetime

| # | Rule | Basis |
|---|---|---|
| HI-1 | A handle belongs to one tuple (`task_id` reconciled with the authoritative task context, `operation_id`, principal, `agent_id`). It is never shared, cached across tasks, or pooled. A lookup by any other tuple is refused with `CONTEXT_MISMATCH` and does not touch the owner's handle (`FILES-05`). | `design`, draft §10.1 |
| HI-2 | A handle is closed when the task ends: completion, cancellation, expiry, error, or `handle_max_lifetime_seconds` after the open, whichever comes first. The open itself happens before the admission receipt expires, at most 60 seconds after issuance (draft §12.1). | `doc M9` (`CloseHandle`), `design` |
| HI-3 | The handle is not inherited by a child process. The broker starts no child process while a user handle is open, and a process created by an impersonating thread receives the primary token of the process, not the impersonation token. | `doc M9`, `doc M5`, `design`; `probe OI-9` |
| HI-4 | The handle is never given to the agent, to another process, or to another thread pool. Bytes only leave the broker. | `design` |
| HI-5 | Whether the verified handle stays usable after the thread reverts, so that reads can run outside the impersonation window, is not established. Until `OI-4` settles it, reads that fail for that reason refuse the request and never retry as another identity. | `probe OI-4`, `design` |
| HI-6 | On cancellation the broker stops sending bytes and closes the handle when an in-flight native call returns. Cancelling the native call itself is not claimed. | `design`, draft §18 |

### 3.5 Thread affinity and the impersonation window

Impersonation is the ability of a thread to run with different security information than its process (`doc M6`). The window is therefore a property of one thread.

| # | Rule | Basis |
|---|---|---|
| TA-1 | The sequence enter impersonation, open, optional handle queries, revert runs on one operating-system thread. The thread is pinned before impersonation begins and released only after a verified revert. | `doc M6`, `design` |
| TA-2 | Inside the window the thread runs no other work: no task or thread hop, no callback, no logging, no network or registry call, no child process. Anything that runs there runs with the user's rights, and work moved to another thread runs with the broker's. | `doc M5`, `design` |
| TA-3 | If entering impersonation fails, no file is opened. The documentation says that after a failed `ImpersonateSecurityContext` later requests run in the process's context, a privileged process can do what the client could not, and callers should check the result and execute no client request. The check `execution-identity-v1` returns `UNKNOWN` (deferred) before the open, and an execution-time failure returns `DEPENDENCY_UNAVAILABLE` with no open (`FILES-01`). | `doc M2`, draft §17.5 |
| TA-4 | After entering, the broker reads the effective user SID of the thread's token and compares it with the principal. A difference reverts and returns `FAIL` with `EXECUTOR_MISMATCH`; nothing is opened (draft §17.5). | `doc M13`, `doc M15`, `design` |
| TA-5 | Revert is unconditional on every exit path, including an error and a panic, with the call that matches the entry (`RevertSecurityContext` for `ImpersonateSecurityContext`, `SetThreadToken` with a null token or `RevertToSelf` for a thread assignment). | `doc M4`, `doc M7`, `doc M8`, `design` |
| TA-6 | If the revert fails, the documentation says the application keeps running in the client's context, "which is not appropriate", and should shut down the process. The broker marks itself unhealthy, refuses every later protected operation with no open and no bytes, reports the state to its supervisor, and terminates. The thread is never returned to service (`FILES-09`). | `doc M7`, `design` |
| TA-7 | Whether `ImpersonateSecurityContext` affects the calling thread or the whole process is not clear from the page ("the thread or process"). The rules assume a thread; the alternative is `QuerySecurityContextToken` with a thread assignment, whose handle is closed with `CloseHandle`. | `doc M2`, `doc M3`, `doc M8`; `probe OI-1` |

### 3.6 Revocation limits

| # | Rule | Basis |
|---|---|---|
| RL-1 | A token holds the user SID and the SIDs of the groups of which the user is a member, and the system creates it when the user signs in. A handle receives the access rights granted at open. The pages read do not state that a later change of group membership or of an ACL leaves an existing token or handle unchanged. The profile therefore documents both as limits, and claims neither as a revocation mechanism. | `doc M13`, `doc M29`, `doc M10`; `probe OI-3`, `probe OI-4` |
| RL-2 | A handle that is open keeps its access until the task ends, the deadline passes, or the broker closes it. A revocation reaches the next open, not the open handle (freshness profile, sections 4.1 and 6). | `design` |
| RL-3 | The group list in a new token can reflect directory data older than the token (for example, a service ticket that the client cached). The profile declares the context age as the bound it can enforce and records the upstream lag as unestablished. It needs a domain controller to probe. | `design`; `probe OI-10` |

## 4. Native dependencies

All sixteen components are listed; each unused one carries its reason. "To be supplied" means the component is a responsibility of the deployment or of a later task, and listing it does not assert that it has been built.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator and filter chain in the file broker on the Windows file server | Gateway implementer | To be supplied |
| C02 | Native authentication and claim adapters | baseline | Windows authentication through Negotiate, and the token read for principal and groups | Windows IAM owner and adapter owner | Authentication exists; the adapter is the reference implementation (see the end of this profile), not yet run on Windows |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry with administrator-run enrollment, looked up by the Windows SID workload and the presented `agent_id` | IAM and security owner | Registry contract and a memory backend exist; a durable backend is to be supplied |
| C04 | Native delegation and task authority | delegated or task execution | Delegation and task registry binding user, agent, purpose and task, read through `authority_ref` | Application and IAM owner | To be supplied; the semantics of `authority_ref` for user-context acquisition are a dependency on the delegation and execution-identity deliverable (finding G03) |
| C05 | Evidence and authoritative status sources | baseline | Enrollment registry, delegation and task registry, hold store, Windows security context | Adapter owner | To be supplied |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the read route needs no external approval; a separately approved task is a task-authority fact (C04) |
| C07 | Purpose and exact operation mapper | baseline | Mapper at revision `pact-files-1` and the file registry | Adapter owner | To be supplied |
| C08 | Native resource executor and authorization | the actual resource operation | Local NTFS and the Windows access check under the impersonated user | Resource owner (file server administrator) | Exists |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store | Gateway and platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Broker outcome writer, and an immutable record naming the executor identity | Resource owner and evidence owner | The native source of the executor record is `OI-12` |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | Registry only, no adaptation lifecycle; to be supplied |
| C13 | Revocation and security holds | baseline | Revocation and hold store | Security and IAM owner | To be supplied |
| C14 | Protected evidence and audit storage | baseline | Access-controlled evidence and audit store | Security and data owner | To be supplied |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | Per-task handle table: handle lifetime, cancellation, task isolation | Application and resource owner | To be supplied; no transactions or budgets because the route is read-only |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no containment, egress or output control is claimed; data-use restrictions are labeled attested-only |

## 5. Alternative and bypass paths

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Native access to the same files by other means: the user's own SMB share access, a local or remote logon to the file server, backup software | `out-of-claim` | Not a broker route; native ACLs apply unchanged; excluded in section 6 |
| B2 | Open under the broker's own service identity because impersonation is unavailable or fails (broader-account fallback) | `closed` | Files are opened only inside the impersonation window, and nothing is opened when impersonation fails or the executor is not the principal (3.5); fixture `FILES-01` |
| B3 | Object substitution behind the configured path: a replaced file, a junction or symbolic link at any path component, a hard link, an alternate name | `closed` | Post-open checks of the reparse attribute, the volume serial and file identifier, and the final path before any read (3.3); fixtures `FILES-02`, `FILES-07` |
| B4 | Reuse of an open handle by another task, operation, agent or child process | `closed` | Per-task, non-inheritable, never shared (3.4); fixture `FILES-05` |
| B5 | Write, delete, rename, directory listing or search through the broker | `closed` | Only R1 exists and its mapping binds method, file id and read access mode (section 2); fixture `FILES-06` |
| B6 | Remote access to the files over SMB from another host, with delegation and share-level permissions | `out-of-claim` | [`smb.md`](smb.md): not claimed; excluded in section 6 |
| B7 | A Unix file broker or any other non-Windows file system adapter | `out-of-claim` | [`unix.md`](unix.md): not claimed; excluded in section 6 |

## 6. Unsupported forms

The first three rows are the I04 row of the handoff "Deliberate design choices" table, split into its three forms. The fourth, broker-account fallback, comes from the sample's statement of the boundary. The others come from the routes and paths found while filling sections 2, 3 and 5.

| Unsupported form | Seed (handoff source row) | Why it is not established |
|---|---|---|
| Remote SMB delegation and share-level permission controls | I04 files: "Remote SMB delegation/share controls" | The claim is a broker-local open of a local NTFS file at the local impersonation level (IA-7). [`smb.md`](smb.md) is a stub: not claimed |
| Unix behavior | I04 files: "Unix behavior" | No Unix identity, permission, ACL or path semantics are claimed. [`unix.md`](unix.md) is a stub: not claimed |
| Immediate handle revocation | I04 files: "immediate handle revocation" | An open handle keeps its access (3.6); a revocation reaches later opens only |
| Broker-account fallback | Sample I04: the broker "does not open files using the broker service account's broader rights" | The broker never opens as its own identity, whether impersonation is unavailable, fails, or would yield another executor (3.5, `FILES-01`) |
| Any route other than R1, including every write, delete, rename, listing and search | Section 2 | Not listed in section 2, so not claimed |
| Directories, reparse points of any kind (symbolic links, junctions, mount points, placeholders), files whose data is not immediately available | Section 3.3 | Rejected after open by PB-4 |
| Non-NTFS volumes, network paths, device namespaces | Section 3.3, PB-2 | Only fully qualified local NTFS paths registered by an administrator are served |
| Identity by any means other than a completed Negotiate exchange: OpenID Connect alone, password logon, `LsaLogonUser`, service-for-user | Section 3.1; sample I04: "An Entra OIDC sign-in alone does not establish a usable Windows file-access token" | Not implemented (IA-4, IA-12) |
| Group semantics beyond comparing token group SIDs under a configured rule: nested groups, SID history | Sample I04 | A group list is optional; rights come from the open (ER-1, ER-2) |
| Enforced purpose or data-use restrictions | Draft §17.4 | `execution-control-v1` is not claimed, so any such restriction is labeled attested-only and no egress or output control is claimed |

## 7. Identity mapping

Rules are those of [`identity-mapping.md`](../identity-mapping.md); this table records the choices of this profile.

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | Namespace `files`: the user and the workload are the Windows account, `files:{domain-sid}:{user-sid}` (identity-mapping section 3.3), with `domain-sid` the SID without its last subauthority (IA-8). A group value is `files:{domain-sid}:{group-sid}` by the same rule. Never `DOMAIN\user`, display names or SID history. A user that moves to another domain gets a new SID and so a new identity with its own enrollment (`doc M29`) |
| Trusted enrollment actors | The native administrative workflow only (`enroll.Admin`). No authorized issuer is configured for namespace `files` in wire version 0.1. The user, the agent, and anyone presenting the holder key are not enrolling actors (IM-12, IM-13) |
| Shared-account handling | Supported under IM-16 to IM-20, for the reason that IM-19 requires. The workload is the user's Windows account, because the open runs under the user's impersonation token and so the request must be authenticated as the user (ER-1, IA-8): the system uses an access token, which carries the SID of the user's account, to identify the user when a thread interacts with a securable object; every process executed on behalf of the user has a copy of that token; and an impersonating thread interacts with securable objects using the client's security context (`doc M13`). An account per agent would make the open check that account's rights instead of the user's. The documented way to give an agent its own logon and still obtain the user's impersonation token is a service-for-user logon: it takes the user's UPN, which cannot be null, as an input that the broker would have to trust, and a service account needs `SeTcbPrivilege` on the computer to get an impersonation token instead of an identification token (`doc M27`, `doc M28`); this profile does not implement it (IA-12). PACT still tells the agents apart: each agent has its own record and holder key naming the same workload (IM-17), selected by the presented `agent_id` (IM-18), and resolution by the workload alone is `UNKNOWN`. Selection cases: `FILES-10`, `FILES-11` |
| Certificate, token, or role-session bindings | The Windows security context authenticates the workload only. It is not bound to the holder key (IM-21); no certificate, `cnf` constraint or role session is used |
| Lifecycle rules (rotation, compromise, recovery) | Deferred to `identity-mapping.md`. SIDs are not reused (`doc M29`), so IM-6 name reuse does not arise; the deletion of an account is followed by an administrator's revocation of the records bound to it (IM-29). Because the profile supports shared accounts, a compromised record closes the account to no other agent: the other agents of the account keep their own records, and another agent can still be enrolled on it (IM-20). A compromised record stays terminal (IM-28): only the native administrative workflow of draft §6.4 retires it (`REVOKED`). The propagation bound is the enrollment source's status age, 0 (F1 in section 8) |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule. Two narrowings: only `Admin` enrolls, and SID history never selects the principal |

## 8. Freshness

Five sources are listed; every outage ends in `DEFERRED`, which fails closed (draft §18). The class of each source is that of the freshness profile, section 4.1.

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Enrollment registry (agent and key binding status) | Current authoritative state; the status time is the read time, the observation time is the last change (IM-10) | 30 | 0 | `DEFERRED` |
| F2 Windows security context of the completed Negotiate exchange (principal SID, token group SIDs) | Cached credential snapshot; the observation and status time are the instant the final `AcceptSecurityContext` call returned, and no later check of account state takes place; the `SourceRef` includes the logon session and token locally unique identifiers (`doc M14`) and that instant, so a new observation time always has a new reference | 300 | 300 | `DEFERRED` |
| F3 Native file open under impersonation (effective right to open) | Current authoritative decision, made by the open at execution (freshness profile, section 6) | 0 | 0 | `DEFERRED` |
| F4 Delegation and task registry (`authority_ref`) | Current authoritative state; the semantics of `authority_ref` for user-context acquisition depend on the delegation deliverable | 30 | 0 | `DEFERRED` |
| F5 Security hold store | Current authoritative state, read for each evaluation | 30 | 0 | `DEFERRED` |

The bound of F2 is the longest age of a context the broker serves (`context_max_age_seconds`), not a measure of how old the directory data in a new token can be (rule RL-3 in section 3.6, `OI-10`). A rule that demands a status bound below 300 seconds on the group list cannot be met by this source: the result is `DEFERRED`, or an authorized publisher changes the requirement (draft §17.2).

### 8.1 Membership and status sources

Only the security context supplies membership facts. The enrollment registry supplies binding status, not membership, and the broker reads no account-enabled fact of its own.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F2 Windows security context of the completed Negotiate exchange (principal SID, token group SIDs) | `identity`, `groups` | `false` | Not applicable: no live check | `none` | Not applicable: no change feed | 300 | `cached_snapshot` |

## 9. Residual limits

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | File contents already returned to the agent are not recalled by a later revocation. `execution-control-v1` is not claimed, so any purpose or data-use restriction is attested-only and no egress or output control is claimed (draft §17.4, §18) | Disclosed here; no bound |
| Revocation propagation | A change to F1, F4 or F5 reaches the broker at the next evaluation within each source's own consistency. A change to group membership reaches the broker only through a new Negotiate exchange. An operation already executed is not undone by revoking its receipt (draft §18) | 0 s status bound for F1, F4, F5; 300 s context age plus an unestablished upstream lag for F2 |
| Open handle | A handle already open keeps the access granted at open until the task ends, the deadline passes, or the broker closes it. Whether a later ACL or group change affects it is an open item; no revocation of an open handle is claimed | At most `handle_max_lifetime_seconds` after the open; `OI-3`, `OI-4` |
| Token snapshot | The principal and group SIDs are a snapshot from when the context was established. The age of the directory data inside a new token is not established | `OI-10`; needs a domain controller |
| Impersonation level | The local level only; no remote resource is reached under the user's rights | IA-7 |
| Executor evidence | Draft §14.2 asks for an immutable native record that names the actual executor identity. No native source is established; the broker's audit record is the evidence reference until one is named, and its qualification is open | `OI-12` |
| Path and object binding | An event that gives a registered file a new file identifier, or changes its final path, makes the broker refuse the file until an administrator registers it again | Fail closed; administrator action |

## 10. Fixture index

The cases are adapter cases of this profile in `spec/v1.0/fixtures/adapters/files/`, one file per variant, named by its lower-case ID and variant, such as `files-01.enter-fails.json`, with the manifest id `adapters/files/files-01.enter-fails`; every file is registered in `spec/v1.0/fixtures/manifest.json` and listed in the `fixtures` array of `profile.json`. They state the native systems in the model `files/1` of the [file broker cases README](../../fixtures/adapters/files/README.md): the accounts and the Negotiate tokens the security package completes, the impersonation of the broker thread, the file registry, and the objects of the file system with their attributes and access control lists, which a harness realizes with fakes on every platform. The Evidence column names the files, and says where a part of an item is a property of the validator rather than of an adapter function: an adapter case shows what the function returns, and the admission effect (`FAIL`, `INADMISSIBLE`, `DEFERRED`) is the validator's comparison of it with the requirement. Three items are tests of the adapter package rather than cases, because the case format can express neither a lookup by another task's tuple nor a case restricted to one platform: `FILES-05`, and `FILES-W01` and `FILES-W02`, which need the NTFS access check and run in the Windows job against a test local user that the job creates. The identity, freshness and request-binding cases of `spec/v1.0/fixtures/adapters/_common/` also apply and are not repeated; the profile supports shared workloads, so the `shared` cases run.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `FILES-01` | Impersonation unavailable: entering the window fails, entering leaves the thread running as the service account, or the principal has no completed Negotiate context | No open by any identity, and none as the service identity. `authorize_native` is `DEPENDENCY_UNAVAILABLE`, or an error when the executor would be the service; `execution-identity-v1` is `UNKNOWN` with `DEPENDENCY_UNAVAILABLE` when the window cannot be entered and `FAIL` with `EXECUTOR_MISMATCH` when the executor would be the service (draft §17.5). The validator's result is `DEFERRED` | `adapters/files/files-01.enter-fails`, `files-01.executor-is-service`, `files-01.no-context`, `files-01.check-enter-fails`, `files-01.check-executor-is-service`, with the control `files-01.check-impersonated` | B2, 3.5 |
| `FILES-02` | Resolved final path, or volume serial and file identifier, differs from the registry after the open; a final path that differs only in letter case | Handle closed, no bytes, `CONTEXT_MISMATCH` | `adapters/files/files-02.other-object-id`, `files-02.other-volume`, `files-02.other-final-path`, `files-02.final-path-case` | B3, 3.3 |
| `FILES-03` | The open returns access denied; a deny entry for the user ahead of a group grant | Native denial, a `DENY` of the open's source with no obligation; no contents; no execution (draft §22.2). An allow names the open as its source, with no obligation, no decision record and no decision time | `adapters/files/files-03.access-denied`, `files-03.deny-entry`, with the controls `files-03.read-granted` and `files-03.decision-provenance` | R1, 3.2 |
| `FILES-04` | (a) A connection's context older than `context_max_age_seconds`; (b) a rule demands a group observation fresher than F2 can give | (a) Native denial `NO_CREDENTIAL` with a new Negotiate challenge, no open; a context exactly that old authenticates. (b) The group claim carries the instant the exchange completed as observation and status time; the validator's comparison of a rule limit below the best bound of F2 gives `UNSUPPORTED_REQUIREMENT` and `DEFERRED` (freshness profile, section 4.2), and a context older than the rule limit `STALE_EVIDENCE` (draft §5, invariant 5) | (a) `adapters/files/files-04.stale-context`, with the control `files-04.context-at-limit`; (b) `files-04.claim-times` | F2, IA-9 |
| `FILES-05` | A handle opened for one task looked up by another task, operation, agent, principal or realm | `CONTEXT_MISMATCH`; no bytes; the owner's handle is unaffected and serves its own read once | Go test of the adapter package (`TestHandleIsolation`); the lifetime and task-end rules of HI-2 likewise (`TestHandleLifetime`) | B4, 3.4 |
| `FILES-06` | A presentation bound to a read used for a write, delete, other path, or a query; an operation with another access | `map_operation` of revision `pact-files-1` refuses the request as a violation of the operation mapping, `INVALID_MESSAGE` (draft §13.4), so the read presentation has no operation it could admit; `authorize_native` of an operation with a write action is `CONTEXT_MISMATCH` and opens nothing; no execution | `adapters/files/files-06.delete`, `files-06.put`, `files-06.query`, `files-06.extra-segment`, `files-06.write-operation`, with the control `files-06.read-mapped` | R1, B5 |
| `FILES-07` | The configured leaf is a reparse point (a symbolic link or a junction), a directory, an offline file, or a file not fully present | Rejected after open, `CONTEXT_MISMATCH`; handle closed; no bytes | `adapters/files/files-07.symbolic-link-leaf`, `files-07.junction-leaf`, `files-07.directory`, `files-07.offline`, `files-07.recall-on-data-access` | B3, 3.3 |
| `FILES-08` | A signed profile claims a group that the token lacks | The group list of `read_native_claim` is the token's and does not hold the group; the validator's comparison does not satisfy the authoritative requirement (draft §22.2), not `ADMISSIBLE`. The principal identifier is the token's user; another path is `UNSUPPORTED_REQUIREMENT` | `adapters/files/files-08.token-groups`, `files-08.principal-id`, `files-08.unapproved-path` | R1, B2 |
| `FILES-09` | (a) The revert after impersonation fails; (b) the broker was marked unhealthy by an earlier failed revert | (a) No handle is kept and nothing executes, `DEPENDENCY_UNAVAILABLE`; the broker is marked unhealthy. (b) Every later protected request is refused with no open and no bytes: `authorize_native` `DEPENDENCY_UNAVAILABLE`, `execution-identity-v1` `UNKNOWN` with `DEPENDENCY_UNAVAILABLE` | (a) `adapters/files/files-09.revert-fails`; (b) `files-09.unhealthy`, `files-09.unhealthy-check`; the sequence of (a) then (b) on one broker, with the read of a handle kept before, is a Go test (`TestRevertFailureMakesBrokerUnhealthy`) | 3.5 |
| `FILES-10` | One user account with `ACTIVE` records for agents A (key KA) and B (key KB), enrolled in either order | A and B each resolve to their own record and key, whatever the order of the records, never the agent enrolled first. That a presentation by A signed with KB is `INADMISSIBLE` with `INVALID_PROOF` is the validator's comparison with A's key (identity-mapping §5, §8) | `adapters/files/files-10.agent-a`, `files-10.agent-b`, `files-10.agent-a-other-order` | R1, section 7 |
| `FILES-11` | The account of `FILES-10` with A `REVOKED` and B `ACTIVE`; with A `COMPROMISED` and B `ACTIVE`; with A and B both `REVOKED`; and agent IDs C with no record on the account, of an agent enrolled only for another user's account in the realm, and of an agent enrolled only in another realm | Each agent ID resolves to its own record: a revoked or compromised one as its status with its own key, and B keeps its own `ACTIVE` record (IM-20). C and the agent of another realm get `UNKNOWN` without the enrolled-elsewhere report, the agent of another account `UNKNOWN` with it. The codes `INVALID_PROOF`, `SECURITY_HOLD` and `CONTEXT_MISMATCH` are the validator's (identity-mapping §8) | `adapters/files/files-11.a-revoked`, `files-11.b-beside-revoked`, `files-11.a-compromised`, `files-11.b-beside-compromised`, `files-11.both-revoked`, `files-11.unenrolled-agent`, `files-11.other-account-agent`, `files-11.other-realm-agent` | R1, section 7 |
| `FILES-12` | A completed Negotiate exchange; identity headers naming another account; another account, one with the same display name, and one with the same relative identifier in another domain; a request with a bearer token and no Negotiate token; a token the security package rejects | The token's user is the principal and the workload, `files:{domain-sid}:{user-sid}`, with mechanism `negotiate`; the headers and the display name never name it, and another domain is another principal. No Negotiate token is `NO_CREDENTIAL` (IA-1); a rejected token is `CREDENTIAL_REJECTED` and never appears in the denial (IA-3, draft §19) | `adapters/files/files-12.completed-exchange`, `files-12.identity-headers-ignored`, `files-12.other-account`, `files-12.same-display-name`, `files-12.other-domain`, `files-12.no-negotiate`, `files-12.rejected-token` | 3.1, section 7 |
| `FILES-W01` | Windows only: a file with a restricted ACL, readable by the broker's service identity, opened under the test user | The system denies the open, a native `DENY`; no bytes; proves that the open used the user's identity | Go test of the adapter package in the Windows job (`TestWindowsRestrictedACL`) | R1, 3.2, B2 |
| `FILES-W02` | Windows only: a file with a direct grant to the test user and no group grant | The open succeeds without the project group and the read returns the file's bytes; the right comes from the native check | Go test of the adapter package in the Windows job (`TestWindowsDirectGrant`) | R1, 3.2 |

Freshness rows F1, F4 and F5, and their outages, are covered by the common identity and freshness fixtures; this profile adds no files-specific case for them. The Go repository keeps two naive brokers as the red baseline of the files cases: one that opens as the service account when impersonation fails, and one that always does; every files case fails against at least one of them, except the controls `files-01.check-impersonated`, `files-06.read-mapped` and `files-10.agent-a`.

### Replaced common cases

The common cases of the adapter conformance suite run against this adapter. Eight `authenticate_native` cases state a principal or a denial reason that a Negotiate exchange cannot give, because IA-8 derives the principal from the token's user SID, and three `authorize_native` cases expect a decision member that the native open cannot carry, because the access check answers allowed or denied with no obligation, decision record, decision time or policy revision. They are replaced ([adapters README](../../fixtures/adapters/README.md), "Replaced common cases"; draft §22.2). The others pass, with the deployment-supplied sources that their native state describes.

| Common case | Why the broker cannot realize it | Replacement |
|---|---|---|
| `COMMON-01.credential-wins` | Expects `https://idp.acme.example/bob` | `FILES-12.identity-headers-ignored`: identity headers naming another account; the exchange's user is the principal |
| `COMMON-02.via-enforcement-point` | Expects `https://idp.acme.example/alice` | `FILES-12.completed-exchange`: authenticated as `files:{domain-sid}:{user-sid}`, mechanism `negotiate`, realm of the broker |
| `COMMON-09.authenticate-realm` | Expects a `globex` principal id | `FILES-12.other-domain`: the same relative identifier in another domain is another principal |
| `COMMON-10.authenticate-error` | Pins `CREDENTIAL_REJECTED` for a bearer token and a cookie, which carry no Negotiate token and are `NO_CREDENTIAL` (IA-1) | `FILES-12.rejected-token`: a rejected Negotiate token is `CREDENTIAL_REJECTED`, and neither it nor the cookie appears in the denial |
| `IDENT-01.authenticate` | Expects `basic:acme-accounts:20511` | `FILES-12.other-account`: another account authenticates as its own SID |
| `IDENT-02.authenticate` | Expects an `oauth:` identifier of another tenant | `FILES-12.other-domain`: another authority is another domain SID (IM-4) |
| `IDENT-03.authenticate` | Splits user and client; the broker's principal and workload are both the user's account (section 7) | `FILES-12.completed-exchange`: the principal and the workload are the same identifier |
| `IDENT-05.authenticate` | Expects `basic:acme-accounts:30981` | `FILES-12.same-display-name`: an account with the same display name authenticates as itself |
| `COMMON-06.allow-no-execution` | Expects an obligation on the allow | `FILES-03.read-granted`: an allow of the open's source with no obligation, and authorizing reads nothing |
| `COMMON-06.deny-unchanged` | Expects an obligation on the denial | `FILES-03.access-denied`: the native denial of the open's source with no obligation, and nothing executes |
| `COMMON-06.decision-provenance` | Expects a decision record, a decision time and a policy revision of a policy source | `FILES-03.decision-provenance`: the decision names the open as its source and carries no decision record (`source_ref` null) and no decision time, because the access check reports neither |

### 10.1 Mapping of the G19 closure items to fixtures

The finding G19 of the handoff asks for six specifications and for separate remote and Unix profiles. It names five cases to reject, and delegation and share denial for remote variants.

| G19 item | Where | Fixtures | Status |
|---|---|---|---|
| Identity acquisition | 3.1 | `FILES-01`, `FILES-04`, `FILES-12` | The levels a real exchange gives are `OI-1`, `OI-2` |
| Effective user, group and inherited rights | 3.2 | `FILES-03`, `FILES-08`, `FILES-W01`, `FILES-W02` | No case for an inherited group grant; recommended |
| Actual least-access opens | 3.2, ER-3 | `FILES-06`, `FILES-W01`, `FILES-W02` | No case asserts the requested access mask; recommended |
| Path, reparse and object binding | 3.3 | `FILES-02`, `FILES-07` | Intermediate components `OI-6`, names `OI-7` |
| Handle isolation and lifetime | 3.4 | `FILES-05` | No case for inheritance; `OI-9` |
| Native revocation limits | 3.6 | none: documented limits | `OI-3`, `OI-4` |
| Separate remote and Unix profiles | [`smb.md`](smb.md), [`unix.md`](unix.md) | none: stubs state "not claimed" | Not claimed |
| Reject broader-account fallback | 3.5 | `FILES-01`, `FILES-09` | |
| Reject changed paths or objects | 3.3 | `FILES-02`, `FILES-07` | |
| Reject inaccessible ACLs | 3.2 | `FILES-03`, `FILES-W01` | |
| Reject stale contexts | 3.1 | `FILES-04` | |
| Reject cross-task handles | 3.4 | `FILES-05` | |
| Remote variants: delegation and share denial | [`smb.md`](smb.md) | none | Not claimed |

## Open items to probe

None of these has been probed. The Windows probe is separate work and runs in the Windows CI job (the `windows-latest` runner). Where an item needs a domain controller, whether the job can provide one is not established here.

| ID | Question | Probe | Rules that wait on it |
|---|---|---|---|
| OI-1 | Does `ImpersonateSecurityContext` affect the calling thread only, or the process? | Impersonate on a pinned thread and read the effective identity from a second thread; if process-wide, use `QuerySecurityContextToken` with a thread assignment | IA-5, TA-7 |
| OI-2 | Which token type and level does a completed local-account Negotiate exchange give, and what does a client that permits only identification level produce? | Read token statistics on the server side for both clients | IA-6 |
| OI-3 | Does a change of group membership after the context is created leave the token's group list unchanged? | Create a local test user and group, establish the context, add the user to the group, read the token groups again | RL-1 |
| OI-4 | Does an open handle keep working after (a) a DACL change, (b) a group change, (c) a revert of the opening thread? | Open under the test user, change, read again | HI-5, RL-1, RL-2 |
| OI-5 | What is the smallest access mask that lets the read, `FileAttributeTagInfo`, `FileIdInfo` and `GetFinalPathNameByHandle` succeed? Which error code does a denied open return? How does a deny entry for write rights interact with `SYNCHRONIZE` in the mask? | Try masks against a file with each ACL shape | ER-3, ER-7 |
| OI-6 | Does `FILE_FLAG_OPEN_REPARSE_POINT` apply to reparse points in intermediate path components (junction, symbolic link, mount point)? | Open through each, then read attribute tag and final path | PB-6 |
| OI-7 | What does `GetFinalPathNameByHandle` return with `FILE_NAME_NORMALIZED` and `FILE_NAME_OPENED` and with `VOLUME_NAME_DOS` and `VOLUME_NAME_GUID`, for case differences, 8.3 aliases, hard links (which name), trailing dots and spaces, the `\\?\` prefix and stream names? | Open each form, compare the strings | PB-5, PB-8 |
| OI-8 | Does `FileIdInfo` stay equal across rename on one volume and change on replacement? Which volume query establishes local NTFS? | Rename, replace, query | PB-9, PB-10 |
| OI-9 | Is a handle opened with null security attributes absent from a child process created with handle inheritance? Does a process created by an impersonating thread run as the service? | Create a child that lists its handles and identity | HI-3 |
| OI-10 | How old can the group data in a new token be (for example a service ticket cached by the client), and what does the exchange confirm about current account state? | Needs a domain controller; change membership and disable an account between exchanges | RL-3, IA-9 |
| OI-11 | Does the broker supply channel bindings to `AcceptSecurityContext`, and what is the effect on a relayed token? | Run an exchange over TLS with and without bindings | IA-11 |
| OI-12 | Which native facility supplies the immutable record of the executor identity that draft §14.2 asks reports to reference? This is a design question for the evidence owner, not a probe | Candidate: the broker's own audit record; whether it qualifies is decided by the receiver | C10, residual limits |

## Reference implementation (informative)

The reference implementation of the adapter is the Go package `go/adapters/files`. It reaches Windows through three interfaces, `SecurityPackage` (the Negotiate exchange), `Impersonator` (the impersonation of the calling thread) and `FileSystem` (the open and what the handle reports), so its rules run on every platform; on Windows `NewSSPI`, `ThreadImpersonator` and `NTFS` implement them with `golang.org/x/sys/windows`, in files that build for Windows only. The contracts it satisfies are those of `go/adapter`, `go/adapter/enroll` and `go/adapter/installed`. The other sections are language-neutral.

| Profile rule | Go package element |
|---|---|
| `authenticate_native`, IA-1 to IA-11 | `Broker.AuthenticateNative` runs the next leg of the connection's exchange (`Broker.ConnContext` gives each connection of the listener its state; `Broker.Challenge` is the `WWW-Authenticate` value of the response) and returns an `adapter.Principal` with `ID` and `Workload` set to `files:{domain-sid}:{user-sid}` (`PrincipalID`), the broker's `Realm`, `Mechanism` `negotiate` and `AuthenticatedAt` the instant the final leg returned (IA-9). A leg that needs another, an absent token and a context older than `Config.ContextMaxAge` are `*adapter.NativeDenial` `DenialNoCredential`; a failed leg, and a token below the impersonation level (IA-6), `DenialCredentialRejected` |
| `resolve_agent_binding`, section 7 | `enroll.Resolver` over the `enroll.Registry` of `Config.Registry`. The agent ID selects the agent's record on the shared account (IM-18); an agent with no record on the account gives `adapter.BindingUnknown`. Because the profile supports shared accounts, the conformance run sets `SharedWorkloads` in its `adaptertest.Options`, and a registry built with `WithSharedWorkloads` serves it. Trusted actors are `enroll.Admin`; `enroll.Agent` has no authority |
| `map_operation` | `Broker.MapOperation`: revision `pact-files-1` has the routes of `Routes` and cannot be replaced; a query, another method or another path violates it and wraps `adapter.ErrInvalidMessage`; an uninstalled revision wraps `adapter.ErrUnsupportedRequirement` and a principal of another realm `adapter.ErrContextMismatch` |
| `read_native_claim`, F2 | `Broker.ReadNativeClaim` answers `PathPrincipalID` and `PathGroupIDs` from the token of the principal's completed context, with `ObservedAt` and `StatusCheckedAt` the instant the exchange completed and a `SourceRef` naming the token and that instant; other paths come from `Config.Claims` and wrap `adapter.ErrUnsupportedRequirement` when none is installed. The Windows token lists the groups that are enabled for access checks, without logon and integrity SIDs |
| Evaluation of F2 and the other sources | `freshness.Evaluate` and `freshness.Evaluator` with a `freshness.Monotonic` guard (`Config.Guard`); reason codes `freshness.StaleEvidence`, `freshness.ClockAhead`, `freshness.Restamped`, `freshness.UnsupportedRequirement`, `freshness.DependencyUnavailable` |
| `check_context`, TA-3, TA-4 | `Broker.CheckContext` runs `CheckExecutionIdentity` itself: `VerdictPass` with `REQUIREMENT_SATISFIED`; `VerdictFail` with `EXECUTOR_MISMATCH`; `VerdictUnknown` with `DEPENDENCY_UNAVAILABLE`. Other checks are `Config.Checks` |
| `authorize_native`, ER-1 to ER-7, PB-4, TA-1 to TA-6 | `Broker.AuthorizeNative` opens in the impersonation window and returns `adapter.Decision` with `EffectAllow` or `EffectDeny` of `Config.OpenSourceID`; an object mismatch wraps `ErrObjectMismatch` (`adapter.ErrContextMismatch`), a failed entry `ErrImpersonationUnavailable` and a failed revert `ErrUnhealthy` (both `adapter.ErrDependencyUnavailable`). The task and the agent of the request come from `WithTask` |
| Execution, HI-1 to HI-6, PB-7 | `Broker.Execute` reads a kept handle once, for its exact `HandleKey`; `Broker.EndTask` and `Config.HandleMaxLifetime` close handles; `Broker.MarkUnhealthy`, `Broker.Healthy` and `Config.OnUnhealthy` carry TA-6 |
| Registration, PB-2 | `Register` opens a fully qualified local path and records the entry of a `StaticRegistry` from that one handle |
| `record_outcome`, ER-7 | `Broker.RecordOutcome` returns `adapter.Signed`, or `adapter.NoVisibility` with a reason when `Config.ExecutionVisible` is not set |
| Descriptor | `adapter.Descriptor{Protocol: "http", Version: "1.1", MappingRevision: "pact-files-1"}` |

Go notes for TA-1 and TA-2. The Go runtime documents that `runtime.LockOSThread` wires the calling goroutine to its operating-system thread, that no other goroutine runs on that thread meanwhile, that a goroutine should call it before calling operating-system services that depend on per-thread state, and that a goroutine that exits without unlocking terminates its thread (`doc G1`). The window therefore runs on a goroutine of its own, locked before the impersonation begins and unlocked only after a successful revert, and starts no goroutine. `golang.org/x/sys/windows` at `v0.49.0`, the version the module pins, exports none of the security-package functions (`AcquireCredentialsHandle`, `AcceptSecurityContext`, `QuerySecurityContextToken`, `ImpersonateSecurityContext`, `DeleteSecurityContext`, `FreeCredentialsHandle`) and no `FILE_ID_INFO`, `FILE_ATTRIBUTE_TAG_INFO` or `TOKEN_STATISTICS` type; the package declares the functions it calls from `secur32.dll` and the structures as their pages declare them, and assigns the token of `QuerySecurityContextToken` to the thread with `SetThreadToken` (TA-7). The values the pages read do not state, and the open items, are listed in the package documentation and wait on the Windows job.

## Sources

Microsoft pages, all read on 2026-10-16 under `https://learn.microsoft.com/en-us/`. The tags M30 to M32 are used only in [`smb.md`](smb.md).

| Tag | Page |
|---|---|
| M1 | `windows/win32/api/sspi/nf-sspi-acceptsecuritycontext` |
| M2 | `windows/win32/api/sspi/nf-sspi-impersonatesecuritycontext` |
| M3 | `windows/win32/api/sspi/nf-sspi-querysecuritycontexttoken` |
| M4 | `windows/win32/api/sspi/nf-sspi-revertsecuritycontext` |
| M5 | `windows/win32/secauthz/impersonation-levels` |
| M6 | `windows/win32/secauthz/client-impersonation` |
| M7 | `windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself` |
| M8 | `windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken` |
| M9 | `windows/win32/api/fileapi/nf-fileapi-createfilew` |
| M10 | `windows/win32/fileio/file-security-and-access-rights` |
| M11 | `windows/win32/fileio/file-access-rights-constants` |
| M12 | `windows/win32/secauthz/how-dacls-control-access-to-an-object` |
| M13 | `windows/win32/secauthz/access-tokens` |
| M14 | `windows/win32/api/winnt/ns-winnt-token_statistics` |
| M15 | `windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation` |
| M16 | `windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew` |
| M17 | `windows/win32/api/winbase/ns-winbase-file_id_info` |
| M18 | `windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex` |
| M19 | `windows/win32/api/winbase/ns-winbase-file_attribute_tag_info` |
| M20 | `windows/win32/fileio/reparse-points` |
| M21 | `windows/win32/fileio/reparse-points-and-file-operations` |
| M22 | `windows/win32/fileio/hard-links-and-junctions` |
| M23 | `windows/win32/fileio/symbolic-link-effects-on-file-systems-functions` |
| M24 | `windows/win32/fileio/naming-a-file` |
| M25 | `windows/win32/fileio/file-streams` |
| M26 | `windows/win32/secauthn/microsoft-negotiate` |
| M27 | `windows/win32/api/ntsecapi/nf-ntsecapi-lsalogonuser` |
| M28 | `windows/win32/api/ntsecapi/ns-ntsecapi-kerb_s4u_logon` |
| M29 | `windows-server/identity/ad-ds/manage/understand-security-identifiers` |
| M33 | `windows/win32/fileio/file-attribute-constants` |

Other sources: `doc R1` is RFC 4559, "SPNEGO-based Kerberos and NTLM HTTP Authentication in Microsoft Windows" (sections 4.1, 4.2, 5, 6), read from the RFC Editor text. `doc G1` is the documentation of `runtime.LockOSThread` in the Go 1.26.1 source and on pkg.go.dev. The sample [`example_I04.md`](../../examples/example_I04.md) and the draft are the other references.
