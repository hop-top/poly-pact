# Integration sample 04 — File access under the user's own permissions

**Status:** Informative integration sample for PACT Protocol v1.0. Names, paths, groups, and policies are fictional. HTTP and profile excerpts are partial illustrations, not runnable or complete signed wire fixtures. The adapter design is deployment-specific.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I04. Finding and component IDs refer to the companion handoff.md. These are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- The broker can obtain a supported usable Windows user context and use it for the real file open.
- Native ACL evaluation, file-ID mapping, delegation, and handle isolation are implemented.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C04 | User/agent file task and usable execution context. |
| C08 | Actual least-access open retaining user/group/inherited ACLs. |
| C15 | Handle lifetime, cancellation, and task isolation. |
| C16 | Real output/egress controls where claimed. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G03 | Actor binding and executor identity: see the Actor binding section below, Section 17.5, and the `execution-identity-v1` check. | Profile / clarification |
| G19 | Complete path/object/handle controls and separate SMB/Unix profiles. Specified for the local NTFS open by the integration profile [`files`](../profiles/files/profile.md), whose section 10.1 maps each G19 item to rules and cases; the SMB and Unix documents [`smb.md`](../profiles/files/smb.md) and [`unix.md`](../profiles/files/unix.md) are stubs that make no claim. | Profile / coverage |
| G25 | Distinguish attested from enforced data-use controls per §17.4. | Deployment / coverage |

### Deliberate simplifications and limitations

- The design uses local NTFS; remote SMB delegation/share controls and Unix semantics are uncovered.
- Existing tokens/handles may outlive changes; instantaneous revocation is not claimed.
- `execution-control-v1` is not required, so the runtime guarantee is labeled "attested-only": the sample mentions real output and egress controls only "where claimed", and post-read residual limits remain for the file contents.

### Profile and fixtures

The integration profile [`files`](../profiles/files/profile.md) states the conformance claim behind this sample: a broker on a Windows file server that authenticates the user through a completed Negotiate exchange (section 3.1), serves one read route R1 (`GET /files/{file_id}/content`, action `file.read`) whose opaque `file_id` the trusted file registry maps to one local NTFS path, volume serial number, and file identifier, opens the file under the user's impersonation token (section 3.2), checks the opened object before any read (section 3.3), and keeps each handle to one task (section 3.4). The principal is `files:{domain-sid}:{user-sid}`, and the user's account is a workload shared by every agent that acts for the user, each with its own enrollment record (profile section 7). Remote SMB access and Unix behaviour are not claimed: [`smb.md`](../profiles/files/smb.md) and [`unix.md`](../profiles/files/unix.md) are stubs with no fixtures. The adapter cases are in [`fixtures/adapters/files/`](../fixtures/adapters/files/README.md), registered in the fixture manifest; the decisions table below names the case group or case for each row. They describe the accounts, the Negotiate tokens, the impersonation of the broker thread, and the file system with its ACLs, which the harness realizes with fakes on every platform; they do not exercise Windows.

### Validation still required

The cases cover restricted ACLs, stale contexts, broader-account fallback, path, reparse, and object substitution, and cross-task handles, at the adapter, against fakes. These remain unvalidated:

- All Windows-only behaviour, which awaits a run of the Windows CI job: the Go tests `FILES-W01` (a restricted ACL that the broker's own identity could read, denied to the test user) and `FILES-W02` (a direct user grant without the project group), and the probes of open items OI-1 to OI-9 and OI-11 (impersonation scope and levels, group and handle behaviour after changes, the access mask, intermediate reparse points, final-path forms, file identifiers, handle inheritance, channel binding). No Windows behaviour has been probed for the profile.
- An inherited group grant, and the access mask the open requests: the profile's section 10.1 recommends cases for both, and none exists.
- The age of the group data inside a new token, which needs a domain controller (open item OI-10).
- The native record of the executor identity that Section 14.2 asks reports to reference (open item OI-12).
- Remote claims: delegation and share-denial tests belong to an SMB profile, which [`smb.md`](../profiles/files/smb.md) leaves unclaimed; a Unix adapter is likewise unclaimed ([`unix.md`](../profiles/files/unix.md)).

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Scenario and placement

Maya asks a document assistant to summarize a departmental project file. Windows already controls that file using permissions assigned directly to users and through security groups. The assistant must read only what Maya's effective native access permits, further restricted to the approved task.

A PACT-aware file broker runs on the Windows file server. It authenticates Maya through existing Windows authentication and obtains a usable native user security context through an authorized mechanism. It separately verifies the enrolled agent and its authority to act for Maya.

The broker performs the actual local file open under Maya's supported impersonation context. It does not open files using the broker service account's broader rights after merely checking a profile field.

## Illustrative existing permissions

| Object or identity | Existing native configuration |
|---|---|
| Maya | Member of `Project-Orion-Readers` |
| Orion folder | The group has inherited read permissions on ordinary project files |
| `brief.docx` | Inherits the project's read permissions |
| `restricted.docx` | Protected ACL limited to a separate audience; Maya has no effective read access |
| `personal-notes.docx` | A direct user ACE grants Maya read access independently of the project group |

This table simplifies the ACLs. Windows evaluates the actual security descriptor, requested access, and user/group token information. The broker does not calculate rights by adding group names from a profile. ACE ordering, enabled and deny-only groups, inheritance, and other applicable policy can matter. See [Microsoft's access-check description](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object).

## Native facts and PACT requirements

| Fact | Authoritative source and purpose |
|---|---|
| User principal | Authenticated Windows SID mapped to a stable native principal, `files:{domain-sid}:{user-sid}` (integration profile, rule IA-8) |
| Effective security context | Native user token with applicable group information |
| Agent and holder key | Authorized enrollment registry, independent of user authentication |
| Authority to act for Maya | Native delegation/task registry binding user, agent, purpose, and task |
| Requested file and access mode | Broker's configured file-ID mapping and actual operation |
| Effective right to open the file | Native file open under the user's security context |

A required profile excerpt could be:

```json
{
  "attributes": {
    "environment": {
      "principal_id": "files:S-1-5-21-1004336348-1177238915-682003330:S-1-5-21-1004336348-1177238915-682003330-1105",
      "group_ids": ["files:S-1-5-21-1004336348-1177238915-682003330:S-1-5-21-1004336348-1177238915-682003330-1210"]
    },
    "delegation": {
      "authority_ref": "document-task:orion-brief-42"
    }
  }
}
```

These identifiers are fictional SIDs in the form the integration profile defines: the domain SID, then the full SID of the user or of the group `Project-Orion-Readers` (profile section 7). Display names and `DOMAIN\user` are never the identifier. If the gateway requires group identifiers, it compares them with authoritative native values under a configured rule and requests only groups relevant to admission. The group values are those of the token of the completed exchange, so a rule that demands them fresher than the exchange's context age, 300 seconds in the profile's illustrative configuration, cannot be met (profile section 8).

A group list is optional to this integration: the gateway can require verified principal/delegation facts and leave effective ACL access to the native file open. A direct user permission can permit access without a particular group, while a group member can still lack access to a particular file.

## Actor binding

This table applies Section 17.5 to this sample. It adds no field. Every actor transition is native: PACT records and checks it and never mints it.

| Actor | Binding field or check | Native source |
|---|---|---|
| Agent | `sub`, `holder_jkt` | Authorized enrollment registry, independent of user authentication (Sections 6.1 and 6.2); each agent acting for Maya has its own record on her account, selected by the presented agent ID (integration profile section 7) |
| Principal | `OperationContext.principal_id`; check `native-principal-binding-v1` | `authenticate_native`: the authenticated Windows SID mapped to a stable native principal (Section 17.1) |
| Authorized task | `Intent.task_id`, reconciled with the authoritative task context | `task_attribution_source`: the native task record for the document summary |
| Native delegation | `/attributes/delegation/authority_ref`; check `native-delegation-v1` | Native delegation and task registry, binding user, agent, purpose, and task |
| Broker or gateway | `aud`, `environment_id` | Trusted configuration (Section 4.2): the file broker on the Windows file server |
| Downstream executor | Check `execution-identity-v1`; declared class `impersonated-user` | The broker's native file open under the supported impersonation context of Maya's security token |

The installed `execution-identity-v1` mapping declares the class `impersonated-user` for Maya, the document-summary task, and the read of the resolved file. The check returns `PASS` only when the executor that will run the open equals that class and binding. The mapping rests on the authorized mechanism by which the broker obtains Maya's native security context; a profile creates no Windows token, and where that context is unavailable the executor is indeterminate. `authorize_native` is invoked with Maya as the principal, never with the broker's own authority.

Adversarial results (Section 17.5):

- Another user's Windows identity presented: `native-principal-binding-v1` returns `FAIL` with reason code `CONTEXT_MISMATCH`.
- The read presented under a task other than the approved document task: `native-delegation-v1` returns `FAIL` with reason code `TASK_MISMATCH`.
- The user-to-agent delegation is stale or revoked: `native-delegation-v1` returns `FAIL` with reason code `STALE_EVIDENCE` or `REVOKED_EVIDENCE`.
- The open would proceed under the broker's service account, with its broader rights: `execution-identity-v1` returns `FAIL` with reason code `EXECUTOR_MISMATCH`.
- The user execution context is unavailable and the executor cannot be determined: `execution-identity-v1` returns `UNKNOWN`, which yields `DEFERRED`.

Executor evidence (Section 14.2): each `AUTHORIZATION` and `EXECUTION` report in this sample references, in `evidence_refs`, an immutable native record identifying the actual executor identity. Section 14.2 states this without exception for the access-denied open. A report whose executor class differs from the declared `impersonated-user` class is `UNQUALIFIED`.

## Exchange

1. The user establishes the existing authenticated Windows context. Enrollment and task records establish which agent/key may use that context. No profile creates a Windows token.
2. The assistant requests a PACT contract for reading the opaque resource `file-orion-brief` with the recognized document-summary purpose.
3. The broker maps that identifier to its configured file, such as `D:\Departments\Orion\brief.docx`. It issues requirements and a single-use nonce bound to the operation, principal, and intent.
4. The assistant prepares the required profile and evidence, signs the complete presentation with its enrolled key, and submits the protected read:

```http
GET /files/file-orion-brief/content HTTP/1.1
Host: files-broker.example
Authorization: Negotiate <existing-Windows-authentication-token>
PACT-Presentation: <complete-compact-signed-presentation>
```

The header illustrates an established Windows-authenticated exchange, not the full multi-message negotiation.

5. The broker checks native authentication, agent/user delegation, PACT signature and binding, field provenance, freshness, status, and holds. Passing admission produces `ADMISSIBLE`.
6. The broker applies its own task/resource policy, enters the supported user impersonation context, and opens the resolved file for the minimum required read access. Windows applies the native access checks.
7. If allowed, the broker reads from that authorized handle and returns the permitted data. It reliably restores its original execution context and does not share the user's handle across unrelated tasks.

For `restricted.docx`, PACT can pass its configured profile requirements while the native open returns access denied. No file contents are returned.

## Binding and execution controls

The adapter binds the opaque file ID, user, access mode, purpose, and exact HTTP request. It resolves only configured resource namespaces and handles path traversal, reparse points, and object substitution through its native file-access implementation. A client cannot turn a read into a write, another path, or an unrestricted search. Under the integration profile, the client supplies no path text; the broker opens the registered path only, without following a reparse point at the leaf, and before any read checks that the handle is no reparse point, directory, or offline file, that its volume serial number and file identifier equal the registry entry, and that its final path equals the registered one (rules PB-3 and PB-4). A mismatch closes the handle and returns no bytes (`FILES-02`, `FILES-07`). Each handle belongs to one task, operation, principal, and agent, is not inheritable, and is closed when the task ends or after at most 300 seconds in the illustrative configuration (rules HI-1 to HI-4; `FILES-05`).

A preliminary “can read?” query is insufficient: the actual open must use the intended native context and access rights. A change between checking and use cannot justify opening under the service account instead. The open runs on one pinned thread inside the impersonation window; if impersonation cannot be entered, or the thread's effective user is not the principal, nothing is opened, and a failed revert takes the broker out of service (rules TA-1 to TA-6; `FILES-01`, `FILES-09`).

This sample uses a broker-local NTFS open. A remote SMB deployment must establish supported remote delegation and preserve applicable share-level and filesystem controls; the SMB stub [`smb.md`](../profiles/files/smb.md) lists what such a profile needs and claims none of it. Local impersonation does not automatically provide remote delegation. An Entra OIDC sign-in alone does not establish a usable Windows file-access token.

## Decisions to illustrate

| Request | Expected result under the example ACLs | Profile case |
|---|---|---|
| Read `brief.docx` for the approved task | PACT passes; native open allows | `adapters/files/files-12.completed-exchange`, `adapters/files/files-06.read-mapped`, `adapters/files/files-03.read-granted` |
| Read `restricted.docx` | Native denial blocks access even if PACT passes | `adapters/files/files-03.access-denied`, `adapters/files/files-03.deny-entry`; on Windows, `FILES-W01`, awaiting the Windows CI run |
| Read `personal-notes.docx` under a separately approved task | Direct user permission can allow without the project group | `FILES-W02`, a Windows-only Go test awaiting the Windows CI run |
| Write/delete using a read-bound presentation | Binding check blocks the change; a fresh request still needs native rights. The broker maps no write, delete, other path, or query, so the request is refused with `INVALID_MESSAGE` | `FILES-06` |
| Forge group membership in the profile | Native comparison fails | `adapters/files/files-08.token-groups` |
| User execution context unavailable | Fail closed; do not execute as the broker account | `FILES-01`; a failed revert: `FILES-09` |
| Read outside the task despite native access | Installed task/purpose controls block the request | Evaluation case `delegation/changed-task` |
| Registered file replaced, or reached through a link, directory, or offline placeholder | Handle closed, no bytes, `CONTEXT_MISMATCH` | `FILES-02`, `FILES-07` |
| Handle of one task looked up by another task, operation, or agent | `CONTEXT_MISMATCH`; the owner's handle is unaffected | `FILES-05`, a Go test of the adapter package |
| Negotiate context older than the profile's bound | Native denial with a new challenge; no open | `adapters/files/files-04.stale-context` |
| Identity headers naming another account | No effect; the exchange's user is the principal | `adapters/files/files-12.identity-headers-ignored` |
| Two agents acting for Maya on her account | Each resolves to its own record and key | `FILES-10`, `FILES-11` |

A native ACL does not itself constrain purpose. A valid purpose declaration does not confer ACL access.

## Revocation, reputation, and reuse

Group membership and open handles have native lifecycle semantics. An established token can contain older membership, and an existing handle is not necessarily revoked by an ACL change. The adapter documents freshness, token renewal, handle lifetime, and cancellation; it does not promise instantaneous revocation. The integration profile states them in sections 3.4, 3.6, 8, and 9: a change of group membership reaches the broker only through a new Negotiate exchange, a revocation reaches the next open and not an open handle, and whether a token or a handle is affected by a later change at all is open (open items OI-3 and OI-4, awaiting the Windows CI run). Subsequent operations obtain the required current checks and fresh PACT bindings.

A denied open alone is not misconduct. Observed reads and independently assessed summaries can supply qualified outcomes. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, the access-denied open is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, an observed read is “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`), and an independently assessed summary is an “Independent assessment” (`QUALITY`, `task_quality`). Reputation cannot add a group, modify an ACL, or enable backup/restore privileges to bypass ordinary access.

A Unix adapter can follow the same boundary using a supported native execution identity and actual file opens under that identity. It must implement that platform's permission and ACL semantics rather than copy the Windows group example literally. The Unix stub [`unix.md`](../profiles/files/unix.md) states that boundary and claims nothing.

## What this demonstrates

The existing file system remains authoritative for user and group rights. PACT verifies required agent context and task binding; the actual operation preserves the user's native authority.

**PACT anchors:** §§2.3, 4.3, 6, 8–12, 14, 17–18.

## Official references

- [Microsoft: How AccessCheck works](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object)
- [Microsoft: Impersonation levels](https://learn.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels)
- [Microsoft: Access control overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control)
- [Microsoft: Evaluating effective access on remote resources](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/access-checks-windows-apis-return-incorrect-results)
