# PACT integration profile stub: file broker, SMB

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

**Status: stub. Not claimed.** This document makes no PACT conformance claim. It has no `profile.json`, no fixtures and no registry entry, and no adapter of any role is declared for SMB. It fixes the boundary of a future profile and lists what that profile needs, so that nobody reads the Windows local profile ([`profile.md`](profile.md)) as covering a file reached over SMB. The sample [`example_I04.md`](../../examples/example_I04.md) says: "A remote SMB deployment must establish supported remote delegation and preserve applicable share-level and filesystem controls. Local impersonation does not automatically provide remote delegation."

Where this document and the draft ([`draft.md`](../../draft.md)) differ, the draft governs. It contains no code. Statements about Windows behavior carry a basis: `doc` (the cited page, read on 2026-10-16, listed under Sources), `design` (a requirement a future profile would place on the broker), or `probe` (not established; the Windows probe is separate work and has not run). No Windows behavior is stated from memory.

## 1. Boundary

| Item | Statement |
|---|---|
| What a future profile would cover | A PACT-aware file broker that reads a file through an SMB share, as the requesting user, from a host other than the one that holds the file, or through a share name on the same host |
| Difference from the local profile | The local profile opens a file on the broker's own volume at the local impersonation level. A file reached over SMB belongs to another system, to which the user's identity reaches only if it is delegated (`doc M5`) |
| Same boundary as the local profile | The broker never reaches the file under its own identity as a fallback; it computes no right itself; a native denial is final (draft §2.3, §4.3, §17.5) |
| Not covered | Local NTFS opens ([`profile.md`](profile.md)), Unix ([`unix.md`](unix.md)), distributed namespaces, and clustered or scale-out shares |
| Claim | None. Roles claimed: none. Conformance profile: none. Fixtures: none |

## 2. Required mechanisms

| ID | Mechanism | What a profile must establish | Basis |
|---|---|---|---|
| S1 | Constrained delegation | The impersonation level that reaches remote systems is `SecurityDelegation`; `SecurityImpersonation` is the local level (`doc M5`). A front-end service can obtain a service ticket to a back-end service on a user's behalf through the Kerberos extension S4U2Proxy. Constrained delegation limits the services to which the front-end may delegate, and resource-based constrained delegation is configured on the back-end service's account by its administrator (`doc M30`). A profile must name which form it requires, who configures it, and how the broker proves the delegated identity is the principal. Without delegation the user's identity does not reach the remote server, and what that server sees instead is not established; the broker must never fall back to its own identity | `doc M5`, `doc M30`; `design`; `probe` |
| S2 | Identity of the delegated client | The documentation defines two well-known SIDs that tell an access control list whether the client's identity was asserted by an authentication authority from proof of its credentials or asserted by a service (`doc M30`). A profile must state which it accepts and how `execution-identity-v1` reports it | `doc M30`; `design` |
| S3 | Share-level permissions | Share permissions and file-system permissions are independent, and the more restrictive applies to access through the share. Share permissions apply only to network shares and do not restrict a user at the server itself (`doc M31`, an archived page for Windows Server 2008 R2). A broker that opens a local path therefore never meets share-level restrictions, so a remote profile must open through the share. Evaluating effective access over a share needs a UNC share path, not a mapped drive letter, and the effective-permission interfaces can give wrong results for remote resources (`doc M32`) | `doc M31`, `doc M32`; `design` |
| S4 | Path and object binding | The local rule of comparing the final path of the handle cannot be copied. SMB does not support queries for normalized paths, so the function splits the path and queries each component, and fails with access denied if the user lacks access to any component; volume GUID paths are not created for network shares (`doc M16`). Extended file information is documented as supported over SMB 3.0 (`doc M18`); what the file identifier means across shares, mounts and failover is not established | `doc M16`, `doc M18`; `probe` |
| S5 | Identity acquisition | The Negotiate exchange of the local profile gives the broker a context for its own host. Whether and how it yields a delegable context, and what an OpenID Connect sign-in alone provides (sample I04: it "does not establish a usable Windows file-access token"), are open | `design`; `probe` |
| S6 | Handle and session isolation | How the SMB sessions and connections of different users are kept apart on one broker, and what the handle rules of the local profile become | `design`; `probe` |
| S7 | Revocation limits | Lifetime of the service tickets and SMB sessions behind a delegated open, and what an open handle keeps after a change. Not established | `probe` |

## 3. Unsupported in wire version 0.1

Every SMB form is unsupported. The first row is the wider claim that sample I04 does not establish.

| Unsupported form | Why it is not established |
|---|---|
| Remote SMB delegation and share controls | Not claimed: this document is a stub |
| Constrained delegation of any form for file access | `S1` is a requirement list, not a specification; nothing is probed |
| Share-level permission enforcement | `S3` states the interaction; no mechanism is specified |
| Network path and object binding | `S4` says the local check does not transfer |
| Broker-account fallback | Never allowed, as in the local profile |
| Immediate revocation of an open handle | Same limit as the local profile; `S7` |

## 4. To become a claim

A full profile replaces this stub, filled per [`TEMPLATE.md`](../TEMPLATE.md), with a `profile.json` that validates against `integration-profile.schema.json`, a registry entry, and negative fixtures that cover the local cases and the two that the requirements add for remote variants: delegation and share denial. A Windows environment with a domain controller and a second host is a precondition for the probe.

## Reference implementation (informative)

None exists. The Go package `go/adapter` and its siblings define the adapter contracts a remote broker would satisfy.

## Sources

Microsoft pages, read on 2026-10-16 under `https://learn.microsoft.com/en-us/`.

| Tag | Page |
|---|---|
| M5 | `windows/win32/secauthz/impersonation-levels` |
| M16 | `windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew` |
| M18 | `windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex` |
| M30 | `windows-server/security/kerberos/kerberos-constrained-delegation-overview` |
| M31 | `previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754178(v=ws.11)` |
| M32 | `troubleshoot/windows-server/windows-security/access-checks-windows-apis-return-incorrect-results` |
