# PACT integration profile stub: file broker, Unix

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

**Status: stub. Not claimed.** This document makes no PACT conformance claim. It has no `profile.json`, no fixtures and no registry entry, and no adapter of any role is declared for Unix. It fixes the boundary of a future profile and lists the mechanisms that profile needs, so that nobody reads the Windows profile ([`profile.md`](profile.md)) as covering Unix. The sample [`example_I04.md`](../../examples/example_I04.md) says the same: a Unix adapter follows the same boundary but "must implement that platform's permission and ACL semantics rather than copy the Windows group example literally".

Where this document and the draft ([`draft.md`](../../draft.md)) differ, the draft governs. It contains no code. Statements about operating-system behavior carry a basis: `doc` (the cited page, read on 2026-10-16, listed under Sources), `design` (a requirement a future profile would place on the broker), or `probe` (not established; the Linux probe is separate work and has not run). No Unix behavior is stated from memory.

## 1. Boundary

| Item | Statement |
|---|---|
| What a future profile would cover | A PACT-aware file broker on a Unix-like host that opens a local file under the requesting user's own identity and permissions, with the same split as the Windows profile: native authentication, enrollment of the agent, PACT admission, then a native open whose access check is the authorization |
| Same boundary as Windows | The broker never opens as its own identity when the user's identity is unavailable; it computes no right from a group list; a native denial is final; the open is the least access needed (draft §2.3, §4.3, §17.5) |
| Executor class | `impersonated-user` in the sense of draft §17.5: the executor that runs the open equals the principal's identity. How a Unix process takes that identity is `U2` below |
| Not covered | Windows, SMB ([`smb.md`](smb.md)), network file systems, containers and user namespaces, and mandatory access control layers. None is claimed |
| Claim | None. Roles claimed: none. Conformance profile: none. Fixtures: none |

## 2. Required mechanisms

A claim needs each row below to be specified, probed and covered by a negative case. The "Windows rule" column names the rule of [`profile.md`](profile.md) that the row replaces.

| ID | Mechanism | What a profile must establish | Windows rule | Basis |
|---|---|---|---|---|
| U1 | Identity acquisition and namespace | How the authenticated Unix user is established and mapped to a stable identifier. Identifiers for a mechanism without a row in identity-mapping section 3.3, such as a user id, use an `x-` namespace token defined by the profile. A numeric user id can be reassigned after a deletion, so identity-mapping rule IM-6 applies | 3.1, 7 | `design` |
| U2 | Execution identity | A separate helper process per task, started with the target user id, group id and supplementary group ids, performs the open. The broker's own identity never opens a file. Which privilege the broker needs to start a process under another identity, and what an empty supplementary group list does, are not established | 3.5 | `design`; `probe` |
| U3 | Path binding | Open relative to a directory descriptor. `O_NOFOLLOW` fails the open if the final component is a symbolic link and does not affect earlier components (`doc L2`). On Linux, `openat2` with `RESOLVE_BENEATH` refuses a resolution in which any component is not a descendant of the directory descriptor, with `EXDEV`; `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_MAGICLINKS` fail with `ELOOP`; `RESOLVE_NO_XDEV` refuses mount-point crossings (`doc L1`). `openat2` dates from Linux 5.6; the page gives no version for each `RESOLVE_*` flag, so availability on the runner kernel is open. A kernel without `openat2` is unsupported, with no emulation by a walk of components | 3.3 | `doc L1`, `doc L2`; `probe` |
| U4 | Object binding | After the open, the identity of the object behind the descriptor (device and inode) equals the registry entry. The behavior of identifier reuse after deletion is not established | 3.3, PB-4(3) | `design`; `probe` |
| U5 | Effective rights | The kernel's access check decides. For a POSIX access control list, the user entries and the owner entry are tested against the effective user id, and the mask entry caps the rights that named-user, owning-group and named-group entries can grant (`doc L3`). The broker computes no right itself and opens read-only | 3.2 | `doc L3`, `design` |
| U6 | Descriptor isolation | A descriptor is per task and never shared. A new descriptor stays open across an `execve` by default and `O_CLOEXEC` changes that default (`doc L2`), so every descriptor is opened close-on-exec. How bytes leave the helper (a pipe, or passing the descriptor) is not decided | 3.4 | `doc L2`, `design` |
| U7 | Revocation limits | What survives a later change to a group membership or an ACL: the supplementary groups of a running helper, and an open descriptor. Neither is established | 3.6 | `probe` |

## 3. Unsupported in wire version 0.1

Every Unix form is unsupported. The rows below are the forms a reader could assume from sample I04, Unix behavior among them.

| Unsupported form | Why it is not established |
|---|---|
| Any Unix broker, identity, permission, ACL or path behavior | Not claimed: this document is a stub |
| Helper process under the user's identity | `U2` is a requirement list, not a specification |
| Descriptor-relative opens with `O_NOFOLLOW` and `openat2` resolution flags | `U3` is open for versions and flags |
| POSIX ACL and mode-bit semantics, including the mask | `U5` states the kernel decides; nothing is probed |
| Network file systems, containers, user namespaces, mandatory access control | Not covered by any row |
| Immediate revocation of an open descriptor | Same limit as Windows; `U7` |

## 4. To become a claim

A full profile replaces this stub, filled per [`TEMPLATE.md`](../TEMPLATE.md), with a `profile.json` that validates against `integration-profile.schema.json`, negative fixtures for each required mechanism that run on a Linux runner, and its entry in the profile registry. The Linux probe settles `U2`, `U3`, `U4` and `U7` first.

## Reference implementation (informative)

None exists. For `U2`, the Go standard library starts a process under another identity through the `SysProcAttr.Credential` field of `exec.Cmd`; `syscall.Credential` has the fields `Uid`, `Gid`, `Groups` and `NoSetGroups` (Go 1.26.1 source, `syscall/exec_unix.go` and `exec_linux.go`). For `U3`, `golang.org/x/sys/unix` defines `Openat2`, `OpenHow` and the `RESOLVE_*` constants for Linux at v0.44.0, the version observed in a local module cache when this stub was written. The Go package `go/adapter` and its siblings define the adapter contracts a Unix broker would satisfy, as they do for Windows.

## Sources

| Tag | Source |
|---|---|
| L1 | `openat2(2)`, Linux manual page, `https://man7.org/linux/man-pages/man2/openat2.2.html`, read on 2026-10-16 |
| L2 | `open(2)`, Linux manual page, `https://man7.org/linux/man-pages/man2/open.2.html`, read on 2026-10-16 |
| L3 | `acl(5)`, Linux manual page, `https://man7.org/linux/man-pages/man5/acl.5.html`, read on 2026-10-16 |
