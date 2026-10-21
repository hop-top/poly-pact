# stdio-ipc transport profile: probe record

This record backs sections 1 to 5 of the [`stdio-ipc` transport profile](profile.md). It lists every fact about an operating system or a library that the profile relies on, with the evidence for it. It targets spec version 1.0 and wire version 0.1 and is a draft.

## How to read the record

Each row ends with one status:

- `verified`: a probe program ran on the host named and produced the result shown.
- `documented`: the primary source named states it; no probe ran.
- `to probe`: neither. The profile does not use the fact as a rule; it lists it as an open item or an unsupported claim.

A probe is a throwaway program outside the source tree. It is not a fixture and nothing in the repository runs it. Probe rows of a later host are appended; a row is never edited to a new result. A result that differs from an earlier one gets a new row that names the earlier row.

## Hosts

| Host | Operating system | Kernel | Architecture | Toolchain | Dates |
|---|---|---|---|---|---|
| H1 | macOS 15.6.1 (build 24G90) | Darwin 24.6.0 | arm64 | Go 1.26.1 and `golang.org/x/sys` v0.49.0 on 2026-10-15; Go 1.26.9 and `golang.org/x/sys` v0.49.0 on 2026-10-20 | 2026-10-15 (planning), 2026-10-20 (re-check) |

No Linux or Windows host has run a probe yet. Every Linux and Windows row is `documented` or `to probe`.

## macOS probes (host H1)

Method. The parent sets umask 022, creates a fresh directory of mode 0700, and listens on the pathname socket `p.sock` inside it (`SOCK_STREAM`). Child processes connect to it. The parent reads options with `getsockopt` at level `SOL_LOCAL` (0): `LOCAL_PEERCRED` (1) into a `struct xucred` through `unix.GetsockoptXucred`, and `LOCAL_PEERPID` (2) through `unix.GetsockoptInt`, both from `golang.org/x/sys/unix`; it also reads both options through the standard library's `syscall.GetsockoptInt`. The constants are the ones in the SDK header `sys/un.h` (S02); the `xucred` layout, with `cr_version` as its first member and `XUCRED_VERSION` 0, is the one in `sys/ucred.h` (S03).

| Row | Fact | Probe | Result | Status |
|---|---|---|---|---|
| M01 | `LOCAL_PEERCRED` returns the uid of the connecting process on an accepted pathname socket. | Child connects; parent reads `LOCAL_PEERCRED` with `GetsockoptXucred` on the accepted socket. | `cr_version` 0, `cr_uid` 501 (the child's uid), `cr_ngroups` 16, `cr_groups[0]` 20. | `verified` 2026-10-15 and 2026-10-20 |
| M02 | `LOCAL_PEERPID` returns the pid of the connecting process. | As M01, reading `LOCAL_PEERPID`. | The child's pid. | `verified` 2026-10-15 and 2026-10-20 |
| M03 | An anonymous pipe has no peer credential. | Parent spawns a child whose stdin is an anonymous pipe; the child runs `fstat` and both options on descriptor 0. | `fstat` reports `S_IFIFO`; both options fail with `ENOTSOCK` ("socket operation on non-socket"). | `verified` 2026-10-15 and 2026-10-20 |
| M04 | A socketpair end handed to a child as stdin carries the parent's credentials. | Parent creates `socketpair(AF_UNIX, SOCK_STREAM, 0)` and spawns a child with one end as stdin; the child runs `fstat` and both options on descriptor 0. | `fstat` reports `S_IFSOCK`; `LOCAL_PEERPID` is the parent's pid; `LOCAL_PEERCRED` `cr_uid` 501, the parent's uid. | `verified` 2026-10-15 and 2026-10-20 |
| M05 | Reading `LOCAL_PEERCRED` as an integer returns the `xucred` version field, never a uid. | Standard library `syscall.GetsockoptInt(fd, 0, 1)` and `syscall.GetsockoptInt(fd, 0, 2)` on the accepted socket of M01. | The first returns 0 with no error: `cr_version`, which is `XUCRED_VERSION` 0. The second returns the child's pid. A 0 read this way is indistinguishable from uid 0. | `verified` 2026-10-15 and 2026-10-20 |
| M06 | The Go standard library offers no peer-credential call on macOS. | Search of the Go 1.26.9 source for darwin: `src/syscall` defines neither `LOCAL_PEERCRED` nor an `xucred` getter; `golang.org/x/sys/unix` v0.49.0 defines `GetsockoptXucred`, `Xucred`, `SOL_LOCAL`, `LOCAL_PEERCRED` and `LOCAL_PEERPID` (S04). Neither defines `SO_PEERCRED` for darwin. | As stated. | `verified` 2026-10-20 |
| M07 | `net.UnixConn` exposes no peer credential. | Method set of `*net.UnixConn` in Go 1.26.9; `RemoteAddr` of an accepted connection. | Methods `Close`, `CloseRead`, `CloseWrite`, `File`, `LocalAddr`, `Read`, `ReadFrom`, `ReadFromUnix`, `ReadMsgUnix`, `RemoteAddr`, `SetDeadline`, `SetReadBuffer`, `SetReadDeadline`, `SetWriteBuffer`, `SetWriteDeadline`, `SyscallConn`, `Write`, `WriteMsgUnix`, `WriteTo`, `WriteToUnix`; `RemoteAddr` is a `UnixAddr` with an empty name. The descriptor is reached through `SyscallConn`. | `verified` 2026-10-15 and 2026-10-20 |
| M08 | A socket created under the default umask is not owner-only. | `lstat` of `p.sock` after `bind` under umask 022. | Mode `srwxr-xr-x`. | `verified` 2026-10-15 and 2026-10-20 |
| M09 | macOS enforces write permission on the socket file for `connect`. | Same-uid child connects after the parent sets the socket file to mode 0000, then to mode 0555 (no write bit). | `connect` fails with `EACCES` both times; the listener accepts nothing. Matches unix(4) (S01). A connecting process of another uid was not tested. | `verified` 2026-10-20 for the owner (on 2026-10-15: `to probe`); other uids `to probe` |
| M10 | Kernel credentials describe the process that connected, not the process that holds the descriptor now. | A child connects, passes the connected descriptor to a grandchild by inheritance, and exits; the grandchild waits, then writes one line. The parent reads both options three times. | Right after `accept`: the child's pid. After the child exited, before the grandchild wrote: still the child's pid, now a process that does not exist. After the grandchild wrote: the grandchild's pid. `cr_uid` 501 all three times; a descriptor passed to another uid was not tested. | `verified` 2026-10-20: `LOCAL_PEERPID` is not fixed at connect time and can name a process that has exited; `LOCAL_PEERCRED` after a hand-off to another uid `to probe`, documented as connect-time by unix(4) (S01) |

## Linux

| Row | Fact | Evidence | Status |
|---|---|---|---|
| L01 | `SO_PEERCRED` returns the peer's pid, uid and gid as they were when the socket was connected or created. | unix(7) (S05): "The returned credentials are those that were in effect at the time of the call to connect(2), listen(2), or socketpair(2)." | `documented`; `to probe` |
| L02 | `SO_PEERCRED` works on a socketpair. | unix(7) (S05): "The use of this option is possible only for connected AF_UNIX stream sockets and for AF_UNIX stream and datagram socket pairs created using socketpair(2)." | `documented`; `to probe` |
| L03 | Go reads it through the standard library. | `func GetsockoptUcred(fd, level, opt int) (*Ucred, error)` (S09); `SO_PEERCRED` is defined in the Go 1.26.9 linux constants of `src/syscall`. | `documented` |
| L04 | Abstract-namespace sockets have no filesystem access control. | unix(7) (S05): "Socket permissions have no meaning for abstract sockets: the process umask(2) has no effect when binding an abstract socket, and changing the ownership and permissions of the object (via fchown(2) and fchmod(2)) has no effect on the accessibility of the socket." | `documented` |
| L05 | Linux checks write permission on the socket file for `connect`; other systems may not. | unix(7) (S05): "On Linux, connecting to a stream socket object requires write permission on that socket" and "on some systems (e.g., older BSDs), the socket permissions are ignored. Portable programs should not rely on this feature for security." | `documented` |
| L06 | Credentials crossing a user namespace are translated; unmapped ids become the overflow uid. | user_namespaces(7) (S06): credentials passed over a UNIX domain socket "are translated into the corresponding values as per the receiving process's user and group ID mappings", and "an unmapped user ID is converted to the overflow user ID (group ID); the default value for the overflow user ID (group ID) is 65534." The page states this for `SCM_CREDENTIALS`; whether `SO_PEERCRED` values are translated the same way is not stated. | `documented` for `SCM_CREDENTIALS`; `SO_PEERCRED` `to probe` |
| L07 | Another process's descriptors are reachable through `/proc/<pid>/fd`. | proc_pid_fd(5) (S07): "Permission to dereference or read (readlink(2)) the symbolic links in this directory is governed by a ptrace access mode PTRACE_MODE_READ_FSCREDS check". Whether a process of the same user passes that check on a default configuration, and can then open the other process's pipe end, is not stated there. | `documented` (the rule); same-user access `to probe` |
| L08 | An anonymous pipe has no peer credential. | pipe(7) (S08) names no credential mechanism. Expected result as M03 (`ENOTSOCK`). | `to probe` |

## Windows

| Row | Fact | Evidence | Status |
|---|---|---|---|
| W01 | A named pipe accepts remote clients unless the server rejects them. | CreateNamedPipeA (S10): `PIPE_REJECT_REMOTE_CLIENTS` (0x00000008): "Connections from remote clients are automatically rejected." | `documented` |
| W02 | The default security descriptor of a named pipe is not owner-only. | Named Pipe Security and Access Rights (S11): "The ACLs in the default security descriptor for a named pipe grant full control to the LocalSystem account, administrators, and the creator owner. They also grant read access to members of the Everyone group and the anonymous account." | `documented` |
| W03 | The server can take on the client's security context. | ImpersonateNamedPipeClient (S12): "the named-pipe file system changes the thread of the calling process to start impersonating the security context of the last message read from the pipe." | `documented` |
| W04 | The client chooses the impersonation level. | Impersonating a Named Pipe Client (S13): "By default, a server impersonates at the SecurityImpersonation impersonation level. However, when the client calls the CreateFile function to open a handle to the client end of the pipe, the client can use the SECURITY_SQOS_PRESENT flag to control the server's impersonation level." CreateFileA (S14): "SECURITY_IDENTIFICATION Impersonates a client at the Identification impersonation level." | `documented` |
| W05 | The server can read the client's process id. | GetNamedPipeClientProcessId (S15): "Retrieves the client process identifier for the specified named pipe." | `documented` |
| W06 | The server reads the client's user SID at Identification level. | Planned probe: client opens the pipe with `SECURITY_SQOS_PRESENT` and `SECURITY_IDENTIFICATION`; server reads one frame, calls `ImpersonateNamedPipeClient`, opens the thread token, reads its user SID, and reverts. Also: whether the SID can change between messages of one connection (W03 says "the last message read"). | `to probe` |
| W07 | A server can detect that another process already created its pipe name. | CreateNamedPipeA (S10): `FILE_FLAG_FIRST_PIPE_INSTANCE`: "If you attempt to create multiple instances of a pipe with this flag, creation of the first instance succeeds, but creation of the next instance fails with ERROR_ACCESS_DENIED." Whether creation fails when the existing instance belongs to another process of the same user is not stated. | `to probe` |
| W08 | AF_UNIX on Windows offers no peer credential. | AF_UNIX comes to Windows (S16, informative, 2017): "There is no support for ancillary data in the Windows unix socket implementation." The post names no peer-credential option. | `to probe` |
| W09 | Pipes and sockets crossing the WSL boundary. | AF_UNIX comes to Windows (S16, 2017) says interoperation with WSL unix sockets did not work "currently". No statement about named pipes or AF_UNIX across the WSL boundary was found on the WSL pages read (S17). | `to probe` |
| W10 | Handle inheritance can be limited to a list of handles. | No source read. | `to probe` |

## Sources

Web sources were fetched on 2026-10-20; each answered `200` with the title shown. Local sources are the files on host H1.

| Source | Location | Title or file |
|---|---|---|
| S01 | macOS manual page unix(4), host H1 (page footer "macOS 15.6", dated June 9, 1993) | `unix` – UNIX-domain protocol family |
| S02 | macOS SDK header `usr/include/sys/un.h`, Command Line Tools SDK on host H1 | `SOL_LOCAL` 0, `LOCAL_PEERCRED` 0x001, `LOCAL_PEERPID` 0x002, `LOCAL_PEEREPID` 0x003 |
| S03 | macOS SDK header `usr/include/sys/ucred.h`, same SDK | `struct xucred`, `XUCRED_VERSION` 0 |
| S04 | `golang.org/x/sys` v0.49.0: `unix/syscall_darwin.go` (`GetsockoptXucred`), `unix/ztypes_darwin_arm64.go` (`Xucred`), `unix/zerrors_darwin_arm64.go` (constants) | module source |
| S05 | https://man7.org/linux/man-pages/man7/unix.7.html | "unix(7) - Linux manual page" |
| S06 | https://man7.org/linux/man-pages/man7/user_namespaces.7.html | "user_namespaces(7) - Linux manual page" |
| S07 | https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html | "proc_pid_fd(5) - Linux manual page" |
| S08 | https://man7.org/linux/man-pages/man7/pipe.7.html | "pipe(7) - Linux manual page" |
| S09 | https://pkg.go.dev/syscall?GOOS=linux | "syscall package - syscall - Go Packages" |
| S10 | https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea | "CreateNamedPipeA function (winbase.h)" |
| S11 | https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights | "Named Pipe Security and Access Rights" |
| S12 | https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient | "ImpersonateNamedPipeClient function (namedpipeapi.h)" |
| S13 | https://learn.microsoft.com/en-us/windows/win32/ipc/impersonating-a-named-pipe-client | "Impersonating a Named Pipe Client" |
| S14 | https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea | "CreateFileA function (fileapi.h)" |
| S15 | https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid | "GetNamedPipeClientProcessId function (winbase.h)" |
| S16 | https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/ | "AF_UNIX comes to Windows - Windows Command Line" (published 2017-12-19) |
| S17 | https://learn.microsoft.com/en-us/windows/wsl/filesystems, https://learn.microsoft.com/en-us/windows/wsl/networking, https://learn.microsoft.com/en-us/windows/wsl/faq | "Working across file systems", "Accessing network applications with WSL", "FAQ's about Windows Subsystem for Linux" |
