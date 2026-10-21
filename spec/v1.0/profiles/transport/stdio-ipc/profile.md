# PACT transport profile: stdio-ipc

This profile targets spec version 1.0 and wire version 0.1 and is a draft. It is the transport profile (kind `transport`, id `stdio-ipc`, version `0.1`) that draft §13.3 and §13.3.1 require for local IPC and stdio, listed in [`registry.json`](../../registry.json). It is work in progress: this revision holds sections 1 to 5, which cover three items of the §13.3.1 list: the channel set and the channels it excludes, peer identity binding for each channel with an assurance level, and the list of what the channel does not protect. Framing and frame limits, the discovery method, the operation names, error carriage, and the replay-store scope come in sections 6 to 11 in a later change. Until those sections exist, the profile must not be cited as support for any claim.

The uppercase requirement words have the meanings that draft §3 gives them. Section references such as §6.2 are to the [draft](../../../draft.md); TEMPLATE section 5 is section 5 of the integration profile [`TEMPLATE.md`](../../TEMPLATE.md). Rows such as M01, L01 and W01, and sources such as S01, are those of the [probe record](probes.md), which holds the evidence and the sources for every statement here about an operating system or a library.

A deployment declares this profile with a `TransportDeclaration` (Appendix A.3) under the extension `pact-transport-profile-v1` (§13.3.1, §21). The declaration's `channels` takes the tokens of section 1 and its `identity_assurance` takes the tokens of section 2.

## 1. Scope and channels

### 1.1 Channels in scope

| Token | Channel | Platforms | Assurance (section 2) |
|---|---|---|---|
| `stdio` | Standard input and output of a child process, connected to the parent that spawned it, either by anonymous pipes or by one end of a Unix domain socketpair | Linux, macOS, Windows (anonymous pipes only) | `launcher` over anonymous pipes; `kernel-peer` over a socketpair |
| `uds` | Pathname Unix domain socket of type `SOCK_STREAM` | Linux, macOS | `kernel-peer` |
| `named-pipe` | Windows named pipe that rejects remote clients (section 4.5) | Windows | `kernel-peer`, with the identity read still `to probe` (W06) |

A `TransportDeclaration` lists in `channels` only the channels the deployment offers, and in `identity_assurance` every assurance level those channels provide. A deployment that offers `stdio` over anonymous pipes lists `launcher`.

### 1.2 Excluded channels

The channels below are unsupported in version 0.1. PACT messages over any of them stay under the HTTPS baseline (§13): §13.3.1 requires that "a channel reachable over a network, such as loopback TCP or a forwarded or tunnelled socket, is not eligible for a local-channel profile and stays under the HTTPS baseline", and the same holds for every other channel this table excludes. A message that arrives on an excluded channel is not a `stdio-ipc` message, whatever it carries.

| Channel | Reason for the exclusion |
|---|---|
| Loopback TCP, and TCP or UDP on any address | Reachable over a network; §13.3.1 names loopback TCP as ineligible, and §19 requires TLS on network paths. |
| Forwarded or tunnelled sockets: `ssh -L` and ssh socket forwarding, `socat` relays, WSL interop pipes, container port publishing | Reachable over a network or through a relay. The kernel reports the credentials of the process that called `connect` (S01, S05), which is the relay, not the process that originated the request. §13.3.1 names forwarded and tunnelled sockets as ineligible. |
| Shared memory | No peer identity mechanism and no framing are defined for it in this profile. |
| Linux abstract-namespace sockets | They have no filesystem access control: "Socket permissions have no meaning for abstract sockets" (L04). The socket directory rules of section 4.4 cannot apply to them. |
| Unix domain sockets of type `SOCK_DGRAM` or `SOCK_SEQPACKET` | macOS documents `LOCAL_PEERCRED` for `SOCK_STREAM` sockets only (S01), and a datagram socket has no connection to bind an identity to. |
| `AF_UNIX` sockets on Windows | No peer-credential mechanism is documented in the sources read; the 2017 announcement states that ancillary data is not supported (W08). |
| Pipes and sockets that cross the WSL boundary | How the identity of the originating process reaches the other side is not established (W09). They are treated as forwarded. |

## 2. Peer identity and assurance levels

### 2.1 Assurance levels

The `identity_assurance` tokens name how the gateway knows who is on the other end of a channel.

- `kernel-peer`: the gateway reads the peer's operating-system identity from the kernel on the connected channel: the uid on Linux and macOS, the user SID on Windows. The kernel sets the value when the channel is connected or created; on macOS, neither end can influence it except by connecting or listening under different credentials (S01).
- `launcher`: the channel carries no kernel peer credential. The identity rests on the process that created the channel, the parent that spawned the child and handed it the pipe ends.

Every claim over this profile MUST state the assurance level of each channel it covers. An integration profile that lists `stdio-ipc` in its claim states it in its section 1, and the wording rule of section 3.3 applies to a claim at `launcher` assurance.

### 2.2 Identity by channel

| Channel | Platform | Mechanism | What it yields | Level | Evidence |
|---|---|---|---|---|---|
| `uds` | Linux | `getsockopt` `SO_PEERCRED` on the connected socket; in Go, `syscall.GetsockoptUcred` of the standard library | `struct ucred`: pid, uid, gid as they were at `connect`, `listen` or `socketpair` | `kernel-peer` | L01, L03: `documented`, `to probe` |
| `uds` | macOS | `getsockopt` at level `SOL_LOCAL`: `LOCAL_PEERCRED` into `struct xucred`, and `LOCAL_PEERPID`; in Go, `golang.org/x/sys/unix` `GetsockoptXucred` and `GetsockoptInt` | `xucred`: effective uid and group list at `connect` (S01); a pid | `kernel-peer` | M01, M02, M06: `verified` |
| `stdio` over a socketpair | Linux | `SO_PEERCRED` on the child's end | As for `uds` on Linux | `kernel-peer` | L02: `documented`, `to probe` |
| `stdio` over a socketpair | macOS | `LOCAL_PEERCRED` and `LOCAL_PEERPID` on the child's end | The parent's uid and pid | `kernel-peer` | M04: `verified` |
| `stdio` over anonymous pipes | all | none: a pipe is not a socket | nothing from the kernel; on macOS both options fail with `ENOTSOCK` | `launcher` | M03: `verified` on macOS; L08: `to probe` on Linux; Windows `to probe` |
| `named-pipe` | Windows | `ImpersonateNamedPipeClient`, then the user SID of the impersonation token; `GetNamedPipeClientProcessId` for the pid | the client's security context (W03) and pid (W05) | `kernel-peer` | W03 to W05: `documented`; W06: `to probe` |

### 2.3 Binding rules

1. `authenticate_native` (§17.1) over a `kernel-peer` channel reads the peer credential on the connected channel before it acts on the first frame, and compares the uid or SID with the identity that trusted configuration (§4.2) expects for that channel. A mismatch, or a credential that cannot be read, is a native denial. The authenticated workload is the one that trusted configuration maps that uid or SID to.
2. The uid or SID names a workload, never an agent. The agent comes from the agent ID the request names, through `resolve_agent_binding`, and the holder-key proof binds the request to that enrollment (§6.2, §17.1).
3. On macOS, an implementation MUST read `LOCAL_PEERCRED` as a whole `struct xucred` and take the uid from `cr_uid`. Read as an integer, the option returns the structure's first field, `cr_version`, which is 0 (M05), the same value as the uid of root.
4. A process id read from the channel is audit data only. It MUST NOT be resolved to an executable or a command line and MUST NOT take part in an admission or authorization decision: a process id can be reused, and on macOS `LOCAL_PEERPID` is not fixed at connect time; it named a process that had exited, and then the process that wrote last (M10).
5. On Linux, a peer uid equal to the overflow uid (65534 by default, L06) MUST be rejected: it is what a uid without a mapping in the receiving user namespace becomes (section 4.1).
6. On Windows, the client security context that `ImpersonateNamedPipeClient` takes on is that of "the last message read from the pipe" (W03), so the gateway reads it after reading the first frame and before acting on it. Whether it can change between frames of one connection is `to probe` (W06).

### 2.4 Launcher assurance

At `launcher` assurance the parent knows what it started: the program it executed, the credentials it ran it under, and the pipe ends it handed over. The child knows only its own uid and its parent's pid. It has no kernel credential for the other end of its pipes, and rule 4 of section 2.3 forbids resolving the parent's pid to a program. The identity a `launcher` channel carries is therefore the declared launch path: the configured parent and the configured command, under the configured uid.

A parent that hands the child one end of a socketpair as its standard input and output instead of anonymous pipes raises the channel to `kernel-peer` on Linux and macOS: the child reads the parent's uid and pid from the kernel (M04 on macOS; L02 on Linux).

## 3. What the channel proves and does not prove

### 3.1 Proven

- At `kernel-peer` assurance: the process at the other end ran under the expected uid or SID when it connected, or when it created the socketpair.
- At `launcher` assurance: the request arrived through the channel that the declared launcher created.

Message authenticity at the PACT layer does not come from the channel. It comes from the holder-key signature on every presentation (§6.2), which no transport identity replaces: "Transport authentication alone does not replace this proof." This profile waives none of the requirements that §13.3.1 lists as not waivable.

### 3.2 Not proven

The channel does not protect against, and a claim over it does not establish:

- **Which program is on the other end.** A uid or SID names an operating-system user, not an executable, and a process id is audit data only (section 2.3, rule 4).
- **Anything about other processes of the same operating-system user.** This profile assumes they can reach the channel and its secrets: read another process's pipe and socket descriptors through `/proc/<pid>/fd` on Linux, which a ptrace access check governs (L07); attach a debugger; read a key file that is not protected from them; and connect to any socket their uid may open. The uid a kernel credential reports is that of the process that connected (S01, S05), whichever process holds the descriptor now, and on macOS the reported pid follows the process that wrote last (M10): a kernel credential proves who connected, not who writes now.
- **Root or administrator.** A process running as root, or with administrator or LocalSystem rights on Windows (which the default named-pipe security descriptor grants full control, W02), is inside the trust boundary. Nothing in this profile constrains it.
- **Container escape.** A process that leaves its container or its user namespace is outside what a uid comparison inside one namespace can see (section 4.1).
- **Confidentiality.** Local channels are not encrypted. §19: "PACT signatures provide integrity and attribution, not confidentiality."

### 3.3 Claim wording rule

A claim over `launcher` assurance says: "enforced for requests arriving through the declared launch path; same-user processes are inside the trust boundary". Its bypass table (TEMPLATE section 5) lists direct execution of the protected server by any process of the same operating-system user as `out-of-claim`, unless a separation by uid or by sandbox closes the path; TEMPLATE section 5 states the evidence each disposition needs.

### 3.4 Enforced mode at `launcher` assurance

A request that arrives on a `launcher` channel MAY be admitted in `enforced` mode only when the gateway itself is the launcher: the gateway created the pipes and spawned the process at the other end. That gateway knows the process from its own trusted configuration (§4.2): the program it executed and the uid it ran it under. `authenticate_native` (§17.1) returns that configured workload, which is the trusted local workload identity that §13.3 requires a local adapter to bind to. A claim of `enforced` mode on such a channel MUST carry the wording of section 3.3.

Every other `launcher` channel is `observe` only. On such a channel, for example when the gateway is the child of the process that spawned it, the gateway holds no identity for the other end beyond its parent's pid (section 2.4) and cannot authenticate the principal, so it cannot claim enforced support (§4.4). Its records declare observation mode (§4.4), and the deployment discloses that native access is not conditioned on PACT admission (§22.1).

## 4. Platform notes

### 4.1 Containers and user namespaces

A peer uid is meaningful only inside one user namespace. A uid comparison of section 2.3 is valid only when the gateway and the peer run in the same user namespace. Credentials passed over a Unix domain socket into another user namespace are translated, and a uid without a mapping becomes the overflow uid, 65534 by default (L06); rule 5 of section 2.3 rejects it. Whether `SO_PEERCRED` values are translated in the same way is `to probe` (L06), and so is the uid a gateway sees for a socket shared into a container by a bind mount.

### 4.2 WSL

Named pipes and sockets that cross the boundary between WSL and Windows are excluded (section 1.2, W09). A channel wholly inside one WSL distribution is a Linux channel.

### 4.3 Descriptor and handle inheritance

Every descriptor of the parent other than the channel ends it hands to the child MUST be close-on-exec, so that a spawned child inherits only its channel. A parent MUST NOT let its channel descriptors leak into any other child. On Windows, the parent limits inheritance to the handles of the channel; the API for that is `to probe` (W10).

### 4.4 Socket directory rules

A gateway that listens on a `uds` channel:

- creates the socket in a private directory of mode 0700, owned by the gateway's uid;
- refuses a socket path with a symbolic link in any component, and a directory whose parent other uids can write;
- before it binds, treats a socket file already at the path as stale only if it is a socket owned by the gateway's uid in that directory and no listener accepts a connection on it, and only then removes it; otherwise it does not start.

The socket file mode is not a control on its own: a socket created under umask 022 has mode `srwxr-xr-x` (M08); Linux checks write permission on the socket file for `connect` (L05) and macOS did for its owner (M09), but "on some systems (e.g., older BSDs), the socket permissions are ignored" (L05). The private directory and the peer credential check of section 2.3 are the controls.

### 4.5 Windows named-pipe rules

A gateway that listens on a `named-pipe` channel:

- MUST create every pipe instance with `PIPE_REJECT_REMOTE_CLIENTS`. Without it the pipe accepts remote clients (W01), is reachable over a network, and is not eligible for this profile (section 1.2).
- MUST create the pipe with an explicit security descriptor that grants access only to the gateway and to the client identities trusted configuration expects. The default security descriptor also grants read access to Everyone and to the anonymous account (W02).
- SHOULD expect clients to open the pipe with `SECURITY_SQOS_PRESENT` and `SECURITY_IDENTIFICATION` (W04), so that the gateway can read the client's identity without acting as the client. Reading the user SID at that level is `to probe` (W06).

Whether `FILE_FLAG_FIRST_PIPE_INSTANCE` lets a gateway detect a pipe name already created by another process is `to probe` (W07).

## 5. Residual limits and unsupported claims

### 5.1 Residual limits

| ID | Limit | Effect on a claim |
|---|---|---|
| R1 | Processes of the same operating-system user are inside the trust boundary (section 3.2). | A claim excludes them, or closes the path by uid or sandbox separation with evidence (TEMPLATE section 5). |
| R2 | Root, administrator, and LocalSystem are inside the trust boundary. | No claim covers them. |
| R3 | The channel does not identify the program at the other end; process ids are audit data only. | No claim names the program at the other end. |
| R4 | Kernel credentials describe the process that connected, not the process that holds the descriptor now. | A claim at `kernel-peer` assurance covers the connecting identity only. |
| R5 | Local channels carry no encryption. | No confidentiality claim. |
| R6 | At `launcher` assurance the child cannot verify its parent beyond its own uid and the parent's pid. | Only a gateway that is the launcher may claim `enforced` mode, with the wording of section 3.3; every other `launcher` channel is `observe` only (section 3.4). |
| R7 | The Linux rows are documented but not probed, and the Windows identity read is not established (L01, L02, L08, W06). | The probe record lists what remains to run. |
| R8 | Translation of peer credentials across user namespaces is not established for `SO_PEERCRED` (L06). | Uid comparisons across user namespaces are unsupported. |
| R9 | Socket file permissions are not portable (L05). | No control relies on the socket file mode alone. |

### 5.2 Unsupported claims

A claim over this profile does not state, and its reader does not infer:

1. that the peer is a particular program or binary;
2. enforcement against processes of the same operating-system user, unless a uid or sandbox separation closes the path, with the evidence TEMPLATE section 5 requires;
3. protection against root, administrator, or LocalSystem;
4. confidentiality of the messages on the channel;
5. that the channel identity replaces the holder-key proof of §6.2, or any other requirement that §13.3.1 does not let a transport profile waive;
6. `stdio-ipc` over any channel that section 1.2 excludes;
7. `kernel-peer` assurance over `named-pipe`, until row W06 of the probe record is `verified`;
8. `enforced` mode on a `launcher` channel whose launcher is not the gateway (section 3.4);
9. uid comparisons across user namespaces.
