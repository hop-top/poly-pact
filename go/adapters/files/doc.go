// Package files is the file broker adapter of the integration profile
// spec/v1.0/profiles/files (Windows local NTFS): a PACT-aware broker that serves
// route R1, GET /files/{file_id}/content, by opening one registered local
// file under the requesting user's impersonated security context.
//
// The broker reaches Windows through three seams, so that its rules run and
// are tested on every platform:
//
//   - SecurityPackage: the server side of the Negotiate exchange of a
//     connection (profile 3.1);
//   - Impersonator: the impersonation of the calling operating-system thread
//     (profile 3.5);
//   - FileSystem: the open of a path as the calling thread's identity, and
//     what the handle reports (profile 3.2, 3.3).
//
// On Windows, [NewSSPI], [ThreadImpersonator] and [NTFS] implement them with
// golang.org/x/sys/windows, in the files that build for windows only.
//
// # Functions
//
//   - AuthenticateNative: the Negotiate exchange of the request's connection
//     decides; identity headers are never read. The principal and the
//     workload are files:{domain-sid}:{user-sid} of the token's user, and
//     AuthenticatedAt is the instant the final leg returned. A context older
//     than Config.ContextMaxAge is discarded (IA-9).
//   - ResolveAgentBinding: the enrollment registry, with the agent ID
//     selecting the record on the user's account, which every agent acting
//     for the user shares (profile section 7).
//   - MapOperation: revision pact-files-1 maps R1 and nothing else: another
//     method, path or a query violates the mapping, INVALID_MESSAGE.
//   - ReadNativeClaim: the user and the enabled groups of the token of the
//     completed exchange, with its completion instant as observation and
//     status time (F2); other approved paths from the deployment's sources.
//   - CheckContext: execution-identity-v1 enters the impersonation window
//     and compares the effective identity with the principal, opening
//     nothing; other checks are the deployment's.
//   - AuthorizeNative: the open under the impersonation token is the
//     decision. The handle is verified (reparse attribute, directory,
//     offline or not present data, volume serial number and file identifier,
//     final path) before it is kept, under the request's HandleKey, for
//     Execute. A denial is a DENY of the open's source.
//   - RecordOutcome: outcome reports signed by the broker, which observes the
//     reads it serves when Config.ExecutionVisible says so.
//
// Execute reads the contents of a kept handle once, for the exact tuple of
// task, operation, principal and agent that opened it; EndTask and the
// handle lifetime close handles (profile 3.4). A failed revert marks the
// broker unhealthy: every later protected operation is refused and
// Config.OnUnhealthy tells the supervisor, which terminates the process
// (TA-6).
//
// # The impersonation window
//
// The window runs on a goroutine of its own, locked with
// runtime.LockOSThread before the impersonation begins and unlocked only
// after a successful revert, so a thread whose revert failed ends with its
// goroutine. The window runs the open and the handle queries and nothing
// else, and starts no goroutine (TA-1, TA-2). A failed entry opens nothing
// and is not reverted, since the SetThreadToken page asks that the
// assignment succeed before RevertToSelf is called.
//
// # Probes
//
// golang.org/x/sys v0.49.0, the version go.mod pins, was read for the
// functions the profile names:
//
//   - Exported: SetThreadToken, RevertToSelf, OpenThreadToken,
//     GetTokenInformation and the Token methods for its user and groups,
//     CreateFile, GetFileInformationByHandleEx, GetFinalPathNameByHandle,
//     the classes FileAttributeTagInfo and FileIdInfo, and the constants of
//     the file flags, attributes and access rights the broker uses.
//   - Not exported: AcquireCredentialsHandleW, AcceptSecurityContext,
//     QuerySecurityContextToken, DeleteSecurityContext,
//     FreeCredentialsHandle, InitializeSecurityContextW and
//     ImpersonateSecurityContext (of secur32.dll the package declares only
//     GetUserNameExW and TranslateNameW), LogonUserW, and the
//     FILE_ID_INFO, FILE_ATTRIBUTE_TAG_INFO and TOKEN_STATISTICS structures.
//     The broker declares the secur32.dll functions with
//     windows.NewLazySystemDLL and the structures member for member as
//     their pages declare them. It assigns the token of
//     QuerySecurityContextToken to the thread with SetThreadToken instead of
//     calling ImpersonateSecurityContext (profile TA-7).
//
// To probe in the Windows job, where no page read states them: the values
// SECBUFFER_VERSION (0) and SECURITY_NATIVE_DREP (0x10), the output token
// size, the package name "Negotiate", the logon values of the test tier,
// that OpenThreadToken fails with ERROR_NO_TOKEN on a thread that is not
// impersonating, and the profile's open items OI-1 to OI-11.
//
// # Sources
//
// Microsoft Learn pages read for this package: AcceptSecurityContext,
// AcquireCredentialsHandleW, QuerySecurityContextToken,
// DeleteSecurityContext, FreeCredentialsHandle, InitializeSecurityContextW,
// SecBuffer, SecBufferDesc, SetThreadToken, RevertToSelf, OpenThreadToken,
// TOKEN_STATISTICS, TOKEN_GROUPS, SECURITY_IMPERSONATION_LEVEL, Impersonation
// Levels, LogonUserW, CreateFileW, GetFinalPathNameByHandleW,
// GetFileInformationByHandleEx, FILE_ID_INFO, FILE_ATTRIBUTE_TAG_INFO and
// File Attribute Constants, under
// https://learn.microsoft.com/en-us/windows/win32/; and RFC 4559 for the
// Negotiate header.
package files
