// Package azurerm is a minimal executor of one Azure Resource Manager
// operation, the restart of one virtual machine (sample I14), under the task
// ledger of the multi-operation profile (spec/v1.0/profiles/multi-operation.md).
// It uses the standard library and the packages of this module only; it
// does not use an Azure SDK.
//
// # What the executor does
//
// [Executor.Restart] runs one admitted restart:
//
//  1. It requires the activation gate to PASS. The gate is an interface: the
//     approval-class check of the activation (draft Section 17.3.1) is the
//     deployment's installed check and is not implemented here. A gate that
//     is not PASS reserves nothing and sends nothing (MO-10).
//  2. It reserves the restart in the task ledger as a ledger-deduplicated
//     write (profile section 6.1): the ledger sends at most one request per
//     logical operation (MO-33). A repeat is answered from the record and
//     sends nothing (MO-31): operation-in-flight while it is Reserved or
//     Accepted, outcome-unknown while it is Unknown.
//  3. It obtains a token on behalf of the user through [graph.TokenAcquirer]
//     with the scope [ScopeARMDefault]. A failed token request releases the
//     reservation (MO-22).
//  4. It sends POST {vm-resource-id}/restart?api-version=2025-04-01 once
//     and records how the attempt ended: 200 is Succeeded; 202 is Accepted
//     with the handle (MO-41, MO-42); a status the route lists as definitive
//     is Failed (MO-37); every other status, a timeout, a connection closed
//     after the request was written, or an answer that cannot be read is
//     Unknown (MO-35). Nothing is retried: the outcome stays UNKNOWN until a
//     terminal status is read, and no second POST is sent for an ambiguous
//     restart (draft Section 10.3; MO-32, MO-33).
//
// [Executor.Track] reads the status of an accepted restart through its
// handle, under the user's delegated token (MO-48), waiting the Retry-After
// the native API gave or the configured minimum interval (MO-45), bounded by
// max_status_reads. A handle is followed only when its origin and path
// prefix are configured (MO-43). A status read that the principal is not
// permitted to make, or that fails, leaves the record Accepted and reports
// DEPENDENCY_UNAVAILABLE; no success is inferred (MO-46). An ambiguous
// restart is reconciled only through the deployment's native status source
// ([Config].Reconcile, MO-38, MO-40); without one it stays Unknown (MO-39).
//
// # Azure facts
//
// From Microsoft Learn, read on 2026-10-20:
//
//   - [S2] "Status of asynchronous operations",
//     https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/async-operations:
//     an asynchronous operation initially returns 201 or 202; the client
//     looks first for Azure-AsyncOperation ("If your operation returns this
//     value, use it to track the status of the operation") and uses
//     Location "only when Azure-AsyncOperation isn't returned"; Retry-After
//     is "the number of seconds to wait before checking the status"; a GET
//     of the Azure-AsyncOperation URL returns an object that always includes
//     status, with "Succeeded | Failed | Canceled | {resource provider
//     values}", and the error object "when the status is Failed or
//     Canceled"; the start example shows the status InProgress; for a
//     Location URL "If the request is still running, you receive a status
//     code 202. If the request is completed, you receive a status code 200"
//     (an example for a storage account, not for compute); provisioningState
//     is the value of operations that "create, update, or delete (PUT,
//     PATCH, DELETE) a resource", so the executor does not read it as the
//     completion of a restart (MO-44); tracking needs "sufficient permission
//     at the resource group level", and "If you only have permission at the
//     resource level, you can start the operation but you can't track its
//     status"; the URL tracking a compute start is
//     https://management.azure.com/subscriptions/{subscription-id}/providers/Microsoft.Compute/locations/{region}/operations/{operation-id}.
//   - [S3] "Virtual Machines - Restart", API version 2025-04-01,
//     https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/restart?view=rest-compute-2025-04-01:
//     POST https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/restart?api-version=2025-04-01;
//     responses 200 OK ("The request has succeeded"), 202 Accepted with the
//     headers Location (string) and Retry-After (integer), and "Other Status
//     Codes", CloudError "An unexpected error response"; Azure Active
//     Directory OAuth2 with the scope user_impersonation. The page lists no
//     Azure-AsyncOperation header for the restart and documents no status
//     as rejected before any effect, so the default route lists no
//     definitive status.
//
// From RFC 9110, read on 2026-10-20: 202 "has been accepted for processing,
// but the processing has not been completed" and is "intentionally
// noncommittal" (Section 15.3.3); Retry-After is "HTTP-date /
// delay-seconds", delay-seconds a non-negative decimal integer (Section
// 10.2.3); a client "SHOULD NOT automatically retry a request with a
// non-idempotent method unless it has some means to know that the request
// semantics are actually idempotent ... or some means to detect that the
// original request was never applied" (Section 9.2.2).
//
// From the Go documentation of net/http.Transport (go doc, Go 1.26): the
// Transport retries a request on a network error only when the request is
// idempotent, and a request is idempotent for it with the methods GET, HEAD,
// OPTIONS or TRACE or with an Idempotency-Key or X-Idempotency-Key header.
// The restart POST carries neither header, so the default transport does not
// send it twice.
//
// # Interpretations and open items
//
// A status read is interpreted by the shape of its answer, whichever header
// gave the handle: 202 is running; 200 with a status member is the
// operation status object of [S2]; 200 without one establishes nothing,
// because what a finished compute restart answers at its Location URL is
// not established by any source read (profile probe P3), so the record stays
// Accepted. Whether the restart response also carries Azure-AsyncOperation
// (probe P2), which read tells that a restart took effect when no 202 was
// received (P1), whether a running restart can be cancelled (P4), and what a
// resource-scoped principal reads at the handle (P6) are to probe; the
// executor fails closed on each.
package azurerm
