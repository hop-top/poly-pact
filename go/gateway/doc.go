// Package gateway is PACT admission as net/http middleware: the in-gateway
// deployment form of draft Section 4.4, which evaluates PACT and native
// policy in the gateway's own request path.
//
// [New] returns a func(http.Handler) http.Handler that wraps the protected
// application. It serves the requirements endpoint and gives every other
// request the class of its route (Config.Routes, net/http ServeMux
// patterns; a request no pattern matches is enforced):
//
//   - [ClassOff]: PACT does not apply.
//   - [ClassObserve]: a presented request is evaluated and its receipt
//     recorded, in observation mode, and the request then goes to the
//     application unchanged, whatever the evaluation decided or whether it
//     could run at all (draft 2.3, 4.4).
//   - [ClassEnforce]: the request reaches the application only when native
//     authentication, PACT admission and native authorization all hold
//     (draft 2.3).
//
// # Requirements
//
// POST /pact/v0.1/requirements takes a natively authenticated
// ContractRequest and answers with a signed contract, application/jose
// (draft 9.1, 13.2). The gateway authenticates the request and resolves the
// binding of the agent and key it names through the adapter (draft 17.1),
// applies the installed mapping to the proposed operation, which must yield
// its method, target, action, resources, principal, environment and headers
// (request binding RB-42), takes the effective requirements from
// Config.Requirements in the mode of the proposed operation's route, and
// issues through the Publisher, which registers the nonce. It records the
// installed mapping version (RB-42) and the operation_id the request
// proposed (draft 10.2) with the contract before it returns the contract; a
// contract it cannot record is not returned.
//
// # Enforcing
//
// For a request of an enforce route the gateway, in this order:
//
//  1. authenticates it through the adapter (authenticate_native, draft
//     17.1); a native denial is INVALID_PROOF;
//  2. takes the one PACT-Presentation field (draft 13.2); none is
//     INVALID_PROOF, the request carries no holder proof;
//  3. checks that the mapping version recorded with the embedded contract is
//     the installed one (RB-43): another version, or none, is
//     REQUIREMENTS_CHANGED;
//  4. binds the request through the adapter's map_operation, the baseline
//     HTTP mapping of package hop.top/pact-go/core/binding for the reference
//     adapters: the exact request bytes, with every refusal of the request
//     binding profile (INVALID_MESSAGE). The body the application reads is
//     the bytes that were bound; the gateway never re-encodes the request.
//     The operation_id of the bound operation is the one recorded with the
//     contract, never the one map_operation returns (draft 10.2);
//  5. evaluates the presentation for that operation and principal with the
//     validator of package hop.top/pact-go/validator, which records the
//     receipt durably before it returns it (draft 11.3, 12.2);
//  6. requires an ADMISSIBLE receipt in enforced mode;
//  7. asks native authorization (authorize_native); a denial always wins
//     (draft 2.3) and is answered by Config.NativeDenial, and an unknown or
//     failed decision is DEPENDENCY_UNAVAILABLE;
//  8. calls the application with the [Admission] in the request context,
//     where [FromContext] reads it, and without the PACT-Presentation field
//     (request binding RB-51). The principal is never put in a header.
//
// The response carries the compact receipt in PACT-Admission when it fits
// Config.AdmissionHeaderBytes (draft 13.2). A refused request gets an RFC
// 9457 problem with the HTTP status of the draft 13.4 table and a fresh
// request_id; a refusal after an evaluation names the decision and the
// receipt's jti in its extensions.
//
// # Failing closed
//
// A store that cannot answer, a replay store, receipt store, hold store,
// policy registry or contract record store, never yields an admission: the
// validator defers, a receipt that cannot be recorded is never positive, and
// the gateway answers DEPENDENCY_UNAVAILABLE (draft 12.2, 18). An error that
// carries no code of the draft 13.4 table is treated the same way.
//
// # Stores
//
// Every store is an interface: [ContractRecords] here, and the stores of
// packages hop.top/pact-go/contract and hop.top/pact-go/validator. Replicas share
// one of each. [MemoryRecords], [MemoryHolds], [StaticPolicy] and
// [MemoryStatus], with contract.MemoryReplay and validator.MemoryReceipts,
// are the in-memory implementations for one process. Keys stay behind the
// contract.Signer, validator.Signer and holder key interfaces.
//
// The package is standard library and hop.top/pact-go packages only.
package gateway
