// Package rebac is the adapter of the integration profile "ReBAC with an
// OpenFGA relationship store" (spec/v1.0/profiles/rebac): authorize_native is one
// OpenFGA Check per protected operation, against a pinned store and model,
// sent over the HTTP API with the standard library only.
//
// # What the adapter does
//
//   - AuthorizeNative: refuses, with no Check, a principal or an operation of
//     another realm or environment, an operation context that its own method
//     and target do not map to under the pinned mapping revision (a context
//     bound to document.read for an edit), an action without a row in the
//     relation table, and a principal or a resource without a registry entry
//     in the realm. Otherwise it sends one Check to
//     POST /stores/{store_id}/check of the pinned store, with the pinned
//     authorization_model_id, consistency HIGHER_CONSISTENCY, the mapped
//     user:<subject id>, the relation of the action and the mapped object,
//     and nothing else: no contextual tuples, no context. A 200 answer with
//     one boolean allowed is the decision, returned as the store gave it;
//     400 and 404 are UNSUPPORTED_REQUIREMENT; any other outcome is
//     DEPENDENCY_UNAVAILABLE and never an allow. The decision names the
//     store as its source and the model as its policy revision; it carries
//     no obligation, no decision record and no decision time.
//   - MapOperation: the baseline HTTP mapping of package binding with the
//     route table of the installed revision; DocumentRoutes are routes R1
//     and R2 of the profile.
//   - AuthenticateNative: the deployment's identity mechanism, which
//     Config.Authenticator names; the store authenticates nobody.
//   - ResolveAgentBinding, ReadNativeClaim, CheckContext, RecordOutcome: the
//     deployment-supplied parts of package installed and the enrollment
//     registry of package enroll.
//
// The adapter keeps no cache of Check answers and never retries with a
// weaker consistency (profile RB-10, RB-13). It has no relationship write and
// no path to one (RB-16).
//
// # Upstream facts
//
// The Check request and response, the consistency values, the
// authorization_model_id rule and the status codes are those of the Check
// reference of the OpenFGA documentation
// (https://openfga.dev/docs/api/service/relationship-queries/check-user-authorization),
// the pre-shared key header that of
// https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga,
// both read on 2026-10-18; the profile cites them as [OF-2] and [OF-6].
//
// # Probes
//
// Observed on 2026-10-18 on OpenFGA v1.10.0 (image openfga/openfga:v1.10.0,
// in-memory datastore, pre-shared key), and recorded in section 14.3 of the
// profile:
//
//   - With the Check query and iterator caches enabled, a Check with
//     MINIMIZE_LATENCY or with no consistency after a tuple deletion answered
//     from the cache (allowed true); HIGHER_CONSISTENCY answered false.
//   - consistency "STRONG", not a value of the enum, was answered as the
//     default, from the cache; a number was 400 validation_error. The
//     preference is therefore the constant [HigherConsistency].
//   - An unknown model id was 400 authorization_model_not_found; an
//     undefined relation 400 validation_error; an unknown store 400
//     latest_authorization_model_not_found without a model id and 400
//     authorization_model_not_found with one; a store id that is not a ULID
//     400 validation_error; an undefined path 404 undefined_endpoint.
//   - A missing key was 401 bearer_token_missing, another key 401
//     unauthenticated.
//   - A well-formed answer was {"allowed":true,"resolution":""}; an unknown
//     member of the request was ignored.
//
// The integration tier (TestIntegration, PACT_TEST_OPENFGA_URL and
// PACT_TEST_OPENFGA_KEY) ran green against that server with its caches
// enabled.
package rebac
