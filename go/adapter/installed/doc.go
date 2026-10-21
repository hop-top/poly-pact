// Package installed holds the deployment-supplied parts of an adapter that do
// not depend on how the request was authenticated: the sources of approved
// native paths ([ClaimSource]), the installed context checks
// ([InstalledCheck]), the route table of an installed operation mapping
// ([Route]), the native permission lookup ([PermissionLookup]), and the signer
// of outcome reports ([Reporting]).
//
// Draft 17.1 states the adapter functions as behavioral contracts that
// "existing gateway plugins, policy hooks, middleware, directory lookups, or
// native claims can satisfy". An adapter of one mechanism composes these parts
// with its own authentication and its own enrollment lookup; the functions
// here apply the rules every such composition keeps: source times are passed
// on as the source gives them and never later than now plus the baseline skew
// (draft A.2), a check that is not installed is UNKNOWN (draft 17.2), a native
// decision is returned unchanged with its provenance (draft 4.3, 17.1), and an
// outcome report never claims an execution the gateway does not observe (draft
// 14.5). Errors carry the sentinels of package adapter; the caller adds its
// own prefix.
package installed
