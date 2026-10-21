// Package graph is the adapter of the integration profile "Microsoft Graph
// delegated and application execution" (spec/v1.0/profiles/graph): a mail gateway
// whose admitted reads are executed by one call to Microsoft Graph "List
// messages", in one of two forms, each its own adapter entry:
//
//   - Form D (graph-delegated-obo, rows GD1 and GD2): the gateway application
//     exchanges the request's token A for token B by the on-behalf-of (OBO)
//     flow and reads /v1.0/me/messages for the signed-in user.
//   - Form A (graph-app-only, rows GA1 and GA2): the executor application of
//     the workload obtains an app-only token by the client credentials grant
//     and reads /v1.0/users/{registered-mailbox}/messages, only while the
//     grant preflight of the executor application passes.
//
// It uses the standard library and the packages of this module only. Token
// requests are form POSTs made here rather than through the Microsoft
// Authentication Library; [TokenAcquirer] is the boundary that keeps such a
// library swappable. An adapter is built with exactly one acquirer
// ([OnBehalfOf] in form D, [ClientCredentials] in form A): the configuration
// has no field for a second credential, so an executor has nothing to fall
// back to (GR-11). The client assertion of a certificate credential is signed
// here with crypto/rsa; package hop.top/pact-go/core/jws, which signs and
// verifies PACT artifacts, is not widened.
//
// # What the adapter does
//
//   - MapOperation: GD1 and GA1 with exactly $select=id,subject,body&$top=10
//     (GR-23), GD2 and GA2 with exactly one page_token whose continuation
//     record is of the principal, a row of the form and the version, and
//     holds a link of Graph's origin, the row's path and the pinned options
//     (GR-24, RB-58). The resource is the user's mailbox in form D and the
//     registered mailbox of the workload's executor binding in form A. No
//     token is requested and Graph is not called.
//   - CheckContext: execution-identity-v1 over the executor registry and, in
//     form A, the latest preflight (GR-21, GR-26); the other checks, among
//     them native-delegation-v1 over the deployment's task registry, are the
//     deployment's.
//   - ReadNativeClaim: /graph/execution_app_id in form A (GR-32).
//   - AuthenticateNative, ResolveAgentBinding, AuthorizeNative: the
//     authenticating profile's inbound authentication (form E of package
//     oauth in form D), the enrollment registry and the gateway's policy.
//   - RecordOutcome: signed reports; [OutcomeOf] gives the fields of an
//     execution (GR-29, GR-30).
//   - [Adapter.Execute]: maps the request again and requires the admitted
//     operation, requires execution-identity-v1, in form D authenticates the
//     request again so that token A is the operation's own, obtains token B,
//     sends the one downstream request with only the executor's
//     Authorization, records a returned @odata.nextLink (RB-57), and returns
//     the page. Nothing is retried; [StatusOf] gives the gateway's answer.
//     With a task ledger ([Config].Tasks, spec/v1.0/profiles/multi-operation.md)
//     each page is first reserved against the budget of its native task
//     ([ListingRoute]); the answer is read only up to the remaining
//     max_bytes; a next link is bound to the native task through the
//     ledger, whose pager is [NewPager] of the form; and a failed token
//     request releases the reservation (MO-21, MO-22, MO-55, MO-56).
//   - [Adapter.RunPreflight]: step 1 reads the executor application's app
//     role assignments under the auditor's token and requires each to be in
//     the allowlist; step 2 reads the operator's attestation of
//     Test-ServicePrincipalAuthorization; the result is held with the settle
//     window W and the interval P (GR-18 to GR-21). A deployment runs it
//     every P.
//
// # Microsoft facts
//
// From Microsoft Learn, read on 2026-10-18; the labels are those of the
// profile's Sources section, M12 and M13 added here:
//
//   - OBO request: POST to https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
//     with grant_type "urn:ietf:params:oauth:grant-type:jwt-bearer",
//     client_id, client_secret or client_assertion_type
//     "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" and
//     client_assertion, assertion "must have an audience (aud) claim of the
//     app making this OBO request", scope, and requested_token_use
//     "on_behalf_of"; the response has token_type, scope ("The scope of
//     access granted in the token"), expires_in and access_token; the refresh
//     token "is only provided if the offline_access scope was requested"; on a
//     Conditional Access requirement the endpoint answers error
//     "interaction_required" with a claims member, and "the middle-tier
//     service replies with HTTP 401 Unauthorized and with a WWW-Authenticate
//     HTTP header containing the error and the claim challenge"
//     [M1, https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-on-behalf-of-flow].
//   - Client credentials: grant_type "client_credentials", scope
//     https://graph.microsoft.com/.default, client_secret or a certificate
//     assertion; the success example carries token_type, expires_in and
//     access_token and no scope; "The only type that the Microsoft identity
//     platform supports is bearer", while the example shows "Bearer"; refresh
//     tokens "will never be granted with this flow"
//     [M2, https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow].
//   - Certificate assertion: header alg "Should be PS256", typ JWT and
//     x5t#S256, the "Base64url-encoded SHA-256 thumbprint of the X.509
//     certificate's DER encoding"; claims aud the tenant's token endpoint, iss
//     and sub the client ID, a jti, nbf, iat and exp "5-10 minutes after nbf
//     at most"; "Use PSS padding"
//     [M12, https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials].
//     The assertion therefore uses PS256.
//   - Error codes: the error member invalid_grant ("Some of the
//     authentication material ... was invalid ... or otherwise unusable"),
//     interaction_required ("The request requires user interaction"),
//     invalid_client, temporarily_unavailable; AADSTS65001 DelegationDoesNotExist
//     ("The user or administrator hasn't consented to use the application"),
//     AADSTS50057 UserDisabled, AADSTS50076 and AADSTS50079 (multifactor
//     authentication); and "Apps that take a dependency on text or error code
//     numbers will be broken over time"
//     [M13, https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes].
//     The adapter therefore branches on the error member only: interaction
//     required, or a claims value, is [*InteractionRequired]; every other
//     4xx is a native denial; 5xx and an unreachable endpoint are a
//     dependency error. No error is followed by another credential.
//   - Claims challenge: "Bearer realm=..., authorization_uri=...,
//     error="insufficient_claims", claims=..." with claims "a base 64
//     encoded claims request"; with a tenant realm the authorization_uri
//     includes the tenant; Graph sends claims challenges only to clients that
//     declare the cp1 capability [M11, https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge].
//   - appRoleAssignments: GET /servicePrincipals(appId='{appId}')/appRoleAssignments,
//     least privileged permission Application.Read.All; the example response
//     has @odata.context and value items with id, createdDateTime, appRoleId,
//     principalDisplayName, principalId, principalType, resourceDisplayName
//     and resourceId; "This request might have replication delays"
//     [M7, https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0].
//     Step 1 reads appRoleId and resourceId and follows @odata.nextLink,
//     "Use the entire URL", until none is returned
//     [M6, https://learn.microsoft.com/en-us/graph/paging].
//   - Test-ServicePrincipalAuthorization is a cmdlet "available only in the
//     cloud-based service", with -Identity and -Resource; its examples print
//     RoleName, GrantedPermissions, AllowedResourceScope, ScopeType (values
//     CustomRecipientScope, AdministrativeUnit, Organization) and InScope
//     (True, False, Not Run)
//     [M9, https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/test-serviceprincipalauthorization].
//     No REST form was found, so step 2 reads an attestation the operator
//     records ([RBACAttestation], [AttestationFile]); an attestation older
//     than P, or for another application or mailbox, leaves the run not
//     completed.
//   - List messages: GET /me/messages and /users/{id | userPrincipalName}/messages;
//     "apply the entire URL returned in @odata.nextLink"; the default page is
//     10 messages and $top ranges from 1 to 1000
//     [M5, https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0].
//   - Throttling: HTTP 429 with Retry-After, and "all requests accrue against
//     your usage limits" [M10, https://learn.microsoft.com/en-us/graph/throttling].
//
// # Probes
//
// None of the profile's probes P1 to P9 was run: they need a test tenant, and
// the tests never call a Microsoft endpoint. The unit tier runs against an
// in-process token endpoint and Graph over TLS. The consent-loss probe P2 is
// answered from M13 only as far as the codes go (AADSTS65001 with
// invalid_grant is the documented consent error); the adapter does not depend
// on it. The appRoleAssignments shape is that of the M7 example. P1 (the
// next link's path and encoding) and P3 (the spelling of Mail.Read in the OBO
// scope; accepted spellings are [AcquirerConfig.AcceptedScopes]) stay open
// and fail closed.
package graph
