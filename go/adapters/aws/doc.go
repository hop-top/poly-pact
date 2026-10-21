// Package aws is the AWS adapter of the integration profile spec/v1.0/profiles/aws:
// the seven functions of draft 17.1 for a custom API served by Amazon API
// Gateway as an HTTP API, whose routes use IAM authorization and a Lambda
// proxy integration at payload format version 2.0, and whose integration
// function hosts the adapter and the in-gateway validator (integration
// sample I09). The event types are defined here by hand: the package uses the
// standard library and the packages of this module, and neither an AWS SDK
// nor the AWS Lambda library.
//
// The integration function decodes nothing itself. It hands each raw event
// to [Invocation], or attaches it to a request with [WithEvent], and passes
// that request to the adapter's functions, which read the event and nothing
// else of the request. An adapter serves one API and is built with [New]
// from a [Config]: the gateway's realm, the account and partition, the origin
// whose host is the API's custom domain, the role table ([RoleTable]), the
// configuration check ([ConfigurationCheck]), the declared execution role
// and its [Executor] source, and the deployment-supplied parts of package
// installed.
//
// # What it does
//
//   - AuthenticateNative: the caller from requestContext.authorizer.iam only
//     (profile AR-5, AR-6): an assumed-role session of the configured
//     partition whose account is the API's, whose role is found in the role
//     table by its unique ID and has the name of the session ARN, and whose
//     session name meets the AssumeRole pattern and the entry's rule
//     (AR-7 to AR-10). The identifier aws:{account}:{role-arn}:unreported
//     ([WorkloadID]) is the principal and the workload (AR-9, AR-11). No
//     request is served unless the last configuration check passed within
//     the interval P (AR-3).
//   - MapOperation: the event shape of AR-13, then the baseline HTTP mapping
//     of package binding over [FromEvent]: target_uri from the configured
//     origin, rawPath and rawQueryString octet for octet, never from the
//     decoded parameter maps (AR-14 to AR-19).
//   - ResolveAgentBinding: the enrollment registry, through [enroll.Resolver],
//     one enrollment per role (AR-12).
//   - ReadNativeClaim: the paths of AR-25 from the authenticated principal,
//     with no observation time and the status time timeEpoch minus L; other
//     approved paths from the sources the deployment installs.
//   - CheckContext: the installed check execution-identity-v1 (AR-22) and
//     the checks the deployment installs.
//   - AuthorizeNative, RecordOutcome: the deployment-supplied parts of
//     package installed; the business handler's permission check decides for
//     the original principal (AR-21).
//
// The adapter never reads the wall clock: [Config.Clock] is its only source
// of the current time.
//
// # Sources
//
// Read on 2026-10-18, as the profile's sources A1 to A24 were read for it on
// 2026-10-16:
//
//   - Amazon API Gateway Developer Guide, "Create AWS Lambda proxy
//     integrations for HTTP APIs",
//     https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html:
//     the members of the 2.0 event, lowercase header names, duplicate
//     headers and query strings combined with commas, the cookies member,
//     and rawPath without the API mapping value. The page shows a JWT
//     authorizer and no IAM context, and it states nothing about how
//     rawPath and rawQueryString encode the request-target: that they carry
//     it unchanged is to be probed (profile probe P2), and the enforced claim
//     holds only where the probe passed (AR-15).
//   - AWS Lambda library for Go, test event
//     events/testdata/apigw-v2-request-iam.json, branch main,
//     https://github.com/aws/aws-lambda-go/blob/main/events/testdata/apigw-v2-request-iam.json:
//     the member names under requestContext.authorizer.iam (accessKey,
//     accountId, callerId, cognitoIdentity, principalOrgId, userArn, userId).
//     It is library source, not documentation; in it the
//     {role-id}:{session-name} form is the value of callerId, while the
//     profile (AR-8) reads it from userId, which fails closed until probe P1
//     settles which member carries it.
//   - Amazon API Gateway Developer Guide, "Create routes for HTTP APIs",
//     https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-routes.html:
//     route keys, the decoding of URL-encoded request parameters, and route
//     selection by the most specific match.
//   - IAM User Guide, "IAM identifiers",
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html:
//     the role, assumed-role, user, root and federated-user ARN forms and
//     the AROA prefix of role unique IDs.
//   - IAM User Guide, "IAM policy elements: Variables and tags",
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable:
//     aws:userid of an assumed role is {role-id}:{caller-specified-role-name}.
//   - AWS STS API Reference, "AssumeRole",
//     https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html:
//     RoleSessionName has 2 to 64 characters of [\w+=,.@-].
//   - IAM User Guide, "Authentication methods",
//     https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-authentication-methods.html:
//     the query-string parameters of Signature Version 4.
package aws
