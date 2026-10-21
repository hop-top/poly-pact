# Source of `sample-v2-iam.json`

`sample-v2-iam.json` is a payload format version 2.0 event that Amazon API
Gateway would pass to the Lambda integration of the reference route R1 of the
[AWS profile](../../../../profiles/aws/profile.md), `GET /metrics/operations`,
for a caller signed in as a session of the role `metrics-reader`. Every value
is fictitious: the account `111122223333`, the API id, the custom domain
`api.metrics.example`, the role unique ID, the access key ID and the session
name are the fixture's own.

Its structure is taken from two sources, read on 2026-10-18:

| Part | Source |
|---|---|
| Every member outside `requestContext.authorizer`: `version`, `routeKey`, `rawPath`, `rawQueryString`, `cookies`, `headers` with lowercase names, `queryStringParameters`, `requestContext` with `accountId`, `apiId`, `domainName`, `domainPrefix`, `http` (`method`, `path`, `protocol`, `sourceIp`, `userAgent`), `requestId`, `routeKey`, `stage`, `time` and `timeEpoch`, and `isBase64Encoded` | The 2.0 example of the section "Payload format structure" of the Amazon API Gateway Developer Guide page [Create AWS Lambda proxy integrations for HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html) (profile source A1) |
| The member names under `requestContext.authorizer.iam`: `accessKey`, `accountId`, `callerId`, `cognitoIdentity`, `principalOrgId`, `userArn`, `userId` | The test event [`events/testdata/apigw-v2-request-iam.json`](https://github.com/aws/aws-lambda-go/blob/main/events/testdata/apigw-v2-request-iam.json) of the AWS Lambda library for Go, branch `main` (profile source A23). It is library source, not documentation |

The documentation example shows a JWT authorizer (`requestContext.authorizer.jwt`)
and no IAM context, so the IAM member names rest on the library test event
alone, and the event of a deployed API is *to probe* (profile probe P1). The
value forms follow the profile: `userArn` is the assumed-role session ARN
`arn:aws:sts::{account}:assumed-role/{role-name}/{role-session-name}` of the
IAM User Guide page [IAM identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)
(A13), and `userId` is `{role-id}:{caller-specified-role-name}`, the form of
`aws:userid` for an assumed role on the page
[IAM policy elements: Variables and tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable)
(A14), which profile rule AR-8 reads from `userId`. In the library test event
that form is the value of `callerId`, and `userId` holds a role unique ID
alone; which member carries it in a deployed API is part of probe P1.

The sample leaves out four members of the documentation example: `body`,
because R1 accepts none; `pathParameters`, because R1 has no path variable;
`stageVariables`, because the profile defines none; and
`requestContext.authentication`, which carries a client certificate of mutual
TLS that the profile does not use. The harness of the AWS cases builds every
event from this sample ([`../README.md`](../README.md), "Events").
