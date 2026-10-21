# AWS adapter cases

These are the cases of the AWS adapter of the integration profile
[`profiles/aws`](../../../profiles/aws/profile.md): Amazon API Gateway HTTP API
routes with IAM authorization and a payload format 2.0 Lambda proxy
integration. They run after the common cases, with the case file format, the
outcomes and the checks of [`../README.md`](../README.md). The profile does not
support workloads shared by several agents, so a harness runs the `dedicated`
cases. Section 10 of the profile says which case group each file belongs to,
which planned behaviour is tested outside these files, and which common cases
the adapter replaces.

The adapter does not read an HTTP request. API Gateway authenticates and
authorizes the signed request and passes the Lambda function an event (profile
AR-5, AR-13); the adapter reads that event and nothing else. A case still
states its stimulus as the `request` of the case format: the harness turns the
request into the event that API Gateway would deliver for it, as "Events"
below defines, and a case changes that event where it needs to with the
`event` member of its native state. This settles open item O3 of the profile.

## Model `aws/1`

```
{
  "model": "aws/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "api": {"partition", "account_id", "api_id"},
  "propagation_bound_seconds": <seconds>,             // optional, default 60
  "check_interval_seconds": <seconds>,                // optional, default 300
  "configuration_check": {"completed_at", "passed", "findings": [...]},  // optional
  "roles": [{"account_id", "role_arn", "role_id",
             "session_name": {"rule", "value"}}],
  "sessions": [{"ref", "iam": {...}}],
  "mappings": [{"version", "routes": [{"method", "path", "action",
                                       "resource", "body"}]}],   // optional
  "event": {...},                                     // optional
  "execution": {"declared_role_arn", "running_role_arn"},        // optional
  "enrollments": [...],                               // optional
  "policy": [...],                                    // optional
  "unavailable_sources": [...]                        // optional
}
```

Times are Unix seconds.

- `gateway`: as in `common/1`. The origin's host is the configured custom
  domain name of the API (profile AR-1, AR-13).
- `api`: the configured partition, the account that owns the API and the
  integration function, and the API's id.
- `propagation_bound_seconds`: the declared IAM propagation bound `L` (profile
  section 8). An authenticated principal reports the status time
  `requestContext.timeEpoch`, in whole seconds, minus `L` (AR-25).
- `check_interval_seconds`: the interval `P` of the configuration check
  (AR-3).
- `configuration_check`: the last completed configuration check: when it
  completed, whether it passed, and the conditions of AR-3 that it found
  violated, such as `resource-policy-deny-missing` or `function-url-present`.
  Absent, no check has completed.
- `roles`: the role table (AR-8 to AR-10). `role_arn` is the role's ARN with
  its path and `role_id` its unique ID. `session_name.rule` is `any`, `exact`
  or `prefix`; `value` is the exact value or the prefix and is absent for
  `any`.
- `sessions`: what API Gateway reports for a caller it authenticated: `iam`
  is the object it puts in `requestContext.authorizer.iam`, written as the
  event carries it, so a case can state any member, including a malformed one.
- `mappings`: installed operation mappings, as in `common/1`. A route with
  `body` true accepts a request body; every other route refuses a non-empty
  body (request-binding RB-37). Absent, the mapping is the profile's, revision
  `pact-aws-1`: `GET /metrics/operations` maps to the action
  `metrics.operations.read` and the resource
  `https://metrics.example/operations`, with no body (profile section 2).
- `event`: a JSON merge patch (RFC 7396) that the harness applies to the event
  it built, last. A member set to `null` is removed.
- `execution`: the execution role the mapping declares for every row
  (`declared_role_arn`, AR-22) and the identity the function would run the
  operation under (`running_role_arn`), as the deployment's executor source
  reports it, with the source id `lambda-execution-context`. `null` or absent,
  the source cannot establish it. Absent as a whole, both are the declared
  role.
- `enrollments`, `policy`, `unavailable_sources`: as in `common/1`. The
  permission check of the business handler (AR-21) is `policy`. The role
  table is the source `role-table`, the configuration check the source
  `configuration-check`, and the executor source `lambda-execution-context`.

The installed check of the adapter is `execution-identity-v1` (draft 17.5,
profile AR-22): `PASS` with `REQUIREMENT_SATISFIED` when the running identity
is the declared execution role, `FAIL` with `EXECUTOR_MISMATCH` when it is any
other identity, and `UNKNOWN` with `DEPENDENCY_UNAVAILABLE` when the executor
source cannot establish it.

## Events

The harness builds the event of a request in this order.

1. It starts from [`events/sample-v2-iam.json`](events/sample-v2-iam.json),
   whose source [`events/SOURCE.md`](events/SOURCE.md) names, and removes
   `cookies`, `queryStringParameters`, `pathParameters`, `stageVariables`,
   `body`, `requestContext.authentication` and `requestContext.authorizer`.
2. From the request's `url`, the part after the authority is split at its
   first `?`: what precedes it is `rawPath` and `requestContext.http.path`, and
   what follows it is `rawQueryString`, empty when there is none. Both are the
   octets as written, so a `#` and an escape stay where they are.
3. `headers` holds every header of the request other than `Host` with its
   name in lowercase and its value as written, except `Cookie`, whose value
   becomes the one element of `cookies`. `requestContext.http.method` is the request's method.
4. With `body_b64`, `body` is that text and `isBase64Encoded` is `true`;
   without it, `body` is absent and `isBase64Encoded` is `false`.
5. `requestContext.accountId` and `apiId` are those of `api`;
   `requestContext.stage` is `$default`; `requestContext.domainName` is the
   host of the configured origin in lowercase, preceded by the userinfo of the
   request's `url` and `@` when the url has userinfo, and `domainPrefix` is its
   first label; `timeEpoch` is the case's `now` in milliseconds and `time` the
   same instant in the form of the sample.
6. `routeKey` and `requestContext.routeKey` are the method and path template
   of the first route of the installed mappings whose method equals the
   request's and whose template matches `rawPath`, a `{name}` segment matching
   one non-empty segment; `$default` when no route matches (route selection of
   the API Gateway Developer Guide, profile source A4).
7. When the request names a session in `native_state_ref`,
   `requestContext.authorizer` is `{"iam": <that session's iam>}`; otherwise
   the event has no `authorizer`.
8. The `event` patch of the native state is applied.

A request whose `arrival` is `direct` is given to the adapter without an
event: it did not come through API Gateway. The authority of a case's `url`
other than its userinfo does not reach the event: API Gateway delivers only the
requests that reached the configured custom domain, so a `url` that names an
internal address stands for a request sent to that domain. Whether API Gateway
passes a target with userinfo, a fragment or an ambiguous encoding to the
function at all is probe P2 of the profile; the harness delivers it so that the
adapter's refusal is tested.

## Common cases

The common cases state their native state in `common/1`. An AWS harness
realizes it with the account `111122223333` in the partition `aws` and a role
table with one role per identity: the role
`arn:aws:iam::111122223333:role/common/<ref>`, whose unique ID is `AROA`
followed by the first 17 characters of the upper-case hexadecimal SHA-256
digest of the UTF-8 octets of `<ref>`, with the session-name rule `any`. The
identity's session has the session name `<ref>`, the `userArn`
`arn:aws:sts::111122223333:assumed-role/<ref>/<ref>`, the `userId` of the
role ID, `:` and `<ref>`, the same `callerId`, the `accountId` of the
account, the `accessKey` `ASIA` followed by characters 5 to 20 of the role
ID, and a null `cognitoIdentity` and `principalOrgId`. The configuration check passed at `now`. The routes of the
installed mappings accept a body. The other functions use the
deployment-supplied sources that `common/1` describes. Eight common
`authenticate_native` cases expect a principal or a denial reason that an IAM
context cannot carry and are replaced (profile section 10; adapters README,
"Replaced common cases").
