# PACT AWS API Gateway IAM caller and execution-role profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose and status

This is the integration profile ([`TEMPLATE.md`](../TEMPLATE.md)) for a custom API served by Amazon API Gateway as an HTTP API, whose routes require AWS IAM authorization and whose integration is an AWS Lambda function that hosts the PACT adapter and validator, the scenario of [`example_I09.md`](../../examples/example_I09.md). It states how the authenticated caller and its STS role session map to an enrolled workload, how the actual operation is reconstructed from the Lambda proxy event, and how the function's execution role acts downstream as a distinct actor. It answers the AWS half of the open finding G21 of the specification review; the [Kubernetes profile](../k8s/profile.md) answers the other half, and the section "G21 closure map" shows which rule answers which closure item. The machine-readable form is [`profile.json`](profile.json).

The profile adds no wire field and no protocol requirement. Where it and [`draft.md`](../../draft.md) differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. The rules AR-1 to AR-27 are normative for a claim made under this profile, and the G21 closure items carry the identifiers AWS-01 to AWS-13, which are also the identifiers of the negative cases of section 10. Shared rules are not repeated: identifiers, enrollment, and lifecycle are in [`identity-mapping.md`](../identity-mapping.md) (IM-1 to IM-29), request binding is in [`request-binding.md`](../request-binding.md) (RB-1 to RB-64), and observation and status times are in [`freshness.md`](../freshness.md). A rule below can be stricter than those documents, and none is weaker.

Every statement about AWS has one of three bases. A label in square brackets, such as [A1], cites an AWS page read for this profile on 2026-10-16; the section "Sources" lists each one. *Profile* marks a requirement this profile places on the adapter or the deployment; it is a rule, not a statement about AWS. *To probe* marks a fact that the pages read did not establish; the section "Open items and probes" names the probe, and every rule that rests on one is written so that it fails closed whichever way the probe comes out, or is a precondition of the claim. No statement here describes AWS from memory.

## Profile header

| Field | Value |
|---|---|
| Profile name | `aws`: Amazon API Gateway HTTP API with IAM authorization and a Lambda proxy integration |
| Target product and version | Amazon API Gateway HTTP APIs (the API Gateway version 2 API [A10]) whose claimed routes use the authorization type `AWS_IAM` [A2] and a Lambda proxy integration at payload format version `2.0` [A1]; callers authenticate with temporary credentials of AWS STS role sessions [A22] and sign with Signature Version 4 [A2]. AWS documentation carries no release number: the pages of the section "Sources" were read on 2026-10-16, and a deployment records the date on which it re-reads them (probe P9) |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `r1`, 2026-10-16 |
| Maintainer | PACT adapter maintainers |
| Reference documents | draft = `spec/v1.0/draft.md`; identity rules = [`identity-mapping.md`](../identity-mapping.md); request binding = [`request-binding.md`](../request-binding.md); freshness rules = [`freshness.md`](../freshness.md); scenario = [`example_I09.md`](../../examples/example_I09.md) |
| Mapping revision | `pact-aws-1`: the identity inputs, the event-to-operation reconstruction, and the executor rules below |

## Terms

| Term | Meaning in this profile |
|---|---|
| Event | The JSON object, payload format version `2.0`, that API Gateway passes to the Lambda function for one request [A1]. |
| Integration function | The Lambda function behind the claimed routes. It hosts the adapter, the in-gateway validator, and the business handler of each route. |
| IAM context | The member `requestContext.authorizer.iam` of an event for an `AWS_IAM` route (AR-5). |
| Role table | The configured, finite set of role entries the gateway accepts as callers. An entry holds the account, the role ARN with its path, the role's unique ID, and the session-name rule (AR-8, AR-10). It changes only through the gateway's administrative controls (draft §4.2). |
| Session-name rule | The rule of a role entry that the role session name of a request must satisfy: `any`, or an exact value or prefix that the role's trust policy enforces (AR-10). |
| Configuration check | The check of the API's and the function's AWS configuration that the adapter runs before it serves and then periodically (AR-3). |
| Execution role | The IAM role that Lambda assumes when it invokes the integration function and whose permissions the function's code uses [A12]. |
| Native denial | The result of `authenticate_native` when native authentication was evaluated and failed (draft §17.1), with one public reason of a closed set: `NO_CREDENTIAL` when the event carries no IAM context, `CREDENTIAL_REJECTED` otherwise. Its code is `INVALID_PROOF`. |

## Rules

### A. Supported form and configuration

**AR-1. One supported form.** A claimed route is a route of an HTTP API with the authorization type `AWS_IAM` [A2] and a Lambda proxy integration whose payload format version is `2.0` [A1]. The API has exactly one stage, `$default`, and the claimed routes are reached through exactly one configured custom domain name with no API mapping that carries a path, and the default `execute-api` endpoint is disabled [A5]. Each condition has a source: for named stages the stage name begins the request path [A10], `rawPath` does not carry the API mapping value of a custom domain [A1], and the default endpoint otherwise remains a second entry point [A5]. REST APIs, WebSocket APIs, payload format `1.0`, JWT and Lambda authorizers, non-proxy and HTTP integrations, named stages, and API mappings with a path are unsupported (section 6). *Basis: profile, with [A1], [A2], [A5], [A10].*

**AR-2. Route keys.** Each mapping row (section 2) names one route key, the method and resource path of an API route [A4]. A claimed route key is neither `$default`, nor a route with a greedy path variable such as `{proxy+}`, nor a route with the method `ANY`: API Gateway selects them for requests that match no more specific route [A4], so a row could not predict the requests it receives. *Basis: profile, with [A4].*

**AR-3. Configuration check.** Before it serves the first protected request, and then at least every `P` seconds, the adapter reads the configuration of the API and of the integration function through their management interfaces and verifies: every route key of the mapping table exists with the authorization type `AWS_IAM`; its integration is the integration function with payload format `2.0`; the stage list is exactly `$default`; the default endpoint is disabled; no API mapping of the configured domain carries a path; the integration function has no function URL; and its resource-based policy contains the deny of AR-4. A protected request is served only when the last completed check passed and is not older than `P`. A check that fails makes the claim invalid: no protected request is served until a later check passes. A check that cannot complete is an outage (section 8, F4). Which management calls and fields report these settings, and the permissions they need, is *to probe* (P5); the settings themselves are documented [A1], [A2], [A5]. The reference configuration, an illustrative policy choice and not a recommended threshold, is `P` = 300 s. How a failed check is reported is open item O2. *Basis: profile; to probe (P5).*

**AR-4. Only API Gateway invokes the function.** An event is only as authentic as its invoker, and the event carries no proof that API Gateway produced it. Within one account, an allow in an identity-based or a resource-based policy suffices for a request, and an explicit deny in either overrides any allow [A17]; a principal whose identity policy allows `lambda:InvokeFunction` can therefore invoke the function with a fabricated event unless something denies it. The function's resource-based policy carries an explicit `Deny` of `lambda:InvokeFunction` for every principal unless the request comes from API Gateway for this API, expressed with the condition key `aws:SourceArn` and the API's ARN pattern, as the resource policy of the integration names it [A10], [A11]. A negated operator such as `ArnNotLike` evaluates to true when the key is not present in the request context, and `aws:SourceArn` is present only when a resource triggers a service to call another service on behalf of the resource owner [A24], so the deny applies to a direct invocation, which carries no source ARN. Whether that deny blocks every direct `Invoke` in the same and other accounts, and does not block API Gateway's own invocation, is *to probe* (P4). Until P4 passes, the enforced claim of this profile does not hold (section 9). The function has no function URL (AR-3). *Basis: source [A10], [A11], [A17], [A24]; profile; to probe (P4).*

### B. Caller identity (`authenticate_native`)

**AR-5. The only identity input.** The caller's identity is read only from the IAM context of the event. API Gateway invokes an `AWS_IAM` route only when the client signed the request with AWS credentials under Signature Version 4 and holds `execute-api` permission for the route [A2]. The AWS pages read document the identity of IAM-authorized HTTP API routes only as access-log variables: `$context.identity.accountId` ("The AWS account ID associated with the request"), `caller` ("The principal identifier of the caller that signed the request"), `user` ("The principal identifier of the user that will be authorized against resource access"), `userArn` ("The Amazon Resource Name (ARN) of the effective user identified after authentication"), and `principalOrgId`, each "Supported for routes that use IAM authorization" [A3]. The payload format page shows no IAM context in its `2.0` example [A1]. The member names `accessKey`, `accountId`, `callerId`, `cognitoIdentity`, `principalOrgId`, `userArn`, and `userId` under `requestContext.authorizer.iam` come from a test event of AWS's Lambda library for Go [A23], which is library source and not documentation. They are recorded here as the names the adapter reads, and they are *to probe* (P1) against a deployed API. An event for an `AWS_IAM` route in which `requestContext.authorizer.iam`, `accountId`, `userArn`, or `userId` is absent, or not a string where a string is expected, is a native denial with `NO_CREDENTIAL` when the IAM context is absent and `CREDENTIAL_REJECTED` otherwise. *Basis: source [A1], [A2], [A3]; library source [A23]; to probe (P1).*

**AR-6. Never identity.** No request header, query parameter, or body member is an identity input, even when it spells an ARN or carries an `x-amz-` or `x-amzn-` name (IM-1; RB-27). Within the event, `requestContext.authorizer.jwt`, `requestContext.authorizer.lambda`, `cognitoIdentity`, `principalOrgId`, `accessKey`, `requestContext.authentication`, and the session token are never identity inputs, and the session name and any source identity never select a workload or an agent (AR-10; IM-24). An event whose `requestContext.authorizer` carries any member besides `iam` is refused as a native denial with `CREDENTIAL_REJECTED`. *Basis: profile.*

**AR-7. Assumed-role sessions only.** The `userArn` has the form `arn:aws:sts::{account}:assumed-role/{role-name}/{role-session-name}`, the ARN of an active role session [A13], in the configured partition. The `userArn` of an IAM user, of the account root user (`arn:aws:iam::{account}:root`), and of a federated user session (`arn:aws:sts::{account}:federated-user/{user-name}`) [A13], and every event whose `cognitoIdentity` is present and not null, is a native denial with `CREDENTIAL_REJECTED`. The role session name has 2 to 64 characters of the pattern `[\w+=,.@-]*` [A22]; a session segment outside it is refused the same way. *Basis: source [A13], [A22]; profile.*

**AR-8. Account and role.** The `{account}` of `userArn` equals `accountId` of the IAM context, equals `requestContext.accountId`, whose access-log form `$context.accountId` is the API owner's account [A3] (that the event member carries the same value is part of probe P1), and equals the account of the role entry. A caller from another account is refused (section 6). The role entry is the one whose role unique ID is the part before the first `:` of the value that identifies the session as `{role-id}:{caller-specified-role-name}`, the form of `aws:userid` for an assumed role, where the role ID is the role's unique ID [A14]. Which IAM-context member carries that value is *to probe* (P1); until P1 settles it, the adapter reads `userId`, and an event whose `userId` does not have that form is refused, which fails closed. The `{role-name}` of `userArn` equals the last path segment of the entry's role ARN; a mismatch is refused. The role ARN of the entry is configured with its path, because a role ARN carries the role name with its path while the assumed-role ARN carries the role name alone [A13], so the role ARN cannot be derived from the session ARN. Every refusal of this rule is a native denial with `CREDENTIAL_REJECTED`. *Basis: source [A3], [A13], [A14]; profile; to probe (P1).*

**AR-9. Workload identifier and name reuse.** The workload, which is also the principal (identity-mapping §3.4), is `aws:{account}:{role-arn}:unreported`, written under identity-mapping §3.1 to §3.3 with every octet of the role ARN that is not `unreserved`, such as `:` and `/`, escaped (IM-2). IAM assigns every role a unique ID when it creates it [A13], and the unique ID tells two resources apart that reused a friendly name [A13]. A role deleted and created again under the same name therefore has a new unique ID, finds no role entry under AR-8, and is refused until an administrator records the new ID; this is option (a) of IM-6. *Basis: source [A13]; profile.*

**AR-10. Session name, never identity.** The role session name is chosen by the caller of `AssumeRole` [A14], [A22], so it never selects a workload or an agent, and it is no evidence of which process created the session (IM-16, IM-24). Each role entry carries a session-name rule. The value `any` imposes nothing. An exact value or a prefix states a value that the role's trust policy requires through the condition key `sts:RoleSessionName` [A16], which an administrator maintains; the adapter compares the last segment of `userArn` with the rule, octet for octet, and refuses a mismatch as a native denial with `CREDENTIAL_REJECTED`. A match is a necessary condition only: it adds nothing to the identifier and nothing to the enrollment. The interpretation of the "session-name policy" of the finding as this filter is open item O1. *Basis: source [A14], [A16], [A22]; profile.*

**AR-11. Session policy not distinguished.** The session-policy component of the identifier is `unreported`, because no page read shows that the event reports the session policy of a role session (identity-mapping §3.3; *to probe*, P1). Sessions of one role under different session policies are then one workload (IM-24), which section 9 records. A session policy can only narrow the role: the permissions of the session are the intersection of the role's identity-based policy and the session policies, and session policies cannot grant more than the role's policy [A22]. *Basis: source [A22]; profile; to probe (P1).*

**AR-12. Dedicated roles, enrollment, and the holder key.** Each role entry is dedicated to one agent: its trust policy admits only the principal that runs that agent, which the administrator maintains. A role with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states, and shared roles are unsupported (IM-19; section 6). `resolve_agent_binding` takes the realm, the workload of AR-9, and the agent ID that the presentation names, and returns that agent's enrollment on the workload, or `UNKNOWN` when there is none; the workload alone never names an agent. The holder key is bound only by the enrollment record (IM-21): AWS signing credentials and the PACT holder key are different credentials with independent lifecycles (example I09), and no AWS credential, KMS key, or session tag enrolls or certifies a holder key. *Basis: profile.*

### C. Operation binding (`map_operation`)

**AR-13. Event shape.** The event's `version` is `2.0`; its `routeKey` equals the route key of the mapping row that the binding selects from the method and `rawPath` (RB-32); `requestContext.stage` is `$default`; and `requestContext.domainName` equals the host of the configured origin. Its access-log form `$context.domainName` is the full domain name used to invoke the API [A3]; that the event member carries the same value is part of probe P1. An event that fails any of these is refused with `INVALID_MESSAGE` before any PACT evaluation. A payload `1.0` event has no `rawQueryString` and carries query parameters only as maps [A1], and in the REST API proxy event "the order of the request parameters is not preserved" [A7], so neither can yield the exact target of draft §10.2. *Basis: source [A1], [A3], [A7]; profile.*

**AR-14. Target URI.** `target_uri` is the configured origin (RB-1) followed by `rawPath`, followed, when `rawQueryString` is not empty, by `?` and `rawQueryString`. `requestContext.http.path`, `pathParameters`, and `queryStringParameters` are never inputs: API Gateway decodes URL-encoded request parameters before passing them to the integration [A4] and combines duplicate query strings with commas in `queryStringParameters` [A1]. The refusals of draft §10.2 and of request-binding §4.1 apply to `rawPath` and `rawQueryString` as the event carries them, with `INVALID_MESSAGE`: an escape of an unreserved character, lowercase hexadecimal digits in an escape, `%2F` in the path, escapes that decode to octets that are not well-formed UTF-8, a character that RFC 3986 does not allow, and dot segments (`.` or `..` path segments), which are ambiguous encodings in draft §10.2 and are rejected, never normalized. An empty `rawQueryString` binds as no query, so a request sent as `/a?` binds as `/a`, and a presentation computed for `/a?` is a context mismatch, which fails closed (open item O6). *Basis: draft §10.2; source [A1], [A4]; profile.*

**AR-15. Precondition on the raw members.** Whether `rawPath` and `rawQueryString` carry the octets of the request-target unchanged, including every form AR-14 refuses, and whether API Gateway rejects or rewrites some of them before invoking the function, is *to probe* (P2). If API Gateway decoded or normalized the target before the event, the adapter could not refuse an ambiguous encoding, as draft §10.2 requires. The enforced claim of this profile holds only for a deployment in which P2 passed; until then the adapter is not enabled for enforcement. *Basis: draft §10.2; profile; to probe (P2).*

**AR-16. Parameters from the raw path only.** The adapter derives the path parameters of the selected row from `rawPath` under the row's grammar (RB-32, RB-34) and refuses an event whose `pathParameters` member names a different value for any of them, with `INVALID_MESSAGE`. The business handler reads parameters only from the operation the adapter mapped, never from `pathParameters` or `queryStringParameters`, so that the operation that is admitted and the operation that is executed are the same. *Basis: profile, with [A4].*

**AR-17. No signature in the query.** A `rawQueryString` that contains a parameter named `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature`, or `X-Amz-Security-Token`, the query-string form of Signature Version 4 [A21], compared without regard to ASCII case, is refused with `INVALID_MESSAGE`, so that no credential enters `target_uri` (draft §19). Whether HTTP APIs accept the query-string form at all is *to probe* (P7); the rule holds either way. *Basis: source [A21]; draft §19; profile.*

**AR-18. Headers.** All header names of the event are lowercase, and duplicate headers are combined with commas in `headers` [A1]. `headers` of the operation context holds, for each allowlisted name present in the event, the value the event carries (RB-16, RB-17). This differs from the baseline normalization of RB-23, which joins field lines with a comma and one space, so the gateway publishes a `header_normalization_id` of its own that names this rule (RB-25; open item O5). The field lines of a covered header cannot be told apart from one line that contains commas; an agent sends each covered header on one field line, and a presentation computed under RB-23 for several lines is a context mismatch, which fails closed. Whether API Gateway trims white space, and which headers it adds or drops, is *to probe* (P3). Never covered, in addition to RB-20: the Signature Version 4 `authorization` header [A21], and every name that begins with `x-amz-` or `x-amzn-`, which includes the signing date header `x-amz-date` [A20]. Cookies arrive in the event's `cookies` member [A1] and are never covered (RB-20). An event whose `headers` names `content-encoding` is refused with `INVALID_MESSAGE` (RB-12). *Basis: source [A1], [A20], [A21]; profile; to probe (P3).*

**AR-19. Body.** When `isBase64Encoded` is `true`, the body octets are the base64 decoding of `body`, padded and with no other character; any other `body` is refused with `INVALID_MESSAGE`. Otherwise the body octets are the UTF-8 encoding of the `body` string. API Gateway decides whether to base64-encode a request body from its `content-type` [A9]. Whether a body that is not base64-encoded reaches the function octet for octet, for content that is not UTF-8, is *to probe* (P8). Until P8 passes, a row that accepts a body is unsupported (section 6), and a non-empty body on a row that accepts none is refused (RB-37). `body_digest` is computed over the octets as RB-11 states. *Basis: source [A9]; profile; to probe (P8).*

**AR-20. Method and sizes.** `method` is `requestContext.http.method` under RB-5. The total combined size of the request line and header values of an HTTP API request is at most 10240 bytes and cannot be increased [A6]; a presentation that does not fit in the `PACT-Presentation` header together with the other headers cannot be carried by the `header` transport of this profile, and draft §13.2 then requires a negotiated envelope or a trusted gateway-to-validator transfer, which this profile does not define (open item O7). *Basis: source [A6]; draft §13.2.*

### D. Native authorization and execution

**AR-21. Native authorization in two parts.** `authorize_native` with the original principal has two parts. The first runs in API Gateway before the event exists: it invokes the route only when the caller has `execute-api` permission for it [A2], evaluated for the route's resource ARN `arn:aws:execute-api:{region}:{account-id}:{api-id}/{stage-name}/{HTTP-VERB}/{resource-path-specifier}` [A8] under AWS policy evaluation, in which an explicit deny overrides an allow and permissions boundaries and service control policies restrict what identity policies allow [A17]. A denial there means that no event exists, so no PACT evaluation runs. HTTP APIs do not support resource policies [A2], so no API resource policy is part of the decision. The second part runs in the integration function after PACT evaluation: the business handler's own permission check for the workload of AR-9 on the operation's resources, supplied by the deployment (C08). A denial by either part is final (draft §2.3). *Basis: source [A2], [A8], [A17]; draft §2.3, §17.5.*

**AR-22. The execution role is a distinct actor.** The business operation runs under the execution role, which Lambda assumes when the function is invoked [A12]; the mapping declares the executor identity class `registered-app-executor` for every row, and `execution-identity-v1` is installed (draft §17.5). The execution role does not inherit the caller's authority: it is not a role of the role table; it holds no permission to assume a role of the role table or a role named by request data; it never uses a credential taken from the request (the Signature Version 4 `Authorization` header carries the access key ID and a signature, not the secret key [A21]); and its permissions are those that the translation row of each route declares (C07, C08), not those of the caller. The original principal's restrictions are preserved by AR-21 and by the fixed translation of each row (draft §4.3; RB-48 to RB-54), never by giving the execution role the caller's permissions. Any other credential in the function, or a fallback to one, is `FAIL` with `EXECUTOR_MISMATCH`, and an executor the adapter cannot establish is `UNKNOWN`, which yields `DEFERRED` (draft §17.5). *Basis: source [A12], [A21]; draft §4.3, §17.5; profile.*

**AR-23. Custom API only.** The claim covers the routes of section 2 of this API and nothing else. A PACT header sent to another AWS service makes nothing PACT-aware, and the profile states nothing about what the execution role or the caller's role can reach outside these routes (example I09; section 6). *Basis: profile.*

### E. Results, native claim, and principal binding

**AR-24. Results.** The adapter's checks run in this order for each event: event shape and route (AR-13), identity (AR-5 to AR-10), configuration check age (AR-3), operation binding (AR-14 to AR-20), then enrollment (AR-12). Each result uses the codes of draft §13.4 and the decisions of draft §11.4.

| Condition | Where | Decision | Code | Transport result |
|---|---|---|---|---|
| Invalid or expired signature, no `execute-api` permission, explicit deny | API Gateway | none: no event reaches the function | none | API Gateway's own error response; no receipt, no `OutcomeReport` (draft §14.5) |
| Event without IAM context (a route that is not `AWS_IAM`) | `authenticate_native` | native denial | `INVALID_PROOF` | 401, public reason `NO_CREDENTIAL` |
| IAM context incomplete, principal not an assumed-role session, account mismatch, no role entry for the role ID, role name mismatch, session-name rule not met, another authorizer member present | `authenticate_native` | native denial | `INVALID_PROOF` | 401, public reason `CREDENTIAL_REJECTED` |
| Event version, route key, stage, or domain name not as AR-13 requires | `map_operation` | refused | `INVALID_MESSAGE` | 400 |
| A refusal of AR-14 to AR-19 | `map_operation` | refused | `INVALID_MESSAGE` | 400 |
| No passing configuration check within `P`, or the check cannot complete | gateway | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503 (open item O2) |
| Workload not enrolled for the named agent, or `REVOKED` | `resolve_agent_binding` | `INADMISSIBLE` | `INVALID_PROOF` | 401 |
| `COMPROMISED` binding | `resolve_agent_binding` | `INADMISSIBLE` | `SECURITY_HOLD` | 403 |
| Agent enrolled for another workload than the authenticated one | validator | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| A role with more than one enrollment in force, a configuration error (AR-12) | `resolve_agent_binding` | As identity-mapping §5 states (IM-19) | As identity-mapping §5 states (IM-19) | The status of that code (draft §13.4) |
| Enrollment registry or role table cannot answer | `resolve_agent_binding`, `authenticate_native` | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503 |
| Workload of the actual request differs from the workload bound at contract issuance (AR-26) | validator, `operation_digest` | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| Presented `principal_id` differs from the workload of AR-9 (AR-26) | validator, `native-principal-binding-v1` | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| Executor is not the declared execution role (AR-22) | `execution-identity-v1` | `FAIL` | `EXECUTOR_MISMATCH` | not executed |
| The handler's permission check denies after admission (AR-21) | `authorize_native` | native denial | none | not executed; native error |

The public error never says which identity condition failed (draft §13.4). A `DEFERRED` result before authentication completed carries no receipt, as in the [mTLS profile](../mtls/profile.md) (its open item O8).

**AR-25. Native claim.** The approved native paths for `read_native_claim` are `/attributes/environment/principal_id`, whose value is the workload identifier of AR-9; `/attributes/environment/workload_role`, the role ARN of the role entry; and `/attributes/environment/account_id`, the account of AR-8. Any other path returns `UNSUPPORTED_REQUIREMENT`. The source is F1 of section 8: the claim has no source observation time, because IAM's request context holds the issue time of temporary credentials as `aws:TokenIssueTime` [A15] but no page read shows it in the event (*to probe*, P1), so a rule that bounds the observation age of these paths is `DEFERRED` with `UNSUPPORTED_REQUIREMENT`; the status time is the event's `requestContext.timeEpoch` minus the declared IAM propagation bound `L` (freshness §4.2, convention 1). *Basis: profile; to probe (P1).*

**AR-26. Principal binding.** The workload identifier at contract issuance is bound by the contract's `operation_digest` and compared by the validator with the identifier of the actual request (draft §9.1, §11.3 step 5). The baseline check `native-principal-binding-v1`, which the validator evaluates (draft §17.5), compares the presented `/attributes/environment/principal_id` with the identifier of AR-9 and returns `FAIL` with `CONTEXT_MISMATCH` when they differ. A new session of the same role between issuance and evaluation keeps the identifier and passes; a session of another role fails. The function implements neither comparison. *Basis: draft §9.1, §11.3, §17.5; profile.*

**AR-27. Timeouts.** The maximum integration timeout of an HTTP API is 30 seconds and cannot be increased [A6]. An evaluation in the function that would not finish within the remaining integration time does not wait: the check that waits is `UNKNOWN` and the decision is `DEFERRED` (draft §12.2; freshness §5). *Basis: source [A6]; draft §12.2.*

## 1. Claim scope

The integration function evaluates PACT in the request path of the API (draft §4.4, in-gateway: API Gateway and the function together are the gateway), claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over the `header` transport, and is a partial role implementation (draft §22.1) because it claims neither Reputation nor Learning. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1; the roles it does not claim are supplied by connected services of the deployment. The enforced claim holds only for a deployment in which probes P2 and P4 passed (AR-4, AR-15).

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced` |
| Presentation transports (draft §13.2) | `header`, within the header budget of AR-20 |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` (`GatewayMetadata.adapters`, draft Appendix A) |
|---|---|---|
| `aws-apigateway-http-api` | `payload-format-2.0` | `pact-aws-1` |

`payload-format-2.0` names the event format of [A1], the one native protocol version this adapter reads. `pact-aws-1` names the rules of this profile; a change to any of them is a new mapping revision.

## 2. Protected routes and actions

One reference route is claimed, the operations-metrics read of example I09, deployed on the `$default` stage of the API (AR-1). The example's illustrative permission names a stage `prod`; this profile does not support named stages, so the deployment writes the caller's `execute-api` permission [A8] for the `$default` stage. A deployment that claims other routes lists them in its own profile under AR-2 and the rules of request-binding §5.

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/metrics/operations` (route key `GET /metrics/operations`) | `GET` | `metrics.operations.read` | `https://metrics.example/operations`, a constant (RB-40). No query parameter is read (RB-35, RB-36), no body is accepted (RB-37), and no header is allowlisted; `content-type` is covered only when a body is present, which R1 refuses |

## 3. Enforcement points

The required functions run in request order, the first part of native authorization in API Gateway and the rest in the integration function, and the other four adapter functions of draft §17.1 are listed as supporting rows.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | API Gateway's Signature Version 4 check for the `AWS_IAM` route [A2], then the adapter in the integration function (AR-5 to AR-10) | AWS (API Gateway) and adapter owner | Produces the principal and workload `aws:{account}:{role-arn}:unreported` in the realm of the gateway; otherwise a native denial (AR-24) |
| 2 | `map_operation` | Adapter in the integration function, mapping revision `pact-aws-1` | Adapter owner | Reconstructs the operation from `rawPath`, `rawQueryString`, `headers`, and `body` (AR-13 to AR-20) |
| 3 | PACT evaluation | In-gateway validator in the integration function | Gateway implementer | After mapping and before the handler's permission check; the freshness checks of section 8 apply |
| 4 | `authorize_native` | API Gateway's `execute-api` decision before the event, and the handler's permission check after PACT evaluation (AR-21) | AWS (IAM) and resource owner | A native denial is final (draft §2.3); both parts use the original principal |
| 5 | Execution | The handler of R1 under the execution role (AR-22) | Resource owner | Reached only after steps 1 to 4 pass; executor class `registered-app-executor` |
| support | `resolve_agent_binding` | Enrollment registry lookup for the realm, the workload, and the agent the presentation names (AR-12) | Gateway implementer | Supplies the enrolled agent, operator, holder key, and status |
| support | `read_native_claim` | Adapter, approved paths of AR-25 only | Adapter owner | Returns values with the times of AR-25 |
| support | `check_context` | Installed check `execution-identity-v1` (AR-22) | Gateway implementer | No other named check runs here: `native-principal-binding-v1` is evaluated by the validator (AR-26). The task and runtime checks of example I09 are supplied by the deployment |
| support | `record_outcome` | Gateway outcome writer in the integration function, after execution | Gateway implementer | A request that API Gateway refuses never reaches the function and produces no `OutcomeReport` (draft §14.5) |

## 4. Native dependencies

Eleven of the sixteen handoff components are used, and each of the other five carries the reason it does not apply. The adapter of these rules is the package `go/adapters/aws`, built with `aws.New` from an `aws.Config` that names the gateway's realm, the account and partition, the origin whose host is the custom domain, the role table, the configuration check, the declared execution role with its executor source, and the deployment-supplied parts of `go/adapter/installed`. It uses the standard library only: the payload `2.0` event types are defined in the package, and neither an AWS SDK nor the AWS Lambda library is a dependency. The integration function hands each raw event to `aws.Invocation` and passes the result to the adapter's functions.

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | In-gateway validator in the integration function | Gateway implementer | To be supplied |
| C02 | Native authentication and claim adapters | baseline | API Gateway `AWS_IAM` route authorization and the adapter of these rules; the role table | AWS, IAM owner, and adapter owner | API Gateway exists; the adapter is `go/adapters/aws`; the role table store and the configuration check's management reads (P5) are to be supplied |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry (a registry contract and an in-memory backend exist in `go/adapter/enroll`), administrator-run enrollment | IAM and security owner | Registry contract exists; production store to be supplied |
| C04 | Native delegation and task authority | delegated or task execution | The deployment's native production-observation task authorization (example I09) | Resource owner | Not supplied by this profile; the `authority_ref` field of example I09 stays with the deployment (section 6) |
| C05 | Evidence and authoritative status sources | baseline | IAM and STS through API Gateway's per-request decision, the enrollment registry, the role table, the configuration check | AWS and adapter owner | AWS exists; the rest to be supplied |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the read route needs no external approval |
| C07 | Purpose and exact operation mapper | baseline | The mapper of AR-13 to AR-20 for R1, and the translation row of R1: the fixed read of the metrics store that the handler performs, with no request data in it beyond the row's constants | Adapter and application owner | The mapper is `MapOperation` of `go/adapters/aws`, with the route table of R1; the handler's translation row is to be supplied |
| C08 | Native resource executor and authorization | the actual resource operation | The handler of R1 under the execution role, and its permission check for the original principal (AR-21, AR-22) | Resource owner | To be supplied |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store reached by the integration function | Gateway and platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Gateway outcome writer and the API's access log | Resource owner | To be supplied |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | To be supplied; registry only, no adaptation lifecycle |
| C13 | Revocation and security holds | baseline | Enrollment status, the hold store, and IAM session revocation [A18] | Security and IAM owner | To be supplied; IAM revocation exists |
| C14 | Protected evidence and audit storage | baseline | Access-controlled audit store; no signature, session token, or cookie is stored (draft §19) | Security and data owner | To be supplied |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: read route, no transactions or budgets |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no runtime attestation or data-use guarantee is claimed; the runtime evidence of example I09 stays attested-only (draft §17.4) |

## 5. Alternative and bypass paths

Ten other ways to reach the protected operation or its identity input are listed: seven `closed`, one `equivalently-enforced`, and two `out-of-claim`. The cases named as evidence are in section 10.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | Direct invocation of the integration function with a fabricated event, by any principal allowed `lambda:InvokeFunction` | `closed` | The resource-policy deny of AR-4 and its presence verified by the configuration check (AR-3); rests on probe P4; case `AWS-02` |
| B2 | A function URL of the integration function | `closed` | None is configured, verified by AR-3; case `AWS-02` |
| B3 | The default `execute-api` endpoint, or another domain name | `closed` | The default endpoint is disabled (AR-1, verified by AR-3) and `requestContext.domainName` must be the configured host (AR-13); case `AWS-10` |
| B4 | Routes of the API that are not `AWS_IAM`, the `$default` route, greedy and `ANY` routes, reaching the integration function | `closed` | An event without IAM context is a native denial (AR-5) and a route key outside the mapping table is refused (AR-13); AR-3 verifies the claimed routes; case `AWS-09` |
| B5 | Named stages and API mappings with a path | `closed` | AR-1, verified by AR-3, and the stage check of AR-13; case `AWS-10` |
| B6 | A REST API, or a payload format `1.0` integration, reaching the same function | `closed` | The event version check of AR-13; case `AWS-06` |
| B7 | Identity headers or query parameters sent by the client, such as one naming another role ARN | `closed` | AR-5 and AR-6: identity comes from the IAM context only; case `AWS-01` |
| B8 | The PACT endpoints of draft §13.2 that require native authentication, such as `POST /pact/v0.1/requirements`, routed through the same API | `equivalently-enforced` | They are `AWS_IAM` routes of the same API served by the same integration function, so AR-1 to AR-12 apply to them; case `AWS-09` |
| B9 | Direct calls by the agent's role to the metrics store or another AWS service | `out-of-claim` | Excluded in section 6 (direct PACT enforcement across arbitrary AWS services); the role's own IAM policy governs them |
| B10 | Other principals that hold `execute-api` permission for R1 | `out-of-claim` | Not agents of this claim: such a principal authenticates as itself, has no role entry or enrollment, and is refused at AR-8 or AR-12; excluded in section 6 |

## 6. Unsupported forms

The first two rows are seeded from the I09 row of the handoff "Deliberate design choices" table, which reads: "Custom IAM-authorized API Gateway integration" is the choice and "Direct PACT enforcement across arbitrary AWS services or inherited caller authority for its execution role" is the wider claim not established. The other rows come from the rules and sections of this profile.

| Unsupported form | Seed (handoff source row) | Why it is not established |
|---|---|---|
| Direct PACT enforcement across arbitrary AWS services | I09: "Direct PACT enforcement across arbitrary AWS services" | Only the routes of section 2 of one custom API are claimed (AR-23); no other AWS service evaluates PACT |
| Inherited caller authority for the execution role | I09: "inherited caller authority for its execution role" | The execution role is a distinct actor with its own declared permissions (AR-22) |
| REST APIs, WebSocket APIs, payload format `1.0`, non-proxy and HTTP integrations | Section 3, AR-13 | Payload `1.0` has no `rawQueryString` [A1] and the REST proxy event does not preserve the order of request parameters [A7], so the exact target cannot be reconstructed |
| JWT and Lambda authorizers, and every authentication other than Signature Version 4 with role-session credentials: IAM users, the root user, federated users, Amazon Cognito credentials | Section 7, AR-6, AR-7 | Only assumed-role sessions map to a workload |
| Callers from another account | AR-8 | The role, the caller, and the API are in one account |
| Shared roles, and telling agents apart by session name or source identity | Section 7, AR-10, AR-12 | One role per agent, the default of identity-mapping §5 (IM-19); a role with more than one enrollment in force is a configuration error (AR-12); session names are chosen by the caller [A14] |
| Telling sessions of one role apart by session policy | AR-11 | The event reports no session policy (P1); the identifier uses `unreported` |
| Named stages, API mappings with a path, more than one domain, the default endpoint | AR-1 | The path in the event would not be the path the client sent [A1], [A10] |
| The `$default` route, greedy path variables, and the `ANY` method | AR-2 | A row could not predict the requests it receives [A4] |
| Routes that accept a body | AR-19 | Body octets are not established for text bodies (P8) |
| Query-string Signature Version 4 authentication | AR-17 | Credentials would enter `target_uri` (draft §19) |
| Presentations that exceed the header budget of an HTTP API request | AR-20 | No envelope or validator transfer is defined (open item O7) |
| Any field of the I09 profile other than those of AR-25: the delegation `authority_ref` and the runtime isolation evidence | Section 3 | Those sources are supplied by the deployment outside this profile |
| Any route other than R1 | Section 2 | Not listed in section 2, so not claimed |
| Agents' direct calls to AWS services, and other principals' calls | Section 5, B9 and B10 | Excluded by their `out-of-claim` disposition |

## 7. Identity mapping

Each agent has a dedicated IAM role in the API owner's account; the role, recorded in the role table with its unique ID, is enrolled by an administrator and bound to the holder key in the enrollment registry. All other rules are those of [`identity-mapping.md`](../identity-mapping.md).

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | Workload only: `aws:{account-id}:{role-arn}:{session-policy-id}` of identity-mapping §3.3, with `role-arn` the role's ARN with its path (AR-8) and `session-policy-id` always `unreported` (AR-11). The principal equals the workload (identity-mapping §3.4). No `x-` namespace |
| Trusted enrollment actors | The native administrative workflow of the realm and, where configured, an authorized identity-binding issuer for the `aws` namespace (identity-mapping §4.2). AWS STS, API Gateway, the role's trust policy, and the agent are not enrollment actors |
| Shared-account handling | Not supported, the default of identity-mapping §5 (section 6). A role with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states (AR-12, IM-19) |
| Certificate, token, or role-session bindings | The role session authenticates the workload and is bound to nothing else. The binding is to the role, never to the session, its name, its source identity, or its session token (IM-24); name reuse is handled by the role unique ID (AR-9, IM-6 (a)); the holder key is bound only by enrollment (AR-12, IM-21) |
| Lifecycle rules (rotation, compromise, recovery) | Identity-mapping §7 for the enrollment record. Session expiry and session revocation are native authentication events and change no record. The propagation bound for the record is in section 9 |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule. Stricter choices: assumed-role sessions only (AR-7); the role entry is selected by the role unique ID and the role name must agree with it (AR-8); a session-name rule may refuse sessions (AR-10); shared roles refused (IM-19 allows supporting them only with a stated reason). The session-policy component is `unreported`, which IM-24 permits with the residual limit of section 9 |

## 8. Freshness

Four sources are listed, with `max_age` and `status_max_age` in seconds, and every outage ends in `DEFERRED`, which fails closed (draft §18). The figures for F1 and F4 follow from the reference configuration, an illustrative policy choice and not a recommended threshold: the IAM propagation bound `L` = 60 s, which no AWS page read states (P6), and the configuration check interval `P` = 300 s. A deployment declares its own values.

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Caller role session as API Gateway authenticated and authorized it (IAM context of the event) | Cached credential snapshot (draft §17.2), class "token" of freshness §4.1: the session's credentials were fixed at issue. The event carries no issue time of the session (P1), so the source observation time is absent (AR-25); the status time is `requestContext.timeEpoch` minus `L`, because IAM is eventually consistent [A19]. A session lasts at most 43200 s [A22] | 43200 | 60 | `DEFERRED` |
| F2 Enrollment registry (workload to agent and holder key binding) | Current authoritative state, read for each evaluation (AR-12). The observation time is the last change of the record (IM-10) | 0 | 0 | `DEFERRED` |
| F3 Role table (gateway configuration) | Current authoritative state, read for each event (AR-8 to AR-10) | 0 | 0 | `DEFERRED`: a table that cannot be read or is invalid fails closed |
| F4 Configuration check of the API and the integration function | Snapshot of AWS configuration taken by the check of AR-3, at most `P` old when a request is served | 300 | 300 | `DEFERRED` |

A contract rule over the paths of AR-25 cannot bound the observation age: the result is `DEFERRED` with `UNSUPPORTED_REQUIREMENT` (freshness §3.1, rule 6). A rule whose `status_max_age_seconds` is below 60 is unachievable for F1 and is `DEFERRED` with `UNSUPPORTED_REQUIREMENT` before the claim is read (freshness §4.2, convention 2), so the hold-check advice of draft §18 to use zero cannot be met by IAM state through this source.

### 8.1 Membership and status sources

F1 and F2 supply identity and status facts about the authenticated principal. F1 offers no check that the adapter can make at evaluation time: the adapter reads what API Gateway decided for this request, so it has no live check and its values are cached snapshots. F2 is a registry lookup made for each evaluation. The integration reads no group or role-assignment fact.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 Caller role session as API Gateway authenticated and authorized it (IAM context of the event) | `identity` | `false` | Not applicable: the adapter does not call IAM | `none` | Not applicable: no change feed | 60 | `cached_snapshot` |
| F2 Enrollment registry (workload to agent and holder key binding) | `identity`, `account_state` | `true` | Enrollment registry lookup | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

### 8.2 Attribute sources

The account and the role of the authenticated session are subject attributes that the native claim offers (AR-25); both are derived from F1, with the role ARN taken from the role entry that F1 selects.

| Source | `category` | `attributes` | `freshness` |
|---|---|---|---|
| F1 Caller role session as API Gateway authenticated and authorized it (IAM context of the event) | `subject` | `/attributes/environment/account_id`, `/attributes/environment/workload_role` | F1 Caller role session as API Gateway authenticated and authorized it (IAM context of the event) |

## 9. Residual limits

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Metrics already returned to the agent are not recalled by a later revocation of a session or an enrollment; an executed operation is not undone by revoking its receipt (draft §18); no egress or data-use control is claimed (draft §17.4) | Disclosed here; no bound |
| Revocation propagation: role session (F1) | Temporary credentials stay usable until they expire, at most 43200 s after issue [A22], unless an administrator revokes the role's sessions; the revoke action attaches a deny for sessions issued before about 30 seconds into the future, to cover propagation [A18], and IAM changes reach all endpoints only eventually [A19]. No page read states a bound for a policy change to reach API Gateway's authorization (P6) | The declared `L`; illustrative 60 s |
| Revocation propagation: enrollment (F2) | Revocation, compromise mark, and rotation take effect at the next evaluation, in the consistency domain of the registry (identity-mapping §7.5; draft §18) | 0 s within that domain; a registry with eventual consistency declares its replication delay |
| Revocation propagation: role table and configuration (F3, F4) | Removing a role entry takes effect at the next event after the configuration is reloaded; a configuration change at AWS that breaks AR-1 or AR-4 is seen at the next configuration check | The reload time of the deployment; `P` = 300 s for F4 |
| Session policy (IM-24) | Sessions of one role under different session policies are one workload (AR-11). A session policy can only narrow the role [A22], so a narrower session is admitted as the role and then fails natively where it lacks a permission | Disclosed; no bound |
| Direct invocation (AR-4) | The event carries no proof of its invoker. The claim rests on the resource-policy deny, which probe P4 must show effective, and on the configuration check | Precondition of the claim (section 1) |
| Raw target (AR-15) | Request binding relies on `rawPath` and `rawQueryString` carrying the target unchanged, which probe P2 must show | Precondition of the claim (section 1) |
| Header field lines (AR-18) | Several field lines of a covered header and one line with commas bind alike | Disclosed; agents send one line per covered header |
| Header budget (AR-20) | A presentation larger than the header budget cannot be presented; API Gateway refuses the request, and no evidence is truncated or dropped | 10240 bytes for the request line and headers [A6] |
| Execution role scope (AR-22) | The execution role can do whatever its own policy allows. The profile verifies neither that policy nor its trust policy; the deployment declares the permissions of each translation row (open item O4) | Disclosed; deployment declaration |
| Session name (AR-10) | A session-name rule refuses sessions; it never proves which process created a session, because the name is chosen by the caller of `AssumeRole` | Disclosed |
| Clock | `requestContext.timeEpoch` is API Gateway's clock. A clock ahead of the validator by more than the skew makes the status time unusable (freshness §3.1, rule 2) | Skew of 5 s (draft §7.5) |

## 10. Fixture index

Fourteen negative cases cover the route, every `closed` and `equivalently-enforced` path, the freshness rows, and the configuration-error rule of AR-12; the expected results use the wording of draft §22.2 where a case applies. Each is a group of adapter cases of this profile in `spec/v1.0/fixtures/adapters/aws/`, one file per variant, named by its lower-case ID and variant, such as `aws-01.forged-identity.json`, with the manifest id `adapters/aws/aws-01.forged-identity`; every file is registered in `spec/v1.0/fixtures/manifest.json` and listed in the `fixtures` array of `profile.json`. The Evidence column names the files, and the part of a case that is a property of the validator, the gateway, or the deployment rather than of an adapter function says where it is tested. The input of each case is a payload `2.0` event that the harness builds from the case's request and native state, in the model `aws/1` of the [AWS cases README](../../fixtures/adapters/aws/README.md), starting from the sample event `adapters/aws/events/sample-v2-iam.json`; this settles open item O3. The identity, freshness, and request-binding cases of `spec/v1.0/fixtures/adapters/_common/` also apply and are not repeated. `AWS-14` covers the configuration-error rule of AR-12 and is not a G21 closure item.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `AWS-01` | Event for an enrolled role whose request also carries headers and a query parameter naming another enrolled role ARN, and an `x-amzn-` header naming another account | The extra inputs have no effect; the event is evaluated as the session's own role | `adapters/aws/aws-01.forged-identity`, with the control `aws-01.own-role` | R1, B7 |
| `AWS-02` | Configuration in which the function's resource policy lacks the deny of AR-4; one with a function URL; an event delivered while no check has completed; a passing check older than `P` | No protected request served: `authenticate_native` fails with `DEPENDENCY_UNAVAILABLE`, so the exchange is `DEFERRED`; a check exactly `P` old still serves | `adapters/aws/aws-02.resource-policy-deny-missing`, `aws-02.function-url-present`, `aws-02.never-passed`, `aws-02.stale`, with the control `aws-02.at-interval`. The management reads of the check itself (probe P5) are the deployment's; the cases state the result of the last completed check | B1, B2, F4 |
| `AWS-03` | Session of a role that has no role entry; of a role with the same name in another account; of a role recreated under the same name (new unique ID); a role ID of an entry with another role name in `userArn`; an IAM context or an event whose account is not that of `userArn`; a role with the same name under another path, with its own entry | Native denial, 401, `CREDENTIAL_REJECTED`; never resolved to the enrolled workload. The role under another path is its own workload, selected by its unique ID | `adapters/aws/aws-03.no-role-entry`, `aws-03.other-account`, `aws-03.recreated-role`, `aws-03.name-mismatch`, `aws-03.context-account-mismatch`, `aws-03.api-account-mismatch`, `aws-03.same-name-other-path` | R1, F3 |
| `AWS-04` | Session name equal to another agent's role name; session name outside the entry's session-name rule; session name outside the pattern of [A22] | The name never selects a workload or agent; a mismatch is a native denial, `CREDENTIAL_REJECTED` | `adapters/aws/aws-04.other-agent-name`, `aws-04.outside-rule`, `aws-04.outside-pattern`, with the control `aws-04.inside-rule` | R1 |
| `AWS-05` | `userArn` of an IAM user, of the root user, of a federated user; an IAM context with a non-null `cognitoIdentity` | Native denial, 401, `CREDENTIAL_REJECTED`, which carries neither the signature nor the session token of the request | `adapters/aws/aws-05.iam-user`, `aws-05.root`, `aws-05.federated-user`, `aws-05.cognito-identity`; a role of another account is `aws-03.other-account` | R1 |
| `AWS-06` | Event with `version` `1.0`; a REST-shaped event with `multiValueQueryStringParameters` and no `rawQueryString` | `INVALID_MESSAGE`; the target is never rebuilt from the parameter maps | `adapters/aws/aws-06.version-1`, `aws-06.rest-shaped` | R1, B6 |
| `AWS-07` | `rawQueryString` reordered or extended after the contract; `rawPath` with `%6Fperations`, `%2c`, `%2F`, `/./`, `/../`, `%C0%AF`; query with `X-Amz-Signature` or `x-amz-security-token`; `content-encoding` present; non-empty body on R1; base64 body with an invalid character or a line break | The query binds octet for octet as sent, so a change after issuance is a context mismatch (draft §22.2); `INVALID_MESSAGE` for the rest. An empty query binds as none, and a body binds as its decoded octets | `adapters/aws/aws-07.query-as-sent`, `aws-07.empty-query`, `aws-07.unreserved-escape`, `aws-07.lowercase-escape`, `aws-07.encoded-slash`, `aws-07.dot-segment`, `aws-07.dot-dot-segment`, `aws-07.overlong-utf8`, `aws-07.signature-query`, `aws-07.signature-query-case`, `aws-07.content-encoding`, `aws-07.body-on-row-without-body`, `aws-07.invalid-base64`, `aws-07.base64-newline`, with the controls `aws-07.base64-body` and `aws-07.text-body` on a deployment row that accepts a body. The mismatch itself is the validator's comparison of `operation_digest` (AR-26), not an adapter function; a changed covered header is a Go test of the adapter package, because R1 covers no header | R1 |
| `AWS-08` | `pathParameters` that disagree with `rawPath`; `queryStringParameters` that disagree with `rawQueryString`; a `requestContext.http.path` that differs from `rawPath`; a `routeKey` other than the row the method and `rawPath` select | `INVALID_MESSAGE` for the path parameters and the route key; the query parameter map and `requestContext.http.path` are never inputs (AR-14), so the target comes from `rawPath` and `rawQueryString` | `adapters/aws/aws-08.path-parameter-mismatch`, `aws-08.query-parameters-ignored`, `aws-08.route-key-mismatch`, `aws-08.http-path-ignored`, with the control `aws-08.path-parameter-match`, on a deployment row with a path variable | R1 |
| `AWS-09` | Event without `requestContext.authorizer.iam`; event with an `authorizer.jwt` member; event for the `$default` route; contract request to `POST /pact/v0.1/requirements` without IAM context | Native denial, 401, `NO_CREDENTIAL` or `CREDENTIAL_REJECTED`; the `$default` route is `INVALID_MESSAGE`; no trusted personalized contract is issued | `adapters/aws/aws-09.no-iam-context`, `aws-09.jwt-member`, `aws-09.default-route`, `aws-09.contract-request`. The refusal to issue a contract is a gateway property, covered by the gateway pipeline test when a gateway exists; reserved, not landed | B4, B8 |
| `AWS-10` | `requestContext.domainName` of the default `execute-api` endpoint or another domain; `requestContext.stage` other than `$default` | `INVALID_MESSAGE` | `adapters/aws/aws-10.execute-api-domain`, `aws-10.other-domain`, `aws-10.named-stage` | B3, B5 |
| `AWS-11` | Executor that would run under a role other than the declared execution role: a role of the role table, a broader fallback role, the caller's session; an executor that cannot be established | `FAIL` with `EXECUTOR_MISMATCH`; no execution; `UNKNOWN` with `DEPENDENCY_UNAVAILABLE`, so `DEFERRED`, when the executor cannot be established (draft §17.5) | `adapters/aws/aws-11.caller-role`, `aws-11.broader-fallback`, `aws-11.caller-credential`, `aws-11.indeterminate`, `aws-11.executor-source-down`, with the control `aws-11.declared` | R1 |
| `AWS-12` | Valid admission, then the handler's permission check denies the principal the metrics resource | Native denial, unchanged, with its source; no execution (draft §22.2) | `adapters/aws/aws-12.handler-denies`, with the control `aws-12.handler-allows` | R1 |
| `AWS-13` | Enrollment registry, role table, or configuration check unavailable at evaluation; a rule with a status limit below 60 s on a path of AR-25; a rule that bounds the observation age of those paths | `DEFERRED` with `DEPENDENCY_UNAVAILABLE`, then `UNSUPPORTED_REQUIREMENT` for the two rules (draft §18, §22.2) | `adapters/aws/aws-13.registry-down`, `aws-13.role-table-down`, `aws-13.configuration-check-down`. The two rules are judged by the validator before it reads the claim (freshness §4.2, convention 2; §3.1, rule 6); reserved for the evaluation cases, not landed. That the claim reports no observation time and the status time `timeEpoch` minus `L` is a Go test of the adapter package | F1, F2, F3, F4 |
| `AWS-14` | Two enrollment records, for agents A and B, on the workload of one role entry: (a) the enrollment that would add the second record; (b) both records present, and a presentation by A signed with A's key, and one by B signed with B's key | (a) Refused; (b) neither record is selected, for either agent: the configuration error of identity-mapping §5 (IM-19) | (b) `adapters/aws/aws-14.two-agents-a`, `aws-14.two-agents-b`, with the control `aws-14.dedicated`; (a) is a Go test of the adapter package against the enrollment registry | AR-12, section 7 |

### Replaced common cases

The common cases of the adapter conformance suite run against this adapter. Eight `authenticate_native` cases state a principal or a denial reason that an IAM context cannot carry and are replaced ([adapters README](../../fixtures/adapters/README.md), "Replaced common cases"; draft §22.2). The others pass, with the deployment-supplied sources that their native state describes.

| Common case | Why the IAM context cannot realize it | Replacement |
|---|---|---|
| `COMMON-01.credential-wins` | Expects `https://idp.acme.example/bob` and a workload that is not an `aws:` identifier | `AWS-01.forged-identity`: headers and a query parameter naming another enrolled role; authenticated as the session's own role (AR-5, AR-6) |
| `COMMON-02.via-enforcement-point` | Expects `https://idp.acme.example/alice` | `AWS-01.own-role`: the event of an `AWS_IAM` route; authenticated as the role's `aws:` identifier, mechanism `aws-iam`, realm of the gateway |
| `COMMON-09.authenticate-realm` | Expects a `globex` principal id | `AWS-01.own-role`: the realm is the gateway's configuration, never a value of the event |
| `COMMON-10.authenticate-error` | Pins `CREDENTIAL_REJECTED` for a bearer token and a cookie; the only credential of this mechanism is the IAM context, and an event without one is `NO_CREDENTIAL` (AR-5) | `AWS-05.iam-user`: an IAM user's `userArn` with a Signature Version 4 `Authorization` header and a session token; `CREDENTIAL_REJECTED`, and neither the signature nor the token appears in the result |
| `IDENT-01.authenticate` | Expects `basic:acme-accounts:20511` | `AWS-03.same-name-other-path`: another role authenticates as its own workload, selected by its unique ID (AR-8) |
| `IDENT-02.authenticate` | Expects an `oauth:` identifier of another tenant | `AWS-03.same-name-other-path`: the same role name under another path is another workload (AR-8, AR-9) |
| `IDENT-03.authenticate` | Splits user and client; under this mechanism the principal is the workload | `AWS-01.own-role`: the principal and the workload are the role's identifier (identity-mapping §3.4) |
| `IDENT-05.authenticate` | Expects `basic:acme-accounts:30981` | `AWS-04.other-agent-name`: the session name, the analogue of a display name, never selects a workload (AR-10) |

## G21 closure map

The open finding G21 asks, for AWS, to pin the authentic caller and role-session context and its transformation, the actual downstream actor, and the implemented scope, and it asks for evidence that forged identity headers, a wrong role session, a broader fallback, and translated operations with different semantics are rejected. The Kubernetes items are in the [Kubernetes profile](../k8s/profile.md).

| G21 closure item | Rules | Cases |
|---|---|---|
| Authentic AWS caller context | AR-4 to AR-8 | `AWS-01`, `AWS-02`, `AWS-05`, `AWS-09` |
| Role session to enrolled workload, with the session name never trusted | AR-8 to AR-12 | `AWS-03`, `AWS-04` |
| Transformation of the request into the event and back to the operation | AR-13 to AR-20 | `AWS-06`, `AWS-07`, `AWS-08`, `AWS-10` |
| Actual downstream actor | AR-21, AR-22 | `AWS-11`, `AWS-12` |
| Implemented scope | AR-1, AR-2, AR-23; section 6 | `AWS-09`, `AWS-10` |
| Evidence: reject forged identity headers | AR-5, AR-6 | `AWS-01` |
| Evidence: reject a wrong role session | AR-7 to AR-10 | `AWS-03`, `AWS-04`, `AWS-05` |
| Evidence: reject a broader fallback | AR-22 | `AWS-11` |
| Evidence: reject translated operations with different semantics | AR-13 to AR-17 | `AWS-06`, `AWS-07`, `AWS-08` |
| Freshness and outage | AR-3, AR-25; section 8 | `AWS-02`, `AWS-13` |

## Sources

Every page was read on 2026-10-16. Labels are used in the rules.

| Label | Source | Used for |
|---|---|---|
| A1 | Amazon API Gateway Developer Guide, [Create AWS Lambda proxy integrations for HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html) | Payload format versions and their differences; the `2.0` event structure (`rawPath`, `rawQueryString`, `cookies`, `headers`, `body`, `isBase64Encoded`); lowercase header names; duplicate headers and query strings combined with commas; `rawPath` without the API mapping value |
| A2 | Amazon API Gateway Developer Guide, [Control access to HTTP APIs with IAM authorization](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-access-control-iam.html) | Signature Version 4, the `execute-api` permission for the route, `AWS_IAM` route authorization, no resource policies for HTTP APIs |
| A3 | Amazon API Gateway Developer Guide, [Customize HTTP API access logs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging-variables.html) | `$context.accountId`, `$context.domainName`, and the `$context.identity.*` variables of IAM-authorized routes |
| A4 | Amazon API Gateway Developer Guide, [Create routes for HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-routes.html) | Route keys, path variables, greedy variables, the `$default` route, route selection, and the decoding of URL-encoded request parameters |
| A5 | Amazon API Gateway Developer Guide, [Disable the default endpoint for HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-disable-default-endpoint.html) | The default `execute-api` endpoint and how it is disabled |
| A6 | Amazon API Gateway Developer Guide, [Quotas for configuring and running an HTTP API](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html) | 10240 bytes for the request line and headers; 30 s integration timeout |
| A7 | Amazon API Gateway Developer Guide, [Lambda proxy integrations in API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html) | The REST proxy event and "the order of the request parameters is not preserved" |
| A8 | Amazon API Gateway Developer Guide, [Control access for invoking an API](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html) | The `execute-api` resource ARN format |
| A9 | AWS Compute Blog, [Handling binary data using Amazon API Gateway HTTP APIs](https://aws.amazon.com/blogs/compute/handling-binary-data-using-amazon-api-gateway-http-apis/), 31 March 2021 | The request body encoding inferred from `content-type`; a vendor article, not reference documentation |
| A10 | AWS Lambda Developer Guide, [Invoking a Lambda function using an Amazon API Gateway endpoint](https://docs.aws.amazon.com/lambda/latest/dg/services-apigateway.html) | HTTP APIs as the version 2 API, the stage name at the beginning of the path for named stages, the function policy with `aws:SourceArn` |
| A11 | AWS Lambda Developer Guide, [Working with resource-based policies in Lambda](https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html) | Resource-based policies with explicit `Deny` statements and condition keys |
| A12 | AWS Lambda Developer Guide, [Defining Lambda function permissions with an execution role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html) | What the execution role is and that Lambda assumes it on invocation |
| A13 | IAM User Guide, [IAM identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html) | Role and assumed-role session ARN formats, unique IDs and their prefixes, name reuse |
| A14 | IAM User Guide, [Policy variables, principal key values](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#principaltable) | `aws:userid` of an assumed role (`role-id:caller-specified-role-name`), with the caller-specified name taken from `RoleSessionName` |
| A15 | IAM User Guide, [AWS global condition context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) | `aws:PrincipalArn` (the role ARN for a role session), `aws:SourceIdentity`, `aws:TokenIssueTime` |
| A16 | IAM User Guide, [IAM and AWS STS condition context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html) | `sts:RoleSessionName` in a role trust policy |
| A17 | IAM User Guide, [Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) | Union of identity and resource policies in one account, explicit deny, boundaries, SCPs |
| A18 | IAM User Guide, [Revoke IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html) | Revoking a role's sessions and the 30 second margin |
| A19 | IAM User Guide, [Changes that I make are not always immediately visible](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency) | Eventual consistency of IAM |
| A20 | IAM User Guide, [Elements of an AWS API request signature](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-signing-elements.html) | The `x-amz-date` header and the signature elements |
| A21 | IAM User Guide, [Authentication methods](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-authentication-methods.html) | The `Authorization` header and the query-string form of Signature Version 4, `X-Amz-Security-Token` |
| A22 | AWS STS API Reference, [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) | `RoleSessionName` and its pattern, session policies as an intersection, `DurationSeconds` up to 43200, `AssumedRoleUser` |
| A23 | AWS Lambda library for Go, test event [`events/testdata/apigw-v2-request-iam.json`](https://github.com/aws/aws-lambda-go/blob/main/events/testdata/apigw-v2-request-iam.json), branch `main` | The member names of `requestContext.authorizer.iam`; library source, not documentation, and its values are fictitious |
| A24 | IAM User Guide, [IAM JSON policy elements: Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html) | A negated operator such as `ArnNotLike` is true when the key is absent; `aws:SourceArn` is present only for a service acting on behalf of a resource |

## Open items and probes

No rule depends on an unprobed behavior except where it is stated as a precondition of the claim (AR-4, AR-15).

| ID | Item | Probe or decision needed | If the outcome differs |
|---|---|---|---|
| P1 | The members of `requestContext.authorizer.iam` in a `2.0` event for an `AWS_IAM` route called with assumed-role credentials; which member carries `role-id:session-name`; whether any member reports the session policy or the session's issue time | Deploy an HTTP API with one `AWS_IAM` route and a `2.0` Lambda proxy integration, call it with sessions created with and without a session policy, and record the event | AR-5 and AR-8 change the member names they read; a reported session policy replaces `unreported` (AR-11); a reported issue time gives F1 an observation time (AR-25) |
| P2 | Whether `rawPath` and `rawQueryString` carry the request-target unchanged for the forms AR-14 refuses (`%41`, `%2f`, `%2F`, `/./`, `/../`, `//`, `%C0%AF`, `+`, repeated and reordered parameters, an empty query), and which of them API Gateway refuses before invoking | Send each form through the custom domain and compare the event with the octets sent | Until it passes the adapter is not enabled (AR-15) |
| P3 | Header handling: white space around values, the separator of combined values, headers API Gateway adds or removes, and whether `content-encoding` and `transfer-encoding` reach `headers` | Send repeated and padded headers and record the event | AR-18's published normalization changes |
| P4 | Whether a resource-policy `Deny` of `lambda:InvokeFunction` with `ArnNotLike` on `aws:SourceArn` blocks every direct invocation, in the account and from others, without blocking API Gateway's invocation | Invoke the function directly from principals with identity-policy allows, then through the API | Until it passes the enforced claim does not hold (AR-4) |
| P5 | The management calls and fields that report a route's authorization type, an integration's payload format, the stages, the API mappings, the default-endpoint setting, a function URL, and a function's resource policy, with the permissions the configuration check needs | Read them for a configured API and function | AR-3's reads change; the conditions do not |
| P6 | How long an IAM policy change, and the revoke-sessions deny, takes to reach API Gateway's authorization | Change a policy and poll the route | The measured value becomes `L` (section 8) |
| P7 | Whether HTTP APIs accept query-string Signature Version 4 | Call a route with a presigned URL | None: AR-17 refuses it either way |
| P8 | Whether a body that is not base64-encoded reaches the function octet for octet, and which content types are base64-encoded | Send text bodies with non-UTF-8 octets and several content types | Rows with a body stay unsupported until it passes (AR-19) |
| P9 | AWS pages carry no release; a later revision can change a fact cited here | Re-read the sources at each profile revision and record the date | The affected rule is revised |
| O1 | The finding's "session-name policy" is read as the session-name rule of AR-10: a filter enforced by the trust policy that never adds identity. A stricter reading would require a non-`any` rule for every entry | Maintainer decision | AR-10 changes |
| O2 | How a failed configuration check is reported: AR-24 uses `DEFERRED` with `DEPENDENCY_UNAVAILABLE`, which fails closed but is not an outage | Maintainer decision | AR-24's row changes |
| O3 | The common adapter harness describes an HTTP request (`request` of `spec/v1.0/fixtures/adapters/README.md`); the AWS cases need a payload `2.0` event as input | Decided: the harness builds the event from the case's request and the `event` patch of the `aws/1` model of the [AWS cases README](../../fixtures/adapters/aws/README.md), starting from the sample event of `adapters/aws/events/` | Section 10's input form |
| O4 | No preflight of the execution role's permissions is defined; the Kubernetes profile has one for its executor account. An IAM simulation of the execution role against a forbidden action list would be the analogue | Maintainer decision and a probe of the simulation interface | A rule like the Kubernetes preflight is added |
| O5 | The `header_normalization_id` for AR-18 is chosen by the gateway, as for request-binding RB-25 (its open item O7) | Maintainer decision | A first-party identifier is defined |
| O6 | `/a?` and `/a` produce the same event (AR-14) | Settled by P2 | AR-14 refuses the empty query if the event can tell them apart |
| O7 | Draft §13.2 requires an envelope or a validator transfer for presentations larger than the header limit; this profile defines neither (AR-20) | Maintainer decision | An `adapter-envelope` form for HTTP APIs is added |
