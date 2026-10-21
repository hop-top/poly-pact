# Integration 09 — AWS IAM roles, temporary credentials, and policy boundaries

**Status:** Informative integration example for PACT Protocol v1.0. Organizations, identifiers, routes, requirements, and thresholds are fictional deployment choices. Excerpts are incomplete illustrations, not signed wire fixtures or a tested implementation. The gateway needs the described installed adapter; the named platform is not claimed to support PACT natively.

**Readiness review (2026-10-15):** Conditional design only. This narrative does not establish a live integration, interoperability, or end-to-end security result. Read the assumptions, components, and unresolved items before interpreting the successful exchange.


## Assumptions, required components, and unresolved gaps

**Review ID:** I09. Finding and component IDs refer to the companion handoff.md. These are editorial identifiers, not new protocol fields or registered reason codes.

### Assumptions

- The IAM-authorized API exposes authentic caller and exact request context to its trusted integration.
- Complete native policy authorizes the enrolled temporary role session and business route.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C02 | AWS-native authentication and authentic caller context. |
| C03 | Verified role-session/agent/key registry. |
| C07 | Pinned API Gateway mapping. |
| C08 | Actual metrics-endpoint enforcement. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Unresolved gaps

Shared open work: G01, G02, G04, G05, G07, G13, G24, G27. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Specific issues exposed here:

| Finding | Issue to resolve | Classification |
|---|---|---|
| G04 | Prove request binding survives the selected gateway transformations. | Profile |
| G21 | Define IAM caller/session mapping, executor identity, and supported AWS scope. Specified for this sample by the integration profile [`aws`](../profiles/aws/profile.md); its G21 closure map ties each AWS item to rules and cases. | Profile / coverage |

### Deliberate simplifications and limitations

- Only a custom IAM-authorized API is covered, not arbitrary direct AWS services.
- A downstream API needs an explicit actor/permission mapping; the integration role does not inherit caller permissions.

### Profile and fixtures

The integration profile [`aws`](../profiles/aws/profile.md) states the conformance claim behind this sample: an HTTP API whose route uses `AWS_IAM` authorization and a Lambda proxy integration at payload format `2.0`, served on the `$default` stage through one custom domain (rule AR-1); route R1 (`GET /metrics/operations`, action `metrics.operations.read`); the workload `aws:{account-id}:{role-arn}:unreported` of a dedicated role (rules AR-8, AR-9, AR-12); the execution role as a distinct executor (rule AR-22); and the fixture index of its section 10. The adapter cases are in [`fixtures/adapters/aws/`](../fixtures/adapters/aws/README.md), registered in the fixture manifest; the decisions table below names the case group or case for each row. Each case's input is a payload `2.0` event that the harness builds from a sample event, a role table, and a configuration-check result; the cases are not a deployed API.

### Validation still required

The cases cover forged identity inputs, wrong role, account, and session, request mutation in the event, the executor fallback, and a refusal by the handler after admission, at the adapter. These remain unvalidated:

- The preconditions of the enforced claim, which the profile leaves to probes on a deployed API: that `rawPath` and `rawQueryString` carry the request target unchanged (rule AR-15, probe P2), and that the resource-policy deny of rule AR-4 blocks every direct invocation of the function without blocking API Gateway (probe P4).
- The member names of the IAM context in a deployed `2.0` event, including which member carries `role-id:session-name` (probe P1), header handling (P3), the management reads of the configuration check (P5), and the IAM propagation bound `L` (P6).
- Native explicit deny, a route outside the role's permission, and expired temporary credentials: API Gateway refuses these before any event exists, so no case of the profile reaches them.
- The permissions of the execution role and of the handler's translation row, which the profile does not verify (open item O4), and the handler's permission check itself (C08).
- The refusal to issue a contract on a requirements request without IAM context (`AWS-09`), and the two validator rules of `AWS-13`, which are reserved and not landed.

No finding is closed by this narrative or by the fixture coverage above. Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

A production-observer agent reads operations metrics from Northstar's custom API hosted behind Amazon API Gateway. The protected method uses AWS IAM authorization. The agent runs with temporary credentials for its administrator-provisioned observation role.

The API integration additionally evaluates PACT before executing the business read. This example protects an IAM-authorized API method; it does not claim that adding a header makes S3 or every AWS service PACT-aware.

## Native authorization and enforcement

For an IAM-authorized API Gateway method, the caller signs its request using the supported AWS signing mechanism. API Gateway authenticates and authorizes the invocation through AWS controls. See [API Gateway IAM permissions](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html).

The agent's configured role permits only the intended operations-metrics route. Applicable identity/resource policies, permissions boundaries, session restrictions, and organization-level controls retain their AWS semantics, including relevant explicit denials. See [IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html). PACT cannot edit those policies or manufacture an STS session.

The API integration receives caller identity through authenticated AWS-generated context, with deployment-specific mappings pinned to the chosen API type: under the integration profile, the IAM context of the Lambda proxy event only (rules AR-5 and AR-6). An arbitrary client header containing an ARN is not native identity.

## Illustrative native permission

This partial identity-policy statement permits one method on the `$default` stage, the only stage the integration profile supports (rule AR-1). Complete trust, resource, organization, and boundary policies remain necessary.

```json
{
  "Effect": "Allow",
  "Action": "execute-api:Invoke",
  "Resource": "arn:aws:execute-api:ca-central-1:111122223333:metrics-api/$default/GET/metrics/operations"
}
```

The PACT requirements endpoint is separately authorized by the deployment. An agent also needs whatever native permission protects that endpoint; access to requirements does not imply access to the business method.

## Required profile and mapping

| Fact | Authoritative source | Integration profile |
|---|---|---|
| `/attributes/environment/principal_id` | Native AWS caller identity from the authenticated request context | The workload of the role session, such as `aws:111122223333:arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fproduction-observer:unreported` (rule AR-9); compared by `native-principal-binding-v1` (rule AR-26) |
| `/attributes/environment/workload_role` | Approved role/enrollment mapping; session-to-role resolution is verified | The role ARN of the role entry, selected by the role's unique ID (rules AR-8 and AR-25) |
| `/attributes/environment/account_id` | Configured account mapping reconciled with authenticated identity | The account of rule AR-8, which equals the API owner's account |
| `/attributes/delegation/authority_ref` | Native production-observation task authorization | Outside the profile: supplied by the deployment (C04; profile section 6) |
| `/attributes/runtime/isolation` | Required evidence from an approved runtime issuer | Outside the profile; attested-only, because no containment control is claimed (C16) |

The deployment decides which temporary sessions belong to the enrolled workload. Matching an agent-chosen role-session name is insufficient (rule AR-10). AWS signing credentials and the PACT holder key are different credentials with independently governed lifecycles (rule AR-12). The event reports neither the session policy nor the issue time of the session, so sessions of one role are one workload, and a rule that bounds the observation age of these paths, or asks for a status age below the IAM propagation bound `L`, is `DEFERRED` with `UNSUPPORTED_REQUIREMENT` (rules AR-11 and AR-25; profile section 8).

## Successful exchange

1. The agent receives temporary role credentials through its existing authorized AWS workload process. PACT does not issue them.
2. Using the authorized requirements route, it requests a contract for reading the operations metrics under the recognized observation purpose.
3. The gateway resolves the authenticated caller and enrolled key, maps the exact method/path/query/body, and returns its signed contract and nonce.
4. The agent prepares and signs the complete PACT presentation, then uses the supported AWS SDK/signer to sign the actual API invocation with that presentation attached.
5. API Gateway performs native IAM authentication and authorization. A denied invocation never reaches protected execution, whether or not the PACT presentation would otherwise be valid.
6. The trusted integration reconstructs the operation under its versioned mapping and validates PACT, including caller/task binding, evidence, freshness, and holds. It does not trust client-edited identity fields.
7. If admission and all native application conditions allow, the metrics read executes. Otherwise the integration blocks it.

The adapter must preserve enough exact request information for the PACT binding. If the selected API integration transforms path/query/body information so the baseline cannot be reconstructed reliably, the deployment must supply a declared equivalent adapter mapping before claiming enforced support. The integration profile reconstructs the operation from `rawPath`, `rawQueryString`, `headers`, and `body` of the event (rules AR-13 to AR-20), and the request line and headers together must fit the HTTP API limit of 10240 bytes, presentation included (rule AR-20).

AWS authentication metadata is validated through the native signing layer. PACT's header mapping includes consequential business headers while treating native credentials according to the draft's exclusions; the Signature Version 4 `authorization` header and every `x-amz-` and `x-amzn-` header are never covered (rule AR-18). The PACT receipt is not an AWS credential or signature.

## Decisions and failure variations

| Condition | Expected behavior | Profile case |
|---|---|---|
| Valid role session, permitted route, current evidence, correct task | Native IAM and PACT allow; execute | `adapters/aws/aws-01.own-role`, `adapters/aws/aws-12.handler-allows`, `adapters/aws/aws-11.declared` |
| Role tries a finance-metrics route outside its permission | Native IAM blocks invocation | None: API Gateway refuses before any event exists |
| Applicable explicit native deny | Deny remains effective regardless of reputation | None: API Gateway refuses before any event exists |
| Valid AWS request, wrong enrolled PACT key | PACT proof/binding blocks execution | Evaluation case `admission/old-holder-key`; an agent enrolled for another workload: `admission/agent-of-other-workload` |
| Profile names another account or role | Native comparison/context check fails: `native-principal-binding-v1` returns `FAIL` with `CONTEXT_MISMATCH` | Evaluation case `admission/wrong-principal` |
| Temporary credentials expire | Native authentication/authorization blocks access | None: API Gateway refuses before any event exists |
| Required PACT dependency unavailable | Defer in the integration; do not execute merely because IAM passed | `AWS-13`; a configuration check missing or older than `P`: `AWS-02` |
| Identity headers or query parameters naming another role or account | No effect; the event is evaluated as the session's own role | `adapters/aws/aws-01.forged-identity` |
| Session of a role without a role entry, of another account, or of a role recreated under the same name | Native denial with `CREDENTIAL_REJECTED` | `AWS-03` |
| Session name naming another agent, or outside the entry's session-name rule | The name never selects a workload; a mismatch is a native denial | `AWS-04` |
| IAM user, root user, federated user, or Amazon Cognito credentials | Native denial with `CREDENTIAL_REJECTED` | `AWS-05` |
| Query, path, or body changed or ambiguously encoded in the event | Context mismatch for a change after issuance; `INVALID_MESSAGE` for an ambiguous encoding | `AWS-07`, `AWS-08`; a payload `1.0` or REST-shaped event: `AWS-06` |
| Route without IAM authorization, `$default` route, other domain or stage | Native denial or `INVALID_MESSAGE` | `AWS-09`, `AWS-10` |
| Function lacks the deny of direct invocation, or has a function URL | No protected request served | `adapters/aws/aws-02.resource-policy-deny-missing`, `adapters/aws/aws-02.function-url-present` |
| Executor would run under the caller's role or a broader fallback role | `execution-identity-v1` returns `FAIL` with `EXECUTOR_MISMATCH`; no execution | `AWS-11` |
| PACT admits, the handler's permission check denies | Native denial, unchanged; no execution | `adapters/aws/aws-12.handler-denies` |

## Downstream permissions and learning boundary

This API's business authorization is the protected route plus its installed native task/resource policy. If a different deployment calls S3 or another AWS API, it must separately define the downstream actor and preserve that service's native restrictions. The integration's execution role does not automatically represent the original caller's permissions.

Successful request signing, IAM admission, and PACT admission add no positive task-performance weight. Qualified task outcomes can update contextual reputation. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, an IAM refusal or explicit deny is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, an expired temporary credential, rejected by AWS authentication, is a “Pre-authentication or transport failure” with no `OutcomeReport`, and the executed metrics read is “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`). Learning cannot alter role trust, request new native policies, bypass a boundary, or clear an explicit deny.

**PACT anchors:** §§2.3, 4, 6–12, 14–18.

## Primary references

- [AWS: API Gateway IAM permissions](https://docs.aws.amazon.com/apigateway/latest/developerguide/permissions.html)
- [AWS: IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS: Temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
