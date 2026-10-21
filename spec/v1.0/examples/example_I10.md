# Integration 10 — Kubernetes service accounts and namespace RBAC

**Status:** Informative integration example for PACT Protocol v1.0. Organizations, identifiers, routes, requirements, and thresholds are fictional deployment choices. Excerpts are incomplete illustrations, not signed wire fixtures or a tested implementation. The gateway needs the described installed adapter; the named platform is not claimed to support PACT natively.

This example is informative: it does not establish a live integration, interoperability, or an end-to-end security result.


## Assumptions, components, and limitations

Component IDs C01 to C16 are the components of section 4 of the integration profile [template](../profiles/TEMPLATE.md); they are editorial identifiers, not protocol fields or registered reason codes.

### Assumptions

- A controlled gateway maps the workload to a dedicated service account and authorized API credential.
- The complete cluster policy has no unintended additive grants to that identity.

### Required components

The shared baseline requires C01–C03, C05, C07, C09–C10, C13–C14, and the current policy/artifact registry portion of C12. These cover the enforced gateway, trusted native/identity adapters, evidence, task/request mapping, atomic exchange state, attributable records, holds, and protected storage. This scenario additionally requires or makes explicit:

| Component ID | Scenario-specific responsibility |
|---|---|
| C03 | Cluster/namespace/service-account/agent/key registry. |
| C02 | Audience-correct native token validation. |
| C07 | Resource/verb/namespace mapping. |
| C08 | Assigned-account executor without admin fallback. |

C11 and the full C12 lifecycle are needed wherever reputation or adaptation is used; an authorized current conservative baseline is still required without adaptive relaxation. C16 actual containment is required for the runtime/data-use guarantees claimed, not merely because a profile includes a runtime label.

### Deliberate simplifications and limitations

- The design is a gateway plus dedicated account, not universal interception or arbitrary impersonation.
- One RoleBinding cannot prove the absence of broader grants.

### Profile and fixtures

The integration profile [`k8s`](../profiles/k8s/profile.md) states the conformance claim behind this sample: one pinned cluster and the claimed namespace `operations` (rule KR-1); the caller's pod-bound service-account token, minted for the gateway audience and accepted only through a `TokenReview` (rules KR-2 and KR-4 to KR-8); the workload `k8s:{cluster-id}:system:serviceaccount:{namespace}:{name}` (rule KR-7); an executor that holds only that account's projected token, with no broader credential to fall back to (rule KR-11); the RBAC preflight of a forbidden list (rules KR-14 to KR-18); the gateway routes R1 (list) and R2 (get) of deployments in `operations`; and the fixture index of its section 10. The adapter cases are in [`fixtures/adapters/k8s/`](../fixtures/adapters/k8s/README.md), registered in the fixture manifest; the decisions table below names the case group or case for each row. Their native state states the answers of the API server, which the harness serves from an API server of its own; the cases are not a live cluster. The RBAC objects above are the fixture asset `adapters/k8s/rbac`.

### Limitations and open points

Open in every example: the enforced integration scope; native identity and the enrolled agent and key mapping; exact request binding and native translation; achievable source freshness and execution-time rechecks; native outcome and visibility mappings; executed end-to-end conformance evidence; privacy, retention, correction, and lineage operations; and transport, latency, capacity, and outage budgets. The draft already states many underlying security rules; profiles, implementations, and evidence still need to establish them. Open points specific to this example:

- Specify exact gateway-to-Kubernetes binding.
- Define token audience, broker privileges, account mapping, and complete RBAC scope. Specified for this sample by the integration profile [`k8s`](../profiles/k8s/profile.md); its requirement coverage table ties each Kubernetes item to rules and cases.

The cases cover Secrets reads, mutation, cluster-wide access, wrong cluster, account, and audience, account re-creation, broker over-privilege, executor fallback, additive grants found by the preflight, and native permission removal after admission, at the adapter. These remain unvalidated:

- A live cluster: the integration test of the adapter package runs only against a cluster that its environment names, with the RBAC objects above applied, and is skipped otherwise; the profile's sources are those of Kubernetes v1.37 (probe P1).
- Facts the profile leaves to probes on a cluster: whether a review's `uid` equals the account's `metadata.uid` (P2), token-authentication caching and how soon a deleted pod's token stops authenticating (P3, the bound `B`), how soon RBAC changes reach `SubjectAccessReview` answers (P4, the allowance `R`), and the verb authorized for `pods/exec` (P6).
- Grants outside the finite forbidden list, which the preflight does not detect (rule KR-18); authorizers that decide on `extra` (open item O5); a token minted for the gateway audience and an API server audience together (open item O3).
- Other pods and token Secrets of the registered account that the agent did not create (bypass path B7, open item O4): a deployment control of pod and Secret creation in the namespace.
- The refusal to issue a contract on a requirements request with a token of the wrong audience (`K8S-02`), and the status-limit rule of `K8S-13`, which are reserved and not landed.

Native IAM, approvals, resource policy, and execution remain responsibilities of the environment; the dependencies are not a proposal to move those subsystems into the PACT core.

## Situation

Northstar's release-observer agent inspects deployment status in the `operations` namespace. Its native Kubernetes service account may get and list deployments there. It cannot read Secrets, modify deployments, or administer the cluster.

An installed PACT-aware operations gateway mediates the agent's task requests. The agent authenticates to it as its dedicated Kubernetes service account, and the gateway's enrollment registry binds that account to the enrolled agent and key. A controlled executor runs as the same registered account and uses only that account's credential for downstream API calls (integration profile, rules KR-10 and KR-11).

## Native RBAC setup

The following illustrative objects are installed by an administrator, never by the PACT profile:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-observer
  namespace: operations
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: release-observer-binding
  namespace: operations
subjects:
  - kind: ServiceAccount
    name: release-observer
    namespace: operations
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: deployment-observer
```

The service account exists separately. The cluster's complete native policy must be checked for other grants to this identity; this RoleBinding alone does not prove an absence of broader grants. Kubernetes RBAC rules are additive and use native API resource/verb/namespace semantics. See [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

## Required profile and identity mapping

| Fact | Rule/source | Integration profile |
|---|---|---|
| `/attributes/environment/principal_id` | Equals registered `system:serviceaccount:operations:release-observer` mapping | The workload `k8s:{cluster-id}:system:serviceaccount:operations:release-observer`, such as `k8s:northstar-prod:system:serviceaccount:operations:release-observer` (rule KR-7); compared by `native-principal-binding-v1` (rule KR-21) |
| `/attributes/environment/cluster_id` | Equals the configured target cluster identity | The `cluster-id` of the cluster entry, never the API server address or a token's `iss` (rules KR-1 and KR-20) |
| `/attributes/environment/namespace` | Equals `operations` for this task | The namespace of the reviewed account, within the claimed set (rules KR-5 and KR-20) |
| `/attributes/delegation/authority_ref` | Current native release-observation task reference | Outside the profile: supplied by the deployment (profile section 6) |
| `/attributes/runtime/isolation` | Trusted required runtime evidence | Outside the profile; supplied by the deployment (profile section 6) |

The gateway authenticates the requesting workload independently of profile text and resolves its enrollment/key and allowed executor account. Service-account names are cluster/namespace-qualified; a same-named account in another cluster is not equivalent. A rule that asks for a status age below 60 s on these paths is `DEFERRED` with `UNSUPPORTED_REQUIREMENT` (profile section 8).

The gateway accepts a Kubernetes-issued token: the agent's pod-bound service-account token, minted for the gateway's own audience and validated by a `TokenReview` with that audience, never offline (rules KR-2, KR-4, and KR-6). A token intended only for that gateway is not automatically suitable for the Kubernetes API: the API server does not accept a token whose only audience is the gateway audience (rule KR-2), and the agent's pod holds no token for the API server (rule KR-8). See [Kubernetes authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/).

## Successful exchange

1. The workload authenticates to the operations gateway with its pod-bound service-account token for the gateway audience. The trusted registry resolves the enrolled agent/key on the dedicated service account of the pinned cluster.
2. The agent proposes listing deployments in `operations` for its approved release-status task.
3. The gateway issues a signed PACT contract bound to that operation and native identity mapping. The agent obtains required evidence and signs its presentation.
4. The gateway verifies all PACT requirements, purpose/task checks, freshness, status, nonce, and request binding. Passing checks produce `ADMISSIBLE`.
5. After its own native task authorization, the executor uses a valid credential for the registered service account to call the configured Kubernetes API:

```http
GET /apis/apps/v1/namespaces/operations/deployments HTTP/1.1
Host: <configured-Kubernetes-API-host>
Authorization: Bearer <API-valid-token-for-release-observer-service-account>
```

6. The Kubernetes API authenticates that account and evaluates current native authorization. Only the permitted list executes.
7. The gateway records admission, downstream authorization, and actual observed execution separately. Later operations need the appropriate fresh PACT exchange.

The executor does not fall back to a cluster-admin credential or arbitrary user impersonation. Any credential-brokering privilege is narrowly administered and cannot be selected by the agent through a profile field. Under the integration profile there is no brokering: the executor's only credential is the projected token of the registered account, the gateway account may only create reviews and read pods, and the RBAC preflight finds token minting, impersonation, Secret reads, and pod creation and exec denied to both accounts before any request is served (rules KR-3, KR-11, and KR-14). Tokens never enter PACT artifacts or reputation logs.

## Decisions and failure variations

| Request or condition | Expected behavior | Profile case |
|---|---|---|
| List deployments in `operations` for the approved task | Admit; native RBAC allows under the stated complete policy | `adapters/k8s/k8s-01.own-token`, `adapters/k8s/k8s-10.list`, `adapters/k8s/k8s-11.binding-present` |
| List deployments cluster-wide | No grant from the namespace Role; native authorization blocks. No gateway route maps a cluster-wide list, and a grant of one to the account fails the preflight, so no protected request is served until a later preflight passes | `adapters/k8s/k8s-08.cluster-list`; another namespace in the path: `adapters/k8s/k8s-10.other-namespace` |
| Read a Secret in `operations` | Native RBAC denies under the example policy. No gateway route maps it, and a grant of it fails the preflight | `adapters/k8s/k8s-08.secrets-get` |
| Patch a deployment using the list-bound presentation | PACT request binding fails; a fresh patch request still lacks the required native grant, and a grant of it fails the preflight | Evaluation case `admission/modified-action`; `adapters/k8s/k8s-08.aggregated-patch` |
| Agent changes cluster/namespace in its profile | Mapping/context comparison fails: `native-principal-binding-v1` returns `FAIL` with `CONTEXT_MISMATCH` | Evaluation case `admission/wrong-principal`; the identifiers differ: `adapters/k8s/k8s-03.other-cluster-workload`, `adapters/k8s/k8s-04.same-name-other-namespace` |
| Service-account credential unavailable or invalid | No downstream execution as the gateway's own broader identity: `UNKNOWN`, so `DEFERRED`, for a missing or refused executor token; `FAIL` with `EXECUTOR_MISMATCH` for any other credential | `K8S-07` |
| PACT passes, but native RBAC changed | The API's current native decision remains authoritative | `adapters/k8s/k8s-11.binding-removed`, `adapters/k8s/k8s-11.no-gateway-substitution` |
| Impersonation or authenticating-proxy headers naming another account | No effect; never forwarded | `adapters/k8s/k8s-01.impersonation-headers` |
| Token for another audience, with empty or wrong `status.audiences` | Native denial with `CREDENTIAL_REJECTED` | `K8S-02` |
| Token of another cluster | Native denial | `adapters/k8s/k8s-03.other-cluster-token` |
| Account outside the claimed namespaces, re-created under the same name, or not registered | Native denial with `CREDENTIAL_REJECTED` | `K8S-04` |
| Token not pod-bound, or an agent pod that holds a token for the API server | Native denial with `CREDENTIAL_REJECTED` | `K8S-05`, `K8S-06` |
| Gateway account allowed Secret reads, impersonation, or token minting | Claim invalid; no protected request served | `K8S-12` |
| Watch, selector, or `resourceVersion` in the gateway request | Binds into the target as sent and changes the operation; never forwarded | `K8S-10` |
| Preflight with an evaluation error, or the authorization API unavailable | `DEFERRED` with `DEPENDENCY_UNAVAILABLE` | `K8S-09`; review, pod read, or registry unavailable: `K8S-13` |

## Revocation, outcomes, and learning

The adapter documents service-account token expiry, native validation, authorization-cache behavior, and changes to task/enrollment bindings; the integration profile states them in its sections 8 and 9. A fresh PACT receipt does not renew a Kubernetes token. Native denial and required-source uncertainty remain blocking conditions.

Qualified release-observation outcomes may update reliability or task quality in this cluster, action, resource, purpose, and runtime context. Merely listing repeatedly under one task does not create independent positive task history. Section 14.5 maps them: the “PACT admission decision” (`ADMISSION`) and the “Native authorization allow” (`AUTHORIZATION`) carry zero weight, a refused Secret read or cluster-wide list is a “Native denial” (`AUTHORIZATION`, `FAILURE`, `none`) with zero weight, the permitted list is “Execution completed with data returned” (`EXECUTION`, `SUCCESS`, `reliability`), and task quality needs an “Independent assessment” (`QUALITY`, `task_quality`). Access to Secrets or mutation cannot be earned through reputation.

Learning can vary approved adaptive evidence requirements, but cannot install a RoleBinding, request cluster-admin privileges, broaden the executor mapping, or treat admission as a Kubernetes access token.

## Boundary demonstrated

PACT supplies verified agent context at the gateway; the actual Kubernetes call runs under the explicitly assigned service account and remains subject to native namespace/resource/verb controls.

**PACT anchors:** §§2.3, 4, 6–12, 14–18.

## Primary references

- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Kubernetes authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
