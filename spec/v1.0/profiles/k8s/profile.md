# PACT Kubernetes service-account caller and executor profile

This profile targets spec version 1.0 and wire version 0.1 and is a draft.

## Purpose and status

This is the integration profile ([`TEMPLATE.md`](../TEMPLATE.md)) for a PACT-aware operations gateway that authenticates agents by their Kubernetes service-account tokens and executes admitted operations against the Kubernetes API under the agent's registered service account, the scenario of [`example_I10.md`](../../examples/example_I10.md). It states how the gateway validates a caller's token and its audience, how cluster and namespace are pinned, which credential the executor uses and why no broader one exists to fall back to, and the RBAC preflight that must find a list of forbidden actions denied before any request is served. It covers the Kubernetes half of the cloud and Kubernetes caller and executor boundaries; the [AWS profile](../aws/profile.md) covers the other half, and the section "Requirement coverage" shows which rule answers which requirement. The machine-readable form is [`profile.json`](profile.json).

The profile adds no wire field and no protocol requirement. Where it and [`draft.md`](../../draft.md) differ, the draft governs. The uppercase requirement words have the meanings given in draft §3. The rules KR-1 to KR-24 are normative for a claim made under this profile, and the requirement cases carry the identifiers K8S-01 to K8S-13, which are also the identifiers of the negative cases of section 10. Shared rules are not repeated: identifiers, enrollment, and lifecycle are in [`identity-mapping.md`](../identity-mapping.md) (IM-1 to IM-29), request binding is in [`request-binding.md`](../request-binding.md) (RB-1 to RB-64), and observation and status times are in [`freshness.md`](../freshness.md). A rule below can be stricter than those documents, and none is weaker.

Every statement about Kubernetes has one of three bases. A label in square brackets, such as [K1], cites a kubernetes.io page read for this profile on 2026-10-16; the pages are those generated for Kubernetes v1.37, and the section "Sources" lists each one. *Profile* marks a requirement this profile places on the gateway or the deployment. *To probe* marks a fact that the pages read did not establish; the section "Open items and probes" names the probe, and every rule that rests on one fails closed whichever way the probe comes out. No statement here describes Kubernetes from memory.

## Profile header

| Field | Value |
|---|---|
| Profile name | `k8s`: Kubernetes service-account caller and executor |
| Target product and version | Kubernetes clusters with RBAC authorization [K9]; the API groups `authentication.k8s.io/v1` (`TokenReview` [K1], `SelfSubjectReview` [K3]) and `authorization.k8s.io/v1` (`SubjectAccessReview` [K10]); pod-bound projected service-account tokens [K4], [K5]. The pages read are those of the Kubernetes v1.37 documentation; a deployment records its cluster version and re-reads the pages for it (probe P1) |
| Spec version, wire version | `1.0`, `0.1` |
| Profile revision, date | `r1`, 2026-10-16 |
| Maintainer | PACT adapter maintainers |
| Reference documents | draft = `spec/v1.0/draft.md`; identity rules = [`identity-mapping.md`](../identity-mapping.md); request binding = [`request-binding.md`](../request-binding.md); freshness rules = [`freshness.md`](../freshness.md); scenario = [`example_I10.md`](../../examples/example_I10.md) |
| Mapping revision | `pact-k8s-1`: the identity inputs, the translation rows, and the preflight list below |

## Terms

| Term | Meaning in this profile |
|---|---|
| Cluster entry | The configured record of the one cluster the claim covers: the `cluster-id`, the API server URL, the trust anchors for the API server's TLS certificate, the gateway audience, and the claimed namespaces (KR-1). It changes only through the gateway's administrative controls (draft §4.2). |
| Gateway audience | The audience the gateway identifies itself as when it reviews a caller's token (KR-2). |
| Registered account | The service account registered for one agent: its namespace, name, and the `uid` recorded at enrollment (KR-7). It is both the caller principal and the executor identity. |
| Agent pod | A pod in which the agent runs as the registered account, holding a token for the gateway audience only (KR-8). |
| Executor | The component, in a pod of its own that runs as the registered account, that sends the downstream requests of an admitted operation with that pod's token for the API server (KR-11). |
| Gateway account | The service account the gateway itself uses, only to create `TokenReview` and `SubjectAccessReview` objects and to read pods (KR-3). |
| Preflight | The set of `SubjectAccessReview` checks of KR-14 to KR-17 that must all be denied. |
| Native denial | The result of `authenticate_native` when native authentication was evaluated and failed (draft §17.1), with the public reason `NO_CREDENTIAL` when the request carries no bearer token and `CREDENTIAL_REJECTED` otherwise. Its code is `INVALID_PROOF`. |

## Rules

### A. Cluster, audience, and accounts

**KR-1. One pinned cluster.** Every `TokenReview`, `SubjectAccessReview`, pod read, and downstream request goes to the API server of the cluster entry, over TLS verified against the entry's trust anchors. The cluster is never taken from a token's `iss` claim, a request, an AgentProfile, or a signed claim. The `cluster-id` is the configured identifier of the cluster, not the text of its API server address (identity-mapping §3.3). The claimed namespaces are a finite set of the entry; a namespace outside it is not served. *Basis: profile.*

**KR-2. Gateway audience.** The gateway audience is an HTTPS URI under the deployment's control. It is not one of the audiences the API server accepts for service-account tokens: `--api-audiences` defines those, and when it is not set with `--service-account-issuer` the control plane defaults to a list that holds only the issuer URL [K6]. Because the service-account token authenticator validates that tokens used against the API are bound to at least one of those audiences [K6], a token whose only audience is the gateway audience is not accepted by the API server. Whether a token minted for several audiences, the gateway's and an API server audience, can reach the gateway is open item O3. *Basis: source [K6]; profile.*

**KR-3. Gateway account privileges.** The gateway account may create `tokenreviews` and `subjectaccessreviews` and get `pods` in the claimed namespaces, and nothing else; the default ClusterRole `system:auth-delegator` "Allows delegated authentication and authorization checks" [K9] covers the first two. The gateway account's credential is never sent in a downstream request and never reaches the executor. The preflight of KR-14 runs for the gateway account too. *Basis: source [K9]; profile.*

### B. Caller identity (`authenticate_native`)

**KR-4. Token review.** The caller's token is the bearer token of the `Authorization` header (a credential header, never covered: RB-20). The gateway creates a `TokenReview` with `spec.token` and `spec.audiences` set to exactly one entry, the gateway audience. `spec.audiences` lists "the identifiers that the resource server presented with the token identifies as", and without it "the audience will default to the audience of the Kubernetes apiserver" [K1]. The token is accepted only when `status.authenticated` is `true`, `status.error` is empty, and `status.audiences` is not empty and contains the gateway audience: a client that sets `spec.audiences` "should validate that a compatible audience identifier is returned in the `status.audiences` field", and an empty `status.audiences` with `authenticated` true means "the token is valid against the audience of the Kubernetes API server" [K1]. Anything else is a native denial with `CREDENTIAL_REJECTED`; a request with no bearer token is `NO_CREDENTIAL`. Offline JWT validation never replaces the review: a service that verifies a token offline does not verify that its bound claims are current, and clients that require that assurance must use the `TokenReview` API [K4]. *Basis: source [K1], [K4]; profile.*

**KR-5. Service accounts only.** `status.user.username` has the form `system:serviceaccount:{namespace}:{name}` and `status.user.groups` contains `system:serviceaccounts` and `system:serviceaccounts:{namespace}`, the user name and groups of a service account [K3], with `{namespace}` a claimed namespace. Any other user, such as an OpenID Connect user, an X.509 client, or a static or webhook token user, is a native denial with `CREDENTIAL_REJECTED`; an OpenID Connect user belongs to the `oauth` namespace of identity-mapping §3.3 and is outside this profile. *Basis: source [K3]; profile.*

**KR-6. Pod-bound tokens only.** `status.user.extra` carries `authentication.kubernetes.io/pod-name` and `authentication.kubernetes.io/pod-uid`, each with one value, as the review of a pod-bound token reports them [K4]. A token without them is a native denial with `CREDENTIAL_REJECTED`. A pod-bound token is invalidated when its pod is deleted, and deleting a pod expires its bound tokens [K4], whereas a token held in a Secret can be one that never expires [K4]. The pod name and the node name are never identity (identity-mapping §3.3); the pod is used only for KR-8. *Basis: source [K4]; profile.*

**KR-7. Identifier and name reuse.** The workload, which is also the principal (identity-mapping §3.4), is `k8s:{cluster-id}:system:serviceaccount:{namespace}:{name}`. The registered account records a `uid`, and `status.user.uid` must equal it: `uid` "identifies this user across time. If this user is deleted and another user by the same name is added, they will have different UIDs" [K2]. A service account deleted and created again under the same name is therefore refused until an administrator records the new `uid`; this is option (a) of IM-6. Whether `status.user.uid` equals the service account's `metadata.uid` is *to probe* (P2); the administrator records the value that a review of the account's token reports. A mismatch is a native denial with `CREDENTIAL_REJECTED`. *Basis: source [K2]; profile; to probe (P2).*

**KR-8. The agent pod holds no API token.** By default Kubernetes provides a pod with the credentials of its service account [K7]. For each evaluation the gateway reads the pod named by `pod-name` in the caller's namespace, with no `resourceVersion`, which returns data at the most recent resource version [K13], and requires: its `metadata.uid` equals `pod-uid`; its `spec.serviceAccountName` names the registered account; its `spec.automountServiceAccountToken` is `false`, which takes precedence over the service account's setting [K6]; and every `serviceAccountToken` source of its projected volumes names the gateway audience, because the audience defaults to the identifier of the API server when it is omitted [K5]. A failure is a native denial with `CREDENTIAL_REJECTED`, and a pod read that cannot complete is `DEFERRED`. The rule keeps a token for the API server out of the agent's own pod, so the agent cannot reach the API directly from there (section 5, B1). A token Secret mounted into the pod is not detected, because the gateway account has no access to Secrets; section 9 records it (open item O4). *Basis: source [K5], [K6], [K7], [K13]; profile.*

**KR-9. No forwarded identity.** The gateway ignores for identity, removes before `authorize_native` and execution, and never forwards the impersonation headers `Impersonate-User`, `Impersonate-Uid`, `Impersonate-Group`, and `Impersonate-Extra-(extra name)` [K12], the authenticating-proxy headers such as `X-Remote-User`, `X-Remote-Group`, and `X-Remote-Extra-` [K3], and every other header that names a user (IM-1). The executor never sets an impersonation header, and the preflight denies impersonation to the registered account and the gateway account (K-F5). *Basis: source [K3], [K12]; profile.*

**KR-10. Enrollment.** `resolve_agent_binding` takes the realm, the workload of KR-7, and the agent ID that the presentation names, and returns that agent's enrollment on the workload, or `UNKNOWN` when there is none; the workload alone never names an agent. One registered account serves one agent: a workload with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states, and shared accounts are unsupported (IM-19; section 6). The holder key is bound only by enrollment (IM-21): no service-account token, Secret, or certificate enrolls or certifies it. *Basis: profile.*

### C. Executor and native authorization

**KR-11. Executor credential.** The executor runs in its own pod whose `spec.serviceAccountName` is the registered account. Its only credential is the token of a projected `serviceAccountToken` source whose audience is the API server's identifier (the default when the field is omitted [K5]), with an `expirationSeconds` of at least 600 and by default 3600 [K5], which the kubelet refreshes before it expires [K4]. No kubeconfig, token Secret, client certificate, credential plugin, or other token is present in the executor, and the gateway account's credential never reaches it (KR-3). The executor identity class is `dedicated-role` (draft §17.5), and `execution-identity-v1` returns `PASS` only when a `SelfSubjectReview`, which reports how the cluster maps the authentication information of its caller [K3], made with the executor's token names the registered account with its recorded `uid`. A token that is missing, unreadable, or refused makes the executor indeterminate: `UNKNOWN`, which yields `DEFERRED`. Any other identity is `FAIL` with `EXECUTOR_MISMATCH`. There is no cluster-admin or other broader credential to fall back to by construction. *Basis: source [K3], [K4], [K5]; draft §17.5; profile.*

**KR-12. Native authorization with the original principal.** The registered account is both the principal and the executor identity, so the API server's authorization of the downstream request is `authorize_native` with the original principal (draft §17.5). All parts of an API request must be allowed by some authorization mechanism; if every module has no opinion the request is denied, and a deny is a 403 response [K8]. A native denial is final (draft §2.3), and PACT admission grants nothing the API server denies. *Basis: source [K8]; draft §2.3, §17.5.*

**KR-13. Translation rows.** Each row's downstream request has the constant origin of the cluster entry, a constant method, and a constant path in the form `/apis/GROUP/VERSION/namespaces/NAMESPACE/RESOURCETYPE` or `.../RESOURCETYPE/NAME` [K13], whose namespace is a constant of the row and whose name is the row's path parameter as bound (RB-49). The row sends no query: no `watch`, with which Kubernetes calls a `GET` a watch and not a get [K13], no `resourceVersion`, no `limit` or `continue`, and no label or field selector (RB-50). Its headers are the executor's `Authorization` header, a constant `Accept: application/json`, and nothing copied from the client (RB-51). `limit` and `continue` are the paging parameters of a list [K13]; the row sets neither, and a response that nonetheless carries a `continue` token is an error, after which nothing more is fetched. *Basis: source [K8], [K13]; profile.*

### D. RBAC preflight

**KR-14. Forbidden list.** For the registered account and for the gateway account, the preflight asks the API server, with one `SubjectAccessReview` per row and namespace, whether each action below is allowed. In `resourceAttributes`, an empty `namespace` means all namespaces for a namespaced resource, and `*` means all for `group`, `resource`, and `verb` [K11]. K-F1, the `patch` verb of K-F3, and the deployments row of K-F4 carry the three cases that example I10 names: a Secret read, a deployment patch, and a cluster-wide list. The other rows, verbs, and resources are additions of this profile (open item O1).

| ID | Action | `verb` | `group` | `resource` (`subresource`) | `namespace` | Why it is forbidden |
|---|---|---|---|---|---|---|
| K-F1 | Read Secrets | `get` | `""` | `secrets` | each claimed namespace, and `""` | Example I10; anyone who can read a token Secret can authenticate as its service account [K3] |
| K-F2 | Read Secrets by list or watch | `list`, `watch` | `""` | `secrets` | each claimed namespace, and `""` | `get`, `list`, and `watch` can all return the full details of a resource [K8] |
| K-F3 | Change deployments | `patch`, `update`, `create`, `delete`, `deletecollection` | `apps` | `deployments` | each claimed namespace | Example I10 names `patch`; the other verbs change deployments as well [K8] |
| K-F4 | List across the cluster | `list` | `apps`, and `""` | `deployments`, and `namespaces` | `""` | Example I10 names a cluster-wide list; `""` asks for all namespaces [K11] |
| K-F5 | Impersonate | `impersonate` | `""`, and `authentication.k8s.io` | `users`, `groups`, `serviceaccounts`; `uids` | `""` | Impersonation acts as another user, and the group, UID, and extra headers each require `Impersonate-User` [K12]; the verb applies to users, groups, and service accounts [K8], and UIDs are under `authentication.k8s.io` [K12] |
| K-F6 | Mint a service-account token | `create` | `""` | `serviceaccounts` (`token`) | each claimed namespace, and `""` | The TokenRequest subresource of a ServiceAccount issues time-bound tokens for it [K4], created by `POST /api/v1/namespaces/{namespace}/serviceaccounts/{name}/token` [K14]; a new token would bypass KR-8 and KR-11 |
| K-F7 | Run a pod | `create` | `""` | `pods` | each claimed namespace | A user who can run arbitrary pods in a namespace can use its service accounts and mount its Secrets [K8] |
| K-F7a | Exec into a pod | `get`, `create` | `""` | `pods` (`exec`) | each claimed namespace | A command in the executor's pod reaches its token; both verbs are checked because the verb the API server authorizes for `exec` was not established (P6) |
| K-F8 | Escalate through RBAC | `escalate`, `bind` | `rbac.authorization.k8s.io` | `roles`, `clusterroles` | `""` | The verbs that allow editing roles and bindings beyond one's own permissions [K8], [K9] |
| K-F9 | Everything | `*` | `*` | `*` | `""` | The super-user grant that `cluster-admin` gives [K9] |

**KR-15. Preflight inputs.** `spec.user`, `spec.uid`, and `spec.groups` of each review are those the API server reports for the account: for the registered account, those of the most recent successful `TokenReview` of its token (KR-4); for the gateway account, those of a `SelfSubjectReview` made with its own token [K3]. A review that names a user without groups asks "What if User were not a member of any groups" [K10], so a review without the account's groups is not a preflight. `spec.extra` is not set (open item O5). *Basis: source [K3], [K10]; profile.*

**KR-16. Preflight results.** A row passes when `status.allowed` is `false` and `status.evaluationError` is empty. `status.denied` is not required: RBAC has no deny rules [K9], and a request on which every authorizer has no opinion is denied [K8]. `status.allowed` `true` for any row makes the claim invalid for that account: no protected request of an agent of a failing registered account is served, and no protected request at all when the gateway account fails, until a later preflight passes. An `evaluationError`, or a review that fails, leaves the preflight not established: an error means that the authorizer could not evaluate everything it should have, for example a missing role, even when it still reached a decision [K10], so the answer may not reflect the grants that apply. *Basis: source [K8], [K9], [K10]; profile.*

**KR-17. Preflight timing.** The preflight runs before the first protected request, at least every `P` seconds, and after every change to the registered accounts or the cluster entry. A protected request is served only when the last completed preflight of its registered account and of the gateway account passed and is not older than `P`; otherwise the result is `DEFERRED` with `DEPENDENCY_UNAVAILABLE` (open item O2). Grants can appear between two preflights: a new ClusterRole that matches an aggregated ClusterRole's selector adds its rules to that role [K9], and an authorization webhook can cache decisions for a configured time [K8]. The reference configuration, an illustrative policy choice and not a recommended threshold, is `P` = 300 s, with a propagation allowance `R` = 60 s (probe P4). *Basis: source [K8], [K9]; profile; to probe (P4).*

**KR-18. What the preflight does not prove.** The preflight shows that the listed actions are denied for the listed accounts when it ran. It does not show that no other grant exists: RBAC permissions are purely additive [K9], and one Role and RoleBinding cannot prove the absence of broader grants (example I10). Absence-of-grants proofs from a manifest are unsupported (section 6). *Basis: source [K9]; profile.*

### E. Results, native claim, and principal binding

**KR-19. Results.** The checks run in this order for each request: token review (KR-4 to KR-7), agent pod (KR-8), preflight age (KR-17), mapping (request-binding), enrollment (KR-10), and, for an admitted operation, the executor (KR-11). Each result uses the codes of draft §13.4 and the decisions of draft §11.4.

| Condition | Where | Decision | Code | Transport result |
|---|---|---|---|---|
| No bearer token | `authenticate_native` | native denial | `INVALID_PROOF` | 401, public reason `NO_CREDENTIAL` |
| Review not authenticated, wrong or empty `status.audiences`, not a service account, namespace not claimed, not pod-bound, `uid` mismatch, agent pod check failed | `authenticate_native` | native denial | `INVALID_PROOF` | 401, public reason `CREDENTIAL_REJECTED` |
| `TokenReview` or pod read cannot complete | `authenticate_native` | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503; no receipt |
| No passing preflight within `P`, a failed preflight, or a preflight not established | gateway | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503 (open item O2) |
| Workload not enrolled for the named agent, or `REVOKED` | `resolve_agent_binding` | `INADMISSIBLE` | `INVALID_PROOF` | 401 |
| `COMPROMISED` binding | `resolve_agent_binding` | `INADMISSIBLE` | `SECURITY_HOLD` | 403 |
| Agent enrolled for another workload | validator | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| A workload with more than one enrollment in force, a configuration error (KR-10) | `resolve_agent_binding` | As identity-mapping §5 states (IM-19) | As identity-mapping §5 states (IM-19) | The status of that code (draft §13.4) |
| Enrollment registry cannot answer | `resolve_agent_binding` | `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503 |
| Workload of the actual request differs from the workload bound at contract issuance (KR-21) | validator, `operation_digest` | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| Presented `principal_id` differs from the workload of KR-7 (KR-21) | validator, `native-principal-binding-v1` | `INADMISSIBLE` | `CONTEXT_MISMATCH` | 403 |
| Executor token missing or refused | `execution-identity-v1` | `UNKNOWN`, `DEFERRED` | `DEPENDENCY_UNAVAILABLE` | 503; not executed |
| Executor identity other than the registered account | `execution-identity-v1` | `FAIL` | `EXECUTOR_MISMATCH` | not executed |
| API server denies the downstream request | `authorize_native` | native denial | none | not executed; native error |

The public error never says which identity condition failed (draft §13.4). A `DEFERRED` result before authentication completed carries no receipt, as in the [mTLS profile](../mtls/profile.md) (its open item O8).

**KR-20. Native claim.** The approved native paths for `read_native_claim` are `/attributes/environment/principal_id`, the workload identifier of KR-7; `/attributes/environment/namespace`, the namespace of the reviewed account; and `/attributes/environment/cluster_id`, the `cluster-id` of the cluster entry. Any other path returns `UNSUPPORTED_REQUIREMENT`. For the first two the source observation time is the token's `iat` claim, read from the token only after the review authenticated it (the token is a signed JWT [K3], and its payload carries `iat` [K6]), and the status time is the time of the review minus the declared bound `B` (section 8, F1). For `cluster_id` both times are the time of the evaluation (F3). *Basis: source [K3], [K6]; profile.*

**KR-21. Principal binding.** The workload identifier at contract issuance is bound by the contract's `operation_digest` and compared by the validator with the identifier of the actual request (draft §9.1, §11.3 step 5). The baseline check `native-principal-binding-v1`, which the validator evaluates (draft §17.5), compares the presented `/attributes/environment/principal_id` with the identifier of KR-7 and returns `FAIL` with `CONTEXT_MISMATCH` when they differ. A refreshed token of the same account keeps the identifier and passes. The gateway implements neither comparison. *Basis: draft §9.1, §11.3, §17.5; profile.*

**KR-22. Timeouts.** Every review and pod read has a client time limit, and no evaluation waits beyond its deadline (draft §12.2; freshness §5). *Basis: profile.*

**KR-23. Gateway endpoints.** The PACT endpoints of draft §13.2 that require native authentication, such as `POST /pact/v0.1/requirements`, are served on the same listener and authenticate through KR-4 to KR-10. *Basis: profile.*

**KR-24. Request binding.** The gateway is an ordinary HTTPS server, and the baseline binding of [`request-binding.md`](../request-binding.md) applies to its requests without change, including the refusal of ambiguous encodings and dot segments with `INVALID_MESSAGE` (draft §10.2). *Basis: draft §10.2.*

## 1. Claim scope

The operations gateway evaluates PACT in its own request path (draft §4.4), claims `PACT Gateway 0.1` and `PACT Validator 0.1` in `enforced` mode over the `header` transport, and is a partial role implementation (draft §22.1) because it claims neither Reputation nor Learning. It declares the `full` conformance profile and the `https` transport profile, both at version 0.1; the roles it does not claim are supplied by connected services of the deployment.

| Item | Value |
|---|---|
| Deployment form (draft §4.4) | in-gateway |
| Roles claimed (draft §22.1) | `PACT Gateway 0.1`, `PACT Validator 0.1` |
| Partial role statement (draft §22.1) | Partial role implementation: `PACT Reputation 0.1` and `PACT Learning 0.1` are not claimed |
| Mode (draft §2.3) | `enforced` |
| Observation disclosure (draft §22.1) | not applicable: mode is `enforced` |
| Presentation transports (draft §13.2) | `header` |
| Conformance profile(s) (draft §21, §22.1) | `full` 0.1 |
| Transport profile(s) (draft §13, §13.3) | `https` 0.1 |

| Adapter `protocol` | Adapter `version` | Adapter `mapping_revision` (`GatewayMetadata.adapters`, draft Appendix A) |
|---|---|---|
| `kubernetes-serviceaccount` | `authentication.k8s.io/v1+authorization.k8s.io/v1` | `pact-k8s-1` |

The version names the two API group versions the adapter calls. `pact-k8s-1` names the rules of this profile, including the forbidden list of KR-14; a change to any of them is a new mapping revision.

## 2. Protected routes and actions

Two reference routes are claimed, the deployment-status reads of example I10 in the `operations` namespace. Both are gateway routes; the namespace is a constant of each row and never comes from the request. `{cluster-id}` comes from the cluster entry (RB-40).

| ID | Route pattern | Method | Action | Resource mapping |
|---|---|---|---|---|
| R1 | `/api/v1/deployments` | `GET` | `deployments.list` | `https://k8s.example/clusters/{cluster-id}/apis/apps/v1/namespaces/operations/deployments`. No query parameter is read, no body is accepted, and no header is allowlisted. Translation: `GET /apis/apps/v1/namespaces/operations/deployments` (KR-13) |
| R2 | `/api/v1/deployments/{name}` | `GET` | `deployments.get` | `https://k8s.example/clusters/{cluster-id}/apis/apps/v1/namespaces/operations/deployments/{name}`; `name` is 1 to 253 characters of lowercase letters, digits, `-`, and `.`, beginning and ending with a letter or digit (a profile grammar under RB-34). Translation: `GET /apis/apps/v1/namespaces/operations/deployments/{name}` (KR-13) |

## 3. Enforcement points

The required functions run in request order inside the gateway, except that native authorization and execution run in the API server on the executor's request; the other four adapter functions of draft §17.1 are listed as supporting rows.

| Order | Function | Where it runs | Run by | Notes |
|---|---|---|---|---|
| 1 | `authenticate_native` | Gateway authentication stage: `TokenReview` at the pinned API server and the agent pod check (KR-4 to KR-9) | Gateway implementer and adapter owner | Produces the principal and workload `k8s:{cluster-id}:system:serviceaccount:{namespace}:{name}` in the realm of the cluster entry |
| 2 | `map_operation` | Gateway mapping stage, mapping revision `pact-k8s-1`, baseline binding (KR-24) | Adapter owner | Rows R1 and R2 |
| 3 | PACT evaluation | In-gateway validator in the same request path | Gateway implementer | After mapping, only while a passing preflight is within `P` (KR-17) |
| 4 | `authorize_native` | The API server's authorization of the executor's request under the registered account (KR-12) | Cluster administrator | A native denial is final (draft §2.3) |
| 5 | Execution | The executor's request of the translation row (KR-11, KR-13) | Resource owner | Executor class `dedicated-role` |
| support | `resolve_agent_binding` | Enrollment registry lookup for the realm, the workload, and the agent the presentation names (KR-10) | Gateway implementer | Supplies the enrolled agent, operator, holder key, and status |
| support | `read_native_claim` | Adapter, approved paths of KR-20 only | Adapter owner | Returns values with the times of KR-20 |
| support | `check_context` | Installed check `execution-identity-v1` (KR-11) | Gateway implementer | No other named check runs here: `native-principal-binding-v1` is evaluated by the validator (KR-21). The release-task and runtime checks of example I10 are supplied by the deployment |
| support | `record_outcome` | Gateway outcome writer, after the executor's response | Gateway implementer | Admission, the API server's decision, and the observed execution are recorded separately (example I10) |

## 4. Native dependencies

Eleven of the sixteen components are used, and each of the other five carries the reason it does not apply. The adapter of these rules is the package `go/adapters/k8s`, built with `k8s.New` from a `k8s.Config` that names the gateway's realm, the cluster entry (cluster id, API server URL and trust anchors, gateway audience, claimed namespaces), the registered accounts, the gateway account's token, the executors, and the enrollment registry; its `k8s.Executor` sends the translation rows with the registered account's projected token and accepts no other credential. It uses the standard library only and validates no token offline (KR-4).

| ID | Responsibility | Needed when | Provided by | Owner | Status or reason not used |
|---|---|---|---|---|---|
| C01 | PACT enforcement gateway/validator | baseline | The operations gateway and its in-gateway validator | Gateway implementer | To be supplied |
| C02 | Native authentication and claim adapters | baseline | `TokenReview` at the pinned API server, the agent pod check, the adapter of these rules, and the gateway account with the privileges of KR-3 | Cluster administrator and adapter owner | The API exists; the adapter is `go/adapters/k8s`; the gateway account with the privileges of KR-3 is to be supplied |
| C03 | Enrollment, issuer trust, and key lifecycle | baseline | Enrollment registry (a registry contract and an in-memory backend exist in `go/adapter/enroll`), administrator-run enrollment, the registered accounts with their `uid` | IAM and security owner | Registry contract exists; production store to be supplied |
| C04 | Native delegation and task authority | delegated or task execution | The deployment's native release-observation task reference (example I10) | Resource owner | Not supplied by this profile; the `authority_ref` field stays with the deployment (section 6) |
| C05 | Evidence and authoritative status sources | baseline | The API server (reviews, pod reads, preflight), the enrollment registry, the cluster entry | Cluster administrator and adapter owner | The API exists; the rest to be supplied |
| C06 | External approval, exception, or PIM workflow | required external authorization | none | none | Not used: the read routes need no external approval |
| C07 | Purpose and exact operation mapper | baseline | Mapper and translation rows of R1 and R2 (KR-13) | Adapter owner | The mapper is `MapOperation` of `go/adapters/k8s` and the translation rows are `k8s.Executor` |
| C08 | Native resource executor and authorization | the actual resource operation | The executor under the registered account (KR-11) and the API server's authorization (KR-12) | Cluster administrator and resource owner | The API exists; the executor is `k8s.Executor`, and its pod running as the registered account is to be supplied |
| C09 | Durable atomic exchange state | baseline | Replay and receipt store of the gateway | Gateway and platform owner | To be supplied |
| C10 | Task attribution and outcome qualification | baseline | Gateway outcome writer and the API server's audit log | Resource owner | To be supplied |
| C11 | Contextual reputation service | reputation | none | none | Not used: `PACT Reputation 0.1` is not claimed |
| C12 | Policy/artifact registry and learning lifecycle | baseline: current authorized policy/artifact registry; adaptation: full lifecycle | Policy registry holding the base requirements | Platform owner | To be supplied; registry only, no adaptation lifecycle |
| C13 | Revocation and security holds | baseline | Enrollment status, the hold store, and native token invalidation by pod deletion [K4] | Security and IAM owner | To be supplied; native invalidation exists |
| C14 | Protected evidence and audit storage | baseline | Access-controlled audit store; no token enters PACT artifacts, logs, or reputation records (example I10) | Security and data owner | To be supplied |
| C15 | Native transactions, budgets, and side-effect control | relevant business transactions or limits | none | none | Not used: read routes, no transactions or budgets |
| C16 | Runtime authority and containment | claimed runtime or data-use guarantees | none | none | Not used: no runtime attestation or data-use guarantee is claimed; the runtime evidence of example I10 stays attested-only (draft §17.4) |

## 5. Alternative and bypass paths

Eight other ways to reach the protected resources or the identity input are listed: five `closed`, one `equivalently-enforced`, and two `out-of-claim`. The cases named as evidence are in section 10.

| ID | Path | Disposition | Evidence |
|---|---|---|---|
| B1 | The agent calls the Kubernetes API directly with a token of the registered account from its own pod | `closed` | KR-8 keeps every token for the API server out of the agent pod, and the preflight denies minting a token (K-F6) and reading token Secrets (K-F1, K-F2) to the registered account; cases `K8S-06`, `K8S-08` |
| B2 | The agent obtains the executor's token, by exec into the executor pod or by running a pod of its own as the registered account | `closed` | The preflight denies running pods (K-F7), exec into pods (K-F7a), and token minting (K-F6) to the registered account; case `K8S-08` |
| B3 | Identity or impersonation headers sent through the gateway | `closed` | KR-9 ignores and removes them, and the preflight denies impersonation (K-F5); case `K8S-01` |
| B4 | The gateway account's credential or another broader credential used for the downstream request | `closed` | KR-3 and KR-11: the executor holds only the registered account's projected token, and the preflight runs for the gateway account as well; cases `K8S-07`, `K8S-12` |
| B5 | A token from another cluster, or a request to another API server | `closed` | KR-1 and KR-4: every review goes to the pinned API server with the gateway audience; case `K8S-03` |
| B6 | The PACT endpoints of draft §13.2 that require native authentication | `equivalently-enforced` | KR-23: they authenticate through KR-4 to KR-10; case `K8S-02` |
| B7 | Other pods running as the registered account, created by principals other than the agent, such as administrators and controllers, and token Secrets of the account | `out-of-claim` | The gateway cannot inventory every creator of pods or Secrets in the namespace; excluded in section 6 and recorded in section 9 (open item O4) |
| B8 | Node-level access to the tokens of pods on a node, and other users of the cluster acting on the same resources | `out-of-claim` | Not agents of this claim and not mediated by the gateway; excluded in section 6 |

## 6. Unsupported forms

The first three rows come from the design choice of sample I10, a dedicated-account executor and a declared namespace scope, and the wider claim it does not establish: universal interception, arbitrary impersonation, or the absence of other additive grants shown from one YAML snippet. The other rows come from the rules and sections of this profile.

| Unsupported form | Source | Why it is not established |
|---|---|---|
| Universal interception of Kubernetes API access | I10: "Universal interception" | Only requests through the gateway's routes are claimed; direct API access by the agent is closed only for its own pod (KR-8; section 5, B7) |
| Arbitrary impersonation | I10: "arbitrary impersonation" | The executor never impersonates, and the preflight denies the verb (KR-9, K-F5) |
| Absence of other additive grants from one YAML snippet | I10: "absence of other additive grants from one YAML snippet" | RBAC is additive [K9]; the preflight checks a finite list at a time (KR-18) |
| Users other than service accounts: OpenID Connect, X.509, static, and webhook token users | Section 7, KR-5 | Only service accounts map to a workload |
| Legacy token Secrets, unbound tokens, and offline JWT validation | KR-4, KR-6 | Only reviewed, pod-bound tokens are accepted |
| Shared service accounts | Section 7, KR-10 | One registered account per agent, the default of identity-mapping §5 (IM-19); a workload with more than one enrollment in force is a configuration error (KR-10) |
| More than one cluster per cluster entry, and namespaces outside the claimed set | KR-1 | Cluster and namespace are pinned |
| Watch, selectors, paging, and every verb other than `get` and `list` of the rows | KR-13 | The rows send fixed requests only |
| Authorization through webhooks or modes whose inputs the preflight does not reproduce | KR-15, KR-17 | The preflight sets no `extra` and a webhook can cache decisions (open item O5) |
| Any field of the I10 profile other than those of KR-20: the delegation `authority_ref` and the runtime isolation evidence | Section 3 | Those sources are supplied by the deployment outside this profile |
| Any route other than R1 and R2 | Section 2 | Not listed in section 2, so not claimed |
| Pods and Secrets of the registered account created by others; node-level access; other users | Section 5, B7 and B8 | Excluded by their `out-of-claim` disposition |

## 7. Identity mapping

Each agent has a dedicated service account in a claimed namespace of the pinned cluster, enrolled by an administrator with its `uid` and bound to the holder key in the enrollment registry. All other rules are those of [`identity-mapping.md`](../identity-mapping.md).

| Item | This profile |
|---|---|
| Native identifier namespaces (user, client, workload) | Workload only: `k8s:{cluster-id}:system:serviceaccount:{namespace}:{name}` of identity-mapping §3.3. The principal equals the workload (identity-mapping §3.4). No `x-` namespace |
| Trusted enrollment actors | The native administrative workflow of the realm and, where configured, an authorized identity-binding issuer for the `k8s` namespace (identity-mapping §4.2). The cluster's token issuer, the gateway, and the agent are not enrollment actors |
| Shared-account handling | Not supported, the default of identity-mapping §5 (section 6). A workload with more than one enrollment in force is a configuration error, with the consequence that identity-mapping §5 states (KR-10, IM-19) |
| Certificate, token, or role-session bindings | The pod-bound token authenticates the workload and is bound to nothing else. The binding is to the service account, never to the token, the pod, the node, or the audience (identity-mapping §3.3, IM-24); name reuse is handled by the `uid` (KR-7, IM-6 (a)); the holder key is bound only by enrollment (KR-10, IM-21) |
| Lifecycle rules (rotation, compromise, recovery) | Identity-mapping §7 for the enrollment record. Token expiry, refresh, and invalidation by pod deletion are native authentication events and change no record. The propagation bound for the record is in section 9 |
| Departures from `spec/v1.0/profiles/identity-mapping.md` | None that weaken a rule. Stricter choices: service accounts only (KR-5); pod-bound tokens only (KR-6); the `uid` must match the recorded one (KR-7); the agent pod check (KR-8); shared accounts refused (IM-19 allows supporting them only with a stated reason) |

## 8. Freshness

Five sources are listed, with `max_age` and `status_max_age` in seconds, and every outage ends in `DEFERRED`, which fails closed (draft §18). The figures follow from the reference configuration, an illustrative policy choice and not a recommended threshold: a token lifetime of 3600 s, the default `expirationSeconds` [K5]; a review bound `B` = 60 s, the window after a bound object's deletion timestamp beyond which its tokens no longer authenticate [K4], with any further caching by the API server to probe (P3); and the preflight interval `P` = 300 s with the propagation allowance `R` = 60 s (P4). A deployment declares its own values.

| Source | Observation semantics | Achievable `max_age` (s) | `status_max_age` (s) | Outage behavior |
|---|---|---|---|---|
| F1 Caller token as the pinned API server's TokenReview reports it | Cached credential snapshot (draft §17.2), class "token" of freshness §4.1: the observation time is the token's `iat` (KR-20) and the status time is the review time minus `B`, because the review is the status check | 3600 | 60 | `DEFERRED` |
| F2 Enrollment registry (workload to agent and holder key binding) | Current authoritative state, read for each evaluation (KR-10). The observation time is the last change of the record (IM-10) | 0 | 0 | `DEFERRED` |
| F3 Cluster entry and registered accounts (gateway configuration) | Current authoritative state, read for each request (KR-1, KR-7) | 0 | 0 | `DEFERRED`: a configuration that cannot be read or is invalid fails closed |
| F4 Agent pod as the pinned API server returns it | Current authoritative state: a read with no `resourceVersion` returns the most recent resource version [K13] | 0 | 0 | `DEFERRED` |
| F5 RBAC preflight of the registered account and the gateway account | Snapshot of the API server's authorization answers taken by the preflight, at most `P` old when a request is served, plus `R` for grants that propagate after it (KR-17) | 360 | 360 | `DEFERRED` |

A contract rule over the paths of KR-20 whose status limit is below 60, or whose observation limit is below the token's age, cannot be met by F1: the first is `DEFERRED` with `UNSUPPORTED_REQUIREMENT` before the claim is read (freshness §4.2, convention 2), the second is `STALE_EVIDENCE`. The hold-check advice of draft §18 to use zero cannot be met through F1.

### 8.1 Membership and status sources

F1 and F2 supply identity and status facts about the authenticated principal. F1 is a review the gateway makes for each request, so it has a live check; the facts it reports were fixed when the token was issued and are cached snapshots, and the review confirms that the token and its bound objects are still in force. F2 is a registry lookup made for each evaluation. The integration reads no group or role-assignment fact as a claim; the preflight of F5 checks grants without offering a claim.

| Source | `facts` | `live_check.available` | `live_check.endpoint_class` | `change_feed.mode` | `change_feed.mechanism` | `best_status_max_age_seconds` | `value_semantics` |
|---|---|---|---|---|---|---|---|
| F1 Caller token as the pinned API server's TokenReview reports it | `identity`, `account_state` | `true` | `TokenReview` at the pinned API server | `none` | Not applicable: no change feed | 60 | `cached_snapshot` |
| F2 Enrollment registry (workload to agent and holder key binding) | `identity`, `account_state` | `true` | Enrollment registry lookup | `none` | Not applicable: no change feed | 0 | `authoritative_current` |

### 8.2 Attribute sources

The namespace of the authenticated account and the pinned cluster are subject attributes that the native claim offers (KR-20).

| Source | `category` | `attributes` | `freshness` |
|---|---|---|---|
| F1 Caller token as the pinned API server's TokenReview reports it | `subject` | `/attributes/environment/namespace` | F1 Caller token as the pinned API server's TokenReview reports it |
| F3 Cluster entry and registered accounts (gateway configuration) | `subject` | `/attributes/environment/cluster_id` | F3 Cluster entry and registered accounts (gateway configuration) |

## 9. Residual limits

| Limit | What remains true | Bound or disclosure |
|---|---|---|
| Post-read | Deployment data already returned to the agent is not recalled by a later revocation; an executed operation is not undone by revoking its receipt (draft §18); no egress or data-use control is claimed (draft §17.4) | Disclosed here; no bound |
| Revocation propagation: caller token (F1) | There is no specific mechanism to invalidate a token issued through the TokenRequest API; deleting the pod expires its bound tokens [K4], and a token becomes invalid against the API when its pod or service account is deleted [K6]. A token stays valid until then or until it expires | `B` = 60 s after deletion (illustrative, P3); otherwise the token lifetime |
| Revocation propagation: enrollment (F2) | Revocation, compromise mark, and rotation take effect at the next evaluation, in the consistency domain of the registry (identity-mapping §7.5; draft §18) | 0 s within that domain; a registry with eventual consistency declares its replication delay |
| Revocation propagation: native permission | A RoleBinding removed after admission takes effect at the API server's next authorization of the executor's request (KR-12); the API server's decision is authoritative (example I10) | The cluster's own authorization consistency (P4) |
| Additive grants between preflights | A grant added after a passing preflight, directly or by ClusterRole aggregation [K9], is not seen until the next preflight | `P + R` = 360 s (illustrative) |
| Finite forbidden list | The preflight checks the actions of KR-14 only; another grant that is not on the list is not detected (KR-18) | Disclosed |
| Other pods and Secrets of the registered account | Pods running as the registered account that the agent did not create, and token Secrets of the account, can hold tokens for the API server that the gateway does not see (B7) | Disclosed; deployment control of pod and Secret creation in the namespace (open item O4) |
| Preflight inputs | The preflight sets no `extra`, so an authorizer that decides on `extra` is not exercised (KR-15) | Disclosed (open item O5) |
| Token audience | A token minted with both the gateway audience and an API server audience would also be usable against the API server; the review shows only the intersection with the requested audiences [K1] | Disclosed (open item O3) |
| Clock | The token's `iat` comes from the cluster's issuer clock. A time ahead of the validator by more than the skew is refused (freshness §3.1, rule 2) | Skew of 5 s (draft §7.5) |

## 10. Fixture index

Fourteen negative cases cover every `closed` and `equivalently-enforced` path, the freshness rows, and the configuration-error rule of KR-10; the expected results use the wording of draft §22.2 where a case applies. Each is a group of adapter cases of this profile in `spec/v1.0/fixtures/adapters/k8s/`, one file per variant, named by its lower-case ID and variant, such as `k8s-01.own-token.json`, with the manifest id `adapters/k8s/k8s-01.own-token`; every file is registered in `spec/v1.0/fixtures/manifest.json` and listed in the `fixtures` array of `profile.json`. The Evidence column names the files, and the part of a case that is a property of the validator, the gateway, the executor, or the deployment rather than of an adapter function says where it is tested. The native state of each case describes the review, pod, authorization, and self-review answers of the API server, in the model `k8s/1` of the [Kubernetes cases README](../../fixtures/adapters/k8s/README.md), which the harness serves from an API server of its own; this settles open item O6. The identity, freshness, and request-binding cases of `spec/v1.0/fixtures/adapters/_common/` also apply and are not repeated. `K8S-14` covers the configuration-error rule of KR-10 and is not one of the requirement cases.

| Fixture ID | Negative case (input) | Expected result | Evidence | Covers |
|---|---|---|---|---|
| `K8S-01` | Valid token of account A with `Impersonate-User`, `Impersonate-Group`, `Impersonate-Uid`, `X-Remote-User`, and `X-Remote-Group` headers naming enrolled account B | The headers have no effect and never reach the API server; the request is evaluated as A | `adapters/k8s/k8s-01.impersonation-headers`, with the control `k8s-01.own-token`. The harness's API server answers 403 to a request that carries such a header, so a forwarded header fails the case. Their removal before `authorize_native` and execution is a property of the gateway's request path, tested with the executor in the adapter package | R1, R2, B3 |
| `K8S-02` | Token whose review returns `authenticated` true with an empty `status.audiences`; one for the API server's audience, which the review for the gateway audience does not authenticate; one whose `status.audiences` lacks the gateway audience; the first on `POST /pact/v0.1/requirements` | Native denial, 401, `CREDENTIAL_REJECTED` | `adapters/k8s/k8s-02.empty-audiences`, `k8s-02.other-audience`, `k8s-02.lacks-gateway-audience`, `k8s-02.requirements-endpoint`. The API server of `k8s-02.other-audience` authenticates the token for a review without `spec.audiences`, so an adapter that leaves them out fails it. That no trusted personalized contract is issued is a gateway property, covered by the gateway pipeline test when a gateway exists; reserved, not landed | R1, R2, B6 |
| `K8S-03` | Token issued by another cluster (review not authenticated at the pinned API server); an account with the same namespace and name in another cluster | Native denial; the identifiers differ by `cluster-id`, and the other is not enrolled: `UNKNOWN`, reporting the agent ID enrolled for another workload | `adapters/k8s/k8s-03.other-cluster-token`, `k8s-03.other-cluster-workload` | R1, R2, B5 |
| `K8S-04` | Account in a namespace outside the claimed set; account deleted and created again under the same name (new `uid`); a user name that is not a service account; a service account that is not registered; a review without the service-account groups of the namespace; the same account name in another claimed namespace | Native denial, 401, `CREDENTIAL_REJECTED`. The account of another claimed namespace is its own workload | `adapters/k8s/k8s-04.unclaimed-namespace`, `k8s-04.recreated-account`, `k8s-04.not-service-account`, `k8s-04.unregistered-account`, `k8s-04.missing-groups`, with the control `k8s-04.same-name-other-namespace` | R1, R2, F3 |
| `K8S-05` | Token whose review carries no `pod-name` or `pod-uid`; one with two `pod-name` values; a pod named after another enrolled account | Native denial, 401, `CREDENTIAL_REJECTED`; the pod name never selects a workload | `adapters/k8s/k8s-05.no-pod-claims`, `k8s-05.two-pod-names`, with the control `k8s-05.pod-name-not-identity` | R1, R2 |
| `K8S-06` | Agent pod with `automountServiceAccountToken` not `false` (unset, `true`); with a projected token without an audience or with the API server's audience; whose `metadata.uid` differs from `pod-uid`; that runs as another account; a pod that does not exist | Native denial, 401, `CREDENTIAL_REJECTED` | `adapters/k8s/k8s-06.automount-unset`, `k8s-06.automount-true`, `k8s-06.projected-no-audience`, `k8s-06.projected-api-audience`, `k8s-06.pod-uid-mismatch`, `k8s-06.other-account`, `k8s-06.pod-not-found`, with the control `k8s-06.gateway-audience-projection`; a pod read that cannot complete is `K8S-13` | R1, R2, B1, F4 |
| `K8S-07` | Admitted operation whose executor token is missing or refused; executor configured with the gateway account's token, a kubeconfig credential, or an impersonation header; executor whose self-review names the account with another `uid` | `UNKNOWN` with `DEPENDENCY_UNAVAILABLE`, so `DEFERRED`, for the first two; `FAIL` with `EXECUTOR_MISMATCH` for the others; nothing runs | `adapters/k8s/k8s-07.token-missing`, `k8s-07.token-refused`, `k8s-07.gateway-token`, `k8s-07.kubeconfig`, `k8s-07.impersonation`, `k8s-07.recreated-account`, with the control `k8s-07.registered-account`. That no request with another identity reaches the API server, because the executor accepts no other credential source, is a Go test of the adapter package | R1, R2, B4 |
| `K8S-08` | Preflight answers `allowed` true for one row of KR-14 for the registered account: a ClusterRoleBinding of Secret reads to the group `system:serviceaccounts`, an aggregated ClusterRole that grants deployment `patch`, a binding that grants cluster-wide `list`, a grant to mint tokens or to exec into pods | Claim invalid for that account: `DEFERRED` with `DEPENDENCY_UNAVAILABLE` from `authenticate_native`, and no execution until a later preflight passes | `adapters/k8s/k8s-08.secrets-get`, `k8s-08.aggregated-patch`, `k8s-08.cluster-list`, `k8s-08.token-create`, `k8s-08.pod-exec`. Every case also grants the `get` and `list` of the I10 Role, which are not on the forbidden list, and `k8s-01.own-token` shows that they pass | R1, R2, B1, B2, F5 |
| `K8S-09` | Preflight with an `evaluationError`; a self-review of the gateway account without groups, which leaves the preflight without the inputs of KR-15; the authorization API unavailable; a preflight older than `P` | Not established: `DEFERRED` with `DEPENDENCY_UNAVAILABLE`; never served on the strength of a stale or incomplete preflight | `adapters/k8s/k8s-09.evaluation-error`, `k8s-09.gateway-review-no-groups`, `k8s-09.authorization-unavailable`. A case starts from an adapter that holds no preflight, so the stale preflight is a Go test of the adapter package. A token review without the groups of the account is a native denial before the preflight (KR-5, KR-19): `k8s-04.missing-groups` | F5 |
| `K8S-10` | Gateway request with `?watch=1`, a label selector, or `resourceVersion=0`; another namespace in the path; a deployment name outside the grammar of R2; a downstream response that carries a `continue` token | The query is not forwarded and binds into `target_uri` as sent, so it changes the operation (context mismatch, draft §22.2); another namespace or name selects no row (`UNSUPPORTED_REQUIREMENT`); the continuation is not followed | `adapters/k8s/k8s-10.watch`, `k8s-10.label-selector`, `k8s-10.resource-version`, `k8s-10.other-namespace`, `k8s-10.bad-name`, with the controls `k8s-10.list` and `k8s-10.get`. The mismatch itself is the validator's comparison of `operation_digest` (KR-21), not an adapter function; the translation of KR-13 and the continuation are properties of the executor, Go tests of the adapter package | R1, R2 |
| `K8S-11` | Valid admission, then the API server denies the registered account the request because the RoleBinding was removed; the gateway account, not the registered account, is allowed the request | Native denial, `DENY`, as the API server answered: source `kubernetes-api-server`, no obligation and no decision time; the gateway account's grant is never used; no execution (draft §22.2) | `adapters/k8s/k8s-11.binding-removed`, `k8s-11.no-gateway-substitution`, with the control `k8s-11.binding-present`. That the API server's 403 to the executor is final and not retried is a Go test of the adapter package; the RBAC objects of example I10 are the asset `adapters/k8s/rbac` (`assets/rbac.yaml`), which the gated integration test of the adapter package expects applied | R1, R2 |
| `K8S-12` | Preflight answers `allowed` true for the gateway account on K-F1, K-F5, or K-F6 | Claim invalid: no protected request served, `DEFERRED` with `DEPENDENCY_UNAVAILABLE` | `adapters/k8s/k8s-12.gateway-secrets-get`, `k8s-12.gateway-impersonate`, `k8s-12.gateway-token-create` | B4, F5 |
| `K8S-13` | `TokenReview`, pod read, or enrollment registry unavailable at evaluation; a rule with a status limit below 60 s on a path of KR-20 | `DEFERRED` with `DEPENDENCY_UNAVAILABLE`, then `UNSUPPORTED_REQUIREMENT` for the rule (draft §18, §22.2) | `adapters/k8s/k8s-13.tokenreview-down`, `k8s-13.pod-read-down`, `k8s-13.registry-down`. The claims of KR-20 carry the times that make such a rule unmeetable: `k8s-13.claim-principal` and `k8s-13.claim-namespace` the token's `iat` and the review time minus `B`, `k8s-13.claim-cluster` the time of the evaluation, and `k8s-13.claim-unapproved` refuses another path. The rule itself is judged by the validator before it reads the claim (freshness §4.2, convention 2); reserved for the evaluation cases, not landed | F1, F2, F4 |
| `K8S-14` | Two enrollment records, for agents A and B, on the workload of one registered account: (a) the enrollment that would add the second record; (b) both records present, and a presentation by A signed with A's key, and one by B signed with B's key | (a) Refused; (b) neither record is selected, for either agent: the configuration error of identity-mapping §5 (IM-19) | (b) `adapters/k8s/k8s-14.two-agents-a`, `k8s-14.two-agents-b`, with the control `k8s-14.dedicated`; (a) is a Go test of the adapter package against the enrollment registry | KR-10, section 7 |

### Replaced common cases

The common cases of the adapter conformance suite run against this adapter. Seven `authenticate_native` cases state a principal that a reviewed service-account token cannot yield, and three `authorize_native` cases a decision member that a `SubjectAccessReview` answer cannot carry [K10]; they are replaced ([adapters README](../../fixtures/adapters/README.md), "Replaced common cases"; draft §22.2). The others pass, realized as the Kubernetes cases README states; this settles open item O8.

| Common case | Why a reviewed service-account token cannot realize it | Replacement |
|---|---|---|
| `COMMON-01.credential-wins` | Expects `https://idp.acme.example/bob` and a workload that is not a `k8s:` identifier | `K8S-01.impersonation-headers`: impersonation and authenticating-proxy headers naming another enrolled account; authenticated as the token's own account (KR-9) |
| `COMMON-02.via-enforcement-point` | Expects `https://idp.acme.example/alice` | `K8S-01.own-token`: authenticated as the account's `k8s:` identifier, mechanism `kubernetes-serviceaccount`, realm of the gateway |
| `COMMON-09.authenticate-realm` | Expects a `globex` principal id | `K8S-01.own-token`: the realm is the gateway's configuration, never a value of the review |
| `IDENT-01.authenticate` | Expects `basic:acme-accounts:20511` | `K8S-04.same-name-other-namespace`: another account authenticates as its own workload (KR-7) |
| `IDENT-02.authenticate` | Expects an `oauth:` identifier of another tenant | `K8S-04.same-name-other-namespace`: the same account name in another namespace is another workload (KR-7) |
| `IDENT-03.authenticate` | Splits user and client; under this mechanism the principal is the workload | `K8S-01.own-token`: the principal and the workload are the account's identifier (identity-mapping §3.4) |
| `COMMON-06.allow-no-execution` | Expects an obligation with the allow | `K8S-11.binding-present`: the API server's allow, with no obligation, the source `kubernetes-api-server`, and no decision time (KR-12) |
| `COMMON-06.deny-unchanged` | Expects an obligation with the denial | `K8S-11.binding-removed`: the API server's denial, with no obligation, as it answered (KR-12) |
| `COMMON-06.decision-provenance` | Expects a decision record, a decision time, and a policy revision | `K8S-11.binding-present`: the source is pinned, and the decision time is pinned as absent, because the answer carries neither a record nor a time nor a revision (KR-12) |
| `IDENT-05.authenticate` | Expects `basic:acme-accounts:30981` | `K8S-05.pod-name-not-identity`: the pod name, the analogue of a display name, never selects a workload (KR-6) |

## Requirement coverage

The requirements, for Kubernetes, are to pin the cluster, namespace, account, and token audience, the broker privileges, the actual downstream actor, and the implemented scope, with evidence that forged identity headers, a wrong cluster, a wrong token audience, a broader fallback, hidden additive grants, and translated operations with different semantics are rejected. The AWS items are in the [AWS profile](../aws/profile.md).

| Requirement | Rules | Cases |
|---|---|---|
| Cluster pinned | KR-1, KR-4 | `K8S-03` |
| Namespace and account pinned | KR-1, KR-5, KR-7 | `K8S-04` |
| Token audience | KR-2, KR-4, KR-6, KR-8 | `K8S-02`, `K8S-05`, `K8S-06` |
| Broker privileges | KR-3, KR-14 | `K8S-12` |
| Actual downstream actor, no cluster-admin fallback | KR-11, KR-12 | `K8S-07`, `K8S-11` |
| Implemented scope | KR-13, KR-18; section 6 | `K8S-10` |
| Complete-RBAC preflight | KR-14 to KR-17 | `K8S-08`, `K8S-09`, `K8S-12` |
| Evidence: reject forged identity headers | KR-9 | `K8S-01` |
| Evidence: reject a wrong cluster | KR-1, KR-4 | `K8S-03` |
| Evidence: reject a wrong token audience | KR-2, KR-4 | `K8S-02` |
| Evidence: reject a broader fallback | KR-3, KR-11 | `K8S-07` |
| Evidence: reject hidden additive grants | KR-14 to KR-16 | `K8S-08`, `K8S-12` |
| Evidence: reject translated operations with different semantics | KR-13, KR-24 | `K8S-10` |
| Freshness and outage | KR-17, KR-20; section 8 | `K8S-09`, `K8S-13` |

## Sources

Every page was read on 2026-10-16; the API reference pages state that they were generated for v1.37, except K14. Labels are used in the rules.

| Label | Source | Used for |
|---|---|---|
| K1 | Kubernetes API reference, [TokenReview](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/) | `spec.token`, `spec.audiences`, `status.audiences`, `status.authenticated`, `status.error`, `status.user` |
| K2 | Kubernetes API reference, [UserInfo](https://kubernetes.io/docs/reference/kubernetes-api/definitions/user-info-v1-authentication/) | `username`, `uid` across time, `groups`, `extra` |
| K3 | Kubernetes documentation, [Authenticating](https://kubernetes.io/docs/reference/access-authn-authz/authentication/) | Service-account tokens as signed JWTs, their user name and groups, the Secret warning, the authenticating-proxy headers, `SelfSubjectReview` |
| K4 | Kubernetes documentation, [Managing Service Accounts](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/) | Bound tokens and the 60 second window, the `extra` of a pod-bound token, offline validation versus `TokenReview`, token refresh, invalidation by pod deletion, tokens in Secrets |
| K5 | Kubernetes documentation, [Projected Volumes](https://kubernetes.io/docs/concepts/storage/projected-volumes/) | `serviceAccountToken` `audience` and its default, `expirationSeconds` |
| K6 | Kubernetes documentation, [Configure Service Accounts for Pods](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) | Opting out of automounting and its precedence, `--api-audiences` and its default, invalidation when the pod or account is deleted, the token payload |
| K7 | Kubernetes documentation, [Service Accounts](https://kubernetes.io/docs/concepts/security/service-accounts/) | Namespaced service accounts and automatic credentials |
| K8 | Kubernetes documentation, [Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) | Deny by default and no opinion, request verbs, `get`, `list`, and `watch` equivalence, the `impersonate`, `bind`, and `escalate` verbs, escalation through workload creation, webhook decision caching |
| K9 | Kubernetes documentation, [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) | Purely additive permissions, service-account prefixes, ClusterRole aggregation, `cluster-admin`, `system:auth-delegator`, escalation prevention |
| K10 | Kubernetes API reference, [SubjectAccessReview](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/) | `spec.user` without groups, `status.allowed`, `status.denied`, `status.evaluationError` |
| K11 | Kubernetes API reference, [ResourceAttributes](https://kubernetes.io/docs/reference/kubernetes-api/definitions/resource-attributes-v1-authorization/) | Empty `namespace` and `*` values |
| K12 | Kubernetes documentation, [User impersonation](https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/) | The impersonation headers and the `impersonate` verb |
| K13 | Kubernetes documentation, [Kubernetes API Concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/) | Resource paths, `watch` on a `GET`, most recent reads, `limit` and `continue` |
| K14 | Kubernetes API reference for v1.32, [TokenRequest](https://v1-32.docs.kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/) | The create path of the `token` subresource. The same path under the current documentation served another page on 2026-10-16, so the v1.32 snapshot was read (probe P1) |

## Open items and probes

No rule depends on an unprobed behavior: each rule that rests on one fails closed whichever way it comes out.

| ID | Item | Probe or decision needed | If the outcome differs |
|---|---|---|---|
| P1 | The pages read are those of v1.37; a cluster of another version can differ | Record the cluster version and re-read the sources for it | The affected rule is revised |
| P2 | Whether `status.user.uid` of a review equals the service account's `metadata.uid` | Review a token and read the account | None: KR-7 compares with the value recorded from a review |
| P3 | Whether the API server caches token authentication for service-account tokens, the default of `--service-account-lookup` (documented as "If true, the API server validates that ServiceAccount tokens exist in etcd" [K3]), and how soon a deleted pod's token stops authenticating | Delete a pod and an account and review their tokens at intervals | The measured value becomes `B` (section 8) |
| P4 | How long a new binding, a removed binding, or an aggregated rule takes to change `SubjectAccessReview` answers, and the cache settings of any authorization webhook | Change RBAC objects and poll the preflight | The measured value becomes `R` (section 8) |
| P5 | The `extra` of reviews for tokens other than pod-bound ones | Review a token Secret's token and an unbound TokenRequest token | None: KR-6 refuses a token without both keys |
| P6 | The verb the API server authorizes for `pods/exec` | Exec into a pod with a role that grants only `get`, then only `create` | None: K-F7a checks both |
| O1 | The forbidden list of KR-14 adds K-F2, K-F5 to K-F9, and K-F7a, and the extra verbs and resources of K-F3 and K-F4, to the three cases of example I10 (Secrets `get`, deployments `patch`, cluster-scope `list`) | Maintainer confirmation | KR-14 shrinks or grows; the mapping revision changes |
| O2 | How a failed preflight is reported: KR-19 uses `DEFERRED` with `DEPENDENCY_UNAVAILABLE`, which fails closed but is not an outage | Maintainer decision | KR-19's row changes |
| O3 | A token minted with the gateway audience and an API server audience; the review returns only the intersection [K1], so the gateway cannot see the other audience. Probe: mint such a token and review it with each audience | Maintainer decision on reading the token's `aud` claim after a successful review | KR-4 adds a refusal of tokens with other audiences |
| O4 | Pods running as the registered account that the agent did not create, and token Secrets of the account, are not inventoried | Maintainer decision on a namespace inventory check, and a probe of the list query it needs | B7 becomes `closed` |
| O5 | The preflight sets no `extra`, so it does not reproduce the inputs of an authorizer that reads them | Maintainer decision | KR-15 sets `extra` from the executor's review |
| O6 | The common adapter harness has no native-state model for reviews, pod reads, and preflight answers | Decided: the `k8s/1` model of the [Kubernetes cases README](../../fixtures/adapters/k8s/README.md) states the answers of the API server, which the harness serves from an API server of its own | Section 10's native state |
| O7 | The registered account is both the caller principal and the executor identity (KR-11, KR-12), following example I10's mapping of the workload to its dedicated account. A design with separate caller and executor accounts would need `authorize_native` for the caller distinct from the executor's own authority (draft §17.5) | Maintainer confirmation | Sections 3 and 7 and KR-11 to KR-12 change |
| O8 | The common `authorize_native` cases `COMMON-06.allow-no-execution`, `COMMON-06.deny-unchanged`, and `COMMON-06.decision-provenance` expect obligations, a decision record, a decision time, and a policy revision, which a `SubjectAccessReview` status does not carry [K10]; `COMMON-06.no-connector-substitution` expects a denial for a principal that is not a reviewed service account | Decided: the three are replaced by `K8S-11` cases (adapters README, "Replaced common cases"); a principal the adapter did not authenticate is denied by the adapter's own mapping source, because the API server decides only for its own users, which `COMMON-06.no-connector-substitution` passes and `K8S-11.no-gateway-substitution` shows for the gateway account | Section 10's replaced-cases table |
