# Kubernetes adapter cases

These are the cases of the Kubernetes adapter of the integration profile
[`profiles/k8s`](../../../profiles/k8s/profile.md): an operations gateway that
authenticates agents by their pod-bound service-account tokens through
`TokenReview`, checks the agent pod, runs an RBAC preflight with
`SubjectAccessReview`, and executes admitted reads under the agent's
registered service account. They run after the common cases, with the case
file format, the outcomes and the checks of [`../README.md`](../README.md). The
profile does not support service accounts shared by several agents, so a
harness runs the `dedicated` cases. Section 10 of the profile says which case
group each file belongs to, which planned behaviour is tested outside these
files, and which common cases the adapter replaces.

The native state of a case describes what the cluster's API server answers:
the review of each token, the pods, the authorization answers, and the
self-reviews. The harness serves them from an API server of its own, which the
adapter reaches as the pinned API server of the cluster entry (profile KR-1),
over TLS that the adapter verifies. This settles open item O6 of the profile.
The object shapes are those of the Kubernetes API reference pages that the
profile cites: `TokenReview` [K1], `UserInfo` [K2], `SelfSubjectReview` [K3],
`SubjectAccessReview` [K10] and `ResourceAttributes` [K11], and the pod fields
of [K5] and [K6].

## Model `k8s/1`

```
{
  "model": "k8s/1",
  "gateway": {"tenant_id", "environment_id", "origin", "header_allowlist"},
  "cluster": {"cluster_id", "gateway_audience", "namespaces": [...]},
  "review_bound_seconds": <seconds>,                  // optional, default 60
  "preflight_interval_seconds": <seconds>,            // optional, default 300
  "accounts": [{"namespace", "name", "uid"}],
  "gateway_account": {"token"},
  "tokens": [{"ref", "token",
              "reviews": [{"audiences": [...], "status": {...}}]}],
  "pods": [{...}],
  "authorization": [{"subject": {"user"} | {"group"}, "verb", "api_group",
                     "resource", "subresource", "namespace", "name",
                     "status": {...}}],
  "self_reviews": [{"token", "user_info": {...}}],
  "executors": [{"account": {"namespace", "name"},
                 "credentials": [...], "token"}],     // optional
  "enrollments": [...],
  "unavailable_sources": [...]                        // optional
}
```

Times are Unix seconds.

- `gateway`: as in `common/1`.
- `cluster`: the cluster entry (profile KR-1, KR-2): the configured
  `cluster-id`, the gateway audience, and the claimed namespaces.
- `review_bound_seconds`: the declared review bound `B` (profile section 8).
  A claim from the review reports the review time minus `B` as its status
  time (KR-20).
- `preflight_interval_seconds`: the preflight interval `P` (KR-17).
- `accounts`: the registered accounts with the `uid` recorded at enrollment
  (KR-7).
- `gateway_account`: the token the gateway account sends to the API server
  for its reviews and pod reads (KR-3).
- `tokens`: the bearer tokens a case's requests can present. `ref` names a
  token in `request.native_state_ref`, and the harness sends it as
  `Authorization: Bearer <token>`. Each token is a compact JWS whose payload
  carries `iat`, as a service-account token does ([K3], [K6]); its signature
  is not meant to verify, and the adapter never verifies it offline (KR-4).
  `reviews` is what the API server answers to a `TokenReview` of the token:
  the `status` of the entry whose `audiences` equals the review's
  `spec.audiences`, member for member and in order, an empty list matching a
  review without `spec.audiences` [K1]. A review that matches no entry, and
  a review of a token that is not listed, is answered
  `{"authenticated": false}`.
- `pods`: the pod objects the API server returns, as it returns them.
- `authorization`: the API server's answers to `SubjectAccessReview`. A grant
  answers a review whose `spec.user` is the subject's `user`, or whose
  `spec.groups` contains the subject's `group`, and whose
  `resourceAttributes` have the grant's `verb`, `group` (`api_group`),
  `resource`, `subresource` and `namespace`, an absent `subresource` being the
  empty one. A grant with a `name` answers only for that name, and one without
  answers for every name. The first grant that answers gives the `status`; a
  review no grant answers is `{"allowed": false}`, the answer when no
  authorizer has an opinion [K8], [K10].
- `self_reviews`: what a `SelfSubjectReview` made with a token reports as its
  `status.userInfo` [K3]. A self-review with a token that is not listed is
  answered 401.
- `executors`: the executor of a registered account as it reports itself:
  the kinds of credential it holds, among `projected-token`, `kubeconfig`,
  `token-secret`, `client-certificate`, `credential-plugin` and
  `impersonation` (KR-11), and the token it sends, `null` when it holds none.
  The executor makes its self-review with that token.
- `enrollments`: as in `common/1`, from the source `enrollment-registry`.
- `unavailable_sources`: the sources that cannot answer, among
  `tokenreviews`, `pods`, `subjectaccessreviews`, `selfsubjectreviews` and
  `enrollment-registry`.

## API server

The harness's API server answers:

| Request | Answer |
|---|---|
| `POST /apis/authentication.k8s.io/v1/tokenreviews` | The `TokenReview` with the status of `tokens` |
| `POST /apis/authorization.k8s.io/v1/subjectaccessreviews` | The `SubjectAccessReview` with the status of `authorization` |
| `GET /api/v1/namespaces/{namespace}/pods/{name}` | The pod of `pods`, 404 when there is none, 400 for a read with a query |
| `POST /apis/authentication.k8s.io/v1/selfsubjectreviews` | The `SelfSubjectReview` with the `userInfo` of `self_reviews` |

The first three are answered only for a request that carries the gateway
account's token; any other is answered 401. A request that carries a header
whose name begins with `Impersonate-` or `X-Remote-`, matched without regard
to case, is answered 403: the gateway account may not impersonate (KR-3,
K-F5) and is not an authenticating proxy, and the profile forbids forwarding
either kind of header (KR-9). A source in `unavailable_sources` is answered
503. A review is answered with status 201; the codes a real API server uses
for a review are to probe, and an adapter accepts 200 and 201 (profile probe
P1).

## Adapter outputs

An authenticated principal has the mechanism `kubernetes-serviceaccount`, the
identifier `k8s:{cluster-id}:system:serviceaccount:{namespace}:{name}` as both
its id and its workload (KR-7), and the attribute `k8s`:
`{"cluster_id", "namespace", "name", "uid", "groups", "issued_at",
"reviewed_at"}`, the reviewed account, its groups as the review reports them,
the token's `iat`, and the time of the review. `read_native_claim` answers the
paths of KR-20 from it: `/attributes/environment/principal_id` and
`/attributes/environment/namespace` with the source `kubernetes-tokenreview`,
observed at `issued_at` and status-checked at `reviewed_at` minus `B`;
`/attributes/environment/cluster_id` with the source `cluster-entry`, both
times the time of the evaluation.

The installed check of the adapter is `execution-identity-v1` (draft 17.5,
KR-11): `PASS` with `REQUIREMENT_SATISFIED` when the executor of the
operation's registered account holds only a `projected-token` and its
self-review names that account with its recorded `uid`; `FAIL` with
`EXECUTOR_MISMATCH` for another credential kind or another identity;
`UNKNOWN` with `DEPENDENCY_UNAVAILABLE` when its token is missing or refused.

`authorize_native` asks the API server, with a `SubjectAccessReview` for the
registered account (KR-15), whether the translated request of the operation's
row is allowed (KR-12, KR-13): `ALLOW` for `allowed` true, `UNKNOWN` with an
`evaluationError`, `DENY` otherwise, with the source `kubernetes-api-server`,
the API server's reason, no obligation and no decision time. A principal the
adapter did not authenticate, and an operation of no row, are a `DENY` of the
adapter's own mapping source: the API server decides only for its own users.

The asset [`assets/rbac.yaml`](assets/rbac.yaml) holds the Role and
RoleBinding of example I10, verbatim. The gated integration test of the Go
adapter package expects them applied to its cluster.

## Common cases

The common cases state their native state in `common/1`. A Kubernetes
harness realizes it with the cluster `common-cluster`, the one claimed
namespace `common`, and one registered account per identity, named by the
identity's `ref`, whose `uid` is the first 32 characters of the lower-case
hexadecimal SHA-256 digest of the UTF-8 octets of the `ref`. The identity's
token is a compact JWS whose payload has the `iat` of `now` minus 600 and the
`jti` of the identity's `secret`; its review for the gateway audience is
authenticated, with that audience, the account's user name, `uid` and
service-account groups, and the `pod-name` `{ref}-agent` with the `pod-uid`
formed the same way from `{ref}-agent`, the name of a pod that runs as the
account with `automountServiceAccountToken` `false`. No grant is listed, so the preflight
passes. The other functions use the deployment-supplied sources that
`common/1` describes, except `authorize_native`, whose native policy is the
API server's: a `common/1` principal is not a reviewed service account, so the
adapter denies it. Seven common `authenticate_native` cases expect a principal
that a reviewed service-account token cannot yield, and three
`authorize_native` cases a decision member that a `SubjectAccessReview` answer
cannot carry; they are replaced (profile section 10; adapters README,
"Replaced common cases").
