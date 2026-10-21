// Package k8s is the Kubernetes adapter of the integration profile
// spec/v1.0/profiles/k8s: the seven functions of draft 17.1 for an operations
// gateway that authenticates agents by their pod-bound service-account
// tokens and executes admitted reads against the Kubernetes API under the
// agent's registered service account (integration sample I10). The API
// objects are defined here by hand: the package uses the standard library
// (net/http, crypto/tls, encoding/json) and the packages of this module, and
// no Kubernetes client library. It never validates a token offline: every
// token is reviewed by the pinned API server (profile KR-4). The adapter
// never reads the wall clock: [Config.Clock] is its only source of the
// current time.
//
// An adapter is built with [New] from a [Config]: the cluster entry (cluster
// id, API server URL and trust anchors, gateway audience, claimed
// namespaces), the registered accounts ([Account]), the gateway account's
// token, the executors ([ExecutorSource]) and the deployment-supplied parts
// of package installed. The gateway marks requests with [Enforce] or [Mark].
// [Executor] sends the downstream requests with the registered account's
// projected token, and accepts no other credential.
//
// # What it does
//
//   - AuthenticateNative: the enforcement marker, the one bearer token, a
//     TokenReview with spec.audiences exactly the gateway audience and
//     status.audiences required to contain it (KR-4), service accounts of
//     claimed namespaces with their groups (KR-5), pod-bound tokens (KR-6),
//     the recorded uid (KR-7), the agent pod check (KR-8), and a passing RBAC
//     preflight within P for the account and the gateway account (KR-14 to
//     KR-17). The identifier k8s:{cluster-id}:system:serviceaccount:
//     {namespace}:{name} ([Identifier]) is the principal and the workload.
//   - ResolveAgentBinding: the enrollment registry through [enroll.Resolver],
//     one registered account per agent (KR-10).
//   - MapOperation: rows R1 and R2 of mapping revision pact-k8s-1 with the
//     baseline binding (KR-13, KR-24).
//   - ReadNativeClaim: the three paths of KR-20.
//   - CheckContext: execution-identity-v1 (KR-11) and the checks the
//     deployment installs.
//   - AuthorizeNative: a SubjectAccessReview of the registered account for
//     the translated request, returned unchanged (KR-12).
//   - RecordOutcome: package installed.
//
// # Probed behaviour
//
// Read on 2026-10-18 from the Kubernetes documentation, the pages the
// profile's sources K1 to K14 name; the API reference pages state that they
// were generated for v1.37:
//
//   - TokenReview v1
//     (https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/):
//     spec.token is "the opaque bearer token"; without spec.audiences "the
//     audience will default to the audience of the Kubernetes apiserver";
//     status.audiences are identifiers "in the intersection of the
//     TokenReviewSpec audiences and the token's audiences", a client that
//     sets spec.audiences "should validate that a compatible audience
//     identifier is returned", and an empty status.audiences with
//     authenticated true means the token "is valid against the audience of
//     the Kubernetes API server"; status.authenticated "indicates that the
//     token was associated with a known user"; status.error "indicates that
//     the token couldn't be checked"; status.user is the UserInfo. The
//     adapter therefore sends exactly the gateway audience and requires it
//     back.
//   - Managing Service Accounts
//     (https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/):
//     the example review of a pod-bound token carries extra
//     authentication.kubernetes.io/pod-name and pod-uid, the groups
//     system:serviceaccounts, system:serviceaccounts:{namespace} and
//     system:authenticated, and the user name
//     system:serviceaccount:{namespace}:{name}; offline validators "do not
//     verify" that bound claims are current, and clients that need it "MUST
//     use the TokenReview API"; deleting a pod expires its bound tokens.
//   - Projected Volumes
//     (https://kubernetes.io/docs/concepts/storage/projected-volumes/): the
//     serviceAccountToken audience "is optional and it defaults to the
//     identifier of the API server"; expirationSeconds defaults to one hour
//     and is at least 600. The agent pod check therefore refuses a source
//     without an audience.
//   - Configure Service Accounts for Pods
//     (https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/):
//     automountServiceAccountToken false on the pod spec opts out, and the
//     pod spec takes precedence over the service account's setting.
//   - SubjectAccessReview v1
//     (https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/):
//     a user without groups is asked "What if User were not a member of any
//     groups"; status.allowed is required; allowed false and denied false is
//     no opinion; evaluationError means some error occurred even when a
//     decision was reached. The status has no obligation, decision record,
//     decision time or policy revision.
//   - Authenticating
//     (https://kubernetes.io/docs/reference/access-authn-authz/authentication/):
//     the service-account user name and groups; SelfSubjectReview is POST
//     /apis/authentication.k8s.io/v1/selfsubjectreviews and reports
//     status.userInfo after every authentication mechanism, impersonation
//     included, so a self-review cannot reveal an impersonation header: the
//     executor's credential kinds are checked separately; the
//     authenticating-proxy headers X-Remote-User, X-Remote-Group and
//     X-Remote-Extra-.
//
// To probe: the HTTP status a real API server returns for the review
// creates (the pages read do not state it; the adapter accepts 200 and 201),
// whether status.user.uid equals the account's metadata.uid (profile P2),
// and the profile's probes P3 to P6.
package k8s
