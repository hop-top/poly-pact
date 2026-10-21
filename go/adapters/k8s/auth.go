package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core/clock"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/internal/ascii"
)

// denial returns a native denial with the public reason.
func denial(reason adapter.DenialReason) error { return &adapter.NativeDenial{Reason: reason} }

var rejected = denial(adapter.DenialCredentialRejected)

// dependency is an error that wraps adapter.ErrDependencyUnavailable.
func dependency(what string) error {
	return fmt.Errorf("k8s: %s: %w", what, adapter.ErrDependencyUnavailable)
}

// reviewed is what a review, the token and the pod check establish.
type reviewed struct {
	account  Account
	groups   []string
	issuedAt time.Time
}

// AuthenticateNative authenticates r by its service-account token, in the
// order of KR-19.
//
// A request without the enforcement marker is refused before any token is
// read: NO_CREDENTIAL without an Authorization field, CREDENTIAL_REJECTED
// otherwise. The token is the bearer token of the single Authorization field
// (KR-4); no other header is read, and none is forwarded (KR-9). The token is
// reviewed at the pinned API server with spec.audiences exactly the gateway
// audience, and accepted only when status.authenticated is true,
// status.error is empty and status.audiences contains the gateway audience
// (KR-4); the user must be a service account of a claimed namespace with the
// service-account groups (KR-5), a registered account with its recorded uid
// (KR-7), and pod-bound with one pod-name and one pod-uid (KR-6). The token's
// iat is read only then (KR-20). The agent pod is read and checked (KR-8).
// Then the RBAC preflight of the account and of the gateway account must have
// passed within P (KR-17). Every refusal is CREDENTIAL_REJECTED; a review,
// pod read or preflight that cannot complete, and a preflight that failed,
// are errors that wrap [adapter.ErrDependencyUnavailable].
//
// The principal and the workload are [Identifier] of the account, in the
// gateway's realm, with the attribute [AttrK8s].
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	if r == nil {
		return adapter.Principal{}, denial(adapter.DenialNoCredential)
	}
	lines := r.Header.Values("Authorization")
	switch {
	case len(lines) == 0:
		return adapter.Principal{}, denial(adapter.DenialNoCredential)
	case !Marked(r) || len(lines) > 1:
		return adapter.Principal{}, rejected
	}
	scheme, token, ok := strings.Cut(lines[0], " ")
	token = strings.TrimLeft(token, " ")
	if !ok || !ascii.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return adapter.Principal{}, rejected
	}
	gw, err := a.cfg.GatewayToken(ctx)
	if err != nil || gw == "" {
		return adapter.Principal{}, dependency("the gateway account's token cannot be read")
	}
	rv, err := a.review(ctx, gw, token)
	if err != nil {
		return adapter.Principal{}, err
	}
	if err := a.ensurePreflight(ctx, gw, subject{user: rv.account.Username(), uid: rv.account.UID, groups: rv.groups}); err != nil {
		return adapter.Principal{}, err
	}
	now := a.cfg.Clock.Now()
	return adapter.Principal{
		ID:              Identifier(a.cfg.ClusterID, rv.account.Namespace, rv.account.Name),
		Realm:           a.cfg.Realm,
		Workload:        adapter.Workload(Identifier(a.cfg.ClusterID, rv.account.Namespace, rv.account.Name)),
		Mechanism:       Mechanism,
		AuthenticatedAt: now,
		Attributes: map[string]any{AttrK8s: map[string]any{
			"cluster_id": a.cfg.ClusterID, "namespace": rv.account.Namespace, "name": rv.account.Name,
			"uid": rv.account.UID, "groups": slices.Clone(rv.groups),
			"issued_at": rv.issuedAt.Unix(), "reviewed_at": now.Unix(),
		}},
	}, nil
}

// review applies KR-4 to KR-8 to a token.
func (a *Adapter) review(ctx context.Context, gw, token string) (reviewed, error) {
	st, err := a.api.tokenReview(ctx, gw, token, a.cfg.GatewayAudience)
	if err != nil {
		return reviewed{}, dependency("the token review cannot complete")
	}
	if !st.Authenticated || st.Error != "" || !slices.Contains(st.Audiences, a.cfg.GatewayAudience) {
		return reviewed{}, rejected
	}
	ns, name, ok := serviceAccount(st.User.Username)
	if !ok || !slices.Contains(a.cfg.Namespaces, ns) ||
		!slices.Contains(st.User.Groups, "system:serviceaccounts") ||
		!slices.Contains(st.User.Groups, "system:serviceaccounts:"+ns) {
		return reviewed{}, rejected
	}
	acct, ok := a.accounts[ns+"/"+name]
	if !ok || st.User.UID == "" || st.User.UID != acct.UID {
		return reviewed{}, rejected
	}
	podName, podUID := st.User.Extra[ExtraPodName], st.User.Extra[ExtraPodUID]
	if len(podName) != 1 || len(podUID) != 1 || podName[0] == "" || podUID[0] == "" {
		return reviewed{}, rejected
	}
	iat, ok := issuedAt(token)
	if !ok || iat.After(a.cfg.Clock.Now().Add(clock.BaselineSkew)) {
		return reviewed{}, rejected
	}
	if err := a.checkPod(ctx, gw, acct, podName[0], podUID[0]); err != nil {
		return reviewed{}, err
	}
	return reviewed{account: acct, groups: slices.Clone(st.User.Groups), issuedAt: iat}, nil
}

// serviceAccount splits system:serviceaccount:{namespace}:{name} [K3].
func serviceAccount(username string) (ns, name string, ok bool) {
	rest, found := strings.CutPrefix(username, "system:serviceaccount:")
	if !found {
		return "", "", false
	}
	ns, name, found = strings.Cut(rest, ":")
	if !found || ns == "" || name == "" || strings.Contains(name, ":") {
		return "", "", false
	}
	return ns, name, true
}

// issuedAt reads the iat claim of a compact JWS token after its review
// authenticated it; the signature is not verified here (KR-4, KR-20).
func issuedAt(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims map[string]json.RawMessage
	if strictjson.Unmarshal(raw, strictjson.Limits{}, &claims) != nil {
		return time.Time{}, false
	}
	var iat json.Number
	if v, ok := claims["iat"]; !ok || json.Unmarshal(v, &iat) != nil {
		return time.Time{}, false
	}
	n, err := iat.Int64()
	if err != nil || n < 0 || n > strictjson.MaxSafeInteger {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

// checkPod is the agent pod check of KR-8.
func (a *Adapter) checkPod(ctx context.Context, gw string, acct Account, name, uid string) error {
	p, err := a.api.pod(ctx, gw, acct.Namespace, name)
	switch {
	case errors.Is(err, errNotFound):
		return rejected
	case err != nil:
		return dependency("the agent pod cannot be read")
	}
	if p.Metadata.UID != uid || p.Metadata.Name != name || p.Metadata.Namespace != acct.Namespace ||
		p.Spec.ServiceAccountName != acct.Name ||
		p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken {
		return rejected
	}
	for _, v := range p.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, src := range v.Projected.Sources {
			if t := src.ServiceAccountToken; t != nil && (t.Audience == nil || *t.Audience != a.cfg.GatewayAudience) {
				return rejected
			}
		}
	}
	return nil
}
