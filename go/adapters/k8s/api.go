package k8s

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"hop.top/pact-go/core/strictjson"
)

// The API objects the adapter sends and reads, defined by hand from the
// Kubernetes API reference (profile sources K1, K2, K3, K10, K11): only the
// members the profile uses.

// TokenReview is an authentication.k8s.io/v1 TokenReview [K1].
type TokenReview struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Spec       TokenReviewSpec   `json:"spec"`
	Status     TokenReviewStatus `json:"status"`
}

// TokenReviewSpec is the spec of a TokenReview: the opaque bearer token and
// the audiences the resource server identifies as.
type TokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

// TokenReviewStatus is the answer of a TokenReview.
type TokenReviewStatus struct {
	Authenticated bool     `json:"authenticated"`
	Audiences     []string `json:"audiences"`
	Error         string   `json:"error"`
	User          UserInfo `json:"user"`
}

// UserInfo is the user a review reports [K2].
type UserInfo struct {
	Username string              `json:"username"`
	UID      string              `json:"uid"`
	Groups   []string            `json:"groups"`
	Extra    map[string][]string `json:"extra"`
}

// The extra keys of a pod-bound token's review [K4].
const (
	ExtraPodName = "authentication.kubernetes.io/pod-name"
	ExtraPodUID  = "authentication.kubernetes.io/pod-uid"
)

// SubjectAccessReview is an authorization.k8s.io/v1 SubjectAccessReview
// [K10].
type SubjectAccessReview struct {
	APIVersion string                    `json:"apiVersion"`
	Kind       string                    `json:"kind"`
	Spec       SubjectAccessReviewSpec   `json:"spec"`
	Status     SubjectAccessReviewStatus `json:"status"`
}

// SubjectAccessReviewSpec asks about one access of one user. Extra is never
// set (KR-15, open item O5).
type SubjectAccessReviewSpec struct {
	User               string              `json:"user"`
	UID                string              `json:"uid,omitempty"`
	Groups             []string            `json:"groups,omitempty"`
	ResourceAttributes *ResourceAttributes `json:"resourceAttributes"`
}

// ResourceAttributes describe a resource access [K11]: an empty Namespace is
// every namespace, and "*" is every value of Group, Resource and Verb.
type ResourceAttributes struct {
	Namespace   string `json:"namespace"`
	Verb        string `json:"verb"`
	Group       string `json:"group"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

// SubjectAccessReviewStatus is the authorizer's answer [K10].
type SubjectAccessReviewStatus struct {
	Allowed         bool   `json:"allowed"`
	Denied          bool   `json:"denied"`
	Reason          string `json:"reason"`
	EvaluationError string `json:"evaluationError"`
}

// SelfSubjectReview is an authentication.k8s.io/v1 SelfSubjectReview [K3].
type SelfSubjectReview struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     struct {
		UserInfo UserInfo `json:"userInfo"`
	} `json:"status"`
}

// Pod is the part of a v1 Pod the agent pod check reads (KR-8).
type Pod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"metadata"`
	Spec struct {
		ServiceAccountName           string `json:"serviceAccountName"`
		AutomountServiceAccountToken *bool  `json:"automountServiceAccountToken"`
		Volumes                      []struct {
			Projected *struct {
				Sources []struct {
					ServiceAccountToken *struct {
						Audience *string `json:"audience"`
					} `json:"serviceAccountToken"`
				} `json:"sources"`
			} `json:"projected"`
		} `json:"volumes"`
	} `json:"spec"`
}

// The API paths the adapter calls [K1], [K3], [K10], [K13].
const (
	pathTokenReviews = "/apis/authentication.k8s.io/v1/tokenreviews"
	pathSelfReviews  = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
	pathSARs         = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
)

// maxAnswer bounds an answer of the API server.
const maxAnswer = 1 << 20

// errNotFound is a read of an object that does not exist.
var errNotFound = errors.New("k8s: not found")

// errRefused is an answer 401 or 403: the API server refused the caller's
// credential or the request.
var errRefused = errors.New("k8s: refused")

// errUnusable is any other answer the adapter cannot use. Its text never
// holds a token.
var errUnusable = errors.New("k8s: unusable answer")

// apiClient sends requests to the pinned API server.
type apiClient struct {
	base    string
	client  *http.Client
	timeout time.Duration
}

func newAPIClient(base string, roots *x509.CertPool, timeout time.Duration) *apiClient {
	return &apiClient{base: base, client: newHTTPClient(roots), timeout: timeout}
}

// do sends one request with the bearer token and decodes a 200 or 201 answer
// strictly into out, ignoring members the adapter does not read.
func (c *apiClient) do(ctx context.Context, method, path, token string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var body io.Reader = http.NoBody
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return errUnusable
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return errUnusable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return errUnusable
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	switch {
	case err != nil || len(raw) > maxAnswer:
		return errUnusable
	case resp.StatusCode == http.StatusNotFound:
		return errNotFound
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return errRefused
	case resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated:
		return errUnusable
	}
	if err := decode(raw, out); err != nil {
		return errUnusable
	}
	return nil
}

// decode reads one JSON object with no duplicate member into out; members
// out does not name are ignored, as an API object carries many.
func decode(raw []byte, out any) error {
	var probe map[string]json.RawMessage
	if err := strictjson.Unmarshal(raw, strictjson.Limits{MaxBytes: maxAnswer}, &probe); err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// tokenReview reviews token for the one gateway audience (KR-4).
func (c *apiClient) tokenReview(ctx context.Context, gatewayToken, token, audience string) (TokenReviewStatus, error) {
	in := TokenReview{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview",
		Spec: TokenReviewSpec{Token: token, Audiences: []string{audience}}}
	var out TokenReview
	if err := c.do(ctx, http.MethodPost, pathTokenReviews, gatewayToken, in, &out); err != nil {
		return TokenReviewStatus{}, err
	}
	return out.Status, nil
}

// pod reads a pod with no resourceVersion, which returns the most recent
// data [K13].
func (c *apiClient) pod(ctx context.Context, gatewayToken, namespace, name string) (Pod, error) {
	var out Pod
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(name)
	if err := c.do(ctx, http.MethodGet, path, gatewayToken, nil, &out); err != nil {
		return Pod{}, err
	}
	return out, nil
}

// accessReview asks whether the spec's user may make its access.
func (c *apiClient) accessReview(ctx context.Context, gatewayToken string, spec SubjectAccessReviewSpec) (SubjectAccessReviewStatus, error) {
	in := SubjectAccessReview{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview", Spec: spec}
	var out SubjectAccessReview
	if err := c.do(ctx, http.MethodPost, pathSARs, gatewayToken, in, &out); err != nil {
		return SubjectAccessReviewStatus{}, err
	}
	return out.Status, nil
}

// selfReview reports how the cluster maps the caller of token [K3].
func (c *apiClient) selfReview(ctx context.Context, token string) (UserInfo, error) {
	in := map[string]string{"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"}
	var out SelfSubjectReview
	if err := c.do(ctx, http.MethodPost, pathSelfReviews, token, in, &out); err != nil {
		return UserInfo{}, err
	}
	if out.Status.UserInfo.Username == "" {
		return UserInfo{}, fmt.Errorf("k8s: self-review names no user: %w", errUnusable)
	}
	return out.Status.UserInfo, nil
}
