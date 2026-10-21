package k8s_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/strictjson"
)

// k8sModel is the model of the native state of the Kubernetes cases, defined
// in spec/v1.0/fixtures/adapters/k8s/README.md.
const k8sModel = "k8s/1"

// The source ids of the k8s/1 model: the API server's review, read and
// authorization endpoints, and the enrollment registry.
const (
	srcTokenReviews  = "tokenreviews"
	srcPods          = "pods"
	srcSARs          = "subjectaccessreviews"
	srcSelfReviews   = "selfsubjectreviews"
	srcEnrollmentReg = "enrollment-registry"
)

// The API paths the harness's API server answers (profile sources K1, K3,
// K10, K13).
const (
	pathTokenReviews = "/apis/authentication.k8s.io/v1/tokenreviews"
	pathSelfReviews  = "/apis/authentication.k8s.io/v1/selfsubjectreviews"
	pathSARs         = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
	podsPrefix       = "/api/v1/namespaces/"
)

// k8sState is the k8s/1 native state of a case.
type k8sState struct {
	Model              string              `json:"model"`
	Gateway            memory.Gateway      `json:"gateway"`
	Cluster            clusterState        `json:"cluster"`
	ReviewBound        *int64              `json:"review_bound_seconds"`
	PreflightInterval  *int64              `json:"preflight_interval_seconds"`
	Accounts           []accountState      `json:"accounts"`
	GatewayAccount     gatewayAccount      `json:"gateway_account"`
	Tokens             []tokenState        `json:"tokens"`
	Pods               []json.RawMessage   `json:"pods"`
	Authorization      []grantState        `json:"authorization"`
	SelfReviews        []selfReviewState   `json:"self_reviews"`
	Executors          []executorState     `json:"executors"`
	Enrollments        []memory.Enrollment `json:"enrollments"`
	UnavailableSources []string            `json:"unavailable_sources"`
}

type clusterState struct {
	ClusterID       string   `json:"cluster_id"`
	GatewayAudience string   `json:"gateway_audience"`
	Namespaces      []string `json:"namespaces"`
}

type accountState struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type gatewayAccount struct {
	Token string `json:"token"`
}

type tokenState struct {
	Ref     string        `json:"ref"`
	Token   string        `json:"token"`
	Reviews []reviewState `json:"reviews"`
}

type reviewState struct {
	Audiences []string        `json:"audiences"`
	Status    json.RawMessage `json:"status"`
}

type grantState struct {
	Subject     subjectState    `json:"subject"`
	Verb        string          `json:"verb"`
	APIGroup    string          `json:"api_group"`
	Resource    string          `json:"resource"`
	Subresource string          `json:"subresource"`
	Namespace   string          `json:"namespace"`
	Name        *string         `json:"name"`
	Status      json.RawMessage `json:"status"`
}

type subjectState struct {
	User  string `json:"user"`
	Group string `json:"group"`
}

type selfReviewState struct {
	Token    string          `json:"token"`
	UserInfo json.RawMessage `json:"user_info"`
}

type executorState struct {
	Account     accountRef `json:"account"`
	Credentials []string   `json:"credentials"`
	Token       *string    `json:"token"`
}

type accountRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// world is a parsed k8s/1 state with the harness's API server: a TLS server
// that answers TokenReview, SubjectAccessReview, SelfSubjectReview and pod
// reads from the state, as the Kubernetes cases README, section "API server",
// defines.
type world struct {
	st     k8sState
	now    time.Time
	server *httptest.Server

	mu       sync.Mutex
	creds    map[*http.Request]string
	received []http.Header
}

// modelOf returns the model member of a native state.
func modelOf(raw []byte) (string, error) {
	var probe struct {
		Model string `json:"model"`
	}
	// Only the model member is read here; the full parse is strict.
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", err
	}
	return probe.Model, nil
}

// loadWorld parses a k8s/1 state strictly and starts its API server, which
// tb closes.
func loadWorld(tb testing.TB, raw []byte, now time.Time) (*world, error) {
	var st k8sState
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &st); err != nil {
		return nil, fmt.Errorf("k8s/1 state: %w", err)
	}
	if st.Model != k8sModel {
		return nil, fmt.Errorf("model is %q, want %q", st.Model, k8sModel)
	}
	return newWorld(tb, st, now)
}

func newWorld(tb testing.TB, st k8sState, now time.Time) (*world, error) {
	switch {
	case st.Gateway.TenantID == "" || st.Gateway.EnvironmentID == "" || st.Gateway.Origin == "":
		return nil, errors.New("k8s/1 state: gateway needs a tenant_id, an environment_id and an origin")
	case st.Cluster.ClusterID == "" || st.Cluster.GatewayAudience == "" || len(st.Cluster.Namespaces) == 0:
		return nil, errors.New("k8s/1 state: cluster needs a cluster_id, a gateway_audience and namespaces")
	case st.GatewayAccount.Token == "":
		return nil, errors.New("k8s/1 state: gateway_account needs a token")
	}
	refs := map[string]bool{}
	for _, t := range st.Tokens {
		if t.Ref == "" || refs[t.Ref] || t.Token == "" {
			return nil, fmt.Errorf("k8s/1 state: token %q is empty or used twice", t.Ref)
		}
		refs[t.Ref] = true
	}
	for _, g := range st.Authorization {
		if (g.Subject.User == "") == (g.Subject.Group == "") || g.Verb == "" || g.Resource == "" || len(g.Status) == 0 {
			return nil, errors.New("k8s/1 state: a grant needs one subject, a verb, a resource and a status")
		}
	}
	w := &world{st: st, now: now, creds: map[*http.Request]string{}}
	w.server = httptest.NewTLSServer(http.HandlerFunc(w.serve))
	tb.Cleanup(w.server.Close)
	return w, nil
}

// client returns an HTTP client that trusts the harness's API server.
func (w *world) client() *http.Client { return w.server.Client() }

// apiServer is the URL of the harness's API server.
func (w *world) apiServer() string { return w.server.URL }

// unavailable reports whether the source named id cannot answer.
func (w *world) unavailable(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Contains(w.st.UnavailableSources, id)
}

// setUnavailable replaces the sources that cannot answer.
func (w *world) setUnavailable(ids ...string) {
	w.mu.Lock()
	w.st.UnavailableSources = ids
	w.mu.Unlock()
}

// Credential attaches the bearer token of the token entry ref to r.
func (w *world) Credential(r *http.Request, ref string) error {
	for _, t := range w.st.Tokens {
		if t.Ref == ref {
			r.Header.Set("Authorization", "Bearer "+t.Token)
			return nil
		}
	}
	return fmt.Errorf("no token %q", ref)
}

// receivedHeaders returns the headers of every request the API server
// received, in order.
func (w *world) receivedHeaders() []http.Header {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.received)
}

// status writes a Kubernetes Status object with the given code.
func status(rw http.ResponseWriter, code int, reason string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"apiVersion": "v1", "kind": "Status", "status": "Failure", "reason": reason, "code": code,
	})
}

// object writes a JSON object with status 200 or 201.
func object(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	_ = json.NewEncoder(rw).Encode(v)
}

// bearer returns the token of the request's Authorization header.
func bearer(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(v, "Bearer "); ok {
		return t
	}
	return ""
}

// serve answers a request to the API server by the rules of the Kubernetes
// cases README, section "API server".
func (w *world) serve(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	w.received = append(w.received, r.Header.Clone())
	w.mu.Unlock()
	for name := range r.Header {
		n := strings.ToLower(name)
		if strings.HasPrefix(n, "impersonate-") || strings.HasPrefix(n, "x-remote-") {
			status(rw, http.StatusForbidden, "Forbidden")
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		status(rw, http.StatusBadRequest, "BadRequest")
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == pathSelfReviews:
		w.selfReview(rw, r)
		return
	case bearer(r) != w.st.GatewayAccount.Token:
		status(rw, http.StatusUnauthorized, "Unauthorized")
		return
	case r.Method == http.MethodPost && r.URL.Path == pathTokenReviews:
		w.tokenReview(rw, body)
	case r.Method == http.MethodPost && r.URL.Path == pathSARs:
		w.accessReview(rw, body)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, podsPrefix):
		w.podRead(rw, r)
	default:
		status(rw, http.StatusNotFound, "NotFound")
	}
}

func (w *world) tokenReview(rw http.ResponseWriter, body []byte) {
	if w.unavailable(srcTokenReviews) {
		status(rw, http.StatusServiceUnavailable, "ServiceUnavailable")
		return
	}
	var tr struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			Token     string   `json:"token"`
			Audiences []string `json:"audiences"`
		} `json:"spec"`
	}
	if json.NewDecoder(bytes.NewReader(body)).Decode(&tr) != nil || tr.Kind != "TokenReview" || tr.Spec.Token == "" {
		status(rw, http.StatusBadRequest, "BadRequest")
		return
	}
	st := json.RawMessage(`{"authenticated":false}`)
	for _, t := range w.st.Tokens {
		if t.Token != tr.Spec.Token {
			continue
		}
		for _, rv := range t.Reviews {
			if slices.Equal(rv.Audiences, tr.Spec.Audiences) || len(rv.Audiences) == 0 && len(tr.Spec.Audiences) == 0 {
				st = rv.Status
				break
			}
		}
	}
	object(rw, http.StatusCreated, map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
		"spec": map[string]any{"token": tr.Spec.Token, "audiences": tr.Spec.Audiences}, "status": st,
	})
}

// sarSpec is the part of a SubjectAccessReview the API server reads.
type sarSpec struct {
	User               string   `json:"user"`
	UID                string   `json:"uid"`
	Groups             []string `json:"groups"`
	ResourceAttributes *struct {
		Namespace   string `json:"namespace"`
		Verb        string `json:"verb"`
		Group       string `json:"group"`
		Resource    string `json:"resource"`
		Subresource string `json:"subresource"`
		Name        string `json:"name"`
	} `json:"resourceAttributes"`
}

// matches reports whether grant g answers the review s: its subject is the
// review's user or one of its groups, and its verb, API group, resource,
// subresource and namespace are those of the review; a grant without a name
// answers for every name.
func (g grantState) matches(s sarSpec) bool {
	ra := s.ResourceAttributes
	switch {
	case ra == nil:
		return false
	case g.Subject.User != "" && g.Subject.User != s.User:
		return false
	case g.Subject.Group != "" && !slices.Contains(s.Groups, g.Subject.Group):
		return false
	case g.Name != nil && *g.Name != ra.Name:
		return false
	}
	return g.Verb == ra.Verb && g.APIGroup == ra.Group && g.Resource == ra.Resource &&
		g.Subresource == ra.Subresource && g.Namespace == ra.Namespace
}

func (w *world) accessReview(rw http.ResponseWriter, body []byte) {
	if w.unavailable(srcSARs) {
		status(rw, http.StatusServiceUnavailable, "ServiceUnavailable")
		return
	}
	var sar struct {
		Kind string  `json:"kind"`
		Spec sarSpec `json:"spec"`
	}
	if json.NewDecoder(bytes.NewReader(body)).Decode(&sar) != nil || sar.Kind != "SubjectAccessReview" ||
		sar.Spec.User == "" || sar.Spec.ResourceAttributes == nil {
		status(rw, http.StatusBadRequest, "BadRequest")
		return
	}
	st := json.RawMessage(`{"allowed":false}`)
	w.mu.Lock()
	grants := slices.Clone(w.st.Authorization)
	w.mu.Unlock()
	for _, g := range grants {
		if g.matches(sar.Spec) {
			st = g.Status
			break
		}
	}
	object(rw, http.StatusCreated, map[string]any{
		"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": sar.Spec, "status": st,
	})
}

func (w *world) selfReview(rw http.ResponseWriter, r *http.Request) {
	if w.unavailable(srcSelfReviews) {
		status(rw, http.StatusServiceUnavailable, "ServiceUnavailable")
		return
	}
	tok := bearer(r)
	for _, s := range w.st.SelfReviews {
		if tok != "" && s.Token == tok {
			object(rw, http.StatusCreated, map[string]any{
				"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview",
				"status": map[string]any{"userInfo": s.UserInfo},
			})
			return
		}
	}
	status(rw, http.StatusUnauthorized, "Unauthorized")
}

func (w *world) podRead(rw http.ResponseWriter, r *http.Request) {
	if w.unavailable(srcPods) {
		status(rw, http.StatusServiceUnavailable, "ServiceUnavailable")
		return
	}
	if r.URL.RawQuery != "" {
		status(rw, http.StatusBadRequest, "BadRequest")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, podsPrefix), "/")
	if len(parts) != 3 || parts[1] != "pods" {
		status(rw, http.StatusNotFound, "NotFound")
		return
	}
	for _, raw := range w.st.Pods {
		var p struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if json.Unmarshal(raw, &p) == nil && p.Metadata.Namespace == parts[0] && p.Metadata.Name == parts[2] {
			var obj map[string]any
			if json.Unmarshal(raw, &obj) != nil {
				break
			}
			obj["apiVersion"], obj["kind"] = "v1", "Pod"
			object(rw, http.StatusOK, obj)
			return
		}
	}
	status(rw, http.StatusNotFound, "NotFound")
}
