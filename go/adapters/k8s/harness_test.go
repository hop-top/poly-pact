package k8s_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// harnessState is a k8s/1 state that exercises every rule of the harness's
// API server.
const harnessState = `{
  "model": "k8s/1",
  "gateway": {"tenant_id": "t", "environment_id": "https://e.example/env", "origin": "https://gw.example", "header_allowlist": []},
  "cluster": {"cluster_id": "c1", "gateway_audience": "https://gw.example", "namespaces": ["ops"]},
  "accounts": [{"namespace": "ops", "name": "a", "uid": "u-a"}],
  "gateway_account": {"token": "gw-token"},
  "tokens": [{"ref": "a", "token": "tok-a", "reviews": [
    {"audiences": ["https://gw.example"], "status": {"authenticated": true, "audiences": ["https://gw.example"]}},
    {"audiences": [], "status": {"authenticated": true, "audiences": ["https://api.example"]}}
  ]}],
  "pods": [{"metadata": {"name": "p", "namespace": "ops", "uid": "pu"}, "spec": {"serviceAccountName": "a"}}],
  "authorization": [
    {"subject": {"group": "system:serviceaccounts"}, "verb": "get", "api_group": "", "resource": "secrets", "namespace": "ops", "status": {"allowed": true}},
    {"subject": {"user": "system:serviceaccount:ops:a"}, "verb": "create", "api_group": "", "resource": "pods", "subresource": "exec", "namespace": "ops", "status": {"allowed": false, "evaluationError": "e"}}
  ],
  "self_reviews": [{"token": "exec-token", "user_info": {"username": "system:serviceaccount:ops:a", "uid": "u-a"}}],
  "enrollments": [],
  "unavailable_sources": []
}`

// call sends a request to the world's API server and returns the status
// code and the decoded body.
func call(t *testing.T, w *world, method, path, token, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, w.apiServer()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := w.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func statusOf(m map[string]any) map[string]any {
	s, _ := m["status"].(map[string]any)
	return s
}

// TestHarnessAPIServer checks the harness's API server against the rules of
// the Kubernetes cases README, section "API server", so that a harness defect
// is not mistaken for an adapter defect.
func TestHarnessAPIServer(t *testing.T) {
	w, err := loadWorld(t, []byte(harnessState), time.Unix(1792080000, 0))
	if err != nil {
		t.Fatal(err)
	}
	tr := func(aud string) string {
		return `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"tok-a"` + aud + `}}`
	}
	if code, m := call(t, w, "POST", pathTokenReviews, "gw-token", tr(`,"audiences":["https://gw.example"]`), nil); code != 201 ||
		statusOf(m)["audiences"].([]any)[0] != "https://gw.example" {
		t.Errorf("review for the gateway audience: %d %v", code, m)
	}
	if code, m := call(t, w, "POST", pathTokenReviews, "gw-token", tr(""), nil); code != 201 ||
		statusOf(m)["audiences"].([]any)[0] != "https://api.example" {
		t.Errorf("review without audiences: %d %v, want the entry with no audiences", code, m)
	}
	if code, m := call(t, w, "POST", pathTokenReviews, "gw-token", tr(`,"audiences":["https://other.example"]`), nil); code != 201 ||
		statusOf(m)["authenticated"] != false {
		t.Errorf("review for an unlisted audience: %d %v, want authenticated false", code, m)
	}
	if code, _ := call(t, w, "POST", pathTokenReviews, "tok-a", tr(""), nil); code != 401 {
		t.Errorf("review not made with the gateway token: %d, want 401", code)
	}
	if code, _ := call(t, w, "POST", pathTokenReviews, "gw-token", tr(""), map[string]string{"Impersonate-User": "x"}); code != 403 {
		t.Errorf("impersonation header: %d, want 403", code)
	}
	if code, _ := call(t, w, "GET", "/api/v1/namespaces/ops/pods/p", "gw-token", "", map[string]string{"X-Remote-User": "x"}); code != 403 {
		t.Errorf("authenticating-proxy header: %d, want 403", code)
	}
	sar := func(user, groups, verb, sub string) string {
		return `{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"` + user + `"` + groups +
			`,"resourceAttributes":{"namespace":"ops","verb":"` + verb + `","group":"","resource":"` + sub + `}}}`
	}
	if _, m := call(t, w, "POST", pathSARs, "gw-token", sar("system:serviceaccount:ops:a", `,"groups":["system:serviceaccounts"]`, "get", `secrets"`), nil); statusOf(m)["allowed"] != true {
		t.Errorf("group grant with the group: %v, want allowed", m)
	}
	if _, m := call(t, w, "POST", pathSARs, "gw-token", sar("system:serviceaccount:ops:a", "", "get", `secrets"`), nil); statusOf(m)["allowed"] != false {
		t.Errorf("group grant without groups: %v, want not allowed", m)
	}
	if _, m := call(t, w, "POST", pathSARs, "gw-token", sar("system:serviceaccount:ops:a", "", "create", `pods","subresource":"exec"`), nil); statusOf(m)["evaluationError"] != "e" {
		t.Errorf("subresource grant: %v, want its status", m)
	}
	if _, m := call(t, w, "POST", pathSARs, "gw-token", sar("system:serviceaccount:ops:a", "", "create", `pods"`), nil); statusOf(m)["allowed"] != false || statusOf(m)["evaluationError"] != nil {
		t.Errorf("a grant of a subresource answers for the resource: %v", m)
	}
	if code, m := call(t, w, "GET", "/api/v1/namespaces/ops/pods/p", "gw-token", "", nil); code != 200 || m["kind"] != "Pod" {
		t.Errorf("pod read: %d %v", code, m)
	}
	if code, _ := call(t, w, "GET", "/api/v1/namespaces/ops/pods/p?resourceVersion=0", "gw-token", "", nil); code != 400 {
		t.Errorf("pod read with a query: %d, want 400", code)
	}
	if code, _ := call(t, w, "GET", "/api/v1/namespaces/ops/pods/q", "gw-token", "", nil); code != 404 {
		t.Errorf("missing pod: %d, want 404", code)
	}
	if code, m := call(t, w, "POST", pathSelfReviews, "exec-token", `{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`, nil); code != 201 ||
		statusOf(m)["userInfo"].(map[string]any)["uid"] != "u-a" {
		t.Errorf("self-review: %d %v", code, m)
	}
	if code, _ := call(t, w, "POST", pathSelfReviews, "unknown", `{}`, nil); code != 401 {
		t.Errorf("self-review with an unknown token: %d, want 401", code)
	}
	w.setUnavailable(srcTokenReviews, srcPods, srcSARs, srcSelfReviews)
	for _, c := range []struct{ method, path, token, body string }{
		{"POST", pathTokenReviews, "gw-token", tr("")},
		{"GET", "/api/v1/namespaces/ops/pods/p", "gw-token", ""},
		{"POST", pathSARs, "gw-token", sar("u", "", "get", `secrets"`)},
		{"POST", pathSelfReviews, "exec-token", `{}`},
	} {
		if code, _ := call(t, w, c.method, c.path, c.token, c.body, nil); code != 503 {
			t.Errorf("%s %s with the source unavailable: %d, want 503", c.method, c.path, code)
		}
	}
}
