package aws_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"
)

// TestHarnessBuildsTheEvent checks the event builder of the harness against
// the steps of the AWS cases README, section "Events", so that a harness
// defect is not mistaken for an adapter defect.
func TestHarnessBuildsTheEvent(t *testing.T) {
	st := []byte(`{
	  "model": "aws/1",
	  "gateway": {"tenant_id": "t", "environment_id": "https://e.example/env", "origin": "HTTPS://API.Metrics.Example", "header_allowlist": []},
	  "api": {"partition": "aws", "account_id": "111122223333", "api_id": "abc"},
	  "roles": [],
	  "sessions": [{"ref": "s", "iam": {"userArn": "u", "userId": "i"}}],
	  "mappings": [{"version": "v", "routes": [{"method": "POST", "path": "/a/{id}", "action": "x", "resource": "r"}]}],
	  "event": {"stageVariables": {"k": "v"}, "requestContext": {"stage": null}}
	}`)
	now := time.Unix(1792080000, 0)
	w, err := loadWorld(st, now)
	if err != nil {
		t.Fatal(err)
	}
	const raw = "https://u:p@internal.example:8443/a/%41b#f?x=1&x=2"
	r, err := http.NewRequest(http.MethodPost, raw, bytes.NewReader([]byte("hi")))
	if err != nil {
		t.Fatal(err)
	}
	r.RequestURI = raw
	r.Header.Set("X-Thing", "1")
	r.Header.Set("Cookie", "a=b")
	if err := w.Credential(r, "s"); err != nil {
		t.Fatal(err)
	}
	out, err := w.event(r)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(r.Body); string(b) != "hi" {
		t.Errorf("body after the build = %q, want it restored", b)
	}
	var ev map[string]any
	if err := json.Unmarshal(out, &ev); err != nil {
		t.Fatal(err)
	}
	rc := ev["requestContext"].(map[string]any)
	want := map[string]any{
		"rawPath":         "/a/%41b#f",
		"rawQueryString":  "x=1&x=2",
		"routeKey":        "POST /a/{id}",
		"body":            "aGk=",
		"isBase64Encoded": true,
		"headers":         map[string]any{"x-thing": "1"},
		"cookies":         []any{"a=b"},
		"stageVariables":  map[string]any{"k": "v"},
	}
	for k, v := range want {
		if !reflect.DeepEqual(ev[k], v) {
			t.Errorf("%s = %#v, want %#v", k, ev[k], v)
		}
	}
	wantRC := map[string]any{
		"accountId":    "111122223333",
		"apiId":        "abc",
		"domainName":   "u:p@api.metrics.example",
		"domainPrefix": "api",
		"routeKey":     "POST /a/{id}",
		"timeEpoch":    float64(1792080000000),
		"time":         "15/Oct/2026:16:00:00 +0000",
		"authorizer":   map[string]any{"iam": map[string]any{"userArn": "u", "userId": "i"}},
	}
	for k, v := range wantRC {
		if !reflect.DeepEqual(rc[k], v) {
			t.Errorf("requestContext.%s = %#v, want %#v", k, rc[k], v)
		}
	}
	if _, ok := rc["stage"]; ok {
		t.Error("requestContext.stage survived a null in the patch")
	}
	for _, k := range []string{"queryStringParameters", "pathParameters"} {
		if _, ok := ev[k]; ok {
			t.Errorf("%s is set; the harness leaves it to the patch", k)
		}
	}
	if hc := rc["http"].(map[string]any); hc["method"] != "POST" || hc["path"] != "/a/%41b#f" {
		t.Errorf("requestContext.http = %v", hc)
	}
}
