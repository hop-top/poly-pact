package adaptertest

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

func mapCase(outcome string, e Expect, req Request) *Case {
	e.Function, e.Outcome = fnMapOperation, outcome
	if req.Method == "" {
		req.Method = "GET"
	}
	if req.URL == "" {
		req.URL = "https://gateway.example/invoices/1"
	}
	p := goodPrincipal()
	return &Case{
		Request: &req,
		Call: Call{
			MappingVersion: "map-1",
			Principal:      &PrincipalJSON{ID: p.ID, Realm: acmeJS, Workload: "w-1"},
		},
		Expect: e,
	}
}

func mapFake(op core.OperationContext, err error) *fake {
	return &fake{mapOp: func(context.Context, *http.Request, adapter.Principal, string) (core.OperationContext, error) {
		return op, err
	}}
}

func TestMapOperationChecks(t *testing.T) {
	good := goodOp()
	with := func(f func(*core.OperationContext)) core.OperationContext {
		op := good
		op.Headers = map[string]string{}
		f(&op)
		return op
	}
	loose := Expect{Operation: &ExpectOperation{}}
	resources := []string{"https://invoices.example/invoices/1"}
	otherResources := []string{"https://invoices.example/invoices/2"}
	headers := map[string]string{"x-request-kind": "approval"}
	emptyHeaders := map[string]string{}

	runRows(t, []row{
		{"mapped", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{
			EnvironmentID: good.EnvironmentID, PrincipalID: good.PrincipalID, Action: "invoice.read",
			Resources: &resources, Method: "GET", TargetURI: good.TargetURI, BodyDigest: string(good.BodyDigest),
			Headers: &emptyHeaders,
		}}, Request{}), nil},
		{"mapped but errors", mapFake(core.OperationContext{}, adapter.ErrContextMismatch), mapCase(outMapped, loose, Request{}),
			[]string{"want an operation context"}},
		{"no operation id", mapFake(with(func(o *core.OperationContext) { o.OperationID = "" }), nil), mapCase(outMapped, loose, Request{}),
			[]string{"operation_id is empty"}},
		{"principal from elsewhere", mapFake(with(func(o *core.OperationContext) { o.PrincipalID = "https://idp.example/mallory" }), nil),
			mapCase(outMapped, loose, Request{}), []string{"never from the request"}},
		{"lowercase method", mapFake(with(func(o *core.OperationContext) { o.Method = "get" }), nil),
			mapCase(outMapped, loose, Request{}), []string{"not uppercase"}},
		{"http target", mapFake(with(func(o *core.OperationContext) { o.TargetURI = "http://gateway.example/x" }), nil),
			mapCase(outMapped, loose, Request{}), []string{"not an https URI"}},
		{"fragment in target", mapFake(with(func(o *core.OperationContext) { o.TargetURI = "https://gateway.example/x#f" }), nil),
			mapCase(outMapped, loose, Request{}), []string{"carries a fragment"}},
		{"bad body digest", mapFake(with(func(o *core.OperationContext) { o.BodyDigest = "abc" }), nil),
			mapCase(outMapped, loose, Request{}), []string{"body_digest"}},
		{"nil resources", mapFake(with(func(o *core.OperationContext) { o.Resources = nil }), nil),
			mapCase(outMapped, loose, Request{}), []string{"resources is nil"}},
		{"nil headers", mapFake(with(func(o *core.OperationContext) { o.Headers = nil }), nil),
			mapCase(outMapped, loose, Request{}), []string{"headers is nil"}},
		{"uppercase header name", mapFake(with(func(o *core.OperationContext) { o.Headers = map[string]string{"X-Kind": "a"} }), nil),
			mapCase(outMapped, loose, Request{}), []string{"not lowercase"}},
		{"wrong environment", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{EnvironmentID: "other"}}, Request{}),
			[]string{"environment_id is"}},
		{"wrong principal expectation", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{PrincipalID: "other"}}, Request{}),
			[]string{"principal_id is"}},
		{"wrong action", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{Action: "invoice.approve"}}, Request{}),
			[]string{"action is"}},
		{"wrong resources", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{Resources: &otherResources}}, Request{}),
			[]string{"resources are"}},
		{"wrong method", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{Method: "POST"}}, Request{}),
			[]string{"method is"}},
		{"wrong target", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{TargetURI: "https://x.example/"}}, Request{}),
			[]string{"target_uri is"}},
		{"wrong digest", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{BodyDigest: "yy"}}, Request{}),
			[]string{"body_digest is"}},
		{"wrong headers", mapFake(good, nil), mapCase(outMapped, Expect{Operation: &ExpectOperation{Headers: &headers}}, Request{}),
			[]string{"headers are"}},

		{"error", mapFake(core.OperationContext{}, adapter.ErrContextMismatch),
			mapCase(outError, Expect{ReasonCode: "CONTEXT_MISMATCH"}, Request{}), nil},
		{"error expected, mapped", mapFake(good, nil), mapCase(outError, Expect{}, Request{}), []string{"want an error"}},
		{"error with an operation", mapFake(good, errors.New("x")), mapCase(outError, Expect{}, Request{}),
			[]string{"together with an error"}},
	})
}

// codedOnly carries a draft 13.4 code but is not the package sentinel, so
// errors.Is does not match it.
type codedOnly struct{ code adapter.Code }

func (e codedOnly) Error() string      { return "coded only" }
func (e codedOnly) Code() adapter.Code { return e.code }

// TestMapOperationMalformedRequestCode: the code a rejected malformed request
// reports, INVALID_MESSAGE (draft 13.4), is checked against the case, and the
// error must be the ErrInvalidMessage sentinel or wrap it.
func TestMapOperationMalformedRequestCode(t *testing.T) {
	want := Expect{ReasonCode: "INVALID_MESSAGE"}
	empty := core.OperationContext{}
	runRows(t, []row{
		{"the sentinel", mapFake(empty, adapter.ErrInvalidMessage), mapCase(outError, want, Request{}), nil},
		{"wrapped", mapFake(empty, fmt.Errorf("target: %w: fragment", fmt.Errorf("map: %w", adapter.ErrInvalidMessage))),
			mapCase(outError, want, Request{}), nil},
		{"another code", mapFake(empty, adapter.ErrUnsupportedRequirement), mapCase(outError, want, Request{}),
			[]string{"code is UNSUPPORTED_REQUIREMENT, want INVALID_MESSAGE"}},
		{"no code", mapFake(empty, errors.New("cannot map")), mapCase(outError, want, Request{}),
			[]string{"carries no draft 13.4 code, want INVALID_MESSAGE"}},
		{"the code without the sentinel", mapFake(empty, codedOnly{adapter.CodeInvalidMessage}), mapCase(outError, want, Request{}),
			[]string{"does not wrap the sentinel"}},
	})
}

func TestMapOperationRestoresTheBody(t *testing.T) {
	body := []byte(`{"amount":"1"}`)
	req := Request{Method: "POST", URL: "https://gateway.example/invoices/1", BodyB64: base64.StdEncoding.EncodeToString(body)}
	read := func(restore func(*http.Request, []byte)) *fake {
		return &fake{mapOp: func(_ context.Context, r *http.Request, _ adapter.Principal, _ string) (core.OperationContext, error) {
			b, _ := io.ReadAll(r.Body)
			restore(r, b)
			return goodOp(), nil
		}}
	}
	runRows(t, []row{
		{"restored", read(func(r *http.Request, b []byte) { r.Body = io.NopCloser(bytes.NewReader(b)) }),
			mapCase(outMapped, Expect{Operation: &ExpectOperation{}}, req), nil},
		{"left consumed", read(func(r *http.Request, b []byte) {}),
			mapCase(outMapped, Expect{Operation: &ExpectOperation{}}, req), []string{"must restore"}},
		{"left nil", read(func(r *http.Request, b []byte) { r.Body = nil }),
			mapCase(outMapped, Expect{Operation: &ExpectOperation{}}, req), []string{"without a body"}},
		{"restored truncated", read(func(r *http.Request, b []byte) { r.Body = io.NopCloser(bytes.NewReader(b[:3])) }),
			mapCase(outMapped, Expect{Operation: &ExpectOperation{}}, req), []string{"want the original"}},
	})
}

func TestMapOperationReceivesTheCase(t *testing.T) {
	var gotReq *http.Request
	var gotP adapter.Principal
	var gotVersion string
	f := &fake{mapOp: func(_ context.Context, r *http.Request, p adapter.Principal, v string) (core.OperationContext, error) {
		gotReq, gotP, gotVersion = r, p, v
		return goodOp(), nil
	}}
	c := mapCase(outMapped, Expect{Operation: &ExpectOperation{}}, Request{
		Method: "POST", URL: "https://svc:pw@gateway.example/invoices/1?a=%2f&b=2#frag",
		Headers:        map[string]string{"X-One": "1", "Host": "attacker.example"},
		NativeStateRef: "alice",
	})
	wantClean(t, runFake(t, f, c))
	if gotReq.Method != "POST" || gotReq.URL.User == nil || gotReq.URL.Fragment != "frag" || gotReq.URL.RawQuery != "a=%2f&b=2" {
		t.Errorf("the adapter got %s %v, want the URL exactly as the case states it", gotReq.Method, gotReq.URL)
	}
	if gotReq.Header.Get("X-One") != "1" || gotReq.Host != "attacker.example" {
		t.Errorf("headers = %v, host = %q", gotReq.Header, gotReq.Host)
	}
	if gotReq.Header.Get("Authorization") != "Bearer tok-alice" {
		t.Errorf("the Credential hook did not run: %v", gotReq.Header)
	}
	if gotP.ID != "https://idp.example/alice" || gotP.Realm != acme || gotP.Mechanism != "test" || !gotP.AuthenticatedAt.Equal(now) {
		t.Errorf("principal = %+v", gotP)
	}
	if gotVersion != "map-1" {
		t.Errorf("mapping version = %q", gotVersion)
	}
}
