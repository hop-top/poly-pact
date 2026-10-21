package aws_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// stub is the red baseline of the AWS cases: the adapter a Lambda function
// gets by reading the API Gateway event in the obvious way. It takes the
// caller from any request header that spells an ARN and otherwise from
// userArn, derives the role ARN from the session ARN, so it loses the role's
// path, and checks no role table, unique ID, account, session name,
// configuration check, authorizer member or Cognito identity. It rebuilds the
// target from the decoded path and query maps, refuses nothing, resolves the
// first enrollment of the workload whatever agent is named, passes every
// check, and runs the operation while authorizing.
//
// Every AWS case except those of stubPasses must fail against it; see
// TestStubFailsTheAWSCases.
type stub struct {
	w     *world
	clk   clock.Clock
	hooks *adaptertest.Hooks
}

// stubPasses are the AWS cases that the stub passes: a request with no IAM
// context and no ARN in a header has no caller to read, the declared
// executor passes as every check does, and the one enrollment of a workload
// is also the first one.
var stubPasses = map[string]bool{
	"AWS-09.no-iam-context":   true,
	"AWS-09.contract-request": true,
	"AWS-11.declared":         true,
	"AWS-14.dedicated":        true,
}

// stubEventKey is the context key under which the stub's Arrive hook attaches
// the raw event.
type stubEventKey struct{}

// stubFactory builds the stub for an aws/1 case; it realizes no other model.
func stubFactory(_ testing.TB, env adaptertest.Env) (adaptertest.Subject, error) {
	model, err := modelOf(env.State)
	if err != nil {
		return adaptertest.Subject{}, err
	}
	if model != awsModel {
		return adaptertest.Subject{}, fmt.Errorf("stub: model %q is not realized", model)
	}
	w, err := loadWorld(env.State, env.Clock.Now())
	if err != nil {
		return adaptertest.Subject{}, err
	}
	s := &stub{w: w, clk: env.Clock, hooks: env.Hooks}
	return adaptertest.Subject{
		Adapter: s,
		Arrive: func(r *http.Request) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), stubEventKey{}, w.mustEvent(r)))
		},
		Credential: w.Credential,
	}, nil
}

// stubEvent is the part of the event the stub reads, decoded leniently.
type stubEvent struct {
	Headers               map[string]string `json:"headers"`
	QueryStringParameters map[string]string `json:"queryStringParameters"`
	RequestContext        struct {
		HTTP struct {
			Method string `json:"method"`
			Path   string `json:"path"`
		} `json:"http"`
		Authorizer struct {
			IAM *struct {
				UserArn string `json:"userArn"`
			} `json:"iam"`
		} `json:"authorizer"`
	} `json:"requestContext"`
}

func eventOf(r *http.Request) (*stubEvent, bool) {
	raw, ok := r.Context().Value(stubEventKey{}).([]byte)
	if !ok {
		return nil, false
	}
	var ev stubEvent
	if json.Unmarshal(raw, &ev) != nil {
		return nil, false
	}
	return &ev, true
}

func (s *stub) Describe() adapter.Descriptor {
	return adapter.Descriptor{Protocol: "aws-apigateway-http-api", Version: "payload-format-2.0", MappingRevision: "pact-aws-1"}
}

func (s *stub) realm() adapter.Realm {
	return adapter.Realm{TenantID: s.w.st.Gateway.TenantID, EnvironmentID: s.w.st.Gateway.EnvironmentID}
}

func (s *stub) AuthenticateNative(_ context.Context, r *http.Request) (adapter.Principal, error) {
	ev, ok := eventOf(r)
	if !ok {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	arn := ""
	for _, v := range ev.Headers {
		if strings.HasPrefix(v, "arn:aws:") {
			arn = v
		}
	}
	if arn == "" && ev.RequestContext.Authorizer.IAM != nil {
		arn = ev.RequestContext.Authorizer.IAM.UserArn
	}
	if arn == "" {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	account, resource := parts[4], parts[5]
	roleARN := arn
	if rest, ok := strings.CutPrefix(resource, "assumed-role/"); ok {
		name, _, _ := strings.Cut(rest, "/")
		roleARN = "arn:aws:iam::" + account + ":role/" + name
	}
	id := "aws:" + account + ":" + url.QueryEscape(roleARN) + ":unreported"
	return adapter.Principal{
		ID: id, Realm: s.realm(), Workload: adapter.Workload(id), Mechanism: "aws-iam", AuthenticatedAt: s.clk.Now(),
	}, nil
}

func (s *stub) ResolveAgentBinding(_ context.Context, realm adapter.Realm, workload adapter.Workload, _ adapter.AgentID) (adapter.AgentBinding, error) {
	for _, e := range s.w.st.Enrollments {
		if e.Workload != string(workload) || e.Realm.TenantID != realm.TenantID || e.Realm.EnvironmentID != realm.EnvironmentID {
			continue
		}
		return adapter.AgentBinding{
			AgentID: e.AgentID, OperatorID: e.OperatorID, HolderJKT: core.Digest(e.HolderJKT),
			Status: adapter.BindingStatus(e.Status), SourceID: e.SourceID, SourceRef: e.SourceRef,
			ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(),
		}, nil
	}
	return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
}

func (s *stub) MapOperation(_ context.Context, r *http.Request, p adapter.Principal, _ string) (core.OperationContext, error) {
	ev, ok := eventOf(r)
	if !ok {
		return core.OperationContext{}, adapter.ErrInvalidMessage
	}
	target := s.w.st.Gateway.Origin + ev.RequestContext.HTTP.Path
	if len(ev.QueryStringParameters) > 0 {
		keys := make([]string, 0, len(ev.QueryStringParameters))
		for k := range ev.QueryStringParameters {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		q := url.Values{}
		for _, k := range keys {
			q.Set(k, ev.QueryStringParameters[k])
		}
		target += "?" + q.Encode()
	}
	return core.OperationContext{
		OperationID:   "op-stub",
		EnvironmentID: s.w.st.Gateway.EnvironmentID,
		PrincipalID:   p.ID,
		Action:        "metrics.operations.read",
		Resources:     []string{"https://metrics.example" + ev.RequestContext.HTTP.Path},
		Method:        ev.RequestContext.HTTP.Method,
		TargetURI:     target,
		BodyDigest:    core.Digest("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"),
		Headers:       ev.Headers,
	}, nil
}

func (s *stub) ReadNativeClaim(_ context.Context, _ string, c adapter.ClaimContext) (adapter.NativeClaim, error) {
	return adapter.NativeClaim{Value: c.Principal.ID, ObservedAt: s.clk.Now(), StatusCheckedAt: s.clk.Now(), SourceID: "stub"}, nil
}

func (s *stub) CheckContext(context.Context, string, adapter.CheckInput) adapter.CheckOutcome {
	return adapter.CheckOutcome{Result: adapter.VerdictPass, ReasonCode: "REQUIREMENT_SATISFIED", SourceID: "stub", ObservedAt: s.clk.Now()}
}

func (s *stub) AuthorizeNative(context.Context, adapter.Principal, core.OperationContext) (adapter.Decision, error) {
	s.hooks.Fire("execute")
	return adapter.Decision{Effect: adapter.EffectAllow, SourceID: "stub"}, nil
}

func (s *stub) RecordOutcome(context.Context, adapter.Observation) (adapter.Recorded, error) {
	return adapter.NoVisibility{Reason: "stub"}, nil
}

// TestStubFailsTheAWSCases is the red baseline: the AWS cases catch the naive
// adapter. Every AWS case fails against the stub except those of stubPasses,
// which pass.
func TestStubFailsTheAWSCases(t *testing.T) {
	results, err := adaptertest.Evaluate(t, stubFactory, adaptertest.Options{Adapter: "aws"})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range results {
		if !strings.HasPrefix(r.ID, "AWS-") {
			continue
		}
		seen++
		switch {
		case stubPasses[r.ID] && !r.Passed():
			t.Errorf("%s fails against the stub, which is expected to pass it: %v", r.ID, r.Failures)
		case !stubPasses[r.ID] && r.Passed():
			t.Errorf("%s passes against the stub: the case does not catch the naive adapter", r.ID)
		}
	}
	if seen == 0 {
		t.Fatal("no AWS case ran")
	}
}
