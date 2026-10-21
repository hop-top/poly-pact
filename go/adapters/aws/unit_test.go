package aws_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/installed"
	"hop.top/pact-go/adapters/aws"
	"hop.top/pact-go/adapters/memory"
)

const (
	unitNow     = 1792080000
	unitAccount = "111122223333"
	unitRoleARN = "arn:aws:iam::111122223333:role/agents/metrics-reader"
	unitRoleID  = "AROAEXAMPLEREADER0001"
	unitExec    = "arn:aws:iam::111122223333:role/service-role/metrics-api-handler"
)

var unitRealm = adapter.Realm{TenantID: "northwind", EnvironmentID: "https://api.metrics.example/environments/operations"}

// unitAdapter builds the adapter with one role entry, a passing
// configuration check and the declared executor; edit adjusts the
// configuration first.
func unitAdapter(t *testing.T, edit func(*aws.Config)) *aws.Adapter {
	t.Helper()
	ref, err := memory.New(memory.State{Model: memory.Model, Gateway: memory.Gateway{
		TenantID: unitRealm.TenantID, EnvironmentID: unitRealm.EnvironmentID, Origin: "https://api.metrics.example",
	}}, fixedClock(unitNow))
	if err != nil {
		t.Fatal(err)
	}
	cfg := aws.Config{
		Realm:     unitRealm,
		AccountID: unitAccount,
		Origin:    "https://api.metrics.example",
		Roles: fixtureRoles{entries: map[string]aws.RoleEntry{unitRoleID: {
			AccountID: unitAccount, RoleARN: unitRoleARN, RoleID: unitRoleID,
			SessionName: aws.SessionNameRule{Kind: aws.SessionNameAny},
		}}},
		ConfigCheck:      fixtureCheck{report: aws.CheckReport{CompletedAt: time.Unix(unitNow-30, 0), Passed: true}},
		ExecutionRoleARN: unitExec,
		Executor:         fixtureExecutor{running: unitExec},
		Registry:         referenceRegistry{ref},
		Permissions:      commonPolicy{},
		Clock:            fixedClock(unitNow),
	}
	if edit != nil {
		edit(&cfg)
	}
	a, err := aws.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// unitEvent is the event of R1 for a session of the role, with the request
// time timeEpoch and the extra members of extra spliced into its top level.
func unitEvent(timeEpoch, extra string) []byte {
	return []byte(`{
	  "version": "2.0", "routeKey": "GET /metrics/operations", "rawPath": "/metrics/operations", "rawQueryString": "",
	  ` + extra + `
	  "requestContext": {
	    "accountId": "111122223333", "apiId": "a1b2c3d4e5", "domainName": "api.metrics.example", "domainPrefix": "api",
	    "http": {"method": "GET", "path": "/metrics/operations", "protocol": "HTTP/1.1", "sourceIp": "192.0.2.1", "userAgent": "t"},
	    "requestId": "r", "routeKey": "GET /metrics/operations", "stage": "$default", "time": "t", "timeEpoch": ` + timeEpoch + `,
	    "authorizer": {"iam": {"accessKey": "ASIAEXAMPLEREADER001", "accountId": "111122223333",
	      "callerId": "AROAEXAMPLEREADER0001:metrics-assistant", "cognitoIdentity": null, "principalOrgId": null,
	      "userArn": "arn:aws:sts::111122223333:assumed-role/metrics-reader/metrics-assistant",
	      "userId": "AROAEXAMPLEREADER0001:metrics-assistant"}}
	  },
	  "isBase64Encoded": false
	}`)
}

// TestSampleEventDecodes decodes the sample event of the fixtures strictly,
// the event every AWS case is built from, and authenticates it.
func TestSampleEventDecodes(t *testing.T) {
	fsys, err := fixtures()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(fsys, samplePath)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := aws.DecodeEvent(raw, aws.DefaultMaxEventBytes)
	if err != nil {
		t.Fatalf("DecodeEvent(sample) = %v", err)
	}
	if ev.Version != "2.0" || ev.RawQueryString == nil || *ev.RawQueryString != "window=1h" || ev.RequestContext.TimeEpoch != unitNow*1000 {
		t.Errorf("sample decoded as %+v", ev)
	}
	p, err := unitAdapter(t, nil).AuthenticateNative(context.Background(), aws.Invocation(context.Background(), raw))
	if err != nil || p.ID != aws.WorkloadID(unitAccount, unitRoleARN) {
		t.Errorf("AuthenticateNative(sample) = %+v, %v", p, err)
	}
}

// TestEventMembers decodes an event with every member of the 2.0 example of
// the developer guide, and refuses one with a member the format does not
// have or a duplicate member.
func TestEventMembers(t *testing.T) {
	full := unitEvent("1792080000000", `"cookies": ["a=b"], "headers": {"accept": "*/*"}, "queryStringParameters": {},
	  "pathParameters": {}, "stageVariables": {"k": "v"}, "body": "hi",`)
	full = []byte(strings.Replace(string(full), `"requestContext": {`, `"requestContext": {"authentication": {"clientCert": {"clientCertPem": "x"}},`, 1))
	if _, err := aws.DecodeEvent(full, aws.DefaultMaxEventBytes); err != nil {
		t.Errorf("DecodeEvent(every member) = %v", err)
	}
	for name, raw := range map[string][]byte{
		"unknown member":   unitEvent("1792080000000", `"multiValueHeaders": {},`),
		"duplicate member": unitEvent("1792080000000", `"rawPath": "/metrics/operations",`),
		"null map":         unitEvent("1792080000000", `"headers": null,`),
	} {
		if _, err := aws.DecodeEvent(raw, aws.DefaultMaxEventBytes); !errors.Is(err, adapter.ErrInvalidMessage) {
			t.Errorf("%s: DecodeEvent() = %v, want ErrInvalidMessage", name, err)
		}
	}
	if _, err := aws.DecodeEvent(unitEvent("1792080000000", ""), 64); !errors.Is(err, adapter.ErrInvalidMessage) {
		t.Errorf("over the size limit: DecodeEvent() = %v, want ErrInvalidMessage", err)
	}
}

// TestIAMClaimTimes is the adapter half of AWS-13 for the paths of AR-25:
// the claim has no observation time and the status time timeEpoch minus L,
// whatever the time of the read; a status time ahead of the clock is a
// dependency error, never a clamped time.
func TestIAMClaimTimes(t *testing.T) {
	ctx := context.Background()
	a := unitAdapter(t, nil)
	p, err := a.AuthenticateNative(ctx, aws.Invocation(ctx, unitEvent("1792079990500", "")))
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]any{
		aws.PathPrincipalID:  aws.WorkloadID(unitAccount, unitRoleARN),
		aws.PathWorkloadRole: unitRoleARN,
		aws.PathAccountID:    unitAccount,
	} {
		c, err := a.ReadNativeClaim(ctx, path, adapter.ClaimContext{Principal: p})
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if c.Value != want || !c.ObservedAt.IsZero() || c.StatusCheckedAt.Unix() != 1792079990-60 || c.SourceID == "" {
			t.Errorf("%s: claim %+v, want %v with no observation time and status time 1792079930", path, c, want)
		}
	}
	other := p
	other.Mechanism = "bearer"
	if _, err := a.ReadNativeClaim(ctx, aws.PathPrincipalID, adapter.ClaimContext{Principal: other}); !errors.Is(err, adapter.ErrContextMismatch) {
		t.Errorf("principal of another mechanism: %v, want ErrContextMismatch", err)
	}
	ahead, err := unitAdapter(t, func(c *aws.Config) { c.PropagationBound = time.Second }).
		AuthenticateNative(ctx, aws.Invocation(ctx, unitEvent("1792080090000", "")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadNativeClaim(ctx, aws.PathAccountID, adapter.ClaimContext{Principal: ahead}); !errors.Is(err, adapter.ErrDependencyUnavailable) {
		t.Errorf("status time ahead of the clock: %v, want ErrDependencyUnavailable", err)
	}
	if _, err := a.ReadNativeClaim(ctx, "/attributes/environment/session_name", adapter.ClaimContext{Principal: p}); !errors.Is(err, adapter.ErrUnsupportedRequirement) {
		t.Errorf("unapproved path: %v, want ErrUnsupportedRequirement", err)
	}
}

// TestCoveredHeaderAsCombined is the header part of AWS-07: a covered header
// is the value the event carries, with API Gateway's commas (AR-18), so a
// header changed after issuance gives another operation context.
func TestCoveredHeaderAsCombined(t *testing.T) {
	ctx := context.Background()
	a := unitAdapter(t, func(c *aws.Config) { c.HeaderAllowlist = []string{"x-metrics-scope"} })
	p := adapter.Principal{ID: aws.WorkloadID(unitAccount, unitRoleARN), Realm: unitRealm}
	op := func(value string) map[string]string {
		t.Helper()
		o, err := a.MapOperation(ctx, aws.Invocation(ctx, unitEvent("1792080000000", `"headers": {"x-metrics-scope": "`+value+`"},`)), p, aws.MappingRevision)
		if err != nil {
			t.Fatal(err)
		}
		return o.Headers
	}
	if h := op("errors,latency"); h["x-metrics-scope"] != "errors,latency" {
		t.Errorf("headers = %v, want the combined value as the event carries it", h)
	}
	if h := op("errors"); h["x-metrics-scope"] != "errors" {
		t.Errorf("headers = %v, want the changed value", h)
	}
	if _, err := a.MapOperation(ctx, aws.Invocation(ctx, unitEvent("1792080000000", `"headers": {"X-Metrics-Scope": "errors"},`)), p, aws.MappingRevision); !errors.Is(err, adapter.ErrInvalidMessage) {
		t.Errorf("header name not lowercase: %v, want ErrInvalidMessage", err)
	}
}

// TestNoEvent: a request that carries no event did not come through API
// Gateway; it is not authenticated and not mapped.
func TestNoEvent(t *testing.T) {
	ctx := context.Background()
	a := unitAdapter(t, nil)
	r := aws.Invocation(ctx, nil).WithContext(context.Background())
	var denial *adapter.NativeDenial
	if _, err := a.AuthenticateNative(ctx, r); !errors.As(err, &denial) || denial.PublicReason() != adapter.DenialNoCredential {
		t.Errorf("AuthenticateNative() = %v, want NO_CREDENTIAL", err)
	}
	p := adapter.Principal{ID: aws.WorkloadID(unitAccount, unitRoleARN), Realm: unitRealm}
	if _, err := a.MapOperation(ctx, r, p, aws.MappingRevision); !errors.Is(err, adapter.ErrInvalidMessage) {
		t.Errorf("MapOperation() = %v, want ErrInvalidMessage", err)
	}
}

// TestNewRefuses checks the configuration rules of New.
func TestNewRefuses(t *testing.T) {
	for name, edit := range map[string]func(*aws.Config){
		"authorization covered":   func(c *aws.Config) { c.HeaderAllowlist = []string{"Authorization"} },
		"x-amz- header covered":   func(c *aws.Config) { c.HeaderAllowlist = []string{"x-amz-date"} },
		"x-amzn- header covered":  func(c *aws.Config) { c.HeaderAllowlist = []string{"x-amzn-trace-id"} },
		"account not 12 digits":   func(c *aws.Config) { c.AccountID = "1234" },
		"no role table":           func(c *aws.Config) { c.Roles = nil },
		"no configuration check":  func(c *aws.Config) { c.ConfigCheck = nil },
		"no executor":             func(c *aws.Config) { c.Executor = nil },
		"no execution role":       func(c *aws.Config) { c.ExecutionRoleARN = "" },
		"own check reinstalled":   func(c *aws.Config) { c.Checks = map[string]installed.InstalledCheck{aws.CheckExecutionIdentity: {}} },
		"claim of an AR-25 path":  func(c *aws.Config) { c.Claims = map[string]installed.ClaimSource{aws.PathAccountID: nil} },
		"partition not a name":    func(c *aws.Config) { c.Partition = "AWS" },
		"origin without a scheme": func(c *aws.Config) { c.Origin = "api.metrics.example" },
	} {
		ref, _ := memory.New(memory.State{Model: memory.Model, Gateway: memory.Gateway{TenantID: "t", EnvironmentID: "https://e.example", Origin: "https://e.example"}}, fixedClock(unitNow))
		cfg := aws.Config{
			Realm: unitRealm, AccountID: unitAccount, Origin: "https://api.metrics.example",
			Roles: fixtureRoles{}, ConfigCheck: fixtureCheck{}, ExecutionRoleARN: unitExec, Executor: fixtureExecutor{},
			Registry: referenceRegistry{ref}, Permissions: commonPolicy{}, Clock: fixedClock(unitNow),
		}
		edit(&cfg)
		if _, err := aws.New(cfg); err == nil {
			t.Errorf("%s: New() accepted the configuration", name)
		}
	}
}

// TestWorkloadIDEscapes checks the identifier against the aws example of
// identity-mapping section 3.3, whose last component is none.
func TestWorkloadIDEscapes(t *testing.T) {
	got := aws.WorkloadID("123456789012", "arn:aws:iam::123456789012:role/agent-runner")
	want := "aws:123456789012:arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fagent-runner:unreported"
	if got != want {
		t.Errorf("WorkloadID() = %q, want %q", got, want)
	}
}
