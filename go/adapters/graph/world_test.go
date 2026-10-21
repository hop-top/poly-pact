package graph_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"time"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapter/task"
	"hop.top/pact-go/adapters/oauth"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/clock"
)

// graphModel is the native-state model of the Graph cases
// (spec/v1.0/fixtures/adapters/graph/README.md).
const graphModel = "graph/1"

// sourceRegistry is the source id of the executor registry (profile G1).
const sourceRegistry = "executor-registry"

// The forms of profile section 1.
const (
	formDelegated   = "delegated"
	formApplication = "application"
)

// Profile constants (profile section 2, GR-6, GR-15, GR-23).
const (
	fixedQuery   = "$select=id,subject,body&$top=10"
	scopeMail    = "https://graph.microsoft.com/Mail.Read"
	scopeDefault = "https://graph.microsoft.com/.default"
	grantOBO     = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	grantCC      = "client_credentials"
	graphOrigin  = "https://graph.microsoft.com"
	loginHost    = "login.microsoftonline.com"
	graphHost    = "graph.microsoft.com"
	mailAction   = "mail.message.list"
	revision     = "pact-graph-1"
	checkID      = "execution-identity-v1"
	pathAppID    = "/graph/execution_app_id"
)

func fixtures() (fs.FS, error) { return adaptertest.DefaultFixtures() }

// graphState is a graph/1 native state.
type graphState struct {
	Model              string          `json:"model"`
	Gateway            gatewayState    `json:"gateway"`
	Form               string          `json:"form"`
	Entra              entraState      `json:"entra"`
	ExecutorAppID      string          `json:"executor_app_id"`
	Registry           []bindingRec    `json:"registry"`
	Continuations      []continuation  `json:"continuations"`
	Preflight          *preflightState `json:"preflight"`
	UnavailableSources []string        `json:"unavailable_sources"`
	Reporting          *reportingState `json:"reporting"`
}

type gatewayState struct {
	TenantID        string   `json:"tenant_id"`
	EnvironmentID   string   `json:"environment_id"`
	Origin          string   `json:"origin"`
	HeaderAllowlist []string `json:"header_allowlist"`
}

type entraState struct {
	TenantID     string `json:"tenant_id"`
	GatewayAppID string `json:"gateway_app_id"`
}

type realmState struct {
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
}

// bindingRec is a record of the executor registry (profile G1, GR-13,
// GR-14).
type bindingRec struct {
	Realm              realmState `json:"realm"`
	Row                string     `json:"row"`
	Workload           string     `json:"workload"`
	Class              string     `json:"class"`
	Grant              string     `json:"grant"`
	AppID              string     `json:"app_id"`
	ServicePrincipalID string     `json:"service_principal_id"`
	MailboxID          string     `json:"mailbox_id"`
	Ref                string     `json:"ref"`
	ChangedAt          int64      `json:"changed_at"`
}

// continuation is a continuation record of RB-57.
type continuation struct {
	PageToken      string `json:"page_token"`
	Row            string `json:"row"`
	Principal      string `json:"principal"`
	TaskID         string `json:"task_id"`
	AgentID        string `json:"agent_id"`
	MappingVersion string `json:"mapping_version"`
	Link           string `json:"link"`
}

type preflightState struct {
	Allowlist []allowEntry `json:"allowlist"`
	Runs      []runState   `json:"runs"`
}

type allowEntry struct {
	ResourceID string `json:"resource_id"`
	AppRoleID  string `json:"app_role_id"`
}

// runState is one preflight run: the step 1 pages Graph serves and the step 2
// attestation the operator supplied.
type runState struct {
	At              int64              `json:"at"`
	Unreachable     bool               `json:"unreachable"`
	AssignmentPages [][]map[string]any `json:"assignment_pages"`
	RBAC            *attestation       `json:"rbac"`
}

// attestation is the operator-supplied record of Test-ServicePrincipalAuthorization.
type attestation struct {
	Identity string    `json:"identity"`
	Resource string    `json:"resource"`
	RanAt    int64     `json:"ran_at"`
	Rows     []rbacRow `json:"rows"`
}

type rbacRow struct {
	RoleName             string `json:"RoleName"`
	GrantedPermissions   string `json:"GrantedPermissions"`
	AllowedResourceScope string `json:"AllowedResourceScope"`
	ScopeType            string `json:"ScopeType"`
	InScope              string `json:"InScope"`
}

type reportingState struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	KID      string `json:"kid"`
}

// modelOf returns the model member of a native state.
func modelOf(raw json.RawMessage) (string, error) {
	var m struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("native state: %w", err)
	}
	return m.Model, nil
}

var rows = []string{"GD1", "GD2", "GA1", "GA2"}

// parseState strict-parses a graph/1 state.
func parseState(raw json.RawMessage) (graphState, error) {
	var st graphState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return graphState{}, fmt.Errorf("graph/1 state: %w", err)
	}
	switch {
	case st.Model != graphModel:
		return graphState{}, fmt.Errorf("graph/1 state: model %q", st.Model)
	case st.Form != formDelegated && st.Form != formApplication:
		return graphState{}, fmt.Errorf("graph/1 state: form %q", st.Form)
	case st.Gateway.TenantID == "" || st.Gateway.EnvironmentID == "" || st.Gateway.Origin == "":
		return graphState{}, errors.New("graph/1 state: the gateway is required")
	case st.Entra.TenantID == "" || st.Entra.GatewayAppID == "":
		return graphState{}, errors.New("graph/1 state: entra is required")
	case (st.Form == formApplication) != (st.ExecutorAppID != ""):
		return graphState{}, errors.New("graph/1 state: executor_app_id is required in form A and absent in form D")
	}
	for _, b := range st.Registry {
		if !slices.Contains(rows, b.Row) {
			return graphState{}, fmt.Errorf("graph/1 state: row %q is not a row of the profile", b.Row)
		}
	}
	for _, c := range st.Continuations {
		if !slices.Contains(rows, c.Row) || c.PageToken == "" || c.Link == "" {
			return graphState{}, fmt.Errorf("graph/1 state: continuation %q is incomplete", c.PageToken)
		}
	}
	return st, nil
}

func (st graphState) down(source string) bool { return slices.Contains(st.UnavailableSources, source) }

func (st graphState) realm() adapter.Realm {
	return adapter.Realm{TenantID: st.Gateway.TenantID, EnvironmentID: st.Gateway.EnvironmentID}
}

// The unit tier. A broker is an adapter under test with the execution path
// of profile section 3, row 5, and the grant preflight of section C. The unit
// cases reach the token endpoint and Graph only through it.
type broker interface {
	adapter.Adapter
	execute(ctx context.Context, in execInput) execution
	preflight(ctx context.Context)
}

// execInput is one admitted operation as the gateway hands it to the
// executor: the request that carried it, the authenticated principal, the
// mapped operation, and the task and agent of the admission.
type execInput struct {
	req       *http.Request
	principal adapter.Principal
	op        core.OperationContext
	task      string
	agent     string
}

// report is the outcome report an execution gives (profile GR-29, GR-30).
type report struct {
	kind      core.EventKind
	result    core.OutcomeResult
	dimension core.Dimension
	details   string
	evidence  []string
}

// execution is what the broker reports for one operation: the gateway's
// answer to the agent and the outcome report.
type execution struct {
	status          int
	wwwAuthenticate string
	retryAfter      string
	messages        json.RawMessage
	pageToken       string
	// report is nil when the operation produces no report (OI-3).
	report *report
	// mismatch is set for an error that is EXECUTOR_MISMATCH.
	mismatch bool
	code     adapter.Code
	err      error
}

// unitWorld is the native state of a unit case.
type unitWorld struct {
	form     string
	cloud    *fakeCloud
	hooks    *adaptertest.Hooks
	clk      *clock.Fake
	registry []bindingRec
	// registryDown makes the executor registry unable to answer.
	registryDown bool
	// continuations preloads the continuation store.
	continuations []continuation
	// frontDoor authenticates form D requests, the OAuth profile's form E.
	frontDoor adapter.NativeAuthenticator
	// attest is the RBAC attestation the operator's file currently holds;
	// nil when there is none.
	attest *attestation
	// tasks is the task ledger of the executor; nil runs it without one.
	tasks task.TaskLedger
}

// Unit-tier identifiers, the same as those of the case files.
const (
	uTenant       = "northwind"
	uEnv          = "https://mail.northwind.example/environments/production"
	uOrigin       = "https://mail.northwind.example"
	uTID          = "8f3d2c1b-5a4e-4f6d-9b7a-1c2e3f4a5b6c"
	uGatewayApp   = "3f1c9a2e-6b7d-4e8f-a0b1-c2d3e4f5a6b7"
	uGatewaySP    = "4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c7d"
	uExecApp      = "9e8d7c6b-5a49-4382-a1b0-c9d8e7f6a5b4"
	uExecSP       = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
	uAuditorApp   = "7a6b5c4d-3e2f-4109-8a7b-6c5d4e3f2a10"
	uClientApp    = "d4e5f6a7-b8c9-4d0e-8f1a-2b3c4d5e6f70"
	uMailbox      = "0f9e8d7c-6b5a-4493-8271-605f4e3d2c1b"
	uOtherMailbox = "6d5c4b3a-2918-4706-b5f4-e3d2c1b0a998"
	uOID          = "2b3c4d5e-6f70-4182-93a4-b5c6d7e8f901"
	uWorkload     = "https://workloads.northwind.example/mail-digest"
	uAgent        = "https://agents.northwind.example/mail-assistant"
	uTask         = "native-task:mail-digest-0042"
	uNow          = 1792080000

	secretOBO      = "obo-client-secret-7d41c09a"
	secretExecutor = "executor-client-secret-2f8e61b3"
	secretAuditor  = "auditor-client-secret-91c3d5e0"
)

var (
	uRealm = adapter.Realm{TenantID: uTenant, EnvironmentID: uEnv}
	// uIssuer is the form E issuer of the tenant (OAUTH-37).
	uIssuer = "https://" + loginHost + "/" + uTID + "/v2.0"
	uUser   = oauth.Identifier(uIssuer, uTID, uOID)
)

var secrets = []string{secretOBO, secretExecutor, secretAuditor}

func unitBindings(form string) []bindingRec {
	realm := realmState(uRealm)
	changed := int64(uNow - 86400)
	if form == formDelegated {
		return []bindingRec{
			{Realm: realm, Row: "GD1", Class: "delegated-user", Grant: "on_behalf_of", AppID: uGatewayApp, ServicePrincipalID: uGatewaySP, Ref: "executor-registry:gd1:r7", ChangedAt: changed},
			{Realm: realm, Row: "GD2", Class: "delegated-user", Grant: "on_behalf_of", AppID: uGatewayApp, ServicePrincipalID: uGatewaySP, Ref: "executor-registry:gd2:r7", ChangedAt: changed},
		}
	}
	return []bindingRec{
		{Realm: realm, Row: "GA1", Workload: uWorkload, Class: "registered-app-executor", Grant: "client_credentials", AppID: uExecApp, ServicePrincipalID: uExecSP, MailboxID: uMailbox, Ref: "executor-registry:ga1:mail-digest:r7", ChangedAt: changed},
		{Realm: realm, Row: "GA2", Workload: uWorkload, Class: "registered-app-executor", Grant: "client_credentials", AppID: uExecApp, ServicePrincipalID: uExecSP, MailboxID: uMailbox, Ref: "executor-registry:ga2:mail-digest:r7", ChangedAt: changed},
	}
}

// userPrincipal is the authenticated user of form D.
func userPrincipal() adapter.Principal {
	return adapter.Principal{
		ID: uUser, Realm: uRealm, Workload: adapter.Workload(oauth.Identifier(uIssuer, uTID, uClientApp)),
		Mechanism: "oauth", AuthenticatedAt: time.Unix(uNow, 0),
	}
}

// workloadPrincipal is the authenticated workload of form A.
func workloadPrincipal() adapter.Principal {
	return adapter.Principal{ID: uWorkload, Realm: uRealm, Workload: adapter.Workload(uWorkload), Mechanism: "mtls", AuthenticatedAt: time.Unix(uNow, 0)}
}

// gatewayRequest is a GET of the gateway with the target as written and the
// given headers.
func gatewayRequest(target string, header http.Header) *http.Request {
	u, err := url.Parse(target)
	if err != nil {
		panic(err)
	}
	if header == nil {
		header = http.Header{}
	}
	r := &http.Request{Method: http.MethodGet, URL: u, Host: u.Host, Header: header, RequestURI: target, Body: http.NoBody}
	return r.WithContext(context.Background())
}
