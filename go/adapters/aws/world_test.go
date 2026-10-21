package aws_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/strictjson"
)

// awsModel is the model of the native state of the AWS cases, defined in
// spec/v1.0/fixtures/adapters/aws/README.md.
const awsModel = "aws/1"

// samplePath is the event every event of a case is built from.
const samplePath = "adapters/aws/events/sample-v2-iam.json"

// The source ids of the aws/1 model.
const (
	srcRoleTable   = "role-table"
	srcConfigCheck = "configuration-check"
	srcExecutor    = "lambda-execution-context"
)

// The defaults of the aws/1 model: the propagation bound L and the check
// interval P of the profile's reference configuration (section 8).
const (
	defaultPropagation   = 60
	defaultCheckInterval = 300
)

// The R1 mapping of the profile, installed when a state names no mapping.
const (
	r1Version  = "pact-aws-1"
	r1Method   = http.MethodGet
	r1Path     = "/metrics/operations"
	r1Action   = "metrics.operations.read"
	r1Resource = "https://metrics.example/operations"
)

// commonAccount is the account of the common/1 realization.
const commonAccount = "111122223333"

// awsState is the aws/1 native state of a case.
type awsState struct {
	Model              string              `json:"model"`
	Gateway            memory.Gateway      `json:"gateway"`
	API                apiState            `json:"api"`
	PropagationBound   *int64              `json:"propagation_bound_seconds"`
	CheckInterval      *int64              `json:"check_interval_seconds"`
	ConfigurationCheck *configCheckState   `json:"configuration_check"`
	Roles              []roleState         `json:"roles"`
	Sessions           []sessionState      `json:"sessions"`
	Mappings           []mappingState      `json:"mappings"`
	Event              json.RawMessage     `json:"event"`
	Execution          *executionState     `json:"execution"`
	Enrollments        []memory.Enrollment `json:"enrollments"`
	Policy             []memory.PolicyRule `json:"policy"`
	UnavailableSources []string            `json:"unavailable_sources"`
}

type apiState struct {
	Partition string `json:"partition"`
	AccountID string `json:"account_id"`
	APIID     string `json:"api_id"`
}

type configCheckState struct {
	CompletedAt int64    `json:"completed_at"`
	Passed      bool     `json:"passed"`
	Findings    []string `json:"findings"`
}

type roleState struct {
	AccountID   string          `json:"account_id"`
	RoleARN     string          `json:"role_arn"`
	RoleID      string          `json:"role_id"`
	SessionName sessionNameRule `json:"session_name"`
}

type sessionNameRule struct {
	Rule  string `json:"rule"`
	Value string `json:"value"`
}

type sessionState struct {
	Ref string          `json:"ref"`
	IAM json.RawMessage `json:"iam"`
}

type mappingState struct {
	Version string       `json:"version"`
	Routes  []routeState `json:"routes"`
}

type routeState struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Body     bool   `json:"body"`
}

type executionState struct {
	DeclaredRoleARN string  `json:"declared_role_arn"`
	RunningRoleARN  *string `json:"running_role_arn"`
}

// world is a parsed aws/1 state, or the aws/1 realization of a common/1
// state, with what the harness needs to build events: the sample event, the
// clock and the sessions that Credential attached.
type world struct {
	st     awsState
	sample []byte
	now    time.Time

	mu    sync.Mutex
	creds map[*http.Request]string
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

// fixtures is the fixture tree of the source repository.
func fixtures() (fs.FS, error) { return adaptertest.DefaultFixtures() }

// newWorld validates st and reads the sample event.
func newWorld(st awsState, now time.Time) (*world, error) {
	if st.Gateway.TenantID == "" || st.Gateway.EnvironmentID == "" || st.Gateway.Origin == "" {
		return nil, errors.New("aws/1 state: gateway needs a tenant_id, an environment_id and an origin")
	}
	if st.API.Partition == "" || st.API.AccountID == "" || st.API.APIID == "" {
		return nil, errors.New("aws/1 state: api needs a partition, an account_id and an api_id")
	}
	refs := map[string]bool{}
	for _, s := range st.Sessions {
		if s.Ref == "" || refs[s.Ref] || len(s.IAM) == 0 {
			return nil, fmt.Errorf("aws/1 state: session %q is empty, used twice or has no iam", s.Ref)
		}
		refs[s.Ref] = true
	}
	for _, r := range st.Roles {
		switch r.SessionName.Rule {
		case "any", "exact", "prefix":
		default:
			return nil, fmt.Errorf("aws/1 state: role %s has session-name rule %q", r.RoleARN, r.SessionName.Rule)
		}
	}
	fsys, err := fixtures()
	if err != nil {
		return nil, err
	}
	sample, err := fs.ReadFile(fsys, samplePath)
	if err != nil {
		return nil, err
	}
	return &world{st: st, sample: sample, now: now, creds: map[*http.Request]string{}}, nil
}

// loadWorld parses an aws/1 state strictly.
func loadWorld(raw []byte, now time.Time) (*world, error) {
	var st awsState
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &st); err != nil {
		return nil, fmt.Errorf("aws/1 state: %w", err)
	}
	if st.Model != awsModel {
		return nil, fmt.Errorf("model is %q, want %q", st.Model, awsModel)
	}
	return newWorld(st, now)
}

// commonRoleID is the unique ID of the role of a common/1 identity: AROA and
// the first 17 characters of the upper-case hexadecimal SHA-256 digest of the
// identity's ref.
func commonRoleID(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return "AROA" + strings.ToUpper(hex.EncodeToString(sum[:]))[:17]
}

// commonRoleARN is the role of a common/1 identity.
func commonRoleARN(ref string) string {
	return "arn:aws:iam::" + commonAccount + ":role/common/" + ref
}

// commonWorld realizes a common/1 state in aws/1, as the AWS cases README
// states: one role and one session per identity in the account 111122223333,
// a configuration check that passed at now, and routes that accept a body.
func commonWorld(st memory.State, now time.Time) (*world, error) {
	as := awsState{
		Model:              awsModel,
		Gateway:            st.Gateway,
		API:                apiState{Partition: "aws", AccountID: commonAccount, APIID: "common-api"},
		ConfigurationCheck: &configCheckState{CompletedAt: now.Unix(), Passed: true},
		Enrollments:        st.Enrollments,
		Policy:             st.Policy,
		UnavailableSources: st.UnavailableSources,
	}
	for _, id := range st.Identities {
		rid := commonRoleID(id.Ref)
		as.Roles = append(as.Roles, roleState{
			AccountID: commonAccount, RoleARN: commonRoleARN(id.Ref), RoleID: rid,
			SessionName: sessionNameRule{Rule: "any"},
		})
		ctx := map[string]any{
			"accessKey":       "ASIA" + rid[4:20],
			"accountId":       commonAccount,
			"callerId":        rid + ":" + id.Ref,
			"cognitoIdentity": nil,
			"principalOrgId":  nil,
			"userArn":         "arn:aws:sts::" + commonAccount + ":assumed-role/" + id.Ref + "/" + id.Ref,
			"userId":          rid + ":" + id.Ref,
		}
		raw, err := json.Marshal(ctx)
		if err != nil {
			return nil, err
		}
		as.Sessions = append(as.Sessions, sessionState{Ref: id.Ref, IAM: raw})
	}
	for _, m := range st.Mappings {
		ms := mappingState{Version: m.Version}
		for _, rt := range m.Routes {
			ms.Routes = append(ms.Routes, routeState{Method: rt.Method, Path: rt.Path, Action: rt.Action, Resource: rt.Resource, Body: true})
		}
		as.Mappings = append(as.Mappings, ms)
	}
	return newWorld(as, now)
}

// mappings returns the installed mappings: the state's, or R1 of the profile.
func (w *world) mappings() []mappingState {
	if len(w.st.Mappings) > 0 {
		return w.st.Mappings
	}
	return []mappingState{{Version: r1Version, Routes: []routeState{{Method: r1Method, Path: r1Path, Action: r1Action, Resource: r1Resource}}}}
}

// unavailable reports whether the source named id cannot answer.
func (w *world) unavailable(id string) bool { return slices.Contains(w.st.UnavailableSources, id) }

// propagation is the declared IAM propagation bound L.
func (w *world) propagation() time.Duration {
	if w.st.PropagationBound != nil {
		return time.Duration(*w.st.PropagationBound) * time.Second
	}
	return defaultPropagation * time.Second
}

// interval is the configuration check interval P.
func (w *world) interval() time.Duration {
	if w.st.CheckInterval != nil {
		return time.Duration(*w.st.CheckInterval) * time.Second
	}
	return defaultCheckInterval * time.Second
}

// Credential records that r was signed with the credentials of the session
// ref, which API Gateway then reports as the IAM context of the event.
func (w *world) Credential(r *http.Request, ref string) error {
	for _, s := range w.st.Sessions {
		if s.Ref == ref {
			w.mu.Lock()
			w.creds[r] = ref
			w.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("no session %q", ref)
}

// session returns the IAM context of the session attached to r, if any.
func (w *world) session(r *http.Request) json.RawMessage {
	w.mu.Lock()
	ref, ok := w.creds[r]
	w.mu.Unlock()
	if !ok {
		return nil
	}
	for _, s := range w.st.Sessions {
		if s.Ref == ref {
			return s.IAM
		}
	}
	return nil
}

// decodeJSON decodes data with numbers kept as written.
func decodeJSON(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// mergePatch applies the JSON merge patch patch to target (RFC 7396,
// section 2).
func mergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = map[string]any{}
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
			continue
		}
		t[k] = mergePatch(t[k], v)
	}
	return t
}

// splitTarget splits the absolute url of a case into its userinfo, the raw
// path and the raw query: the part after the authority is split at its first
// "?", and every octet stays as written.
func splitTarget(raw string) (userinfo, rawPath, rawQuery string, err error) {
	_, rest, ok := strings.Cut(raw, "://")
	if !ok {
		return "", "", "", fmt.Errorf("url %q is not absolute", raw)
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, after := rest[:end], rest[end:]
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		userinfo = authority[:at]
	}
	rawPath, rawQuery, _ = strings.Cut(after, "?")
	return userinfo, rawPath, rawQuery, nil
}

// matchTemplate reports whether a path template matches a raw path: a
// {name} segment matches one non-empty segment, any other segment itself.
func matchTemplate(tmpl, path string) bool {
	ts, ps := strings.Split(tmpl, "/"), strings.Split(path, "/")
	if len(ts) != len(ps) {
		return false
	}
	for i, t := range ts {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			if ps[i] == "" {
				return false
			}
			continue
		}
		if t != ps[i] {
			return false
		}
	}
	return true
}

// routeKey selects the route API Gateway invokes for a method and a raw
// path: the first route of the installed mappings with that method whose
// template matches, or $default.
func (w *world) routeKey(method, rawPath string) string {
	for _, m := range w.mappings() {
		for _, rt := range m.Routes {
			if rt.Method == method && matchTemplate(rt.Path, rawPath) {
				return rt.Method + " " + rt.Path
			}
		}
	}
	return "$default"
}

// originHost is the host of the configured origin, in lowercase.
func (w *world) originHost() (string, error) {
	u, err := url.Parse(w.st.Gateway.Origin)
	if err != nil {
		return "", err
	}
	return strings.ToLower(u.Hostname()), nil
}

// event builds the payload 2.0 event that API Gateway delivers for r, by the
// steps of the AWS cases README, section "Events". It restores r's body.
func (w *world) event(r *http.Request) ([]byte, error) {
	v, err := decodeJSON(w.sample)
	if err != nil {
		return nil, fmt.Errorf("sample event: %w", err)
	}
	ev, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("sample event is not an object")
	}
	rc, ok := ev["requestContext"].(map[string]any)
	if !ok {
		return nil, errors.New("sample event has no requestContext")
	}
	httpCtx, ok := rc["http"].(map[string]any)
	if !ok {
		return nil, errors.New("sample event has no requestContext.http")
	}
	for _, k := range []string{"cookies", "queryStringParameters", "pathParameters", "stageVariables", "body"} {
		delete(ev, k)
	}
	delete(rc, "authentication")
	delete(rc, "authorizer")

	userinfo, rawPath, rawQuery, err := splitTarget(r.RequestURI)
	if err != nil {
		return nil, err
	}
	ev["rawPath"], ev["rawQueryString"] = rawPath, rawQuery
	httpCtx["path"], httpCtx["method"] = rawPath, r.Method

	headers := map[string]any{}
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if lower == "cookie" {
			ev["cookies"] = []any{strings.Join(values, ",")}
			continue
		}
		headers[lower] = strings.Join(values, ",")
	}
	ev["headers"] = headers

	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		if len(b) > 0 {
			ev["body"] = base64.StdEncoding.EncodeToString(b)
			ev["isBase64Encoded"] = true
		} else {
			ev["isBase64Encoded"] = false
		}
	} else {
		ev["isBase64Encoded"] = false
	}

	host, err := w.originHost()
	if err != nil {
		return nil, err
	}
	domain := host
	if userinfo != "" {
		domain = userinfo + "@" + host
	}
	prefix, _, _ := strings.Cut(host, ".")
	rc["accountId"], rc["apiId"] = w.st.API.AccountID, w.st.API.APIID
	rc["stage"], rc["domainName"], rc["domainPrefix"] = "$default", domain, prefix
	rc["timeEpoch"] = json.Number(fmt.Sprint(w.now.UnixMilli()))
	rc["time"] = w.now.UTC().Format("02/Jan/2006:15:04:05 -0700")
	key := w.routeKey(r.Method, rawPath)
	ev["routeKey"], rc["routeKey"] = key, key

	if s := w.session(r); s != nil {
		iam, err := decodeJSON(s)
		if err != nil {
			return nil, fmt.Errorf("session iam: %w", err)
		}
		rc["authorizer"] = map[string]any{"iam": iam}
	}

	var out any = ev
	if len(w.st.Event) > 0 {
		patch, err := decodeJSON(w.st.Event)
		if err != nil {
			return nil, fmt.Errorf("event patch: %w", err)
		}
		out = mergePatch(ev, patch)
	}
	return json.Marshal(out)
}

// mustEvent is event for the Arrive hook, which cannot return an error: a
// harness defect panics rather than hand the adapter a request with no event.
func (w *world) mustEvent(r *http.Request) []byte {
	raw, err := w.event(r)
	if err != nil {
		panic(fmt.Sprintf("aws harness: cannot build the event: %v", err))
	}
	return raw
}
