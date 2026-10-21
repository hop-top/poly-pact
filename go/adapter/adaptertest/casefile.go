package adaptertest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
)

// caseVersion is the only case file format this package reads.
const caseVersion = 1

// maxCaseBytes bounds one case file.
const maxCaseBytes = 1 << 20

// The seven function names of the draft 17.1 table, as a case file spells
// them in expect.function.
const (
	fnAuthenticate = "authenticate_native"
	fnBinding      = "resolve_agent_binding"
	fnMapOperation = "map_operation"
	fnClaim        = "read_native_claim"
	fnCheck        = "check_context"
	fnAuthorize    = "authorize_native"
	fnRecord       = "record_outcome"
)

// Outcomes a case can expect. functionOutcomes lists the ones each function
// accepts; README.md in the fixture directory defines them. check_context
// uses the verdict as the outcome and authorize_native the effect.
const (
	outAuthenticated = "authenticated"
	outDenied        = "denied"
	outError         = "error"
	outBound         = "bound"
	outNotEnrolled   = "unknown"
	outUnusable      = "unusable"
	outMapped        = "mapped"
	outClaim         = "claim"
	outPass          = "PASS"
	outFail          = "FAIL"
	outUnknown       = "UNKNOWN"
	outAllow         = "ALLOW"
	outDeny          = "DENY"
	outNotAllowed    = "not_allowed"
	outSigned        = "signed"
	outNoVisibility  = "no_visibility"
	outNoExecSuccess = "no_execution_success"
)

var functionOutcomes = map[string][]string{
	fnAuthenticate: {outAuthenticated, outDenied, outError},
	fnBinding:      {outBound, outNotEnrolled, outUnusable, outError},
	fnMapOperation: {outMapped, outError},
	fnClaim:        {outClaim, outError},
	fnCheck:        {outPass, outFail, outUnknown},
	fnAuthorize:    {outAllow, outDeny, outUnknown, outNotAllowed, outError},
	fnRecord:       {outSigned, outNoVisibility, outNoExecSuccess, outError},
}

// Values of Case.Workloads: whether the adapter's profile supports workloads
// shared by several agents (draft 17.1, identity mapping IM-19).
const (
	workloadsShared    = "shared"
	workloadsDedicated = "dedicated"
)

// Values of Request.Arrival.
const (
	arrivalEnforcementPoint = "enforcement_point"
	arrivalDirect           = "direct"
)

// Case is one case file: a stimulus for one of the seven functions and the
// behavior the draft requires of it. The JSON member names are the file
// format; README.md in the fixture directory documents each.
type Case struct {
	CaseVersion int      `json:"case_version"`
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Draft       []string `json:"draft"`
	// Workloads limits the case to the adapters whose profile supports
	// workloads shared by several agents, "shared", or to those whose profile
	// does not, "dedicated". Empty, the case applies to every adapter.
	Workloads string `json:"workloads"`
	// Now is the case's current time in Unix seconds; defaultNow when absent.
	Now *int64 `json:"now"`
	// NativeState is handed to the adapter's Factory verbatim.
	NativeState json.RawMessage `json:"native_state"`
	Request     *Request        `json:"request"`
	Call        Call            `json:"call"`
	Expect      Expect          `json:"expect"`

	// common is set for a case of adapters/_common.
	common bool
}

// Request describes the HTTP request of an authenticate_native or
// map_operation case.
type Request struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	// BodyB64 is the request body, standard base64 with padding.
	BodyB64 string `json:"body_b64"`
	// TLSPeer describes the client certificate of a mutual-TLS connection.
	TLSPeer *TLSPeer `json:"tls_peer"`
	// NativeStateRef names the native identity whose credential the request
	// presents; the Factory's Credential hook attaches it.
	NativeStateRef string `json:"native_state_ref"`
	// Arrival is "enforcement_point" (the default) or "direct".
	Arrival string `json:"arrival"`
}

// TLSPeer is a synthetic client certificate: the attributes an adapter reads
// from the peer certificate of a mutual-TLS connection.
type TLSPeer struct {
	SubjectCN string   `json:"subject_cn"`
	IssuerCN  string   `json:"issuer_cn"`
	DNSNames  []string `json:"dns_names"`
	URIs      []string `json:"uris"`
}

// RealmJSON is a realm in a case file.
type RealmJSON struct {
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
}

// PrincipalJSON is an authenticated principal handed to a function directly.
type PrincipalJSON struct {
	ID       string    `json:"id"`
	Realm    RealmJSON `json:"realm"`
	Workload string    `json:"workload"`
	// Mechanism defaults to "test".
	Mechanism string `json:"mechanism"`
	// AuthenticatedAt is Unix seconds; the case's now when absent.
	AuthenticatedAt *int64         `json:"authenticated_at"`
	Attributes      map[string]any `json:"attributes"`
}

// BindingJSON is an agent binding handed to check_context: the binding of the
// agent the request names, as resolve_agent_binding returned it and the
// validator verified it (draft 11.3 step 2, 17.1).
type BindingJSON struct {
	AgentID    string `json:"agent_id"`
	OperatorID string `json:"operator_id"`
	HolderJKT  string `json:"holder_jkt"`
	// Status is ACTIVE when absent.
	Status string `json:"status"`
}

// ObservationJSON is an observation in a case file. Its member names are those
// of the outcome report (draft 14.1).
type ObservationJSON struct {
	EventID            string                 `json:"event_id"`
	EventKind          core.EventKind         `json:"event_kind"`
	Context            core.ReputationContext `json:"context"`
	TaskID             string                 `json:"task_id"`
	OperationID        string                 `json:"operation_id"`
	AdmissionReceiptID *string                `json:"admission_receipt_id"`
	ObservedAt         int64                  `json:"observed_at"`
	Result             core.OutcomeResult     `json:"result"`
	Dimension          core.Dimension         `json:"dimension"`
	Severity           core.Severity          `json:"severity"`
	EvidenceRefs       []string               `json:"evidence_refs"`
	Attribution        core.Attribution       `json:"attribution"`
	Supersedes         []string               `json:"supersedes"`
	Details            string                 `json:"details"`
}

// Call holds the arguments of the function under test other than the HTTP
// request. Which members a case may set depends on Expect.Function.
type Call struct {
	Realm    *RealmJSON `json:"realm"`
	Workload string     `json:"workload"`
	// AgentID is the agent ID the request names, the third input of
	// resolve_agent_binding (draft 17.1).
	AgentID        string         `json:"agent_id"`
	MappingVersion string         `json:"mapping_version"`
	Principal      *PrincipalJSON `json:"principal"`
	// Binding is the agent binding of a check_context call; absent, the call
	// establishes no agent and the check receives an empty binding.
	Binding      *BindingJSON           `json:"binding"`
	NativePath   string                 `json:"native_path"`
	CheckID      *string                `json:"check_id"`
	Intent       *core.Intent           `json:"intent"`
	Operation    *core.OperationContext `json:"operation"`
	EvidenceRefs []string               `json:"evidence_refs"`
	Observation  *ObservationJSON       `json:"observation"`
}

// Expect is what the case requires. Function, Outcome and the member that
// belongs to the outcome carry the assertions; the rest are optional.
type Expect struct {
	// Function is one of the seven draft 17.1 function names.
	Function string `json:"function"`
	// Outcome is one of the outcomes defined for Function.
	Outcome string `json:"outcome"`
	// ReasonCode is the stable code the function reports: the public denial
	// reason, the draft 13.4 code of an error, or the ReasonCode of a check.
	ReasonCode string `json:"reason_code"`
	// MustNotCall lists native hooks that must not have fired by the end of
	// the case.
	MustNotCall []string `json:"must_not_call"`
	// LeakScan, when present, requires that no credential appears in the
	// values and errors the function returns.
	LeakScan *LeakScan `json:"leak_scan"`

	Principal *ExpectPrincipal `json:"principal"`
	Binding   *ExpectBinding   `json:"binding"`
	Operation *ExpectOperation `json:"operation"`
	Claim     *ExpectClaim     `json:"claim"`
	Decision  *ExpectDecision  `json:"decision"`
}

// LeakScan configures the credential scan of draft 19.
type LeakScan struct {
	// Secrets are literal credential values that must not appear anywhere.
	Secrets []string `json:"secrets"`
}

// ExpectPrincipal lists the fields of the authenticated principal to check. An
// empty field is not checked.
type ExpectPrincipal struct {
	ID        string     `json:"id"`
	Realm     *RealmJSON `json:"realm"`
	Workload  string     `json:"workload"`
	Mechanism string     `json:"mechanism"`
	// Attributes, when present, is a JSON object. Each of its members must
	// equal, as JSON data, the principal's attribute of the same name; an
	// attribute the object does not name is not checked.
	Attributes json.RawMessage `json:"attributes"`
}

// ExpectBinding lists the fields of the agent binding to check. An empty field
// is not checked.
type ExpectBinding struct {
	AgentID    string `json:"agent_id"`
	OperatorID string `json:"operator_id"`
	HolderJKT  string `json:"holder_jkt"`
	Status     string `json:"status"`
	// EnrolledElsewhere, when present, is the required value of
	// AgentBinding.EnrolledElsewhere: whether the agent ID is enrolled for
	// another workload of the realm (draft 17.1). It may be true only for the
	// outcome "unknown", and it is the only member that outcome accepts.
	EnrolledElsewhere *bool `json:"enrolled_elsewhere"`
}

// ExpectOperation lists the fields of the operation context to check. An empty
// string or an absent member is not checked.
type ExpectOperation struct {
	EnvironmentID string             `json:"environment_id"`
	PrincipalID   string             `json:"principal_id"`
	Action        string             `json:"action"`
	Resources     *[]string          `json:"resources"`
	Method        string             `json:"method"`
	TargetURI     string             `json:"target_uri"`
	BodyDigest    string             `json:"body_digest"`
	Headers       *map[string]string `json:"headers"`
}

// ExpectClaim lists the fields of the native claim to check. An absent member
// is not checked; a JSON null in a time member requires the zero time.
type ExpectClaim struct {
	Value           json.RawMessage `json:"value"`
	ObservedAt      json.RawMessage `json:"observed_at"`
	StatusCheckedAt json.RawMessage `json:"status_checked_at"`
	SourceID        string          `json:"source_id"`
	SourceRef       string          `json:"source_ref"`
}

// ExpectDecision lists the fields of the native decision to check. An absent
// member or an empty string is not checked; a JSON null in decided_at requires
// the zero time, and a JSON null in source_ref requires an empty source
// reference: the source keeps no record of the decision.
type ExpectDecision struct {
	// Obligations, when present, must equal the decision's obligations
	// exactly, in order.
	Obligations *[]ObligationJSON `json:"obligations"`
	// SourceID, SourceRef, DecidedAt and PolicyRevision are the provenance the
	// native policy source gave: the source, its record of the decision, the
	// decision time in Unix seconds, and the policy revision.
	SourceID       string          `json:"source_id"`
	SourceRef      json.RawMessage `json:"source_ref"`
	DecidedAt      json.RawMessage `json:"decided_at"`
	PolicyRevision string          `json:"policy_revision"`
}

// ObligationJSON is an obligation in a case file.
type ObligationJSON struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes"`
}

var idPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[0-9]{2,}(\.[a-z0-9]+(-[a-z0-9]+)*)?$`)
var adapterNamePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// commonDir is the directory of the cases every adapter must pass, relative to
// the fixture root.
const commonDir = "adapters/_common"

// Load reads the common cases and, when adapterName is not empty, the cases in
// adapters/<adapterName>, from the fixture tree fsys. An adapter's case files
// sit directly in its directory, as the common cases do; a subdirectory is not
// read. A case file that does not strict-parse, or breaks a rule of the
// format, is an error.
func Load(fsys fs.FS, adapterName string) ([]Case, error) {
	cases, err := loadDir(fsys, commonDir)
	if err != nil {
		return nil, err
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("adaptertest: no case files in %s", commonDir)
	}
	for i := range cases {
		cases[i].common = true
	}
	if adapterName != "" {
		if !adapterNamePattern.MatchString(adapterName) {
			return nil, fmt.Errorf("adaptertest: adapter name %q is not a lowercase hyphenated name", adapterName)
		}
		own, err := loadDir(fsys, path.Join("adapters", adapterName))
		if err != nil {
			return nil, err
		}
		if len(own) == 0 {
			return nil, fmt.Errorf("adaptertest: no case files in adapters/%s", adapterName)
		}
		cases = append(cases, own...)
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.ID] {
			return nil, fmt.Errorf("adaptertest: case id %s is used twice", c.ID)
		}
		seen[c.ID] = true
	}
	return cases, nil
}

func loadDir(fsys fs.FS, dir string) ([]Case, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("adaptertest: read %s: %w", dir, err)
	}
	var cases []Case
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		file := path.Join(dir, e.Name())
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, fmt.Errorf("adaptertest: read %s: %w", file, err)
		}
		var c Case
		if err := strictjson.Unmarshal(data, strictjson.Limits{MaxBytes: maxCaseBytes}, &c); err != nil {
			return nil, fmt.Errorf("adaptertest: %s: %w", file, err)
		}
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("adaptertest: %s: %w", file, err)
		}
		cases = append(cases, c)
	}
	return cases, nil
}

// appliesTo reports whether the case runs against an adapter whose profile
// supports workloads shared by several agents (shared true) or does not.
func (c *Case) appliesTo(shared bool) bool {
	switch c.Workloads {
	case workloadsShared:
		return shared
	case workloadsDedicated:
		return !shared
	}
	return true
}

// presentCall lists the members of the call that are set.
func (c *Case) presentCall() []string {
	k := &c.Call
	var set []string
	add := func(present bool, name string) {
		if present {
			set = append(set, name)
		}
	}
	add(k.Realm != nil, "realm")
	add(k.Workload != "", "workload")
	add(k.AgentID != "", "agent_id")
	add(k.MappingVersion != "", "mapping_version")
	add(k.Principal != nil, "principal")
	add(k.Binding != nil, "binding")
	add(k.NativePath != "", "native_path")
	add(k.CheckID != nil, "check_id")
	add(k.Intent != nil, "intent")
	add(k.Operation != nil, "operation")
	add(k.EvidenceRefs != nil, "evidence_refs")
	add(k.Observation != nil, "observation")
	return set
}

// callMembers lists, per function, the required and the optional members of
// the call.
var callMembers = map[string]struct{ required, optional []string }{
	fnAuthenticate: {},
	fnBinding:      {required: []string{"realm", "workload", "agent_id"}},
	fnMapOperation: {required: []string{"principal", "mapping_version"}},
	fnClaim:        {required: []string{"principal", "native_path"}, optional: []string{"intent", "operation"}},
	fnCheck:        {required: []string{"check_id", "principal", "operation"}, optional: []string{"binding", "intent", "evidence_refs"}},
	fnAuthorize:    {required: []string{"principal", "operation"}},
	fnRecord:       {required: []string{"observation"}},
}

// expectMember names the Expect member that an outcome must come with, because
// the outcome says nothing without it.
var expectMember = map[string]string{
	outAuthenticated: "principal",
	outBound:         "binding",
	outUnusable:      "binding",
}

// presentExpect lists the outcome-specific members of the expectation.
func (e *Expect) presentExpect() []string {
	var set []string
	add := func(present bool, name string) {
		if present {
			set = append(set, name)
		}
	}
	add(e.Principal != nil, "principal")
	add(e.Binding != nil, "binding")
	add(e.Operation != nil, "operation")
	add(e.Claim != nil, "claim")
	add(e.Decision != nil, "decision")
	return set
}

// functionExpect names the outcome-specific Expect members a function accepts.
var functionExpect = map[string][]string{
	fnAuthenticate: {"principal"},
	fnBinding:      {"binding"},
	fnMapOperation: {"operation"},
	fnClaim:        {"claim"},
	fnAuthorize:    {"decision"},
}

func (c *Case) validate() error {
	if c.CaseVersion != caseVersion {
		return fmt.Errorf("case_version is %d, want %d", c.CaseVersion, caseVersion)
	}
	if !idPattern.MatchString(c.ID) {
		return fmt.Errorf("id %q does not match %s", c.ID, idPattern)
	}
	if strings.TrimSpace(c.Title) == "" {
		return fmt.Errorf("%s: title is empty", c.ID)
	}
	switch c.Workloads {
	case "", workloadsShared, workloadsDedicated:
	default:
		return fmt.Errorf("%s: workloads %q is not %q or %q", c.ID, c.Workloads, workloadsShared, workloadsDedicated)
	}
	if c.Now != nil && (*c.Now < 0 || *c.Now > strictjson.MaxSafeInteger) {
		return fmt.Errorf("%s: now is outside 0..2^53-1", c.ID)
	}
	if !isJSONObject(c.NativeState) {
		return fmt.Errorf("%s: native_state is not a JSON object", c.ID)
	}
	f := c.Expect.Function
	outcomes, ok := functionOutcomes[f]
	if !ok {
		return fmt.Errorf("%s: expect.function %q is not one of the seven functions", c.ID, f)
	}
	if !slices.Contains(outcomes, c.Expect.Outcome) {
		return fmt.Errorf("%s: outcome %q is not defined for %s (want one of %v)", c.ID, c.Expect.Outcome, f, outcomes)
	}
	if err := c.validateRequest(f); err != nil {
		return fmt.Errorf("%s: %w", c.ID, err)
	}
	if err := c.validateCall(f); err != nil {
		return fmt.Errorf("%s: %w", c.ID, err)
	}
	if err := c.validateExpect(f); err != nil {
		return fmt.Errorf("%s: %w", c.ID, err)
	}
	return nil
}

func isJSONObject(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
}

func (c *Case) validateRequest(f string) error {
	takesRequest := f == fnAuthenticate || f == fnMapOperation
	switch {
	case takesRequest && c.Request == nil:
		return fmt.Errorf("%s needs a request", f)
	case !takesRequest && c.Request != nil:
		return fmt.Errorf("%s takes no request", f)
	case c.Request == nil:
		return nil
	}
	r := c.Request
	if r.Method == "" || r.URL == "" {
		return fmt.Errorf("request needs a method and a url")
	}
	switch r.Arrival {
	case "", arrivalEnforcementPoint, arrivalDirect:
	default:
		return fmt.Errorf("request.arrival %q is not %q or %q", r.Arrival, arrivalEnforcementPoint, arrivalDirect)
	}
	for name := range r.Headers {
		if name == "" || strings.ContainsAny(name, " \t\r\n:") {
			return fmt.Errorf("request header name %q is not valid", name)
		}
	}
	if _, err := decodeBody(r.BodyB64); err != nil {
		return err
	}
	return nil
}

func (c *Case) validateCall(f string) error {
	m := callMembers[f]
	set := c.presentCall()
	for _, name := range m.required {
		if !slices.Contains(set, name) {
			return fmt.Errorf("call.%s is required for %s", name, f)
		}
	}
	for _, name := range set {
		if !slices.Contains(m.required, name) && !slices.Contains(m.optional, name) {
			return fmt.Errorf("call.%s is not an argument of %s", name, f)
		}
	}
	if f == fnCheck {
		return c.validateCheckCall()
	}
	return nil
}

// validateCheckCall checks the principal and the binding of a check_context
// call: the principal is the one the operation names (draft 12.1), and a
// binding has a defined status.
func (c *Case) validateCheckCall() error {
	k := &c.Call
	if k.Principal.ID != k.Operation.PrincipalID {
		return fmt.Errorf("call.principal.id %q is not call.operation.principal_id %q: the principal is the one of the operation (draft 12.1)", k.Principal.ID, k.Operation.PrincipalID)
	}
	if b := k.Binding; b != nil && b.Status != "" && !adapter.BindingStatus(b.Status).Valid() {
		return fmt.Errorf("call.binding.status %q is not a binding status", b.Status)
	}
	return nil
}

// validateElsewhere checks expect.binding.enrolled_elsewhere: only an UNKNOWN
// result reports the agent ID enrolled for another workload (draft 17.1), so
// the member may be true only for the outcome unknown, and that outcome, which
// names no record, accepts no other binding member.
func (e *Expect) validateElsewhere() error {
	b := e.Binding
	if b == nil {
		return nil
	}
	if e.Outcome == outNotEnrolled {
		if b.AgentID != "" || b.OperatorID != "" || b.HolderJKT != "" || b.Status != "" {
			return fmt.Errorf("outcome %q accepts only enrolled_elsewhere in expect.binding", e.Outcome)
		}
		return nil
	}
	if b.EnrolledElsewhere != nil && *b.EnrolledElsewhere {
		return fmt.Errorf("expect.binding.enrolled_elsewhere true applies only to outcome %q, not %q", outNotEnrolled, e.Outcome)
	}
	return nil
}

func (c *Case) validateExpect(f string) error {
	e := &c.Expect
	for _, name := range e.presentExpect() {
		if !slices.Contains(functionExpect[f], name) {
			return fmt.Errorf("expect.%s does not apply to %s", name, f)
		}
	}
	if want, ok := expectMember[e.Outcome]; ok && !slices.Contains(e.presentExpect(), want) {
		return fmt.Errorf("outcome %q needs expect.%s", e.Outcome, want)
	}
	if err := e.validateElsewhere(); err != nil {
		return err
	}
	if p := e.Principal; p != nil && len(p.Attributes) > 0 && !isJSONObject(p.Attributes) {
		return fmt.Errorf("expect.principal.attributes is not a JSON object")
	}
	for _, h := range e.MustNotCall {
		if strings.TrimSpace(h) == "" {
			return fmt.Errorf("expect.must_not_call has an empty hook name")
		}
	}
	return nil
}
