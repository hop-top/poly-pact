package abac_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/strictjson"
)

// abacModel is the model of the native state of the ABAC cases, defined in
// spec/v1.0/fixtures/adapters/abac/README.md.
const abacModel = "abac/1"

// hookPDP is the native hook an ABAC harness fires each time a request
// reaches the PDP.
const hookPDP = "pdp-query"

// policyAsset names the policy of the cases, assets/policy.rego. The fake PDP
// realizes its rule in Go (i11); the integration tier loads the file into OPA.
const policyAsset = "policy.rego"

// The approved native paths of the fact sources (profile section 8.2, and F1
// of section 8.1).
const (
	pathPrincipalID      = "/subject/principal_id"
	pathDepartment       = "/subject/department"
	pathClearance        = "/subject/clearance"
	pathDeviceCompliant  = "/environment/device/compliant"
	pathClassification   = "/resource/classification"
	pathOwningDepartment = "/resource/owning_department"
	pathNetworkZone      = "/environment/network_zone"
	pathTime             = "/environment/time"
)

// abacState is the abac/1 native state of a case.
type abacState struct {
	Model              string            `json:"model"`
	Gateway            memory.Gateway    `json:"gateway"`
	PDP                pdpState          `json:"pdp"`
	Entry              *entryState       `json:"entry"`
	Zones              []zoneState       `json:"zones"`
	Facts              []factState       `json:"facts"`
	Sightings          []memory.Sighting `json:"sightings"`
	UnavailableSources []string          `json:"unavailable_sources"`
}

// entryState is the installed ABAC check entry of a case (profile ABAC-16):
// the identifier of the check, the pinned policy version and, optionally, the
// installed obligation set.
type entryState struct {
	CheckID       string   `json:"check_id"`
	PolicyVersion string   `json:"policy_version"`
	Obligations   []string `json:"obligations"`
}

// pdpState is the policy decision point of a case.
type pdpState struct {
	SourceID     string          `json:"source_id"`
	DecisionPath string          `json:"decision_path"`
	Policy       string          `json:"policy"`
	DecisionID   string          `json:"decision_id"`
	Answer       *answerState    `json:"answer"`
	ExpectInput  json.RawMessage `json:"expect_input"`
}

// answerState is the literal answer of a PDP that does not run the policy.
type answerState struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
	Timeout bool              `json:"timeout"`
	Refused bool              `json:"refused"`
}

// zoneState is one entry of the zone map.
type zoneState struct {
	Prefix string `json:"prefix"`
	Zone   string `json:"zone"`
}

// factState is one record of a fact source.
type factState struct {
	Path            string          `json:"path"`
	Principal       string          `json:"principal"`
	Resource        string          `json:"resource"`
	DeviceID        string          `json:"device_id"`
	Value           json.RawMessage `json:"value"`
	ObservedAt      *int64          `json:"observed_at"`
	StatusCheckedAt *int64          `json:"status_checked_at"`
	SourceID        string          `json:"source_id"`
	SourceRef       string          `json:"source_ref"`
}

// value decodes the fact's value, keeping numbers as written.
func (f factState) value() (any, error) {
	return decodeJSON(f.Value)
}

// key is what selects the record: the principal, resource or device it is a
// fact of.
func (f factState) key() string {
	switch {
	case strings.HasPrefix(f.Path, "/subject/"):
		return f.Principal
	case strings.HasPrefix(f.Path, "/resource/"):
		return f.Resource
	}
	return f.DeviceID
}

// world is the native systems of an abac/1 case: the fact sources, the zone
// map and the PDP, which runs as a TLS server for the life of the test.
type world struct {
	st    abacState
	zones []zone
	pdp   *fakePDP
}

type zone struct {
	prefix netip.Prefix
	name   string
}

func fixtures() (fs.FS, error) { return adaptertest.DefaultFixtures() }

// modelOf reads the model member of a native state.
func modelOf(raw json.RawMessage) (string, error) {
	var head struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return "", fmt.Errorf("native state: %w", err)
	}
	return head.Model, nil
}

// loadWorld parses an abac/1 state strictly and starts its PDP.
func loadWorld(tb testing.TB, raw json.RawMessage, hooks *adaptertest.Hooks) (*world, error) {
	var st abacState
	if err := strictjson.Unmarshal(raw, strictjson.Limits{MaxBytes: 1 << 20}, &st); err != nil {
		return nil, fmt.Errorf("abac/1 state: %w", err)
	}
	if st.Model != abacModel {
		return nil, fmt.Errorf("model %q is not %s", st.Model, abacModel)
	}
	w := &world{st: st}
	for _, z := range st.Zones {
		p, err := netip.ParsePrefix(z.Prefix)
		if err != nil || z.Zone == "" {
			return nil, fmt.Errorf("zone %q: %v", z.Prefix, err)
		}
		w.zones = append(w.zones, zone{prefix: p.Masked(), name: z.Zone})
	}
	for _, f := range st.Facts {
		if f.Path == "" || f.SourceID == "" || f.key() == "" || len(f.Value) == 0 {
			return nil, fmt.Errorf("fact %+v lacks its path, key, value or source", f)
		}
	}
	pdp := st.PDP
	switch {
	case pdp.SourceID == "" || pdp.DecisionPath == "":
		return nil, errors.New("pdp: no source_id or decision_path")
	case (pdp.Policy == "") == (pdp.Answer == nil):
		return nil, errors.New("pdp: exactly one of policy and answer")
	case pdp.Policy != "" && pdp.Policy != policyAsset:
		return nil, fmt.Errorf("pdp: policy %q is not %s", pdp.Policy, policyAsset)
	case pdp.Policy != "" && pdp.DecisionID == "":
		return nil, errors.New("pdp: a policy PDP needs a decision_id")
	}
	var decide decideFunc
	if pdp.Policy != "" {
		decide = func(input any) (int, string) {
			b, _ := json.Marshal(map[string]any{"decision_id": pdp.DecisionID, "result": i11(input)})
			return http.StatusOK, string(b)
		}
	}
	w.pdp = startPDP(tb, pdp, hooks, decide)
	return w, nil
}

// fact returns the record of path for key, if the sources hold one.
func (w *world) fact(path, key string) (factState, bool) {
	for _, f := range w.st.Facts {
		if f.Path == path && f.key() == key {
			return f, true
		}
	}
	return factState{}, false
}

// sourceOf returns the source id that answers path: the source of any record
// of that path.
func (w *world) sourceOf(path string) string {
	for _, f := range w.st.Facts {
		if f.Path == path {
			return f.SourceID
		}
	}
	return ""
}

// down reports whether the source cannot currently answer.
func (w *world) down(source string) bool {
	return slices.Contains(w.st.UnavailableSources, source)
}

// zoneOf returns the zone of an address: the zone of the longest prefix that
// contains it.
func (w *world) zoneOf(addr netip.Addr) (string, bool) {
	best, bits := "", -1
	for _, z := range w.zones {
		if z.prefix.Contains(addr) && z.prefix.Bits() > bits {
			best, bits = z.name, z.prefix.Bits()
		}
	}
	return best, bits >= 0
}

// decideFunc answers a well-formed query with a status and a body.
type decideFunc func(input any) (int, string)

// fakePDP is the PDP of a case: an HTTPS server that accepts only the request
// of profile ABAC-13 and answers as the case states.
type fakePDP struct {
	URL    string
	Client *http.Client
	st     pdpState
	hooks  *adaptertest.Hooks
	decide decideFunc
}

// startPDP starts the PDP of st. A PDP that refuses connections gets the
// address of a listener that was closed again. With decide nil the PDP gives
// the literal answer of st.
func startPDP(tb testing.TB, st pdpState, hooks *adaptertest.Hooks, decide decideFunc) *fakePDP {
	p := &fakePDP{st: st, hooks: hooks, decide: decide}
	srv := httptest.NewTLSServer(http.HandlerFunc(p.serve))
	tb.Cleanup(srv.Close)
	p.URL, p.Client = srv.URL, srv.Client()
	if st.Answer != nil && st.Answer.Refused {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			tb.Fatalf("listen: %v", err)
		}
		p.URL = "https://" + l.Addr().String()
		_ = l.Close()
	}
	return p
}

// opaError writes an error body in the form OPA gives one.
func opaError(rw http.ResponseWriter, status int, code, msg string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	b, _ := json.Marshal(map[string]string{"code": code, "message": msg})
	_, _ = rw.Write(b)
}

func (p *fakePDP) serve(rw http.ResponseWriter, r *http.Request) {
	p.hooks.Fire(hookPDP)
	input, problem := p.check(r)
	if problem != "" {
		opaError(rw, http.StatusBadRequest, "invalid_parameter", "harness: "+problem)
		return
	}
	if len(p.st.ExpectInput) > 0 {
		want, err := decodeJSON(p.st.ExpectInput)
		if err != nil || !reflect.DeepEqual(want, input) {
			got, _ := json.Marshal(input)
			opaError(rw, http.StatusBadRequest, "invalid_parameter", "harness: the input is not the one the case expects: "+string(got))
			return
		}
	}
	a := p.st.Answer
	switch {
	case p.decide != nil:
		status, body := p.decide(input)
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(status)
		_, _ = io.WriteString(rw, body)
	case a.Timeout:
		<-r.Context().Done()
	default:
		for k, v := range a.Headers {
			rw.Header().Set(k, v)
		}
		if rw.Header().Get("Content-Type") == "" {
			rw.Header().Set("Content-Type", "application/json")
		}
		rw.WriteHeader(a.Status)
		if a.Body != nil {
			_, _ = io.WriteString(rw, *a.Body)
		}
	}
}

// check returns the input of a request of the form of ABAC-13, or what is
// wrong with the request.
func (p *fakePDP) check(r *http.Request) (any, string) {
	if r.Method != http.MethodPost {
		return nil, "method " + r.Method
	}
	if r.URL.Path != "/v1/data/"+p.st.DecisionPath {
		return nil, "path " + r.URL.Path
	}
	q := r.URL.Query()
	if q.Get("strict-builtin-errors") != "true" || len(q["strict-builtin-errors"]) != 1 {
		return nil, "no strict-builtin-errors=true"
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return nil, "content type " + r.Header.Get("Content-Type")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err.Error()
	}
	var top map[string]json.RawMessage
	if err := strictjson.Unmarshal(b, strictjson.Limits{MaxBytes: 1 << 20}, &top); err != nil {
		return nil, "body: " + err.Error()
	}
	raw, ok := top["input"]
	if !ok || len(top) != 1 {
		return nil, "the body has members besides input, or no input"
	}
	in, err := decodeJSON(raw)
	if err != nil {
		return nil, err.Error()
	}
	return in, ""
}

// decodeJSON decodes a JSON value with numbers kept as written.
func decodeJSON(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// The rule of assets/policy.rego, realized for the fake PDP: the illustrative
// rule of example I11 over the input of profile section 11.
var (
	i11Chain   = []string{"public", "internal", "confidential", "restricted"}
	i11Version = "abac-2026-10-01"
)

// member returns the value at the member names of path in v, if every one is
// present.
func member(v any, path ...string) (any, bool) {
	for _, name := range path {
		o, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = o[name]; !ok {
			return nil, false
		}
	}
	return v, true
}

// rank is the position of a level name in the chain; a value that is not a
// name of the chain has none.
func rank(v any) (int, bool) {
	s, ok := v.(string)
	if !ok {
		return 0, false
	}
	i := slices.Index(i11Chain, s)
	return i, i >= 0
}

// i11 is the decision document the policy gives for input.
func i11(input any) map[string]any {
	str := func(path ...string) (string, bool) {
		v, ok := member(input, path...)
		s, isStr := v.(string)
		return s, ok && isStr
	}
	action, okAction := str("action", "id")
	dept, okDept := member(input, "subject", "department")
	owner, okOwner := member(input, "resource", "owning_department")
	clr, okClr := member(input, "subject", "clearance")
	cls, okCls := member(input, "resource", "classification")
	compliant, _ := member(input, "environment", "device", "compliant")
	zoneName, okZone := str("environment", "network_zone")

	rc, okRC := rank(clr)
	rk, okRK := rank(cls)
	allow := okAction && action == "document.read" &&
		okDept && okOwner && reflect.DeepEqual(dept, owner) &&
		okClr && okCls && okRC && okRK && rc >= rk &&
		compliant == true &&
		okZone && zoneName == "corporate"
	if !allow {
		return map[string]any{"allow": false, "obligations": []any{}, "policy_version": i11Version}
	}
	obligations := []any{}
	if conf, _ := rank("confidential"); okRK && rk >= conf {
		obligations = []any{
			map[string]any{"type": "filter_fields", "params": map[string]any{"keep": []any{"/title", "/supplier", "/terms"}}},
			map[string]any{"type": "watermark", "params": map[string]any{"label": "supplier-review"}},
		}
	}
	return map[string]any{"allow": true, "obligations": obligations, "policy_version": i11Version}
}
