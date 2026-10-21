package memory

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
	"hop.top/pact-go/core/strictjson"
	"hop.top/pact-go/internal/ascii"
)

// Model is the value of State.Model: the neutral "common/1" native state that
// the common conformance cases use. The fixture README defines it.
const Model = "common/1"

// maxStateBytes bounds the state document.
const maxStateBytes = 1 << 20

// State is the native state of the memory adapter: the stores it reads. It is
// the "common/1" model of the common conformance cases, in Go. Unknown members
// in a document are an error.
type State struct {
	Model string `json:"model"`
	// Gateway is the trusted configuration of the gateway the adapter serves.
	Gateway Gateway `json:"gateway"`
	// Mappings are the installed operation mappings, by version.
	Mappings []Mapping `json:"mappings"`
	// Identities is the identity store: who each credential authenticates.
	Identities []Identity `json:"identities"`
	// Enrollments is the enrollment source of agent/key bindings.
	Enrollments []Enrollment `json:"enrollments"`
	// ApprovedPaths are the native paths an administrator approved for
	// ReadNativeClaim.
	ApprovedPaths []string `json:"approved_paths"`
	// Claims are the authoritative values behind the approved paths.
	Claims []ClaimRecord `json:"claims"`
	// Checks are the installed context checks and their native verdicts.
	Checks []CheckRecord `json:"checks"`
	// Policy is the native authorization policy.
	Policy []PolicyRule `json:"policy"`
	// Visibility is "execution" when the adapter observes executions and
	// "none", or absent, when it does not.
	Visibility string `json:"visibility"`
	// Reporting configures the signer of outcome reports. When absent,
	// RecordOutcome is unavailable.
	Reporting *Reporting `json:"reporting"`
	// Sightings are the observation times that the adapter's guard against
	// re-stamping already holds, one per source record. A check with
	// freshness limits is evaluated against them.
	Sightings []Sighting `json:"sightings"`
	// UnavailableSources are the ids of configured sources that cannot
	// currently answer. A record of such a source cannot be read.
	UnavailableSources []string `json:"unavailable_sources"`
}

// Realm is a tenant in one environment.
type Realm struct {
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
}

// Gateway is the trusted configuration of draft 4.2 that the adapter needs.
type Gateway struct {
	TenantID      string `json:"tenant_id"`
	EnvironmentID string `json:"environment_id"`
	// Origin is the public HTTPS origin of the gateway. It is the only source
	// of the scheme, host and port of a target URI.
	Origin string `json:"origin"`
	// HeaderAllowlist names the application headers that are covered by the
	// operation context, besides content-type.
	HeaderAllowlist []string `json:"header_allowlist"`
}

// Mapping is one installed version of the operation mapping.
type Mapping struct {
	Version string  `json:"version"`
	Routes  []Route `json:"routes"`
}

// Route maps a method and a path template to an action and a resource
// template. A {name} segment of the path matches one path segment, and the
// same placeholder in Resource is replaced by it.
type Route struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// Identity is an authenticated principal and the secret that proves it.
type Identity struct {
	// Ref is the name by which a case refers to the identity.
	Ref string `json:"ref"`
	// ID is the principal id, namespaced by issuer.
	ID       string `json:"id"`
	Realm    Realm  `json:"realm"`
	Workload string `json:"workload"`
	// Secret is the bearer token that authenticates the identity.
	Secret     string         `json:"secret"`
	Attributes map[string]any `json:"attributes"`
}

// Enrollment is an agent/key binding of a workload.
type Enrollment struct {
	Realm           Realm  `json:"realm"`
	Workload        string `json:"workload"`
	AgentID         string `json:"agent_id"`
	OperatorID      string `json:"operator_id"`
	HolderJKT       string `json:"holder_jkt"`
	Status          string `json:"status"`
	ObservedAt      *int64 `json:"observed_at"`
	StatusCheckedAt *int64 `json:"status_checked_at"`
	SourceID        string `json:"source_id"`
	SourceRef       string `json:"source_ref"`
}

// ClaimRecord is one authoritative value of a principal.
type ClaimRecord struct {
	Realm     Realm  `json:"realm"`
	Principal string `json:"principal"`
	Path      string `json:"path"`
	// Resource, when set, makes the record a fact of that resource: it is read
	// only for an operation whose resources list it.
	Resource string `json:"resource"`
	// TaskID, when set, makes the record a fact of that task: it is read only
	// for an intent whose task_id equals it.
	TaskID string `json:"task_id"`
	// Value is the value as JSON. It may be null.
	Value json.RawMessage `json:"value"`
	// ObservedAt and StatusCheckedAt are the times the source gives, in Unix
	// seconds; absent when the source gives none.
	ObservedAt      *int64 `json:"observed_at"`
	StatusCheckedAt *int64 `json:"status_checked_at"`
	SourceID        string `json:"source_id"`
	SourceRef       string `json:"source_ref"`
}

// CheckRecord is an installed check and the verdict of its native state.
type CheckRecord struct {
	ID string `json:"id"`
	// Principal, when set, is the principal the record is the check's native
	// state for: it applies only in a call whose authenticated principal has
	// this id (draft 17.1, 17.3.1).
	Principal string `json:"principal"`
	// AgentID, when set, is the agent the record is the check's native state
	// for: it applies only in a call whose agent binding names this agent.
	AgentID    string `json:"agent_id"`
	Result     string `json:"result"`
	ReasonCode string `json:"reason_code"`
	SourceID   string `json:"source_id"`
	SourceRef  string `json:"source_ref"`
	ObservedAt *int64 `json:"observed_at"`
	// StatusCheckedAt is the status time of the record the check consults,
	// in Unix seconds; absent when no status check took place.
	StatusCheckedAt *int64 `json:"status_checked_at"`
	// Freshness, when set, holds the age limits the installed check requires
	// of the record it consults.
	Freshness *CheckFreshness `json:"freshness"`
	// PinnedRevision, when set, is the revision of the native source that the
	// installed check is pinned to; Revision is the one the source reports now.
	PinnedRevision string `json:"pinned_revision"`
	Revision       string `json:"revision"`
}

// PolicyRule is one rule of the native policy. A rule applies to the principal
// of the realm that it names, for the action, and for the resource when it
// names one.
type PolicyRule struct {
	Realm       Realm        `json:"realm"`
	Principal   string       `json:"principal"`
	Action      string       `json:"action"`
	Resource    string       `json:"resource"`
	Effect      string       `json:"effect"`
	Obligations []Obligation `json:"obligations"`
	Reason      string       `json:"reason"`
	// SourceID names the policy source that holds the rule; when it is empty
	// the rule is in the adapter's own policy store, [PolicySourceID].
	SourceID string `json:"source_id"`
	// SourceRef, DecidedAt and PolicyRevision are the provenance the source
	// gives for a decision by this rule: its record of the decision, the
	// decision time in Unix seconds, and the policy revision. Each is absent
	// when the source gives none.
	SourceRef      string `json:"source_ref"`
	DecidedAt      *int64 `json:"decided_at"`
	PolicyRevision string `json:"policy_revision"`
}

// Obligation is an obligation of a policy rule.
type Obligation struct {
	ID         string         `json:"id"`
	Attributes map[string]any `json:"attributes"`
}

// Reporting names the issuer, audience and key of outcome reports.
type Reporting struct {
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	KID      string `json:"kid"`
}

// ParseState strict-parses a state document and validates it.
func ParseState(raw []byte) (State, error) {
	var st State
	if err := strictjson.Unmarshal(raw, strictjson.Limits{MaxBytes: maxStateBytes}, &st); err != nil {
		return State{}, fmt.Errorf("memory: state: %w", err)
	}
	if err := st.Validate(); err != nil {
		return State{}, fmt.Errorf("memory: state: %w", err)
	}
	return st, nil
}

// forbiddenHeaders are the headers that never belong to an operation context
// (draft 10.2, 19): credentials, presentations, hop-by-hop headers and
// signatures.
var forbiddenHeaders = []string{
	"authorization", "proxy-authorization", "cookie", "set-cookie",
	"pact-presentation", "pact-admission",
	"connection", "keep-alive", "proxy-connection", "te", "trailer",
	"transfer-encoding", "upgrade",
	"signature", "signature-input", "content-digest", "digest",
}

// Validate reports the first problem in the state.
func (st State) Validate() error {
	if st.Model != Model {
		return fmt.Errorf("model is %q, want %q", st.Model, Model)
	}
	g := st.Gateway
	if g.TenantID == "" || g.EnvironmentID == "" {
		return errors.New("gateway needs a tenant_id and an environment_id")
	}
	if _, err := NormalizeOrigin(g.Origin); err != nil {
		return fmt.Errorf("gateway origin: %w", err)
	}
	for _, h := range g.HeaderAllowlist {
		if h != strings.ToLower(h) || slices.Contains(forbiddenHeaders, h) {
			return fmt.Errorf("gateway header_allowlist: %q must be a lowercase application header; credentials, presentations, hop-by-hop headers and signatures never belong to an operation", h)
		}
	}
	for _, m := range st.Mappings {
		if m.Version == "" {
			return errors.New("a mapping has no version")
		}
		for _, rt := range m.Routes {
			if rt.Method == "" || !strings.HasPrefix(rt.Path, "/") || rt.Action == "" || rt.Resource == "" {
				return fmt.Errorf("mapping %q has an incomplete route", m.Version)
			}
		}
	}
	refs := map[string]bool{}
	for _, i := range st.Identities {
		if i.Ref == "" || i.ID == "" || i.Secret == "" || i.Realm == (Realm{}) {
			return fmt.Errorf("identity %q needs a ref, an id, a realm and a secret", i.Ref)
		}
		if refs[i.Ref] {
			return fmt.Errorf("identity ref %q is used twice", i.Ref)
		}
		refs[i.Ref] = true
	}
	for _, e := range st.Enrollments {
		if !adapter.BindingStatus(e.Status).Valid() {
			return fmt.Errorf("enrollment of %q has status %q", e.Workload, e.Status)
		}
		if e.HolderJKT != "" {
			if err := core.Digest(e.HolderJKT).Validate(); err != nil {
				return fmt.Errorf("enrollment of %q: %w", e.Workload, err)
			}
		}
		if e.SourceID == "" {
			return fmt.Errorf("enrollment of %q names no source_id", e.Workload)
		}
		if u, err := url.Parse(e.AgentID); err != nil || !u.IsAbs() {
			return fmt.Errorf("enrollment of %q: agent_id %q is not an absolute URI", e.Workload, e.AgentID)
		}
	}
	for _, c := range st.Claims {
		if !slices.Contains(st.ApprovedPaths, c.Path) {
			return fmt.Errorf("claim %q is not under an approved path", c.Path)
		}
		if len(c.Value) == 0 {
			return fmt.Errorf("claim %q has no value", c.Path)
		}
		if c.SourceID == "" {
			return fmt.Errorf("claim %q names no source_id", c.Path)
		}
	}
	for _, c := range st.Checks {
		if c.ID == "" || !adapter.Verdict(c.Result).Valid() || c.ReasonCode == "" {
			return fmt.Errorf("check %q needs an id, a result and a reason_code", c.ID)
		}
	}
	for _, p := range st.Policy {
		if !adapter.Effect(p.Effect).Valid() || p.Principal == "" || p.Action == "" {
			return fmt.Errorf("a policy rule for %q needs a principal, an action and an effect", p.Principal)
		}
	}
	if err := st.validateFreshness(); err != nil {
		return err
	}
	switch st.Visibility {
	case "", "execution", "none":
	default:
		return fmt.Errorf("visibility is %q, want \"execution\" or \"none\"", st.Visibility)
	}
	if r := st.Reporting; r != nil && (r.Issuer == "" || r.Audience == "" || r.KID == "") {
		return errors.New("reporting needs an issuer, an audience and a kid")
	}
	return nil
}

// NormalizeOrigin returns the origin in the form a target URI uses: the scheme
// and host lowercase, the default port omitted (draft 10.2). Only an HTTPS
// origin without userinfo, path, query or fragment is valid.
func NormalizeOrigin(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return "", err
	}
	if !ascii.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("%q is not an https origin", origin)
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("%q is not a bare origin", origin)
	}
	host := ascii.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("%q has no host", origin)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && port != "443" {
		host += ":" + port
	}
	return "https://" + host, nil
}
