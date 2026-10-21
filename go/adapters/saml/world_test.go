package saml_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core/strictjson"
)

// samlModel is the model of the native state of the SAML cases, defined in
// spec/v1.0/fixtures/adapters/saml/README.md.
const samlModel = "saml/1"

// Source ids of the native stores of the saml/1 model.
const (
	sessionSource = "sp-sessions"
	grantSource   = "task-grants"
)

// Event kinds of the saml/1 model.
const (
	eventSignIn = "sign_in"
	eventLogout = "logout"
)

// samlState is the saml/1 native state of a case.
type samlState struct {
	Model              string               `json:"model"`
	Gateway            memory.Gateway       `json:"gateway"`
	SP                 spConfig             `json:"sp"`
	Agents             []agentCredential    `json:"agents"`
	Enrollments        []memory.Enrollment  `json:"enrollments"`
	Events             []event              `json:"events"`
	Grants             []grantRecord        `json:"grants"`
	DirectoryPaths     []string             `json:"directory_paths"`
	Claims             []memory.ClaimRecord `json:"claims"`
	Checks             []memory.CheckRecord `json:"checks"`
	Sightings          []memory.Sighting    `json:"sightings"`
	UnavailableSources []string             `json:"unavailable_sources"`
}

// spConfig is the configuration of the SP's SAML implementation that the
// fake SP's assertion gate reads.
type spConfig struct {
	EntityID    string   `json:"entity_id"`
	TrustedIDPs []string `json:"trusted_idps"`
}

// agentCredential is an agent's own broker credential: a bearer token that
// the broker's agent authentication maps to the agent's workload.
type agentCredential struct {
	Ref      string `json:"ref"`
	Token    string `json:"token"`
	Workload string `json:"workload"`
}

// event is a sign-in, an assertion that reaches the SP's SAML
// implementation, or a logout, in the order the SP sees them.
type event struct {
	Kind              string `json:"kind"`
	AssertionID       string `json:"assertion_id"`
	Issuer            string `json:"issuer"`
	Audience          string `json:"audience"`
	Subject           string `json:"subject"`
	AuthnInstant      int64  `json:"authn_instant"`
	SessionID         string `json:"session_id"`
	SessionCredential string `json:"session_credential"`
	ExpiresAt         int64  `json:"expires_at"`
}

// grantRecord is a TaskGrant of the broker's grant store.
type grantRecord struct {
	TaskID    string      `json:"task_id"`
	SessionID string      `json:"session_id"`
	User      string      `json:"user"`
	AgentID   string      `json:"agent_id"`
	Scope     *grantScope `json:"scope"`
	ExpiresAt int64       `json:"expires_at"`
	Revoked   bool        `json:"revoked"`
}

// grantScope is the scope of a grant: the permitted purpose_id values,
// actions and resources. A grant without one permits the whole mapping.
type grantScope struct {
	Purposes  []string `json:"purposes"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

// spSession is an SPSession that the fake SP created.
type spSession struct {
	SessionID string
	Principal string
	IDPRealm  string
	// Credential is the browser credential of the session. It never reaches
	// the adapter; a case presents it only as a copied cookie.
	Credential   string
	AuthnInstant int64
	ExpiresAt    int64
	LoggedOut    bool
}

// world is a parsed saml/1 state with the sessions the fake SP created.
type world struct {
	st       samlState
	sessions []spSession
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

// loadWorld parses a saml/1 state strictly and runs its events through the
// fake SP.
func loadWorld(raw []byte) (*world, error) {
	var st samlState
	if err := strictjson.Unmarshal(raw, strictjson.Limits{}, &st); err != nil {
		return nil, fmt.Errorf("saml/1 state: %w", err)
	}
	if st.Model != samlModel {
		return nil, fmt.Errorf("model is %q, want %q", st.Model, samlModel)
	}
	if st.Gateway.TenantID == "" || st.Gateway.EnvironmentID == "" || st.Gateway.Origin == "" {
		return nil, errors.New("saml/1 state: gateway needs a tenant_id, an environment_id and an origin")
	}
	if st.SP.EntityID == "" || len(st.SP.TrustedIDPs) == 0 {
		return nil, errors.New("saml/1 state: sp needs an entity_id and trusted_idps")
	}
	refs := map[string]bool{}
	for _, a := range st.Agents {
		if a.Ref == "" || a.Token == "" || a.Workload == "" || refs[a.Ref] {
			return nil, fmt.Errorf("saml/1 state: agent %q is incomplete or named twice", a.Ref)
		}
		refs[a.Ref] = true
	}
	tasks := map[string]bool{}
	for _, g := range st.Grants {
		if g.TaskID == "" || g.SessionID == "" || g.User == "" || g.AgentID == "" || tasks[g.TaskID] {
			return nil, fmt.Errorf("saml/1 state: grant %q is incomplete or named twice", g.TaskID)
		}
		tasks[g.TaskID] = true
	}
	w := &world{st: st}
	if err := w.runSP(); err != nil {
		return nil, err
	}
	return w, nil
}

// runSP is the fake SP: an in-memory session store behind a minimal
// assertion gate that stands in for the SP's SAML implementation. A sign-in
// creates a session only when its audience is the SP's entity ID (SAML
// Profiles, section 4.1.4.2), its issuer is a trusted identity provider, and
// its assertion ID was not used before (section 4.1.4.5). The principal is
// the saml identifier of the SP, the issuer and the subject (profile SB-4,
// identity mapping IM-2). A logout marks the session logged out for good.
func (w *world) runSP() error {
	used := map[string]bool{}
	for i, e := range w.st.Events {
		switch e.Kind {
		case eventSignIn:
			if e.AssertionID == "" || e.SessionID == "" || e.Subject == "" || e.ExpiresAt == 0 {
				return fmt.Errorf("saml/1 state: event %d is an incomplete sign-in", i)
			}
			replay := used[e.AssertionID]
			used[e.AssertionID] = true
			if replay || e.Audience != w.st.SP.EntityID || !slices.Contains(w.st.SP.TrustedIDPs, e.Issuer) {
				continue
			}
			if _, ok := w.session(e.SessionID); ok {
				return fmt.Errorf("saml/1 state: event %d reuses session id %q", i, e.SessionID)
			}
			w.sessions = append(w.sessions, spSession{
				SessionID:    e.SessionID,
				Principal:    samlPrincipal(w.st.SP.EntityID, e.Issuer, e.Subject),
				IDPRealm:     e.Issuer,
				Credential:   e.SessionCredential,
				AuthnInstant: e.AuthnInstant,
				ExpiresAt:    e.ExpiresAt,
			})
		case eventLogout:
			if e.AssertionID != "" || e.Subject != "" || e.Issuer != "" || e.Audience != "" {
				return fmt.Errorf("saml/1 state: event %d is a logout with sign-in members", i)
			}
			for j := range w.sessions {
				if w.sessions[j].SessionID == e.SessionID {
					w.sessions[j].LoggedOut = true
				}
			}
		default:
			return fmt.Errorf("saml/1 state: event %d has kind %q", i, e.Kind)
		}
	}
	return nil
}

// session returns the session the fake SP holds under id.
func (w *world) session(id string) (spSession, bool) {
	for _, s := range w.sessions {
		if s.SessionID == id {
			return s, true
		}
	}
	return spSession{}, false
}

// samlPrincipal is saml:{sp-id}:{idp-entity-id}:{subject}, each component
// percent-encoded as IM-2 says: every octet that is not unreserved as %XX in
// upper-case hexadecimal.
func samlPrincipal(sp, idp, subject string) string {
	return "saml:" + pctEncode(sp) + ":" + pctEncode(idp) + ":" + pctEncode(subject)
}

func pctEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// realm is the realm of the gateway.
func (w *world) realm() adapter.Realm {
	return adapter.Realm{TenantID: w.st.Gateway.TenantID, EnvironmentID: w.st.Gateway.EnvironmentID}
}

// unavailable reports whether the source named id cannot answer.
func (w *world) unavailable(id string) bool { return slices.Contains(w.st.UnavailableSources, id) }

// attachCredential sets the broker token of the agent ref names on r as a
// bearer token (RFC 6750, section 2.1), unless r already carries an
// Authorization header.
func attachCredential(agents []agentCredential, r *http.Request, ref string) error {
	for _, a := range agents {
		if a.Ref != ref {
			continue
		}
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+a.Token)
		}
		return nil
	}
	return fmt.Errorf("no agent %q", ref)
}

// taskOfPath returns the task_id of a path of the broker's agent-facing
// routes, /broker/v1/tasks/{task_id}/records and
// /broker/v1/tasks/{task_id}/records/{record_id}.
func taskOfPath(path string) (string, bool) {
	segs := strings.Split(path, "/")
	if (len(segs) == 6 || len(segs) == 7) && segs[0] == "" && segs[1] == "broker" && segs[2] == "v1" && segs[3] == "tasks" && segs[5] == "records" && segs[4] != "" {
		return segs[4], true
	}
	return "", false
}
