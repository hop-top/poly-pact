package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"hop.top/pact-go/adapter"
)

// The answers of a store that holds no such record. Any other error means the
// store could not answer.
var (
	ErrNoSession = errors.New("saml: no such session")
	ErrNoGrant   = errors.New("saml: no such grant")
)

// SPSession is the SP's own record of one signed-in user session (profile
// annex A.1). The SP creates it after its SAML implementation accepted the
// assertion that established the session; the adapter only reads it.
type SPSession struct {
	// SessionID is the SP's internal identifier of the record, the key of the
	// grants made in it. It is not the browser credential, the assertion ID or
	// the SAML SessionIndex.
	SessionID string
	// Principal is the user, saml:{sp-id}:{idp-entity-id}:{subject} (SB-4).
	Principal string
	// IDPRealm is the configured identifier of the identity provider that
	// authenticated the session (SB-4, SB-23).
	IDPRealm string
	// AuthnInstant is the time the identity provider gives for the
	// authentication. It is never an observation time (SB-7).
	AuthnInstant time.Time
	// ExpiresAt is the end of the session as the SP enforces it (SB-5).
	ExpiresAt time.Time
	// LoggedOut says the SP ended the session; it never returns to false
	// (SB-6).
	LoggedOut bool
}

// Live reports whether the session is live at now: not logged out and now is
// before ExpiresAt, with no grace (SB-6, draft 7.5).
func (s SPSession) Live(now time.Time) bool {
	return !s.LoggedOut && !s.ExpiresAt.IsZero() && now.Before(s.ExpiresAt)
}

// SessionStore is the SP's session store, read live (profile section 8, F1).
type SessionStore interface {
	// SourceID names the store as a source of claims.
	SourceID() string
	// Session returns the record of sessionID, or [ErrNoSession].
	Session(ctx context.Context, sessionID string) (SPSession, error)
}

// TaskGrant is the broker's record that a user authorized one enrolled agent
// to perform one task in one session (profile annex A.2). Its terms never
// change (SB-9).
type TaskGrant struct {
	// TaskID is assigned by the broker; it is the Intent.task_id of every
	// operation under the grant.
	TaskID string
	// SessionID is the session in which the grant was made.
	SessionID string
	// User is the principal of that session.
	User string
	// AgentID is the enrolled agent the user authorized.
	AgentID string
	// Scope is the upper bound of the grant in the installed mapping's
	// terms (SB-11, SB-13); nil permits every purpose, action and resource
	// of the mapping.
	Scope *GrantScope
	// ExpiresAt is the end of the grant.
	ExpiresAt time.Time
	// Revoked says the grant was revoked; it never returns to false.
	Revoked bool
}

// GrantScope lists what a grant permits (profile annex A.2): the purpose_id
// values of the intent, the actions and the resources of the operation, each
// compared exactly. An empty list permits none.
type GrantScope struct {
	Purposes  []string
	Actions   []string
	Resources []string
}

// TaskBroker is the broker's grant store, read live (profile section 8, F2).
type TaskBroker interface {
	// SourceID names the store as a source of check outcomes.
	SourceID() string
	// Grant returns the grant of taskID, or [ErrNoGrant].
	Grant(ctx context.Context, taskID string) (TaskGrant, error)
}

// AgentIdentity is what the broker's agent authentication establishes: the
// agent's own workload and how it authenticated.
type AgentIdentity struct {
	// Workload is the agent's broker workload, in the namespace of the
	// mechanism that authenticated it or an x- namespace; never in the saml
	// namespace and never derived from a session (SB-15).
	Workload adapter.Workload
	// Mechanism names how the agent authenticated; recorded, not
	// interpreted.
	Mechanism adapter.Mechanism
}

// AgentAuthenticator verifies the agent's own broker credential (SB-15). The
// profile leaves the mechanism to the deployment, which states it.
type AgentAuthenticator interface {
	// AuthenticateAgent returns the agent's identity, or a *[adapter.NativeDenial]
	// with NO_CREDENTIAL when the request carries no agent credential and
	// CREDENTIAL_REJECTED when it is not accepted, or an error that wraps
	// [adapter.ErrDependencyUnavailable] when it could not be evaluated. It
	// never accepts a SAML assertion or the user's session credential.
	AuthenticateAgent(ctx context.Context, r *http.Request) (AgentIdentity, error)
}

// Sessions is an in-memory [SessionStore]. The SP writes a record with Put
// after its SAML implementation accepted the assertion, and ends it with
// Logout. It is safe for concurrent use.
type Sessions struct {
	source string
	mu     sync.RWMutex
	byID   map[string]SPSession
}

// NewSessions returns an empty store whose source id is sourceID.
func NewSessions(sourceID string) *Sessions {
	return &Sessions{source: sourceID, byID: map[string]SPSession{}}
}

// SourceID returns the source id of the store.
func (s *Sessions) SourceID() string { return s.source }

// Put adds a session. A record without an id, a principal, an identity
// provider or an end, and a second record with the same id, are refused: a
// new sign-in is a new record (SB-6).
func (s *Sessions) Put(rec SPSession) error {
	if rec.SessionID == "" || rec.Principal == "" || rec.IDPRealm == "" || rec.ExpiresAt.IsZero() {
		return errors.New("saml: a session needs an id, a principal, an identity provider and an end")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[rec.SessionID]; ok {
		return fmt.Errorf("saml: session %q exists", rec.SessionID)
	}
	s.byID[rec.SessionID] = rec
	return nil
}

// Logout marks the session logged out, for good.
func (s *Sessions) Logout(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byID[sessionID]
	if !ok {
		return ErrNoSession
	}
	rec.LoggedOut = true
	s.byID[sessionID] = rec
	return nil
}

// Session returns the record of sessionID.
func (s *Sessions) Session(ctx context.Context, sessionID string) (SPSession, error) {
	if err := ctx.Err(); err != nil {
		return SPSession{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byID[sessionID]
	if !ok {
		return SPSession{}, ErrNoSession
	}
	return rec, nil
}

// Grants is an in-memory [TaskBroker]. The broker writes a grant with Put
// when an authenticated portal action creates it (SB-8) and revokes it with
// Revoke. It is safe for concurrent use.
type Grants struct {
	source string
	mu     sync.RWMutex
	byTask map[string]TaskGrant
}

// NewGrants returns an empty store whose source id is sourceID.
func NewGrants(sourceID string) *Grants {
	return &Grants{source: sourceID, byTask: map[string]TaskGrant{}}
}

// SourceID returns the source id of the store.
func (g *Grants) SourceID() string { return g.source }

// Put adds a grant. A grant without a task, a session, a user, an agent or an
// end, and a second grant for the same task, are refused: changing a term is
// a new grant (SB-9).
func (g *Grants) Put(rec TaskGrant) error {
	if rec.TaskID == "" || rec.SessionID == "" || rec.User == "" || rec.AgentID == "" || rec.ExpiresAt.IsZero() {
		return errors.New("saml: a grant needs a task, a session, a user, an agent and an end")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.byTask[rec.TaskID]; ok {
		return fmt.Errorf("saml: a grant for task %q exists", rec.TaskID)
	}
	g.byTask[rec.TaskID] = rec
	return nil
}

// Revoke revokes the grant of taskID, for good.
func (g *Grants) Revoke(taskID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.byTask[taskID]
	if !ok {
		return ErrNoGrant
	}
	rec.Revoked = true
	g.byTask[taskID] = rec
	return nil
}

// Grant returns the grant of taskID.
func (g *Grants) Grant(ctx context.Context, taskID string) (TaskGrant, error) {
	if err := ctx.Err(); err != nil {
		return TaskGrant{}, err
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	rec, ok := g.byTask[taskID]
	if !ok {
		return TaskGrant{}, ErrNoGrant
	}
	return rec, nil
}
