package saml

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
)

// rejected is the one public result of every authentication failure after
// the agent credential (SB-17): it does not tell an unknown task from a grant
// whose session is not live or a grant made for another agent.
func rejected() error { return &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected} }

// AuthenticateNative authenticates an agent request on a broker route.
//
// A request without the enforcement marker is refused before anything is
// read. The agent's own broker credential is then verified by
// [Config.Agents], which gives the agent's workload; its denial is returned
// as it is. The request's task reference is the {task_id} segment of the
// installed route the method and the escaped path match; the grant of that
// task is read from [Config.Grants], and the session the grant records from
// [Config.Sessions], both live. The grant's agent must hold an enrollment in
// force, ACTIVE or COMPROMISED, on the agent's workload in [Config.Registry],
// looked up by realm, workload and the grant's agent ID: the broker serves a
// grant only to the agent it names (SB-16). The principal is that session's
// principal, when the session is live and the grant's user is that principal
// (SB-6, SB-16). No header, query parameter, body, cookie or profile value
// selects the principal or the session. A route with no task reference, a
// task with no grant, a session that does not exist or is not live, a grant
// whose user is not its session's principal, and a grant whose agent has no
// enrollment in force on the workload are the same CREDENTIAL_REJECTED
// (SB-17). A registry error that wraps [adapter.ErrUnsupportedRequirement],
// such as a workload with two enrollments in force, is returned as it is. A
// store or registry that cannot answer, a session principal that is not a
// saml identifier, and an agent workload in the saml namespace are errors
// that wrap [adapter.ErrDependencyUnavailable] (SB-18).
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	if r == nil || r.URL == nil || !Marked(r) {
		return adapter.Principal{}, rejected()
	}
	agent, err := a.cfg.Agents.AuthenticateAgent(ctx, r)
	if err != nil {
		var d *adapter.NativeDenial
		if errors.As(err, &d) {
			return adapter.Principal{}, &adapter.NativeDenial{Reason: d.PublicReason()}
		}
		return adapter.Principal{}, dependency("authenticate", err)
	}
	switch {
	case agent.Workload == "":
		return adapter.Principal{}, fmt.Errorf("saml: authenticate: the agent authentication gives no workload: %w", adapter.ErrDependencyUnavailable)
	case strings.HasPrefix(string(agent.Workload), "saml:"):
		return adapter.Principal{}, fmt.Errorf("saml: authenticate: an agent workload is never a saml identifier: %w", adapter.ErrDependencyUnavailable)
	}
	task, ok := a.taskOf(r.Method, r.URL.EscapedPath())
	if !ok {
		return adapter.Principal{}, rejected()
	}
	g, s, err := a.grantSession(ctx, task)
	switch {
	case errors.Is(err, errNotUsable):
		return adapter.Principal{}, rejected()
	case err != nil:
		return adapter.Principal{}, dependency("authenticate", err)
	}
	b, err := a.cfg.Registry.Lookup(ctx, a.cfg.Realm, agent.Workload, adapter.AgentID(g.AgentID))
	switch {
	case err != nil:
		return adapter.Principal{}, dependency("authenticate", err)
	case b.Status != adapter.BindingActive && b.Status != adapter.BindingCompromised:
		return adapter.Principal{}, rejected()
	}
	return adapter.Principal{
		ID:              s.Principal,
		Realm:           a.cfg.Realm,
		Workload:        agent.Workload,
		Mechanism:       agent.Mechanism,
		AuthenticatedAt: a.now(),
	}, nil
}

// errNotUsable is the answer of grantSession when the task names no grant
// whose live session is its user's.
var errNotUsable = errors.New("saml: no live session for the task")

// grantSession reads the grant of task and the session it records, live, and
// returns them when the session is live and the grant's user is the
// session's principal. Otherwise it returns errNotUsable, or the error of a
// store that could not answer.
func (a *Adapter) grantSession(ctx context.Context, task string) (TaskGrant, SPSession, error) {
	g, err := a.cfg.Grants.Grant(ctx, task)
	switch {
	case errors.Is(err, ErrNoGrant):
		return TaskGrant{}, SPSession{}, errNotUsable
	case err != nil:
		return TaskGrant{}, SPSession{}, err
	case g.TaskID != task:
		return TaskGrant{}, SPSession{}, fmt.Errorf("the grant store answered for task %q with task %q", task, g.TaskID)
	}
	s, err := a.cfg.Sessions.Session(ctx, g.SessionID)
	switch {
	case errors.Is(err, ErrNoSession):
		return TaskGrant{}, SPSession{}, errNotUsable
	case err != nil:
		return TaskGrant{}, SPSession{}, err
	case s.SessionID != g.SessionID:
		return TaskGrant{}, SPSession{}, fmt.Errorf("the session store answered for session %q with session %q", g.SessionID, s.SessionID)
	case !validPrincipal(s.Principal):
		return TaskGrant{}, SPSession{}, errors.New("the session store gives a principal that is not a saml identifier")
	case !s.Live(a.now()) || g.User != s.Principal:
		return TaskGrant{}, SPSession{}, errNotUsable
	}
	return g, s, nil
}

// validPrincipal reports whether p is saml:{sp-id}:{idp-entity-id}:{subject}
// in the grammar of identity mapping section 3.1: three components, each a
// non-empty run of unreserved characters and upper-case percent escapes.
func validPrincipal(p string) bool {
	parts := strings.Split(p, ":")
	if len(parts) != 4 || parts[0] != "saml" {
		return false
	}
	for _, c := range parts[1:] {
		if !validComponent(c) {
			return false
		}
	}
	return true
}

func validComponent(c string) bool {
	if c == "" {
		return false
	}
	for i := 0; i < len(c); i++ {
		if c[i] == '%' {
			if i+2 >= len(c) || !upperHex(c[i+1]) || !upperHex(c[i+2]) {
				return false
			}
			i += 2
			continue
		}
		if !unreserved(c[i : i+1]) {
			return false
		}
	}
	return true
}

func upperHex(b byte) bool { return b >= '0' && b <= '9' || b >= 'A' && b <= 'F' }

// ResolveAgentBinding returns the enrolled binding of agent to the agent's
// broker workload in realm, from the enrollment registry through
// [enroll.Resolver]. The SAML sign-in plays no part (SB-14). The workload
// alone never names an agent; the profile does not support workloads shared
// by several agents, so a workload with more than one enrollment in force is
// the registry's configuration error, an error that wraps
// [adapter.ErrUnsupportedRequirement] (identity mapping IM-19). A revoked or
// compromised binding comes back as that status. A registry that cannot
// answer, a status that is not defined, and a time later than now plus the
// skew are [adapter.ErrDependencyUnavailable].
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Registry}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, dependency("resolve binding", err)
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("saml: resolve binding: the registry reports status %q: %w", b.Status, adapter.ErrDependencyUnavailable)
	}
	if err := sourceTimes(a.now(), b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, fmt.Errorf("saml: resolve binding: %w", err)
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}
