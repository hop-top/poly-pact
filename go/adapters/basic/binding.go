package basic

import (
	"context"
	"fmt"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapter/enroll"
)

// ResolveAgentBinding returns the enrolled binding of agent to the
// authenticated account in realm, from the enrollment registry through
// [enroll.Resolver].
//
// The account alone never names an agent: the agent ID the request names
// selects among the enrollments of the account, and the holder-key proof then
// binds the request to it (draft 6.2, 17.1). The profile does not support
// accounts shared by several agents, so an account with more than one
// enrollment in force is the registry's configuration error, an error that
// wraps [adapter.ErrUnsupportedRequirement], for whichever agent (identity
// mapping IM-19). A revoked or compromised binding comes back as that status,
// never as active. A registry that cannot answer, a status that is not
// defined, and a time later than now plus the skew are
// [adapter.ErrDependencyUnavailable].
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	b, err := enroll.Resolver{Registry: a.cfg.Registry}.ResolveAgentBinding(ctx, realm, workload, agent)
	if err != nil {
		return adapter.AgentBinding{}, dependency("resolve binding", err)
	}
	if !b.Status.Valid() {
		return adapter.AgentBinding{}, fmt.Errorf("basic: resolve binding: the registry reports status %q: %w", b.Status, adapter.ErrDependencyUnavailable)
	}
	if err := a.checkSourceTimes("resolve binding", b.ObservedAt, b.StatusCheckedAt); err != nil {
		return adapter.AgentBinding{}, err
	}
	if b.Status != adapter.BindingUnknown {
		b.EnrolledElsewhere = false
	}
	return b, nil
}
