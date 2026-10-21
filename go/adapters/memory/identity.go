package memory

import (
	"context"
	"fmt"
	"maps"
	"net/http"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// AuthenticateNative authenticates r against the identity store.
//
// The credential is the bearer token of the Authorization header and nothing
// else: a header such as X-User or X-Forwarded-User, which any client can send,
// names no one (draft 8.5). A request that did not pass through the
// enforcement point is refused whatever it carries.
func (a *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if err := a.live(ctx, "authenticate"); err != nil {
		return adapter.Principal{}, err
	}
	token, presented := bearer(r)
	if !presented {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialNoCredential}
	}
	if !Arrived(r) {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	id, ok := a.identityBySecret(token)
	if !ok {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	return adapter.Principal{
		ID:              id.ID,
		Realm:           adapter.Realm{TenantID: id.Realm.TenantID, EnvironmentID: id.Realm.EnvironmentID},
		Workload:        adapter.Workload(id.Workload),
		Mechanism:       "bearer",
		AuthenticatedAt: a.clk.Now(),
		Attributes:      maps.Clone(id.Attributes),
	}, nil
}

// ResolveAgentBinding returns the enrolled binding of agent to workload in
// realm.
//
// The records are selected by realm, workload and agent ID together: the agent
// ID selects among the records of the workload only, so a record of the agent
// on another workload, or in another realm, is never the answer, and neither
// is a record of another agent of a workload that several agents share. An
// agent with no such record has status UNKNOWN; the workload alone names no
// agent. When the source holds several records of the agent on the workload,
// [current] picks the answer. A binding the source holds as revoked or
// compromised is returned as that status, with the agent, operator and holder
// key of the record and no error, so that the caller can state the reason
// (identity mapping IM-11, IM-29); it is never reported as active.
//
// Unless the adapter was built [WithSharedWorkloads], a workload serves one
// agent, and a workload with more than one enrollment in force in the realm is
// a configuration error: whichever agent ID the request names, the call
// returns no binding and an error that wraps [adapter.ErrUnsupportedRequirement]
// (draft 17.1, identity mapping IM-19). A record is in force unless it is
// REVOKED, as for [current]; a COMPROMISED record counts. Counting needs every
// record of the workload, so a record of the workload whose source cannot
// answer fails the call as a source that cannot answer.
//
// An UNKNOWN answer reports, in EnrolledElsewhere, whether the agent has a
// record, in any status, on another workload of the realm (draft 17.1). A
// record in another realm never sets it. A record of the agent on another
// workload whose source cannot answer leaves that report unknown, so the call
// fails as a source that cannot answer.
func (a *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	if err := a.live(ctx, "resolve binding"); err != nil {
		return adapter.AgentBinding{}, err
	}
	if !a.shared {
		if err := a.dedicated(realm, workload); err != nil {
			return adapter.AgentBinding{}, err
		}
	}
	var rows, elsewhere []Enrollment
	for _, e := range a.st.Enrollments {
		if e.Realm.TenantID != realm.TenantID || e.Realm.EnvironmentID != realm.EnvironmentID || e.AgentID != string(agent) {
			continue
		}
		if e.Workload != string(workload) {
			elsewhere = append(elsewhere, e)
			continue
		}
		if a.unavailable(e.SourceID) {
			return adapter.AgentBinding{}, outage("resolve binding", e.SourceID)
		}
		rows = append(rows, e)
	}
	if e, ok := current(rows); ok {
		switch status := adapter.BindingStatus(e.Status); status {
		case adapter.BindingActive, adapter.BindingRevoked, adapter.BindingCompromised:
			observed, checked := sourceTime(e.ObservedAt), sourceTime(e.StatusCheckedAt)
			if err := a.checkSourceTimes(observed, checked); err != nil {
				return adapter.AgentBinding{}, err
			}
			return adapter.AgentBinding{
				AgentID:         e.AgentID,
				OperatorID:      e.OperatorID,
				HolderJKT:       core.Digest(e.HolderJKT),
				Status:          status,
				ObservedAt:      observed,
				StatusCheckedAt: checked,
				SourceID:        e.SourceID,
				SourceRef:       e.SourceRef,
			}, nil
		}
	}
	for _, e := range elsewhere {
		if a.unavailable(e.SourceID) {
			return adapter.AgentBinding{}, outage("resolve binding", e.SourceID)
		}
	}
	return adapter.AgentBinding{Status: adapter.BindingUnknown, EnrolledElsewhere: len(elsewhere) > 0}, nil
}

// dedicated fails when workload has more than one enrollment in force in realm:
// the configuration error of a workload that serves one agent (identity
// mapping IM-19).
func (a *Adapter) dedicated(realm adapter.Realm, workload adapter.Workload) error {
	inForce := 0
	for _, e := range a.st.Enrollments {
		if e.Realm.TenantID != realm.TenantID || e.Realm.EnvironmentID != realm.EnvironmentID || e.Workload != string(workload) {
			continue
		}
		if a.unavailable(e.SourceID) {
			return outage("resolve binding", e.SourceID)
		}
		if adapter.BindingStatus(e.Status) != adapter.BindingRevoked {
			inForce++
		}
	}
	if inForce > 1 {
		return fmt.Errorf("memory: resolve binding: workload %q has %d enrollments in force and serves one agent, a configuration error for the administrators of the enrollment source: %w",
			workload, inForce, adapter.ErrUnsupportedRequirement)
	}
	return nil
}

// current returns the enrollment that answers for an agent on a workload,
// given all the records of that agent on that workload in the realm, and false
// when none does.
//
// One record in force, one that is not REVOKED, is the answer. A COMPROMISED
// record stays in force, so that a compromise is never hidden behind another
// record of the agent. When no record is in force, a single revoked record is
// the answer. Several records, in force or revoked, answer nothing, never the
// first or the most recent (identity mapping IM-18).
func current(rows []Enrollment) (Enrollment, bool) {
	inForce := make([]Enrollment, 0, len(rows))
	for _, e := range rows {
		if adapter.BindingStatus(e.Status) != adapter.BindingRevoked {
			inForce = append(inForce, e)
		}
	}
	if len(inForce) == 0 {
		inForce = rows
	}
	if len(inForce) != 1 {
		return Enrollment{}, false
	}
	return inForce[0], true
}
