package broken

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/adapters/memory"
	"hop.top/pact-go/core"
)

// principalOf builds the principal of a stored identity.
func (b *Adapter) principalOf(i memory.Identity) adapter.Principal {
	return adapter.Principal{
		ID:              i.ID,
		Realm:           adapter.Realm{TenantID: i.Realm.TenantID, EnvironmentID: i.Realm.EnvironmentID},
		Workload:        adapter.Workload(i.Workload),
		Mechanism:       "bearer",
		AuthenticatedAt: b.now(),
	}
}

// identityFromHeaders finds the stored identity that a client-supplied
// identity header names, by id, by local name, or by certificate subject.
func (b *Adapter) identityFromHeaders(r *http.Request) (memory.Identity, bool) {
	for _, name := range []string{"X-User", "X-Principal", "X-Forwarded-User", "X-Client-Cert", "X-Acme-Identity"} {
		v := r.Header.Get(name)
		if v == "" {
			continue
		}
		v = strings.TrimPrefix(strings.SplitN(v, ",", 2)[0], "CN=")
		for _, i := range b.State().Identities {
			if i.ID == v || path.Base(i.ID) == v {
				return i, true
			}
		}
	}
	return memory.Identity{}, false
}

// AuthenticateNative is the memory adapter's, with the authentication defects.
func (b *Adapter) AuthenticateNative(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	p, err := b.authenticate(ctx, r)
	if b.on[LeakTokenInDenial] && err != nil {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		return adapter.Principal{}, fmt.Errorf("authentication failed for token %s (cookie %s): %w", token, r.Header.Get("Cookie"), err)
	}
	return p, err
}

func (b *Adapter) authenticate(ctx context.Context, r *http.Request) (adapter.Principal, error) {
	if b.on[RejectEnforcementPoint] && memory.Arrived(r) {
		return adapter.Principal{}, &adapter.NativeDenial{Reason: adapter.DenialCredentialRejected}
	}
	if b.on[AcceptBypass] {
		r = memory.Arrive(r)
	}
	p, err := b.Adapter.AuthenticateNative(ctx, r)

	var denial *adapter.NativeDenial
	if b.on[TrustHeaderIdentity] && errors.As(err, &denial) && denial.Reason == adapter.DenialNoCredential {
		if id, ok := b.identityFromHeaders(r); ok {
			return b.principalOf(id), nil
		}
	}
	if b.on[HeaderOverridesCredential] && err == nil {
		if id, ok := b.identityFromHeaders(r); ok {
			return b.principalOf(id), nil
		}
	}
	if b.on[ConflateIssuers] && err == nil {
		local := path.Base(p.ID)
		for _, i := range b.State().Identities {
			if path.Base(i.ID) == local {
				return b.principalOf(i), nil
			}
		}
	}
	if err == nil {
		p = b.misattribute(p)
	}
	return p, err
}

// misattribute applies the defects that give an authenticated principal the
// identity or the workload of someone else.
func (b *Adapter) misattribute(p adapter.Principal) adapter.Principal {
	ids := b.State().Identities
	if b.on[ConflateTenants] {
		for _, i := range ids {
			if lastComponent(i.ID) == lastComponent(p.ID) {
				return b.principalOf(i)
			}
		}
	}
	if name, ok := p.Attributes["display_name"].(string); ok && b.on[IdentityByDisplayName] {
		for _, i := range ids {
			if other, _ := i.Attributes["display_name"].(string); other == name {
				return b.principalOf(i)
			}
		}
	}
	if b.on[UserWorkload] {
		for _, i := range ids {
			if i.ID == p.ID {
				p.Workload = adapter.Workload(i.Workload)
				break
			}
		}
	}
	if b.on[RealmWorkload] {
		for _, e := range b.State().Enrollments {
			if sameRealm(e.Realm, p.Realm) {
				p.Workload = adapter.Workload(e.Workload)
				break
			}
		}
	}
	return p
}

// lastComponent returns what follows the last colon of a namespaced
// identifier, or the whole identifier when it has none.
func lastComponent(id string) string {
	return id[strings.LastIndexByte(id, ':')+1:]
}

// dropLast returns the identifier without its last component, or "" when it
// has a single one.
func dropLast(id string) string {
	i := strings.LastIndexByte(id, ':')
	if i < 0 {
		return ""
	}
	return id[:i]
}

// enrollmentOf finds the enrollment of agent on workload in realm, whatever its
// status.
func (b *Adapter) enrollmentOf(realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (memory.Enrollment, bool) {
	for _, e := range b.recordsOf(realm, workload) {
		if e.AgentID == string(agent) {
			return e, true
		}
	}
	return memory.Enrollment{}, false
}

// recordsOf returns the enrollments of workload in realm, of every agent.
func (b *Adapter) recordsOf(realm adapter.Realm, workload adapter.Workload) []memory.Enrollment {
	var rows []memory.Enrollment
	for _, e := range b.State().Enrollments {
		if sameRealm(e.Realm, realm) && e.Workload == string(workload) {
			rows = append(rows, e)
		}
	}
	return rows
}

// activeOf returns the binding an enrollment would have if it were active.
func (b *Adapter) activeOf(e memory.Enrollment) adapter.AgentBinding {
	return adapter.AgentBinding{
		AgentID:         e.AgentID,
		OperatorID:      e.OperatorID,
		HolderJKT:       core.Digest(e.HolderJKT),
		Status:          adapter.BindingActive,
		ObservedAt:      b.now(),
		StatusCheckedAt: b.now(),
		SourceID:        e.SourceID,
		SourceRef:       e.SourceRef,
	}
}

// ResolveAgentBinding is the memory adapter's, with the binding defects. The
// defects of the lookup choose the realm, the workload and the agent that the
// memory adapter resolves; the defects of the result then change its answer.
func (b *Adapter) ResolveAgentBinding(ctx context.Context, realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) (adapter.AgentBinding, error) {
	// RevokedCountsAsInForce miscounts for the rule of a dedicated workload;
	// SelectDespiteDedicated does not apply that rule at all.
	if b.on[RevokedCountsAsInForce] && !b.shared && !b.on[SelectDespiteDedicated] && len(b.recordsOf(realm, workload)) > 1 {
		return adapter.AgentBinding{}, fmt.Errorf("broken: workload %q has more than one enrollment: %w", workload, adapter.ErrUnsupportedRequirement)
	}
	lookup := realm
	if b.on[ConflateBindingRealms] {
		for _, e := range b.State().Enrollments {
			if e.Workload == string(workload) {
				lookup = adapter.Realm{TenantID: e.Realm.TenantID, EnvironmentID: e.Realm.EnvironmentID}
				break
			}
		}
	}
	asked, askedAgent := workload, agent
	workload = b.looseWorkload(lookup, workload)
	workload = b.crossWorkload(lookup, workload, agent)
	agent = b.selectAgent(lookup, workload, agent)
	got, err := b.Adapter.ResolveAgentBinding(ctx, lookup, workload, agent)
	if err != nil {
		return got, err
	}

	if got.Status == adapter.BindingRevoked || got.Status == adapter.BindingCompromised {
		if e, ok := b.enrollmentOf(lookup, workload, agent); ok {
			compromised := got.Status == adapter.BindingCompromised
			k := b.credentialKey(lookup, workload)
			if (b.on[ReviveRevokedBinding] && !compromised) ||
				(b.on[ReviveCompromisedBinding] && compromised) ||
				(b.on[RecoverByOldKey] && compromised && k != "" && k == e.HolderJKT) {
				return b.activeOf(e), nil
			}
			if b.on[CacheBindingForContract] && b.revokedWithinContract(e) {
				return b.activeOf(e), nil
			}
		}
		if b.on[UnusableAsError] {
			return adapter.AgentBinding{}, fmt.Errorf("broken: the enrolled binding is not in force: %w", adapter.ErrInvalidProof)
		}
		if b.on[StatusWithoutRecord] {
			return adapter.AgentBinding{Status: got.Status, ObservedAt: got.ObservedAt, StatusCheckedAt: got.StatusCheckedAt,
				SourceID: got.SourceID, SourceRef: got.SourceRef}, nil
		}
		return got, nil
	}
	if k := b.credentialKey(lookup, workload); b.on[HolderKeyFromCredential] && k != "" && got.Status == adapter.BindingActive {
		got.HolderJKT = core.Digest(k)
	}
	// Only the caller's own realm, workload and agent lose their binding; a
	// binding found through the defects of the lookup is a different defect.
	if b.on[LoseActiveBinding] && got.Status == adapter.BindingActive && lookup == realm && workload == asked && agent == askedAgent {
		return adapter.AgentBinding{Status: adapter.BindingUnknown}, nil
	}
	if b.on[TrustUnenrolled] && got.Status == adapter.BindingUnknown {
		return adapter.AgentBinding{
			AgentID:         "urn:workload:" + string(workload),
			HolderJKT:       "xx0BcA-wMohw8atYDJOe6peGModklG2wRHBlXHMvl0M",
			Status:          adapter.BindingActive,
			ObservedAt:      b.now(),
			StatusCheckedAt: b.now(),
			SourceID:        "synthetic",
		}, nil
	}
	if got.Status == adapter.BindingUnknown {
		got.EnrolledElsewhere = b.elsewhere(lookup, agent, got.EnrolledElsewhere)
	}
	return got, nil
}

// elsewhere applies the defects that misreport whether the agent ID is
// enrolled for another workload of the realm, given the memory adapter's
// report. Only an UNKNOWN answer carries the report, defects or not.
func (b *Adapter) elsewhere(realm adapter.Realm, agent adapter.AgentID, reported bool) bool {
	if b.on[NeverSetElsewhere] {
		return false
	}
	if b.on[ElsewhereAcrossRealms] {
		for _, e := range b.State().Enrollments {
			if e.AgentID == string(agent) && !sameRealm(e.Realm, realm) {
				return true
			}
		}
	}
	return reported
}

// looseWorkload applies the defects that match a workload with no enrollment
// to an enrolled one by a comparison looser than octet equality.
func (b *Adapter) looseWorkload(realm adapter.Realm, workload adapter.Workload) adapter.Workload {
	if len(b.recordsOf(realm, workload)) > 0 {
		return workload
	}
	w := string(workload)
	for _, e := range b.State().Enrollments {
		if !sameRealm(e.Realm, realm) {
			continue
		}
		if b.on[BindingByRealm] ||
			(b.on[MatchLocalPart] && lastComponent(e.Workload) == lastComponent(w)) ||
			(b.on[DropLastComponent] && dropLast(w) != "" && dropLast(e.Workload) == dropLast(w)) {
			return adapter.Workload(e.Workload)
		}
	}
	return workload
}

// crossWorkload applies CrossWorkloadAgent: an agent with no record on the
// workload is looked up on the first other workload of the realm that enrolls
// it.
func (b *Adapter) crossWorkload(realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) adapter.Workload {
	if !b.on[CrossWorkloadAgent] {
		return workload
	}
	if _, ok := b.enrollmentOf(realm, workload, agent); ok {
		return workload
	}
	for _, e := range b.State().Enrollments {
		if sameRealm(e.Realm, realm) && e.AgentID == string(agent) {
			return adapter.Workload(e.Workload)
		}
	}
	return workload
}

// selectAgent applies the defects that resolve a workload without the agent ID
// the request names: they return the agent they resolve instead, and "" for
// none, which no record names.
func (b *Adapter) selectAgent(realm adapter.Realm, workload adapter.Workload, agent adapter.AgentID) adapter.AgentID {
	rows := b.recordsOf(realm, workload)
	if b.on[IgnoreAgentID] {
		agent = soleInForce(rows)
	}
	if len(rows) < 2 {
		return agent
	}
	switch {
	case b.on[FirstOfShared]:
		return adapter.AgentID(rows[0].AgentID)
	case b.on[RevokedInForce]:
		// Every record counts as in force, so two or more name no agent.
		return ""
	case b.on[CompromisedNotInForce]:
		var kept []memory.Enrollment
		for _, e := range rows {
			if e.Status != string(adapter.BindingCompromised) {
				kept = append(kept, e)
			}
		}
		if len(kept) == 1 {
			return adapter.AgentID(kept[0].AgentID)
		}
	}
	return agent
}

// soleInForce is the rule of the memory adapter applied to every record of a
// workload instead of the records of one agent: the agent of the single record
// in force, or of the single revoked record when none is in force, and ""
// otherwise.
func soleInForce(rows []memory.Enrollment) adapter.AgentID {
	var inForce []memory.Enrollment
	for _, e := range rows {
		if e.Status != string(adapter.BindingRevoked) {
			inForce = append(inForce, e)
		}
	}
	if len(inForce) == 0 {
		inForce = rows
	}
	if len(inForce) != 1 {
		return ""
	}
	return adapter.AgentID(inForce[0].AgentID)
}

// credentialKey returns the thumbprint of the key that the credential of the
// workload's identity is bound to, the jkt member of its cnf attribute, and ""
// when it names none.
func (b *Adapter) credentialKey(realm adapter.Realm, workload adapter.Workload) string {
	for _, i := range b.State().Identities {
		if !sameRealm(i.Realm, realm) || i.Workload != string(workload) {
			continue
		}
		if cnf, ok := i.Attributes["cnf"].(map[string]any); ok {
			if k, ok := cnf["jkt"].(string); ok {
				return k
			}
		}
	}
	return ""
}
