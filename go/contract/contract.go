package contract

import (
	"fmt"
	"slices"

	"hop.top/pact-go/adapter"
	"hop.top/pact-go/core"
)

// SelectionConsistencyCheck is the baseline check a contract lists in
// context_checks when its selected_set is not the policy's conservative set
// (draft 9.3, 9.4 (a)).
const SelectionConsistencyCheck = "selection-consistency-v1"

// Policy is the active policy version a contract pins (draft 9.4): the base
// revision of the learning-policy epoch, the active learning policy and the
// selector artifact. Changing any of them invalidates outstanding contracts.
type Policy struct {
	BaseRevision           string
	LearningPolicyDigest   core.Digest
	LearningArtifactDigest core.Digest
}

// Requirements is the effective requirement set a gateway selected for one
// request (draft 9.4). The publisher signs it complete, never by name.
type Requirements struct {
	// Policy is the active policy the set was selected under.
	Policy Policy
	// SelectedSet names the selected set and ConservativeSet the policy's
	// conservative set (Appendix B.9). When they differ, ContextChecks must
	// list [SelectionConsistencyCheck] (draft 9.4 (a)).
	SelectedSet     string
	ConservativeSet string
	// FieldRules and ContextChecks are the complete effective requirements.
	FieldRules    []core.FieldRule
	ContextChecks []string
	// Mode is enforced or observe.
	Mode core.Mode
	// Extensions are the contract extensions the gateway binds, such as its
	// transport profile (draft 13.3.1); nil for none.
	Extensions core.Object
	// Thresholds are the reputation thresholds the selector relied on to
	// select SelectedSet. When SelectedSet is not ConservativeSet, each must
	// be expressed by a field rule of FieldRules in the canonical form of
	// draft 9.4 (b); nil for none.
	Thresholds []ThresholdRule
}

// ThresholdRule is one reputation threshold a selector relied on (draft
// 9.4 (b)): either a minimum on a dimension statistic or a required
// security status, never both.
type ThresholdRule struct {
	// Dimension and Statistic name the statistic of a minimum, such as
	// reliability and score_bps: the rule's path is
	// /attributes/reputation/dimensions/<Dimension>/<Statistic> and its
	// schema's minimum is Minimum.
	Dimension string
	Statistic string
	Minimum   int64
	// SecurityStatus, when not empty, is a required security status: the
	// rule's path is /attributes/reputation/security_status and its
	// schema's const is SecurityStatus.
	SecurityStatus core.SecurityStatus
}

// Contract is a signed requirement contract, as issued or as verified.
type Contract struct {
	// Compact is the compact JWS, exactly as signed or received.
	Compact string
	// Claims is its decoded payload.
	Claims core.RequirementContract
	// Digest is requirements_digest: the artifact_digest of Compact
	// (draft 7.4, Appendix A.2).
	Digest core.Digest
}

// Expect is the context a contract must name (draft 11.3 step 3).
type Expect struct {
	// AgentID is the agent the presentation names, the contract's sub.
	AgentID string
	// Audience is the gateway's identifier, the contract's aud.
	Audience string
	// Realm is the gateway's tenant and environment.
	Realm adapter.Realm
	// SupportedExtensions lists the contract extensions the gateway
	// supports; any other is unsupported (draft 7.1).
	SupportedExtensions []string
}

// NonceRecord binds a contract nonce to the agent, holder key, realm,
// operation digest and requirement contract digest (draft 7.5).
type NonceRecord struct {
	Nonce              string
	AgentID            string
	HolderJKT          core.Digest
	Realm              adapter.Realm
	OperationDigest    core.Digest
	RequirementsDigest core.Digest
}

// NonceRecord returns the nonce record of c.
func (c Contract) NonceRecord() NonceRecord {
	return NonceRecord{
		Nonce:              c.Claims.Nonce,
		AgentID:            c.Claims.Subject,
		HolderJKT:          c.Claims.HolderJKT,
		Realm:              adapter.Realm{TenantID: c.Claims.TenantID, EnvironmentID: c.Claims.EnvironmentID},
		OperationDigest:    c.Claims.OperationDigest,
		RequirementsDigest: c.Digest,
	}
}

// Check is the contract-validity check of draft 11.3 step 3: sub, aud,
// tenant_id and environment_id equal e (ErrContextMismatch), then every
// contract extension is one of e.SupportedExtensions
// (ErrUnsupportedRequirement). An empty field of e matches nothing.
func (c Contract) Check(e Expect) error {
	for _, m := range []struct{ name, got, want string }{
		{"sub", c.Claims.Subject, e.AgentID},
		{"aud", c.Claims.Audience, e.Audience},
		{"tenant_id", c.Claims.TenantID, e.Realm.TenantID},
		{"environment_id", c.Claims.EnvironmentID, e.Realm.EnvironmentID},
	} {
		if m.want == "" || m.got != m.want {
			return fmt.Errorf("%w: %s %q, expected %q", ErrContextMismatch, m.name, m.got, m.want)
		}
	}
	names := make([]string, 0, len(c.Claims.Extensions))
	for name := range c.Claims.Extensions {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if !slices.Contains(e.SupportedExtensions, name) {
			return fmt.Errorf("%w: extension %q", ErrUnsupportedRequirement, name)
		}
	}
	return nil
}

// CheckActive is the active-policy check of draft 11.3 step 3 and 12.2: the
// contract's base_revision, learning_policy_digest and
// learning_artifact_digest equal p, or the contract is no longer active
// (ErrRequirementsChanged).
func (c Contract) CheckActive(p Policy) error {
	for _, m := range []struct{ name, got, want string }{
		{"base_revision", c.Claims.BaseRevision, p.BaseRevision},
		{"learning_policy_digest", string(c.Claims.LearningPolicyDigest), string(p.LearningPolicyDigest)},
		{"learning_artifact_digest", string(c.Claims.LearningArtifactDigest), string(p.LearningArtifactDigest)},
	} {
		if m.want == "" || m.got != m.want {
			return fmt.Errorf("%w: %s %q, active %q", ErrRequirementsChanged, m.name, m.got, m.want)
		}
	}
	return nil
}
