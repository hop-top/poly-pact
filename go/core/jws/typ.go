package jws

// The algorithms of the profile (draft 7.2). AlgES256 is the only alg the
// baseline accepts; AlgEd25519, the fully specified identifier of RFC 9864
// section 2.2, is accepted only where it is negotiated (see Algorithms).
// The ambiguous EdDSA identifier is never accepted.
const (
	AlgES256   = "ES256"
	AlgEd25519 = "Ed25519"
)

// Role is the signer role a typ requires, after the "Required signer" column
// of the draft 7.3 table. Which keys a deployment trusts for a role is
// configuration: see KeyResolver.
type Role string

// Signer roles.
const (
	// RoleRequirementPublisher: a gateway-authorized requirement publisher.
	RoleRequirementPublisher Role = "requirement-publisher"
	// RoleIssuer: an evidence issuer authorized for its claim paths and scope.
	RoleIssuer Role = "issuer"
	// RoleHolder: the enrolled agent holder key. The only role whose key comes
	// from the artifact (an embedded jwk matching holder_jkt) instead of a
	// trusted key set.
	RoleHolder Role = "holder"
	// RoleValidator: a gateway-authorized validator.
	RoleValidator Role = "validator"
	// RoleReporter: a reporter authorized for the observation type.
	RoleReporter Role = "reporter"
	// RoleReputationService: an authorized reputation service.
	RoleReputationService Role = "reputation-service"
	// RolePolicyAuthority: a native administrator or delegated policy
	// authority.
	RolePolicyAuthority Role = "policy-authority"
	// RoleLearningController: a learning controller, authorized for the
	// manifest or for the lifecycle transition.
	RoleLearningController Role = "learning-controller"
)

// The JWS typ values of the draft 7.3 table.
const (
	TypRequirements     = "pact-requirements+jwt"
	TypEvidence         = "pact-evidence+jwt"
	TypPresentation     = "pact-presentation+jwt"
	TypAdmission        = "pact-admission+jwt"
	TypOutcome          = "pact-outcome+jwt"
	TypReputation       = "pact-reputation+jwt"
	TypLearningPolicy   = "pact-learning-policy+jwt"
	TypLearningArtifact = "pact-learning-artifact+jwt"
	TypLearningEvent    = "pact-learning-event+jwt"
)

// typTable is the draft 7.3 table, in its order.
var typTable = []struct {
	typ  string
	role Role
}{
	{TypRequirements, RoleRequirementPublisher},
	{TypEvidence, RoleIssuer},
	{TypPresentation, RoleHolder},
	{TypAdmission, RoleValidator},
	{TypOutcome, RoleReporter},
	{TypReputation, RoleReputationService},
	{TypLearningPolicy, RolePolicyAuthority},
	{TypLearningArtifact, RoleLearningController},
	{TypLearningEvent, RoleLearningController},
}

// TypRole returns the signer role the draft 7.3 table requires for typ. typ
// is compared exactly: case and an "application/" prefix matter.
func TypRole(typ string) (Role, bool) {
	for _, row := range typTable {
		if row.typ == typ {
			return row.role, true
		}
	}
	return "", false
}

// Typs returns the typ values of the draft 7.3 table, in its order.
func Typs() []string {
	out := make([]string, len(typTable))
	for i, row := range typTable {
		out[i] = row.typ
	}
	return out
}
