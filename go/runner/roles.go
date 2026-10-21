package runner

import (
	"slices"
	"strings"

	"hop.top/pact-go/runner/manifest"
)

// conformanceRoles are the conformance roles of the table of draft Section
// 22.1, in its order and with its names.
var conformanceRoles = []string{"Holder", "Gateway", "Validator", "Reputation", "Learning"}

// omittedRoles holds the omitted_roles of the ConformanceDeclaration of each
// conformance profile, the payload of pact-conformance-profile-v1 defined by
// $defs.ConformanceDeclaration of spec/v1.0/schemas/pact.schema.json. Draft
// Section 22.1 permits a declared profile to omit only the Reputation or the
// Learning role, and the schema accordingly limits omitted_roles to
// reputation and learning, and to no item for full. The registry entries of
// kind conformance carry no machine-readable declaration, so this table
// records it: full omits none, single-owner omits reputation and learning.
var omittedRoles = map[string][]string{
	manifest.ConformanceProfileFull:        {},
	manifest.ConformanceProfileSingleOwner: {"reputation", "learning"},
}

// ConformanceRoles returns the conformance roles of draft Section 22.1, in
// the order of its table.
func ConformanceRoles() []string { return slices.Clone(conformanceRoles) }

// RolesClaimed returns the conformance roles that a deployment of the
// conformance profile claims: the roles of draft Section 22.1, in their
// order, minus the omitted_roles of the profile's ConformanceDeclaration. It
// returns nil for an id that is not a conformance profile.
func RolesClaimed(profile string) []string {
	omitted, ok := omittedRoles[profile]
	if !ok {
		return nil
	}
	var out []string
	for _, r := range conformanceRoles {
		if !slices.Contains(omitted, strings.ToLower(r)) {
			out = append(out, r)
		}
	}
	return out
}
