# The illustrative rule of integration example I11 as an OPA policy for the
# decision document of profiles/abac (ABAC-11, ABAC-15, ABAC-20). It is test
# data: a fictional native policy, not a PACT policy language. Loaded by the
# integration tier of the abac adapter cases; the path of the decision is
# /v1/data/pact/abac/decision.
#
# The document pact.abac.decision is an object with exactly allow,
# obligations and policy_version. Every input that the rule does not allow
# gets the default decision, a denial with no obligations.
package pact.abac

# policy_version is the label of this policy (ABAC-16).
policy_version := "abac-2026-10-01"

# chain is the clearance order, lowest first (ABAC-11).
chain := ["public", "internal", "confidential", "restricted"]

# rank is the position of a level in the chain; a name outside the chain has
# no rank, so every comparison with it is undefined and the rule does not
# allow.
rank(level) := i if {
	some i
	chain[i] == level
}

default decision := {"allow": false, "obligations": [], "policy_version": "abac-2026-10-01"}

decision := {"allow": true, "obligations": obligations, "policy_version": policy_version} if {
	input.action.id == "document.read"
	input.subject.department == input.resource.owning_department
	rank(input.subject.clearance) >= rank(input.resource.classification)
	input.environment.device.compliant == true
	input.environment.network_zone == "corporate"
}

# A document classified confidential or above is released filtered and
# watermarked; a lower one with no obligation.
default obligations := []

obligations := [
	{"type": "filter_fields", "params": {"keep": ["/title", "/supplier", "/terms"]}},
	{"type": "watermark", "params": {"label": "supplier-review"}},
] if rank(input.resource.classification) >= rank("confidential")
