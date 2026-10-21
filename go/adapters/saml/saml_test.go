package saml_test

import (
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
)

// replaced are the common authenticate_native cases whose expected principal
// a SAML session broker cannot produce, each with the SAML case that shows the
// same property (profile section 10, "Replaced common cases"). The principal
// of this adapter is the saml identifier of the session that the grant of the
// request's task records (SB-4, SB-16); a common request names no task.
var replaced = map[string]adaptertest.Replacement{
	"COMMON-01.credential-wins": {
		By:     "SAML-03.identity-headers",
		Reason: "expects https://idp.acme.example/bob from a bearer credential; the principal is the session principal of the task's grant (SB-16), and a common request names no task",
	},
	"COMMON-02.via-enforcement-point": {
		By:     "SAML-17.via-enforcement-point",
		Reason: "expects https://idp.acme.example/alice; the principal is a saml identifier of the grant's session (SB-4, SB-16)",
	},
	"COMMON-09.authenticate-realm": {
		By:     "SAML-17.idp-realm",
		Reason: "expects a globex principal id; a same-spelled subject is kept apart by its identity provider component (SB-4, IM-4)",
	},
	"IDENT-01.authenticate": {
		By:     "SAML-17.other-user",
		Reason: "expects a basic: account identifier; another user is the principal of another session, reached through that user's grant (SB-16)",
	},
	"IDENT-02.authenticate": {
		By:     "SAML-17.idp-realm",
		Reason: "expects an oauth: identifier of another tenant; under SAML the issuing authority is the idp-entity-id component (SB-4)",
	},
	"IDENT-03.authenticate": {
		By:     "SAML-17.via-enforcement-point",
		Reason: "splits user and OAuth client; here the principal is the session user and the workload the agent's own broker credential, two identifiers of two namespaces (SB-4, SB-15), and a grant is served only to its grantee (SB-16, SAML-07.other-agent)",
	},
	"IDENT-05.authenticate": {
		By:     "SAML-17.other-user",
		Reason: "expects a basic: account identifier; an SPSession carries no display name and the subject is never one (SB-4)",
	},
}

// TestConformance runs the conformance suite, the common cases and the SAML
// cases of spec/v1.0/fixtures/adapters/saml, with the replaced common cases
// declared. The profile does not support workloads shared by several agents,
// so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, samlFactory, adaptertest.Options{Adapter: "saml", Replaced: replaced})
}
