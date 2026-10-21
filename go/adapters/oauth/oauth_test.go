package oauth_test

import (
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
)

// replaced are the common authenticate_native cases whose expected principal
// a bearer token of this profile cannot yield, each with the OAuth case that
// shows the same property (profile section 10, "Replaced common cases").
var replaced = map[string]adaptertest.Replacement{
	"COMMON-01.credential-wins": {
		By:     "OAUTH-01.identity-headers",
		Reason: "expects https://idp.acme.example/bob; OAUTH-37 derives oauth:{issuer-id}:{tenant}:{subject} from the token",
	},
	"COMMON-02.via-enforcement-point": {
		By:     "OAUTH-26.via-enforcement-point",
		Reason: "expects https://idp.acme.example/alice; the principal is the oauth: identifier of OAUTH-37",
	},
	"COMMON-09.authenticate-realm": {
		By:     "OAUTH-29.gateway-realm",
		Reason: "expects a globex principal on a gateway of realm acme; the realm is the gateway's configuration, never a token value",
	},
	"IDENT-01.authenticate": {
		By:     "OAUTH-29.other-user",
		Reason: "expects a basic: account identifier; a token names an oauth: subject",
	},
	"IDENT-02.authenticate": {
		By:     "OAUTH-29.other-tenant-entry",
		Reason: "two tenants on one route; OAUTH-6 serves a route from one issuer entry, which pins one tenant (OAUTH-26)",
	},
	"IDENT-05.authenticate": {
		By:     "OAUTH-18.display-claims",
		Reason: "expects a basic: account identifier; the display-name property is shown with preferred_username, upn, email and name (OAUTH-33)",
	},
}

// TestConformance runs the conformance suite, the common cases and the OAuth
// cases of spec/v1.0/fixtures/adapters/oauth, with the six replaced common cases
// declared. The OAuth profile does not support clients shared by several
// agents, so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, oauthFactory, adaptertest.Options{Adapter: "oauth", Replaced: replaced})
}
