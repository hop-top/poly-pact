package mtls_test

import (
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
)

// replaced are the common authenticate_native cases whose expected principal
// or denial reason a certificate cannot carry, each with the mTLS case that
// shows the same property (profile section 10, "Replaced common cases").
var replaced = map[string]adaptertest.Replacement{
	"COMMON-01.credential-wins": {
		By:     "MTLS-01.direct-listener-header-ignored",
		Reason: "expects https://idp.acme.example/bob with a workload of another form; MTLS-6 derives an mtls: identifier that is also the workload",
	},
	"COMMON-02.via-enforcement-point": {
		By:     "MTLS-11.valid",
		Reason: "expects https://idp.acme.example/alice; the identifier comes from the certificate under MTLS-6",
	},
	"COMMON-09.authenticate-realm": {
		By:     "MTLS-11.listener-realm",
		Reason: "expects a globex principal id that no certificate yields; the realm is the listener's configuration (MTLS-6)",
	},
	"COMMON-10.authenticate-error": {
		By:     "MTLS-13.unspecified",
		Reason: "pins CREDENTIAL_REJECTED for a bearer token and a cookie; the only credential is the certificate, and none is NO_CREDENTIAL (MTLS-29)",
	},
	"IDENT-01.authenticate": {
		By:     "MTLS-12.authenticate",
		Reason: "expects a basic: account identifier; the subject text of a certificate is never an input (MTLS-6)",
	},
	"IDENT-02.authenticate": {
		By:     "MTLS-18.other-ca",
		Reason: "expects an oauth: identifier of another tenant; under mTLS another authority is another ca-id (IM-22)",
	},
	"IDENT-03.authenticate": {
		By:     "MTLS-18.same-key-other-name",
		Reason: "splits user and client; under mTLS the principal is the workload (identity-mapping 3.4)",
	},
	"IDENT-05.authenticate": {
		By:     "MTLS-12.authenticate",
		Reason: "expects a basic: account identifier; the subject common name, the display-name analogue, is never compared (MTLS-6)",
	},
}

// TestConformance runs the conformance suite, the common cases and the mTLS
// cases of spec/v1.0/fixtures/adapters/mtls, with the eight replaced common cases
// declared. The mTLS profile does not support workloads shared by several
// agents, so the dedicated cases run.
func TestConformance(t *testing.T) {
	adaptertest.Run(t, mtlsFactory, adaptertest.Options{Adapter: "mtls", Replaced: replaced})
}
