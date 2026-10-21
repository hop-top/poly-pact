package contract_test

import (
	"encoding/json"
	"testing"

	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
)

// TestTransport: the transport a contract names is the transport_profile of
// the TransportDeclaration its extensions carry under
// pact-transport-profile-v1, or the HTTPS baseline when they carry none
// (draft 13.3.1, Appendix A.2); a declaration that names no transport
// profile names no transport, which no channel matches.
func TestTransport(t *testing.T) {
	stdio := json.RawMessage(`{"channels":["uds"],"framing":"ndjson","identity_assurance":["kernel-peer"],"max_frame_bytes":360448,"transport_profile":"stdio-ipc","version":"0.1"}`)
	for name, tc := range map[string]struct {
		ext  core.Object
		want string
	}{
		"no extensions":         {nil, "https"},
		"other extension":       {core.Object{"https://ext.example/pact/hint": json.RawMessage(`{"transport_profile":"stdio-ipc"}`)}, "https"},
		"stdio-ipc declaration": {core.Object{"pact-transport-profile-v1": stdio}, "stdio-ipc"},
		"no transport_profile":  {core.Object{"pact-transport-profile-v1": json.RawMessage(`{"version":"0.1"}`)}, ""},
		"not an object":         {core.Object{"pact-transport-profile-v1": json.RawMessage(`"stdio-ipc"`)}, ""},
		"not a string":          {core.Object{"pact-transport-profile-v1": json.RawMessage(`{"transport_profile":7}`)}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			c := contract.Contract{Claims: core.RequirementContract{Extensions: tc.ext}}
			if got := c.Transport(); got != tc.want {
				t.Errorf("Contract.Transport() = %q, want %q", got, tc.want)
			}
			r := contract.Requirements{Extensions: tc.ext}
			if got := r.Transport(); got != tc.want {
				t.Errorf("Requirements.Transport() = %q, want %q", got, tc.want)
			}
		})
	}
	if contract.ExtensionTransportProfile != "pact-transport-profile-v1" || contract.TransportHTTPS != "https" || contract.TransportStdioIPC != "stdio-ipc" {
		t.Errorf("identifiers %q %q %q", contract.ExtensionTransportProfile, contract.TransportHTTPS, contract.TransportStdioIPC)
	}
}

// TestTransportOfFixtures: the signed contracts of the transport cases name
// the transports their decoded files declare.
func TestTransportOfFixtures(t *testing.T) {
	for id, want := range map[string]string{
		"transport/stdio-ipc-contract-over-https": "stdio-ipc",
		"transport/https-contract-over-stdio-ipc": "https",
		"admission/valid":                         "https",
	} {
		c, err := b4Verifier(t).Verify(compactOf(t, id+"/signed/contract.jws"), at(1792080000))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if got := c.Transport(); got != want {
			t.Errorf("%s: Transport() = %q, want %q", id, got, want)
		}
	}
}
