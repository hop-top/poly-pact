package contract

import (
	"encoding/json"

	"hop.top/pact-go/core"
)

// The transport binding of draft 13.3.1: the extension that carries a
// transport profile declaration (draft 21, Appendix A.2) and the transport
// profiles a contract can name.
const (
	// ExtensionTransportProfile is the first-party extension whose value is
	// a TransportDeclaration (Appendix A.3).
	ExtensionTransportProfile = "pact-transport-profile-v1"
	// TransportHTTPS is the HTTPS baseline of draft 13, which has no
	// declaration.
	TransportHTTPS = "https"
	// TransportStdioIPC is the local IPC and stdio profile of draft 13.3.
	TransportStdioIPC = "stdio-ipc"
)

// Transport returns the transport the contract names (draft 13.3.1): the
// transport_profile of the TransportDeclaration its extensions carry under
// [ExtensionTransportProfile], or [TransportHTTPS] when they carry none. A
// declaration without a string transport_profile names no transport: the
// result is empty, which no channel matches.
func (c Contract) Transport() string { return transportOf(c.Claims.Extensions) }

// Transport returns the transport the requirements name, as
// [Contract.Transport] reads it from the contract they are issued as.
func (r Requirements) Transport() string { return transportOf(r.Extensions) }

func transportOf(ext core.Object) string {
	raw, ok := ext[ExtensionTransportProfile]
	if !ok {
		return TransportHTTPS
	}
	var d struct {
		TransportProfile *string `json:"transport_profile"`
	}
	if err := json.Unmarshal(raw, &d); err != nil || d.TransportProfile == nil {
		return ""
	}
	return *d.TransportProfile
}
