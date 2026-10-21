package holder_test

import (
	"encoding/json"
	"testing"

	"hop.top/pact-go/contract"
	"hop.top/pact-go/core"
	"hop.top/pact-go/holder"
)

// TestTransportBinding: an enforced-mode holder does not send a
// presentation over a transport other than the one its contract names: the
// transport_profile of the contract's pact-transport-profile-v1
// declaration, or https when it carries none (draft 13.3.1, the downgrade
// rule). Holder.Transport is the transport the holder sends over, empty for
// the HTTPS baseline. In observe mode the contract is used and the gateway
// records the mismatch.
func TestTransportBinding(t *testing.T) {
	stdio := json.RawMessage(`{"channels":["uds"],"framing":"ndjson","identity_assurance":["kernel-peer"],"max_frame_bytes":360448,"transport_profile":"stdio-ipc","version":"0.1"}`)
	contractOf := func(t *testing.T, ext core.Object, mode core.Mode) string {
		r := bRequirements(t)
		r.Extensions, r.Mode = ext, mode
		return issue(t, contract.NewMemoryReplay(4), bHolderJKT, r, bOperation(t), at(bTime)).Compact
	}
	named := core.Object{"pact-transport-profile-v1": stdio}
	for _, tc := range []struct {
		name      string
		ext       core.Object
		mode      core.Mode
		transport string
		want      error
	}{
		{"https contract, default holder", nil, core.ModeEnforced, "", nil},
		{"https contract, https holder", nil, core.ModeEnforced, "https", nil},
		{"https contract, stdio-ipc holder", nil, core.ModeEnforced, "stdio-ipc", holder.ErrContextMismatch},
		{"stdio-ipc contract, stdio-ipc holder", named, core.ModeEnforced, "stdio-ipc", nil},
		{"stdio-ipc contract, default holder", named, core.ModeEnforced, "", holder.ErrContextMismatch},
		{"stdio-ipc contract, https holder", named, core.ModeEnforced, "https", holder.ErrContextMismatch},
		{"observe stdio-ipc contract, https holder", named, core.ModeObserve, "https", nil},
		{"observe https contract, stdio-ipc holder", nil, core.ModeObserve, "stdio-ipc", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			compact := contractOf(t, tc.ext, tc.mode)
			h := bHolder(t, memoryKey(t, 1))
			h.Extensions = []string{"pact-transport-profile-v1"}
			h.Transport = tc.transport
			_, err := h.VerifyContract(bg, compact, bIntent(t), bOperation(t), at(bTime))
			in := bInput(t)
			in.Contract = compact
			_, perr := h.Present(bg, in, at(bTime))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("VerifyContract: %v", err)
				}
				return
			}
			wantErr(t, err, tc.want)
			wantErr(t, perr, tc.want)
		})
	}
}
