package holder_test

import (
	"testing"

	"hop.top/pact-go/core"
	"hop.top/pact-go/core/jws"
	"hop.top/pact-go/holder"
)

func bMetadata(t testing.TB) core.GatewayMetadata {
	t.Helper()
	var md core.GatewayMetadata
	decodeStrict(t, draftBlock(t, "B.13"), &md)
	return md
}

// TestNegotiate: the B.13 metadata negotiates wire version 0.1 and ES256. A
// gateway that lists no version the holder implements, or not the key's
// algorithm, is refused; the holder never downgrades (draft 13.1, 21). A
// metadata document for another gateway or environment is a mismatch.
func TestNegotiate(t *testing.T) {
	h := bHolder(t, memoryKey(t, 1))
	v, err := h.Negotiate(bg, bMetadata(t))
	if err != nil || v != "0.1" {
		t.Fatalf("Negotiate: %q, %v", v, err)
	}
	cases := map[string]struct {
		edit func(md *core.GatewayMetadata)
		want error
	}{
		"newer only":   {func(md *core.GatewayMetadata) { md.WireVersions = []string{"0.2"} }, holder.ErrUnsupportedVersion},
		"none":         {func(md *core.GatewayMetadata) { md.WireVersions = nil }, holder.ErrUnsupportedVersion},
		"prefix":       {func(md *core.GatewayMetadata) { md.WireVersions = []string{"0.1.1", "0"} }, holder.ErrUnsupportedVersion},
		"alg":          {func(md *core.GatewayMetadata) { md.JWSAlgorithms = []core.JWSAlgorithm{"Ed25519"} }, holder.ErrUnsupportedRequirement},
		"gateway":      {func(md *core.GatewayMetadata) { md.GatewayID = "https://gateway.example/other" }, holder.ErrContextMismatch},
		"environment":  {func(md *core.GatewayMetadata) { md.EnvironmentID = "https://gateway.example/environments/other" }, holder.ErrContextMismatch},
		"unsupp. mode": {func(md *core.GatewayMetadata) { md.WireVersions = []string{"0.2", "0.1"} }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			md := bMetadata(t)
			c.edit(&md)
			v, err := h.Negotiate(bg, md)
			if c.want == nil {
				if err != nil || v != "0.1" {
					t.Fatalf("Negotiate: %q, %v", v, err)
				}
				return
			}
			wantErr(t, err, c.want)
			if v != "" {
				t.Fatalf("version %q on error", v)
			}
		})
	}
	// An Ed25519 key needs Ed25519 both negotiated locally and advertised.
	ed, err := holder.NewMemoryKeyEd25519(edKey(t))
	if err != nil {
		t.Fatal(err)
	}
	h = bHolder(t, ed)
	md := bMetadata(t)
	md.JWSAlgorithms = []core.JWSAlgorithm{"ES256", "Ed25519"}
	_, err = h.Negotiate(bg, md)
	wantErr(t, err, holder.ErrUnsupportedRequirement)
	h.Algorithms = jws.Algorithms{jws.AlgES256, jws.AlgEd25519}
	if v, err := h.Negotiate(bg, md); err != nil || v != "0.1" {
		t.Fatalf("Ed25519 negotiated: %q, %v", v, err)
	}
}
