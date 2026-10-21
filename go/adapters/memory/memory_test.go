package memory_test

import (
	"testing"

	"hop.top/pact-go/adapter/adaptertest"
	"hop.top/pact-go/adapters/memory"
)

// TestSuite runs the conformance suite against the reference adapter in both
// workload modes: by default its workloads are dedicated, the default of every
// profile, and with WithSharedWorkloads they may be shared by several agents
// (identity mapping IM-19).
func TestSuite(t *testing.T) {
	t.Run("dedicated", func(t *testing.T) {
		adaptertest.Run(t, memory.Factory, adaptertest.Options{})
	})
	t.Run("shared", func(t *testing.T) {
		adaptertest.Run(t, memory.FactoryWith(memory.WithSharedWorkloads()), adaptertest.Options{SharedWorkloads: true})
	})
}
