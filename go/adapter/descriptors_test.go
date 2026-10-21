package adapter

import (
	"slices"
	"testing"
)

// single is an adapter that publishes one descriptor.
type single struct {
	Adapter
	d Descriptor
}

func (s single) Describe() Descriptor { return s.d }

// multi is an adapter that serves several native protocol forms.
type multi struct {
	single
	ds []Descriptor
}

func (m multi) Descriptors() []Descriptor { return m.ds }

// TestDescriptorsOf: one GatewayMetadata.adapters entry per pinned protocol
// revision (draft 13.3): every descriptor of a MultiDescriber, otherwise the
// one Describe returns.
func TestDescriptorsOf(t *testing.T) {
	intro := Descriptor{Protocol: "oauth-introspection", Version: "rfc7662", MappingRevision: "pact-oauth-1"}
	entra := Descriptor{Protocol: "entra-access-token", Version: "2.0", MappingRevision: "pact-oauth-1"}
	if got := DescriptorsOf(single{d: intro}); !slices.Equal(got, []Descriptor{intro}) {
		t.Errorf("one form: %v, want [%v]", got, intro)
	}
	m := multi{single: single{d: intro}, ds: []Descriptor{intro, entra}}
	if got := DescriptorsOf(m); !slices.Equal(got, []Descriptor{intro, entra}) {
		t.Errorf("two forms: %v, want [%v %v]", got, intro, entra)
	}
	ds := []Descriptor{intro}
	got := DescriptorsOf(multi{single: single{d: intro}, ds: ds})
	got[0].Protocol = "changed"
	if ds[0] != intro {
		t.Error("the result shares the adapter's slice")
	}
}
