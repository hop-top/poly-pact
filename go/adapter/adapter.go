package adapter

import (
	"slices"

	"hop.top/pact-go/core"
)

// Descriptor names the native protocol an adapter implements and the revision
// of its operation mapping (draft 13.3).
type Descriptor struct {
	// Protocol is the native protocol, such as "mcp".
	Protocol string
	// Version is the exact protocol version the adapter implements.
	Version string
	// MappingRevision is the revision of the adapter's operation mapping.
	MappingRevision string
}

// NativeAdapter returns the descriptor as the entry a gateway publishes in its
// metadata.
func (d Descriptor) NativeAdapter() core.NativeAdapter {
	return core.NativeAdapter{
		Protocol:        d.Protocol,
		Version:         d.Version,
		MappingRevision: d.MappingRevision,
	}
}

// Adapter is the composite an enforced adapter implements: the seven draft
// 17.1 functions and its descriptor.
type Adapter interface {
	NativeAuthenticator
	BindingResolver
	OperationMapper
	ClaimReader
	ContextChecker
	NativeAuthorizer
	OutcomeRecorder

	// Describe returns the adapter's descriptor; for a [MultiDescriber], the
	// primary form.
	Describe() Descriptor
}

// MultiDescriber is implemented by an adapter that serves more than one native
// protocol form and must publish one GatewayMetadata.adapters entry per form
// (draft 13.3). Describe then returns the primary form.
type MultiDescriber interface {
	// Descriptors returns one descriptor per form, the primary form first.
	Descriptors() []Descriptor
}

// DescriptorsOf returns every descriptor an adapter publishes: Descriptors()
// when it is a MultiDescriber, otherwise the one Describe returns. The result
// is the caller's to change.
func DescriptorsOf(a Adapter) []Descriptor {
	if m, ok := a.(MultiDescriber); ok {
		return slices.Clone(m.Descriptors())
	}
	return []Descriptor{a.Describe()}
}
