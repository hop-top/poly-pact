package manifest

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// Patterns of the field rules. manifest.schema.json states the same ones.
const (
	// IDPattern: the id of every entry that is not an adapter case, two or
	// three segments. A segment is lowercase letters and digits joined by
	// hyphens.
	IDPattern = `^[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:-[a-z0-9]+)*(?:/[a-z0-9]+(?:-[a-z0-9]+)*)?$`
	// AdapterCaseIDPattern: the id of an adapter-case entry,
	// adapters/<adapter>/<case>. It follows the file name
	// adapters/<adapter>/<case>.json, so its last two segments may also start
	// with "_" and join with ".", as in adapters/_common/common-03.fragment.
	AdapterCaseIDPattern = `^adapters/_?[a-z0-9]+(?:[-.][a-z0-9]+)*/_?[a-z0-9]+(?:[-.][a-z0-9]+)*$`
	// SourceCaseIDPattern: the id of a source-case entry,
	// sources/<source>/<case>. It follows the file name
	// sources/<source>/<case>.json, so its case segment may also join with
	// ".", as in sources/scim/scim-01.join; no segment starts with "_".
	SourceCaseIDPattern = `^sources/[a-z0-9]+(?:-[a-z0-9]+)*/[a-z0-9]+(?:[-.][a-z0-9]+)*$`
	// PathPattern: relative and slash-separated; a segment is ASCII letters,
	// digits, ".", "_" and "-", and does not start with ".", so there is no
	// leading "/", no empty segment and no "." or ".." segment.
	PathPattern = `^[A-Za-z0-9_-][A-Za-z0-9._-]*(?:/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$`
	// SpecMapRowPattern: a row id of spec/v1.0/spec-map.md, such as R01, CL-11.3,
	// CL-C or COMMON-01.
	SpecMapRowPattern = `^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+(?:\.[0-9]+)*)?$`
	// DraftSectionPattern: a section number such as 11.3, or an appendix
	// letter with an optional subsection, such as C or B.7.
	DraftSectionPattern = `^(?:[1-9][0-9]*|[A-Z])(?:\.[1-9][0-9]*)*$`
)

// fileIDPattern: two or three segments that may each start with "_" and join
// with ".", the widest id form. An id of another form is malformed whatever
// the kind; a spec-map fixture id of this form can name a file.
const fileIDPattern = `^_?[a-z0-9]+(?:[-.][a-z0-9]+)*/_?[a-z0-9]+(?:[-.][a-z0-9]+)*(?:/_?[a-z0-9]+(?:[-.][a-z0-9]+)*)?$`

var (
	idRE            = regexp.MustCompile(IDPattern)
	adapterCaseIDRE = regexp.MustCompile(AdapterCaseIDPattern)
	sourceCaseIDRE  = regexp.MustCompile(SourceCaseIDPattern)
	fileIDRE        = regexp.MustCompile(fileIDPattern)
	pathRE          = regexp.MustCompile(PathPattern)
	specMapRowRE    = regexp.MustCompile(SpecMapRowPattern)
	draftSectionRE  = regexp.MustCompile(DraftSectionPattern)
)

// Kind is what an entry is: the harness verb that runs it or the role of the
// asset.
type Kind string

// Kinds.
const (
	KindKey          Kind = "key"
	KindVector       Kind = "vector"
	KindSchema       Kind = "schema"
	KindEvaluate     Kind = "evaluate"
	KindOutcomes     Kind = "outcomes"
	KindLearning     Kind = "learning"
	KindAdapterCase  Kind = "adapter-case"
	KindAdapterAsset Kind = "adapter-asset"
	// KindSourceCase: a case of a membership or status source that is not
	// an adapter, scope adapter, with its expectations inline and neither an
	// expected file nor an outcome.
	KindSourceCase     Kind = "source-case"
	KindProfileInvalid Kind = "profile-invalid"
	// KindTransport: a transport transcript, scope runner.
	KindTransport Kind = "transport"
	// KindMCP: an MCP adapter vector or case, scope adapter.
	KindMCP Kind = "mcp"
	// KindProfile: a conformance-profile case, scope runner.
	KindProfile Kind = "profile"
)

var kinds = []Kind{
	KindKey, KindVector, KindSchema, KindEvaluate, KindOutcomes, KindLearning,
	KindAdapterCase, KindAdapterAsset, KindSourceCase, KindProfileInvalid,
	KindTransport, KindMCP, KindProfile,
}

// Kinds returns the kinds in the order of the README.
func Kinds() []string { return names(kinds) }

// Known reports whether k is a kind of the manifest format.
func (k Kind) Known() bool { return slices.Contains(kinds, k) }

// HasExpected reports whether entries of kind k name an expected file and an
// outcome. Key, adapter-asset and source-case entries have neither: both are
// null.
func (k Kind) HasExpected() bool {
	return k != KindKey && k != KindAdapterAsset && k != KindSourceCase
}

// Scope says who must pass an entry.
type Scope string

// Scopes.
const (
	// ScopeCore: every language harness.
	ScopeCore Scope = "core"
	// ScopeRunner: only the Go conformance runner.
	ScopeRunner Scope = "runner"
	// ScopeAdapter: the adapter conformance harnesses.
	ScopeAdapter Scope = "adapter"
)

var scopes = []Scope{ScopeCore, ScopeRunner, ScopeAdapter}

// Scopes returns the scopes in the order of the README.
func Scopes() []string { return names(scopes) }

// Known reports whether s is a scope of the manifest format.
func (s Scope) Known() bool { return slices.Contains(scopes, s) }

// RequiredScope returns the one scope an entry of kind k must have: runner
// for transport transcripts and conformance-profile cases, adapter for MCP
// vectors and cases and for source cases, never core, so that the harnesses
// that select entries by scope skip them alike. ok is false for a kind that
// takes any scope.
func (k Kind) RequiredScope() (s Scope, ok bool) {
	switch k {
	case KindTransport, KindProfile:
		return ScopeRunner, true
	case KindMCP, KindSourceCase:
		return ScopeAdapter, true
	}
	return "", false
}

// Conformance profiles: the entries of kind conformance in
// spec/v1.0/profiles/registry.json (draft Section 22.1). An entry runs under the
// profiles its conformance_profile member lists, DefaultConformanceProfile
// when it has none.
const (
	ConformanceProfileFull        = "full"
	ConformanceProfileSingleOwner = "single-owner"
	// DefaultConformanceProfile applies to an entry without
	// conformance_profile.
	DefaultConformanceProfile = ConformanceProfileFull
)

var conformanceProfiles = []string{ConformanceProfileFull, ConformanceProfileSingleOwner}

// ConformanceProfiles returns the conformance profile ids in registry order.
func ConformanceProfiles() []string { return slices.Clone(conformanceProfiles) }

// Transports: the transport profiles an entry exercises, identified by id as
// in claim.transport of spec/v1.0/profiles/integration-profile.schema.json
// (draft Section 21). https is the baseline HTTPS binding (draft Section 13),
// which has no registry entry; stdio-ipc is the local IPC and stdio profile
// of draft Section 13.3, an entry of kind transport in
// spec/v1.0/profiles/registry.json. An entry without transport exercises
// DefaultTransport.
const (
	TransportHTTPS    = "https"
	TransportStdioIPC = "stdio-ipc"
	// DefaultTransport applies to an entry without transport.
	DefaultTransport = TransportHTTPS
)

var transports = []string{TransportHTTPS, TransportStdioIPC}

// Transports returns the transport profile ids in the order of the README.
func Transports() []string { return slices.Clone(transports) }

// Layers: how an entry over stdio-ipc is executed. An entry without layer
// applies to every layer. A transcript entry is a
// language-neutral frame sequence the runner executes, with peer facts
// supplied through the test seam; an os entry needs real operating-system
// facilities and is executed by a language-specific harness.
const (
	LayerTranscript = "transcript"
	LayerOS         = "os"
)

var layers = []string{LayerTranscript, LayerOS}

// Layers returns the layer tokens in the order of the README.
func Layers() []string { return slices.Clone(layers) }

// Capabilities: the optional capabilities an entry may test, each a feature
// the draft makes optional. Draft Section 22.1 lists the mandatory
// capabilities of each role, and Section 22.2 requires a role implementation
// to pass all applicable cases; an entry that tests an optional capability
// applies only to an implementation that declares it.
const (
	// CapabilityJWSEd25519: Ed25519 (RFC 9864) negotiated explicitly for
	// signed artifacts, with RFC 8037 keys (draft Section 7.2, MAY), which
	// the gateway publishes in GatewayMetadata.jws_algorithms (Section 13.1).
	CapabilityJWSEd25519 = "jws-ed25519"
)

var capabilities = []string{CapabilityJWSEd25519}

// Capabilities returns the capability tokens in the order of the README.
func Capabilities() []string { return slices.Clone(capabilities) }

// Outcome tokens: the decisions of draft Section 11.4, then the other
// one-token summaries, among them the qualification results of draft Section
// 14.3.
var outcomes = []string{
	"ADMISSIBLE", "INADMISSIBLE", "DEFERRED",
	"ACCEPTED", "REJECTED", "QUALIFIED", "UNQUALIFIED", "DISPUTED", "MATCH",
}

// Outcomes returns the outcome tokens in the order of the README.
func Outcomes() []string { return slices.Clone(outcomes) }

func names[T ~string](vs []T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}

// neutralExtensions may appear anywhere under the fixture directory;
// nativeExtensions only inside the path of an adapter-asset entry. Both are
// lowercase and compared as written: .JSON is on neither list.
var (
	neutralExtensions = []string{".json", ".yaml", ".md", ".jws"}
	nativeExtensions  = []string{".sql", ".rego", ".fga", ".ldif"}
)

// TestdataDir holds the test inputs of the manifest checks themselves, such
// as the test manifests of testdata/manifest; they are not fixtures.
const TestdataDir = "testdata"

// exempt reports whether the fixture file rel needs no covering entry:
// manifest.json and manifest.schema.json at the top, files under testdata/
// at the top, files named README.md, and files whose name starts with
// LICENSE.
func exempt(rel string) bool {
	if rel == FileName || rel == SchemaFileName || within(rel, TestdataDir) {
		return true
	}
	name := path.Base(rel)
	return name == "README.md" || strings.HasPrefix(name, "LICENSE")
}

// within reports whether rel is p or lies inside the directory p.
func within(rel, p string) bool {
	return rel == p || strings.HasPrefix(rel, p+"/")
}
