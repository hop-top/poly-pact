// Package sourcetest is the conformance harness of membership and status
// sources that are not adapters: the cases of kind source-case under
// spec/v1.0/fixtures/sources/<source>/, whose shared envelope
// spec/v1.0/fixtures/sources/README.md defines.
//
// A source is the receiving end of a protocol the identity system pushes and
// an [adapter.ClaimReader] over the state it was pushed (package
// [hop.top/pact-go/adapter/source]). A case states the source's configuration
// and seed state, a sequence of inbound messages (steps) and the reads that
// follow. The harness holds the clock at the time of each step and read,
// hands each step to the source's [Driver], which delivers the message and
// checks the source's answer against the step's expect member, and checks
// each read itself, as spec/v1.0/fixtures/adapters/README.md checks
// read_native_claim: the source is named, no time is later than the read's
// time plus the skew, the value is compared as JSON data, and an error
// carries the expected draft 13.4 code and wraps its sentinel.
//
// The step and source members are per source model, such as scim/1, and
// the source's own document defines them; the harness never looks inside.
//
//	func TestConformance(t *testing.T) {
//		sourcetest.Run(t, driver, sourcetest.Options{Source: "scim"})
//	}
package sourcetest
