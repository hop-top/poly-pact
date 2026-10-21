// Package core holds the Go types of the PACT 0.1 wire objects.
//
// There is one struct per entry of $defs in spec/v1.0/schemas/pact.schema.json, with
// the same member names and the same required and optional split, except the
// payload-only definitions ConformanceDeclaration and TransportDeclaration,
// which validate extension values and are not wire objects. A required
// member has a plain json tag. An optional member (the open "extensions"
// object, and the endpoints and jwks_uri of GatewayMetadata) is tagged
// omitzero, so a present but empty object survives a decode and encode round
// trip.
//
// Value mapping:
//   - string enums are typed string constants (Mode, Decision, ...), each with
//     a Valid method;
//   - integers are int64, and a nullable integer is *int64;
//   - base64url SHA-256 digests and key thumbprints are Digest;
//   - free-form JSON (a claim value, a field-rule schema) is json.RawMessage;
//   - the open objects "attributes" and "extensions" are Object, which keeps
//     member values as raw JSON.
//
// Decode untrusted input with [hop.top/pact-go/core/strictjson], not with
// encoding/json alone. The types do not enforce the schema's patterns, lengths
// or numeric ranges; a schema validator does that. They also do not produce
// digests or signatures: compute object_digest over the received JSON, never
// over a re-encoded struct.
//
// schema_drift_test.go fails when a struct and the schema disagree.
package core
