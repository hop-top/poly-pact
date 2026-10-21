// Package evalcase reads the evaluation cases of spec/v1.0/fixtures and checks
// their signed files. It is standard library and hop.top/pact-go packages
// only, and is distinct from the adapter case files that adaptertest reads.
// The format is spec/v1.0/fixtures/README.md, sections Evaluation cases,
// Signed artifacts and Format v2.
//
// # Evaluation cases
//
// Load reads a manifest entry of kind evaluate into a Case: one Exchange
// for a case directory, or one per exchange directory of a multi-exchange
// case's sequence.json, in order. An Exchange holds config.json,
// native_context.json, signing.json and exchange.json as typed values,
// exchange.json with its defaults applied, every other JSON file of the
// directory as bytes, the committed signed files, and the expected
// decision.json, whether at expected/<id>/decision.json or, for an exchange,
// at expected/<id>/<exchange>/decision.json. v1 cases read the same under
// format v2, since every v2 member has a default.
//
// # Signed files
//
// The generator contract of signing.json is applied by Walk, which pactfix
// generate drives to sign and Verify drives to check: Dirs lists the
// directories to sign, LoadKeys the test keys of KeysFile, and each File
// says what a signed file must carry. Verify, and so Load,
// fails on a stale signed file, one the generator would sign again. Each
// returned Signed also carries the result of verifying it against the
// directory's trust records (config.json trust and the authenticated
// holder_jkt), which a case may make fail by design.
//
// Paths are slash-separated and relative to the fixture directory, the
// directory of manifest.json, or to a case directory where a field says so.
package evalcase
