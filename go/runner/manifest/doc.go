// Package manifest reads and checks spec/v1.0/fixtures/manifest.json, the index of
// the language-neutral conformance fixtures. The format is defined in
// spec/v1.0/fixtures/README.md; spec/v1.0/fixtures/manifest.schema.json states the same
// field rules as a JSON Schema for consumers in other languages.
//
// The package has three parts, standard library and core/strictjson only:
//
//   - Load and Parse read the manifest with the strict parse rules of draft
//     Section 7.1. Validate applies the field rules: the members of every
//     entry, the id, path, kind, scope, expected, outcome, spec_map_row and
//     draft_section forms, the optional members capabilities,
//     conformance_profile, transport and layer, the scope of the kinds that
//     have one, the layout of adapter cases, unique ids and order by id.
//   - Completeness checks the manifest against the fixture directory: every
//     path and expected file exists inside it, every file is covered by an
//     entry (README.md files, files named LICENSE* and the files under
//     testdata/ aside), and every file has a neutral extension, in lower
//     case.
//   - ParseSpecMap and CheckSpecMap check the cross-references with
//     spec/v1.0/spec-map.md: every spec_map_row is a row, every group has a
//     status in the Fixture groups table, and each status (planned, partial
//     or landed) agrees with the manifest and with the fixtures that exist
//     for the ids the rows list.
//
// Check runs all of them, as pactfix check manifest does. Every problem
// names its rule (the Rule constants), so a caller can tell them apart.
//
// Paths are slash-separated and relative to the directory that holds
// manifest.json, so the same manifest resolves in the source repository and
// in the spec mirror.
package manifest
