package main

import (
	"github.com/santhosh-tekuri/jsonschema/v6"

	"hop.top/pact/internal/pactschema"
)

// uriExpression is the RFC 3986 expression every PACT SDK registers for the
// JSON Schema format "uri"; package pactschema holds it, with its license
// notice and derivation.
const uriExpression = pactschema.URIExpression

// uriFormat is the "uri" format checker built on uriExpression.
func uriFormat() *jsonschema.Format { return pactschema.URIFormat() }

// newSchemaCompiler returns a Draft 2020-12 compiler that asserts formats,
// with the shared "uri" checker in place of the library's.
func newSchemaCompiler() *jsonschema.Compiler { return pactschema.NewCompiler() }
