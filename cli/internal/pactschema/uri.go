package pactschema

import (
	"errors"
	"regexp"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ajv-formats is under the MIT License:
//
// Copyright (c) 2020 Evgeny Poberezkin
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// URIExpression matches a URI per RFC 3986 (the URI production of section
// 3), the meaning of JSON Schema format "uri" (JSON Schema Validation
// 2020-12 section 7.3.5). It is the expression every PACT SDK registers for
// the format, so that the ports and Go agree; the vectors of
// spec/v1.0/fixtures/vectors/schema/uri-format.json pin it, and their README
// carries the same text.
//
// The JSON Schema library's own "uri" checker is net/url.Parse plus an
// absolute-URL test, which accepts characters RFC 3986 does not allow (SP,
// non-ASCII, "\", DQUOTE, "{", "}", "|", "^", a second "#"), so NewCompiler
// replaces it.
//
// Derived from the "uri" expression of ajv-formats 3.0.1 (src/formats.ts),
// with these changes:
//
//   - ASCII classes instead of the case-insensitive flag: [a-z] is written
//     [a-zA-Z], [0-9a-f] is written [0-9a-fA-F] and \d is written [0-9].
//     A case-insensitive Unicode match in Go or Python folds U+212A KELVIN
//     SIGN and U+017F LONG S into [a-z], and Python's \d matches non-ASCII
//     digits; RFC 3986 section 2 allows US-ASCII only, and DIGIT is
//     %x30-39 (RFC 5234 Appendix B.1).
//   - The rootless-path alternative of hier-part is optional, so a URI with
//     an empty path and no authority, such as "https:", matches: hier-part
//     may be path-empty (RFC 3986 section 3).
//   - The authority alternative starts with "//", not "/?/". In the
//     original, "scheme:/" also opened an authority, so
//     "https://example.com:80a/" matched as "https:/", an empty authority
//     and the path "/example.com:80a/", and "https:/[::1]" matched with an
//     IP-literal host. RFC 3986 sections 3 and 3.3: an authority is
//     preceded by "//", and a path without one cannot begin with "//". A
//     single "/" after the scheme is path-absolute, the next alternative.
//
// ajv-formats also requires a "/" or ":" in the string (its
// NOT_URI_FRAGMENT test); every match of the expression has a ":" after the
// scheme, so the test adds nothing and is not carried over. The license
// notice of ajv-formats is above.
const URIExpression = `^(?:[a-zA-Z][a-zA-Z0-9+\-.]*:)(?:\/\/(?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:]|%[0-9a-fA-F]{2})*@)?(?:\[(?:(?:(?:(?:[0-9a-fA-F]{1,4}:){6}|::(?:[0-9a-fA-F]{1,4}:){5}|(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){4}|(?:(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){3}|(?:(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){2}|(?:(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}:|(?:(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})?::)(?:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}|(?:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::)|[Vv][0-9a-fA-F]+\.[a-zA-Z0-9\-._~!$&'()*+,;=:]+)\]|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[a-zA-Z0-9\-._~!$&'()*+,;=]|%[0-9a-fA-F]{2})*)(?::[0-9]*)?(?:\/(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*)*|\/(?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})+(?:\/(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*)*)?|(?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})+(?:\/(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*)*)?)(?:\?(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-fA-F]{2})*)?(?:#(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-fA-F]{2})*)?$`

var uriPattern = regexp.MustCompile(URIExpression)

var errNotURI = errors.New("not a URI per RFC 3986")

// URIFormat is the "uri" format checker built on URIExpression. Like every
// format, it asserts nothing about a value that is not a string.
func URIFormat() *jsonschema.Format {
	return &jsonschema.Format{
		Name: "uri",
		Validate: func(v any) error {
			s, ok := v.(string)
			if !ok || uriPattern.MatchString(s) {
				return nil
			}
			return errNotURI
		},
	}
}

// NewCompiler returns a Draft 2020-12 compiler that asserts formats,
// with the shared "uri" checker in place of the library's.
func NewCompiler() *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.AssertFormat()
	c.RegisterFormat(URIFormat())
	return c
}
