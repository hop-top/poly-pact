// Package binding derives the operation context of the baseline HTTP mapping
// (draft Section 10.2) from a request a net/http server received.
//
// [FromRequest] fills method, target_uri, body_digest and headers from the
// request and the gateway's [Config], and copies the principal, action and
// resources the caller derived from the authenticated request and its mapping
// rules. The caller sets operation_id and environment_id. The caller also
// records Config.MappingVersion when it issues a requirement contract and
// checks that the same version is installed when it validates the actual
// operation.
//
// # Rules
//
// method is the request method in uppercase. Only ASCII letters are
// accepted, as the schema pattern ^[A-Z]+$ requires ([RuleMethod]).
//
// target_uri is Config.Origin, normalized, followed by the exact path and
// query of the request-target. Octets, percent-encoding and query order are
// kept. Host, Forwarded and X-Forwarded-* headers are not read.
//   - The origin is https. Its scheme and host are lowercased and port 443 is
//     dropped (RFC 3986 3.2.2, 6.2.2.1, 6.2.3; RFC 9110 4.2.2, 4.2.3).
//   - The request-target is origin-form or http(s) absolute-form (RFC 9112
//     3.2). The authority of an absolute-form target is checked and then
//     dropped. Asterisk-form, authority-form, other schemes, an empty host and
//     an absolute-form target with an empty path are refused ([RuleTargetForm]).
//   - A fragment is refused ([RuleFragment]). It is for client-side
//     processing, so the target URI excludes it (RFC 3986 3.5; RFC 9110 7.1),
//     and neither origin-form nor absolute-form carries one (RFC 9112 3.2.1,
//     3.2.2; RFC 3986 4.3). Userinfo is refused ([RuleUserinfo]): a recipient
//     should treat it as an error (RFC 9110 4.2.4).
//   - A host with a non-ASCII octet or a percent-encoding, which in a host
//     only represents UTF-8, is refused ([RuleNonASCIIHost]; RFC 3986 3.2.2).
//     In the configured origin it is a configuration error.
//   - Every octet of the path and query is allowed there by RFC 3986 3.3 and
//     3.4, so raw non-ASCII, space, controls, "[", "]" and similar are refused
//     ([RuleInvalidCharacter]), and every "%" starts a triplet of RFC 3986 2.1
//     ([RuleMalformedEscape]).
//   - Ambiguous encodings are refused, never normalized (draft 10.2). They
//     are: a percent-encoded unreserved character such as %41 or %2E
//     ([RuleEncodedUnreserved]; RFC 3986 2.3, 6.2.2.2); a lowercase hex digit
//     in an escape ([RuleLowercaseHex]; RFC 3986 2.1, 6.2.2.1); decoded octets
//     that are not valid UTF-8, including overlong forms and surrogates
//     ([RuleInvalidUTF8]; RFC 3629 3, 10); %2F in the path, an encoded path
//     separator ([RuleEncodedSlash]); and a complete "." or ".." path segment,
//     which path segment normalization removes ([RuleDotSegment]; RFC 3986
//     3.3, 5.2.4, 6.2.2.3). Segments are delimited by "/" only, so "a..b",
//     "..." and dots in the query are kept; an encoded dot segment such as
//     %2E%2E is an encoded unreserved character. %2F in the query is data.
//     Other escapes, such as %00, %25 and %5C, and empty segments are kept as
//     sent.
//   - target_uri has at most 1024 characters ([RuleTargetTooLong]).
//
// body_digest is bytes_digest of the request body after transfer decoding,
// which net/http performs for chunked. An empty body hashes the empty byte
// string. Any Content-Encoding field is refused ([RuleContentEncoding]), as
// is a transfer coding other than chunked ([RuleTransferCoding]) and a body
// over Config.MaxBody ([RuleBodyTooLarge]).
//
// headers holds the headers of Config.HeaderAllowlist that are present, under
// lowercase names, plus content-type when the body is not empty. A value is
// each field line without leading and trailing SP and HTAB, joined in order
// with ", " (RFC 9110 5.2, 5.3, 5.5). A name the request lists in a
// Connection field is hop-by-hop for that request and is left out (RFC 9110
// 7.6.1). A value with a control octet other than HTAB (RFC 9110 5.5), or
// that is not UTF-8 and so cannot be carried exactly in PACT JSON (draft
// 7.1), is refused ([RuleHeaderValue]), as is one over 8192 characters
// ([RuleHeaderTooLong]) and a header stored under two map keys that differ
// only in ASCII case ([RuleHeaderKeyCollision]).
//
// A request with more than one Host field line is refused
// ([RuleDuplicateHost]; RFC 9112 3.2). A net/http server answers 400 to it
// before any handler runs, and http.ReadRequest refuses it too, so only a
// request a program built, with more than one Host line in Header, reaches
// the rule.
//
// An origin-form request with no Host has no authority and is refused
// ([RuleMissingHost]; RFC 9112 3.2). Request.Host stands for its Host line:
// a server fills it from Host, or over HTTP/2 from :authority (RFC 9113
// 8.3.1). An absolute-form target carries its own authority (RFC 9112
// 3.2.2), and net/http sets Request.Host from it. A Host value that is not
// uri-host [ ":" port ] with a non-empty host is refused ([RuleInvalidHost];
// RFC 9110 4.2.2, 7.2; RFC 3986 3.2.2, 3.2.3).
//
// Schemes, field names, connection options and coding names are compared
// without regard to ASCII case only (RFC 5234 2.3; RFC 3986 3.1; RFC 9110
// 5.1, 7.6.1, 8.4.1; RFC 9112 7). No Unicode case folding applies, so a name
// with U+212A KELVIN SIGN or U+017F LATIN SMALL LETTER LONG S is not the
// ASCII name it would fold to.
//
// These names cannot be allowlisted: authorization, cookie and set-cookie
// (credentials; draft 10.2, 19); every pact- name (presentation headers);
// connection, keep-alive, te, transfer-encoding, upgrade and every proxy-
// name (hop-by-hop; RFC 9110 7.6.1); signature and signature-input (RFC 9421
// 4.1, 4.2); host, which never selects the origin. The allowlist and
// content-type together have at most 64 names.
//
// # Errors
//
// Every error wraps one of [ErrInvalidConfig], [ErrInvalidRequest] or
// [ErrBodyRead]. A refused request is a [*RequestError] whose Rule names the
// rule; it corresponds to INVALID_MESSAGE of draft 13.4. This package does
// not import the adapter package, so a caller wraps or maps these errors to
// its own codes.
package binding
