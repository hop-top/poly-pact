# Schema format vectors

The schema in [`../../../schemas/pact.schema.json`](../../../schemas/pact.schema.json) (Appendix A.3) uses JSON Schema format `uri`. JSON Schema Validation 2020-12, Section 7.3.5 (<https://json-schema.org/draft/2020-12/json-schema-validation>), defines it: a string is valid when it is a valid URI according to RFC 3986 (<https://www.rfc-editor.org/rfc/rfc3986>), that is, when it matches the `URI` production of RFC 3986 Section 3, fragment included. A JSON Schema library's built-in checker does not always follow it, so every PACT SDK registers the same expression for the format, given below, and passes these vectors with format assertion on.

`uri-format.json` holds the vectors. It is a JSON array, and every element has exactly these members:

| Member | Meaning |
|---|---|
| `id` | Unique name of the vector within the file. |
| `input` | The string validated against `{"type": "string", "format": "uri"}`. |
| `expect` | `accept` when `input` is a URI per RFC 3986, `reject` when it is not. |
| `reason` | The RFC 3986 rule that decides, with its section. |
| `ajv_formats_differs` | `true` when the `uri` format of `ajv-formats` 3.0.1 as published gives the other verdict, `false` otherwise. |

A harness compiles a Draft 2020-12 schema `{"type": "string", "format": "uri"}` with format assertion enabled and the expression below registered as the `uri` format, validates every `input`, and requires the verdict `expect`. The manifest entry has kind `vector`, scope `core`, outcome `MATCH`, `spec_map_row` `CL-A.3` and `draft_section` `A.3`; its `path` and `expected` are both the file.

Every `expect` was derived from the RFC 3986 grammar (Appendix A) and the cited sections, not from a checker. The five strings that separate an RFC 3986 checker from a URL parser are `http://example.com/a b`, `http://example.com/é`, `https://example.com/%zz` and `http://a/b\c`, all rejected (Sections 2.1, 2.3 and 3.3), and `https://example.com:99999/`, accepted (Section 3.2.3: `port = *DIGIT`).

## The expression

The expression is matched against the whole string, with no flags:

```text
^(?:[a-zA-Z][a-zA-Z0-9+\-.]*:)(?:\/\/(?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:]|%[0-9a-fA-F]{2})*@)?(?:\[(?:(?:(?:(?:[0-9a-fA-F]{1,4}:){6}|::(?:[0-9a-fA-F]{1,4}:){5}|(?:[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){4}|(?:(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){3}|(?:(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){2}|(?:(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}:|(?:(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})?::)(?:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}|(?:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::)|[Vv][0-9a-fA-F]+\.[a-zA-Z0-9\-._~!$&'()*+,;=:]+)\]|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[a-zA-Z0-9\-._~!$&'()*+,;=]|%[0-9a-fA-F]{2})*)(?::[0-9]*)?(?:\/(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*)*|\/(?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})+(?:\/(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*)*)?|(?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})+(?:\/(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*)*)?)(?:\?(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-fA-F]{2})*)?(?:#(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-fA-F]{2})*)?$
```

It is derived from the `uri` expression of `ajv-formats` 3.0.1 (`src/formats.ts`, <https://github.com/ajv-validator/ajv-formats>, MIT License, Copyright (c) 2020 Evgeny Poberezkin). Each SDK source that carries it includes that license notice. The changes:

- ASCII classes instead of the case-insensitive flag: `[a-z]` is written `[a-zA-Z]`, `[0-9a-f]` is written `[0-9a-fA-F]` and `\d` is written `[0-9]`. A case-insensitive Unicode match in Go or Python folds U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S into `[a-z]`, and Python's `\d` matches non-ASCII digits; RFC 3986 Section 2 allows US-ASCII only, and `DIGIT` is `%x30-39` (RFC 5234 Appendix B.1). The rows `kelvin-sign-in-path`, `long-s-in-path`, `kelvin-sign-in-host` and `non-ascii-digit-in-port` catch a port that keeps the flag.
- The rootless-path alternative of `hier-part` is optional, so `https:` matches: `hier-part` may be `path-empty` (RFC 3986 Section 3). Row `scheme-only`.
- The authority alternative starts with `//` instead of `/?/`. In the original, `scheme:/` also opened an authority, so `https://example.com:80a/` matched as `https:/`, an empty authority and the path `/example.com:80a/`, and `https:/[::1]` matched with an IP-literal host. RFC 3986 Sections 3 and 3.3: an authority is preceded by `//`, and a path without one cannot begin with `//`. A single `/` after the scheme is `path-absolute`, the next alternative. Rows `port-not-digits` and `ip-literal-without-authority`.

`ajv-formats` also requires a `/` or `:` in the string; every match of the expression has a `:` after the scheme, so that test adds nothing and is left out.

The three rows of the last two changes are the rows with `ajv_formats_differs` set: an SDK that checks its matcher against `ajv-formats` 3.0.1 expects the two to disagree there, and only there.

A port matches the whole string: in Python, `re.fullmatch` or `\Z`, since `$` also matches before a final line feed (row `line-feed-at-end`).
