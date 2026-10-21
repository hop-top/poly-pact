"""JSON Schema support: the format checker the package registers. SDK extra.

The checker carries exactly one format, ``uri``, matched per RFC 3986 by the
expression every PACT SDK shares (spec/v1.0/fixtures/vectors/schema/README.md of
the source repository, which the vectors of uri-format.json pin). Every
other format stays an annotation: jsonschema ignores a format its checker
does not carry. Use it with a Draft 2020-12 validator::

    Draft202012Validator(schema, format_checker=format_checker())
"""

from __future__ import annotations

import re
from typing import Final

from jsonschema import FormatChecker  # type: ignore[import-untyped]

__all__ = ["URI_EXPRESSION", "format_checker"]

# URI_EXPRESSION is derived from the "uri" expression of ajv-formats 3.0.1
# (src/formats.ts), which is under the MIT License:
#
# Copyright (c) 2020 Evgeny Poberezkin
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# The changes: ASCII classes instead of the case-insensitive flag ([a-zA-Z],
# [0-9a-fA-F], [0-9]: a case-insensitive Unicode match folds U+212A KELVIN
# SIGN and U+017F LONG S into [a-z], and \d matches non-ASCII digits, while
# RFC 3986 section 2 allows US-ASCII only); the rootless-path alternative of
# hier-part is optional, so "https:" matches (hier-part may be path-empty,
# RFC 3986 section 3); the authority alternative starts with "//", not "/?/"
# (RFC 3986 sections 3 and 3.3).
URI_EXPRESSION: Final = (
    r"^(?:[a-zA-Z][a-zA-Z0-9+\-.]*:)(?:\/\/(?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:]|%[0-9a-fA-F]"
    r"{2})*@)?(?:\[(?:(?:(?:(?:[0-9a-fA-F]{1,4}:){6}|::(?:[0-9a-fA-F]{1,4}:){5}|(?:[0-9a-f"
    r"A-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){4}|(?:(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4})"
    r"?::(?:[0-9a-fA-F]{1,4}:){3}|(?:(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4})?::(?:[0-9"
    r"a-fA-F]{1,4}:){2}|(?:(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}:"
    r"|(?:(?:[0-9a-fA-F]{1,4}:){0,4}[0-9a-fA-F]{1,4})?::)(?:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1"
    r",4}|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-"
    r"9][0-9]?))|(?:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}|(?:(?:["
    r"0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::)|[Vv][0-9a-fA-F]+\.[a-zA-Z0-9\-._~!$&'()*"
    r"+,;=:]+)\]|(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|["
    r"01]?[0-9][0-9]?)|(?:[a-zA-Z0-9\-._~!$&'()*+,;=]|%[0-9a-fA-F]{2})*)(?::[0-9]*)?(?:\/("
    r"?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*)*|\/(?:(?:[a-zA-Z0-9\-._~!$&'()*+,"
    r";=:@]|%[0-9a-fA-F]{2})+(?:\/(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})*)*)?|("
    r"?:(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@]|%[0-9a-fA-F]{2})+(?:\/(?:[a-zA-Z0-9\-._~!$&'()*+,"
    r";=:@]|%[0-9a-fA-F]{2})*)*)?)(?:\?(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-fA-F]{2})"
    r"*)?(?:#(?:[a-zA-Z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-fA-F]{2})*)?$"
)
"""The RFC 3986 URI expression of format uri, matched against the whole string."""

_URI: Final = re.compile(URI_EXPRESSION)


def _is_uri(instance: object) -> bool:
    # A format applies to strings only. fullmatch, not $: $ also matches
    # before a final line feed.
    return not isinstance(instance, str) or _URI.fullmatch(instance) is not None


def format_checker() -> FormatChecker:
    """Return a new format checker carrying format uri only, for a Draft 2020-12 validator."""
    checker = FormatChecker(formats=())
    checker.checks("uri")(_is_uri)
    return checker
