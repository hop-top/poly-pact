<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Schema;

use Opis\JsonSchema\Format;

/**
 * JSON Schema format uri per RFC 3986: the expression every PACT SDK shares
 * (spec/v1.0/fixtures/vectors/schema/README.md of the source repository,
 * which the vectors of uri-format.json pin), matched against the whole
 * string. It is registered in place of the checker of opis/json-schema,
 * which accepts a trailing line feed.
 *
 * URI_EXPRESSION is derived from the "uri" expression of ajv-formats 3.0.1
 * (src/formats.ts), which is under the MIT License:
 *
 * Copyright (c) 2020 Evgeny Poberezkin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The changes: ASCII classes instead of the case-insensitive flag
 * ([a-zA-Z], [0-9a-fA-F], [0-9]: a case-insensitive Unicode match folds
 * U+212A KELVIN SIGN and U+017F LONG S into [a-z], and \d can match
 * non-ASCII digits, while RFC 3986 section 2 allows US-ASCII only); the
 * rootless-path alternative of hier-part is optional, so "https:" matches
 * (hier-part may be path-empty, RFC 3986 section 3); the authority
 * alternative starts with "//", not "/?/" (RFC 3986 sections 3 and 3.3).
 */
final class UriFormat implements Format
{
    /** The RFC 3986 URI expression of format uri, matched against the whole string with no flags. */
    public const string URI_EXPRESSION = '^(?:[a-zA-Z][a-zA-Z0-9+\\-.]*:)(?:\\/\\/(?:(?:[a-zA-Z0-9\\-._~!$&\'()*+,;=:]|%[0-9a-fA-F]{2})'
        . '*@)?(?:\\[(?:(?:(?:(?:[0-9a-fA-F]{1,4}:){6}|::(?:[0-9a-fA-F]{1,4}:){5}|(?:[0-9a-fA-F]{1,4'
        . '})?::(?:[0-9a-fA-F]{1,4}:){4}|(?:(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4})?::(?:[0-9a-'
        . 'fA-F]{1,4}:){3}|(?:(?:[0-9a-fA-F]{1,4}:){0,2}[0-9a-fA-F]{1,4})?::(?:[0-9a-fA-F]{1,4}:){2'
        . '}|(?:(?:[0-9a-fA-F]{1,4}:){0,3}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}:|(?:(?:[0-9a-fA-F]{1'
        . ',4}:){0,4}[0-9a-fA-F]{1,4})?::)(?:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}|(?:(?:25[0-5]|2[0-4]'
        . '[0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))|(?:(?:[0-9a-fA-F]'
        . '{1,4}:){0,5}[0-9a-fA-F]{1,4})?::[0-9a-fA-F]{1,4}|(?:(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F'
        . ']{1,4})?::)|[Vv][0-9a-fA-F]+\\.[a-zA-Z0-9\\-._~!$&\'()*+,;=:]+)\\]|(?:(?:25[0-5]|2[0-4][0-9]'
        . '|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[a-zA-Z0-9\\-._~!$&\'('
        . ')*+,;=]|%[0-9a-fA-F]{2})*)(?::[0-9]*)?(?:\\/(?:[a-zA-Z0-9\\-._~!$&\'()*+,;=:@]|%[0-9a-fA-F]'
        . '{2})*)*|\\/(?:(?:[a-zA-Z0-9\\-._~!$&\'()*+,;=:@]|%[0-9a-fA-F]{2})+(?:\\/(?:[a-zA-Z0-9\\-._~!$'
        . '&\'()*+,;=:@]|%[0-9a-fA-F]{2})*)*)?|(?:(?:[a-zA-Z0-9\\-._~!$&\'()*+,;=:@]|%[0-9a-fA-F]{2})+'
        . '(?:\\/(?:[a-zA-Z0-9\\-._~!$&\'()*+,;=:@]|%[0-9a-fA-F]{2})*)*)?)(?:\\?(?:[a-zA-Z0-9\\-._~!$&\'('
        . ')*+,;=:@/?]|%[0-9a-fA-F]{2})*)?(?:#(?:[a-zA-Z0-9\\-._~!$&\'()*+,;=:@/?]|%[0-9a-fA-F]{2})*)'
        . '?$';

    /**
     * Whether $s is a URI per RFC 3986. The PCRE D modifier makes $ match at
     * the very end only, not before a final line feed; without u the classes
     * see bytes, so any non-ASCII byte fails. A PCRE failure is a mismatch.
     */
    public static function matches(string $s): bool
    {
        return preg_match("\x07" . self::URI_EXPRESSION . "\x07D", $s) === 1;
    }

    /** The opis Format: a value that is not a string is not checked. */
    public function validate(mixed $data): bool
    {
        return !\is_string($data) || self::matches($data);
    }
}
