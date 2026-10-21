<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\Core\StrictJson\Utf8;

/**
 * JSON string text as Go's encoding/json writes it.
 *
 * @internal
 */
final class Text
{
    private function __construct() {}

    /**
     * The JSON text of $s as Go's encoding/json writes it with
     * SetEscapeHTML(false): U+2028 and U+2029 escaped, other non-ASCII
     * characters raw, control characters escaped, and each byte that starts
     * no valid UTF-8 sequence written as the six characters \ufffd.
     * json_encode() agrees on valid UTF-8 but substitutes a raw U+FFFD once
     * per invalid sequence, so invalid bytes are handled here.
     */
    public static function quote(string $s): string
    {
        $out = '';
        while ($s !== '') {
            $i = Utf8::firstInvalid($s);
            if ($i > 0) {
                $out .= substr(json_encode(substr($s, 0, $i), \JSON_UNESCAPED_SLASHES | \JSON_UNESCAPED_UNICODE | \JSON_THROW_ON_ERROR), 1, -1);
            }
            if ($i < \strlen($s)) {
                $out .= '\ufffd';
                ++$i;
            }
            $s = substr($s, $i);
        }

        return '"' . $out . '"';
    }
}
