<?php

declare(strict_types=1);

namespace HopTop\Pact\Core\Jws;

use HopTop\Pact\PactError;

/**
 * A JWS, a JWK or a key set was rejected for a Reason (Go jws.Error).
 *
 * The message is Go's Error() text: "jws: <reason>", then ": detail" and ":
 * the message of the cause" when there are. The cause (a strict JSON error,
 * a resolver's exception) is getPrevious(). No message carries OpenSSL's
 * error text.
 */
final class JwsError extends PactError
{
    /**
     * @param Reason $reason the reason
     * @param string $detail what was found, such as the member name or the octet count
     */
    public function __construct(
        public readonly Reason $reason,
        public readonly string $detail = '',
        ?\Throwable $previous = null,
    ) {
        $s = $reason->message();
        if ($detail !== '') {
            $s .= ': ' . $detail;
        }
        if ($previous !== null) {
            $s .= ': ' . $previous->getMessage();
        }
        parent::__construct($s, 0, $previous);
    }
}
