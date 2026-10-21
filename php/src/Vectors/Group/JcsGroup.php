<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\Group;

use HopTop\Pact\Core\Jcs\Jcs;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Fixtures;

/**
 * vectors/jcs: canonicalize the input file and compare byte for byte with
 * the expected file; or, for the number list (path and expected the same
 * file), canonicalize a 17-digit exponent literal of each double and compare
 * with its expected text.
 */
final class JcsGroup implements Group
{
    public function run(string $root, Entry $e): void
    {
        if ($e->expected === null) {
            throw new Fail('expected is null');
        }
        if ($e->outcome !== 'ACCEPTED') {
            throw new Fail(\sprintf('outcome %s, want ACCEPTED', json_encode($e->outcome)));
        }
        if ($e->path === $e->expected) {
            self::numbers($root, $e->path);

            return;
        }
        $data = Fixtures::read($root, $e->path);
        $want = Fixtures::read($root, $e->expected);
        $got = Jcs::canonicalize($data);
        if ($got !== $want) {
            throw new Fail(\sprintf('canonical form %s, want %s', json_encode($got, \JSON_INVALID_UTF8_SUBSTITUTE), json_encode($want, \JSON_INVALID_UTF8_SUBSTITUTE)));
        }
        if (Jcs::canonicalize($want) !== $want) {
            throw new Fail('the expected output is not canonical');
        }
    }

    private static function numbers(string $root, string $rel): void
    {
        foreach (Fixtures::arr(Fixtures::readJson($root, $rel), $rel) as $i => $raw) {
            $v = Fixtures::obj($raw, \sprintf('number %d', $i), ['ieee754_hex', 'expected']);
            $hex = $v->get('ieee754_hex');
            $want = $v->get('expected');
            $bits = \is_string($hex) && preg_match('/\A[0-9a-f]{16}\z/', $hex) === 1 ? hex2bin($hex) : false;
            if ($bits === false || !\is_string($want) || $want === '') {
                throw new Fail(\sprintf('number %d is malformed', $i));
            }
            $f = unpack('E', $bits);
            if (!\is_array($f) || !\is_float($f[1]) || !is_finite($f[1])) {
                throw new Fail(\sprintf('number %d is not a finite double', $i));
            }
            // 17 significant digits name the double exactly; the literal is
            // valid JSON whatever its magnitude.
            $got = Jcs::canonicalize(\sprintf('%.16e', $f[1]));
            if ($got !== $want) {
                throw new Fail(\sprintf('%s: canonical form %s, want %s', $hex, $got, $want));
            }
        }
    }
}
