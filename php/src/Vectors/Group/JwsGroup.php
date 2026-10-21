<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\Group;

use HopTop\Pact\Core\Core;
use HopTop\Pact\Core\Digest;
use HopTop\Pact\Core\Evidence;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Jws\Jwk;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\JwsError;
use HopTop\Pact\Core\Jws\KeySet;
use HopTop\Pact\Core\Jws\StaticResolver;
use HopTop\Pact\Core\Jws\Verifier;
use HopTop\Pact\Core\Limits;
use HopTop\Pact\Core\Schema\Schema;
use HopTop\Pact\Core\Schema\SchemaError;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Fixtures;

/**
 * vectors/jws: verify each vector's compact JWS with Jws, or run one of the
 * array files (spec/v1.0/fixtures/vectors/jws/README.md).
 *
 * A verify vector builds its key sets and expected holder_jkt, verifies the
 * compact form, applies decode_as when set, and compares the outcome and,
 * for a rejection, the reason. Only a JwsError with a Reason counts as a
 * rejection; any other exception is a fail.
 */
final class JwsGroup implements Group
{
    /**
     * The reason the harness reports when a verified payload fails the
     * artifact layer: a strict decode as the decode_as type, its schema
     * definition and its pact_version.
     */
    public const PAYLOAD_SCHEMA = 'payload-schema';

    /** The array files of vectors/jws; every other file holds one verify vector. */
    public const THUMBPRINT_ID = 'vectors/jws/thumbprint';
    public const JWK_REJECT_ID = 'vectors/jws/jwk-reject';
    public const KEYS_ID = 'vectors/jws/appendix-c-keys';

    /** @var list<string> */
    public const VERIFY_MEMBERS = [
        'compact', 'decode_as', 'description', 'expect', 'expected_holder_jkt', 'expected_payload',
        'expected_typ', 'id', 'reject_reason', 'signature_valid', 'signer_jwk', 'trusted_keysets',
    ];

    public function run(string $root, Entry $e): void
    {
        Fixtures::singleFile($e);
        match ($e->id) {
            self::THUMBPRINT_ID => self::thumbprints($root, $e),
            self::JWK_REJECT_ID => self::jwkRejects($root, $e),
            self::KEYS_ID => self::keys($root, $e),
            default => self::verify($root, $e),
        };
    }

    /** The Reason value of a rejection, or a Fail for an exception without one. */
    public static function reason(\Throwable $err): string
    {
        $r = Jws::reasonOf($err);
        if ($r === null) {
            throw new Fail(\sprintf('error without a reason: %s: %s', $err::class, $err->getMessage()), 0, $err);
        }

        return $r->value;
    }

    /** Parse a fixture JWK as a public key; a refusal is a Fail. */
    public static function parseJwk(mixed $raw, string $where): Jwk
    {
        try {
            return Jws::parseJwk(Fixtures::dumpJson($raw));
        } catch (JwsError $err) {
            throw new Fail($where . ': ' . $err->getMessage(), 0, $err);
        }
    }

    /**
     * Apply the artifact layer after verification; payload-schema when it
     * refuses, null when it accepts.
     */
    public static function decodeArtifact(string $typ, string $payload): ?string
    {
        if ($typ !== 'Evidence') {
            throw new Fail(\sprintf('decode_as %s is not handled', json_encode($typ)));
        }
        $limits = Limits::defaults()->artifactJson();
        try {
            $ev = StrictJson::decode($payload, Evidence::class, $limits);
            Schema::validate('Evidence', $payload, $limits);
        } catch (StrictJsonError|SchemaError) {
            return self::PAYLOAD_SCHEMA;
        }

        return $ev->pact_version === Core::VERSION ? null : self::PAYLOAD_SCHEMA;
    }

    private static function verify(string $root, Entry $e): void
    {
        $v = Fixtures::obj(Fixtures::readJson($root, $e->path), $e->path, self::VERIFY_MEMBERS);
        if ($v->get('id') !== $e->id) {
            throw new Fail(\sprintf('vector id %s, manifest id %s', json_encode($v->get('id')), json_encode($e->id)));
        }
        $want = $v->get('reject_reason');
        $expect = $v->get('expect');
        if (!(($expect === 'accept' && $want === null && $e->outcome === 'ACCEPTED') || ($expect === 'reject' && \is_string($want) && $e->outcome === 'REJECTED'))) {
            throw new Fail(\sprintf('expect %s, reject_reason and outcome %s do not agree', json_encode($expect), json_encode($e->outcome)));
        }
        $keysets = $v->get('trusted_keysets');
        if (!$keysets instanceof JsonObject) {
            throw new Fail('trusted_keysets: not an object');
        }
        $sets = [];
        foreach ($keysets as $role => $keys) {
            if (!\is_array($keys) || !array_is_list($keys)) {
                throw new Fail(\sprintf('trusted_keysets.%s: not an array', $role));
            }
            $parsed = array_map(static fn(mixed $k): Jwk => self::parseJwk($k, 'trusted key for ' . $role), $keys);
            try {
                $sets[$role] = new KeySet(...$parsed);
            } catch (JwsError $err) {
                throw new Fail(\sprintf('key set for %s: %s', $role, $err->getMessage()), 0, $err);
            }
        }
        $jkt = Fixtures::str($v->get('expected_holder_jkt'), 'expected_holder_jkt', true);
        $verifier = new Verifier(
            new StaticResolver($sets, $jkt === '' ? null : new Digest($jkt)),
            Fixtures::str($v->get('expected_typ'), 'expected_typ', true),
        );
        $decodeAs = $v->get('decode_as');
        $got = null;
        $payload = '';
        try {
            $payload = $verifier->verify(Fixtures::str($v->get('compact'), 'compact'))->payload;
            if ($decodeAs !== null) {
                $got = self::decodeArtifact(Fixtures::str($decodeAs, 'decode_as'), $payload);
            }
        } catch (Fail $f) {
            throw $f;
        } catch (\Throwable $err) {
            $got = self::reason($err);
        }
        if ($expect === 'accept') {
            if ($got !== null) {
                throw new Fail(\sprintf('rejected (%s), want accept', $got));
            }
            $wantPayload = $v->get('expected_payload');
            if (!\is_string($wantPayload) || $payload !== $wantPayload) {
                throw new Fail(\sprintf('payload %s differs from expected_payload', json_encode($payload, \JSON_INVALID_UTF8_SUBSTITUTE)));
            }

            return;
        }
        if ($got !== $want) {
            throw new Fail(\sprintf('reason %s, want %s', json_encode($got), json_encode($want)));
        }
    }

    private static function thumbprints(string $root, Entry $e): void
    {
        if ($e->outcome !== 'ACCEPTED') {
            throw new Fail(\sprintf('outcome %s is not ACCEPTED', json_encode($e->outcome)));
        }
        foreach (Fixtures::arr(Fixtures::readJson($root, $e->path), $e->path) as $i => $raw) {
            $v = Fixtures::obj($raw, \sprintf('vector %d', $i), ['id', 'jwk', 'expected_thumbprint'], ['description', 'source']);
            $id = Fixtures::str($v->get('id'), 'id');
            $tp = Jws::thumbprint(self::parseJwk($v->get('jwk'), $id))->value;
            if ($tp !== $v->get('expected_thumbprint')) {
                throw new Fail(\sprintf('%s: thumbprint %s, want %s', $id, $tp, json_encode($v->get('expected_thumbprint'))));
            }
        }
    }

    private static function jwkRejects(string $root, Entry $e): void
    {
        if ($e->outcome !== 'REJECTED') {
            throw new Fail(\sprintf('outcome %s is not REJECTED', json_encode($e->outcome)));
        }
        foreach (Fixtures::arr(Fixtures::readJson($root, $e->path), $e->path) as $i => $raw) {
            $v = Fixtures::obj($raw, \sprintf('vector %d', $i), ['id', 'jwk', 'reject_reason'], ['description']);
            $id = Fixtures::str($v->get('id'), 'id');
            $got = null;
            try {
                Jws::thumbprint(Jws::parseJwk(Fixtures::dumpJson($v->get('jwk'))));
            } catch (\Throwable $err) {
                $got = self::reason($err);
            }
            if ($got !== $v->get('reject_reason')) {
                throw new Fail(\sprintf('%s: reason %s, want %s', $id, json_encode($got), json_encode($v->get('reject_reason'))));
            }
        }
    }

    private static function keys(string $root, Entry $e): void
    {
        foreach (Fixtures::arr(Fixtures::readJson($root, $e->path), $e->path) as $i => $raw) {
            $v = Fixtures::obj($raw, \sprintf('vector %d', $i), ['id', 'd', 'expected_x', 'expected_y', 'expected_thumbprint'], ['description']);
            $id = Fixtures::str($v->get('id'), 'id');
            $d = Fixtures::b64url(Fixtures::str($v->get('d'), $id . ': d'), $id . ': d');
            if (\strlen($d) !== 32) {
                throw new Fail($id . ': d is not 32 octets of base64url');
            }
            $k = Jws::publicJwk(KeyGroup::privateKey($d, $id));
            if ($k->x !== $v->get('expected_x') || $k->y !== $v->get('expected_y')) {
                throw new Fail(\sprintf('%s: derived x=%s y=%s, want x=%s y=%s', $id, $k->x, $k->y, json_encode($v->get('expected_x')), json_encode($v->get('expected_y'))));
            }
            $tp = Jws::thumbprint($k)->value;
            if ($tp !== $v->get('expected_thumbprint')) {
                throw new Fail(\sprintf('%s: thumbprint %s, want %s', $id, $tp, json_encode($v->get('expected_thumbprint'))));
            }
        }
    }
}
