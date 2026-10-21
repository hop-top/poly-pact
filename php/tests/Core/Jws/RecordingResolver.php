<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jws;

use HopTop\Pact\Core\Digest;
use HopTop\Pact\Core\Jws\KeyRequest;
use HopTop\Pact\Core\Jws\KeyResolver;
use HopTop\Pact\Core\Jws\KeySet;

/** A KeyResolver that records its requests and fails on demand. */
final class RecordingResolver implements KeyResolver
{
    /** @var list<KeyRequest> */
    public array $reqs = [];

    /** @var list<string> */
    public array $calls = [];

    public function __construct(
        private readonly ?KeySet $keys = null,
        private readonly Digest $jkt = new Digest(''),
        private readonly ?\Exception $keysErr = null,
        private readonly ?\Exception $holderErr = null,
    ) {}

    public function trustedKeys(KeyRequest $req): ?KeySet
    {
        $this->reqs[] = $req;
        $this->calls[] = 'trustedKeys';
        if ($this->keysErr !== null) {
            throw $this->keysErr;
        }

        return $this->keys;
    }

    public function holderJkt(KeyRequest $req): Digest
    {
        $this->reqs[] = $req;
        $this->calls[] = 'holderJkt';
        if ($this->holderErr !== null) {
            throw $this->holderErr;
        }

        return $this->jkt;
    }
}
