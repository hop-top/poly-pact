<?php

declare(strict_types=1);

namespace HopTop\Pact\Vectors\Group;

use HopTop\Pact\Core\OperationContext;
use HopTop\Pact\Core\StrictJson\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Core\StrictJson\StrictJsonError;
use HopTop\Pact\Vectors\Entry;
use HopTop\Pact\Vectors\Fail;
use HopTop\Pact\Vectors\Fixtures;

/** vectors/strictjson: strict-decode the input as an OperationContext; accept or reject as expect says. */
final class StrictJsonGroup implements Group
{
    public function run(string $root, Entry $e): void
    {
        Fixtures::singleFile($e);
        $v = Fixtures::obj(Fixtures::readJson($root, $e->path), $e->path, ['id', 'expect', 'reason'], ['input_text', 'input_b64']);
        if ($v->get('id') !== $e->id || \in_array($v->get('reason'), ['', null], true)) {
            throw new Fail(\sprintf('vector id %s (manifest %s) or empty reason', json_encode($v->get('id')), json_encode($e->id)));
        }
        $text = Fixtures::str($v->get('input_text', ''), 'input_text');
        $b64 = Fixtures::str($v->get('input_b64', ''), 'input_b64');
        if ($text !== '' && $b64 !== '') {
            throw new Fail('both input_text and input_b64 are set');
        }
        if ($b64 !== '') {
            $data = preg_match('/\A[A-Za-z0-9+\/]*={0,2}\z/', $b64) === 1 && \strlen($b64) % 4 === 0 ? base64_decode($b64, true) : false;
            if ($data === false) {
                throw new Fail('input_b64: not padded standard base64');
            }
        } elseif ($text !== '') {
            $data = $text;
        } else {
            throw new Fail('no input');
        }
        $expect = $v->get('expect');
        $want = ['accept' => 'ACCEPTED', 'reject' => 'REJECTED'][\is_string($expect) ? $expect : ''] ?? null;
        if ($want === null || $want !== $e->outcome) {
            throw new Fail(\sprintf('expect %s does not agree with outcome %s', json_encode($expect), json_encode($e->outcome)));
        }
        try {
            StrictJson::decode($data, OperationContext::class, new Limits());
        } catch (StrictJsonError $err) {
            if ($expect === 'accept') {
                throw new Fail(\sprintf('rejected (%s), want accept', $err->getMessage()), 0, $err);
            }

            return;
        }
        if ($expect === 'reject') {
            throw new Fail('accepted, want reject');
        }
    }
}
