<?php

declare(strict_types=1);

namespace HopTop\Pact\Tests\Core\Jws;

use HopTop\Pact\Core\Core;
use HopTop\Pact\Core\Evidence;
use HopTop\Pact\Core\JsonObject;
use HopTop\Pact\Core\Jws\Header;
use HopTop\Pact\Core\Jws\Jwk;
use HopTop\Pact\Core\Jws\Jws;
use HopTop\Pact\Core\Jws\KeySet;
use HopTop\Pact\Core\Jws\Reason;
use HopTop\Pact\Core\Jws\Role;
use HopTop\Pact\Core\Jws\StaticResolver;
use HopTop\Pact\Core\Jws\Verifier;
use HopTop\Pact\Core\Limits;
use HopTop\Pact\Core\StrictJson\StrictJson;
use HopTop\Pact\Tests\Repo;
use PHPUnit\Framework\TestCase;

/**
 * The profile against the draft: the section 7.3 typ table, the section 20.1
 * frame minimum and the Appendix C keys and JWS. Port of
 * go/core/jws/draft_test.go and TestSignMatchesAppendixCHeader of
 * sign_test.go, and of the Python port's test_jws_draft.py.
 *
 * It reads spec/v1.0/draft.md and spec/v1.0/fixtures: it fails when they are
 * absent under PACT_REQUIRE_VECTORS=1 and skips otherwise.
 */
final class DraftTest extends TestCase
{
    /**
     * The "Required signer" cells of the draft 7.3 table and their roles. A
     * changed cell fails testTypTableMatchesDraft until it is mapped.
     */
    private const SIGNER_ROLES = [
        'Gateway-authorized requirement publisher' => Role::REQUIREMENT_PUBLISHER,
        'Issuer authorized for its claim paths and scope' => Role::ISSUER,
        'Enrolled agent holder key' => Role::HOLDER,
        'Gateway-authorized validator' => Role::VALIDATOR,
        'Authorized reporter for the observation type' => Role::REPORTER,
        'Authorized reputation service' => Role::REPUTATION_SERVICE,
        'Native administrator or delegated policy authority' => Role::POLICY_AUTHORITY,
        'Authorized learning controller' => Role::LEARNING_CONTROLLER,
        'Controller authorized for that transition' => Role::LEARNING_CONTROLLER,
    ];

    private static function draft(): string
    {
        return Repo::read('spec/v1.0/draft.md');
    }

    /** The draft text from the heading $start up to the heading $end. */
    private static function section(string $draft, string $start, string $end): string
    {
        $i = strpos($draft, $start);
        self::assertNotFalse($i, 'draft has no ' . $start);
        $j = strpos($draft, $end, $i);
        self::assertNotFalse($j, \sprintf('draft has no %s after %s', $end, $start));

        return substr($draft, $i, $j - $i);
    }

    /** The body of the first fenced block of $lang after $marker. */
    private static function fenced(string $text, string $marker, string $lang): string
    {
        $i = strpos($text, $marker);
        self::assertNotFalse($i, 'no ' . $marker);
        $open = '```' . $lang . "\n";
        $j = strpos($text, $open, $i);
        self::assertNotFalse($j, \sprintf('no %s block after %s', $lang, $marker));
        $body = substr($text, $j + \strlen($open));
        $k = strpos($body, "\n```");
        self::assertNotFalse($k, \sprintf('unterminated %s block after %s', $lang, $marker));

        return substr($body, 0, $k);
    }

    private static function appendixC(): string
    {
        return self::section(self::draft(), '## Appendix C.', '## Appendix D.');
    }

    private static function appendixCCompact(): string
    {
        return trim(self::fenced(self::appendixC(), 'Exact compact evidence JWS:', 'text'));
    }

    private static function appendixB5(): string
    {
        return self::fenced(self::draft(), '### B.5 Runtime evidence', 'json');
    }

    public function testTypTableMatchesDraft(): void
    {
        $table = self::section(self::draft(), '### 7.3 Artifact types and claims', '### 7.4');
        preg_match_all('/^\| ([^|]+?) \| `([^`]+)` \| ([^|]+?) \|$/m', $table, $rows, \PREG_SET_ORDER);
        self::assertNotEmpty($rows, 'no typ rows found in draft 7.3');
        $typs = [];
        foreach ($rows as [, , $typ, $signer]) {
            $typs[] = $typ;
            self::assertArrayHasKey($signer, self::SIGNER_ROLES, \sprintf('draft 7.3 signer %s (typ %s) has no role', $signer, $typ));
            self::assertSame(self::SIGNER_ROLES[$signer], Jws::typRole($typ), $typ);
        }
        self::assertSame($typs, Jws::typs());
        foreach (['', 'JWT', 'pact-profile+jwt', 'pact-evidence+JWT'] as $typ) {
            self::assertNull(Jws::typRole($typ), $typ);
        }
        // The constants name the same values, in the table's order.
        self::assertSame($typs, [
            Jws::TYP_REQUIREMENTS,
            Jws::TYP_EVIDENCE,
            Jws::TYP_PRESENTATION,
            Jws::TYP_ADMISSION,
            Jws::TYP_OUTCOME,
            Jws::TYP_REPUTATION,
            Jws::TYP_LEARNING_POLICY,
            Jws::TYP_LEARNING_ARTIFACT,
            Jws::TYP_LEARNING_EVENT,
        ]);
    }

    public function testDefaultMaxCompactBytesMatchesDraft(): void
    {
        // Section 20.1: the frame minimum covers an encoded 256 KiB payload plus the JOSE header and signature.
        self::assertStringContainsString('349526 + 10922 = 360448', self::draft());
        self::assertSame(360448, Jws::DEFAULT_MAX_COMPACT_BYTES);
    }

    /**
     * The public keys of P-256 scalars 1 (holder) and 2 (issuer) are the JWKs
     * printed in Appendix C, and the holder thumbprint is the printed
     * holder_jkt.
     */
    public function testAppendixCKeys(): void
    {
        $c = self::appendixC();
        $ip = Jws::parseJwk(self::fenced($c, 'Issuer public JWK', 'json'));
        $holder = StrictJson::parse(self::fenced($c, 'Holder public JWK and thumbprint', 'json'));
        self::assertInstanceOf(JsonObject::class, $holder);
        $hp = $holder->get('jwk');
        self::assertInstanceOf(JsonObject::class, $hp);
        foreach ([1 => [$hp->get('x'), $hp->get('y')], 2 => [$ip->x, $ip->y]] as $scalar => $xy) {
            $k = Jws::publicJwk(Keys::scalarKey($scalar));
            self::assertSame($xy, [$k->x, $k->y], 'scalar ' . $scalar);
            if ($scalar === 1) {
                self::assertSame($holder->get('holder_jkt'), Jws::thumbprint($k)->value);
                self::assertSame(Keys::HOLDER_JKT, Jws::thumbprint($k)->value);
            }
        }
        self::assertSame('test-issuer-key-1', $ip->kid);
    }

    /**
     * The exact compact evidence JWS of Appendix C verifies under the printed
     * issuer JWK and meets every expectation the appendix states.
     */
    public function testAppendixCJws(): void
    {
        $c = self::appendixC();
        $issuer = Jws::parseJwk(self::fenced($c, 'Issuer public JWK', 'json'));
        $res = new StaticResolver([Role::ISSUER->value => new KeySet($issuer)]);
        $p = (new Verifier($res, Jws::TYP_EVIDENCE))->verify(self::appendixCCompact());
        self::assertSame(['pact-evidence+jwt', Role::ISSUER], [$p->header->typ, $p->role]);
        self::assertSame(self::appendixB5(), $p->payload);
        $ev = StrictJson::decode($p->payload, Evidence::class, Limits::defaults()->artifactJson());
        self::assertSame(Core::VERSION, $ev->pact_version);
        self::assertSame('https://identity.example/agents/invoice-assistant', $ev->sub);
        self::assertCount(1, $ev->claims);
        self::assertSame(['/attributes/runtime/isolation', 'managed'], [$ev->claims[0]->path, $ev->claims[0]->value]);
        self::assertSame(Keys::HOLDER_JKT, $ev->holder_jkt);
        // Not under the holder key.
        $hk = Keys::fixtureJwk('holder');
        $wrong = new StaticResolver([Role::ISSUER->value => new KeySet(new Jwk($hk->kty, $hk->crv, $hk->x, $hk->y, 'test-issuer-key-1'))]);
        Keys::wantReason(static fn() => Jws::verify(self::appendixCCompact(), $wrong), Reason::SIGNATURE_INVALID);
    }

    /**
     * The earlier Appendix C JWS has a valid signature but carries
     * pact_version 0.2, which the schema constant (0.1) rejects.
     */
    public function testAppendixCVersionMismatch(): void
    {
        $compact = trim(Repo::read('spec/v1.0/fixtures/parse/appendix-c-wrong-version.jws'));
        $res = new StaticResolver([Role::ISSUER->value => new KeySet(Keys::fixtureJwk('issuer'))]);
        $p = (new Verifier($res, Jws::TYP_EVIDENCE))->verify($compact);
        $ev = StrictJson::decode($p->payload, Evidence::class, Limits::defaults()->artifactJson());
        self::assertSame('0.2', $ev->pact_version);
        self::assertNotSame(Core::VERSION, $ev->pact_version);
    }

    /**
     * The header sign() writes for an evidence artifact is the protected
     * header of the Appendix C JWS, byte for byte, and the payload is signed
     * as given.
     */
    public function testSignMatchesAppendixCHeader(): void
    {
        $want = explode('.', self::appendixCCompact());
        $got = explode('.', Jws::sign(new Header(typ: Jws::TYP_EVIDENCE, kid: 'test-issuer-key-1'), self::appendixB5(), Keys::scalarKey(2)));
        self::assertSame($want[0], $got[0]);
        self::assertSame($want[1], $got[1], 'the payload bytes were changed');
    }
}
