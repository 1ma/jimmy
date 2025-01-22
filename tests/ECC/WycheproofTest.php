<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WycheproofTest extends TestCase
{
    private const string ECDSA_BITCOIN_TESTS_PATH = __DIR__.'/../../vendor/c2sp/wycheproof/testvectors_v1/ecdsa_secp256k1_sha256_bitcoin_test.json';

    #[DataProvider('wycheproofVectorProvider')]
    public function testWycheproofVectors(S256Point $publicKey, string $derSignature, string $rawMessage, bool $result): void
    {
        try {
            $signature = Signature::parse($derSignature);
        } catch (\InvalidArgumentException $e) {
            self::assertTrue('s is larger than N/2' === $e->getMessage());

            return;
        }

        $z = gmp_import(hash('sha256', $rawMessage, true));

        self::assertSame($result, $publicKey->verify($z, $signature));
    }

    public static function wycheproofVectorProvider(): array
    {
        $root = json_decode(file_get_contents(self::ECDSA_BITCOIN_TESTS_PATH));

        $group0 = $root->testGroups[0];

        $publicKey = S256Point::parse(hex2bin($group0->publicKey->uncompressed));
        $tests     = $group0->tests;

        $data = [];
        for ($i = 0; $i < 2; ++$i) {
            $data["Test #{$tests[$i]->tcId}: {$tests[$i]->comment}"] = [
                $publicKey,
                hex2bin($tests[$i]->sig),
                hex2bin($tests[$i]->msg),
                'valid' === $tests[$i]->result,
            ];
        }

        return $data;
    }
}
