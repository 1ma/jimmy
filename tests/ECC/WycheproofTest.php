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

    /**
     * Format:
     *  tcId => [expected exception class, expected exception message]
     */
    private const array EXPECTED_EXCEPTIONS = [
        1 => [\InvalidArgumentException::class, 's is larger than N/2'],
    ];

    #[DataProvider('wycheproofVectorProvider')]
    public function testWycheproofVectors(int $tcId, S256Point $publicKey, string $derSignature, string $rawMessage, bool $result): void
    {
        if (\array_key_exists($tcId, self::EXPECTED_EXCEPTIONS)) {
            $this->expectException(self::EXPECTED_EXCEPTIONS[$tcId][0]);
            $this->expectExceptionMessage(self::EXPECTED_EXCEPTIONS[$tcId][1]);
        }

        $signature = Signature::parse($derSignature);
        $z         = gmp_import(hash('sha256', $rawMessage, true));

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
                $tests[$i]->tcId,
                $publicKey,
                hex2bin($tests[$i]->sig),
                hex2bin($tests[$i]->msg),
                'valid' === $tests[$i]->result,
            ];
        }

        return $data;
    }
}
