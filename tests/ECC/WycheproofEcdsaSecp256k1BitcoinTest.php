<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WycheproofEcdsaSecp256k1BitcoinTest extends TestCase
{
    private const string ECDSA_BITCOIN_TESTS_PATH = __DIR__.'/../../vendor/c2sp/wycheproof/testvectors_v1/ecdsa_secp256k1_sha256_bitcoin_test.json';

    private const string FLAG_SIGNATURE_MALLEABILITY = 'SignatureMalleabilityBitcoin';
    private const string FLAG_BER_ENCODING           = 'BerEncodedSignature';
    private const string FLAG_INVALID_ENCODING       = 'InvalidEncoding';
    private const string FLAG_MODIFIED_SIGNATURE     = 'ModifiedSignature';
    private const string FLAG_INVALID_SIGNATURE      = 'InvalidSignature';
    private const string FLAG_INVALID_TYPES_IN_SIG   = 'InvalidTypesInSignature';
    private const string FLAG_RANGE_CHECK            = 'RangeCheck';
    private const string FLAG_MODIFIED_INTEGER       = 'ModifiedInteger';
    private const string FLAG_INTEGER_OVERFLOW       = 'IntegerOverflow';

    private const array NON_EXCEPTION_VECTORS = [
        97, 98, 99, 104, 140, 141, 142, 147,
        148, 150, 152, 154, 156, 158, 161, 164,
        165, 172, 173, 188, 189, 196, 197, 204,
        205, 212, 213, 220, 221,
    ];

    private const array NON_FLAGGED_EXCEPTION_VECTORS = [
        358, 388,
    ];

    #[DataProvider('wycheproofTestVectorProvider')]
    public function testWycheproofVectors(int $tcId, S256Point $publicKey, string $derSignature, string $rawMessage, array $testFlags, bool $expectedResult): void
    {
        if ((!\in_array($tcId, self::NON_EXCEPTION_VECTORS) && !empty(array_intersect([
            self::FLAG_SIGNATURE_MALLEABILITY,
            self::FLAG_BER_ENCODING,
            self::FLAG_INVALID_ENCODING,
            self::FLAG_MODIFIED_SIGNATURE,
            self::FLAG_INVALID_SIGNATURE,
            self::FLAG_INVALID_TYPES_IN_SIG,
            self::FLAG_RANGE_CHECK,
            self::FLAG_MODIFIED_INTEGER,
            self::FLAG_INTEGER_OVERFLOW,
        ], $testFlags))) || \in_array($tcId, self::NON_FLAGGED_EXCEPTION_VECTORS)) {
            $this->expectException(\InvalidArgumentException::class);
        }

        $signature = Signature::parse($derSignature);
        $z         = gmp_import(hash('sha256', $rawMessage, true));

        self::assertSame($expectedResult, $publicKey->verify($z, $signature));
    }

    public static function wycheproofTestVectorProvider(): array
    {
        $root = json_decode(file_get_contents(self::ECDSA_BITCOIN_TESTS_PATH));

        $vectors = [];
        foreach ($root->testGroups as $testGroup) {
            $publicKey = S256Point::parse(hex2bin($testGroup->publicKey->uncompressed));
            foreach ($testGroup->tests as $test) {
                $vectors["Test #{$test->tcId}: {$test->comment}"] = [
                    $test->tcId,
                    $publicKey,
                    hex2bin($test->sig),
                    hex2bin($test->msg),
                    $test->flags,
                    'valid' === $test->result,
                ];
            }
        }

        return $vectors;
    }
}
