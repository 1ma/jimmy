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

    private const string FLAG_SIGNATURE_MALLEABILITY = 'SignatureMalleabilityBitcoin';
    private const string FLAG_BER_ENCODING           = 'BerEncodedSignature';
    private const string FLAG_INVALID_ENCODING       = 'InvalidEncoding';
    private const string FLAG_MODIFIED_SIGNATURE     = 'ModifiedSignature';
    private const string FLAG_INVALID_SIGNATURE      = 'InvalidSignature';
    private const string FLAG_INVALID_TYPES_IN_SIG   = 'InvalidTypesInSignature';

    #[DataProvider('wycheproofTestVectorProvider')]
    public function testWycheproofVectors(S256Point $publicKey, string $derSignature, string $rawMessage, array $flags, bool $result): void
    {
        if (\in_array(self::FLAG_SIGNATURE_MALLEABILITY, $flags)) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('s is larger than N/2');
        }

        if (!empty(array_intersect([
            self::FLAG_BER_ENCODING,
            self::FLAG_INVALID_ENCODING,
            self::FLAG_MODIFIED_SIGNATURE,
            self::FLAG_INVALID_SIGNATURE,
            self::FLAG_INVALID_TYPES_IN_SIG,
        ], $flags))) {
            $this->expectException(\InvalidArgumentException::class);
            $this->expectExceptionMessage('Invalid DER signature');
        }

        $signature = Signature::parse($derSignature);
        $z         = gmp_import(hash('sha256', $rawMessage, true));

        self::assertSame($result, $publicKey->verify($z, $signature));
    }

    public static function wycheproofTestVectorProvider(): array
    {
        $root = json_decode(file_get_contents(self::ECDSA_BITCOIN_TESTS_PATH));

        $vector = [];
        foreach ($root->testGroups as $testGroup) {
            $publicKey = S256Point::parse(hex2bin($testGroup->publicKey->uncompressed));
            foreach ($testGroup->tests as $test) {
                $vector["Test #{$test->tcId}: {$test->comment}"] = [
                    $publicKey,
                    hex2bin($test->sig),
                    hex2bin($test->msg),
                    $test->flags,
                    'valid' === $test->result,
                ];
            }
        }

        return $vector;
    }
}
