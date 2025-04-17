<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;
use Bitcoin\Encoding;
use Bitcoin\Network;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PrivateKeyTest extends TestCase
{
    private const string BIP340_TEST_VECTOR_PATH = __DIR__.'/../../vendor/bitcoin/bips/bip-0340/test-vectors.csv';

    public function testWifSerialization(): void
    {
        $s1 = new PrivateKey(gmp_init(5003));
        $s2 = new PrivateKey(gmp_init(2021 ** 5));
        $s3 = new PrivateKey(gmp_init(0x54321DEADBEEF));

        self::assertSame('cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK', $s1->wif(compressed: true, mode: Network::TESTNET));
        self::assertSame('91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic', $s2->wif(compressed: false, mode: Network::TESTNET));
        self::assertSame('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a', $s3->wif(compressed: true, mode: Network::MAINNET));
    }

    public function testWifParsing(): void
    {
        self::assertEquals(gmp_init(5003), PrivateKey::fromWIF('cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK')->secret);
        self::assertEquals(gmp_init(2021 ** 5), PrivateKey::fromWIF('91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic')->secret);
        self::assertEquals(gmp_init(0x54321DEADBEEF), PrivateKey::fromWIF('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a')->secret);
    }

    #[DataProvider('bip340TestVectorProvider')]
    public function testSchnorrSignatures(
        int $testNumber,
        string $privateKey,
        string $publicKey,
        string $auxRand,
        string $message,
        string $expectedSignature,
        bool $expectedVerification,
    ): void {
        if (14 === $testNumber) {
            // The public key of test 14 is not valid, as it exceeds the secp256k1 field size
            $this->expectException(\InvalidArgumentException::class);
            self::assertFalse($expectedVerification);
        }

        $point = S256Point::liftX(gmp_import($publicKey));

        $signature = new Signature(
            gmp_import(substr($expectedSignature, 0, 32)),
            gmp_import(substr($expectedSignature, 32, 32)),
            true
        );

        self::assertSame($expectedVerification, $point->schnorr($message, $signature));

        if (empty($privateKey)) {
            return;
        }

        $key = new PrivateKey(gmp_import($privateKey));

        self::assertSame($publicKey, Encoding::serN($key->pubKey->x->num, 32));

        self::assertSame($expectedSignature, $key->schnorr($message, $auxRand)->bip340());
    }

    public static function bip340TestVectorProvider(): array
    {
        $f      = fopen(self::BIP340_TEST_VECTOR_PATH, 'r');
        $header = fgetcsv($f);

        $vectors = [];
        while (false !== $row = fgetcsv($f)) {
            $row = array_combine($header, $row);

            $description = "Test #{$row['index']}";
            if (!empty($row['comment'])) {
                $description .= ': '.$row['comment'];
            }

            $vectors[$description] = [
                (int) $row['index'],
                hex2bin($row['secret key']),
                hex2bin($row['public key']),
                hex2bin($row['aux_rand']),
                hex2bin($row['message']),
                hex2bin($row['signature']),
                'TRUE' === $row['verification result'],
            ];
        }

        fclose($f);

        return $vectors;
    }
}
