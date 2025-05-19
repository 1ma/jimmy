<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\PublicKey;
use Bitcoin\ECC\S256Params;
use Bitcoin\ECC\Signature;
use Bitcoin\Encoding;
use Bitcoin\Network;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PrivateKeyTest extends TestCase
{
    private const string BIP340_TEST_VECTOR_PATH = __DIR__.'/../../vendor/bitcoin/bips/bip-0340/test-vectors.csv';

    public function testMakeSureNIsTheOrderOfTheGeneratorPoint(): void
    {
        $infinity = S256Params::G()->scalarMul(S256Params::N());

        self::assertTrue($infinity->atInfinity());
    }

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

    public function testKeyTweaking(): void
    {
        $t   = gmp_init('0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9');
        $prv = new PrivateKey(gmp_init('0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF'));

        self::assertSame($prv->tweak($t)->pubKey->sec(), $prv->pubKey->tweak($t)->sec());
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

        $pubKey = PublicKey::liftX(gmp_import($publicKey));

        $signature = new Signature(
            gmp_import(substr($expectedSignature, 0, 32)),
            gmp_import(substr($expectedSignature, 32, 32)),
            true
        );

        self::assertSame($expectedVerification, $pubKey->schnorr($message, $signature));

        if (empty($privateKey)) {
            return;
        }

        $key = new PrivateKey(gmp_import($privateKey));

        self::assertSame($publicKey, Encoding\Endian::toBE($key->pubKey->x->num, 32));

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

        $vectors['Test #100: Sample Nostr event signature'] = [
            100,
            '',
            hex2bin('07adfda9c5adc80881bb2a5220f6e3181e0c043b90fa115c4f183464022968e6'),
            '',
            hex2bin('d677b5efa1484e3461884d6ba01e78b7ced36ccfc4b5b873c0b4142ea574938f'),
            hex2bin('49352dbe20322a9cc40433537a147805e2541846c006a3e06d9f90faadb89c83ee6da24807fb9eddc6ed9a1d3c15cd5438df07ec6149d6bf48fe1312c9593567'),
            true,
        ];

        fclose($f);

        return $vectors;
    }
}
