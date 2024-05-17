<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\S256Field;
use Bitcoin\ECC\S256Params;
use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;
use Bitcoin\Encoding;
use Bitcoin\Hashing;
use Bitcoin\Network;
use PHPUnit\Framework\TestCase;

final class S256PointTest extends TestCase
{
    public function testSecp256k1FundamentalProperties(): void
    {
        // Check that G is a point on the secp256k1 curve
        self::assertEquals(
            (S256Params::G()->y->num ** 2)     % S256Params::P(),
            (S256Params::G()->x->num ** 3 + 7) % S256Params::P()
        );

        // Check that G has the order n (i.e. n*G is the infinity point on secp256k1)
        self::assertSame('S256Point(,)', (string) S256Params::G()->scalarMul(S256Params::N()));
    }

    public function testRawSignatureVerification(): void
    {
        $z = gmp_init('0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423');
        $r = gmp_init('0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6');
        $s = gmp_init('0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec');

        $point = new S256Point(
            new S256Field('0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574'),
            new S256Field('0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4')
        );

        $sInv = gmp_powm($s, S256Params::N() - 2, S256Params::N());
        $u    = ($z * $sInv) % S256Params::N();
        $v    = ($r * $sInv) % S256Params::N();

        self::assertTrue($r == S256Params::G()->scalarMul($u)->add($point->scalarMul($v))->x->num);
    }

    public function testVerifySignaturesExercise6Chapter3(): void
    {
        $point = new S256Point(
            new S256Field('0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c'),
            new S256Field('0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
        );

        // signature #1
        $z = gmp_init('0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60');
        $r = gmp_init('0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395');
        $s = gmp_init('0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4');

        $sInv = gmp_powm($s, S256Params::N() - 2, S256Params::N());
        $u    = ($z * $sInv) % S256Params::N();
        $v    = ($r * $sInv) % S256Params::N();

        self::assertTrue($r == S256Params::G()->scalarMul($u)->add($point->scalarMul($v))->x->num);

        // signature #2
        $z = gmp_init('0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d');
        $r = gmp_init('0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c');
        $s = gmp_init('0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6');

        $sInv = gmp_powm($s, S256Params::N() - 2, S256Params::N());
        $u    = ($z * $sInv) % S256Params::N();
        $v    = ($r * $sInv) % S256Params::N();

        self::assertTrue($r == S256Params::G()->scalarMul($u)->add($point->scalarMul($v))->x->num);
    }

    public function testRawSignatureCreation(): void
    {
        $k = 1234567890;
        $e = gmp_import(Hashing::hash256('my secret'));
        $z = gmp_import(Hashing::hash256('my message'));

        $r     = S256Params::G()->scalarMul($k)->x->num;
        $kInv  = gmp_powm($k, S256Params::N() - 2, S256Params::N());
        $s     = (($z + $r * $e) * $kInv) % S256Params::N();
        $point = S256Params::G()->scalarMul($e);

        self::assertSame('S256Point(028d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52,0ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2)', (string) $point);
        self::assertSame('231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78', gmp_strval($z, 16));
        self::assertSame('2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22', gmp_strval($r, 16));
        self::assertSame('bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9', gmp_strval($s, 16));
    }

    public function testCreateSignatureExercise7Chapter3(): void
    {
        $k = 1234567890;
        $e = 12345;
        $z = gmp_import(Hashing::hash256('Programming Bitcoin!'));

        $r     = S256Params::G()->scalarMul($k)->x->num;
        $kInv  = gmp_powm($k, S256Params::N() - 2, S256Params::N());
        $s     = (($z + $r * $e) * $kInv) % S256Params::N();
        $point = S256Params::G()->scalarMul($e);

        self::assertSame('S256Point(f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f,0eba29d0f0c5408ed681984dc525982abefccd9f7ff01dd26da4999cf3f6a295)', (string) $point);
        self::assertSame('969f6056aa26f7d2795fd013fe88868d09c9f6aed96965016e1936ae47060d48', gmp_strval($z, 16));
        self::assertSame('2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22', gmp_strval($r, 16));
        self::assertSame('1dbc63bfef4416705e602a7b564161167076d8b20990a0f26f316cff2cb0bc1a', gmp_strval($s, 16));
    }

    public function testVerifySignatures(): void
    {
        // Test case based on exercise 6 from chapter 3

        $pubkey = new S256Point(
            new S256Field('0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c'),
            new S256Field('0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
        );

        $sig = new Signature(
            gmp_init('0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395'),
            gmp_init('0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4')
        );

        $z = gmp_init('0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60');

        self::assertTrue($pubkey->verify($z, $sig));
    }

    public function testCreateSignature(): void
    {
        // Test case partially based on exercise 7 from chapter 3 (k is not 1234567890)

        $z      = gmp_import(Hashing::hash256('Programming Bitcoin!'));
        $pvtKey = new PrivateKey(gmp_init(12345));
        $sig    = $pvtKey->sign($z);

        self::assertSame(
            'Signature(8eeacac05e4c29e793b5287ed044637132ce9ead7fded533e7441d87a8dc9c23,36674f81f10c7fb347c1224bd546813ea24ada6f642c02f2248516e3aa8cb303)',
            (string) $sig
        );

        self::assertTrue($pvtKey->pubKey->verify($z, $sig));
    }

    public function testInvalidSecData(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        S256Point::parse("\x00\x01\x02\x03");
    }

    public function testUncompressedSecFormat(): void
    {
        $pubKey = new S256Point(
            new S256Field('0x028d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52'),
            new S256Field('0x0ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2')
        );

        self::assertSame(
            hex2bin('04028d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c520ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2'),
            $pubKey->sec(false)
        );

        $s1 = new PrivateKey(gmp_init(5000));
        $s2 = new PrivateKey(gmp_init(2018 ** 5));
        $s3 = new PrivateKey(gmp_init(0xDEADBEEF12345));

        self::assertSame(
            hex2bin('04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10'),
            $s1->pubKey->sec(false)
        );

        self::assertSame(
            hex2bin('04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06'),
            $s2->pubKey->sec(false)
        );

        self::assertSame(
            hex2bin('04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121'),
            $s3->pubKey->sec(false)
        );

        $p1 = S256Point::parse($s1->pubKey->sec(false));
        $p2 = S256Point::parse($s2->pubKey->sec(false));
        $p3 = S256Point::parse($s3->pubKey->sec(false));

        self::assertTrue($p1->x->num == $s1->pubKey->x->num);
        self::assertTrue($p1->y->num == $s1->pubKey->y->num);
        self::assertTrue($p2->x->num == $s2->pubKey->x->num);
        self::assertTrue($p2->y->num == $s2->pubKey->y->num);
        self::assertTrue($p3->x->num == $s3->pubKey->x->num);
        self::assertTrue($p3->y->num == $s3->pubKey->y->num);
    }

    public function testCompressedSecFormat(): void
    {
        $s1 = new PrivateKey(gmp_init(5001));
        $s2 = new PrivateKey(gmp_init(2019 ** 5));
        $s3 = new PrivateKey(gmp_init(0xDEADBEEF54321));

        self::assertSame(
            hex2bin('0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1'),
            $s1->pubKey->sec()
        );

        self::assertSame(
            hex2bin('02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701'),
            $s2->pubKey->sec()
        );

        self::assertSame(
            hex2bin('0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690'),
            $s3->pubKey->sec()
        );

        $p1 = S256Point::parse($s1->pubKey->sec());
        $p2 = S256Point::parse($s2->pubKey->sec());
        $p3 = S256Point::parse($s3->pubKey->sec());

        self::assertTrue($p1->x->num == $s1->pubKey->x->num);
        self::assertTrue($p1->y->num == $s1->pubKey->y->num);
        self::assertTrue($p2->x->num == $s2->pubKey->x->num);
        self::assertTrue($p2->y->num == $s2->pubKey->y->num);
        self::assertTrue($p3->x->num == $s3->pubKey->x->num);
        self::assertTrue($p3->y->num == $s3->pubKey->y->num);
    }

    public function testAddressDerivations(): void
    {
        $s1 = new PrivateKey(gmp_init(5002));
        $s2 = new PrivateKey(gmp_init(2020 ** 5));
        $s3 = new PrivateKey(gmp_init(0x12345DEADBEEF));

        self::assertSame('mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA', $s1->pubKey->address(compressed: false, mode: Network::TESTNET));
        self::assertSame('mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH', $s2->pubKey->address(compressed: true, mode: Network::TESTNET));
        self::assertSame('1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1', $s3->pubKey->address(compressed: true, mode: Network::MAINNET));

        // Based on example from Chapter 6 page 120
        $sec    = hex2bin('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352');
        $pubkey = S256Point::parse($sec);

        self::assertSame('1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs', $pubkey->address(compressed: true, mode: Network::MAINNET));
        self::assertSame(Hashing::hash160($sec), Encoding::decodeLegacyAddress('1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'));
    }
}
