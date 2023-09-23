<?php

declare(strict_types=1);

use Bitcoin\PrivateKey;
use Bitcoin\S256Field;
use Bitcoin\S256Point;
use PHPUnit\Framework\TestCase;

final class S256PointTest extends TestCase
{
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
    }
}
