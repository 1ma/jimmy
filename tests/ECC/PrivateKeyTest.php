<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\Network;
use PHPUnit\Framework\TestCase;

final class PrivateKeyTest extends TestCase
{
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
}
