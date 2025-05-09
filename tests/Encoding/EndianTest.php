<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Encoding;

use Bitcoin\ECC\S256Params;
use Bitcoin\Encoding;
use PHPUnit\Framework\TestCase;

final class EndianTest extends TestCase
{
    public function testLittleEndianEncodingAndDecoding(): void
    {
        $littleEndianN = Encoding\Endian::toLE(S256Params::N());
        self::assertSame('414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff', bin2hex($littleEndianN));
        self::assertSame('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', gmp_strval(Encoding\Endian::fromLE($littleEndianN), 16));

        $littleEndianTrickyNumber = Encoding\Endian::toLE(gmp_init('0x8000000000000000000000000000000000000000000000000000000000000000'));
        self::assertSame('0000000000000000000000000000000000000000000000000000000000000080', bin2hex($littleEndianTrickyNumber));
        self::assertSame('8000000000000000000000000000000000000000000000000000000000000000', gmp_strval(Encoding\Endian::fromLE($littleEndianTrickyNumber), 16));
    }
}
