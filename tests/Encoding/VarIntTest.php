<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Encoding;

use Bitcoin\Encoding;
use Bitcoin\Tests\StreamingHelperTrait;
use PHPUnit\Framework\TestCase;

final class VarIntTest extends TestCase
{
    use StreamingHelperTrait;

    public function testVarIntEncodingAndParsing(): void
    {
        self::assertSame('00', bin2hex(Encoding\VarInt::encode(0)));
        self::assertSame('64', bin2hex(Encoding\VarInt::encode(100)));
        self::assertSame('fdff00', bin2hex(Encoding\VarInt::encode(255)));
        self::assertSame('fd2b02', bin2hex(Encoding\VarInt::encode(555)));
        self::assertSame('fe7f110100', bin2hex(Encoding\VarInt::encode(70015)));
        self::assertSame('ff6dc7ed3e60100000', bin2hex(Encoding\VarInt::encode(18005558675309)));

        self::assertSame(0, Encoding\VarInt::decode(self::stream(hex2bin('00'))));
        self::assertSame(100, Encoding\VarInt::decode(self::stream(hex2bin('64'))));
        self::assertSame(255, Encoding\VarInt::decode(self::stream(hex2bin('fdff00'))));
        self::assertSame(555, Encoding\VarInt::decode(self::stream(hex2bin('fd2b02'))));
        self::assertSame(70015, Encoding\VarInt::decode(self::stream(hex2bin('fe7f110100'))));
        self::assertSame(18005558675309, Encoding\VarInt::decode(self::stream(hex2bin('ff6dc7ed3e60100000'))));
    }
}
