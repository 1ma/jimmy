<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\ECC\S256Params;
use Bitcoin\Encoding;
use Bitcoin\Network;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EncodingTest extends TestCase
{
    use StreamingHelperTrait;

    #[DataProvider('base58encoderDataProvider')]
    public function testEncoding(string $expectedEncoding, string $data): void
    {
        self::assertSame($expectedEncoding, Encoding::base58encode(hex2bin($data)));
    }

    #[DataProvider('base58encoderDataProvider')]
    public function testDecoding(string $data, string $expectedDecoding): void
    {
        self::assertSame(hex2bin($expectedDecoding), Encoding::base58decode($data));
    }

    public static function base58encoderDataProvider(): array
    {
        return [
            ['1', '00'],
            ['11', '0000'],
            ['9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6', '7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d'],
            ['4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd', 'eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c'],
            ['EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7', 'c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6'],
        ];
    }

    public function testInvalidChecksum(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid checksum');

        Encoding::base58decode('3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXg', true);
    }

    public function testLittleEndianEncodingAndDecoding(): void
    {
        $littleEndianN = Encoding::toLE(S256Params::N());
        self::assertSame('414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff', bin2hex($littleEndianN));
        self::assertSame('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', gmp_strval(Encoding::fromLE($littleEndianN), 16));

        $littleEndianTrickyNumber = Encoding::toLE(gmp_init('0x8000000000000000000000000000000000000000000000000000000000000000'));
        self::assertSame('0000000000000000000000000000000000000000000000000000000000000080', bin2hex($littleEndianTrickyNumber));
        self::assertSame('8000000000000000000000000000000000000000000000000000000000000000', gmp_strval(Encoding::fromLE($littleEndianTrickyNumber), 16));
    }

    public function testVarIntEncodingAndParsing(): void
    {
        self::assertSame('00', bin2hex(Encoding::encodeVarInt(0)));
        self::assertSame('64', bin2hex(Encoding::encodeVarInt(100)));
        self::assertSame('fdff00', bin2hex(Encoding::encodeVarInt(255)));
        self::assertSame('fd2b02', bin2hex(Encoding::encodeVarInt(555)));
        self::assertSame('fe7f110100', bin2hex(Encoding::encodeVarInt(70015)));
        self::assertSame('ff6dc7ed3e60100000', bin2hex(Encoding::encodeVarInt(18005558675309)));

        self::assertSame(0, Encoding::decodeVarInt(self::stream(hex2bin('00'))));
        self::assertSame(100, Encoding::decodeVarInt(self::stream(hex2bin('64'))));
        self::assertSame(255, Encoding::decodeVarInt(self::stream(hex2bin('fdff00'))));
        self::assertSame(555, Encoding::decodeVarInt(self::stream(hex2bin('fd2b02'))));
        self::assertSame(70015, Encoding::decodeVarInt(self::stream(hex2bin('fe7f110100'))));
        self::assertSame(18005558675309, Encoding::decodeVarInt(self::stream(hex2bin('ff6dc7ed3e60100000'))));
    }

    public function testP2SHAddressGeneration(): void
    {
        // Based on example from Chapter 8 page 157
        self::assertSame('3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh', Encoding::hash160ToPayToScriptKeyHashAddress(hex2bin('74d691da1574e6b3c192ecfb52cc8984ee7b6c56'), mode: Network::MAINNET));
    }

    public function testStackNumEncodingEdgeCases(): void
    {
        self::assertSame(hex2bin(''), Encoding::encodeStackNum(0));
        self::assertSame(hex2bin('81'), Encoding::encodeStackNum(-1));
        self::assertSame(hex2bin('ff80'), Encoding::encodeStackNum(-255));

        self::assertSame(0, Encoding::decodeStackNum(''));
        self::assertSame(-1, Encoding::decodeStackNum(hex2bin('81')));
        self::assertSame(-255, Encoding::decodeStackNum(hex2bin('ff80')));
    }
}
