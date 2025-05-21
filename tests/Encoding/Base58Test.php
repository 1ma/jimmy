<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Encoding;

use Bitcoin\Encoding;
use Bitcoin\Network;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class Base58Test extends TestCase
{
    #[DataProvider('base58encoderDataProvider')]
    public function testEncoding(string $expectedEncoding, string $data): void
    {
        self::assertSame($expectedEncoding, Encoding\Base58::encode(hex2bin($data)));
    }

    #[DataProvider('base58encoderDataProvider')]
    public function testDecoding(string $data, string $expectedDecoding): void
    {
        self::assertSame(hex2bin($expectedDecoding), Encoding\Base58::decode($data));
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

        Encoding\Base58::decode('3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXg', true);
    }

    public function testP2SHAddressGeneration(): void
    {
        // Based on example from Chapter 8 page 157
        self::assertSame(
            '3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh',
            Encoding\Address::p2sh(hex2bin('74d691da1574e6b3c192ecfb52cc8984ee7b6c56'), mode: Network::MAINNET)
        );
    }
}
