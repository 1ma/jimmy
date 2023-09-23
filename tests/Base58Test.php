<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\Base58;
use PHPUnit\Framework\TestCase;

final class Base58Test extends TestCase
{
    /**
     * @dataProvider encodingDataProvider
     */
    public function testEncoding(string $expectedEncoding, string $data): void
    {
        self::assertSame($expectedEncoding, Base58::encode(hex2bin($data)));
    }

    public static function encodingDataProvider(): array
    {
        return [
            ['9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6', '7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d'],
            ['4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd', 'eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c'],
            ['EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7', 'c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6'],
        ];
    }
}
