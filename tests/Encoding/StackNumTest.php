<?php

declare(strict_types=1);

namespace Bitcoin\Tests\Encoding;

use Bitcoin\Encoding;
use PHPUnit\Framework\TestCase;

final class StackNumTest extends TestCase
{
    public function testStackNumEncodingEdgeCases(): void
    {
        self::assertSame(hex2bin(''), Encoding\StackNum::encode(0));
        self::assertSame(hex2bin('81'), Encoding\StackNum::encode(-1));
        self::assertSame(hex2bin('ff80'), Encoding\StackNum::encode(-255));

        self::assertSame(0, Encoding\StackNum::decode(''));
        self::assertSame(-1, Encoding\StackNum::decode(hex2bin('81')));
        self::assertSame(-255, Encoding\StackNum::decode(hex2bin('ff80')));
    }
}
