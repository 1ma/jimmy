<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\S256Params;
use PHPUnit\Framework\TestCase;

final class S256FieldTest extends TestCase
{
    public function testDebugSerialization(): void
    {
        self::assertSame(
            'S256Field(0000000000000000000000000000000000000000000000000000000000000000)',
            (string) S256Params::A()
        );

        self::assertSame(
            'S256Field(0000000000000000000000000000000000000000000000000000000000000007)',
            (string) S256Params::B()
        );
    }
}
