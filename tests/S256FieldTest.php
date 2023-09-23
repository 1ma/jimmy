<?php

declare(strict_types=1);

use Bitcoin\S256Field;
use Bitcoin\S256Params;
use PHPUnit\Framework\TestCase;

final class S256FieldTest extends TestCase
{
    public function testVerifySignatures(): void
    {
        self::assertSame(
            'S256Field(0000000000000000000000000000000000000000000000000000000000000007)',
            (string) (new S256Field(S256Params::B->value))
        );
    }
}
