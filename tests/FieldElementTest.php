<?php

declare(strict_types=1);

use Bitcoin\FieldElement;
use PHPUnit\Framework\TestCase;

final class FieldElementTest extends TestCase
{
    public function testSimpleUsage(): void
    {
        $this->expectException(InvalidArgumentException::class);
        self::assertSame('FE_2(1)', (string) new FieldElement(1, 2));

        new FieldElement(-1, 1);
    }
}
