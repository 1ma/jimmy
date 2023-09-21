<?php

declare(strict_types=1);

use Bitcoin\FieldElement;
use PHPUnit\Framework\TestCase;

final class FieldElementTest extends TestCase
{
    public function testInstantiation(): void
    {
        self::assertSame('FE_2(1)', (string) new FieldElement(1, 2));

        $this->expectException(InvalidArgumentException::class);
        new FieldElement(-1, 1);
    }

    public function testAddition(): void
    {
        self::assertEquals(new FieldElement(6, 13), (new FieldElement(7, 13))->add(new FieldElement(12, 13)));

        $this->expectException(InvalidArgumentException::class);
        (new FieldElement(6, 13))->add(new FieldElement(6, 12));
    }

    public function testSubtraction(): void
    {
        self::assertEquals(new FieldElement(57, 60), (new FieldElement(2, 60))->sub(new FieldElement(5, 60)));

        $this->expectException(InvalidArgumentException::class);
        (new FieldElement(6, 13))->sub(new FieldElement(6, 12));
    }
}
