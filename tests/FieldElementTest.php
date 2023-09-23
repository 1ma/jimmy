<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\FieldElement;
use PHPUnit\Framework\TestCase;

final class FieldElementTest extends TestCase
{
    public function testInstantiation(): void
    {
        self::assertSame('FE_101(57)', (string) new FieldElement(57, 101));
        self::assertObjectEquals(new FieldElement(57, 101), new FieldElement(57, 101));

        $this->expectException(\InvalidArgumentException::class);
        new FieldElement(-1, 1);
    }

    public function testNonPrimeOrder(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new FieldElement(2, 4);
    }

    public function testAddition(): void
    {
        self::assertSame('FE_13(6)', (string) (new FieldElement(7, 13))->add(new FieldElement(12, 13)));

        $this->expectException(\InvalidArgumentException::class);
        (new FieldElement(6, 13))->add(new FieldElement(6, 17));
    }

    public function testSubtraction(): void
    {
        self::assertSame('FE_61(58)', (string) (new FieldElement(2, 61))->sub(new FieldElement(5, 61)));
    }

    public function testMultiplication(): void
    {
        self::assertSame('FE_13(3)', (string) (new FieldElement(12, 13))->mul(new FieldElement(10, 13)));
    }

    public function testDivision(): void
    {
        self::assertSame('FE_19(3)', (string) (new FieldElement(2, 19))->div(new FieldElement(7, 19)));
        self::assertSame('FE_19(9)', (string) (new FieldElement(7, 19))->div(new FieldElement(5, 19)));
    }

    public function testExponentiation(): void
    {
        self::assertSame('FE_13(1)', (string) (new FieldElement(3, 13))->exp(3));
        self::assertSame('FE_13(8)', (string) (new FieldElement(7, 13))->exp(-3));
    }
}
