<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\S256Field;
use Bitcoin\ECC\S256Params;
use PHPUnit\Framework\TestCase;

final class S256FieldTest extends TestCase
{
    public function testInstantiation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new S256Field(-1);
    }

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

    public function testAddition(): void
    {
        self::assertSame(
            'S256Field(0000000000000000000000000000000000000000000000000000000000000013)',
            (string) new S256Field(7)->add(new S256Field(12))
        );
    }

    public function testSubtraction(): void
    {
        self::assertSame(
            'S256Field(fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2c)',
            (string) new S256Field(2)->sub(new S256Field(5))
        );
    }

    public function testMultiplication(): void
    {
        self::assertSame(
            'S256Field(0000000000000000000000000000000000000000000000000000000000000078)',
            (string) new S256Field(12)->mul(new S256Field(10))
        );
    }

    public function testDivision(): void
    {
        self::assertSame(
            'S256Field(b6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db6db62492466b)',
            (string) new S256Field(2)->div(new S256Field(7))
        );

        self::assertSame(
            'S256Field(33333333333333333333333333333333333333333333333333333332ffffff3e)',
            (string) new S256Field(7)->div(new S256Field(5))
        );
    }

    public function testExponentiation(): void
    {
        self::assertSame(
            'S256Field(000000000000000000000000000000000000000000000000000000000000001b)',
            (string) new S256Field(3)->exp(3)
        );

        self::assertSame(
            'S256Field(cb023d337fa0776aba96c38b918a1367be52196047a66ff40eed57520d6f31f7)',
            (string) new S256Field(7)->exp(-3)
        );
    }
}
