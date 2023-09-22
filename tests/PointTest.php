<?php

declare(strict_types=1);

use Bitcoin\FieldElement;
use Bitcoin\Point;
use Bitcoin\S256Field;
use Bitcoin\S256Point;
use PHPUnit\Framework\TestCase;

final class PointTest extends TestCase
{
    private const ORDER = 223;

    /**
     * @dataProvider validPointDataProvider
     */
    public function testInstantiation(?FieldElement $x, ?FieldElement $y): void
    {
        self::assertInstanceOf(Point::class, new Point($x, $y, new FieldElement(0, self::ORDER), new FieldElement(7, self::ORDER)));
    }

    public static function validPointDataProvider(): array
    {
        return [
            [new FieldElement(192, self::ORDER), new FieldElement(105, self::ORDER)],
            [new FieldElement(17, self::ORDER), new FieldElement(56, self::ORDER)],
            [new FieldElement(1, self::ORDER), new FieldElement(193, self::ORDER)],
            [null, null],
        ];
    }

    /**
     * @dataProvider invalidPointDataProvider
     */
    public function testInvalidPoints(?FieldElement $x, ?FieldElement $y): void
    {
        $this->expectException(InvalidArgumentException::class);

        new Point($x, $y, new FieldElement(0, self::ORDER), new FieldElement(7, self::ORDER));
    }

    public static function invalidPointDataProvider(): array
    {
        return [
            [new FieldElement(200, self::ORDER), new FieldElement(119, self::ORDER)],
            [new FieldElement(42, self::ORDER), new FieldElement(99, self::ORDER)],
            [new FieldElement(42, self::ORDER), new FieldElement(99, 101)],
            [new FieldElement(42, self::ORDER), null],
        ];
    }

    /**
     * @dataProvider pointAdditionDataProvider
     */
    public function testPointAddition(string $expectedResult, FieldElement $x1, FieldElement $y1, FieldElement $x2, FieldElement $y2): void
    {
        $a = new FieldElement(0, self::ORDER);
        $b = new FieldElement(7, self::ORDER);

        $p1 = new Point($x1, $y1, $a, $b);
        $p2 = new Point($x2, $y2, $a, $b);

        self::assertSame($expectedResult, (string) $p1->add($p2));
    }

    public static function pointAdditionDataProvider(): array
    {
        return [
            ['P(170,142)_0_7_FE(223)', new FieldElement(192, self::ORDER), new FieldElement(105, self::ORDER), new FieldElement(17, self::ORDER), new FieldElement(56, self::ORDER)],
            ['P(220,181)_0_7_FE(223)', new FieldElement(170, self::ORDER), new FieldElement(142, self::ORDER), new FieldElement(60, self::ORDER), new FieldElement(139, self::ORDER)],
            ['P(215,68)_0_7_FE(223)', new FieldElement(47, self::ORDER), new FieldElement(71, self::ORDER), new FieldElement(17, self::ORDER), new FieldElement(56, self::ORDER)],
            ['P(47,71)_0_7_FE(223)', new FieldElement(143, self::ORDER), new FieldElement(98, self::ORDER), new FieldElement(76, self::ORDER), new FieldElement(66, self::ORDER)],
        ];
    }

    public function testScalarMultiplication(): void
    {
        $p = new Point(new FieldElement(47, self::ORDER), new FieldElement(71, self::ORDER), new FieldElement(0, self::ORDER), new FieldElement(7, self::ORDER));

        self::assertSame('P(47,71)_0_7_FE(223)', (string) $p->scalarMul(1));
        self::assertSame('P(36,111)_0_7_FE(223)', (string) $p->scalarMul(2));
        self::assertSame('P(15,137)_0_7_FE(223)', (string) $p->scalarMul(3));
        self::assertSame('P(194,51)_0_7_FE(223)', (string) $p->scalarMul(4));
        self::assertSame('P(126,96)_0_7_FE(223)', (string) $p->scalarMul(5));
        self::assertSame('P(139,137)_0_7_FE(223)', (string) $p->scalarMul(6));
        self::assertSame('P(92,47)_0_7_FE(223)', (string) $p->scalarMul(7));
        self::assertSame('P(116,55)_0_7_FE(223)', (string) $p->scalarMul(8));
        self::assertSame('P(69,86)_0_7_FE(223)', (string) $p->scalarMul(9));
        self::assertSame('P(154,150)_0_7_FE(223)', (string) $p->scalarMul(10));
        self::assertSame('P(154,73)_0_7_FE(223)', (string) $p->scalarMul(11));
        self::assertSame('P(69,137)_0_7_FE(223)', (string) $p->scalarMul(12));
        self::assertSame('P(116,168)_0_7_FE(223)', (string) $p->scalarMul(13));
        self::assertSame('P(92,176)_0_7_FE(223)', (string) $p->scalarMul(14));
        self::assertSame('P(139,86)_0_7_FE(223)', (string) $p->scalarMul(15));
        self::assertSame('P(126,127)_0_7_FE(223)', (string) $p->scalarMul(16));
        self::assertSame('P(194,172)_0_7_FE(223)', (string) $p->scalarMul(17));
        self::assertSame('P(15,86)_0_7_FE(223)', (string) $p->scalarMul(18));
        self::assertSame('P(36,112)_0_7_FE(223)', (string) $p->scalarMul(19));
        self::assertSame('P(47,152)_0_7_FE(223)', (string) $p->scalarMul(20));
        self::assertSame('P(,)_0_7_FE(223)', @(string) $p->scalarMul(21));
    }

    /**
     * @dataProvider groupOrderDataProvider
     */
    public function testGroupOrder(int $expectedResult, Point $p): void
    {
        self::assertEquals(gmp_init($expectedResult), $p->groupOrder());
    }

    public static function groupOrderDataProvider(): array
    {
        return [
            [21, new Point(new FieldElement(47, self::ORDER), new FieldElement(71, self::ORDER), new FieldElement(0, self::ORDER), new FieldElement(7, self::ORDER))],
            [7, new Point(new FieldElement(15, self::ORDER), new FieldElement(86, self::ORDER), new FieldElement(0, self::ORDER), new FieldElement(7, self::ORDER))],
        ];
    }

    public function testSecp256k1FundamentalProperties(): void
    {
        // Check that G is a point on the secp256k1 curve
        $Gx = gmp_init(S256Point::SECP256K1_GX);
        $Gy = gmp_init(S256Point::SECP256K1_GY);
        $p = gmp_init(S256Field::SECP256K1_P);

        self::assertEquals(($Gy ** 2) % $p, ($Gx ** 3 + 7) % $p);

        // Check that G has the order n (i.e. n*G is the infinity point on secp256k1)
        $n = gmp_init(S256Point::SECP256K1_N);
        $G = new S256Point(new S256Field($Gx), new S256Field($Gy));
        self::assertSame('P(,)_0_7_FE(115792089237316195423570985008687907853269984665640564039457584007908834671663)', @(string) $G->scalarMul($n));
    }
}
