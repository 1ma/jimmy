<?php

declare(strict_types=1);

use Bitcoin\FieldElement;
use Bitcoin\Point;
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
}
