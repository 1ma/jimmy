<?php

declare(strict_types=1);

use Bitcoin\Point;
use PHPUnit\Framework\TestCase;

final class PointTest extends TestCase
{
    public function testInstantiation(): void
    {
        self::assertSame('P(-1,-1)_5_7', (string) new Point(-1, -1, 5, 7));
        self::assertSame('P(18,77)_5_7', (string) new Point(18, 77, 5, 7));

        self::assertObjectEquals(new Point(-1, -1, 5, 7), new Point(-1, -1, 5, 7));
        self::assertObjectEquals(new Point(null, null, 5, 7), Point::infinity(5, 7));

        $this->expectException(InvalidArgumentException::class);
        new Point(5, 7, 5, 7);
    }

    public function testInvalidInstantiation(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Point(null, 7, 5, 7);
    }

    public function testPointAddition(): void
    {
        $p1 = new Point(-1, -1, 5, 7);
        $p2 = new Point(-1, 1, 5, 7);
        $inf = Point::infinity(5, 7);

        self::assertSame('P(-1,-1)_5_7', (string) $p1->add($inf));
        self::assertSame('P(-1,1)_5_7', (string) $inf->add($p2));

        $p1 = new Point(2, 5, 5, 7);
        $p2 = new Point(-1, -1, 5, 7);

        self::assertSame('P(3,-7)_5_7', (string) $p1->add($p2));

        self::assertSame('P(18,77)_5_7', (string) $p2->add($p2));
    }
}
