<?php

declare(strict_types=1);

use Bitcoin\RealPoint;
use PHPUnit\Framework\TestCase;

final class RealPointTest extends TestCase
{
    public function testInstantiation(): void
    {
        self::assertSame('P(-1,-1)_5_7', (string) new RealPoint(-1, -1, 5, 7));
        self::assertSame('P(18,77)_5_7', (string) new RealPoint(18, 77, 5, 7));

        self::assertObjectEquals(new RealPoint(-1, -1, 5, 7), new RealPoint(-1, -1, 5, 7));
        self::assertObjectEquals(new RealPoint(null, null, 5, 7), RealPoint::infinity(5, 7));

        $this->expectException(InvalidArgumentException::class);
        new RealPoint(5, 7, 5, 7);
    }

    public function testInvalidInstantiation(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new RealPoint(null, 7, 5, 7);
    }

    public function testPointAddition(): void
    {
        $p1 = new RealPoint(-1, -1, 5, 7);
        $p2 = new RealPoint(-1, 1, 5, 7);
        $inf = RealPoint::infinity(5, 7);

        self::assertSame('P(-1,-1)_5_7', (string) $p1->add($inf));
        self::assertSame('P(-1,1)_5_7', (string) $inf->add($p2));

        $p1 = new RealPoint(2, 5, 5, 7);
        $p2 = new RealPoint(-1, -1, 5, 7);

        self::assertSame('P(3,-7)_5_7', (string) $p1->add($p2));

        self::assertSame('P(18,77)_5_7', (string) $p2->add($p2));
    }
}
