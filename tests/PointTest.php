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

    public function testRawSignatureVerification(): void
    {
        $G = S256Point::G();
        $N = gmp_init(S256Point::SECP256K1_N);
        $z = gmp_init('0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423');
        $r = gmp_init('0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6');
        $s = gmp_init('0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec');

        $point = new S256Point(
            new S256Field('0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574'),
            new S256Field('0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4')
        );

        $sInv = gmp_powm($s, $N - 2, $N);
        $u = ($z * $sInv) % $N;
        $v = ($r * $sInv) % $N;

        self::assertTrue($r == $G->scalarMul($u)->add($point->scalarMul($v))->x->num);
    }

    public function testVerifySignaturesExercise6Chapter3(): void
    {
        $G = S256Point::G();
        $N = gmp_init(S256Point::SECP256K1_N);
        $point = new S256Point(
            new S256Field('0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c'),
            new S256Field('0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34')
        );

        // signature #1
        $z = gmp_init('0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60');
        $r = gmp_init('0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395');
        $s = gmp_init('0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4');

        $sInv = gmp_powm($s, $N - 2, $N);
        $u = ($z * $sInv) % $N;
        $v = ($r * $sInv) % $N;

        self::assertTrue($r == $G->scalarMul($u)->add($point->scalarMul($v))->x->num);

        // signature #2
        $z = gmp_init('0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d');
        $r = gmp_init('0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c');
        $s = gmp_init('0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6');

        $sInv = gmp_powm($s, $N - 2, $N);
        $u = ($z * $sInv) % $N;
        $v = ($r * $sInv) % $N;

        self::assertTrue($r == $G->scalarMul($u)->add($point->scalarMul($v))->x->num);
    }
}
