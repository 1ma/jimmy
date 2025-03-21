<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\Signature;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SignatureTest extends TestCase
{
    public function testDebugSerialization(): void
    {
        $sig = new Signature(
            gmp_init('0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6'),
            gmp_init('0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec'),
            true
        );

        self::assertSame(
            'Signature(37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6,8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec)',
            (string) $sig
        );
    }

    public function testDerSerialization(): void
    {
        $sig = new Signature(
            gmp_init('0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6'),
            gmp_init('0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec'),
            true
        );

        self::assertSame(
            '3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec',
            bin2hex($sig->der())
        );
    }

    #[DataProvider('validDerSignatureProvider')]
    public function testDerParsing(string $expectedR, string $expectedS, string $hexDer): void
    {
        $s = Signature::parse(hex2bin($hexDer), true);
        self::assertSame($expectedR, gmp_strval($s->r, 16));
        self::assertSame($expectedS, gmp_strval($s->s, 16));
    }

    public static function validDerSignatureProvider(): array
    {
        return [
            [
                '37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6',
                '8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec',
                '3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec',
            ],
            [
                'eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c',
                'c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6',
                '3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6',
            ],
        ];
    }
}
