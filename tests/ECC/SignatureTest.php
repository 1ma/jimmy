<?php

declare(strict_types=1);

namespace Bitcoin\Tests\ECC;

use Bitcoin\ECC\Signature;
use PHPUnit\Framework\TestCase;

final class SignatureTest extends TestCase
{
    public function testDebugSerialization(): void
    {
        $sig = new Signature(
            gmp_init('0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6'),
            gmp_init('0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec')
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
            gmp_init('0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec')
        );

        self::assertSame(
            '3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec',
            bin2hex($sig->der())
        );
    }
}
