<?php

declare(strict_types=1);

namespace BIP32;

use Bitcoin\BIP32\DerivationPath;
use Bitcoin\ECC\PrivateKey;
use PHPUnit\Framework\TestCase;

final class DerivationPathTest extends TestCase
{
    public function testPathParsing(): void
    {
        self::assertSame([], DerivationPath::parse('m')->levels);
        self::assertSame([0], DerivationPath::parse('m/0')->levels);
        self::assertSame([0x80000000], DerivationPath::parse("m/0'")->levels);
        self::assertSame([84 + 0x80000000, 1 + 0x80000000, 0x80000000, 0], DerivationPath::parse("m/84'/1'/0'/0")->levels);
    }

    public function testBadPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        DerivationPath::parse('wololo');
    }

    public function testKnownTestCaseFromB4OS(): void
    {
        $path       = DerivationPath::parse("m/84'/1'/0'/0");
        $privateKey = new PrivateKey(gmp_init('0xcf0bad7aef2270b46b5ce749d0db811356a688ba05bd2cf22850be43c3202a87'));
        $chainCode  = hex2bin('58cf12642d390624ee21b444e18296abd8433a794d789f83f29f6381d3d8041c');

        [$firstKey] = $path->deriveRange($privateKey, $chainCode, 0, 1);

        self::assertSame(hex2bin('10b5395fc646a9fef6fc0071dac51a8cd3f57f6a89efa2e5700dddfb9e81ad0f'), gmp_export($firstKey->secret));
    }
}
