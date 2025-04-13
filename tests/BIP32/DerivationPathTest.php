<?php

declare(strict_types=1);

namespace Bitcoin\Tests\BIP32;

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
        $path             = DerivationPath::parse("m/84'/1'/0'/0");
        $masterPrivateKey = new PrivateKey(gmp_init('0xcf0bad7aef2270b46b5ce749d0db811356a688ba05bd2cf22850be43c3202a87'));
        $masterChainCode  = hex2bin('58cf12642d390624ee21b444e18296abd8433a794d789f83f29f6381d3d8041c');

        [$privateKey, $chainCode] = $path->derive($masterPrivateKey, $masterChainCode);
        [$firstKey]               = DerivationPath::range($privateKey, $chainCode, 0, 1);

        self::assertSame(hex2bin('10b5395fc646a9fef6fc0071dac51a8cd3f57f6a89efa2e5700dddfb9e81ad0f'), gmp_export($firstKey->secret));
    }

    public function testChildNumberTooLargeForDerivation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Index too large for ser32 serialization: 4294967296');

        $masterPrivateKey = new PrivateKey(gmp_init('0xcf0bad7aef2270b46b5ce749d0db811356a688ba05bd2cf22850be43c3202a87'));
        $masterChainCode  = hex2bin('58cf12642d390624ee21b444e18296abd8433a794d789f83f29f6381d3d8041c');

        DerivationPath::parse('m/4294967296')->derive($masterPrivateKey, $masterChainCode);
    }

    public function testInvalidChainCodeInDerive(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $masterPrivateKey = new PrivateKey(gmp_init('0xcf0bad7aef2270b46b5ce749d0db811356a688ba05bd2cf22850be43c3202a87'));
        $masterChainCode  = hex2bin('58cf');

        DerivationPath::parse("m/84'/1'/0'/0")->derive($masterPrivateKey, $masterChainCode);
    }

    public function testInvalidChainCodeInRange(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $masterPrivateKey = new PrivateKey(gmp_init('0xcf0bad7aef2270b46b5ce749d0db811356a688ba05bd2cf22850be43c3202a87'));
        $masterChainCode  = hex2bin('58cf');

        DerivationPath::range($masterPrivateKey, $masterChainCode, 0, 1);
    }

    public function testInvalidLimitOrOffset(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $masterPrivateKey = new PrivateKey(gmp_init('0xcf0bad7aef2270b46b5ce749d0db811356a688ba05bd2cf22850be43c3202a87'));
        $masterChainCode  = hex2bin('58cf12642d390624ee21b444e18296abd8433a794d789f83f29f6381d3d8041c');

        DerivationPath::range($masterPrivateKey, $masterChainCode, -1, -1);
    }
}
