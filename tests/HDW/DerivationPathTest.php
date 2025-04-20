<?php

declare(strict_types=1);

namespace Bitcoin\Tests\HDW;

use Bitcoin\HDW\DerivationPath;
use Bitcoin\HDW\ExtendedKey;
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
        $tprv = ExtendedKey::parse('tprv8ZgxMBicQKsPdksbPS6u4aLDgjkt5LWM3vDscWSQKCTPsgKiekL3XiTb5HUHgyyr6e3pTn4JUcZUnPdAbbp3qtUmwmvAYwJHrJQiPMBMpum');

        [$firstKey] = DerivationPath::range(DerivationPath::parse("m/84'/1'/0'/0")->derive($tprv), 0, 1);

        self::assertSame(hex2bin('10b5395fc646a9fef6fc0071dac51a8cd3f57f6a89efa2e5700dddfb9e81ad0f'), gmp_export($firstKey->secret));
    }

    /**
     * Equivalent test to CKDFunctionsTest::testCKDPub() but exercising DerivationPath::range()
     * instead of the CKDPub function directly.
     */
    public function testCKDPub(): void
    {
        $xpub = ExtendedKey::parse('xpub6CdwuTkRV7XEskhbikrbktaKLeuyiZbrFqkU17Ru4NZvitCEAdDA8AqkFwYgSLCLs33vs4JisetTxbnSZo5H6RbCccSBdpJckuPfurPmdRD');

        $external = DerivationPath::parse('m/0')->derive($xpub);
        self::assertSame(
            hex2bin('03e6e2ad4cc102365a4bc2bf7e055824fca9c28b0205dbb262b2a5cd34e19fde7d'),
            DerivationPath::range($external, 0, 1)[0]->sec()
        );

        $internal = DerivationPath::parse('m/1')->derive($xpub);
        self::assertSame(
            hex2bin('024b7cbabc121e401243e76c37fa3d8a0dd7901bd2486610ff75da324b3037e5b2'),
            DerivationPath::range($internal, 0, 1)[0]->sec()
        );
    }

    public function testChildNumberTooLargeForDerivation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Index too large for ser32 serialization: 4294967296');

        $tprv = ExtendedKey::parse('tprv8ZgxMBicQKsPdksbPS6u4aLDgjkt5LWM3vDscWSQKCTPsgKiekL3XiTb5HUHgyyr6e3pTn4JUcZUnPdAbbp3qtUmwmvAYwJHrJQiPMBMpum');

        DerivationPath::parse('m/4294967296')->derive($tprv);
    }

    public function testInvalidLimitOrOffset(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $tprv = ExtendedKey::parse('tprv8ZgxMBicQKsPdksbPS6u4aLDgjkt5LWM3vDscWSQKCTPsgKiekL3XiTb5HUHgyyr6e3pTn4JUcZUnPdAbbp3qtUmwmvAYwJHrJQiPMBMpum');

        DerivationPath::range($tprv, -1, -1);
    }
}
