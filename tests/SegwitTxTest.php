<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\Tx;
use PHPUnit\Framework\TestCase;

final class SegwitTxTest extends TestCase
{
    use StreamingHelperTrait;

    private const P2WPKH_TX        = '02000000000101855da197e40631d06d2a3e72af766ffbf5b092a86aae92a4f80f18390a9338450100000000fdffffff026d741ce301000000160014b97d52217016d38cef37eafd8bd39f60884a5060e3bc1c000000000016001490bcc810ae94fd4fb325722c0d9572496e66cdcc0247304402206dda1ec0f70d7bbd61120a445421db3bedc7f36a67524fb02ff127ca3e199e7f022060760eb6cec81cf7b19ace44d6e95ba1a7e45f1a36c3778197927f6edd5088aa0121021c62d454d1e7f3e42d4cb404483ecdce92a64f04c883cb2321eece2375c423d5679b2600';
    private const P2WPKH_WITNESS_0 = '304402206dda1ec0f70d7bbd61120a445421db3bedc7f36a67524fb02ff127ca3e199e7f022060760eb6cec81cf7b19ace44d6e95ba1a7e45f1a36c3778197927f6edd5088aa01';
    private const P2WPKH_WITNESS_1 = '021c62d454d1e7f3e42d4cb404483ecdce92a64f04c883cb2321eece2375c423d5';

    private const P2WSH_TX = '020000000001017d748137d5b03b6fad79a7db558056888fb9c71812be86833110093a9ea35c7a0000000000fdffffff01a3586a0000000000220020b15ecacee647c944c9713ce3e3246da0f2d0e0b47544734839c7eb01a72b84840600473044022069145e412545c73d14668854edc140f7d42c2aeb2948d9251ce2dcbd3b446db302204aff1eca805c2bf4f986d618c20a154c6661705b6cbe5b41bc3638b9a45612f2014730440220703152cedad32f286c8521cb4054407e51343c9a134f7cce82b4ebdcc8689992022026734f08602d05ca9d8fe99db7b9ef52105c4779c627c62a2035695587db194a01473044022004aa1c19d20274a5592fea0188a6c5893b677fa8ebbf80b7f7177c34a768825a022030cb49415ed3134781dbc945f73d7d2b16597c6c4a3129e626d174f57568c5130147304402201e8ec993246b543d302d2e021f71e2407632fc02aab7811dafd8a30aa9e34e49022032db14c85e919ec4189bfce4e3ff93af46c7d31b84bc83b05761fd735fc234c301ad542102b9f91ab0bf81e33554daf61498bb44ef56fccc9658beb525089dd356216874c52102c748bc1907bb290cec8e57755e4be427069316ea5176383ec4ebbf58245b7c7f2102d132e3237aee03e2909040a407bbaa76ec26de7d1ef1471c41a7470eea80708d210392d3755e67c603d055401c94fc6ede91930e0178d80e7744aba8466468c655252103edae12f0475c908e72378e4f9804a5dc5b8563b0125439af4a1e36d811bd104755ae809b2600';

    public function testP2WPKHParsing(): void
    {
        $tx = Tx::parse(self::stream(hex2bin(self::P2WPKH_TX)));

        self::assertSame(2, $tx->version);
        self::assertCount(1, $tx->txIns);
        self::assertEmpty($tx->txIns[0]->scriptSig->cmds);
        self::assertSame(0xFFFFFFFD, $tx->txIns[0]->seqNum);
        self::assertCount(2, $tx->txIns[0]->witness);
        self::assertSame(hex2bin(self::P2WPKH_WITNESS_0), $tx->txIns[0]->witness[0]);
        self::assertSame(hex2bin(self::P2WPKH_WITNESS_1), $tx->txIns[0]->witness[1]);
        self::assertCount(2, $tx->txOuts);
        self::assertSame(2530151, $tx->locktime);
    }

    public function testP2WPKHSerialization(): void
    {
        $tx = Tx::parse(self::stream(hex2bin(self::P2WPKH_TX)));

        self::assertSame(hex2bin(self::P2WPKH_TX), $tx->serialize());
    }

    public function testSegwitTxIdCalculation(): void
    {
        self::assertSame('d19e7e6869dae7dfc7575d5ce07a018dbeadde26e6b35cce22bc6f9498b13521', Tx::parse(self::stream(hex2bin(self::P2WPKH_TX)))->id());
        self::assertSame('6f0b0db325ad0935395d30fce685154b4e8206c6878ff16435648cdb5f1d7096', Tx::parse(self::stream(hex2bin(self::P2WSH_TX)))->id());
    }

    public function testP2WPKHValidation(): void
    {
        $tx = Tx::parse(self::stream(hex2bin(self::P2WPKH_TX)));

        self::assertTrue($tx->verify());
    }

    public function testP2WSHParsing(): void
    {
        $tx = Tx::parse(self::stream(hex2bin(self::P2WSH_TX)));

        self::assertSame(2, $tx->version);
        self::assertCount(1, $tx->txIns);
        self::assertEmpty($tx->txIns[0]->scriptSig->cmds);
        self::assertSame(0xFFFFFFFD, $tx->txIns[0]->seqNum);
        self::assertCount(6, $tx->txIns[0]->witness);
        self::assertSame(2530176, $tx->locktime);
    }

    public function testP2WSHSerialization(): void
    {
        $tx = Tx::parse(self::stream(hex2bin(self::P2WSH_TX)));

        self::assertSame(hex2bin(self::P2WSH_TX), $tx->serialize());
    }

    public function testP2WSHValidation(): void
    {
        $tx = Tx::parse(self::stream(hex2bin(self::P2WSH_TX)));

        self::assertTrue($tx->verify());
    }
}
