<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\Hashing;
use Bitcoin\Tx;
use PHPUnit\Framework\TestCase;

final class SegwitTxTest extends TestCase
{
    use StreamingHelperTrait;

    private const string P2WPKH_TX        = '02000000000101855da197e40631d06d2a3e72af766ffbf5b092a86aae92a4f80f18390a9338450100000000fdffffff026d741ce301000000160014b97d52217016d38cef37eafd8bd39f60884a5060e3bc1c000000000016001490bcc810ae94fd4fb325722c0d9572496e66cdcc0247304402206dda1ec0f70d7bbd61120a445421db3bedc7f36a67524fb02ff127ca3e199e7f022060760eb6cec81cf7b19ace44d6e95ba1a7e45f1a36c3778197927f6edd5088aa0121021c62d454d1e7f3e42d4cb404483ecdce92a64f04c883cb2321eece2375c423d5679b2600';
    private const string P2WPKH_WITNESS_0 = '304402206dda1ec0f70d7bbd61120a445421db3bedc7f36a67524fb02ff127ca3e199e7f022060760eb6cec81cf7b19ace44d6e95ba1a7e45f1a36c3778197927f6edd5088aa01';
    private const string P2WPKH_WITNESS_1 = '021c62d454d1e7f3e42d4cb404483ecdce92a64f04c883cb2321eece2375c423d5';

    private const string P2WSH_TX = '020000000001017d748137d5b03b6fad79a7db558056888fb9c71812be86833110093a9ea35c7a0000000000fdffffff01a3586a0000000000220020b15ecacee647c944c9713ce3e3246da0f2d0e0b47544734839c7eb01a72b84840600473044022069145e412545c73d14668854edc140f7d42c2aeb2948d9251ce2dcbd3b446db302204aff1eca805c2bf4f986d618c20a154c6661705b6cbe5b41bc3638b9a45612f2014730440220703152cedad32f286c8521cb4054407e51343c9a134f7cce82b4ebdcc8689992022026734f08602d05ca9d8fe99db7b9ef52105c4779c627c62a2035695587db194a01473044022004aa1c19d20274a5592fea0188a6c5893b677fa8ebbf80b7f7177c34a768825a022030cb49415ed3134781dbc945f73d7d2b16597c6c4a3129e626d174f57568c5130147304402201e8ec993246b543d302d2e021f71e2407632fc02aab7811dafd8a30aa9e34e49022032db14c85e919ec4189bfce4e3ff93af46c7d31b84bc83b05761fd735fc234c301ad542102b9f91ab0bf81e33554daf61498bb44ef56fccc9658beb525089dd356216874c52102c748bc1907bb290cec8e57755e4be427069316ea5176383ec4ebbf58245b7c7f2102d132e3237aee03e2909040a407bbaa76ec26de7d1ef1471c41a7470eea80708d210392d3755e67c603d055401c94fc6ede91930e0178d80e7744aba8466468c655252103edae12f0475c908e72378e4f9804a5dc5b8563b0125439af4a1e36d811bd104755ae809b2600';

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

        self::assertSame('8f16b83ac5aee7c59b8de029872f92586cd0c9f4367d163fb3c73e68a85aedac', Tx::parse(self::stream(hex2bin(self::P2WPKH_TX)))->wid());
        self::assertSame('ad289144170bc8a740eb9f6e42ad84620f86278991836f37f943a2732b20c2c8', Tx::parse(self::stream(hex2bin(self::P2WSH_TX)))->wid());
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

    public function testP2WSHTransactionCreation(): void
    {
        $txIn = new Tx\Input('1f0cf1732193dba6d0ac867aae36bf745cdb69b4a525bb7fc016401937551326', 0);

        $changePubKey = hex2bin('03d684657d57e60eb34dafe9a9f00ab5bb96dfa4c0a1ef7ae056d39c0dbe318350');
        $txOut0       = new Tx\Output(381633, Tx\Script::payToSegWitV0(Hashing::hash160($changePubKey)));

        $revealPubKey = hex2bin('024478db27085089124c76a6d14d2421ea65ba01ddd94b769ebcd5fcc251d81826');
        $p2pk         = Tx\Script::payToPubKey($revealPubKey);
        $scriptHash   = hash('sha256', substr($p2pk->serialize(), 1), true);
        $txOut1       = new Tx\Output(1000, Tx\Script::payToSegWitV0($scriptHash));

        $tx = new Tx(1, [$txIn], [$txOut0, $txOut1], locktime: 0, testnet: true, segwit: true);

        self::assertSame('e9df24a4a712622589a7fa0c0eb3972a5a943b4523a9a3c8ecf81a10126bb6ed', $tx->id());
        self::assertTrue($tx->signInput(0, new PrivateKey(gmp_init('0x704a5511e8127119c22805f2c93789fa87e05b3d69b3df4dc801af10c0c15ced'))));
        self::assertTrue($tx->verify());

        self::assertSame(
            '0100000000010126135537194016c07fbb25a5b469db5c74bf36ae7a86acd0a6db932173f10c1f0000000000ffffffff02c1d205000000000016001479482854f90ee78eb082b6a7c1fa256774111adce8030000000000002200200571f70813549b790ac5fee72d8001324006a2c16e9d6459c3b6e596e8e6644302483045022100a299ecdc7e41bc0ed902e34438ec99aa4aa63c81ba2859362659a9a83bf42b250220087c7bf88e5e3ca9441d44255b7b296d0aa828fa08378adc841c371dab18a7b7012103d08bb6d058136f737f76d320af14c06335822e725fbe45cc70297db2d2b35e5e00000000',
            bin2hex($tx->serialize())
        );
    }

    public function testP2WSHTransactionRedemption(): void
    {
        $revealPubKey = hex2bin('024478db27085089124c76a6d14d2421ea65ba01ddd94b769ebcd5fcc251d81826');
        $p2pk         = Tx\Script::payToPubKey($revealPubKey);

        $txIn = new Tx\Input('e9df24a4a712622589a7fa0c0eb3972a5a943b4523a9a3c8ecf81a10126bb6ed', 1, witness: [substr($p2pk->serialize(), 1)]);

        $txOut = new Tx\Output(0, Tx\Script::opReturn('Behold the mythical P2WSH-P2PK transaction.'));

        $tx = new Tx(1, [$txIn], [$txOut], locktime: 0, testnet: true, segwit: true);

        self::assertSame('ba51067de0df0ae015ed3e68477683443bdc31639b4b1cec8d4b15a1c561ad84', $tx->id());
        self::assertTrue($tx->signInput(0, new PrivateKey(gmp_init('0xf3661cd21190e88a2d06cd3df27a32798169d23e460f507e51967f681255c20a'))));
        self::assertTrue($tx->verify());

        self::assertSame(
            '01000000000101edb66b12101af8ecc8a3a923453b945a2a97b30e0cfaa789256212a7a424dfe90100000000ffffffff0100000000000000002d6a2b4265686f6c6420746865206d7974686963616c2050325753482d5032504b207472616e73616374696f6e2e0247304402203c32b2459470182e4d1b58b9f65438313c6af4fbceabd4b0c0480b7bb308a13d022061d6c8902872fb006c0be6d23411354935204ed0b68c8cd7a593f1d1cf7fd7de012321024478db27085089124c76a6d14d2421ea65ba01ddd94b769ebcd5fcc251d81826ac00000000',
            bin2hex($tx->serialize())
        );
    }
}
