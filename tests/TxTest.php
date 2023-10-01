<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\Encoding;
use Bitcoin\Tx;
use PHPUnit\Framework\TestCase;

final class TxTest extends TestCase
{
    use StreamingHelperTrait;

    private const SIMPLE_TX = '0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f711f8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdafe2e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600';
    private const LARGE_TX  = '010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600';

    public function testDebugSerialization(): void
    {
        $tx = new Tx(1, [], [], 0, true);

        $expectedSerialization = <<<TXT
tx: d21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43
version: 1
tx_ins:
tx_outs:
locktime: 0
TXT;

        self::assertSame($expectedSerialization, (string) $tx);
    }

    public function testTransactionParsing(): void
    {
        $rawTx                 = self::stream(hex2bin(self::SIMPLE_TX));
        $expectedSerialization = <<<TXT
tx: 4d2cd204467b27f6961d649ac279bc360103acac65a3120f7536fa2a6d329a82
version: 1
tx_ins:
d1c789a9c603831f715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81:0
tx_outs:
32454049:1976a914bc3b654dca7e56b04dca18f2566cdafe2e8d9ada88ac
10011545:1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac
locktime: 410393
TXT;

        $tx = Tx::parse($rawTx);
        self::assertSame($expectedSerialization, (string) $tx);
        self::assertSame(self::SIMPLE_TX, bin2hex($tx->serialize()));

        $rawTx                 = self::stream(hex2bin(self::LARGE_TX));
        $expectedSerialization = <<<TXT
tx: ee51510d7bbabe28052038d1deb10c03ec74f06a79e21913c6fcf48d56217c87
version: 1
tx_ins:
9e067aedc661fca148e13953df75f8ca6eada9ce3b3d8d68631769ac60999156:1
d37f9e7282f81b7fd3af0fde8b462a1c28024f1d83cf13637ec18d03f4518feb:0
75d7454b7010fa28b00f16cccb640b1756fd6e357c03a3b81b9d119505f47b56:0
45f3f79066d251addc04fd889f776c73afab1cb22559376ff820e6166c5e3ad6:1
tx_outs:
1000273:1976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac
40000000:1976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac
locktime: 410438
TXT;

        $tx = Tx::parse($rawTx);
        self::assertSame($expectedSerialization, (string) $tx);
        self::assertSame(self::LARGE_TX, bin2hex($tx->serialize()));
    }

    /**
     * @dataProvider transactionVerificationProvider
     */
    public function testTransactionVerification(string $txId): void
    {
        self::assertTrue(Tx\Fetcher::fetch($txId, testnet: true)->verify());
    }

    public static function transactionVerificationProvider(): array
    {
        return [
            'Testnet legacy transaction, 1 input 1 output'   => ['c91bfb1368353aa3d30e2492f3ec4eb8e701d28bd2dfe0aa2731543ff3f29218'],
            'Testnet legacy transaction, 1 input 2 outputs'  => ['52559dc26a305f38a1a058a0f413f0a3142c76841176b3a2fe701128f582bfcc'],
            'Testnet legacy transaction, 2 inputs 2 outputs' => ['1f66560bda7196f6378f8cc7c9d2ff8abafb196d4fb2b5d1660fd0ff4a71dd25'],
        ];
    }

    public function testTransactionCreation(): void
    {
        $txIn = new Tx\Input('f781eac22fd176430c7dbf37b9e55dcb2128089854b7d7c0f43eb61012d610e5', 0);

        $txOut1 = new Tx\Output(14424, Tx\Script::payToPubKeyHash(Encoding::base58decode('n14VanAQTFrZcMV8GqfUQmors2NCUBXCin')));
        $txOut2 = new Tx\Output(4878, Tx\Script::payToPubKeyHash(Encoding::base58decode('mfoZu55yYex1X575MRpHJc8yDDttzvyx3M')));
        $txOut3 = new Tx\Output(0, Tx\Script::opReturn('Aquesta transacció ha estat construïda amb PHP, sang i llàgrimes.'));

        $expectedDebugView = <<<TXT
tx: ef448d0587b95a118ab8fb77fd528ef82883d6a97c1a06313f2b99b9d52abea1
version: 1
tx_ins:
f781eac22fd176430c7dbf37b9e55dcb2128089854b7d7c0f43eb61012d610e5:0
tx_outs:
14424:1976a914d6616725f82bef6379cc3a9b9993939dacf31eea88ac
4878:1976a9140324603ae536eed36317f4940e367cd8e027293288ac
0:466a4441717565737461207472616e7361636369c3b320686120657374617420636f6e73747275c3af646120616d62205048502c2073616e672069206c6cc3a06772696d65732e
locktime: 0
TXT;

        $tx = new Tx(1, [$txIn], [$txOut1, $txOut2, $txOut3], locktime: 0, testnet: true);

        self::assertSame($expectedDebugView, (string) $tx);
        self::assertSame(314, $tx->fee());

        self::assertTrue($tx->signInput(0, new PrivateKey(gmp_init('0x97fd784cf2f47514bbff4ae9047b5e6a98a8b456b92f8f2c3aa61ce71911430a'))));
        self::assertTrue($tx->verify());

        self::assertSame(
            '0100000001e510d61210b63ef4c0d7b75498082821cb5de5b937bf7d0c4376d12fc2ea81f7000000006a47304402201a8c717ea78f9072f1f2f7ccf93a9512fb8d49dd0bdf614d67a1237761c7cd8c022030bb04d2057d2e8133fe12d9a6104442a9ddbef993a3f5adc382d908dda24b0801210290c7f33f050a916c31fb17250d8fd755448ee79ff8398f848ce74e056a545606ffffffff0358380000000000001976a914d6616725f82bef6379cc3a9b9993939dacf31eea88ac0e130000000000001976a9140324603ae536eed36317f4940e367cd8e027293288ac0000000000000000466a4441717565737461207472616e7361636369c3b320686120657374617420636f6e73747275c3af646120616d62205048502c2073616e672069206c6cc3a06772696d65732e00000000',
            bin2hex($tx->serialize())
        );
    }

    public function testWhackyTransactionCreation(): void
    {
        $txIn1 = new Tx\Input('7684d6893890d63a6ee8e14f6400e3168fd1638926350bbee8b79dc733f81159', 0);
        $txIn2 = new Tx\Input('7684d6893890d63a6ee8e14f6400e3168fd1638926350bbee8b79dc733f81159', 1);

        $txOut = new Tx\Output(0, Tx\Script::opReturn('Tot vostre, fills de puta.'));

        $expectedDebugView = <<<TXT
tx: da060c1b0d7832320c7b2a52ca9ec4c43533fc095eb9509c750c2ec9cb465fbd
version: 1
tx_ins:
7684d6893890d63a6ee8e14f6400e3168fd1638926350bbee8b79dc733f81159:0
7684d6893890d63a6ee8e14f6400e3168fd1638926350bbee8b79dc733f81159:1
tx_outs:
0:1c6a1a546f7420766f737472652c2066696c6c7320646520707574612e
locktime: 0
TXT;

        $tx = new Tx(1, [$txIn1, $txIn2], [$txOut], locktime: 0, testnet: true);

        self::assertSame($expectedDebugView, (string) $tx);
        self::assertSame(19302, $tx->fee());

        self::assertTrue($tx->signInput(0, new PrivateKey(gmp_init('0x99816cbf9908dc7d0e03eadb953eccd4c1661d4ca52c5084beb0b2dd866e1e8b'))));
        self::assertTrue($tx->signInput(1, new PrivateKey(gmp_init('0x21c4255160194c216c61b4d58b1f8e41d1280bfa67ed9260441d94f6a9e9f94e'))));
        self::assertTrue($tx->verify());

        self::assertSame(
            '01000000025911f833c79db7e8be0b35268963d18f16e300644fe1e86e3ad6903889d68476000000006b48304502210097f902579afdf610fad780c9ced8f80217fa875581a9f169903fdec4bb8eda22022075afba423b644d2fcbe35f77d95d36ede561b8b86a4dab68a70bcd33ee7c1acb012102738c300ffa2c330a80ba9249da9ab1e27ff1ad5e5256e16158821ebb1d427bd7ffffffff5911f833c79db7e8be0b35268963d18f16e300644fe1e86e3ad6903889d68476010000006b4830450221008bfd7ba214c5e56baa78431c5a42920b30f0114972a62b86a2794e9504bf37c50220721315cc58d9983a476555d2e7f2b33ebabb755d4634226d3a0da3cfe361eedb012102757b06ba06c5f2cf8d5060af94774d6873b9d4b1e83ba7b93f8889f07d539860ffffffff0100000000000000001c6a1a546f7420766f737472652c2066696c6c7320646520707574612e00000000',
            bin2hex($tx->serialize())
        );
    }
}
