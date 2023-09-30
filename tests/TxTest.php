<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

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
        $txIn = new Tx\Input('0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299', 13);

        $txOut1 = new Tx\Output(33000000, Tx\Script::payToPubKeyHash(Encoding::base58decode('mzx5YhAH9kNHtcN481u6WkjeHjYtVeKVh2')));
        $txOut2 = new Tx\Output(10000000, Tx\Script::payToPubKeyHash(Encoding::base58decode('mvWZEw2tsFaKVDb77ntJPrYrqnLCDYsbWX')));

        $expectedSerialization = <<<TXT
tx: a8581a29534cfa50cc545c56efd9e9241b77395a08f4c971354f3039605b69ec
version: 1
tx_ins:
0d6fe5213c0b3291f208cba8bfb59b7476dffacc4e5cb66f6eb20a080843a299:13
tx_outs:
33000000:1976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac
10000000:1976a914a476a47413b44c8a2067cf947d97b4ecccdb739488ac
locktime: 0
TXT;

        self::assertSame($expectedSerialization, (string) new Tx(1, [$txIn], [$txOut1, $txOut2], locktime: 0, testnet: true));
    }
}
