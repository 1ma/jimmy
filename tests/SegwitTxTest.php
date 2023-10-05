<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\Tx;
use PHPUnit\Framework\TestCase;

final class SegwitTxTest extends TestCase
{
    use StreamingHelperTrait;

    private const SIMPLE_SEGWIT_TX        = '02000000000101855da197e40631d06d2a3e72af766ffbf5b092a86aae92a4f80f18390a9338450100000000fdffffff026d741ce301000000160014b97d52217016d38cef37eafd8bd39f60884a5060e3bc1c000000000016001490bcc810ae94fd4fb325722c0d9572496e66cdcc0247304402206dda1ec0f70d7bbd61120a445421db3bedc7f36a67524fb02ff127ca3e199e7f022060760eb6cec81cf7b19ace44d6e95ba1a7e45f1a36c3778197927f6edd5088aa0121021c62d454d1e7f3e42d4cb404483ecdce92a64f04c883cb2321eece2375c423d5679b2600';
    private const SIMPLE_SEGWIT_WITNESS_0 = '304402206dda1ec0f70d7bbd61120a445421db3bedc7f36a67524fb02ff127ca3e199e7f022060760eb6cec81cf7b19ace44d6e95ba1a7e45f1a36c3778197927f6edd5088aa01';
    private const SIMPLE_SEGWIT_WITNESS_1 = '021c62d454d1e7f3e42d4cb404483ecdce92a64f04c883cb2321eece2375c423d5';

    public function testSegwitTxParsing(): void
    {
        $tx = Tx::parse(self::stream(hex2bin(self::SIMPLE_SEGWIT_TX)));

        self::assertSame(2, $tx->version);
        self::assertCount(1, $tx->txIns);
        self::assertEmpty($tx->txIns[0]->scriptSig->cmds);
        self::assertSame(0xFFFFFFFD, $tx->txIns[0]->seqNum);
        self::assertCount(2, $tx->txIns[0]->witness);
        self::assertSame(hex2bin(self::SIMPLE_SEGWIT_WITNESS_0), $tx->txIns[0]->witness[0]);
        self::assertSame(hex2bin(self::SIMPLE_SEGWIT_WITNESS_1), $tx->txIns[0]->witness[1]);
        self::assertCount(2, $tx->txOuts);
        self::assertSame(2530151, $tx->locktime);

        self::assertSame(hex2bin(self::SIMPLE_SEGWIT_TX), $tx->serialize());
    }
}
