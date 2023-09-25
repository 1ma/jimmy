<?php

declare(strict_types=1);

namespace Bitcoin\Tests;

use Bitcoin\Tx;
use Bitcoin\TxIn;
use Bitcoin\TxOut;
use PHPUnit\Framework\TestCase;

final class TxTest extends TestCase
{
    public function testDebugSerialization(): void
    {
        $tx = new Tx(1, [new TxIn()], [new TxOut()], 0, true);

        $expectedSerialization = <<<TXT
tx: efe059c8874dbe00c930b5fe5b35d05b9c20b98d18273563dbb0c4d9f5d06068
version: 1
tx_ins:
TxIn
tx_outs:
TxOut
locktime: 0
TXT;

        self::assertSame($expectedSerialization, (string) $tx);
    }
}
