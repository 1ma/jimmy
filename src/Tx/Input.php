<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\Encoding;

final class Input
{
    public readonly string $prevTxId;
    public readonly int $prevIndex;
    public Script $scriptSig;
    public readonly int $seqNum;

    private const DEFAULT_SEQUENCE_NUMBER = 0xFFFFFFFF;

    public function __construct(string $prevTxId, int $prevIndex, Script $scriptSig = null, int $seqNum = self::DEFAULT_SEQUENCE_NUMBER)
    {
        $this->prevTxId  = $prevTxId;
        $this->prevIndex = $prevIndex;
        $this->scriptSig = $scriptSig ?? new Script();
        $this->seqNum    = $seqNum;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream): self
    {
        $prevTxId  = bin2hex(strrev(fread($stream, 32)));
        $prevIndex = gmp_intval(Encoding::fromLE(fread($stream, 4)));
        $scriptSig = Script::parse($stream);
        $seqNum    = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        return new self($prevTxId, $prevIndex, $scriptSig, $seqNum);
    }

    /**
     * @throws \RuntimeException
     */
    public function prevAmount(bool $testnet = true): int
    {
        return Finder::find($this->prevTxId, $testnet)->txOuts[$this->prevIndex]->amount;
    }

    /**
     * @throws \RuntimeException
     */
    public function prevScriptPubKey(bool $testnet = true): Script
    {
        return Finder::find($this->prevTxId, $testnet)->txOuts[$this->prevIndex]->scriptPubKey;
    }

    public function serialize(): string
    {
        $prevTxId  = strrev(hex2bin($this->prevTxId));
        $prevIndex = Encoding::toLE(gmp_init($this->prevIndex), 4);
        $scriptSig = $this->scriptSig->serialize();
        $seqNum    = Encoding::toLE(gmp_init($this->seqNum), 4);

        return $prevTxId.$prevIndex.$scriptSig.$seqNum;
    }

    public function __toString(): string
    {
        return "{$this->prevTxId}:{$this->prevIndex}";
    }
}
