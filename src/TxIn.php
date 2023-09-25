<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class TxIn
{
    public string $prevTxId;
    public int $prevIndex;
    public Script $scriptSig;
    public int $seqNum;

    public function __construct(string $prevTxId, int $prevIndex, Script $scriptSig, int $seqNum)
    {
        $this->prevTxId = $prevTxId;
        $this->prevIndex = $prevIndex;
        $this->scriptSig = $scriptSig;
        $this->seqNum = $seqNum;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream): self
    {
        $prevTxId = strrev(fread($stream, 32));
        $prevIndex = gmp_intval(Encoding::fromLE(fread($stream, 4)));
        $scriptSig = Script::parse($stream);
        $seqNum = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        return new self($prevTxId, $prevIndex, $scriptSig, $seqNum);
    }

    public function serialize(): string
    {
        $prevTxId = strrev($this->prevTxId);
        $prevIndex = Encoding::toLE(gmp_init($this->prevIndex), 4);
        $scriptSig = $this->scriptSig->serialize();
        $seqNum = Encoding::toLE(gmp_init($this->seqNum), 4);

        return $prevTxId.$prevIndex.$scriptSig.$seqNum;
    }

    public function __toString(): string
    {
        $prevTxId = bin2hex($this->prevTxId);

        return "{$prevTxId}:{$this->prevIndex}";
    }
}
