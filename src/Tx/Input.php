<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\Encoding;
use Bitcoin\Network;

final class Input
{
    public readonly string $prevTxId;
    public readonly int $prevIndex;
    public Script $scriptSig;
    public readonly int $seqNum;

    /** @var <int|string>[] */
    public array $witness;

    public const int DISABLE_REPLACE_BY_FEE  = 0xFFFFFFFF;
    public const int BIP125_REPLACE_BY_FEE   = 0xFFFFFFFD;
    public const int DEFAULT_SEQUENCE_NUMBER = self::BIP125_REPLACE_BY_FEE;

    public function __construct(string $prevTxId, int $prevIndex, ?Script $scriptSig = null, int $seqNum = self::DEFAULT_SEQUENCE_NUMBER, array $witness = [])
    {
        $this->prevTxId  = $prevTxId;
        $this->prevIndex = $prevIndex;
        $this->scriptSig = $scriptSig ?? new Script();
        $this->seqNum    = $seqNum;
        $this->witness   = $witness;
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
    public function prevOutput(Network $mode = Network::TESTNET): Output
    {
        return Finder::find($this->prevTxId, $mode)->txOuts[$this->prevIndex];
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
