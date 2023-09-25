<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class TxOut
{
    public int $amount;
    public Script $scriptPubKey;

    public function __construct(int $amount, Script $scriptPubKey)
    {
        $this->amount = $amount;
        $this->scriptPubKey = $scriptPubKey;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream)
    {
        $amount = gmp_intval(Encoding::fromLE(fread($stream, 8)));
        $scriptPubKey = Script::parse($stream);

        return new self($amount, $scriptPubKey);
    }

    public function __toString(): string
    {
        return "{$this->amount}:{$this->scriptPubKey}";
    }
}
