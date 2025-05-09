<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\Encoding;

final readonly class Output
{
    public int $amount;
    public Script $scriptPubKey;

    public function __construct(int $amount, Script $scriptPubKey)
    {
        $this->amount       = $amount;
        $this->scriptPubKey = $scriptPubKey;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream)
    {
        $amount       = gmp_intval(Encoding\Endian::fromLE(fread($stream, 8)));
        $scriptPubKey = Script::parse($stream);

        return new self($amount, $scriptPubKey);
    }

    public function serialize(): string
    {
        $amount       = Encoding\Endian::toLE(gmp_init($this->amount), 8);
        $scriptPubKey = $this->scriptPubKey->serialize();

        return $amount.$scriptPubKey;
    }

    public function __toString(): string
    {
        return "{$this->amount}:{$this->scriptPubKey}";
    }
}
