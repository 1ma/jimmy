<?php

declare(strict_types=1);

namespace Bitcoin\Network\Message;

use Bitcoin\Block;
use Bitcoin\Encoding;
use Bitcoin\Network\Message;

final readonly class Headers implements Message
{
    /**
     * @var Block[]
     */
    public array $blocks;

    public function __construct(Block ...$blocks)
    {
        $this->blocks = $blocks;
    }

    public function command(): string
    {
        return 'headers';
    }

    public static function parse($stream): self
    {
        $blocks  = [];
        $headers = Encoding\VarInt::decode($stream);
        for ($i = 0; $i < $headers; ++$i) {
            $blocks[] = Block::parse($stream);
            if (0 !== $numTxs = Encoding\VarInt::decode($stream)) {
                throw new \RuntimeException("Unexpected number of txs in 'headers' message: $numTxs");
            }
        }

        return new self(...$blocks);
    }

    public function serialize(): string
    {
        throw new \LogicException('not implemented');
    }
}
