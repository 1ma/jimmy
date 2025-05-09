<?php

declare(strict_types=1);

namespace Bitcoin\Network\Message;

use Bitcoin\Encoding;
use Bitcoin\Network\Message;

final readonly class GetHeaders implements Message
{
    public int $protocolVersion;
    public int $numHashes;
    public string $startingBlock;
    public string $endingBlock;

    public function __construct(int $protocolVersion, int $numHashes, string $startingBlock, string $endingBlock)
    {
        $this->protocolVersion = $protocolVersion;
        $this->numHashes       = $numHashes;
        $this->startingBlock   = $startingBlock;
        $this->endingBlock     = $endingBlock;
    }

    public function command(): string
    {
        return 'getheaders';
    }

    public static function parse($stream): self
    {
        throw new \LogicException('not implemented');
    }

    public function serialize(): string
    {
        $protocolVersion = Encoding\Endian::toLE(gmp_init($this->protocolVersion), 4);
        $numHahes        = Encoding\VarInt::encode($this->numHashes);
        $startingBlock   = strrev(hex2bin($this->startingBlock));
        $endingBlock     = strrev(hex2bin($this->endingBlock));

        return $protocolVersion.$numHahes.$startingBlock.$endingBlock;
    }
}
