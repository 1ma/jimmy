<?php

declare(strict_types=1);

namespace Bitcoin;

final class Script
{
    public string $script;

    public function __construct(string $script)
    {
        $this->script = $script;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream): self
    {
        return new self(fread($stream, Encoding::decodeVarInt($stream)));
    }

    public function serialize(): string
    {
        $length = Encoding::encodeVarInt(\strlen($this->script));

        return $length.$this->script;
    }

    public function __toString(): string
    {
        return bin2hex($this->script);
    }
}
