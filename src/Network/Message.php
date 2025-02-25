<?php

declare(strict_types=1);

namespace Bitcoin\Network;

interface Message
{
    public function command(): string;

    /**
     * @param resource $stream
     */
    public static function parse($stream): self;

    public function serialize(): string;
}
