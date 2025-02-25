<?php

declare(strict_types=1);

namespace Bitcoin\Network\Message;

use Bitcoin\Network\Message;

final readonly class VerAck implements Message
{
    public function command(): string
    {
        return 'verack';
    }

    public static function parse($stream): self
    {
        return new self();
    }

    public function serialize(): string
    {
        return '';
    }
}
