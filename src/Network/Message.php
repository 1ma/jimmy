<?php

declare(strict_types=1);

namespace Bitcoin\Network;

interface Message
{
    public function command(): string;

    public function serialize(): string;
}
