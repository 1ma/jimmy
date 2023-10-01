<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

interface Fetcher
{
    /**
     * @return resource|false
     */
    public function fetch(string $txId, bool $testnet): mixed;
}
