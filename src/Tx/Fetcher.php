<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\Network;

interface Fetcher
{
    /**
     * @return resource|false
     */
    public function fetch(string $txId, Network $mode): mixed;
}
