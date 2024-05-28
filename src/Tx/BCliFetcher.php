<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\Network;

final class BCliFetcher implements Fetcher
{
    public function fetch(string $txId, Network $mode): mixed
    {
        if (!\is_string($result = shell_exec("bitcoin-cli getrawtransaction $txId"))) {
            return false;
        }

        if (str_contains($result, 'No such mempool or blockchain transaction')) {
            return false;
        }

        $data   = hex2bin(trim($result));
        $stream = fopen('php://memory', 'r+');
        fwrite($stream, $data);
        rewind($stream);

        return $stream;
    }
}
