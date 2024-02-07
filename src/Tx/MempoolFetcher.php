<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

final class MempoolFetcher implements Fetcher
{
    private const string MAINNET = 'https://mempool.space';
    private const string TESTNET = 'https://mempool.space/testnet';

    public function fetch(string $txId, bool $testnet): mixed
    {
        $httpStream = fopen(($testnet ? self::TESTNET : self::MAINNET)."/api/tx/$txId/raw", 'r');
        if (false === $httpStream) {
            return false;
        }

        $localStream = fopen('php://memory', 'r+');
        stream_copy_to_stream($httpStream, $localStream);

        rewind($localStream);
        fclose($httpStream);

        return $localStream;
    }
}
