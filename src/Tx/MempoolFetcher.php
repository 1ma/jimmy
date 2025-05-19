<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\Network;

/**
 * @codeCoverageIgnore
 */
final readonly class MempoolFetcher implements Fetcher
{
    private const string MAINNET_ENDPOINT = 'https://mempool.space';
    private const string TESTNET_ENDPOINT = 'https://mempool.space/testnet';

    public function fetch(string $txId, Network $mode): mixed
    {
        $httpStream = fopen((Network::TESTNET === $mode ? self::TESTNET_ENDPOINT : self::MAINNET_ENDPOINT)."/api/tx/$txId/raw", 'r');
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
