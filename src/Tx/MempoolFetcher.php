<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

final class MempoolFetcher implements Fetcher
{
    private const MAINNET = 'https://mempool.space';
    private const TESTNET = 'https://mempool.space/testnet';

    public function fetch(string $txId, bool $testnet): mixed
    {
        return fopen(($testnet ? self::TESTNET : self::MAINNET)."/api/tx/$txId/raw", 'r');
    }
}
