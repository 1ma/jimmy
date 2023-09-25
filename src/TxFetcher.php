<?php

declare(strict_types=1);

namespace Bitcoin;

final class TxFetcher
{
    private const MAINNET = 'https://mempool.space';
    private const TESTNET = 'https://mempool.space/testnet';

    /** @var Tx[] */
    private static array $cache = [];

    /**
     * @throws \RuntimeException
     */
    public static function fetch(string $txId, bool $testnet = false): Tx
    {
        if (\array_key_exists($txId, self::$cache)) {
            return self::$cache[$txId];
        }

        $stream = fopen(self::getUrl($testnet)."/api/tx/$txId/raw", 'r');
        if (false === $stream) {
            throw new \RuntimeException('Failed to fetch transaction data from '.self::getUrl($testnet));
        }

        $tx = Tx::parse($stream, $testnet);
        fclose($stream);

        if ($tx->id() !== $txId) {
            throw new \RuntimeException("Don't trust, verify! The computed TxId doesn't match what we asked for.");
        }

        self::$cache[$txId] = $tx;

        return $tx;
    }

    private static function getUrl(bool $testnet): string
    {
        return $testnet ? self::TESTNET : self::MAINNET;
    }
}
