<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\Tx;

final class Finder
{
    private const MAINNET = 'https://mempool.space';
    private const TESTNET = 'https://mempool.space/testnet';

    /** @var Tx[] */
    private static array $cache = [];

    public static Fetcher $fetcher;

    /**
     * @throws \RuntimeException
     */
    public static function find(string $txId, bool $testnet = false): Tx
    {
        if (!isset(self::$fetcher)) {
            self::$fetcher = new MempoolFetcher();
        }

        if (\array_key_exists($txId, self::$cache)) {
            return self::$cache[$txId];
        }

        if (false === ($stream = self::$fetcher->fetch($txId, $testnet))) {
            throw new \RuntimeException('Failed to fetch transaction data');
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
