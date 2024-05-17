<?php

declare(strict_types=1);

namespace Bitcoin\Tx;

use Bitcoin\Network;
use Bitcoin\Tx;

final class Finder
{
    /** @var Tx[] */
    private static array $cache = [];

    public static Fetcher $fetcher;

    /**
     * @throws \RuntimeException
     */
    public static function find(string $txId, Network $mode = Network::TESTNET): Tx
    {
        if (!isset(self::$fetcher)) {
            self::$fetcher = new MempoolFetcher();
        }

        if (\array_key_exists($txId, self::$cache)) {
            return self::$cache[$txId];
        }

        if (false === ($stream = self::$fetcher->fetch($txId, $mode))) {
            throw new \RuntimeException('Failed to fetch transaction data');
        }

        $tx = Tx::parse($stream, $mode);
        fclose($stream);

        if ($tx->id() !== $txId) {
            throw new \RuntimeException("Don't trust, verify! The computed TxId doesn't match what we asked for.");
        }

        self::$cache[$txId] = $tx;

        return $tx;
    }
}
