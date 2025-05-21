<?php

declare(strict_types=1);

namespace Bitcoin\Encoding;

use Bitcoin\ECC\PublicKey;
use Bitcoin\Hashing;
use Bitcoin\Network;

final readonly class Address
{
    private const string P2PKH_MAINNET_PREFIX = "\x00";
    private const string P2PKH_TESTNET_PREFIX = "\x6f";

    private const string P2SH_MAINNET_PREFIX = "\x05";
    private const string P2SH_TESTNET_PREFIX = "\xc4";

    public static function decode(string $address): string
    {
        // Bech32 addresses
        if (\in_array(substr(strtolower($address), 0, 3), ['bc1', 'tb1'], true)) {
            [$version, $program] = Bech32::segwitDecode($address, substr(strtolower($address), 0, 2));

            return pack('C*', ...$program);
        }

        // Base58 addresses
        $data = Base58::decode($address, check: true);
        if (21 !== \strlen($data)) {
            throw new \InvalidArgumentException('Unexpected data length');
        }

        // Ignore address version, just return the payload (hash160 of the public key)
        return substr($data, 1);
    }

    public static function p2pkh(PublicKey $p, bool $compressed = true, Network $mode = Network::TESTNET): string
    {
        $prefix = Network::MAINNET === $mode ? self::P2PKH_MAINNET_PREFIX : self::P2PKH_TESTNET_PREFIX;

        return Base58::checksum($prefix.Hashing::hash160($p->sec($compressed)));
    }

    public static function p2sh(string $hash, Network $mode = Network::TESTNET): string
    {
        return Base58::checksum((Network::TESTNET === $mode ? self::P2SH_TESTNET_PREFIX : self::P2SH_MAINNET_PREFIX).$hash);
    }

    public static function p2wpkh(PublicKey $p, Network $mode = Network::TESTNET): string
    {
        $hrp = Network::MAINNET === $mode ? Bech32::MAINNET_HRP : Bech32::TESTNET_HRP;

        return Bech32::segwitEncode(0, unpack('C*', Hashing::hash160($p->sec(true))), $hrp);
    }
}
