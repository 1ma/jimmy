<?php

declare(strict_types=1);

namespace Bitcoin\Encoding;

final readonly class Address
{
    public static function decode(string $address): string
    {
        if (\in_array(substr(strtolower($address), 0, 3), ['bc1', 'tb1'], true)) {
            [$version, $program] = Bech32::segwitDecode($address, substr(strtolower($address), 0, 2));

            return pack('C*', ...$program);
        }

        $data = Base58::decode($address, check: true);
        if (21 !== \strlen($data)) {
            throw new \InvalidArgumentException('Unexpected data length');
        }

        // Ignore address version, just return the payload (hash160 of the public key)
        return substr($data, 1);
    }
}
