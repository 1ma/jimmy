<?php

declare(strict_types=1);

namespace Bitcoin\Encoding;

use Bitcoin\Hashing;

final readonly class Base58
{
    private const string BTC_BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    private const string GMP_BASE58_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv';

    public static function encode(string $data): string
    {
        $nullBytes = 0;
        while ($nullBytes < \strlen($data) && "\x00" === $data[$nullBytes]) {
            ++$nullBytes;
        }

        $encoded = $nullBytes === \strlen($data) ? '' : gmp_strval(gmp_import($data), 58);

        return str_repeat('1', $nullBytes).strtr($encoded, self::GMP_BASE58_ALPHABET, self::BTC_BASE58_ALPHABET);
    }

    /**
     * If $check is true the last 4 bytes of the decoded data (the checksum) are not returned.
     */
    public static function decode(string $data, bool $check = false): string
    {
        $nullBytes = 0;
        while ('' !== $data && '1' === $data[0]) {
            ++$nullBytes;
            $data = substr($data, 1);
        }

        $decoded = str_repeat("\x00", $nullBytes);

        if ('' === $data) {
            return $decoded;
        }

        $decoded .= gmp_export(gmp_init(strtr($data, self::BTC_BASE58_ALPHABET, self::GMP_BASE58_ALPHABET), 58));

        if ($check) {
            $checksum = substr($decoded, -4);
            $payload  = substr($decoded, 0, -4);

            if (substr(Hashing::hash256($payload), 0, 4) !== $checksum) {
                throw new \InvalidArgumentException('Invalid checksum');
            }

            $decoded = $payload;
        }

        return $decoded;
    }

    public static function checksum(string $data): string
    {
        return self::encode($data.substr(Hashing::hash256($data), 0, 4));
    }
}
