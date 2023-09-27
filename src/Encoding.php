<?php

declare(strict_types=1);

namespace Bitcoin;

final class Encoding
{
    private const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    public static function base58encode(string $data): string
    {
        $nullBytes = 0;
        while ($nullBytes < \strlen($data) && "\x00" === $data[$nullBytes]) {
            ++$nullBytes;
        }

        $result = '';
        $num    = gmp_import($data);

        while ($num > 0) {
            [$num, $mod] = gmp_div_qr($num, 58);
            $result      = self::BASE58_ALPHABET[gmp_intval($mod)].$result;
        }

        return str_repeat('1', $nullBytes).$result;
    }

    public static function base58checksum(string $data): string
    {
        return self::base58encode($data.substr(Hashing::hash256($data), 0, 4));
    }

    public static function fromLE(string $payload): \GMP
    {
        return gmp_import($payload, 1, \GMP_LSW_FIRST | \GMP_LITTLE_ENDIAN);
    }

    public static function toLE(\GMP $number, int $padding = 0): string
    {
        return str_pad(gmp_export($number, 1, \GMP_LSW_FIRST | \GMP_LITTLE_ENDIAN), $padding, "\x00");
    }

    public static function encodeVarInt(int $i): string
    {
        if ($i < 0xFD) {
            return self::toLE(gmp_init($i));
        } elseif ($i < 0x10000) {
            return "\xfd".self::toLE(gmp_init($i), 2);
        } elseif ($i < 0x100000000) {
            return "\xfe".self::toLE(gmp_init($i), 4);
        }

        return "\xff".self::toLE(gmp_init($i), 8);
    }

    /**
     * @param resource $stream
     */
    public static function decodeVarInt($stream): int
    {
        $i = gmp_intval(self::fromLE(fread($stream, 1)));

        if (0xFD === $i) {
            return gmp_intval(self::fromLE(fread($stream, 2)));
        }

        if (0xFE === $i) {
            return gmp_intval(self::fromLE(fread($stream, 4)));
        }

        if (0xFF === $i) {
            return gmp_intval(self::fromLE(fread($stream, 8)));
        }

        return $i;
    }
}
