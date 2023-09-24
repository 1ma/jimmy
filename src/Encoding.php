<?php

declare(strict_types=1);

namespace Bitcoin;

final class Encoding
{
    private const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    public static function fromLE(string $payload): \GMP
    {
        return gmp_import($payload, 1, \GMP_LSW_FIRST | \GMP_LITTLE_ENDIAN);
    }

    public static function toLE(\GMP $number): string
    {
        return gmp_export($number, 1, \GMP_LSW_FIRST | \GMP_LITTLE_ENDIAN);
    }

    public static function base58encode(string $data): string
    {
        $nullBytes = 0;
        while ($nullBytes < \strlen($data) && "\x00" === $data[$nullBytes]) {
            ++$nullBytes;
        }

        $result = '';
        $num = gmp_import($data);

        while ($num > 0) {
            [$num, $mod] = gmp_div_qr($num, 58);
            $result = self::BASE58_ALPHABET[gmp_intval($mod)].$result;
        }

        return str_repeat('1', $nullBytes).$result;
    }

    public static function base58checksum(string $data): string
    {
        return self::base58encode($data.substr(Hashing::hash256($data), 0, 4));
    }

    public static function base58decode(string $data): string
    {
        // TODO
        return '';
    }
}
