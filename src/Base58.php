<?php

declare(strict_types=1);

namespace Bitcoin;

final class Base58
{
    private const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    public static function encode(string $data): string
    {
        $whitespace = 0;
        while ($whitespace < \strlen($data) && "\x00" === $data[$whitespace]) {
            ++$whitespace;
        }

        $result = '';
        $num = gmp_import($data);

        while ($num > 0) {
            [$num, $mod] = gmp_div_qr($num, 58);
            $result = self::BASE58_ALPHABET[gmp_intval($mod)].$result;
        }

        return str_repeat('1', $whitespace).$result;
    }

    public static function encodeWithChecksum(string $data): string
    {
        return self::encode($data.substr(Hashing::hash256($data), 0, 4));
    }

    public static function decode(string $data): string
    {
        // TODO
        return '';
    }
}
