<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class Encoding
{
    private const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    private const P2PKH_MAINNET_PREFIX = "\x00";
    private const P2PKH_TESTNET_PREFIX = "\x6f";

    private const P2SH_MAINNET_PREFIX = "\x05";
    private const P2SH_TESTNET_PREFIX = "\xc4";

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

    public static function base58decode(string $address): string
    {
        $num = gmp_init(0);
        for ($i = 0; $i < \strlen($address); ++$i) {
            $num *= 58;
            $digit = strpos(self::BASE58_ALPHABET, $address[$i]);

            if (false === $digit) {
                throw new \InvalidArgumentException('Invalid character in base58 data: '.$address[$i]);
            }

            $num += $digit;
        }

        $combined = str_pad(gmp_export($num), 25, "\x00", \STR_PAD_LEFT);
        $checksum = substr($combined, -4);
        $data     = substr($combined, 0, -4);

        if (substr(Hashing::hash256($data), 0, 4) !== $checksum) {
            throw new \InvalidArgumentException('bad address');
        }

        return substr($data, 1);
    }

    public static function hash160ToPayToPublicKeyHashAddress(string $hash, bool $testnet = true): string
    {
        return self::base58checksum(($testnet ? self::P2PKH_TESTNET_PREFIX : self::P2PKH_MAINNET_PREFIX).$hash);
    }

    public static function hash160ToPayToScriptKeyHashAddress(string $hash, bool $testnet = true): string
    {
        return self::base58checksum(($testnet ? self::P2SH_TESTNET_PREFIX : self::P2SH_MAINNET_PREFIX).$hash);
    }

    public static function fromLE(string $payload): \GMP
    {
        return gmp_import($payload, 1, \GMP_LSW_FIRST | \GMP_LITTLE_ENDIAN);
    }

    public static function toLE(\GMP $number, int $padding = 0): string
    {
        // gmp_export(GMP(0)) returns an empty string instead of the 0x00 byte
        $le = 0 == $number ? "\x00" : gmp_export($number, 1, \GMP_LSW_FIRST | \GMP_LITTLE_ENDIAN);

        return str_pad($le, $padding, "\x00");
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

    public static function encodeStackNum(int $num): string
    {
        if (0 === $num) {
            return '';
        }

        $absNum   = abs($num);
        $negative = $num < 0;
        $result   = [];
        while ($absNum > 0) {
            $result[] = $absNum & 0xFF;
            $absNum >>= 8;
        }

        if ($result[array_key_last($result)] & 0x80) {
            $result[] = $negative ? 0x80 : 0x00;
        } elseif ($negative) {
            $result[array_key_last($result)] |= 0x80;
        }

        return pack('C'.\count($result), ...$result);
    }

    public static function decodeStackNum(string $element): int
    {
        if ('' === $element) {
            return 0;
        }

        $bigEndian = array_values(unpack('C'.\strlen($element), strrev($element)));

        $negative = $bigEndian[0] & 0x80;
        $result   = $bigEndian[0] & 0x80 ? $bigEndian[0] & 0x7F : $bigEndian[0];

        for ($i = 1; $i < \count($bigEndian); ++$i) {
            $result <<= 8;
            $result += $bigEndian[$i];
        }

        return $negative ? -$result : $result;
    }
}
