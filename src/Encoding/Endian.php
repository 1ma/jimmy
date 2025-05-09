<?php

declare(strict_types=1);

namespace Bitcoin\Encoding;

final readonly class Endian
{
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

    public static function toBE(\GMP $number, int $padding): string
    {
        // gmp_export(GMP(0)) returns an empty string instead of the 0x00 byte
        $be = 0 == $number ? "\x00" : gmp_export($number);

        return str_pad($be, $padding, "\x00", \STR_PAD_LEFT);
    }
}
