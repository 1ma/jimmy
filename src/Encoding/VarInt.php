<?php

declare(strict_types=1);

namespace Bitcoin\Encoding;

final readonly class VarInt
{
    public static function encode(int $i): string
    {
        if ($i < 0xFD) {
            return Endian::toLE(gmp_init($i));
        } elseif ($i < 0x10000) {
            return "\xfd".Endian::toLE(gmp_init($i), 2);
        } elseif ($i < 0x100000000) {
            return "\xfe".Endian::toLE(gmp_init($i), 4);
        }

        return "\xff".Endian::toLE(gmp_init($i), 8);
    }

    /**
     * @param resource $stream
     */
    public static function decode($stream): int
    {
        $i = gmp_intval(Endian::fromLE(fread($stream, 1)));

        if (0xFD === $i) {
            return gmp_intval(Endian::fromLE(fread($stream, 2)));
        }

        if (0xFE === $i) {
            return gmp_intval(Endian::fromLE(fread($stream, 4)));
        }

        if (0xFF === $i) {
            return gmp_intval(Endian::fromLE(fread($stream, 8)));
        }

        return $i;
    }
}
