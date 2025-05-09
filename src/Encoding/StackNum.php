<?php

declare(strict_types=1);

namespace Bitcoin\Encoding;

final readonly class StackNum
{
    public static function encode(int $num): string
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

    public static function decode(string $element): int
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
