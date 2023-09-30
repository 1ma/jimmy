<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

final readonly class Op3Dup
{
    public static function eval(array &$stack): bool
    {
        if (\count($stack) < 3) {
            return false;
        }

        $stack[] = $stack[array_key_last($stack) - 2];
        $stack[] = $stack[array_key_last($stack) - 2];
        $stack[] = $stack[array_key_last($stack) - 2];

        return true;
    }
}
