<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

final readonly class Op2Dup
{
    public static function eval(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $stack[] = $stack[array_key_last($stack) - 1];
        $stack[] = $stack[array_key_last($stack) - 1];

        return true;
    }
}
