<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

final readonly class OpDup
{
    public static function eval(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = $stack[array_key_last($stack)];

        return true;
    }
}
