<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

final readonly class OpSwap
{
    public static function eval(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $first  = array_pop($stack);
        $second = array_pop($stack);

        $stack[] = $first;
        $stack[] = $second;

        return true;
    }
}
