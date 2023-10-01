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

        $top    = array_pop($stack);
        $bottom = array_pop($stack);

        $stack[] = $top;
        $stack[] = $bottom;

        return true;
    }
}
