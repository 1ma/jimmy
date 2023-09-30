<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

final readonly class OpDrop
{
    public static function eval(array &$stack): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        array_pop($stack);

        return true;
    }
}
