<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

use Bitcoin\Encoding;

final readonly class OpEqual
{
    public static function eval(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $stack[] = Encoding\StackNum::encode(array_pop($stack) === array_pop($stack) ? 1 : 0);

        return true;
    }
}
