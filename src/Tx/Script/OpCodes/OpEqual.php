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

        $stack[] = array_pop($stack) === array_pop($stack) ?
            Encoding::encodeStackNum(1) :
            Encoding::encodeStackNum(0);

        return true;
    }
}
