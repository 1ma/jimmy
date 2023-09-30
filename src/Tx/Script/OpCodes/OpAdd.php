<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

use Bitcoin\Encoding;

final readonly class OpAdd
{
    public static function eval(array &$stack): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        $stack[] = Encoding::encodeStackNum(
            Encoding::decodeStackNum(array_pop($stack)) + Encoding::decodeStackNum(array_pop($stack))
        );

        return true;
    }
}
