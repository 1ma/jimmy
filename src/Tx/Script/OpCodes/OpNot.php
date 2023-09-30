<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

use Bitcoin\Encoding;

final readonly class OpNot
{
    public static function eval(array &$stack, int $zeroBranchValue, int $defaultBranchValue): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $stack[] = match (Encoding::decodeStackNum(array_pop($stack))) {
            0       => Encoding::encodeStackNum($zeroBranchValue),
            default => Encoding::encodeStackNum($defaultBranchValue)
        };

        return true;
    }
}
