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

        $stack[] = match (Encoding\StackNum::decode(array_pop($stack))) {
            0       => Encoding\StackNum::encode($zeroBranchValue),
            default => Encoding\StackNum::encode($defaultBranchValue),
        };

        return true;
    }
}
