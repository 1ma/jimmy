<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

use Bitcoin\Hashing;

final readonly class OpHash
{
    public static function eval(array &$stack, string $algorithm): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $value = array_pop($stack);

        $stack[] = match ($algorithm) {
            'hash160' => Hashing::hash160($value),
            'hash256' => Hashing::hash256($value),
            default   => hash($algorithm, $value, true)
        };

        return true;
    }
}
