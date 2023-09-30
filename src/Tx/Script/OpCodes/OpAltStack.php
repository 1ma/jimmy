<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

final readonly class OpAltStack
{
    public static function eval(array &$source, array &$destination): bool
    {
        if (\count($source) < 1) {
            return false;
        }

        $destination[] = array_pop($source);

        return true;
    }
}
