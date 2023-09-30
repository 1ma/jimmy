<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

use Bitcoin\Encoding;

final readonly class OpVerify
{
    public static function eval(array &$stack): bool
    {
        return !empty($stack) && Encoding::encodeStackNum(0) !== array_pop($stack);
    }
}
