<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

use Bitcoin\Encoding;

final readonly class OpNum
{
    public static function eval(array &$stack, int $num): bool
    {
        $stack[] = Encoding::encodeStackNum($num);

        return true;
    }
}
