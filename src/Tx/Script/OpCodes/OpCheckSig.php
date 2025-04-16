<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;
use Bitcoin\Encoding;

final readonly class OpCheckSig
{
    public static function eval(array &$stack, \GMP $z): bool
    {
        if (\count($stack) < 2) {
            return false;
        }

        try {
            $pubKey = S256Point::parse(array_pop($stack));

            // sighash byte must be stripped from the DER data
            $signature = Signature::parse(substr(array_pop($stack), 0, -1), true);
        } catch (\InvalidArgumentException) {
            return false;
        }

        $stack[] = Encoding::encodeStackNum($pubKey->ecdsa($z, $signature) ? 1 : 0);

        return true;
    }
}
