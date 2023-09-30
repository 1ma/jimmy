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
            $signature = Signature::parse(substr(array_pop($stack), 0, -1));
        } catch (\InvalidArgumentException) {
            return false;
        }

        $stack[] = $pubKey->verify($z, $signature) ?
            Encoding::encodeStackNum(1) :
            Encoding::encodeStackNum(0);

        return true;
    }
}
