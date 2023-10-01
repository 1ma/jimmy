<?php

declare(strict_types=1);

namespace Bitcoin\Tx\Script\OpCodes;

use Bitcoin\ECC\S256Point;
use Bitcoin\ECC\Signature;
use Bitcoin\Encoding;

final readonly class OpCheckMultiSig
{
    public static function eval(array &$stack, \GMP $z): bool
    {
        if (\count($stack) < 1) {
            return false;
        }

        $n = Encoding::decodeStackNum(array_pop($stack));
        if ($n < 0 || \count($stack) < $n + 1) {
            return false;
        }

        $pubkeys = [];
        while ($n > 0) {
            $pubkeys[] = array_pop($stack);
            --$n;
        }

        $m = Encoding::decodeStackNum(array_pop($stack));
        if ($m < 0 || \count($stack) < $m + 1) {
            return false;
        }

        $sigs = [];
        while ($m > 0) {
            $sigs[] = array_pop($stack);
            --$m;
        }

        // Satoshi's off-by-one error
        array_pop($stack);

        try {
            $pubkeys = array_map(fn (string $sec): S256Point => S256Point::parse($sec), $pubkeys);
            $sigs    = array_map(fn (string $der): Signature => Signature::parse($der), $sigs);

            foreach ($sigs as $sig) {
                if (empty($pubkeys)) {
                    return false;
                }

                $match = false;
                foreach ($pubkeys as $pubkey) {
                    if ($match = $pubkey->verify($z, $sig)) {
                        break;
                    }
                }

                if (!$match) {
                    return false;
                }
            }
        } catch (\InvalidArgumentException) {
            return false;
        }

        return true;
    }
}
