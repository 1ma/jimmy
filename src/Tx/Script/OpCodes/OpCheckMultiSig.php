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

        $pubKeys = [];
        while ($n > 0) {
            $pubKeys[] = array_pop($stack);
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
            $pubKeys = array_map(fn (string $sec): S256Point => S256Point::parse($sec), $pubKeys);
            $sigs    = array_map(fn (string $der): Signature => Signature::parse(substr($der, 0, -1)), $sigs);

            foreach ($sigs as $sig) {
                if (empty($pubKeys)) {
                    $stack[] = Encoding::encodeStackNum(0);

                    return true;
                }

                $match = false;
                foreach ($pubKeys as $key => $pubkey) {
                    if ($match = $pubkey->verify($z, $sig)) {
                        unset($pubKeys[$key]);
                        break;
                    }
                }

                if (!$match) {
                    $stack[] = Encoding::encodeStackNum(0);

                    return true;
                }
            }
        } catch (\InvalidArgumentException) {
            return false;
        }

        $stack[] = Encoding::encodeStackNum(1);

        return true;
    }
}
