<?php

declare(strict_types=1);

namespace Bitcoin\HDW;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\PublicKey;
use Bitcoin\ECC\S256Params;
use Bitcoin\Hashing;

/**
 * @see https://bips.xyz/32#child-key-derivation-ckd-functions
 */
final readonly class CKDFunctions
{
    public const int HARDENED_OFFSET = 0x80000000;

    /**
     * @see https://bips.xyz/32#private-parent-key--private-child-key
     *
     * @return array{PrivateKey, string}
     */
    public static function CKDPriv(PrivateKey $kParent, string $cParent, int $index): array
    {
        $hmacDataPrefix = self::hardened($index) ? "\x00".$kParent->ser256() : $kParent->pubKey->sec();

        $I = Hashing::sha512hmac($hmacDataPrefix.self::ser32($index), $cParent);

        $kChild = new PrivateKey(gmp_div_r(gmp_import(substr($I, 0, 32)) + $kParent->secret, S256Params::N()));
        $cChild = substr($I, 32, 32);

        return [$kChild, $cChild];
    }

    /**
     * @see https://bips.xyz/32#public-parent-key--public-child-key
     *
     * @return array{PublicKey, string}
     */
    public static function CKDPub(PublicKey $KParent, string $cParent, int $index): array
    {
        if (self::hardened($index)) {
            throw new \InvalidArgumentException('Derivation of hardened indexes is not possible in CKDPub');
        }

        $I = Hashing::sha512hmac($KParent->sec().self::ser32($index), $cParent);

        $kChild = new PrivateKey(gmp_import(substr($I, 0, 32)))->pubKey->add($KParent);
        $cChild = substr($I, 32, 32);

        return [$kChild, $cChild];
    }

    private static function hardened(int $index): bool
    {
        return $index >= self::HARDENED_OFFSET;
    }

    private static function ser32(int $index): string
    {
        if ($index >= 4294967296) { // 2^32
            throw new \InvalidArgumentException('Index too large for ser32 serialization: '.$index);
        }

        return pack('N', $index);
    }
}
