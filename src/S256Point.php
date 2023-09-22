<?php

declare(strict_types=1);

namespace Bitcoin;

/**
 * Represents a Point on the secp256k1 elliptic curve.
 */
final class S256Point extends Point
{
    public const SECP256K1_A = 0;
    public const SECP256K1_B = 7;
    public const SECP256K1_GX = '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    public const SECP256K1_GY = '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
    public const SECP256K1_N = '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';

    public function __construct(?FieldElement $x, ?FieldElement $y)
    {
        parent::__construct($x, $y, new S256Field(self::SECP256K1_A), new S256Field(self::SECP256K1_B));
    }

    /**
     * Return a copy of secp256k1's generator point G.
     */
    public static function G(): self
    {
        return new self(new S256Field(gmp_init(self::SECP256K1_GX)), new S256Field(gmp_init(self::SECP256K1_GY)));
    }

    public function scalarMul(\GMP|int $coefficient): Point
    {
        // Optimization: reduce the coefficient before computing the multiplication
        return parent::scalarMul($coefficient % gmp_init(self::SECP256K1_N));
    }

    public function __toString(): string
    {
        return sprintf(
            'S256Point(%s,%s)',
            str_pad(gmp_strval($this->x->num, 16), 64, '0', \STR_PAD_LEFT),
            str_pad(gmp_strval($this->y->num, 16), 64, '0', \STR_PAD_LEFT)
        );
    }
}
