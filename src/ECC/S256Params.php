<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

/**
 * This class documents the secp256k1 elliptic curve parameters and provides
 * singleton instances of these values to be used elsewhere in the codebase.
 */
final class S256Params
{
    /**
     * The order of the finite field. It is a prime number.
     *
     * In this context "order" means the size of a finite field.
     *
     * P = 2^256 - 2^32 - 977
     */
    private const string P = '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';

    /**
     * Coefficients of the secp256k1 elliptic curve.
     *
     * y^2 = x^3 + 0x + 7
     */
    private const int A = 0;
    private const int B = 7;

    /**
     * Generator point coordinates.
     */
    private const string Gx = '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    private const string Gy = '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

    /**
     * The order of G over the secp256k1 curve.
     *
     * In this context "order" means the number of times that G has to be added to
     * itself (i.e. scalar multiplication n*G) to get to the point at infinity of
     * the secp256k1 curve.
     */
    private const string N = '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';

    private static \GMP $N;
    private static \GMP $Ndiv2;
    private static \GMP $P;
    private static S256Field $A;
    private static S256Field $B;
    private static PublicKey $G;

    public static function N(): \GMP
    {
        if (!isset(self::$N)) {
            self::$N = gmp_init(self::N);
        }

        return self::$N;
    }

    public static function Ndiv2(): \GMP
    {
        if (!isset(self::$Ndiv2)) {
            self::$Ndiv2 = gmp_div(self::N(), 2);
        }

        return self::$Ndiv2;
    }

    public static function P(): \GMP
    {
        if (!isset(self::$P)) {
            self::$P = gmp_init(self::P);
        }

        return self::$P;
    }

    public static function A(): S256Field
    {
        if (!isset(self::$A)) {
            self::$A = new S256Field(self::A);
        }

        return self::$A;
    }

    public static function B(): S256Field
    {
        if (!isset(self::$B)) {
            self::$B = new S256Field(self::B);
        }

        return self::$B;
    }

    public static function G(): PublicKey
    {
        if (!isset(self::$G)) {
            self::$G = new PublicKey(new S256Field(self::Gx), new S256Field(self::Gy));
        }

        return self::$G;
    }
}
