<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

/**
 * Secp256k1 elliptic curve parameters.
 */
enum S256Params: string
{
    /**
     * The order of the finite field. It is a prime number.
     *
     * In this context "order" means the size of the finite field.
     *
     * P = 2^256 - 2^32 - 977
     */
    case P = '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';

    /**
     * Coefficients of the secp256k1 elliptic curve.
     *
     * y^2 = x^3 + 0x + 7
     */
    case A = '0';
    case B = '7';

    /**
     * Generator point coordinates.
     */
    case Gx = '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
    case Gy = '0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

    /**
     * The order of G over the secp256k1 curve.
     *
     * In this context "order" means the number of times that G has to be added to
     * itself (i.e. scalar multiplication n*G) to get to the point at infinity of
     * the secp256k1 curve.
     */
    case N = '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
}
