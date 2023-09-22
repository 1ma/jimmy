<?php

declare(strict_types=1);

namespace Bitcoin;

/**
 * Represents a FieldElement using the secp256k1 prime as the order.
 */
final class S256Field extends FieldElement
{
    /**
     * P = 2**256 - 2**32 - 977.
     */
    public const SECP256K1_P = '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';

    public function __construct(\GMP|int $number)
    {
        parent::__construct($number, gmp_init(self::SECP256K1_P));
    }

    public function __toString(): string
    {
        return sprintf(
            'S256Field(%s)',
            str_pad(gmp_strval($this->num, 16), 64, '0', \STR_PAD_LEFT)
        );
    }
}
