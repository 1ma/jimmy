<?php

declare(strict_types=1);

namespace Bitcoin;

/**
 * Represents a FieldElement using the secp256k1 prime as the order.
 */
final class S256Field extends FieldElement
{
    public function __construct(\GMP|int|string $number)
    {
        if (\is_string($number)) {
            $number = gmp_init($number);
        }

        parent::__construct($number, gmp_init(S256Params::P->value));
    }

    public function __toString(): string
    {
        return sprintf(
            'S256Field(%s)',
            str_pad(gmp_strval($this->num, 16), 64, '0', \STR_PAD_LEFT)
        );
    }
}
