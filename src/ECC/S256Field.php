<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

/**
 * Represents a FieldElement using the secp256k1 prime as the order.
 */
final readonly class S256Field extends FieldElement
{
    public function __construct(\GMP|int|string $number)
    {
        if (\is_string($number)) {
            $number = str_starts_with($number, '0x') ?
                gmp_init($number) :
                gmp_import($number);
        }

        parent::__construct($number, S256Params::P());
    }

    public function sqrt(): static
    {
        return $this->exp(gmp_div_q(S256Params::P() + 1, 4));
    }

    public function __toString(): string
    {
        return sprintf(
            'S256Field(%s)',
            str_pad(gmp_strval($this->num, 16), 64, '0', \STR_PAD_LEFT)
        );
    }
}
