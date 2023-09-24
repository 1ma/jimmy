<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

/**
 * Represents a FieldElement using the secp256k1 prime as the order.
 */
final class S256Field extends FieldElement
{
    private static \GMP $N;
    private static \GMP $P;

    public function __construct(\GMP|int|string $number)
    {
        if (\is_string($number)) {
            $number = gmp_init($number);
        }

        parent::__construct($number, self::P());
    }

    public static function N(): \GMP
    {
        if (!isset(self::$N)) {
            self::$N = gmp_init(S256Params::N->value);
        }

        return self::$N;
    }

    public static function P(): \GMP
    {
        if (!isset(self::$P)) {
            self::$P = gmp_init(S256Params::P->value);
        }

        return self::$P;
    }

    public function sqrt(): static
    {
        return $this->exp(gmp_div_q(self::P() + 1, 4));
    }

    public function __toString(): string
    {
        return sprintf(
            'S256Field(%s)',
            str_pad(gmp_strval($this->num, 16), 64, '0', \STR_PAD_LEFT)
        );
    }
}
