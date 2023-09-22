<?php

declare(strict_types=1);

namespace Bitcoin;

/**
 * Represents a Point on the secp256k1 elliptic curve.
 */
final class S256Point extends Point
{
    public function __construct(?FieldElement $x, ?FieldElement $y)
    {
        parent::__construct($x, $y, new S256Field(S256Params::A->value), new S256Field(S256Params::B->value));
    }

    /**
     * Return a copy of secp256k1's generator point G.
     */
    public static function G(): self
    {
        return new self(new S256Field(S256Params::Gx->value), new S256Field(S256Params::Gy->value));
    }

    public function scalarMul(\GMP|int $coefficient): Point
    {
        // Optimization: reduce the coefficient before computing the multiplication
        return parent::scalarMul($coefficient % gmp_init(S256Params::N->value));
    }

    public function __toString(): string
    {
        if (null === $this->x) {
            return 'S256Point(,)';
        }

        return sprintf('S256Point(%s,%s)', gmp_strval($this->x->num, 16), gmp_strval($this->y->num, 16));
    }
}
