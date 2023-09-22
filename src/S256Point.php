<?php

declare(strict_types=1);

namespace Bitcoin;

/**
 * Represents a Point on the secp256k1 elliptic curve.
 *
 * These points are Bitcoin's public keys.
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
    public static function G(): static
    {
        return new self(new S256Field(S256Params::Gx->value), new S256Field(S256Params::Gy->value));
    }

    public function verify(\GMP $z, Signature $sig): bool
    {
        $N = gmp_init(S256Params::N->value);
        $sInv = gmp_powm($sig->s, $N - 2, $N);

        $u = ($z * $sInv) % $N;
        $v = ($sig->r * $sInv) % $N;

        $R = self::G()->scalarMul($u)->add($this->scalarMul($v));

        return $R->x->num == $sig->r;
    }

    public function scalarMul(\GMP|int $coefficient): static
    {
        // Optimization: reduce the coefficient before computing the multiplication
        return parent::scalarMul($coefficient % gmp_init(S256Params::N->value));
    }

    public function __toString(): string
    {
        if (null === $this->x) {
            return 'S256Point(,)';
        }

        return sprintf(
            'S256Point(%s,%s)',
            str_pad(gmp_strval($this->x->num, 16), 64, '0', \STR_PAD_LEFT),
            str_pad(gmp_strval($this->y->num, 16), 64, '0', \STR_PAD_LEFT)
        );
    }
}
