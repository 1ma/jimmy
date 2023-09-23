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
    private static S256Field $A;
    private static S256Field $B;
    private static S256Point $G;

    public function __construct(?FieldElement $x, ?FieldElement $y)
    {
        if (!isset(self::$A)) {
            self::$A = new S256Field(S256Params::A->value);
            self::$B = new S256Field(S256Params::B->value);
        }

        parent::__construct($x, $y, self::$A, self::$B);
    }

    public function sec(): string
    {
        return "\x04".str_pad(gmp_export($this->x->num), 32, "\x00", \STR_PAD_LEFT).str_pad(gmp_export($this->y->num), 32, "\x00", \STR_PAD_LEFT);
    }

    public function verify(\GMP $z, Signature $sig): bool
    {
        $N = S256Field::N();
        $sInv = gmp_powm($sig->s, $N - 2, $N);

        $u = ($z * $sInv) % $N;
        $v = ($sig->r * $sInv) % $N;

        $R = self::G()->scalarMul($u)->add($this->scalarMul($v));

        return $R->x->num == $sig->r;
    }

    public function scalarMul(\GMP|int $coefficient): static
    {
        // Optimization: reduce the coefficient before computing the multiplication
        return parent::scalarMul($coefficient % S256Field::N());
    }

    /**
     * Return a copy of secp256k1's generator point G.
     */
    public static function G(): static
    {
        if (!isset(self::$G)) {
            self::$G = new self(new S256Field(S256Params::Gx->value), new S256Field(S256Params::Gy->value));
        }

        return self::$G;
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
