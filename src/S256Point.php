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

    public static function parse(string $sec): static
    {
        if (33 !== \strlen($sec) && 65 !== \strlen($sec)) {
            throw new \InvalidArgumentException('Invalid SEC data format');
        }

        if ("\x04" === $sec[0]) {
            return new self(
                new S256Field(gmp_import(substr($sec, 1, 32))),
                new S256Field(gmp_import(substr($sec, 33, 32)))
            );
        }

        $x = new S256Field(gmp_import(substr($sec, 1, 32)));

        $alpha = $x->exp(3)->add(new S256Field(S256Params::B->value));
        $beta = $alpha->sqrt();

        return "\x02" === $sec[0] ?
            new self($x, (0 == $beta->num % 2) ? $beta : new S256Field(S256Field::P() - $beta->num)) :
            new self($x, (0 == $beta->num % 2) ? new S256Field(S256Field::P() - $beta->num) : $beta);
    }

    public function address(bool $compressed = true, bool $testnet = false): string
    {
        $address = ($testnet ? "\x6f" : "\x00").Hashing::hash160($this->sec($compressed));

        return Base58::encode($address.substr(Hashing::hash256($address), 0, 4));
    }

    public function sec(bool $compressed = true): string
    {
        if ($compressed) {
            $prefix = 0 == $this->y->num % 2 ? "\x02" : "\x03";

            return $prefix.str_pad(gmp_export($this->x->num), 32, "\x00", \STR_PAD_LEFT);
        }

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
