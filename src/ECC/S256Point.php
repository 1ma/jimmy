<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

use Bitcoin\Encoding;
use Bitcoin\Hashing;

/**
 * Represents a Point on the secp256k1 elliptic curve.
 *
 * These points are Bitcoin's public keys.
 */
final readonly class S256Point extends Point
{
    public function __construct(?S256Field $x, ?S256Field $y)
    {
        parent::__construct($x, $y, S256Params::A(), S256Params::B());
    }

    public static function parse(string $sec): static
    {
        if (!self::validSecString($sec)) {
            throw new \InvalidArgumentException('Invalid SEC data format');
        }

        if ("\x04" === $sec[0]) {
            return new self(
                new S256Field(substr($sec, 1, 32)),
                new S256Field(substr($sec, 33, 32))
            );
        }

        $x = new S256Field(substr($sec, 1, 32));

        $alpha = $x->exp(3)->add(S256Params::B());
        $beta  = $alpha->sqrt();

        return "\x02" === $sec[0] ?
            new self($x, (0 == $beta->num % 2) ? $beta : new S256Field(S256Params::P() - $beta->num)) :
            new self($x, (0 == $beta->num % 2) ? new S256Field(S256Params::P() - $beta->num) : $beta);
    }

    public function address(bool $compressed = true, bool $testnet = true): string
    {
        return Encoding::base58checksum(
            ($testnet ? "\x6f" : "\x00").Hashing::hash160($this->sec($compressed))
        );
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
        $sInv = gmp_powm($sig->s, S256Params::N() - 2, S256Params::N());

        $u = ($z * $sInv)      % S256Params::N();
        $v = ($sig->r * $sInv) % S256Params::N();

        $R = S256Params::G()->scalarMul($u)->add($this->scalarMul($v));

        return $R->x->num == $sig->r;
    }

    public function scalarMul(\GMP|int $coefficient): static
    {
        // Optimization: reduce the coefficient before computing the multiplication
        return parent::scalarMul($coefficient % S256Params::N());
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

    private static function validSecString(string $data): bool
    {
        return (33 === \strlen($data) && ("\x02" === $data[0] || "\x03" === $data[0]))
            || (65 === \strlen($data) && "\x04" === $data[0]);
    }
}
