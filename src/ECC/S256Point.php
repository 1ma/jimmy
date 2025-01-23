<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

use Bitcoin\Encoding;
use Bitcoin\Hashing;
use Bitcoin\Network;

/**
 * Represents a Point on the secp256k1 elliptic curve.
 *
 * These points are Bitcoin's public keys.
 */
final readonly class S256Point
{
    public ?S256Field $x;
    public ?S256Field $y;

    public function __construct(?S256Field $x, ?S256Field $y)
    {
        if ((null === $x && null !== $y) || (null === $y && null !== $x)) {
            throw new \InvalidArgumentException('If one coordinate is null the other must be null too');
        }

        if (null !== $x && null !== $y && !$y->exp(2)->equals($x->exp(3)->add(S256Params::A()->mul($x))->add(S256Params::B()))) {
            throw new \InvalidArgumentException("Point ({$x->num},{$y->num}) is not on the a=0 b=7 curve");
        }

        $this->x = $x;
        $this->y = $y;
    }

    public static function infinity(): self
    {
        return new self(null, null);
    }

    public function add(self $other): self
    {
        if (null === $this->x) {
            return $other;
        }

        if (null === $other->x) {
            return $this;
        }

        if ($this->x->num == $other->x->num && $this->y->num != $other->y->num) {
            return self::infinity();
        }

        if ($this->equals($other) && 0 == $this->y->num) {
            return self::infinity();
        }

        if ($this->equals($other)) {
            $s = $this->x->exp(2)->mul(new S256Field(3))->add(S256Params::A())->div($this->y->mul(new S256Field(2)));
            $x = $s->exp(2)->sub($this->x->mul(new S256Field(2)));
            $y = $s->mul($this->x->sub($x))->sub($other->y);

            return new static($x, $y);
        }

        $s = $other->y->sub($this->y)->div($other->x->sub($this->x));
        $x = $s->exp(2)->sub($this->x)->sub($other->x);
        $y = $s->mul($this->x->sub($x))->sub($this->y);

        return new static($x, $y);
    }

    public function scalarMul(\GMP|int $coefficient): self
    {
        // Optimization: reduce the coefficient modulo N before computing the multiplication
        $c       = $coefficient % S256Params::N();
        $current = clone $this;
        $result  = self::infinity();

        while ($c > 0) {
            if (gmp_testbit($c, 0)) {
                $result = $result->add($current);
            }

            $c >>= 1;
            $current = $current->add($current);
        }

        return $result;
    }

    public function equals(self $other): bool
    {
        return $this->x->equals($other->x)
            && $this->y->equals($other->y);
    }

    public static function parse(string $sec): self
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

    public function address(bool $compressed = true, Network $mode = Network::TESTNET): string
    {
        return Encoding::hash160ToPayToPublicKeyHashAddress(Hashing::hash160($this->sec($compressed)), $mode);
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

        return null !== $R->x && $R->x->num == $sig->r;
    }

    public function __toString(): string
    {
        if (null === $this->x) {
            return 'S256Point(,)';
        }

        return \sprintf(
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
