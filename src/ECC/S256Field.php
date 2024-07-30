<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

/**
 * Represents a field element whose order is the secp256k1 prime.
 */
final readonly class S256Field
{
    public \GMP $num;

    public function __construct(\GMP|int|string $number)
    {
        if (\is_int($number)) {
            $number = gmp_init($number);
        }

        if (\is_string($number)) {
            $number = str_starts_with($number, '0x') ?
                gmp_init($number) :
                gmp_import($number);
        }

        if ($number < 0 || S256Params::P() <= $number) {
            throw new \InvalidArgumentException("$number not in secp256k1 range");
        }

        $this->num = $number;
    }

    public function add(self $other): self
    {
        return new self(($this->num + $other->num) % S256Params::P());
    }

    public function sub(self $other): self
    {
        return new self(($this->num - $other->num) % S256Params::P());
    }

    public function mul(self $other): self
    {
        return new self(($this->num * $other->num) % S256Params::P());
    }

    public function div(self $divisor): self
    {
        return new self(($this->num * gmp_powm($divisor->num, S256Params::P() - 2, S256Params::P())) % S256Params::P());
    }

    public function exp(\GMP|int $exponent): self
    {
        return new self(gmp_powm($this->num, $exponent % (S256Params::P() - 1), S256Params::P()));
    }

    public function equals(self $other): bool
    {
        return $this->num == $other->num;
    }

    public function sqrt(): self
    {
        return $this->exp(gmp_div_q(S256Params::P() + 1, 4));
    }

    public function __toString(): string
    {
        return \sprintf(
            'S256Field(%s)',
            str_pad(gmp_strval($this->num, 16), 64, '0', \STR_PAD_LEFT)
        );
    }
}
