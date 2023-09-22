<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class FieldElement
{
    public \GMP $num;
    public \GMP $order;

    public function __construct(\GMP|int $number, \GMP|int $order)
    {
        if (gmp_cmp($number, $order) >= 0 || gmp_cmp($number, 0) < 0) {
            throw new \InvalidArgumentException(sprintf('Number %s not in field range 0 to %s', $number, gmp_sub($order, 1)));
        }

        if (0 === gmp_prob_prime($order)) {
            throw new \InvalidArgumentException('Order must be a prime number');
        }

        $this->num = $number instanceof \GMP ? $number : gmp_init($number);
        $this->order = $order instanceof \GMP ? $order : gmp_init($order);
    }

    public function add(self $other): self
    {
        if ($this->order != $other->order) {
            throw new \InvalidArgumentException('Cannot add two numbers in different fields');
        }

        return new self(gmp_mod(gmp_add($this->num, $other->num), $this->order), $this->order);
    }

    public function sub(self $other): self
    {
        if ($this->order != $other->order) {
            throw new \InvalidArgumentException('Cannot add two numbers in different fields');
        }

        return new self(gmp_mod(gmp_sub($this->num, $other->num), $this->order), $this->order);
    }

    public function equals(self $other): bool
    {
        return $this->order == $other->order && $this->num == $other->num;
    }

    public function __toString(): string
    {
        return sprintf('FE_%s(%s)', $this->order, $this->num);
    }
}
