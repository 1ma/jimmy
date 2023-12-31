<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

readonly class FieldElement
{
    public \GMP $num;
    public \GMP $order;

    public function __construct(\GMP|int $number, \GMP|int $order)
    {
        if ($number < 0 || $order <= $number) {
            throw new \InvalidArgumentException("$number not in field range [0, $order)");
        }

        if (0 === gmp_prob_prime($order)) {
            throw new \InvalidArgumentException('Order must be a prime number');
        }

        $this->num   = $number instanceof \GMP ? $number : gmp_init($number);
        $this->order = $order instanceof \GMP ? $order : gmp_init($order);
    }

    public function add(self $other): static
    {
        self::assertSameOrder($this, $other);

        return new static(($this->num + $other->num) % $this->order, $this->order);
    }

    public function sub(self $other): static
    {
        self::assertSameOrder($this, $other);

        return new static(($this->num - $other->num) % $this->order, $this->order);
    }

    public function mul(self $other): static
    {
        self::assertSameOrder($this, $other);

        return new static(($this->num * $other->num) % $this->order, $this->order);
    }

    public function div(self $divisor): static
    {
        self::assertSameOrder($this, $divisor);

        return new static(($this->num * gmp_powm($divisor->num, $this->order - 2, $this->order)) % $this->order, $this->order);
    }

    public function exp(\GMP|int $exponent): static
    {
        return new static(gmp_powm($this->num, $exponent % ($this->order - 1), $this->order), $this->order);
    }

    public function equals(self $other): bool
    {
        return $this->order == $other->order && $this->num == $other->num;
    }

    public function __toString(): string
    {
        return "FE_{$this->order}({$this->num})";
    }

    private static function assertSameOrder(self $left, self $right): void
    {
        if ($left->order != $right->order) {
            throw new \InvalidArgumentException('Cannot operate on two numbers in different fields');
        }
    }
}
