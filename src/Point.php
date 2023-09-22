<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class Point
{
    public ?\GMP $x;
    public ?\GMP $y;
    public \GMP $a;
    public \GMP $b;

    public function __construct(\GMP|int|float|null $x, \GMP|int|float|null $y, \GMP|int|float $a, \GMP|int|float $b)
    {
        if (null !== $x && null !== $y && gmp_pow($y, 2) != gmp_add(gmp_pow($x, 3), gmp_add(gmp_mul($a, $x), $b))) {
            throw new \InvalidArgumentException("Point ($x,$y) is not on the a=$a b=$b curve");
        }

        if ((null === $x && null !== $y) || (null === $y && null !== $x)) {
            throw new \InvalidArgumentException('If one coordinate is null the other must be null too');
        }

        $this->x = null === $x || $x instanceof \GMP ? $x : gmp_init($x);
        $this->y = null === $y || $y instanceof \GMP ? $y : gmp_init($y);
        $this->a = $a instanceof \GMP ? $a : gmp_init($a);
        $this->b = $b instanceof \GMP ? $b : gmp_init($b);
    }

    public static function infinity(\GMP|int|float $a, \GMP|int|float $b): self
    {
        return new self(null, null, $a, $b);
    }

    public function add(self $other): self
    {
        self::assertSameCurve($this, $other);

        if (null === $this->x) {
            return $other;
        }

        if (null === $other->x) {
            return $this;
        }

        if ($this->x == $other->x && $this->y != $other->y) {
            return self::infinity($this->a, $this->b);
        }

        if ($this->equals($other) && 0 == $this->y) {
            return self::infinity($this->a, $this->b);
        }

        if ($this->equals($other)) {
            $s = (3 * $this->x ** 2 + $this->a) / (2 * $this->y);
            $x = $s ** 2 - 2 * $this->x;
            $y = $s * ($this->x - $x) - $other->y;

            return new self($x, $y, $this->a, $this->b);
        }

        $s = ($other->y - $this->y) / ($other->x - $this->x);
        $x = $s ** 2 - $this->x - $other->x;
        $y = $s * ($this->x - $x) - $this->y;

        return new self($x, $y, $this->a, $this->b);
    }

    public function equals(self $other): bool
    {
        return $this->x == $other->x
            && $this->y == $other->y
            && $this->a == $other->a
            && $this->b == $other->b;
    }

    public function __toString(): string
    {
        return "P({$this->x},{$this->y})_{$this->a}_{$this->b}";
    }

    private static function assertSameCurve(self $left, self $right): void
    {
        if ($left->a != $right->a || $left->b != $right->b) {
            throw new \InvalidArgumentException('Cannot operate on two points on different elliptic curves');
        }
    }
}
