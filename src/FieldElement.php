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

        $this->num = gmp_init($number);
        $this->order = gmp_init($order);
    }

    public function __toString(): string
    {
        return sprintf('FE_%s(%s)', $this->order, $this->num);
    }
}
