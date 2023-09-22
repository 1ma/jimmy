<?php

declare(strict_types=1);

namespace Bitcoin;

class Point
{
    public readonly ?FieldElement $x;
    public readonly ?FieldElement $y;
    public readonly FieldElement $a;
    public readonly FieldElement $b;

    public function __construct(?FieldElement $x, ?FieldElement $y, FieldElement $a, FieldElement $b)
    {
        if ((null === $x && null !== $y) || (null === $y && null !== $x)) {
            throw new \InvalidArgumentException('If one coordinate is null the other must be null too');
        }

        if ($a->order != $b->order || (null !== $x && $a->order != $x->order) || (null !== $y && $a->order != $y->order)) {
            throw new \InvalidArgumentException('All FieldElements must be of the same order');
        }

        if (null !== $x && null !== $y && !$y->exp(2)->equals($x->exp(3)->add($a->mul($x))->add($b))) {
            throw new \InvalidArgumentException("Point ({$x->num},{$y->num}) is not on the a={$a->num} b={$b->num} curve");
        }

        $this->x = $x;
        $this->y = $y;
        $this->a = $a;
        $this->b = $b;
    }

    public static function infinity(FieldElement $a, FieldElement $b): self
    {
        return new self(null, null, $a, $b);
    }

    public function add(self $other): self
    {
        self::assertSameCurveAndOrder($this, $other);

        if (null === $this->x) {
            return $other;
        }

        if (null === $other->x) {
            return $this;
        }

        if ($this->x->num == $other->x->num && $this->y->num != $other->y->num) {
            return self::infinity($this->a, $this->b);
        }

        if ($this->equals($other) && 0 == $this->y->num) {
            return self::infinity($this->a, $this->b);
        }

        if ($this->equals($other)) {
            $s = $this->x->exp(2)->mul(new FieldElement(3, $this->x->order))->add($this->a)->div($this->y->mul(new FieldElement(2, $this->y->order)));
            $x = $s->exp(2)->sub($this->x->mul(new FieldElement(2, $this->x->order)));
            $y = $s->mul($this->x->sub($x))->sub($other->y);

            return new self($x, $y, $this->a, $this->b);
        }

        $s = $other->y->sub($this->y)->div($other->x->sub($this->x));
        $x = $s->exp(2)->sub($this->x)->sub($other->x);
        $y = $s->mul($this->x->sub($x))->sub($this->y);

        return new self($x, $y, $this->a, $this->b);
    }

    public function scalarMul(\GMP|int $coefficient): self
    {
        $c = $coefficient instanceof \GMP ? $coefficient : gmp_init($coefficient);
        $current = clone $this;
        $result = self::infinity($this->a, $this->b);

        while ($c > 0) {
            if (gmp_testbit($c, 0)) {
                $result = $result->add($current);
            }

            $c >>= 1;
            $current = $current->add($current);
        }

        return $result;
    }

    /**
     * Finds the scalar that produces the point at infinity.
     */
    public function groupOrder(): \GMP
    {
        $order = gmp_init(1);
        $m = clone $this;

        while (null !== $m->x) {
            $m = $m->add($this);
            ++$order;
        }

        return $order;
    }

    public function equals(self $other): bool
    {
        return $this->x->equals($other->x)
            && $this->y->equals($other->y)
            && $this->a->equals($other->a)
            && $this->b->equals($other->b);
    }

    public function __toString(): string
    {
        return "P({$this->x->num},{$this->y->num})_{$this->a->num}_{$this->b->num}_FE({$this->a->order})";
    }

    private static function assertSameCurveAndOrder(self $p1, self $p2): void
    {
        if ($p1->a->order != $p2->a->order) {
            throw new \InvalidArgumentException('Cannot operate on two points on different finite fields');
        }

        if ($p1->a->num != $p2->a->num || $p1->b->num != $p2->b->num) {
            throw new \InvalidArgumentException('Cannot operate on two points on different elliptic curves');
        }
    }
}
