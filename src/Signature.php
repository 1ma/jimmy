<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class Signature
{
    public \GMP $r;
    public \GMP $s;

    public function __construct(\GMP $r, \GMP $s)
    {
        $this->r = $r;
        $this->s = $s;
    }

    public function __toString(): string
    {
        return sprintf('S256Point(%s,%s)', gmp_strval($this->r, 16), gmp_strval($this->s, 16));
    }
}
