<?php

declare(strict_types=1);

namespace Bitcoin;

final class S256Field extends FieldElement
{
    // 2**256 - 2**32 - 977
    public const SECP256K1_P = '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f';

    public function __construct(\GMP|int $number)
    {
        parent::__construct($number, gmp_init(self::SECP256K1_P));
    }

    public function __toString(): string
    {
        return str_pad(gmp_strval($this->num, 16), 64, '0', \STR_PAD_LEFT);
    }
}
