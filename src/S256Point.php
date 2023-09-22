<?php

declare(strict_types=1);

namespace Bitcoin;

final class S256Point extends Point
{
    public const SECP256K1_A = 0;
    public const SECP256K1_B = 7;

    public function __construct(?FieldElement $x, ?FieldElement $y)
    {
        parent::__construct($x, $y, new S256Field(self::SECP256K1_A), new S256Field(self::SECP256K1_B));
    }
}
