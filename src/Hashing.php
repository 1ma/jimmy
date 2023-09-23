<?php

declare(strict_types=1);

namespace Bitcoin;

final class Hashing
{
    public static function hash160(string $data): string
    {
        return hash('ripemd160', hash('sha256', $data, true), true);
    }

    public static function hash256(string $data): string
    {
        return hash('sha256', hash('sha256', $data, true), true);
    }
}
