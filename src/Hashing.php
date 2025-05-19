<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class Hashing
{
    public static function hash160(string $data): string
    {
        return hash('ripemd160', hash('sha256', $data, true), true);
    }

    public static function hash256(string $data): string
    {
        return hash('sha256', hash('sha256', $data, true), true);
    }

    public static function sha256hmac(string $data, string $key): string
    {
        return hash_hmac('sha256', $data, $key, true);
    }

    public static function sha512hmac(string $data, string $key): string
    {
        return hash_hmac('sha512', $data, $key, true);
    }

    public static function taggedHash(string $tag, string $data): string
    {
        $tag = hash('sha256', $tag, true);

        return hash('sha256', $tag.$tag.$data, true);
    }

    public static function merkleParent(string $hash0, string $hash1): string
    {
        return self::hash256($hash0.$hash1);
    }
}
