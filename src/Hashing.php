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

    public static function merkleRoot(array $leaves): string
    {
        if (empty($leaves)) {
            throw new \InvalidArgumentException('At least one element needed');
        }

        while (\count($leaves) > 1) {
            $leaves = self::merkleParentLevel($leaves);
        }

        return $leaves[0];
    }

    public static function merkleParentLevel(array $children): array
    {
        if (\count($children) < 2) {
            throw new \InvalidArgumentException('At least two elements needed');
        }

        if (0 !== \count($children) % 2) {
            $children[] = $children[array_key_last($children)];
        }

        $parents = [];
        for ($i = 0; $i < \count($children); $i += 2) {
            $parents[] = self::merkleParent($children[$i], $children[$i + 1]);
        }

        return $parents;
    }

    public static function merkleParent(string $leftChild, string $rightChild): string
    {
        return self::hash256($leftChild.$rightChild);
    }
}
