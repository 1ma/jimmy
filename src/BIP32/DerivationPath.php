<?php

declare(strict_types=1);

namespace Bitcoin\BIP32;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\S256Point;

final readonly class DerivationPath
{
    private const string PATH_REGEXP = "#^m(/\d+'?)+$#";

    public array $levels;

    public function __construct(array $levels)
    {
        $this->levels = $levels;
    }

    public static function parse(string $path): self
    {
        if ('m' === $path) {
            return new self([]);
        }

        if (!preg_match(self::PATH_REGEXP, $path)) {
            throw new \InvalidArgumentException('Invalid derivation path: '.$path);
        }

        $levels = [];
        foreach (explode('/', substr($path, 2)) as $value) {
            $offset = 0;
            if ("'" === $value[-1]) {
                $value  = substr($value, 0, -1);
                $offset = CKDFunctions::HARDENED_OFFSET;
            }

            $levels[] = (int) $value + $offset;
        }

        return new self($levels);
    }

    public function derive(ExtendedKey $masterKey): ExtendedKey
    {
        $key         = $masterKey->key;
        $chainCode   = $masterKey->chainCode;
        $extendedKey = $masterKey;

        foreach ($this->levels as $level) {
            [$key, $chainCode] = $key instanceof PrivateKey ?
                CKDFunctions::CKDPriv($key, $chainCode, $level) :
                CKDFunctions::CKDPub($key, $chainCode, $level);

            $extendedKey = new ExtendedKey(
                $extendedKey->version,
                $extendedKey->depth + 1,
                $extendedKey->fingerprint(),
                $level,
                $chainCode,
                $key
            );
        }

        return $extendedKey;
    }

    /**
     * @return array<PrivateKey|S256Point>
     */
    public static function range(ExtendedKey $extendedKey, int $offset, int $limit): array
    {
        if ($offset < 0 || $limit < 0) {
            throw new \InvalidArgumentException('Invalid limit or offset: '.$offset.' '.$limit);
        }

        $keys = [];
        for ($i = $offset; $i < $offset + $limit; ++$i) {
            $keys[] = $extendedKey->key instanceof PrivateKey ?
                CKDFunctions::CKDPriv($extendedKey->key, $extendedKey->chainCode, $i)[0] :
                CKDFunctions::CKDPub($extendedKey->key, $extendedKey->chainCode, $i)[0];
        }

        return $keys;
    }
}
