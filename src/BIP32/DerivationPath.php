<?php

declare(strict_types=1);

namespace Bitcoin\BIP32;

use Bitcoin\ECC\PrivateKey;

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

    public function depth(): int
    {
        return \count($this->levels);
    }

    public function childNumber(): int
    {
        return empty($this->levels) ? 0 : $this->levels[array_key_last($this->levels)];
    }

    /**
     * @return array{PrivateKey, string}
     */
    public function derive(PrivateKey $masterPrivateKey, string $masterChainCode): array
    {
        if (32 !== \strlen($masterChainCode)) {
            throw new \InvalidArgumentException('Invalid chaincode: '.bin2hex($masterChainCode));
        }

        $privateKey = $masterPrivateKey;
        $chainCode  = $masterChainCode;

        foreach ($this->levels as $level) {
            [$privateKey, $chainCode] = CKDFunctions::CKDPriv($privateKey, $chainCode, $level);
        }

        return [$privateKey, $chainCode];
    }

    /**
     * @return PrivateKey[]
     */
    public static function range(PrivateKey $privateKey, string $chainCode, int $offset, int $limit): array
    {
        if (32 !== \strlen($chainCode)) {
            throw new \InvalidArgumentException('Invalid chaincode: '.bin2hex($chainCode));
        }

        if ($offset < 0 || $limit < 0) {
            throw new \InvalidArgumentException('Invalid limit or offset: '.$offset.' '.$limit);
        }

        $keys = [];
        for ($i = $offset; $i < $offset + $limit; ++$i) {
            $keys[] = CKDFunctions::CKDPriv($privateKey, $chainCode, $i)[0];
        }

        return $keys;
    }
}
