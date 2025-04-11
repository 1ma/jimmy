<?php

declare(strict_types=1);

namespace Bitcoin\BIP32;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\S256Params;
use Bitcoin\Hashing;

final readonly class DerivationPath
{
    private const string PATH_REGEXP = "#^m(/\d+'?)*$#";

    private const int HARDENED_OFFSET = 0x80000000;

    public array $levels;

    public function __construct(array $levels)
    {
        $this->levels = $levels;
    }

    public static function parse(string $path): self
    {
        if (!preg_match(self::PATH_REGEXP, $path)) {
            throw new \InvalidArgumentException('Invalid derivation path: '.$path);
        }

        if ('m' === $path) {
            return new self([]);
        }

        $levels = [];
        foreach (explode('/', substr($path, 2)) as $value) {
            $offset = 0;
            if ("'" === $value[-1]) {
                $value  = substr($value, 0, -1);
                $offset = self::HARDENED_OFFSET;
            }

            $levels[] = (int) $value + $offset;
        }

        return new self($levels);
    }

    /**
     * @return PrivateKey[]
     */
    public function deriveRange(PrivateKey $masterPrivateKey, string $masterChainCode, int $offset, int $limit): array
    {
        if (32 !== \strlen($masterChainCode)) {
            throw new \InvalidArgumentException('Invalid chaincode: '.bin2hex($masterChainCode));
        }

        if ($offset < 0) {
            throw new \InvalidArgumentException('Invalid offset: '.$offset);
        }

        if ($limit < 0) {
            throw new \InvalidArgumentException('Invalid limit: '.$limit);
        }

        $privateKey = str_pad(gmp_export($masterPrivateKey->secret), 32, "\x00", \STR_PAD_LEFT);
        $chainCode  = $masterChainCode;

        foreach ($this->levels as $level) {
            [$privateKey, $chainCode] = self::CKDPriv($privateKey, $chainCode, $level);
        }

        $keys = [];
        for ($i = $offset; $i < $offset + $limit; ++$i) {
            $keys[] = new PrivateKey(gmp_import(self::CKDPriv($privateKey, $chainCode, $i)[0]));
        }

        return $keys;
    }

    private function CKDPriv(string $kParent, string $cParent, int $index): array
    {
        $hmacData = self::hardened($index) ?
            "\x00".$kParent.self::ser32($index) :
            new PrivateKey(gmp_import($kParent))->pubKey->sec().self::ser32($index);

        $I = Hashing::sha512hmac($hmacData, $cParent);

        $kChild = (gmp_import(substr($I, 0, 32)) + gmp_import($kParent)) % S256Params::N();
        $cChild = substr($I, 32, 64);

        return [str_pad(gmp_export($kChild), 32, "\x00", \STR_PAD_LEFT), $cChild];
    }

    private static function hardened(int $index): bool
    {
        return $index >= self::HARDENED_OFFSET;
    }

    private static function ser32(int $index): string
    {
        if ($index >= 4294967296) { // 2^32
            throw new \InvalidArgumentException('Index too large for ser32 serialization: '.$index);
        }

        return pack('N', $index);
    }
}
