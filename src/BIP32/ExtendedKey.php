<?php

declare(strict_types=1);

namespace Bitcoin\BIP32;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\S256Point;
use Bitcoin\Encoding;

final readonly class ExtendedKey
{
    public Version $version;
    public int $depth;
    public string $parentFingerprint;
    public int $childNumber;
    public string $chainCode;
    public PrivateKey|S256Point $key;

    public function __construct(Version $version, int $depth, string $parentFingerprint, int $childNumber, string $chainCode, PrivateKey|S256Point $key)
    {
        $this->version           = $version;
        $this->depth             = $depth;
        $this->parentFingerprint = $parentFingerprint;
        $this->childNumber       = $childNumber;
        $this->chainCode         = $chainCode;
        $this->key               = $key;
    }

    /**
     * @throws \InvalidArgumentException
     */
    public static function parse(string $base58): self
    {
        $data = Encoding::base58decode($base58, true);

        if (null === $version = Version::tryFrom(substr($data, 0, 4))) {
            throw new \InvalidArgumentException('Unknown extended key version:'.bin2hex(substr($data, 0, 4)));
        }

        $depth       = unpack('C', substr($data, 4, 1))[1];
        $fingerprint = bin2hex(substr($data, 5, 4));
        $childNumber = unpack('N', substr($data, 9, 4))[1];
        $chainCode   = substr($data, 13, 32);
        $material    = substr($data, 45, 33);
        $key         = "\x00" === $material[0] ? new PrivateKey(gmp_import(substr($material, 1))) : S256Point::parse($material);

        return new self($version, $depth, $fingerprint, $childNumber, $chainCode, $key);
    }
}
