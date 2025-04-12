<?php

declare(strict_types=1);

namespace Bitcoin\BIP32;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\S256Point;
use Bitcoin\Encoding;
use Bitcoin\Hashing;

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

    public function fingerprint(): string
    {
        $pubkey = $this->key instanceof PrivateKey ? $this->key->pubKey : $this->key;

        return bin2hex(substr(Hashing::hash160($pubkey->sec()), 0, 4));
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

    public function __toString(): string
    {
        $version     = $this->version->value;
        $depth       = pack('C', $this->depth);
        $fingerprint = hex2bin($this->parentFingerprint);
        $childNumber = pack('N', $this->childNumber);
        $chainCode   = $this->chainCode;
        $material    = $this->key instanceof PrivateKey ? "\x00".$this->key : $this->key->sec();

        return Encoding::base58checksum($version.$depth.$fingerprint.$childNumber.$chainCode.$material);
    }
}
