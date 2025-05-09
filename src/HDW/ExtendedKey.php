<?php

declare(strict_types=1);

namespace Bitcoin\HDW;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\ECC\S256Point;
use Bitcoin\Encoding;
use Bitcoin\Hashing;

final readonly class ExtendedKey
{
    public const string MASTER_FINGERPRINT = '00000000';

    private const string MASTER_HMAC_KEY = 'Bitcoin seed';
    private const int MASTER_DEPTH       = 0;
    private const int MASTER_CHILD       = 0;

    public Version $version;
    public int $depth;
    public string $parentFingerprint;
    public int $childNumber;
    public string $chainCode;
    public PrivateKey|S256Point $key;

    public function __construct(Version $version, int $depth, string $parentFingerprint, int $childNumber, string $chainCode, PrivateKey|S256Point $key)
    {
        if (0 === $depth && self::MASTER_FINGERPRINT !== $parentFingerprint) {
            throw new \InvalidArgumentException('An extended key of depth 0 cannot have a parent fingerprint');
        }

        if (0 === $depth && 0 !== $childNumber) {
            throw new \InvalidArgumentException('An extended key of depth 0 cannot have a child number other than 0');
        }

        if (\in_array($version, [Version::MAINNET_XPUB, Version::TESTNET_TPUB]) && $key instanceof PrivateKey) {
            throw new \InvalidArgumentException('This is supposed to be an xpub, found a private key in it');
        }

        if (\in_array($version, [Version::MAINNET_XPRV, Version::TESTNET_TPRV]) && $key instanceof S256Point) {
            throw new \InvalidArgumentException('This is supposed to be an xprv, found a public key in it');
        }

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

    public function xpub(): self
    {
        if ($this->key instanceof S256Point) {
            return $this;
        }

        return new self(
            Version::MAINNET_XPRV === $this->version ?
                Version::MAINNET_XPUB : Version::TESTNET_TPUB,
            $this->depth,
            $this->parentFingerprint,
            $this->childNumber,
            $this->chainCode,
            $this->key->pubKey
        );
    }

    public static function create(string $seed, bool $mainnet = false): self
    {
        $I = Hashing::sha512hmac($seed, self::MASTER_HMAC_KEY);

        return new self(
            $mainnet ? Version::MAINNET_XPRV : Version::TESTNET_TPRV,
            self::MASTER_DEPTH,
            self::MASTER_FINGERPRINT,
            self::MASTER_CHILD,
            substr($I, 32, 32),
            new PrivateKey(gmp_import(substr($I, 0, 32)))
        );
    }

    /**
     * @throws \InvalidArgumentException
     */
    public static function parse(string $base58): self
    {
        $data = Encoding\Base58::decode($base58, true);

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

    public function serialize(): string
    {
        $version     = $this->version->value;
        $depth       = pack('C', $this->depth);
        $fingerprint = hex2bin($this->parentFingerprint);
        $childNumber = pack('N', $this->childNumber);
        $chainCode   = $this->chainCode;
        $material    = $this->key instanceof PrivateKey ? "\x00".$this->key->ser256() : $this->key->sec();

        return Encoding\Base58::checksum($version.$depth.$fingerprint.$childNumber.$chainCode.$material);
    }
}
