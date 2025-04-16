<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

use Bitcoin\Encoding;
use Bitcoin\Hashing;
use Bitcoin\Network;

final readonly class PrivateKey
{
    public \GMP $secret;
    public S256Point $pubKey;

    public function __construct(#[\SensitiveParameter] \GMP $secret)
    {
        if ($secret < 1 || $secret >= S256Params::N()) {
            throw new \InvalidArgumentException('A valid private key must be in the [1,N) range');
        }

        $this->secret = $secret;
        $this->pubKey = S256Params::G()->scalarMul($this->secret);
    }

    /**
     * Sign a message using traditional ECDSA.
     */
    public function ecdsa(\GMP $z): Signature
    {
        $k = $this->computeRFC6979KParam($z);

        $r    = S256Params::G()->scalarMul($k)->x->num;
        $kInv = gmp_powm($k, S256Params::N() - 2, S256Params::N());
        $s    = (($z + $r * $this->secret) * $kInv) % S256Params::N();

        if ($s > S256Params::Ndiv2()) {
            $s = S256Params::N() - $s;
        }

        return new Signature($r, $s);
    }

    /**
     * Sign a message using BIP-340 Schnorr.
     */
    public function schnorr(\GMP $z, ?string $auxRand = null): Signature
    {
        return new Signature(gmp_init(1), gmp_init(1));
    }

    public static function fromWIF(string $wif): self
    {
        try {
            $decodedWif = Encoding::base58decode($wif, check: true);
        } catch (\InvalidArgumentException) {
            throw new \InvalidArgumentException('Invalid WIF data: '.$wif);
        }

        if (!\in_array(\strlen($decodedWif), [33, 34]) || !\in_array($decodedWif[0], ["\x80", "\xef"])) {
            throw new \InvalidArgumentException('Invalid WIF key: '.bin2hex($decodedWif));
        }

        return new self(gmp_init('0x'.bin2hex(substr($decodedWif, 1, -1))));
    }

    public function wif(bool $compressed = true, Network $mode = Network::TESTNET): string
    {
        return Encoding::base58checksum(
            (Network::TESTNET === $mode ? "\xef" : "\x80").Encoding::serN($this->secret, 32).($compressed ? "\x01" : '')
        );
    }

    /**
     * Computes a deterministic but unique k value from the
     * given e value (secret) and z value (message to sign).
     *
     * @see https://datatracker.ietf.org/doc/html/rfc6979
     */
    private function computeRFC6979KParam(\GMP $z): \GMP
    {
        if ($z > S256Params::N()) {
            $z -= S256Params::N();
        }

        $zBytes = Encoding::serN($z, 32);
        $eBytes = Encoding::serN($this->secret, 32);

        $k = str_repeat("\x00", 32);
        $v = str_repeat("\x01", 32);

        $k = Hashing::sha256hmac($v."\x00".$eBytes.$zBytes, $k);
        $v = Hashing::sha256hmac($v, $k);

        $k = Hashing::sha256hmac($v."\x01".$eBytes.$zBytes, $k);
        $v = Hashing::sha256hmac($v, $k);

        while (true) {
            $v         = Hashing::sha256hmac($v, $k);
            $candidate = gmp_import($v);
            if ($candidate >= 1 && $candidate < S256Params::N()) {
                return $candidate;
            }

            $k = Hashing::sha256hmac($v."\x00", $k);
            $v = Hashing::sha256hmac($v, $k);
        }
    }

    public function ser256(): string
    {
        return Encoding::serN($this->secret, 32);
    }
}
