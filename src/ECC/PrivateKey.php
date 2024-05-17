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

    public function __construct(\GMP $secret)
    {
        $this->secret = $secret;
        $this->pubKey = S256Params::G()->scalarMul($this->secret);
    }

    public function sign(\GMP $z): Signature
    {
        $k = $this->computeRFC6979KParam($z);

        $r    = S256Params::G()->scalarMul($k)->x->num;
        $kInv = gmp_powm($k, S256Params::N() - 2, S256Params::N());
        $s    = (($z + $r * $this->secret) * $kInv) % S256Params::N();

        if ($s > S256Params::N() / 2) {
            $s = S256Params::N() - $s;
        }

        return new Signature($r, $s);
    }

    public function wif(bool $compressed = true, Network $mode = Network::TESTNET): string
    {
        return Encoding::base58checksum(
            (Network::TESTNET === $mode ? "\xef" : "\x80").str_pad(gmp_export($this->secret), 32, "\x00", \STR_PAD_LEFT).($compressed ? "\x01" : '')
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

        $zBytes = str_pad(gmp_export($z), 32, "\x00", \STR_PAD_LEFT);
        $eBytes = str_pad(gmp_export($this->secret), 32, "\x00", \STR_PAD_LEFT);

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
}
