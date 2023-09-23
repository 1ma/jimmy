<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class PrivateKey
{
    public \GMP $secret;
    public S256Point $pubKey;

    public function __construct(\GMP $secret)
    {
        $this->secret = $secret;
        $this->pubKey = S256Point::G()->scalarMul($this->secret);
    }

    public function sign(\GMP $z): Signature
    {
        $N = S256Field::N();
        $k = $this->computeRFC6979KParam($z, $N);

        $r = S256Point::G()->scalarMul($k)->x->num;
        $kInv = gmp_powm($k, S256Field::N() - 2, $N);
        $s = (($z + $r * $this->secret) * $kInv) % $N;

        if ($s > $N / 2) {
            $s = $N - $s;
        }

        return new Signature($r, $s);
    }

    public function wif(bool $compressed = true, bool $testnet = false): string
    {
        return Base58::encodeWithChecksum(
            ($testnet ? "\xef" : "\x80").str_pad(gmp_export($this->secret), 32, "\x00", \STR_PAD_LEFT).($compressed ? "\x01" : '')
        );
    }

    /**
     * Computes a deterministic but unique k value from the
     * given e value (secret) and z value (message to sign).
     *
     * @see https://datatracker.ietf.org/doc/html/rfc6979
     */
    private function computeRFC6979KParam(\GMP $z, \GMP $N): \GMP
    {
        if ($z > $N) {
            $z -= $N;
        }

        $zBytes = str_pad(gmp_export($z), 32, "\x00", \STR_PAD_LEFT);
        $eBytes = str_pad(gmp_export($this->secret), 32, "\x00", \STR_PAD_LEFT);

        $k = str_repeat("\x00", 32);
        $v = str_repeat("\x01", 32);

        $k = hash_hmac('sha256', $v."\x00".$eBytes.$zBytes, $k, true);
        $v = hash_hmac('sha256', $v, $k, true);

        $k = hash_hmac('sha256', $v."\x01".$eBytes.$zBytes, $k, true);
        $v = hash_hmac('sha256', $v, $k, true);

        while (true) {
            $v = hash_hmac('sha256', $v, $k, true);
            $candidate = gmp_import($v);
            if ($candidate >= 1 && $candidate < $N) {
                return $candidate;
            }

            $k = hash_hmac('sha256', $v."\x00", $k, true);
            $v = hash_hmac('sha256', $v, $k, true);
        }
    }
}
