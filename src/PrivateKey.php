<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class PrivateKey
{
    public \GMP $secret;
    public S256Point $point;

    public function __construct(\GMP $secret)
    {
        $this->secret = $secret;
        $this->point = S256Point::G()->scalarMul($this->secret);
    }

    public function sign(\GMP $z): Signature
    {
        // This method of k generation will be changed later on
        $k = $this->computeRFC6979KParam($z);

        $G = S256Point::G();
        $r = $G->scalarMul($k)->x->num;
        $N = gmp_init(S256Params::N->value);
        $kInv = gmp_powm($k, $N - 2, $N);
        $s = (($z + $r * $this->secret) * $kInv) % $N;

        if ($s > $N / 2) {
            $s = $N - $s;
        }

        return new Signature($r, $s);
    }

    /**
     * Computes a deterministic but unique k value from the
     * given e value (secret) and z value (message to sign).
     *
     * @see https://datatracker.ietf.org/doc/html/rfc6979
     */
    private function computeRFC6979KParam(\GMP $z): \GMP
    {
        $N = gmp_init(S256Params::N->value);
        $k = gmp_init('0x0000000000000000000000000000000000000000000000000000000000000000');
        $v = gmp_init('0x0000000000000000000000000000000000000000000000000000000000000000');

        if ($z > $N) {
            $z -= $N;
        }

        // TODO
        return gmp_random_range(0, S256Params::N->value);
    }
}
