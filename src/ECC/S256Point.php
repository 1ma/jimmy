<?php

declare(strict_types=1);

namespace Bitcoin\ECC;

use Bitcoin\Encoding;
use Bitcoin\Hashing;
use Bitcoin\Network;

/**
 * Represents a Point on the secp256k1 elliptic curve.
 *
 * These points are Bitcoin's public keys.
 */
final readonly class S256Point
{
    public ?S256Field $x;
    public ?S256Field $y;

    private const string P2PKH_MAINNET_PREFIX = "\x00";
    private const string P2PKH_TESTNET_PREFIX = "\x6f";

    public function __construct(?S256Field $x, ?S256Field $y)
    {
        if ((null === $x && null !== $y) || (null === $y && null !== $x)) {
            throw new \InvalidArgumentException('If one coordinate is null the other must be null too');
        }

        if (null !== $x && null !== $y && !$y->exp(2)->equals($x->exp(3)->add(S256Params::A()->mul($x))->add(S256Params::B()))) {
            throw new \InvalidArgumentException("Point ({$x->num},{$y->num}) is not on the a=0 b=7 curve");
        }

        $this->x = $x;
        $this->y = $y;
    }

    public static function infinity(): self
    {
        return new self(null, null);
    }

    public function atInfinity(): bool
    {
        return null === $this->x;
    }

    public function hasEvenY(): bool
    {
        return 0 == $this->y->num % 2;
    }

    public function tweak(\GMP $t): self
    {
        return $this->add(S256Params::G()->scalarMul($t));
    }

    public function add(self $other): self
    {
        if ($this->atInfinity()) {
            return $other;
        }

        if ($other->atInfinity()) {
            return $this;
        }

        if ($this->x->num == $other->x->num && $this->y->num != $other->y->num) {
            return self::infinity();
        }

        $lam = $this->equals($other) ?
            new S256Field(3)->mul($this->x->exp(2))->mul(new S256Field(2)->mul($this->y)->exp(S256Params::P() - 2)) :
            $other->y->sub($this->y)->mul($other->x->sub($this->x)->exp(S256Params::P() - 2));

        $x3 = $lam->mul($lam)->sub($this->x)->sub($other->x);

        return new self($x3, $this->x->sub($x3)->mul($lam)->sub($this->y));
    }

    public function scalarMul(\GMP|int $coefficient): self
    {
        // Optimization: reduce the coefficient modulo N before computing the multiplication
        $c       = $coefficient % S256Params::N();
        $current = clone $this;
        $result  = self::infinity();

        while ($c > 0) {
            if (gmp_testbit($c, 0)) {
                $result = $result->add($current);
            }

            $c >>= 1;
            $current = $current->add($current);
        }

        return $result;
    }

    public function equals(self $other): bool
    {
        return $this->x->equals($other->x)
            && $this->y->equals($other->y);
    }

    public static function liftX(\GMP $x): self
    {
        $ySq = gmp_div_r(gmp_powm($x, 3, S256Params::P()) + 7, S256Params::P());
        $y   = gmp_powm($ySq, gmp_div_q(S256Params::P() + 1, 4), S256Params::P());

        if (gmp_powm($y, 2, S256Params::P()) != $ySq) {
            return self::infinity();
        }

        return new self(new S256Field($x), new S256Field(0 == $y % 2 ? $y : S256Params::P() - $y));
    }

    public static function parse(string $sec): self
    {
        if (!self::validSecString($sec)) {
            throw new \InvalidArgumentException('Invalid SEC data format');
        }

        if ("\x04" === $sec[0]) {
            return new self(
                new S256Field(substr($sec, 1, 32)),
                new S256Field(substr($sec, 33, 32))
            );
        }

        $x = new S256Field(substr($sec, 1, 32));

        $alpha = $x->exp(3)->add(S256Params::B());
        $beta  = $alpha->sqrt();

        return "\x02" === $sec[0] ?
            new self($x, (0 == $beta->num % 2) ? $beta : new S256Field(S256Params::P() - $beta->num)) :
            new self($x, (0 == $beta->num % 2) ? new S256Field(S256Params::P() - $beta->num) : $beta);
    }

    public function address(bool $compressed = true, Network $mode = Network::TESTNET): string
    {
        return self::hash160ToPayToPublicKeyHashAddress(Hashing::hash160($this->sec($compressed)), $mode);
    }

    public function bech32(Network $mode = Network::TESTNET): string
    {
        return 'bc1qwakawaka';
    }

    public function sec(bool $compressed = true): string
    {
        if ($compressed) {
            $prefix = 0 == $this->y->num % 2 ? "\x02" : "\x03";

            return $prefix.Encoding::serN($this->x->num, 32);
        }

        return "\x04".Encoding::serN($this->x->num, 32).Encoding::serN($this->y->num, 32);
    }

    /**
     * Verify a signature according to traditional ECDSA.
     */
    public function ecdsa(\GMP $z, Signature $sig): bool
    {
        $sInv = gmp_powm($sig->s, S256Params::N() - 2, S256Params::N());

        $u = ($z * $sInv)      % S256Params::N();
        $v = ($sig->r * $sInv) % S256Params::N();

        $R = S256Params::G()->scalarMul($u)->add($this->scalarMul($v));

        return null !== $R->x && ($R->x->num % S256Params::N()) == $sig->r;
    }

    /**
     * Verify a signature according to BIP-340 Schnorr.
     */
    public function schnorr(string $msg, Signature $sig): bool
    {
        $P = $this;
        $r = $sig->r;
        $s = $sig->s;

        if ($P->atInfinity() || $r >= S256Params::P() || $s >= S256Params::N()) {
            return false;
        }

        $e = gmp_import(Hashing::taggedHash('BIP0340/challenge', Encoding::serN($r, 32).Encoding::serN($this->x->num, 32).$msg)) % S256Params::N();

        $R = S256Params::G()->scalarMul($s)->add($P->scalarMul(S256Params::N() - $e));

        if ($R->atInfinity() || !$R->hasEvenY() || $R->x->num != $r) {
            return false;
        }

        return true;
    }

    public function __toString(): string
    {
        if (null === $this->x) {
            return 'S256Point(,)';
        }

        return \sprintf(
            'S256Point(%s,%s)',
            str_pad(gmp_strval($this->x->num, 16), 64, '0', \STR_PAD_LEFT),
            str_pad(gmp_strval($this->y->num, 16), 64, '0', \STR_PAD_LEFT)
        );
    }

    private static function validSecString(string $data): bool
    {
        return (33 === \strlen($data) && ("\x02" === $data[0] || "\x03" === $data[0]))
            || (65 === \strlen($data) && "\x04" === $data[0]);
    }

    private static function hash160ToPayToPublicKeyHashAddress(string $hash, Network $mode = Network::TESTNET): string
    {
        return Encoding::base58checksum((Network::TESTNET === $mode ? self::P2PKH_TESTNET_PREFIX : self::P2PKH_MAINNET_PREFIX).$hash);
    }
}
