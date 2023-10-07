<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class Block
{
    public int $version;
    public string $prevBlock;
    public string $merkleRoot;
    public int $timestamp;
    public int $bits;
    public int $nonce;

    public function __construct(int $version, string $prevBlock, string $merkleRoot, int $timestamp, int $bits, int $nonce)
    {
        $this->version    = $version;
        $this->prevBlock  = $prevBlock;
        $this->merkleRoot = $merkleRoot;
        $this->timestamp  = $timestamp;
        $this->bits       = $bits;
        $this->nonce      = $nonce;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream): self
    {
        return new self(
            version: gmp_intval(Encoding::fromLE(fread($stream, 4))),
            prevBlock: bin2hex(strrev(fread($stream, 32))),
            merkleRoot: bin2hex(strrev(fread($stream, 32))),
            timestamp: gmp_intval(Encoding::fromLE(fread($stream, 4))),
            bits: gmp_intval(Encoding::fromLE(fread($stream, 4))),
            nonce: gmp_intval(Encoding::fromLE(fread($stream, 4)))
        );
    }

    public function serialize(): string
    {
        $version    = Encoding::toLE(gmp_init($this->version), 4);
        $prevBlock  = strrev(hex2bin($this->prevBlock));
        $merkleRoot = strrev(hex2bin($this->merkleRoot));
        $timestamp  = Encoding::toLE(gmp_init($this->timestamp), 4);
        $bits       = Encoding::toLE(gmp_init($this->bits), 4);
        $nonce      = Encoding::toLE(gmp_init($this->nonce), 4);

        return $version.$prevBlock.$merkleRoot.$timestamp.$bits.$nonce;
    }

    public function id(): string
    {
        return bin2hex(strrev(Hashing::hash256($this->serialize())));
    }

    public function target(): \GMP
    {
        $exponent    = $this->bits >> 24;
        $coefficient = $this->bits & 0x00FFFFFF;

        return gmp_mul($coefficient, gmp_pow(256, $exponent - 3));
    }

    public function difficulty(): \GMP
    {
        return gmp_div(gmp_mul(0xFFFF, gmp_pow(256, 0x1D - 3)), $this->target());
    }

    public function checkPOW(): bool
    {
        return Encoding::fromLE(Hashing::hash256($this->serialize())) < $this->target();
    }

    public function bip9(): bool
    {
        return ($this->version >> 29) === 0b001;
    }

    public function bip91(): bool
    {
        return 1 === (($this->version >> 4) & 1);
    }

    public function bip141(): bool
    {
        return 1 === (($this->version >> 1) & 1);
    }
}
