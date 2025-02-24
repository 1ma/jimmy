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

    private const int TWO_WEEKS = 60 * 60 * 24 * 14;

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

    public static function targetToBits(\GMP $target): int
    {
        $rawBytes  = gmp_export($target, 1, \GMP_MSW_FIRST);
        $firstByte = unpack('C1', $rawBytes[0])[1];
        if ($firstByte > 0x7F) {
            $exponent    = \strlen($rawBytes) + 1;
            $coefficient = "\x00".substr($rawBytes, 0, 2);
        } else {
            $exponent    = \strlen($rawBytes);
            $coefficient = substr($rawBytes, 0, 3);
        }

        $littleEndianBits = strrev($coefficient).hex2bin(dechex($exponent));

        return gmp_intval(Encoding::fromLE($littleEndianBits));
    }

    public static function newTarget(self $firstBlock, self $lastBlock): \GMP
    {
        if ($lastBlock->timestamp < $firstBlock->timestamp || $firstBlock->bits !== $lastBlock->bits) {
            throw new \InvalidArgumentException('Invalid blocks');
        }

        $timeDifferential = max(self::TWO_WEEKS / 4, min(self::TWO_WEEKS * 4, $lastBlock->timestamp - $firstBlock->timestamp));

        return gmp_div(gmp_mul($lastBlock->target(), $timeDifferential), self::TWO_WEEKS);
    }
}
