<?php

declare(strict_types=1);

namespace Bitcoin;

final readonly class Tx
{
    public int $version;
    public array $txIns;
    public array $txOuts;
    public int $locktime;
    public bool $testnet;

    public function __construct(int $version, array $txIns, array $txOuts, int $locktime, bool $testnet = false)
    {
        $this->version = $version;
        $this->txIns = $txIns;
        $this->txOuts = $txOuts;
        $this->locktime = $locktime;
        $this->testnet = $testnet;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream, bool $testnet = false): self
    {
        $version = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        return new self($version, [], [], 0, $testnet);
    }

    public function id(): string
    {
        // TODO
        return bin2hex(strrev(Hashing::hash256('12345')));
    }

    public function __toString(): string
    {
        return sprintf(
            "tx: %s\nversion: %d\ntx_ins:\n%stx_outs:\n%slocktime: %d",
            $this->id(),
            $this->version,
            array_reduce($this->txIns, fn (string $txIns, TxIn $txIn): string => $txIns.$txIn."\n", ''),
            array_reduce($this->txOuts, fn (string $txOuts, TxOut $txOut): string => $txOuts.$txOut."\n", ''),
            $this->locktime
        );
    }
}
