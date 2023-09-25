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

        $txIns = [];
        $nIns = Encoding::decodeVarInt($stream);
        for ($i = 0; $i < $nIns; ++$i) {
            $txIns[] = TxIn::parse($stream);
        }

        $txOuts = [];
        $nOuts = Encoding::decodeVarInt($stream);
        for ($i = 0; $i < $nOuts; ++$i) {
            $txOuts[] = TxOut::parse($stream);
        }

        $locktime = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        return new self($version, $txIns, $txOuts, $locktime, $testnet);
    }

    public function serialize(): string
    {
        $version = Encoding::toLE(gmp_init($this->version), 4);
        $nTxIns = Encoding::encodeVarInt(\count($this->txIns));
        $txIns = array_reduce($this->txIns, fn (string $txIns, TxIn $txIn): string => $txIns.$txIn->serialize(), '');
        $nTxOuts = Encoding::encodeVarInt(\count($this->txOuts));
        $txOuts = array_reduce($this->txOuts, fn (string $txOuts, TxOut $txOut): string => $txOuts.$txOut->serialize(), '');
        $locktime = Encoding::toLE(gmp_init($this->locktime), 4);

        return $version.$nTxIns.$txIns.$nTxOuts.$txOuts.$locktime;
    }

    public function id(): string
    {
        return bin2hex(strrev(Hashing::hash256($this->serialize())));
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
