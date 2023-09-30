<?php

declare(strict_types=1);

namespace Bitcoin;

use Bitcoin\Tx\Input;
use Bitcoin\Tx\Output;
use Bitcoin\Tx\Script;

final readonly class Tx
{
    public int $version;

    /** @var Input[] */
    public array $txIns;

    /** @var Output[] */
    public array $txOuts;

    public int $locktime;
    public bool $testnet;

    private const SIGHASH_ALL = 0x01;

    public function __construct(int $version, array $txIns, array $txOuts, int $locktime, bool $testnet = false)
    {
        $this->version  = $version;
        $this->txIns    = $txIns;
        $this->txOuts   = $txOuts;
        $this->locktime = $locktime;
        $this->testnet  = $testnet;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream, bool $testnet = false): self
    {
        $version = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        $txIns = [];
        $nIns  = Encoding::decodeVarInt($stream);
        for ($i = 0; $i < $nIns; ++$i) {
            $txIns[] = Input::parse($stream);
        }

        $txOuts = [];
        $nOuts  = Encoding::decodeVarInt($stream);
        for ($i = 0; $i < $nOuts; ++$i) {
            $txOuts[] = Output::parse($stream);
        }

        $locktime = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        return new self($version, $txIns, $txOuts, $locktime, $testnet);
    }

    public function serialize(): string
    {
        $version  = Encoding::toLE(gmp_init($this->version), 4);
        $nTxIns   = Encoding::encodeVarInt(\count($this->txIns));
        $txIns    = array_reduce($this->txIns, fn (string $txIns, Input $txIn): string => $txIns.$txIn->serialize(), '');
        $nTxOuts  = Encoding::encodeVarInt(\count($this->txOuts));
        $txOuts   = array_reduce($this->txOuts, fn (string $txOuts, Output $txOut): string => $txOuts.$txOut->serialize(), '');
        $locktime = Encoding::toLE(gmp_init($this->locktime), 4);

        return $version.$nTxIns.$txIns.$nTxOuts.$txOuts.$locktime;
    }

    public function id(): string
    {
        return bin2hex(strrev(Hashing::hash256($this->serialize())));
    }

    /**
     * @throws \RuntimeException
     */
    public function fee(): int
    {
        $inAmount  = array_reduce($this->txIns, fn (\GMP $subtotal, Input $txIn) => $subtotal + $txIn->prevAmount($this->testnet), gmp_init(0));
        $outAmount = array_reduce($this->txOuts, fn (\GMP $subtotal, Output $txOut) => $subtotal + $txOut->amount, gmp_init(0));

        return gmp_intval($inAmount - $outAmount);
    }

    public function verify(): bool
    {
        if ($this->fee() < 0) {
            return false;
        }

        foreach ($this->txIns as $idx => $_) {
            if (!$this->verifyInput($idx)) {
                return false;
            }
        }

        return true;
    }

    public function verifyInput(int $inputIndex): bool
    {
        if ($inputIndex < 0 || $inputIndex >= \count($this->txIns)) {
            throw new \InvalidArgumentException('Input index out of bounds');
        }

        $txIn = $this->txIns[$inputIndex];

        return Script\Interpreter::evaluate(
            $txIn->scriptSig->combine($txIn->prevScriptPubKey($this->testnet)),
            $this->sigHash($inputIndex)
        );
    }

    private function sigHash(int $inputIndex): \GMP
    {
        $tx = Encoding::toLE(gmp_init($this->version), 4);
        $tx .= Encoding::encodeVarInt(\count($this->txIns));
        foreach ($this->txIns as $i => $txIn) {
            $tx .= (new Input(
                $txIn->prevTxId,
                $txIn->prevIndex,
                $i === $inputIndex ? $txIn->prevScriptPubKey($this->testnet) : new Script(),
                $txIn->seqNum
            ))->serialize();
        }

        $tx .= Encoding::encodeVarInt(\count($this->txOuts));
        foreach ($this->txOuts as $txOut) {
            $tx .= $txOut->serialize();
        }

        $tx .= Encoding::toLE(gmp_init($this->locktime), 4);
        $tx .= Encoding::toLE(gmp_init(self::SIGHASH_ALL), 4);

        return gmp_import(Hashing::hash256($tx));
    }

    public function __toString(): string
    {
        return sprintf(
            "tx: %s\nversion: %d\ntx_ins:\n%stx_outs:\n%slocktime: %d",
            $this->id(),
            $this->version,
            array_reduce($this->txIns, fn (string $txIns, Input $txIn): string => $txIns.$txIn."\n", ''),
            array_reduce($this->txOuts, fn (string $txOuts, Output $txOut): string => $txOuts.$txOut."\n", ''),
            $this->locktime
        );
    }
}
