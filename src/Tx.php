<?php

declare(strict_types=1);

namespace Bitcoin;

use Bitcoin\ECC\PrivateKey;
use Bitcoin\Tx\Input;
use Bitcoin\Tx\Output;
use Bitcoin\Tx\Script;

final class Tx
{
    public readonly int $version;

    /** @var Input[] */
    public array $txIns;

    /** @var Output[] */
    public array $txOuts;

    public readonly int $locktime;
    public readonly bool $testnet;
    public readonly bool $segwit;

    private const SIGHASH_ALL = 0x01;

    private const SEGWIT_MARKER = "\x00";
    private const SEGWIT_FLAG   = "\x01";

    public function __construct(int $version, array $txIns, array $txOuts, int $locktime, bool $testnet = true, bool $segwit = true)
    {
        $this->version  = $version;
        $this->txIns    = $txIns;
        $this->txOuts   = $txOuts;
        $this->locktime = $locktime;
        $this->testnet  = $testnet;
        $this->segwit   = $segwit;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream, bool $testnet = true): self
    {
        fread($stream, 4);

        $segwit = self::SEGWIT_MARKER === fread($stream, 1);

        rewind($stream);

        return $segwit ?
            self::parseSegWit($stream, $testnet) :
            self::parseLegacy($stream, $testnet);
    }

    public function serialize(): string
    {
        $version  = Encoding::toLE(gmp_init($this->version), 4);
        $markers  = $this->segwit ? self::SEGWIT_MARKER.self::SEGWIT_FLAG : '';
        $nTxIns   = Encoding::encodeVarInt(\count($this->txIns));
        $txIns    = array_reduce($this->txIns, fn (string $txIns, Input $txIn): string => $txIns.$txIn->serialize(), '');
        $nTxOuts  = Encoding::encodeVarInt(\count($this->txOuts));
        $txOuts   = array_reduce($this->txOuts, fn (string $txOuts, Output $txOut): string => $txOuts.$txOut->serialize(), '');
        $locktime = Encoding::toLE(gmp_init($this->locktime), 4);

        $witness = '';
        if ($this->segwit) {
            foreach ($this->txIns as $txIn) {
                $witness .= Encoding::encodeVarInt(\count($txIn->witness));
                foreach ($txIn->witness as $element) {
                    $witness .= \is_int($element) ?
                        Encoding::toLE(gmp_init($element)) :
                        Encoding::encodeVarInt(\strlen($element)).$element;
                }
            }
        }

        return $version.$markers.$nTxIns.$txIns.$nTxOuts.$txOuts.$witness.$locktime;
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
        $inAmount  = array_reduce($this->txIns, fn (\GMP $subtotal, Input $txIn) => $subtotal + $txIn->prevOutput($this->testnet)->amount, gmp_init(0));
        $outAmount = array_reduce($this->txOuts, fn (\GMP $subtotal, Output $txOut) => $subtotal + $txOut->amount, gmp_init(0));

        return gmp_intval($inAmount - $outAmount);
    }

    public function signInput(int $inputIndex, PrivateKey $key): bool
    {
        if ($inputIndex < 0 || $inputIndex >= \count($this->txIns)) {
            throw new \InvalidArgumentException('Input index out of bounds');
        }

        $z   = $this->sigHash($inputIndex);
        $sig = $key->sign($z)->der()."\x01"; // SIGHASH_ALL byte
        $sec = $key->pubKey->sec();

        $this->txIns[$inputIndex]->scriptSig = new Script([$sig, $sec]);

        return $this->verifyInput($inputIndex);
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

        $txIn    = $this->txIns[$inputIndex];
        $prevOut = $txIn->prevOutput($this->testnet);

        $redeemScript = null;
        if ($prevOut->scriptPubKey->isP2SH()) {
            $redeemScriptCode = $txIn->scriptSig->cmds[array_key_last($txIn->scriptSig->cmds)];
            $redeemScript     = Script::parseAsString(Encoding::encodeVarInt(\strlen($redeemScriptCode)).$redeemScriptCode);
        }

        return Script\Interpreter::evaluate(
            $txIn->scriptSig->combine($prevOut->scriptPubKey),
            $this->sigHash($inputIndex, $redeemScript)
        );
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

    private function sigHash(int $inputIndex, Script $redeemScript = null): \GMP
    {
        $tx = Encoding::toLE(gmp_init($this->version), 4);
        $tx .= Encoding::encodeVarInt(\count($this->txIns));
        foreach ($this->txIns as $i => $txIn) {
            $scriptSig = new Script();
            if ($i === $inputIndex) {
                $scriptSig = $redeemScript ?? $txIn->prevOutput($this->testnet)->scriptPubKey;
            }

            $tx .= (new Input(
                $txIn->prevTxId,
                $txIn->prevIndex,
                $scriptSig,
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

    private static function parseLegacy($stream, bool $testnet): self
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

        return new self($version, $txIns, $txOuts, $locktime, $testnet, segwit: false);
    }

    private static function parseSegWit($stream, bool $testnet): self
    {
        $version = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        $marker = fread($stream, 2);
        if (self::SEGWIT_MARKER.self::SEGWIT_FLAG !== $marker) {
            throw new \InvalidArgumentException('Not a SegWit transaction');
        }

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

        $witness = [];
        foreach ($txIns as $txIn) {
            $nWitness = Encoding::decodeVarInt($stream);
            for ($i = 0; $i < $nWitness; ++$i) {
                $itemLength = Encoding::decodeVarInt($stream);
                $witness[]  = 0 === $itemLength ? 0 : fread($stream, $itemLength);
            }

            $txIn->witness = $witness;
        }

        $locktime = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        return new self($version, $txIns, $txOuts, $locktime, $testnet, segwit: true);
    }
}
