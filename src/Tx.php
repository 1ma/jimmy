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
    public readonly Network $network;
    public readonly bool $segwit;

    private ?string $hashPrevOuts = null;
    private ?string $hashSequence = null;
    private ?string $hashOutputs  = null;

    private const int SIGHASH_ALL = 0x01;

    private const string SEGWIT_MARKER = "\x00";
    private const string SEGWIT_FLAG   = "\x01";

    public function __construct(int $version, array $txIns, array $txOuts, int $locktime, Network $network = Network::TESTNET, bool $segwit = true)
    {
        $this->version  = $version;
        $this->txIns    = $txIns;
        $this->txOuts   = $txOuts;
        $this->locktime = $locktime;
        $this->network  = $network;
        $this->segwit   = $segwit;
    }

    /**
     * @param resource $stream
     */
    public static function parse($stream, Network $mode = Network::TESTNET): self
    {
        fread($stream, 4);

        $segwit = self::SEGWIT_MARKER === fread($stream, 1);

        rewind($stream);

        return $segwit ?
            self::parseSegWit($stream, $mode) :
            self::parseLegacy($stream, $mode);
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
        return bin2hex(strrev(Hashing::hash256(
            (new self($this->version, $this->txIns, $this->txOuts, $this->locktime, $this->network, segwit: false))->serialize()
        )));
    }

    public function wid(): string
    {
        return bin2hex(strrev(Hashing::hash256($this->serialize())));
    }

    public function isCoinbase(): bool
    {
        return 1                                                                  === \count($this->txIns)
            && '0000000000000000000000000000000000000000000000000000000000000000' === $this->txIns[0]->prevTxId
            && 0xFFFFFFFF                                                         === $this->txIns[0]->prevIndex;
    }

    public function blockHeight(): int|false
    {
        if (!$this->isCoinbase()) {
            return false;
        }

        // BIP-34 forces miners to record the block height as the first element of
        // the coinbase ScriptSig to prevent duplicated Tx IDs.
        return gmp_intval(Encoding::fromLE($this->txIns[0]->scriptSig->cmds[0]));
    }

    /**
     * @throws \RuntimeException
     */
    public function fee(): int
    {
        $inAmount  = array_reduce($this->txIns, fn (\GMP $subtotal, Input $txIn) => $subtotal + $txIn->prevOutput($this->network)->amount, gmp_init(0));
        $outAmount = array_reduce($this->txOuts, fn (\GMP $subtotal, Output $txOut) => $subtotal + $txOut->amount, gmp_init(0));

        return gmp_intval($inAmount - $outAmount);
    }

    public function signInput(int $inputIndex, PrivateKey $key): bool
    {
        if ($inputIndex < 0 || $inputIndex >= \count($this->txIns)) {
            throw new \InvalidArgumentException('Input index out of bounds');
        }

        if ($this->segwit) {
            if ($this->txIns[$inputIndex]->prevOutput($this->network)->scriptPubKey->isP2WSH()) {
                $witnessScript = $this->txIns[$inputIndex]->witness[array_key_last($this->txIns[$inputIndex]->witness)];
                $z             = $this->sigHashBip143($inputIndex, witnessScript: Script::parseAsString(Encoding::encodeVarInt(\strlen($witnessScript)).$witnessScript));
            } else {
                $z = $this->sigHashBip143($inputIndex);
            }
        } else {
            $z = $this->sigHash($inputIndex);
        }

        $sig = $key->sign($z)->der()."\x01"; // SIGHASH_ALL byte
        $sec = $key->pubKey->sec();

        if ($this->segwit) {
            if ($this->txIns[$inputIndex]->prevOutput($this->network)->scriptPubKey->isP2WSH()) {
                array_unshift($this->txIns[$inputIndex]->witness, $sig);
            } else {
                array_unshift($this->txIns[$inputIndex]->witness, $sec);
                array_unshift($this->txIns[$inputIndex]->witness, $sig);
            }
        } else {
            $this->txIns[$inputIndex]->scriptSig = new Script([$sig, $sec]);
        }

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
        $prevOut = $txIn->prevOutput($this->network);

        if ($prevOut->scriptPubKey->isP2SH()) {
            $redeemScriptCode = $txIn->scriptSig->cmds[array_key_last($txIn->scriptSig->cmds)];
            $redeemScript     = Script::parseAsString(Encoding::encodeVarInt(\strlen($redeemScriptCode)).$redeemScriptCode);

            if ($redeemScript->isP2WPKH()) {
                $z       = $this->sigHashBip143($inputIndex, redeemScript: $redeemScript);
                $witness = $txIn->witness;
            } elseif ($redeemScript->isP2WSH()) {
                $command       = $txIn->witness[array_key_last($txIn->witness)];
                $witnessScript = Script::parseAsString(Encoding::encodeVarInt(\strlen($command)).$command);

                $z       = $this->sigHashBip143($inputIndex, witnessScript: $witnessScript);
                $witness = $txIn->witness;
            } else {
                $z       = $this->sigHash($inputIndex, redeemScript: $redeemScript);
                $witness = [];
            }
        } elseif ($prevOut->scriptPubKey->isP2WPKH()) {
            $z       = $this->sigHashBip143($inputIndex);
            $witness = $txIn->witness;
        } elseif ($prevOut->scriptPubKey->isP2WSH()) {
            $command       = $txIn->witness[array_key_last($txIn->witness)];
            $witnessScript = Script::parseAsString(Encoding::encodeVarInt(\strlen($command)).$command);

            $z       = $this->sigHashBip143($inputIndex, witnessScript: $witnessScript);
            $witness = $txIn->witness;
        } else {
            $z       = $this->sigHash($inputIndex);
            $witness = [];
        }

        return Script\Interpreter::evaluate($txIn->scriptSig->combine($prevOut->scriptPubKey), $z, $witness);
    }

    public function __toString(): string
    {
        return \sprintf(
            "tx: %s\nversion: %d\ntx_ins:\n%stx_outs:\n%slocktime: %d",
            $this->id(),
            $this->version,
            array_reduce($this->txIns, fn (string $txIns, Input $txIn): string => $txIns.$txIn."\n", ''),
            array_reduce($this->txOuts, fn (string $txOuts, Output $txOut): string => $txOuts.$txOut."\n", ''),
            $this->locktime
        );
    }

    private function sigHash(int $inputIndex, ?Script $redeemScript = null): \GMP
    {
        $tx = Encoding::toLE(gmp_init($this->version), 4);
        $tx .= Encoding::encodeVarInt(\count($this->txIns));
        foreach ($this->txIns as $i => $txIn) {
            $scriptSig = new Script();
            if ($i === $inputIndex) {
                $scriptSig = $redeemScript ?? $txIn->prevOutput($this->network)->scriptPubKey;
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

    private function initBip143Hashes(): void
    {
        if (null === $this->hashPrevOuts || null === $this->hashSequence) {
            $allPrevOuts = '';
            $allSequence = '';

            foreach ($this->txIns as $txIn) {
                $allPrevOuts .= strrev(hex2bin($txIn->prevTxId)).Encoding::toLE(gmp_init($txIn->prevIndex), 4);
                $allSequence .= Encoding::toLE(gmp_init($txIn->seqNum), 4);
            }

            $this->hashPrevOuts = Hashing::hash256($allPrevOuts);
            $this->hashSequence = Hashing::hash256($allSequence);
        }

        if (null === $this->hashOutputs) {
            $allOutputs = '';

            foreach ($this->txOuts as $txOut) {
                $allOutputs .= $txOut->serialize();
            }

            $this->hashOutputs = Hashing::hash256($allOutputs);
        }
    }

    private function sigHashBip143(int $inputIndex, ?Script $redeemScript = null, ?Script $witnessScript = null): \GMP
    {
        $this->initBip143Hashes();

        $tx = Encoding::toLE(gmp_init($this->version), 4);
        $tx .= $this->hashPrevOuts;
        $tx .= $this->hashSequence;
        $tx .= strrev(hex2bin($this->txIns[$inputIndex]->prevTxId));
        $tx .= Encoding::toLE(gmp_init($this->txIns[$inputIndex]->prevIndex), 4);

        if (null !== $witnessScript) {
            $script = $witnessScript;
        } elseif (null !== $redeemScript) {
            $script = Script::payToPubKeyHash($redeemScript->cmds[1]);
        } else {
            $script = Script::payToPubKeyHash($this->txIns[$inputIndex]->prevOutput($this->network)->scriptPubKey->cmds[1]);
        }

        $tx .= $script->serialize();

        $tx .= Encoding::toLE(gmp_init($this->txIns[$inputIndex]->prevOutput($this->network)->amount), 8);
        $tx .= Encoding::toLE(gmp_init($this->txIns[$inputIndex]->seqNum), 4);

        $tx .= $this->hashOutputs;

        $tx .= Encoding::toLE(gmp_init($this->locktime), 4);
        $tx .= Encoding::toLE(gmp_init(self::SIGHASH_ALL), 4);

        return gmp_import(Hashing::hash256($tx));
    }

    private static function parseLegacy($stream, Network $mode): self
    {
        $version = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        [$txIns, $txOuts] = self::parseInputsAndOputputs($stream);

        $locktime = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        return new self($version, $txIns, $txOuts, $locktime, $mode, segwit: false);
    }

    private static function parseSegWit($stream, Network $mode): self
    {
        $version = gmp_intval(Encoding::fromLE(fread($stream, 4)));

        $marker = fread($stream, 2);
        if (self::SEGWIT_MARKER.self::SEGWIT_FLAG !== $marker) {
            throw new \InvalidArgumentException('Not a SegWit transaction');
        }

        [$txIns, $txOuts] = self::parseInputsAndOputputs($stream);

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

        return new self($version, $txIns, $txOuts, $locktime, $mode, segwit: true);
    }

    private static function parseInputsAndOputputs($stream): array
    {
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

        return [$txIns, $txOuts];
    }
}
